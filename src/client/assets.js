/**
 * Precomputed-asset (archx-build) manifest loading, integrity verification, and variant selection.
 */
import { subtleDo } from './native.js';
import { assertResponseFinalOrigin, fetchBounded, isPlainClientObject, nonRetryableError, parseBoundedJson, resolveHttpUrl, validTokenString } from './network.js';
import { DEFAULTS } from './options.js';
import { boundedInteger, cacheDigest, fetchPriorityInit, normalizedHttpCache } from './sampling.js';

export const ASSET_MANIFEST_CACHE_MAX = 8;
export const assetManifestCache = new Map(); // digest -> Promise<normalized manifest> (bounded LRU)
export const assetManifestObjectCache = new WeakMap(); // host object -> normalized manifest

export async function sha256Hex(bytes) {
  try {
    if (typeof crypto === 'undefined' || !crypto.subtle?.digest) return null;
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const digest = await subtleDo('digest', 'SHA-256', view);
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
  } catch { return null; }
}

export function normalizeManifestIntegrityPin(value) {
  if (value == null || value === '') return null;
  if (typeof value !== 'string') throw nonRetryableError('Archx: assetManifestIntegrity is invalid');
  const hex = value.startsWith('sha256-') ? value.slice('sha256-'.length) : value;
  if (!/^[0-9a-f]{64}$/.test(hex)) throw nonRetryableError('Archx: assetManifestIntegrity is invalid');
  return hex;
}

export function normalizeAssetIntegrityMode(value) {
  if (value === true) return 'require';
  if (value === false || value === 'off') return 'off';
  if (value === 'require') return 'require';
  return 'auto';
}

/**
 * Verify one fetched variant against the SHA-256 digest recorded in the
 * manifest. 'auto' verifies whenever a digest and WebCrypto are available;
 * 'require' fails closed without them. This detects CDN/object-store
 * substitution of individual derivatives between build and browser.
 */
export async function verifyAssetVariantIntegrity(variant, bytes, options) {
  const mode = normalizeAssetIntegrityMode(options.assetIntegrity);
  if (mode === 'off') return;
  if (!variant.sha256) {
    if (mode === 'require') throw nonRetryableError('Archx: asset variant has no integrity digest');
    return;
  }
  const digest = await sha256Hex(bytes);
  if (!digest) {
    if (mode === 'require') {
      throw nonRetryableError('Archx: asset integrity cannot be verified in this browser');
    }
    return;
  }
  if (digest !== variant.sha256) {
    throw nonRetryableError('Archx: asset variant integrity check failed');
  }
}

export function normalizeAssetManifest(raw, baseUrl) {
  if (!isPlainClientObject(raw) || raw.version !== 1 || !isPlainClientObject(raw.assets)) {
    throw nonRetryableError('Archx: asset manifest is invalid');
  }
  const entries = Object.entries(raw.assets);
  if (!entries.length || entries.length > 100000) {
    throw nonRetryableError('Archx: asset manifest has an invalid asset count');
  }
  const assets = new Map();
  for (const [id, assetRaw] of entries) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(id) || !isPlainClientObject(assetRaw)) {
      throw nonRetryableError('Archx: asset manifest contains an invalid asset');
    }
    if (assetRaw.id !== undefined && assetRaw.id !== id) {
      throw nonRetryableError('Archx: asset manifest contains a mismatched asset id');
    }
    const width = assetRaw.width;
    const height = assetRaw.height;
    if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) ||
        width < 1 || height < 1 || width > 65536 || height > 65536) {
      throw nonRetryableError('Archx: asset manifest contains invalid dimensions');
    }
    if (!validTokenString(assetRaw.key, { min: 1, max: 512 })) {
      throw nonRetryableError('Archx: asset manifest contains an invalid key');
    }
    if (!Number.isInteger(assetRaw.grid) || assetRaw.grid < 2 || assetRaw.grid > 32) {
      throw nonRetryableError('Archx: asset manifest contains an invalid grid');
    }
    if (assetRaw.planVersion !== undefined && assetRaw.planVersion !== 1 && assetRaw.planVersion !== 2) {
      throw nonRetryableError('Archx: asset manifest contains an invalid plan version');
    }
    if (assetRaw.aesKey !== undefined &&
        !validTokenString(assetRaw.aesKey, { min: 16, max: 256 })) {
      throw nonRetryableError('Archx: asset manifest contains an invalid AES key');
    }
    if (!Array.isArray(assetRaw.variants) || !assetRaw.variants.length || assetRaw.variants.length > 32) {
      throw nonRetryableError('Archx: asset manifest contains invalid variants');
    }
    const variants = assetRaw.variants.map((variantRaw) => {
      if (!isPlainClientObject(variantRaw) ||
          !Number.isSafeInteger(variantRaw.width) || !Number.isSafeInteger(variantRaw.height) ||
          variantRaw.width < 1 || variantRaw.height < 1 ||
          variantRaw.width > 65536 || variantRaw.height > 65536 ||
          typeof variantRaw.url !== 'string' || !variantRaw.url || variantRaw.url.length > 16384) {
        throw nonRetryableError('Archx: asset manifest contains an invalid variant');
      }
      if (variantRaw.sha256 !== undefined && variantRaw.sha256 !== null &&
          (typeof variantRaw.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(variantRaw.sha256))) {
        throw nonRetryableError('Archx: asset manifest contains an invalid variant digest');
      }
      const url = resolveHttpUrl(variantRaw.url, { base: baseUrl?.href, label: 'asset variant URL' });
      return Object.freeze({
        width: variantRaw.width,
        height: variantRaw.height,
        url,
        bytes: Number.isSafeInteger(variantRaw.bytes) && variantRaw.bytes > 0 ? variantRaw.bytes : null,
        sha256: typeof variantRaw.sha256 === 'string' ? variantRaw.sha256 : null,
      });
    }).sort((a, b) => a.width - b.width || a.height - b.height);
    assets.set(id, Object.freeze({
      id,
      width,
      height,
      key: assetRaw.key,
      grid: assetRaw.grid,
      ...(assetRaw.planVersion !== undefined ? { planVersion: assetRaw.planVersion } : {}),
      ...(assetRaw.aesKey !== undefined ? { aesKey: assetRaw.aesKey } : {}),
      variants: Object.freeze(variants),
    }));
  }
  return Object.freeze({ version: 1, assets });
}

export async function loadAssetManifest(manifestSource, options, controls) {
  const pin = normalizeManifestIntegrityPin(options.assetManifestIntegrity);
  if (isPlainClientObject(manifestSource)) {
    // A pin can only be checked against fetched bytes; never silently
    // ignore it for a host-supplied object.
    if (pin) throw nonRetryableError('Archx: assetManifestIntegrity requires a fetched manifest URL');
    let normalized = assetManifestObjectCache.get(manifestSource);
    if (!normalized) {
      const base = typeof document !== 'undefined'
        ? new URL(document.baseURI)
        : new URL('http://archx.local/');
      normalized = normalizeAssetManifest(manifestSource, base);
      assetManifestObjectCache.set(manifestSource, normalized);
    }
    return normalized;
  }
  const manifestUrl = resolveHttpUrl(manifestSource, { label: 'asset manifest URL' });
  if (manifestUrl.hash) throw nonRetryableError('Archx: asset manifest URL must not contain a fragment');
  const maxBytes = boundedInteger(
    options.assetManifestMaxBytes,
    DEFAULTS.assetManifestMaxBytes,
    1024,
    64 * 1024 * 1024,
  );
  const cacheMode = normalizedHttpCache(options.assetHttpCache, 'default');
  const cacheKey = cacheDigest([
    'asset-manifest', 1, options.cacheScope || '', manifestUrl.href,
    controls.credentials, cacheMode, maxBytes, controls.fetchTimeoutMs, controls.retries,
    pin || '',
  ]);
  let pending = assetManifestCache.get(cacheKey);
  if (pending) {
    assetManifestCache.delete(cacheKey);
    assetManifestCache.set(cacheKey, pending);
  }
  if (!pending) {
    pending = (async () => {
      const response = await fetchBounded(manifestUrl.href, {
        method: 'GET',
        credentials: controls.credentials,
        cache: cacheMode,
        redirect: 'error',
        ...fetchPriorityInit(options),
      }, {
        retries: controls.retries,
        maxBytes,
        timeoutMs: controls.fetchTimeoutMs,
        validateResponse: (res) => assertResponseFinalOrigin(res, new Set([manifestUrl.origin])),
      });
      if (pin) {
        const digest = await sha256Hex(response.bytes);
        if (!digest) {
          throw nonRetryableError('Archx: asset manifest integrity cannot be verified in this browser');
        }
        if (digest !== pin) throw nonRetryableError('Archx: asset manifest integrity check failed');
      }
      return normalizeAssetManifest(parseBoundedJson(response.bytes), manifestUrl);
    })();
    assetManifestCache.set(cacheKey, pending);
    while (assetManifestCache.size > ASSET_MANIFEST_CACHE_MAX) {
      const oldest = assetManifestCache.keys().next().value;
      if (oldest === cacheKey) break;
      assetManifestCache.delete(oldest);
    }
    pending.catch(() => {
      if (assetManifestCache.get(cacheKey) === pending) assetManifestCache.delete(cacheKey);
    });
  }
  return pending;
}

export function chooseAssetVariant(asset, neededWidth) {
  const wanted = Math.max(1, Math.ceil(Number(neededWidth) || 1));
  return asset.variants.find((variant) => variant.width >= wanted) ||
    asset.variants[asset.variants.length - 1];
}

/* ---------- batch token mint scheduler ---------- */
