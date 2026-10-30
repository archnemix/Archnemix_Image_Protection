/**
 * Server configuration: strict option whitelisting, deny-by-default
 * authorization normalization, path/ID validation, and the production
 * audit helpers. inspectServerConfig is the single place that turns
 * host options into the frozen runtime config the middleware consumes.
 * Re-exported from server/middleware.js for back-compat.
 */
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
export const SECRET_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
/* 1x1 transparent PNG served from `{basePath}/taint.png`. A browser that
 * draws it into a canvas cross-origin WITHOUT CORS approval flips that
 * canvas's origin-clean flag to false, after which every readback API —
 * including prototype-call bypasses of instance-level poisoning — throws
 * SecurityError. The bytes are constant and input-independent. */
export const TAINT_PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=',
  'base64',
);
export const FORMAT_EXTENSIONS = Object.freeze({
  jpeg: ['.jpg', '.jpeg'],
  png: ['.png'],
  webp: ['.webp'],
  avif: ['.avif'],
  gif: ['.gif'],
  tiff: ['.tif', '.tiff'],
});
const KNOWN_WEAK_SECRETS = new Set([
  'secret', 'change-me', 'changeme', 'demo-secret', 'test-secret',
  'demo-secret-change-me-in-production', 'archx-secret',
]);

/** Canonical responsive derivative widths for image-heavy catalogs. Serving a
 * handful of reusable widths instead of every viewport/DPR combination is
 * what lets memory/disk/CDN derivative caches reach a high hit rate. */
export const DEFAULT_WIDTH_BUCKETS = Object.freeze([
  160, 240, 320, 480, 640, 800, 960, 1200, 1440, 1600, 1920, 2240, 2560,
]);

/** Round a requested derivative width to a canonical bucket without ever
 * exceeding the server's entitlement cap. If the cap falls between buckets,
 * the largest bucket at or below the cap wins; exact-width serving remains
 * available by not configuring buckets. */
export function canonicalDerivativeWidth(requestedWidth, widthCap, buckets = DEFAULT_WIDTH_BUCKETS) {
  const cap = Math.floor(Number(widthCap));
  const requested = Math.ceil(Number(requestedWidth));
  if (!Number.isFinite(cap) || cap < 1) return 1;
  if (!Number.isFinite(requested) || requested < 1) return cap;
  const desired = Math.min(cap, requested);
  const normalized = [...new Set((Array.isArray(buckets) ? buckets : [])
    .filter((value) => Number.isInteger(value) && value >= 64 && value <= 8192))]
    .sort((a, b) => a - b);
  if (!normalized.length) return desired;
  for (const bucket of normalized) {
    if (bucket >= desired && bucket <= cap) return bucket;
  }
  const atOrBelowCap = normalized.filter((bucket) => bucket <= cap);
  return atOrBelowCap.length ? atOrBelowCap[atOrBelowCap.length - 1] : desired;
}

export function validateImageId(id) {
  return typeof id === 'string' && ID_RE.test(id);
}

export function isPathInside(parent, child) {
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..' + path.sep) && !path.isAbsolute(rel));
}

export function pathsOverlap(a, b) {
  return isPathInside(a, b) || isPathInside(b, a);
}

export function parseStrictInt(value) {
  if (value == null || !/^\d{1,9}$/.test(String(value))) return null;
  const n = Number(value);
  return Number.isSafeInteger(n) ? n : null;
}

/** Bounded sliding-window limiter. Old clients expire and the client map is
 * hard-capped, so an attacker churning source IPs cannot grow memory forever. */
const WATERMARK_FIELDS = new Set(['text', 'color', 'opacity', 'cornerOpacity', 'tile', 'corner', 'angle']);

/** True only for the bounded string/object shapes that may travel in a token. */
export function validateWatermarkValue(value) {
  try {
    if (typeof value === 'string') return value.length > 0 && value.length <= 512 && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const keys = Object.keys(value);
    if (!keys.length || keys.some((key) => !WATERMARK_FIELDS.has(key))) return false;
    if (value.text !== undefined && (typeof value.text !== 'string' || !value.text || value.text.length > 512)) return false;
    if (value.color !== undefined && (typeof value.color !== 'string' || !value.color || value.color.length > 64)) return false;
    for (const field of ['opacity', 'cornerOpacity']) {
      if (value[field] !== undefined && (typeof value[field] !== 'number' || !Number.isFinite(value[field]) || value[field] < 0 || value[field] > 1)) return false;
    }
    for (const field of ['tile', 'corner']) {
      if (value[field] !== undefined && typeof value[field] !== 'boolean') return false;
    }
    if (value.angle !== undefined && (typeof value.angle !== 'number' || !Number.isFinite(value.angle) || value.angle < -360 || value.angle > 360)) return false;
    return true;
  } catch { return false; }
}

export function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function validateStegoConfig(value) {
  try {
    if (typeof value === 'boolean') return true;
    if (!isPlainObject(value)) return false;
    const fields = new Set(['perToken', 'scope', 'keyScope', 'profile', 'strength', 'gridX', 'gridY', 'layoutVersion', 'legacyCode']);
    if (Object.keys(value).some((field) => !fields.has(field))) return false;
    if (value.perToken !== undefined && typeof value.perToken !== 'boolean') return false;
    if (value.scope !== undefined && !['viewer', 'image'].includes(value.scope)) return false;
    if (value.keyScope !== undefined && !['image', 'viewer'].includes(value.keyScope)) return false;
    if (value.profile !== undefined && !['standard', 'robust'].includes(value.profile)) return false;
    if (value.strength !== undefined && (typeof value.strength !== 'number' || !Number.isFinite(value.strength) || value.strength < 1 || value.strength > 16)) return false;
    if (value.gridX !== undefined && (!Number.isInteger(value.gridX) || value.gridX < 4 || value.gridX > 64)) return false;
    if (value.gridY !== undefined && (!Number.isInteger(value.gridY) || value.gridY < 4 || value.gridY > 64)) return false;
    if (value.layoutVersion !== undefined && ![1, 2, 3, 4].includes(value.layoutVersion)) return false;
    if (value.legacyCode !== undefined && typeof value.legacyCode !== 'boolean') return false;
    return true;
  } catch { return false; }
}

/**
 * Fail-closed normalization of an authorize() result. Ambiguous host return
 * shapes such as `{ allowed:false }`, `{ allow:0 }`, `{ permissions:"view" }`,
 * unknown-only objects, or invalid entitlement values deny instead of being
 * silently widened into an authorized full-size delivery.
 */
export function normalizeAuthorizationResult(auth) {
  try {
    if (auth === true) return Object.freeze({});
    if (!auth || typeof auth !== 'object' || Array.isArray(auth)) return null;
    for (const field of ['allow', 'allowed', 'authorized']) {
      if (field in auth && auth[field] !== true) return null;
    }
    if (auth.deny === true || auth.ok === false || auth.success === false || auth.error) return null;

    let scopes = null;
    if ('permissions' in auth || 'scopes' in auth) {
      const raw = 'permissions' in auth ? auth.permissions : auth.scopes;
      if (!Array.isArray(raw) || raw.some((scope) => typeof scope !== 'string')) return null;
      scopes = raw;
    } else if ('scope' in auth) {
      if (typeof auth.scope !== 'string') return null;
      scopes = auth.scope.split(/[\s,]+/).filter(Boolean);
    }
    if (scopes && !scopes.some((scope) => ['image:view', 'archx:image:view', '*'].includes(scope))) return null;

    const knownFields = [
      'allow', 'allowed', 'authorized', 'viewerId', 'userId', 'subject', 'sessionId',
      'buyerId', 'orderId', 'deliveryId', 'traceId',
      'permissions', 'scopes', 'scope', 'maxWidth', 'quality', 'lossless', 'format',
      'watermark', 'steganography', 'stegoFingerprint', 'ttlSec',
    ];
    if (!knownFields.some((field) => field in auth && auth[field] !== undefined)) return null;

    let viewerId = '';
    for (const field of ['viewerId', 'userId', 'subject', 'sessionId']) {
      if (!(field in auth) || auth[field] == null) continue;
      if (!['string', 'number', 'bigint'].includes(typeof auth[field])) return null;
      viewerId = String(auth[field]);
      if (!viewerId || viewerId.length > 512 || /[\u0000-\u001f\u007f]/.test(viewerId)) return null;
      break;
    }
    const traceFields = {};
    for (const field of ['buyerId', 'orderId', 'deliveryId', 'traceId']) {
      if (!(field in auth) || auth[field] == null) continue;
      if (!['string', 'number', 'bigint'].includes(typeof auth[field])) return null;
      const value = String(auth[field]);
      if (!value || value.length > 256 || /[\u0000-\u001f\u007f]/.test(value)) return null;
      traceFields[field] = value;
    }
    if ('maxWidth' in auth && auth.maxWidth !== undefined &&
        (typeof auth.maxWidth !== 'number' || !Number.isFinite(auth.maxWidth) || auth.maxWidth < 64 || auth.maxWidth > 1000000)) return null;
    if ('quality' in auth && auth.quality !== undefined && auth.quality !== 'lossless' &&
        (!Number.isInteger(auth.quality) || auth.quality < 1 || auth.quality > 100)) return null;
    if ('lossless' in auth && auth.lossless !== undefined && typeof auth.lossless !== 'boolean') return null;
    if ('format' in auth && auth.format !== undefined && !['webp', 'png', 'jpeg', 'avif'].includes(auth.format)) return null;
    if ('ttlSec' in auth && auth.ttlSec !== undefined &&
        (!Number.isInteger(auth.ttlSec) || auth.ttlSec < 5 || auth.ttlSec > 900)) return null;
    if ('watermark' in auth && auth.watermark != null && auth.watermark !== false &&
        typeof auth.watermark !== 'function' &&
        !validateWatermarkValue(auth.watermark)) return null;
    if ('steganography' in auth && auth.steganography !== undefined && !validateStegoConfig(auth.steganography)) return null;
    if ('stegoFingerprint' in auth && auth.stegoFingerprint !== undefined &&
        (typeof auth.stegoFingerprint !== 'string' || !auth.stegoFingerprint || auth.stegoFingerprint.length > 512 || /[\u0000-\u001f\u007f]/.test(auth.stegoFingerprint))) return null;

    const normalized = {};
    for (const field of knownFields) {
      if (!(field in auth) || auth[field] === undefined) continue;
      normalized[field] = isPlainObject(auth[field]) ? { ...auth[field] } : auth[field];
    }
    if (viewerId) normalized.viewerId = viewerId;
    Object.assign(normalized, traceFields);
    return Object.freeze(normalized);
  } catch { return null; }
}

function inspectServerConfig(options = {}) {
  const issues = [];
  const warnings = [];
  const fail = (msg) => issues.push(msg);
  const warn = (msg) => warnings.push(msg);
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    return { ok: false, issues: ['options must be an object'], warnings, config: null };
  }

  const knownTopLevelOptions = new Set([
    'abuseDetection', 'activeSecretId', 'allowAnonymous', 'allowClientQuality', 'allowQueryTokens',
    'taintImage',
    'allowedInputFormats', 'allowedOrigins', 'authorize', 'authorizeTimeoutMs',
    'basePath', 'batchTokenMaxBytes', 'batchTokenMaxItems', 'bindTokenTo',
    'blockUntrustedSharpLoaders', 'cacheMasters',
    'callbackTimeoutMs', 'challenge', 'deploymentMode', 'encrypt', 'forensic', 'forensicPerToken',
    'forensicScope', 'format', 'grid',
    'allowSlowRequestAvif', 'images', 'imagesDir', 'imagesDirs', 'lossless', 'masterCacheMaxBytes',
    'maxConcurrentProcessing', 'maxInputBytes', 'maxInputHeight', 'maxInputPixels',
    'maxInputWidth', 'maxOutputPixels', 'maxTrackedClients', 'maxWidthCap', 'maxWidthFraction', 'onAbuse',
    'onDelivery', 'onProvenanceIssue', 'onSecurityEvent', 'onStegoIssue', 'oneTimeTokenMaxEntries',
    'replaySaturation', 'ownership',
    'oneTimeTokens', 'proofOfPossession', 'provenanceFailure',
    'outputCacheDir', 'memoryProfile', 'outputCacheDiskMaxBytes', 'outputCacheDiskMaxEntries',
    'outputCacheDiskTtlMs', 'outputCacheMax', 'outputCacheMaxBytes', 'processing', 'processingConcurrency',
    'processingQueueMax', 'processingQueueTimeoutMs', 'processingTimeoutSec',
    'publicDir', 'publicDirs', 'quality', 'quotas', 'rateLimitMaxClients',
    'rateLimitPerMinute', 'requireSameSiteTokenRequests', 'requireTokenRequestHeader',
    'scrambleKeyMode', 'scramblePlanVersion', 'secret', 'secretId', 'secrets', 'serverWatermark', 'sharedCacheTtlMs',
    'stateStore', 'stateStoreTimeoutMs', 'steganography',
    'stegoRegistryFailure', 'timeoutSec', 'tokenMethods', 'tokenRateLimitPerMinute',
    'trustProxy', 'trustedProxyHops', 'ttlSec', 'widthBuckets',
  ]);
  for (const field of Object.keys(options)) {
    if (!knownTopLevelOptions.has(field)) fail(`unknown option ${field} (refusing to silently ignore a possible security-setting typo)`);
  }

  const normalizeSecretValue = (value) => {
    if (typeof value === 'string') return value;
    if (value instanceof Uint8Array) {
      return Buffer.isBuffer(value)
        ? value
        : Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    }
    return null;
  };
  const signingKeys = new Map();
  const directSecretId = options.secretId == null || options.secretId === ''
    ? (process.env.ARCHX_SECRET_ID || 'primary')
    : String(options.secretId);
  if (!SECRET_ID_RE.test(directSecretId)) fail('secretId must contain 1-64 letters, digits, dot, underscore, or hyphen characters and start with a letter or digit');
  // An explicit `secrets` keyring is authoritative: do not silently add an
  // ambient ARCHX_SECRET (and potentially make it active) alongside it. The
  // environment remains the fallback for the original single-secret form.
  const directSecretRaw = options.secret ??
    (options.secrets === undefined ? process.env.ARCHX_SECRET : undefined);
  if (directSecretRaw != null && directSecretRaw !== '') {
    const directSecret = normalizeSecretValue(directSecretRaw);
    if (directSecret == null) fail('secret must be a string or byte array');
    else signingKeys.set(directSecretId, directSecret);
  }
  if (options.secrets !== undefined) {
    let entries = null;
    if (options.secrets instanceof Map) entries = [...options.secrets.entries()];
    else if (isPlainObject(options.secrets)) entries = Object.entries(options.secrets);
    if (!entries) fail('secrets must be an object or Map mapping key IDs to secret strings/byte arrays');
    else {
      for (const [keyIdRaw, valueRaw] of entries) {
        const keyId = String(keyIdRaw);
        if (!SECRET_ID_RE.test(keyId)) {
          fail(`secrets key "${keyId}" has an invalid key ID`);
          continue;
        }
        const value = normalizeSecretValue(valueRaw);
        if (value == null || (typeof value === 'string' && !value) || (Buffer.isBuffer(value) && !value.length)) {
          fail(`secrets["${keyId}"] must be a non-empty string or byte array`);
          continue;
        }
        if (signingKeys.has(keyId)) {
          const existing = signingKeys.get(keyId);
          const same = Buffer.isBuffer(existing) && Buffer.isBuffer(value)
            ? existing.equals(value)
            : String(existing) === String(value);
          if (!same) fail(`secrets["${keyId}"] conflicts with secret/secretId`);
          continue;
        }
        signingKeys.set(keyId, value);
      }
    }
  }
  if (signingKeys.size > 16) fail('the signing keyring may contain at most 16 keys');
  let activeSecretId = options.activeSecretId == null || options.activeSecretId === ''
    ? null
    : String(options.activeSecretId);
  if (activeSecretId && !SECRET_ID_RE.test(activeSecretId)) fail('activeSecretId has an invalid key ID');
  if (!activeSecretId) {
    if (signingKeys.has(directSecretId)) activeSecretId = directSecretId;
    else if (signingKeys.size === 1) activeSecretId = signingKeys.keys().next().value;
  }
  if (!signingKeys.size) fail('secret is required (options.secret, options.secrets + activeSecretId, or ARCHX_SECRET)');
  else if (!activeSecretId || !signingKeys.has(activeSecretId)) fail('activeSecretId must identify the key used to sign new tokens');
  const secretDigests = new Set();
  for (const [keyId, value] of signingKeys) {
    const rawSecret = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
    const digest = crypto.createHash('sha256').update(rawSecret).digest('hex');
    if (secretDigests.has(digest)) fail('signing-key IDs must not reuse the same secret value');
    secretDigests.add(digest);
    const secretText = typeof value === 'string' ? value.toLowerCase() : '';
    if (rawSecret.length < 32 || KNOWN_WEAK_SECRETS.has(secretText)) {
      fail(`secret for signing key "${keyId}" must be at least 32 bytes and not a known demo/test value`);
    } else if (new Set(rawSecret).size < 8) {
      warn(`signing key "${keyId}" has very low byte diversity; use at least 32 random bytes from a CSPRNG`);
    }
  }
  const secret = activeSecretId ? signingKeys.get(activeSecretId) : undefined;

  const deploymentMode = options.deploymentMode ?? 'single-instance';
  if (!['single-instance', 'multi-instance'].includes(deploymentMode)) {
    fail("deploymentMode must be 'single-instance' or 'multi-instance'");
  }
  const suppliedStateStore = options.stateStore ?? null;
  if (options.stateStore !== undefined && options.stateStore !== null) {
    const requiredMethods = ['claimOnce', 'hitWindow', 'trackDistinct'];
    if (typeof suppliedStateStore !== 'object' || requiredMethods.some((method) => typeof suppliedStateStore[method] !== 'function')) {
      fail('stateStore must implement claimOnce(key, ttlMs), hitWindow(key, options), and trackDistinct(key, member, options)');
    }
    for (const method of ['getCache', 'setCache', 'stats', 'close']) {
      if (suppliedStateStore?.[method] !== undefined && typeof suppliedStateStore[method] !== 'function') {
        fail(`stateStore.${method} must be a function when present`);
      }
    }
  } else if (options.stateStore === null && deploymentMode === 'multi-instance') {
    fail('stateStore is required in multi-instance deployments');
  }
  if (deploymentMode === 'multi-instance' && !suppliedStateStore) {
    fail('deploymentMode "multi-instance" requires a shared, atomic stateStore; the built-in memory store is process-local');
  }
  if (deploymentMode === 'multi-instance' && suppliedStateStore?.kind === 'memory') {
    fail('the built-in memory stateStore cannot coordinate multiple processes; supply a shared atomic store');
  }
  if (!suppliedStateStore) {
    warn('stateStore defaults to process-local memory: run one middleware process or supply a shared atomic stateStore before scaling horizontally');
  }

  const authorize = options.authorize ?? null;
  if (authorize != null && typeof authorize !== 'function') fail('authorize must be a function');
  if (options.allowAnonymous !== undefined && typeof options.allowAnonymous !== 'boolean') fail('allowAnonymous must be boolean');
  const allowAnonymous = options.allowAnonymous === true;
  if (!authorize && !allowAnonymous) {
    fail('authorize(req, id, { phase }) is required; set allowAnonymous:true only for an intentionally public catalog');
  }
  if (allowAnonymous && !authorize) warn('allowAnonymous is enabled: anyone who can reach the site can request authorized-size derivatives');

  if (options.imagesDir !== undefined && (typeof options.imagesDir !== 'string' || !options.imagesDir)) fail('imagesDir must be a non-empty string');
  if (options.imagesDirs !== undefined && (!Array.isArray(options.imagesDirs) || options.imagesDirs.some((dir) => typeof dir !== 'string' || !dir))) {
    fail('imagesDirs must be an array of non-empty strings');
  }
  if (options.images !== undefined) {
    if (!isPlainObject(options.images) || Object.values(options.images).some((value) => typeof value !== 'string' || !value)) {
      fail('images must be an explicit object map of image id to file path strings');
    }
  }
  if (options.publicDir !== undefined && (typeof options.publicDir !== 'string' || !options.publicDir)) fail('publicDir must be a non-empty string');
  if (options.publicDirs !== undefined && (!Array.isArray(options.publicDirs) || options.publicDirs.some((dir) => typeof dir !== 'string' || !dir))) {
    fail('publicDirs must be an array of non-empty strings');
  }
  const dirs = options.imagesDirs || (options.imagesDir ? [options.imagesDir] : []);
  if ((!Array.isArray(dirs) || !dirs.length) && !options.images) {
    fail('imagesDir, imagesDirs, or an explicit images map is required');
  }
  if (!Array.isArray(dirs)) fail('imagesDirs must be an array');

  const checkInt = (name, value, min, max) => {
    if (value == null) return;
    if (!Number.isInteger(value) || value < min || value > max) fail(`${name} must be an integer from ${min} to ${max}`);
  };
  const checkNumber = (name, value, min, max) => {
    if (value == null) return;
    if (typeof value !== 'number' || !Number.isFinite(value) || value < min || value > max) fail(`${name} must be from ${min} to ${max}`);
  };
  const checkBoolean = (name, value) => {
    if (value !== undefined && typeof value !== 'boolean') fail(`${name} must be boolean`);
  };
  const checkUnknownKeys = (name, value, allowed) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return;
    for (const field of Object.keys(value)) {
      if (!allowed.has(field)) fail(`${name}.${field} is not a supported option`);
    }
  };

  const basePathRaw = options.basePath ?? '/archx';
  const basePathSegments = typeof basePathRaw === 'string' ? basePathRaw.split('/').filter(Boolean) : [];
  if (typeof basePathRaw !== 'string' || basePathRaw.length > 128 || !basePathRaw.startsWith('/') ||
      basePathRaw.includes('\\') || basePathRaw.includes('?') || basePathRaw.includes('#') ||
      basePathSegments.length < 1 || basePathSegments.some((part) => part === '.' || part === '..' || !/^[A-Za-z0-9._~-]+$/.test(part))) {
    fail('basePath must be a simple absolute URL path without traversal, query, or fragment');
  }
  checkInt('ttlSec', options.ttlSec, 5, 900);
  checkInt('batchTokenMaxItems', options.batchTokenMaxItems, 1, 500);
  checkInt('batchTokenMaxBytes', options.batchTokenMaxBytes, 1024, 1024 * 1024);
  if (options.forensicScope !== undefined && !['viewer', 'image'].includes(options.forensicScope)) {
    fail("forensicScope must be 'viewer' or 'image'");
  }
  if (options.widthBuckets !== undefined && options.widthBuckets !== null) {
    if (!Array.isArray(options.widthBuckets) || options.widthBuckets.length > 32 ||
        options.widthBuckets.some((value) => !Number.isInteger(value) || value < 64 || value > 8192)) {
      fail('widthBuckets must be an array of up to 32 integer widths from 64 to 8192, or null to disable canonical widths');
    }
  }
  if (options.outputCacheDir !== undefined && options.outputCacheDir !== null &&
      (typeof options.outputCacheDir !== 'string' || !options.outputCacheDir ||
       options.outputCacheDir.length > 4096 || options.outputCacheDir.includes('\0'))) {
    fail('outputCacheDir must be a non-empty filesystem path string');
  }
  checkInt('outputCacheDiskMaxBytes', options.outputCacheDiskMaxBytes, 0, 16 * 1024 * 1024 * 1024 * 1024);
  checkInt('outputCacheDiskMaxEntries', options.outputCacheDiskMaxEntries, 0, 1000000);
  checkInt('outputCacheDiskTtlMs', options.outputCacheDiskTtlMs, 0, 365 * 24 * 3600 * 1000);
  checkInt('grid', options.grid, 2, 32);
  checkInt('maxWidthCap', options.maxWidthCap, 64, 8192);
  checkNumber('maxWidthFraction', options.maxWidthFraction, 0.05, 1);
  checkInt('callbackTimeoutMs', options.callbackTimeoutMs ?? options.authorizeTimeoutMs, 100, 60000);
  checkInt('trustedProxyHops', options.trustedProxyHops, 0, 20);
  for (const field of [
    'oneTimeTokens', 'encrypt', 'lossless', 'allowClientQuality', 'forensicPerToken',
    'cacheMasters', 'trustProxy', 'requireSameSiteTokenRequests',
    'requireTokenRequestHeader', 'allowQueryTokens', 'taintImage',
  ]) checkBoolean(field, options[field]);
  if (options.quality != null && options.quality !== 'lossless') checkInt('quality', options.quality, 1, 100);
  if (options.format != null && !['webp', 'png', 'jpeg', 'avif'].includes(options.format)) fail("format must be 'webp', 'png', 'jpeg', or 'avif'");
  if (options.scrambleKeyMode != null && !['per-image', 'per-token'].includes(options.scrambleKeyMode)) fail('scrambleKeyMode is invalid');
  if (options.scramblePlanVersion != null && options.scramblePlanVersion !== 1 && options.scramblePlanVersion !== 2) fail('scramblePlanVersion must be 1 or 2');
  checkInt('rateLimitPerMinute', options.rateLimitPerMinute, 1, 1000000);
  checkInt('tokenRateLimitPerMinute', options.tokenRateLimitPerMinute, 1, 1000000);
  checkInt('rateLimitMaxClients', options.rateLimitMaxClients, 10, 1000000);
  checkInt('maxTrackedClients', options.maxTrackedClients, 10, 1000000);
  checkInt('oneTimeTokenMaxEntries', options.oneTimeTokenMaxEntries, 100, 5000000);
  if (options.replaySaturation !== undefined &&
      options.replaySaturation !== 'evict' && options.replaySaturation !== 'strict') {
    fail("replaySaturation must be 'evict' or 'strict'");
  }
  if (options.ownership !== undefined && options.ownership !== null) {
    const own = options.ownership;
    if (!isPlainObject(own) || typeof own.owner !== 'string' || !own.owner || own.owner.length > 128) {
      fail('ownership.owner must be a non-empty string of at most 128 chars');
    }
    for (const field of ['copyright', 'artist']) {
      if (own[field] !== undefined && (typeof own[field] !== 'string' || own[field].length > 256)) {
        fail(`ownership.${field} must be a string of at most 256 chars`);
      }
    }
    if (own.privateKey !== undefined) {
      try {
        const keyObject = crypto.createPrivateKey(String(own.privateKey));
        if (keyObject.asymmetricKeyType !== 'ed25519') fail('ownership.privateKey must be an Ed25519 PEM');
      } catch { fail('ownership.privateKey must be a valid Ed25519 PEM'); }
    }
  }
  checkInt('stateStoreTimeoutMs', options.stateStoreTimeoutMs, 1, 10000);
  checkInt('sharedCacheTtlMs', options.sharedCacheTtlMs, 0, 31 * 24 * 3600 * 1000);

  const tokenMethodsRaw = options.tokenMethods ?? ['POST'];
  if (!Array.isArray(tokenMethodsRaw) || !tokenMethodsRaw.length ||
      tokenMethodsRaw.some((m) => !['GET', 'POST'].includes(String(m).toUpperCase()))) {
    fail("tokenMethods must contain only 'GET' and/or 'POST'");
  } else if (tokenMethodsRaw.map((m) => String(m).toUpperCase()).includes('GET')) {
    warn('GET token minting is enabled for legacy clients; POST is preferred');
  }

  if (options.allowedOrigins != null) {
    if (!Array.isArray(options.allowedOrigins) || options.allowedOrigins.includes('*')) {
      fail("allowedOrigins must be an array of exact origins; '*' is not accepted for credentialed protected delivery");
    } else {
      for (const origin of options.allowedOrigins) {
        try {
          if (new URL(origin).origin !== origin) throw new Error('origin mismatch');
        } catch { fail(`allowedOrigins contains an invalid origin: ${String(origin)}`); }
      }
    }
  }

  if (options.processing !== undefined && (!isPlainObject(options.processing))) fail('processing must be an object');
  const processing = isPlainObject(options.processing) ? options.processing : {};
  checkUnknownKeys('processing', processing, new Set([
    'maxInputBytes', 'maxInputPixels', 'maxInputWidth', 'maxInputHeight', 'maxOutputPixels',
    'processingTimeoutSec', 'timeoutSec', 'allowedInputFormats', 'processingConcurrency',
    'maxConcurrentProcessing', 'processingQueueMax', 'processingQueueTimeoutMs',
    'blockUntrustedSharpLoaders', 'webpEffort', 'encoderEffort', 'webpSmartSubsample',
    'smartSubsample', 'resizeKernel', 'pngCompressionLevel', 'jpegChromaSubsampling',
    'sharpConcurrency', 'sharpCache', 'avifEffort', 'avifChromaSubsampling', 'allowSlowRequestAvif',
  ]));
  const pick = (...names) => {
    for (const name of names) {
      if (options[name] != null) return options[name];
      if (processing[name] != null) return processing[name];
    }
    return undefined;
  };
  // memoryProfile scales the DEFAULTS of the bounded in-memory
  // stores for small containers; explicit options always win.
  const compactProfile = options.memoryProfile === 'compact';
  // AVIF effort >2 costs CPU-seconds per encode: on the REQUEST path
  // it is clamped to 2 unless explicitly allowed (pre-build offline
  // with buildArchxAssets for high-effort AVIF catalogs).
  const avifEffortEffective = pick('allowSlowRequestAvif') === true
    ? (pick('avifEffort') ?? 4)
    : Math.min(pick('avifEffort') ?? 4, 2);
  checkInt('maxInputBytes', pick('maxInputBytes'), 1024, 500 * 1024 * 1024);
  checkInt('maxInputPixels', pick('maxInputPixels'), 10000, 268402689);
  checkInt('maxInputWidth', pick('maxInputWidth'), 64, 65536);
  checkInt('maxInputHeight', pick('maxInputHeight'), 64, 65536);
  checkInt('maxOutputPixels', pick('maxOutputPixels'), 10000, 268402689);
  checkNumber('processingTimeoutSec', pick('processingTimeoutSec', 'timeoutSec'), 1, 120);
  checkInt('processingConcurrency', pick('processingConcurrency', 'maxConcurrentProcessing'), 1, 64);
  checkInt('processingQueueMax', pick('processingQueueMax'), 0, 10000);
  checkInt('processingQueueTimeoutMs', pick('processingQueueTimeoutMs'), 0, 120000);
  checkBoolean('blockUntrustedSharpLoaders', pick('blockUntrustedSharpLoaders'));
  checkInt('webpEffort', pick('webpEffort', 'encoderEffort'), 0, 6);
  checkBoolean('webpSmartSubsample', pick('webpSmartSubsample', 'smartSubsample'));
  checkInt('pngCompressionLevel', pick('pngCompressionLevel'), 0, 9);
  checkInt('sharpConcurrency', pick('sharpConcurrency'), 0, 1024);
  checkBoolean('sharpCache', pick('sharpCache'));
  checkInt('avifEffort', pick('avifEffort'), 0, 9);
  checkBoolean('allowSlowRequestAvif', pick('allowSlowRequestAvif'));
  if (options.memoryProfile !== undefined &&
      options.memoryProfile !== 'standard' && options.memoryProfile !== 'compact') {
    fail("memoryProfile must be 'standard' or 'compact'");
  }
  if (pick('avifChromaSubsampling') !== undefined &&
      !['4:2:0', '4:4:4'].includes(pick('avifChromaSubsampling'))) {
    fail("processing.avifChromaSubsampling must be '4:2:0' or '4:4:4'");
  }
  if (pick('resizeKernel') !== undefined &&
      !['nearest', 'cubic', 'mitchell', 'lanczos2', 'lanczos3', 'mks2013', 'mks2021'].includes(pick('resizeKernel'))) {
    fail('processing.resizeKernel is invalid');
  }
  if (pick('jpegChromaSubsampling') !== undefined &&
      !['4:2:0', '4:4:4'].includes(pick('jpegChromaSubsampling'))) {
    fail("processing.jpegChromaSubsampling must be '4:2:0' or '4:4:4'");
  }
  const allowedInputFormatsRaw = pick('allowedInputFormats') ?? ['jpeg', 'png', 'webp', 'avif'];
  if (!Array.isArray(allowedInputFormatsRaw) || !allowedInputFormatsRaw.length ||
      allowedInputFormatsRaw.some((f) => !FORMAT_EXTENSIONS[String(f).toLowerCase()])) {
    fail('allowedInputFormats contains an unsupported format');
  }

  checkInt('outputCacheMax', options.outputCacheMax, 0, 100000);
  checkInt('outputCacheMaxBytes', options.outputCacheMaxBytes, 0, 4 * 1024 * 1024 * 1024);
  checkInt('masterCacheMaxBytes', options.masterCacheMaxBytes, 0, 4 * 1024 * 1024 * 1024);
  if (options.onSecurityEvent != null && typeof options.onSecurityEvent !== 'function') fail('onSecurityEvent must be a function');
  if (options.onAbuse != null && typeof options.onAbuse !== 'function') fail('onAbuse must be a function');
  if (options.onStegoIssue != null && typeof options.onStegoIssue !== 'function') fail('onStegoIssue must be a function');
  if (options.onProvenanceIssue != null && typeof options.onProvenanceIssue !== 'function') fail('onProvenanceIssue must be a function');
  if (options.onDelivery != null && typeof options.onDelivery !== 'function') fail('onDelivery must be a function');
  if (options.serverWatermark != null && typeof options.serverWatermark !== 'function' &&
      !validateWatermarkValue(options.serverWatermark)) fail('serverWatermark must be a bounded string, watermark object, or function');
  if (options.forensic !== undefined) {
    if (typeof options.forensic !== 'boolean' && !isPlainObject(options.forensic)) {
      fail('forensic must be boolean or an object');
    } else if (isPlainObject(options.forensic)) {
      checkUnknownKeys('forensic', options.forensic, new Set(['blockSize', 'delta', 'signsVersion']));
      checkInt('forensic.blockSize', options.forensic.blockSize, 4, 1024);
      checkNumber('forensic.delta', options.forensic.delta, 0, 16);
      checkInt('forensic.signsVersion', options.forensic.signsVersion, 1, 3);
    }
  }
  if (options.steganography !== undefined && !validateStegoConfig(options.steganography)) {
    fail('steganography must be boolean or a bounded { perToken, scope, keyScope, profile, strength, gridX, gridY, layoutVersion, legacyCode } object');
  }
  if (options.bindTokenTo !== undefined) {
    if (Array.isArray(options.bindTokenTo)) {
      if (options.bindTokenTo.some((entry) => !['ip', 'userAgent', 'ua', 'user-agent', 'session'].includes(entry))) {
        fail("bindTokenTo array entries must be 'ip', 'userAgent'/'ua', or 'session'");
      }
    } else if (!isPlainObject(options.bindTokenTo)) fail('bindTokenTo must be an object or an array of binding names');
    else {
      checkUnknownKeys('bindTokenTo', options.bindTokenTo, new Set(['ip', 'userAgent', 'session']));
      for (const [field, value] of Object.entries(options.bindTokenTo)) {
        if (value === undefined) continue;
        if (typeof value !== 'boolean' && typeof value !== 'function' &&
            (typeof value !== 'string' || !value || value.length > 128 || /[\u0000-\u001f\u007f]/.test(value))) {
          fail(`bindTokenTo.${field} must be boolean, a function, or a bounded header name`);
        }
      }
    }
  }
  if (options.trustProxy === true && !(options.trustedProxyHops > 0)) {
    warn('trustProxy has no effect until trustedProxyHops names the exact number of trusted proxy hops; socket IP remains authoritative');
  }

  if (options.quotas !== undefined && !isPlainObject(options.quotas)) fail('quotas must be an object');
  const quotas = isPlainObject(options.quotas) ? options.quotas : {};
  checkUnknownKeys('quotas', quotas, new Set(['windowMs', 'perIp', 'perViewer', 'perIpImage', 'perViewerImage']));
  for (const name of ['perIp', 'perViewer', 'perIpImage', 'perViewerImage']) {
    if (quotas[name] != null) checkInt(`quotas.${name}`, quotas[name], 1, 100000000);
  }
  checkInt('quotas.windowMs', quotas.windowMs, 1000, 31 * 24 * 3600 * 1000);

  if (options.abuseDetection !== undefined && !isPlainObject(options.abuseDetection)) fail('abuseDetection must be an object');
  const abuse = isPlainObject(options.abuseDetection) ? options.abuseDetection : {};
  checkUnknownKeys('abuseDetection', abuse, new Set(['distinctImages', 'windowMs', 'action']));
  checkInt('abuseDetection.distinctImages', abuse.distinctImages, 1, 10000);
  checkInt('abuseDetection.windowMs', abuse.windowMs, 1000, 31 * 24 * 3600 * 1000);
  if (abuse.action != null && !['event', 'deny', 'challenge'].includes(abuse.action)) fail("abuseDetection.action must be 'event', 'deny', or 'challenge'");
  if (options.challenge !== undefined && !isPlainObject(options.challenge)) fail('challenge must be an object');
  const challenge = isPlainObject(options.challenge) ? options.challenge : {};
  checkUnknownKeys('challenge', challenge, new Set(['verify', 'header', 'clearanceTtlSec']));
  if (challenge.verify != null && typeof challenge.verify !== 'function') fail('challenge.verify must be a function');
  if (challenge.header != null && (typeof challenge.header !== 'string' || !/^[a-z0-9-]{1,64}$/.test(challenge.header))) fail('challenge.header must be a lowercase HTTP header name');
  checkInt('challenge.clearanceTtlSec', challenge.clearanceTtlSec, 30, 86400);
  if (abuse.action === 'challenge' && typeof challenge.verify !== 'function') {
    fail("abuseDetection.action 'challenge' requires challenge.verify (e.g. a Turnstile siteverify or WebAuthn assertion check)");
  }

  const availableParallelism = typeof os.availableParallelism === 'function' ? os.availableParallelism() : (os.cpus()?.length || 2);
  const config = Object.freeze({
    secret,
    signingKeys: Object.freeze(Object.fromEntries(signingKeys)),
    activeSecretId,
    deploymentMode,
    stateStore: suppliedStateStore,
    stateStoreTimeoutMs: options.stateStoreTimeoutMs ?? 250,
    sharedCacheTtlMs: options.sharedCacheTtlMs ?? 3600000,
    authorize,
    allowAnonymous,
    basePath: String(basePathRaw).replace(/\/$/, '') || '/archx',
    ttlMs: (options.ttlSec ?? 120) * 1000,
    grid: options.grid ?? 8,
    maxWidthCap: options.maxWidthCap ?? 1920,
    // Strict-preview policy: delivered width may never exceed this
    // fraction of the master's own width (1 = full-resolution pixels
    // allowed when other caps permit). Protects asset classes whose
    // masters must never be delivered at native resolution even to
    // entitled viewers.
    maxWidthFraction: options.maxWidthFraction ?? 1,
    widthBuckets: options.widthBuckets == null
      ? null
      : Object.freeze([...new Set(options.widthBuckets)].sort((a, b) => a - b)),
    batchTokenMaxItems: options.batchTokenMaxItems ?? 100,
    batchTokenMaxBytes: options.batchTokenMaxBytes ?? 65536,
    forensicScope: options.forensicScope ?? 'viewer',
    tokenMethods: Object.freeze([...new Set((tokenMethodsRaw || ['POST']).map((m) => String(m).toUpperCase()))]),
    oneTimeTokens: options.oneTimeTokens !== false,
    rateLimitMaxClients: options.rateLimitMaxClients ?? options.maxTrackedClients ?? (compactProfile ? 2500 : 10000),
    oneTimeTokenMaxEntries: options.oneTimeTokenMaxEntries ?? (compactProfile ? 50000 : 250000),
    replaySaturation: options.replaySaturation === 'strict' ? 'strict' : 'evict',
    ownership: (() => {
      if (!isPlainObject(options.ownership) || !options.ownership.owner) return null;
      const own = options.ownership;
      let privateKey = null, publicKeyFingerprint = null;
      if (own.privateKey) {
        privateKey = crypto.createPrivateKey(String(own.privateKey));
        const der = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
        publicKeyFingerprint = crypto.createHash('sha256').update(der).digest('hex').slice(0, 32);
      }
      return Object.freeze({
        owner: String(own.owner),
        copyright: own.copyright ? String(own.copyright) : null,
        artist: own.artist ? String(own.artist) : null,
        privateKey,
        publicKeyFingerprint,
      });
    })(),
    processing: Object.freeze({
      maxInputBytes: pick('maxInputBytes') ?? 50 * 1024 * 1024,
      maxInputPixels: pick('maxInputPixels') ?? 50000000,
      maxInputWidth: pick('maxInputWidth') ?? 12000,
      maxInputHeight: pick('maxInputHeight') ?? 12000,
      maxOutputPixels: pick('maxOutputPixels') ?? 16777216,
      timeoutSec: Number(pick('processingTimeoutSec', 'timeoutSec') ?? 10),
      allowedInputFormats: Object.freeze(allowedInputFormatsRaw.map((f) => String(f).toLowerCase())),
      blockUntrustedSharpLoaders: pick('blockUntrustedSharpLoaders') !== false,
      webpEffort: pick('webpEffort', 'encoderEffort') ?? 4,
      webpSmartSubsample: pick('webpSmartSubsample', 'smartSubsample') !== false,
      resizeKernel: pick('resizeKernel') ?? 'lanczos3',
      pngCompressionLevel: pick('pngCompressionLevel') ?? 9,
      jpegChromaSubsampling: pick('jpegChromaSubsampling') ?? '4:4:4',
      avifEffort: avifEffortEffective,
      allowSlowRequestAvif: pick('allowSlowRequestAvif') === true,
      avifChromaSubsampling: pick('avifChromaSubsampling') ?? '4:2:0',
      sharpConcurrency: pick('sharpConcurrency') ?? 0,
      sharpCache: pick('sharpCache'),
    }),
    processingConcurrency: pick('processingConcurrency', 'maxConcurrentProcessing') ?? Math.max(1, Math.min(4, availableParallelism || 2)),
    processingQueueMax: pick('processingQueueMax') ?? (compactProfile ? 25 : 100),
    processingQueueTimeoutMs: pick('processingQueueTimeoutMs') ?? 5000,
    quotas: Object.freeze({
      windowMs: quotas.windowMs ?? 3600000,
      perIp: quotas.perIp ?? null,
      perViewer: quotas.perViewer ?? null,
      perIpImage: quotas.perIpImage ?? null,
      perViewerImage: quotas.perViewerImage ?? null,
    }),
    abuseDetection: Object.freeze({
      distinctImages: abuse.distinctImages ?? 250,
      windowMs: abuse.windowMs ?? 600000,
      action: abuse.action ?? 'event',
    }),
    challenge: typeof challenge.verify === 'function' ? Object.freeze({
      verify: challenge.verify,
      header: challenge.header || 'x-archx-challenge',
      clearanceTtlSec: challenge.clearanceTtlSec ?? 600,
    }) : null,
    outputCacheMax: options.outputCacheMax ?? (compactProfile ? 32 : 100),
    outputCacheMaxBytes: options.outputCacheMaxBytes ?? (compactProfile ? 16 : 64) * 1024 * 1024,
    outputCacheDir: options.outputCacheDir ?? null,
    outputCacheDiskMaxBytes: options.outputCacheDiskMaxBytes ?? 2 * 1024 * 1024 * 1024,
    outputCacheDiskMaxEntries: options.outputCacheDiskMaxEntries ?? 20000,
    outputCacheDiskTtlMs: options.outputCacheDiskTtlMs ?? 30 * 24 * 3600 * 1000,
    masterCacheMaxBytes: options.masterCacheMaxBytes ?? (compactProfile ? 32 : 128) * 1024 * 1024,
    memoryProfile: compactProfile ? 'compact' : 'standard',
    cacheMasters: options.cacheMasters !== false,
    trustProxy: options.trustProxy === true && (options.trustedProxyHops ?? 0) > 0,
    trustedProxyHops: options.trustedProxyHops ?? 0,
    requireSameSiteTokenRequests: options.requireSameSiteTokenRequests !== false,
    requireTokenRequestHeader: options.requireTokenRequestHeader !== false,
    // Bearer tokens belong in X-Archx-Token by default. Query transport is
    // retained only as an explicit compatibility opt-in because URL tokens
    // leak through history, Referer headers, screenshots of logs, and many
    // proxy/telemetry pipelines.
    allowQueryTokens: options.allowQueryTokens === true,
    // Public constant-bytes 1x1 PNG used to origin-taint 2D display canvases
    // in cross-origin deployments (see TAINT_PNG). Disable only if the host
    // route policy forbids any unauthenticated route under basePath.
    taintImage: options.taintImage !== false,
    scramblePlanVersion: options.scramblePlanVersion ?? 2,
    encrypt: options.encrypt === true,
    scrambleKeyMode: options.scrambleKeyMode || 'per-image',
    proofOfPossession: options.proofOfPossession === true ? 'required'
      : options.proofOfPossession === false ? 'off'
        : (options.proofOfPossession ?? 'optional'),
    callbackTimeoutMs: options.callbackTimeoutMs ?? options.authorizeTimeoutMs ?? 10000,
    stegoRegistryFailure: options.stegoRegistryFailure ?? 'deny',
    provenanceFailure: options.provenanceFailure ?? 'deny',
    publicDirs: Object.freeze([
      ...(options.publicDir ? [options.publicDir] : []),
      ...(Array.isArray(options.publicDirs) ? options.publicDirs : []),
    ]),
  });
  if (!['deny', 'allow'].includes(config.stegoRegistryFailure)) fail("stegoRegistryFailure must be 'deny' or 'allow'");
  if (!['deny', 'allow'].includes(config.provenanceFailure)) fail("provenanceFailure must be 'deny' or 'allow'");
  if (!['optional', 'required', 'off'].includes(config.proofOfPossession)) {
    fail("proofOfPossession must be 'optional', 'required', 'off', true, or false");
  }
  if (config.allowQueryTokens) warn('allowQueryTokens is enabled for compatibility: bearer tokens can leak through URLs, history, Referer headers, and logs; prefer header transport');
  if (config.proofOfPossession === 'off') warn('proofOfPossession is off: tokens remain bearer tokens if copied before expiry');
  if (config.proofOfPossession === 'optional') warn("proofOfPossession is optional: only tokens minted with a browser proof key are sender-constrained; use 'required' for the hardened production baseline when every supported client can present proofs");
  if (config.abuseDetection.action === 'event') warn("abuseDetection.action is 'event': suspicious distinct-image access is recorded through onSecurityEvent but is not blocked by Archx unless the host acts on it or selects action:'deny'/'challenge'");
  if (options.steganography && !options.onStegoIssue) warn('StegoMark is enabled without onStegoIssue: fingerprints will not be registered to a viewer/order, sharply limiting leak tracing');
  if (options.encrypt === true) warn('encrypt is enabled: the AES and scramble keys in the mint response are necessarily visible to the authorized browser/page and are not secrets from that viewer');
  if (options.allowClientQuality) warn('allowClientQuality lets browsers request quality up to the server entitlement; keep authorize() caps strict');
  if (config.oneTimeTokens === false) warn('oneTimeTokens is disabled: signed tokens can be replayed until expiry');
  if (!config.widthBuckets?.length) warn('widthBuckets is not configured: every viewport/DPR combination can create a distinct derivative and fragment the output cache; image-heavy sites should use canonical widths');
  if (!config.outputCacheDir && !suppliedStateStore) warn('no persistent outputCacheDir or shared state-store cache is configured: derivative reuse is limited to this process memory and is lost on restart');
  if (options.scrambleKeyMode === 'per-token') warn('scrambleKeyMode per-token makes every issued view a distinct derivative, defeating cross-viewer output caching');
  if (options.encrypt !== true) warn('encrypt is off: scrambled payloads are obfuscation only and can be reassembled keylessly by tile-edge continuity (jigsaw) solvers — enable encrypt:true for payload secrecy');
  const avifEffortWarn = options.processing?.avifEffort ?? options.avifEffort;
  if (options.lossless === true && (options.maxWidthFraction ?? 1) >= 1 && (options.maxWidthCap ?? 1920) >= 1920) {
    warn('lossless delivery with maxWidthFraction 1 and a high maxWidthCap lets an entitled viewer receive the master\'s FULL-RESOLUTION pixels (the original file/metadata are still never served, but pixel-for-pixel content is). If these asset classes must stay previews, set maxWidthFraction < 1 (e.g. 0.6) or disable lossless');
  }
  const allowSlowAvif = (options.processing?.allowSlowRequestAvif ?? options.allowSlowRequestAvif) === true;
  if (options.format === 'avif' && (avifEffortWarn ?? 4) > 2 && allowSlowAvif) {
    warn(`dynamic AVIF encoding at effort ${avifEffortWarn ?? 4} costs multiple CPU-seconds per image and can exceed processingTimeoutSec at large sizes (allowSlowRequestAvif is set); consider pre-building AVIF offline`);
  } else if ((avifEffortWarn ?? 4) > 2 && !allowSlowAvif) {
    warn(`avifEffort ${avifEffortWarn ?? 4} is clamped to 2 on the request path (set allowSlowRequestAvif: true to override, or pre-build AVIF offline)`);
  }
  if (options.scramblePlanVersion === 1) warn('scramblePlanVersion 1 uses a 32-bit plan seed (brute-forceable permutation, ~17 s on a 64-core host); v2 (128-bit) has been the default since 1.15 — v1 remains only for pre-1.10 cached clients');
  if (options.forensic && config.forensicScope !== 'image') warn('viewer-scoped forensic marks make derivatives viewer-specific and reduce output-cache sharing; use forensicScope image for reusable catalog derivatives');
  const stegoCfgForWarning = typeof options.steganography === 'object' && options.steganography ? options.steganography : {};
  if (options.steganography && stegoCfgForWarning.scope !== 'image') warn('viewer/token-scoped StegoMark makes derivatives hard to share across viewers; use steganography { scope: "image", perToken: false } for reusable catalog derivatives');
  return { ok: issues.length === 0, issues, warnings, config: issues.length ? null : config };
}

/** Non-throwing production configuration audit. Never returns the secret. */
export function auditArchxServerConfig(options = {}) {
  let inspected;
  try { inspected = inspectServerConfig(options); }
  catch { inspected = { ok: false, issues: ['options could not be inspected safely'], warnings: [], config: null }; }
  const { ok, issues, warnings, config } = inspected;
  return Object.freeze({
    ok,
    issues: Object.freeze([...issues]),
    warnings: Object.freeze([...warnings]),
    summary: config ? Object.freeze({
      basePath: config.basePath,
      authorization: config.authorize ? 'authorize-callback' : 'explicit-anonymous',
      deploymentMode: config.deploymentMode,
      stateStore: config.stateStore ? (config.stateStore.kind || 'custom') : 'memory',
      activeSecretId: config.activeSecretId,
      signingKeyCount: Object.keys(config.signingKeys).length,
      tokenMethods: config.tokenMethods,
      oneTimeTokens: config.oneTimeTokens,
      oneTimeTokenMaxEntries: config.oneTimeTokenMaxEntries,
      replaySaturation: config.replaySaturation,
      ownership: config.ownership
        ? { owner: config.ownership.owner, signed: !!config.ownership.privateKey, publicKeyFingerprint: config.ownership.publicKeyFingerprint }
        : null,
      maxWidthCap: config.maxWidthCap,
      maxWidthFraction: config.maxWidthFraction,
      widthBuckets: config.widthBuckets,
      batchTokenMaxItems: config.batchTokenMaxItems,
      forensicScope: config.forensicScope,
      diskOutputCache: !!config.outputCacheDir,
      processing: config.processing,
      processingConcurrency: config.processingConcurrency,
      requireTokenRequestHeader: config.requireTokenRequestHeader,
      requireSameSiteTokenRequests: config.requireSameSiteTokenRequests,
      allowQueryTokens: config.allowQueryTokens,
      taintImage: config.taintImage,
      scramblePlanVersion: config.scramblePlanVersion,
      proofOfPossession: config.proofOfPossession,
      abuseDetection: config.abuseDetection,
      stepUpChallenge: config.challenge ? 'configured' : 'off',
      quotasConfigured: Object.values(config.quotas).some((value) => typeof value === 'number' && value > 0),
      stegoRegistryConfigured: typeof options.onStegoIssue === 'function',
      provenanceHookConfigured: typeof options.onProvenanceIssue === 'function',
      deliveryHookConfigured: typeof options.onDelivery === 'function',
      securityEventHookConfigured: typeof (options.onSecurityEvent || options.onAbuse) === 'function',
      trustProxy: config.trustProxy,
      trustedProxyHops: config.trustedProxyHops,
      encrypt: config.encrypt,
      scrambleKeyMode: config.scrambleKeyMode,
    }) : null,
  });
}

/**
 * Defaults for a hardened paid/premium deployment. This helper only fills
 * fields the host left undefined; it cannot supply the secret, masters,
 * authorization callback, quotas, shared store, or client compatibility
 * decision for proof-of-possession. Run auditArchxProductionConfig() on the
 * final options in deployment tests.
 */
export function withHardenedProductionDefaults(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('Archx hardened production defaults: options must be an object');
  }
  const abuse = isPlainObject(options.abuseDetection) ? options.abuseDetection : {};
  return {
    tokenMethods: ['POST'],
    requireSameSiteTokenRequests: true,
    requireTokenRequestHeader: true,
    allowQueryTokens: false,
    proofOfPossession: 'required',
    oneTimeTokens: true,
    // Fail-closed replay semantics: when the one-time claim store
    // saturates, the hardened preset rejects NEW claims rather than
    // evicting live ones (availability cost belongs to the operator
    // who sized the store; a silent replay window does not). Size
    // oneTimeTokenMaxEntries >= peak mints x token TTL x margin.
    replaySaturation: 'strict',
    ttlSec: 120,
    callbackTimeoutMs: 10000,
    scramblePlanVersion: 2, // 128-bit permutation seed (see buildScramblePlan)
    // Per-token keys: a captured payload + the key from someone else's
    // cheaper/faster view must never combine. Costs cross-viewer
    // derivative caching (the catalog preset keeps per-image keys,
    // which since 1.15 are variant-scoped w/q/fmt).
    scrambleKeyMode: 'per-token',
    // Scrambling alone is obfuscation: tile-edge continuity solvers can
    // reassemble unencrypted payloads without any key. AES-256-GCM is the
    // actual secrecy layer, so the hardened preset turns it on.
    encrypt: true,
    stegoRegistryFailure: 'deny',
    provenanceFailure: 'deny',
    ...options,
    // One libvips thread per job (the middleware already parallelizes
    // jobs; N_cores x N_jobs only oversubscribes) and no libvips
    // operation cache (Archx has its own bounded master/base/output
    // caches; vips' 50 MB arena is then pure steady-state RSS).
    processing: {
      sharpConcurrency: 1,
      sharpCache: false,
      ...(isPlainObject(options.processing) ? options.processing : {}),
    },
    abuseDetection: {
      distinctImages: 250,
      windowMs: 600000,
      ...abuse,
      action: abuse.action ?? 'deny',
    },
  };
}

/**
 * Defaults for a high-traffic, image-heavy catalog. This helper deliberately
 * optimizes for *transform once, reuse many times*: canonical widths, larger
 * bounded caches, faster WebP settings, image-scoped (rather than per-viewer)
 * baked marks when those marks are already enabled, and batch minting. It
 * does not supply authorization, secrets, masters, a state store, or a cache
 * directory, and it does not weaken token entitlement checks. Host-supplied
 * fields always win, including per-viewer tracing when a paid/high-value
 * workflow needs it more than cache sharing.
 */
export function withCatalogThroughputDefaults(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('Archx catalog throughput defaults: options must be an object');
  }
  const processing = isPlainObject(options.processing) ? options.processing : {};
  let steganography = options.steganography;
  if (steganography === true) {
    steganography = { perToken: false, scope: 'image' };
  } else if (isPlainObject(steganography)) {
    steganography = { perToken: false, scope: 'image', ...steganography };
  }
  const available = typeof os.availableParallelism === 'function'
    ? os.availableParallelism()
    : (os.cpus()?.length || 2);
  const out = {
    quality: 88,
    format: 'webp',
    scrambleKeyMode: 'per-image',
    widthBuckets: [...DEFAULT_WIDTH_BUCKETS],
    batchTokenMaxItems: 100,
    outputCacheMax: 1000,
    outputCacheMaxBytes: 256 * 1024 * 1024,
    masterCacheMaxBytes: 256 * 1024 * 1024,
    sharedCacheTtlMs: 24 * 3600 * 1000,
    forensicPerToken: false,
    forensicScope: 'image',
    processingConcurrency: Math.max(1, Math.min(8, available || 2)),
    processingQueueMax: 500,
    ...options,
    processing: {
      webpEffort: 2,
      webpSmartSubsample: false,
      resizeKernel: 'lanczos2',
      pngCompressionLevel: 6,
      jpegChromaSubsampling: '4:2:0',
      sharpConcurrency: 1,
      sharpCache: false,
      ...processing,
    },
  };
  if (options.steganography !== undefined) out.steganography = steganography;
  return out;
}

/**
 * Stricter, named production-readiness audit. `auditArchxServerConfig()`
 * answers "is this configuration internally valid and fail-closed?" This
 * audit additionally answers "does it match the hardened baseline for a
 * valuable catalog?" It never returns secret values.
 */
export function auditArchxProductionConfig(options = {}, { expectedInstances = 1 } = {}) {
  const base = auditArchxServerConfig(options);
  const blockers = [...base.issues];
  const recommendations = [];
  if (!Number.isInteger(expectedInstances) || expectedInstances < 1 || expectedInstances > 10000) {
    blockers.push('expectedInstances must be an integer from 1 to 10000');
  }
  const summary = base.summary;
  if (summary) {
    if (summary.authorization !== 'authorize-callback') blockers.push('production deployments for valuable images need an authorize() callback; explicit anonymous access is a public catalog, not an entitlement boundary');
    if (summary.allowQueryTokens) blockers.push('allowQueryTokens must be false so bearer tokens stay out of URLs, history, Referer headers, and logs');
    if (summary.proofOfPossession !== 'required') blockers.push("proofOfPossession must be explicitly set to 'required' for the hardened baseline, after confirming every supported client can present proofs");
    if (!summary.oneTimeTokens) blockers.push('oneTimeTokens must be enabled');
    if (summary.oneTimeTokens && summary.oneTimeTokenMaxEntries < 10000) {
      blockers.push('oneTimeTokenMaxEntries is very small: the replay store must hold a full token-TTL of JTIs at peak mint rate or live entries are evicted (see archx.replay_store_evicted)');
    }
    if (summary.oneTimeTokens && summary.replaySaturation !== 'strict') {
      recommendations.push("replaySaturation is 'evict' (availability mode): under sustained mint pressure the in-memory store can evict a live JTI and reopen a narrow replay window for that one signed, re-authorized token (watch archx.replay_store_evicted). Set replaySaturation: 'strict' to reject new claims instead, accepting redemption failures while saturated — size oneTimeTokenMaxEntries to peak-claim-rate × token TTL × safety margin either way");
    }
    if (!summary.encrypt) blockers.push('encrypt must be true: unencrypted scrambled payloads are reassembled keylessly by tile-edge (jigsaw) solvers in well under a second');
    if (summary.scramblePlanVersion !== 2) blockers.push('scramblePlanVersion must be 2: the v1 plan seed is 32-bit and brute-forceable');
    if (summary.tokenMethods.some((method) => method !== 'POST')) blockers.push("tokenMethods must be ['POST'] for the hardened baseline");
    if (!summary.requireTokenRequestHeader) blockers.push('requireTokenRequestHeader must be enabled');
    if (!summary.requireSameSiteTokenRequests) blockers.push('requireSameSiteTokenRequests must be enabled');
    if (Number.isInteger(expectedInstances) && expectedInstances > 1 &&
        (summary.deploymentMode !== 'multi-instance' || summary.stateStore === 'memory')) {
      blockers.push('expectedInstances > 1 requires deploymentMode multi-instance with a shared, atomic stateStore');
    }
    if (options.steganography && !summary.stegoRegistryConfigured) {
      blockers.push('StegoMark is enabled without onStegoIssue, so issued fingerprints cannot be traced to a buyer/order/delivery registry');
    }
    if (summary.abuseDetection.action !== 'deny') recommendations.push("abuseDetection.action is 'event': Archx records suspicious access but does not block it; select 'deny' or document the host response runbook");
    if (!summary.quotasConfigured) recommendations.push('configure per-viewer/IP/image quotas appropriate to the catalog and pricing model');
    if (!summary.securityEventHookConfigured) recommendations.push('configure onSecurityEvent and alert on replay, quota, scraping, registry, and state-store events');
    if (expectedInstances === 1 && summary.stateStore === 'memory') recommendations.push('the memory state store is valid only for one middleware process; declare and test the shared-store topology before adding a second process');
    if (!summary.provenanceHookConfigured) recommendations.push('configure onProvenanceIssue if an external C2PA/provenance registry or reverse-image monitoring workflow needs a signed issuance record');
    if (!summary.deliveryHookConfigured) recommendations.push('configure onDelivery if token issuance/redemption must feed monitoring, reverse-image-search, or enforcement systems');
    if (!summary.widthBuckets?.length) recommendations.push('configure widthBuckets (or withCatalogThroughputDefaults) so thousands of viewport/DPR combinations reuse a small set of derivatives');
    if (!summary.diskOutputCache && summary.stateStore === 'memory') recommendations.push('configure outputCacheDir on a persistent non-public volume and/or a shared cache-capable stateStore so cold Sharp work survives restarts and is shared across the fleet');
    if (options.scrambleKeyMode === 'per-token' || options.forensicPerToken === true) recommendations.push('per-token scramble/forensic material defeats cross-viewer derivative reuse; reserve it for high-value views and use shared catalog derivatives for ordinary browsing');
    if (options.encrypt === true) recommendations.push('encrypt derives a per-token AES key, so encrypted derivatives cannot be reused across viewers; reserve it for high-value views when catalog-scale derivative sharing matters');
  }
  return Object.freeze({
    ok: base.ok,
    ready: blockers.length === 0,
    blockers: Object.freeze([...new Set(blockers)]),
    recommendations: Object.freeze(recommendations),
    warnings: base.warnings,
    summary,
  });
}

export function normalizeServerConfig(options = {}) {
  const inspected = inspectServerConfig(options);
  if (!inspected.ok) {
    throw new TypeError('Archx server configuration is invalid:\n- ' + inspected.issues.join('\n- '));
  }
  return inspected.config;
}
