import { cacheGetEntry } from './bitmap-cache.js';
import { proofKeySkipReason } from './events.js';
import {
  deriveTokenBatchEndpoint, fetchControls, getProofKey, nonRetryableError,
  queueTokenBatchRequest, resolveHttpUrl,
} from './network.js';
import { DEFAULTS } from './options.js';
import { boundedInteger, cacheDigest, canonicalSourceWidth, effectiveSampling } from './sampling.js';

/** Build the bounded token endpoint, dimensions, PoP state, and cache key. */
export async function createTokenMintContext({ options, source, tokenId, host, controls, onProofSkipped }) {
  const src = source || {};
  const endpointRaw = src.tokenEndpoint || options.tokenEndpoint;
  if (!endpointRaw) throw new Error('Archx: tokenEndpoint required for {id} sources');
  const endpointUrl = resolveHttpUrl(endpointRaw, { label: 'token endpoint' });
  if (endpointUrl.search || endpointUrl.hash) {
    throw nonRetryableError('Archx: token endpoint must not contain a query or fragment');
  }
  const rect = host.getBoundingClientRect?.();
  const cssWidth = rect?.width || host.clientWidth || 800;
  const cssHeight = rect?.height || host.clientHeight || cssWidth * 0.75;
  const { dprCap, oversample, requestQuality } = effectiveSampling(options);
  const pixelScale = Math.min(globalThis.devicePixelRatio || 1, dprCap) * Math.max(1, oversample);
  const maxSourceWidth = boundedInteger(options.maxSourceWidth, DEFAULTS.maxSourceWidth, 64, 16384);
  const boxW = canonicalSourceWidth(cssWidth * pixelScale, options.sourceWidthBuckets, maxSourceWidth);
  const boxH = canonicalSourceWidth(cssHeight * pixelScale, options.sourceWidthBuckets, maxSourceWidth);
  const fit = ['cover', 'contain', 'fill'].includes(options.fit) ? options.fit : 'cover';
  const tokenMethod = String(options.tokenMethod || 'POST').toUpperCase() === 'GET' ? 'GET' : 'POST';
  const tokenTransport = ['header', 'query', 'auto'].includes(String(options.tokenTransport || 'header').toLowerCase())
    ? String(options.tokenTransport || 'header').toLowerCase() : 'header';
  const proofSetting = options.proofOfPossession;
  const proofMode = proofSetting === false || proofSetting === 'off' ? 'off'
    : proofSetting === true || proofSetting === 'required' ? 'required' : 'auto';
  const proofKey = proofMode === 'off' ? null : await getProofKey(proofMode === 'required');
  const popSkipReason = proofKeySkipReason(proofMode, proofKey);
  if (popSkipReason) onProofSkipped?.(popSkipReason);

  const mintUrl = new URL(endpointUrl.href);
  mintUrl.pathname = `${mintUrl.pathname.replace(/\/?$/, '/')}${encodeURIComponent(tokenId)}`;
  mintUrl.searchParams.set('w', String(boxW));
  mintUrl.searchParams.set('bw', String(boxW));
  mintUrl.searchParams.set('bh', String(boxH));
  mintUrl.searchParams.set('fit', fit);
  if (requestQuality != null) mintUrl.searchParams.set('q', String(requestQuality));

  const tokenCacheKey = cacheDigest([
    'token', 1, options.cacheScope || '', endpointUrl.origin, endpointUrl.pathname, tokenId,
    boxW, boxH, fit, requestQuality, tokenMethod, tokenTransport, proofKey?.jkt || proofMode, controls.credentials,
    options.allowedTokenOrigins || null, options.grid, options.scrambled === true, options.key || '', options.aesKey || '',
    controls.maxResponseBytes, controls.maxDecodedPixels, controls.maxDecodedDimension,
  ]);
  return {
    endpointUrl, boxW, boxH, fit, requestQuality, tokenMethod, tokenTransport,
    proofMode, proofKey, mintUrl, tokenCacheKey,
  };
}

/** Create a benignly-observed shared batch mint, if this viewer can prefetch. */
export async function createPrefetchedTokenMint({
  options,
  tokenId,
  force,
  hasCachedBytes,
  alreadyPrefetched,
  destroyed,
  isAlreadyPrefetched = () => alreadyPrefetched,
  isDestroyed = () => destroyed,
  signal,
  getMintContext,
}) {
  if (options.tokenBatch !== true || isAlreadyPrefetched() || isDestroyed()) return null;
  if (!force && hasCachedBytes) return null;
  if (!tokenId || typeof tokenId !== 'string' || tokenId.length > 256 || /[\u0000-\u001f\u007f]/.test(tokenId)) return null;
  const controls = fetchControls(options);
  let context;
  try { context = await getMintContext(controls); }
  catch { return null; } // _resolveBytes reports the authoritative error in-order.
  if (isDestroyed() || isAlreadyPrefetched() || context.tokenMethod !== 'POST') return null;
  const batchUrl = deriveTokenBatchEndpoint(context.endpointUrl, options);
  if (!batchUrl) return null;
  const cacheBitmap = options.cacheBitmap !== false && options.memory !== 'strict';
  if (!force && cacheBitmap && cacheGetEntry(context.tokenCacheKey)) return null;
  const headers = context.proofKey
    ? { 'X-Archx-Request': 'token', 'X-Archx-Proof-Key': context.proofKey.header }
    : { 'X-Archx-Request': 'token' };
  const promise = queueTokenBatchRequest({
    batchUrl,
    item: {
      id: tokenId,
      w: context.boxW,
      bw: context.boxW,
      bh: context.boxH,
      fit: context.fit,
      ...(context.requestQuality != null ? { q: context.requestQuality } : {}),
    },
    headers,
    credentials: controls.credentials,
    controls,
    signal,
    options,
  });
  // The authoritative await happens inside _resolveBytes. A destroyed or
  // unused prefetch must not surface an unhandled rejection.
  promise.catch(() => {});
  return { key: context.tokenCacheKey, promise };
}
