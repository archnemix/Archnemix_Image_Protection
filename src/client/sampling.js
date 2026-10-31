/**
 * Geometry + source sampling: fit rectangles, canonical width buckets, DPR/oversample, network-aware caps, origin-taint pixel loading.
 */
import { resolveHttpUrl } from './network.js';
import { DEFAULTS } from './options.js';

export function fitRects(srcW, srcH, dstW, dstH, fit) {
  if (fit === 'fill') return { sx: 0, sy: 0, sw: srcW, sh: srcH, dx: 0, dy: 0, dw: dstW, dh: dstH };
  const srcRatio = srcW / srcH;
  const dstRatio = dstW / dstH;
  if (fit === 'contain') {
    let dw = dstW, dh = dstW / srcRatio;
    if (dh > dstH) { dh = dstH; dw = dstH * srcRatio; }
    return { sx: 0, sy: 0, sw: srcW, sh: srcH, dx: (dstW - dw) / 2, dy: (dstH - dh) / 2, dw, dh };
  }
  // cover: crop source
  let sw = srcW, sh = srcH;
  if (srcRatio > dstRatio) sw = srcH * dstRatio; else sh = srcW / dstRatio;
  return { sx: (srcW - sw) / 2, sy: (srcH - sh) / 2, sw, sh, dx: 0, dy: 0, dw: dstW, dh: dstH };
}

export function cyrb53(str, seed = 0) {
  let h1 = 0xdeadbeef ^ seed;
  let h2 = 0x41c6ce57 ^ seed;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return 4294967296 * (2097151 & h2) + (h1 >>> 0);
}

/* Cache keys are digests, not a second long-lived copy of raw URLs, tenant
 * scopes, scramble keys, or AES material. Two independent 53-bit hashes make
 * accidental cross-image collisions negligible for an in-memory page cache. */
export function cacheDigest(parts) {
  const raw = JSON.stringify(parts);
  return `v1:${raw.length}:${cyrb53(raw, 1).toString(36)}:${cyrb53(raw, 2).toString(36)}`;
}

export function boundedInteger(value, fallback, min, max) {
  return Number.isInteger(value) && value >= min && value <= max ? value : fallback;
}

export function normalizeSourceWidthBuckets(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value
    .filter((width) => Number.isInteger(width) && width >= 64 && width <= 16384))]
    .sort((a, b) => a - b)
    .slice(0, 64);
}

export function canonicalSourceWidth(value, bucketsValue, maxWidth) {
  const max = Math.max(1, Math.floor(Number(maxWidth) || 1));
  const requested = Math.max(1, Math.min(max, Math.ceil(Number(value) || 1)));
  const buckets = normalizeSourceWidthBuckets(bucketsValue);
  if (!buckets.length) return requested;
  for (const bucket of buckets) {
    if (bucket >= requested && bucket <= max) return bucket;
  }
  const atOrBelowMax = buckets.filter((bucket) => bucket <= max);
  return atOrBelowMax.length ? atOrBelowMax[atOrBelowMax.length - 1] : requested;
}

/** Best-effort Network Information API snapshot (Chromium-family browsers).
 * Returns null where the API does not exist; callers then keep the
 * configured sampling unchanged. Never used for security decisions. */
export function networkConnectionInfo() {
  try {
    const conn = typeof navigator !== 'undefined' ? navigator.connection : null;
    if (!conn || typeof conn !== 'object') return null;
    return {
      saveData: conn.saveData === true,
      effectiveType: typeof conn.effectiveType === 'string' ? conn.effectiveType : '',
    };
  } catch { return null; }
}

/**
 * Resolve the sampling actually used for derivative requests. With
 * `networkAware`, a Save-Data preference or a slow effective connection
 * caps DPR/oversampling (and numeric request quality) so constrained users
 * receive a materially smaller derivative instead of the full retina asset;
 * an explicit 'lossless' request is never silently downgraded.
 */
export function effectiveSampling(o) {
  let dprCap = Number.isFinite(Number(o.dprCap)) && Number(o.dprCap) > 0 ? Number(o.dprCap) : DEFAULTS.dprCap;
  let oversample = Number.isFinite(Number(o.sourceOversample)) && Number(o.sourceOversample) > 0
    ? Number(o.sourceOversample) : 1;
  let requestQuality = o.requestQuality === 'lossless' ||
    (Number.isInteger(o.requestQuality) && o.requestQuality >= 1 && o.requestQuality <= 100)
    ? o.requestQuality : null;
  if (o.networkAware === true) {
    const conn = networkConnectionInfo();
    const constrained = !!conn && (conn.saveData ||
      conn.effectiveType === 'slow-2g' || conn.effectiveType === '2g');
    const moderate = !!conn && !constrained && conn.effectiveType === '3g';
    if (constrained) {
      dprCap = Math.min(dprCap, 1);
      oversample = Math.min(oversample, 1);
      if (Number.isInteger(requestQuality)) requestQuality = Math.min(requestQuality, 72);
    } else if (moderate) {
      dprCap = Math.min(dprCap, 1.5);
      oversample = Math.min(oversample, 1);
      if (Number.isInteger(requestQuality)) requestQuality = Math.min(requestQuality, 82);
    }
  }
  return { dprCap, oversample, requestQuality };
}

/* ---------- origin-tainted readback (2D canvases) ----------
 * Instance-level API poisoning cannot stop a determined script that reaches
 * the canvas and calls HTMLCanvasElement.prototype.toDataURL.call(canvas).
 * The browser itself can: drawing a cross-origin image WITHOUT CORS
 * approval flips the canvas's origin-clean flag to false, after which
 * toDataURL/toBlob/getImageData/captureStream throw SecurityError no
 * matter how they are invoked, and the taint propagates through
 * createImageBitmap/drawImage into any laundering canvas. Archx draws a
 * 1x1 cross-origin "taint" pixel first and paints the image over it, so
 * displayed pixels are unchanged. The middleware serves the pixel at
 * {basePath}/taint.png; it only helps when that origin differs from the
 * page origin (cross-origin API/CDN deployments) or when the operator
 * supplies any other cross-origin 1x1 via `taintUrl`. Same-origin
 * deployments simply keep the instance-poisoning layer. */
export const taintImageCache = new Map(); // url -> { img, promise }

export function resolveTaintUrl(o, src) {
  if (o.taintReadback === 'off' || o.taintReadback === false) return null;
  try {
    if (o.taintUrl) {
      const url = resolveHttpUrl(o.taintUrl, { label: 'taint image URL' });
      return typeof location !== 'undefined' && url.origin === location.origin ? null : url.href;
    }
    const endpointRaw = (src && typeof src === 'object' && src.tokenEndpoint) || o.tokenEndpoint;
    if (!endpointRaw || typeof location === 'undefined') return null;
    const endpoint = resolveHttpUrl(endpointRaw, { label: 'token endpoint' });
    if (endpoint.origin === location.origin) return null; // same-origin loads cannot taint
    const segments = endpoint.pathname.split('/').filter(Boolean);
    if (segments[segments.length - 1] !== 'token') return null;
    segments[segments.length - 1] = 'taint.png';
    endpoint.pathname = `/${segments.join('/')}`;
    endpoint.search = '';
    endpoint.hash = '';
    return endpoint.href;
  } catch { return null; }
}

export function loadTaintImage(url) {
  let entry = taintImageCache.get(url);
  if (entry) return entry;
  entry = { img: null, promise: null };
  entry.promise = new Promise((resolve) => {
    try {
      const img = new Image();
      img.referrerPolicy = 'no-referrer';
      // Deliberately NO crossOrigin property: a CORS-approved load would
      // stay origin-clean and defeat the entire purpose.
      const timer = setTimeout(() => resolve(entry.img), 3000);
      img.onload = () => { clearTimeout(timer); entry.img = img; resolve(img); };
      img.onerror = () => { clearTimeout(timer); resolve(null); };
      img.src = url;
    } catch { resolve(null); }
  });
  taintImageCache.set(url, entry);
  return entry;
}

export async function ensureTaintImage(o, src) {
  const url = resolveTaintUrl(o, src);
  if (!url) return null;
  const entry = loadTaintImage(url);
  if (entry.img) return entry.img;
  // First paint waits briefly for a 68-byte immutable pixel, never longer:
  // a dead taint host must not delay or block image display.
  return Promise.race([
    entry.promise,
    new Promise((resolve) => setTimeout(() => resolve(entry.img), 1500)),
  ]);
}

export function normalizedHttpCache(value, fallback = 'no-store') {
  const mode = String(value ?? fallback).toLowerCase();
  return ['default', 'no-store', 'reload', 'no-cache', 'force-cache', 'only-if-cached'].includes(mode)
    ? mode
    : fallback;
}

export function fetchPriorityInit(options = {}) {
  const priority = String(options.fetchPriority || '').toLowerCase();
  return ['high', 'low', 'auto'].includes(priority) ? { priority } : {};
}

/* ---------- precomputed asset manifests (archx-build) ---------- */
