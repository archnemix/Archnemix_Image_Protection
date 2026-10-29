/**
 * Server-side image scrambling (Node + sharp).
 * Takes a master image, down-scales it to web resolution, strips metadata,
 * tile-scrambles its pixels, and (optionally) AES-GCM-encrypts the result
 * inside an .archx container. The master file itself is never sent.
 */
import { createRequire } from 'node:module';
import { signOwnershipClaim, applyOwnershipMetadata } from './ownership.js';
import { Worker } from 'node:worker_threads';
import {
  buildScramblePlan, paddedSize, scramblePixels, scramblePixelsPadded,
  encodeContainer, encryptPayload, generateKeyBase64, applyForensicBlocks,
  embedStegoFingerprint, stegoFingerprint, sniffImageInfo, sha256Bytes,
  perceptualFingerprint as computePerceptualFingerprint,
} from '../src/scramble.js';

// Lazy libvips: importing this module (e.g. through the /server
// re-exports in a token-only worker) must not load Sharp's native
// binary until an image operation actually runs. Token/control-plane
// processes save the native RSS (35-55 MB) and can boot even where
// sharp is not installed; image workers pay one require, once.
const require = createRequire(import.meta.url);
let _sharp = null;
function getSharp() {
  if (!_sharp) {
    const mod = require('sharp');
    _sharp = mod?.default || mod;
  }
  return _sharp;
}
function getSharpOptional() {
  try { return getSharp(); } catch { return null; }
}

export { generateKeyBase64 };

const SHARP_LOADERS = Object.freeze({
  jpeg: 'VipsForeignLoadJpeg',
  png: 'VipsForeignLoadPng',
  webp: 'VipsForeignLoadWebp',
  avif: 'VipsForeignLoadHeif',
  gif: 'VipsForeignLoadNsgif',
  tiff: 'VipsForeignLoadTiff',
});
let sharpLoadersBlocked = false;
const sharpLoadersUnblocked = new Set();
// Loader policy state, keyed by the canonical wanted-set (<= 64
// combinations of 6 loaders + SVG): direct configureSharpSecurity()
// calls are PERMANENT process policy; middleware instances hold
// refcounted LEASES released by handler.close(). The effective
// unblocked set is the intersection of all permanents and live
// leases, so the strictest live configuration wins — but closing a
// strict instance restores its looser siblings, and one per-call
// scrambleImage can no longer narrow loaders for the whole process.
const sharpSecurityPermanent = new Map(); // key -> Set<operation>
const sharpSecurityLeases = new Map(); // key -> { wanted, count }

function sharpWantedSet(allowedFormats) {
  const wanted = new Set(['VipsForeignLoadSvg']);
  for (const format of allowedFormats || []) {
    const operation = SHARP_LOADERS[String(format).toLowerCase()];
    if (operation) wanted.add(operation);
  }
  return wanted;
}
function reconcileSharpLoaders() {
  const sharp = getSharpOptional();
  if (!sharp || typeof sharp.block !== 'function' || typeof sharp.unblock !== 'function') return false;
  if (!sharpLoadersBlocked) {
    sharp.block({ operation: ['VipsForeignLoad'] });
    sharpLoadersBlocked = true;
  }
  let effective = null;
  const intersect = (set) => {
    effective = effective === null ? new Set(set) : new Set([...effective].filter((op) => set.has(op)));
  };
  for (const set of sharpSecurityPermanent.values()) intersect(set);
  for (const lease of sharpSecurityLeases.values()) intersect(lease.wanted);
  if (effective === null) {
    // Baseline when nothing has configured policy yet: the root loader
    // stays blocked (PDF/Magick/OpenSlide/FITS/raw can never load),
    // while SVG (internal watermarks) and the six known raster loaders
    // run. Per-call/per-deployment format allowlists are enforced at
    // the sniff + metadata gates regardless.
    effective = new Set(['VipsForeignLoadSvg', ...Object.values(SHARP_LOADERS)]);
  }
  const toUnblock = [...effective].filter((op) => !sharpLoadersUnblocked.has(op));
  if (toUnblock.length) {
    sharp.unblock({ operation: toUnblock });
    for (const op of toUnblock) sharpLoadersUnblocked.add(op);
  }
  const toReblock = [...sharpLoadersUnblocked].filter((op) => !effective.has(op));
  if (toReblock.length) {
    sharp.block({ operation: toReblock });
    for (const op of toReblock) sharpLoadersUnblocked.delete(op);
  }
  return true;
}

/**
 * Restrict libvips' native file loaders to the formats Archx actually uses.
 * Sharp/libvips choose a loader by sniffing content, so an extension check
 * alone cannot stop a GIF/TIFF/SVG/PDF parser from being reached. This is a
 * process-global Sharp setting; the internally generated SVG watermark and
 * the explicitly allowed master formats are unblocked.
 *
 * Direct calls are permanent for the process and intersect with every
 * other permanent call and live lease (strictest wins, and a stricter
 * later call re-blocks what an earlier one unblocked). Repeat calls
 * with the same format set are O(1). Middleware instances instead use
 * acquireSharpSecurityLease() so handler.close() can give loaders back.
 * Per-call format allowlists still apply at the sniff gate regardless;
 * this loader policy is the defense-in-depth layer behind it.
 */
export function configureSharpSecurity(allowedFormats = ['jpeg', 'png', 'webp', 'avif']) {
  const wanted = sharpWantedSet(allowedFormats);
  const key = [...wanted].sort().join(',');
  if (sharpLoadersBlocked && sharpSecurityPermanent.has(key)) return true;
  sharpSecurityPermanent.set(key, wanted);
  return reconcileSharpLoaders();
}

/**
 * Scoped loader policy for one middleware instance. Returns an
 * idempotent release function; while any lease is live, loaders are
 * restricted to the intersection of all permanents and leases.
 */
export function acquireSharpSecurityLease(allowedFormats = ['jpeg', 'png', 'webp', 'avif']) {
  const wanted = sharpWantedSet(allowedFormats);
  const key = [...wanted].sort().join(',');
  let lease = sharpSecurityLeases.get(key);
  if (!lease) {
    lease = { wanted, count: 0 };
    sharpSecurityLeases.set(key, lease);
  }
  lease.count++;
  reconcileSharpLoaders();
  let released = false;
  return () => {
    if (released) return;
    released = true;
    lease.count--;
    if (lease.count <= 0) sharpSecurityLeases.delete(key);
    reconcileSharpLoaders();
  };
}

/**
 * Establish the baseline loader block (root VipsForeignLoad blocked;
 * SVG + known raster loaders subject to permanents/leases) without
 * imposing any format policy of its own. Called on untrusted-image
 * paths; O(1) after the first call.
 */
export function ensureUntrustedSharpLoadersBlocked() {
  if (sharpLoadersBlocked) return true;
  return reconcileSharpLoaders();
}

/**
 * Process-global Sharp/libvips throughput controls. `concurrency` is the
 * number of libvips threads used *per image operation*; when the middleware
 * already runs several image jobs in parallel, a small value (often 1)
 * usually gives better total throughput and less thread churn than letting
 * every job fan out across every core. The last call wins for the process, so
 * hosts embedding several Archx handlers should configure this once.
 */
export function configureSharpPerformance({ concurrency, cache } = {}) {
  const sharp = getSharp();
  if (concurrency !== undefined) {
    if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 1024) {
      throw new TypeError('Archx Sharp performance: concurrency must be an integer from 1 to 1024');
    }
    if (typeof sharp.concurrency === 'function') sharp.concurrency(concurrency);
  }
  if (cache !== undefined) {
    if (typeof cache !== 'boolean') {
      throw new TypeError('Archx Sharp performance: cache must be boolean');
    }
    if (typeof sharp.cache === 'function') sharp.cache(cache);
  }
  return Object.freeze({
    concurrency: typeof sharp.concurrency === 'function' ? sharp.concurrency() : null,
    cache: typeof sharp.cache === 'function' ? sharp.cache() : null,
  });
}

function bufferView(bytes) {
  return Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

function escapeXml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c]));
}

function processingError(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

function mapSharpError(err) {
  const message = String(err?.message || err || '');
  if (/timeout/i.test(message)) return processingError('ARCHX_PROCESSING_TIMEOUT', 'image processing timed out');
  if (/pixel limit|too large|exceeds.*pixel|input image exceeds/i.test(message)) {
    return processingError('ARCHX_INPUT_TOO_LARGE', 'input image exceeds the configured pixel budget');
  }
  if (/unsupported|unknown format|not an image|invalid image|corrupt|premature end|bad seek|invalid.*header/i.test(message)) {
    return processingError('ARCHX_UNSUPPORTED_IMAGE', 'unsupported or corrupt input image');
  }
  return err;
}

function normalizeProcessingOptions(opts = {}) {
  if (!opts || typeof opts !== 'object' || Array.isArray(opts)) {
    throw new TypeError('Archx image processing: options must be an object');
  }
  if (opts.processing != null && (typeof opts.processing !== 'object' || Array.isArray(opts.processing))) {
    throw new TypeError('Archx image processing: processing must be an object');
  }
  const nested = opts.processing || {};
  const pick = (...names) => {
    for (const name of names) {
      if (opts[name] != null) return opts[name];
      if (nested[name] != null) return nested[name];
    }
    return undefined;
  };
  const integer = (name, value, fallback, min, max) => {
    const n = value == null ? fallback : value;
    if (!Number.isInteger(n) || n < min || n > max) {
      throw new TypeError(`Archx image processing: ${name} must be an integer from ${min} to ${max}`);
    }
    return n;
  };
  const timeoutSec = pick('processingTimeoutSec', 'timeoutSec') ?? 10;
  if (typeof timeoutSec !== 'number' || !Number.isFinite(timeoutSec) || timeoutSec < 1 || timeoutSec > 120) {
    throw new TypeError('Archx image processing: processingTimeoutSec must be from 1 to 120');
  }
  const allowedRaw = pick('allowedInputFormats') ?? ['jpeg', 'png', 'webp', 'avif'];
  if (!Array.isArray(allowedRaw) || !allowedRaw.length ||
      allowedRaw.some((f) => !['jpeg', 'png', 'webp', 'avif', 'gif', 'tiff'].includes(String(f).toLowerCase()))) {
    throw new TypeError('Archx image processing: allowedInputFormats must contain only supported formats');
  }
  const allowedInputFormats = [...new Set(allowedRaw.map((f) => String(f).toLowerCase()))];
  const blockRaw = pick('blockUntrustedSharpLoaders');
  if (blockRaw !== undefined && typeof blockRaw !== 'boolean') {
    throw new TypeError('Archx image processing: blockUntrustedSharpLoaders must be boolean');
  }
  const smartRaw = pick('webpSmartSubsample', 'smartSubsample');
  if (smartRaw !== undefined && typeof smartRaw !== 'boolean') {
    throw new TypeError('Archx image processing: webpSmartSubsample must be boolean');
  }
  const resizeKernel = pick('resizeKernel') ?? 'lanczos3';
  if (!['nearest', 'cubic', 'mitchell', 'lanczos2', 'lanczos3', 'mks2013', 'mks2021'].includes(resizeKernel)) {
    throw new TypeError('Archx image processing: resizeKernel is invalid');
  }
  const jpegChromaSubsampling = pick('jpegChromaSubsampling') ?? '4:4:4';
  if (!['4:2:0', '4:4:4'].includes(jpegChromaSubsampling)) {
    throw new TypeError("Archx image processing: jpegChromaSubsampling must be '4:2:0' or '4:4:4'");
  }
  const avifChromaSubsampling = pick('avifChromaSubsampling') ?? '4:2:0';
  if (!['4:2:0', '4:4:4'].includes(avifChromaSubsampling)) {
    throw new TypeError("Archx image processing: avifChromaSubsampling must be '4:2:0' or '4:4:4'");
  }
  const sharpCacheRaw = pick('sharpCache');
  if (sharpCacheRaw !== undefined && typeof sharpCacheRaw !== 'boolean') {
    throw new TypeError('Archx image processing: sharpCache must be boolean');
  }
  return Object.freeze({
    maxInputBytes: integer('maxInputBytes', pick('maxInputBytes'), 50 * 1024 * 1024, 1024, 500 * 1024 * 1024),
    maxInputPixels: integer('maxInputPixels', pick('maxInputPixels'), 50000000, 10000, 268402689),
    maxInputWidth: integer('maxInputWidth', pick('maxInputWidth'), 12000, 64, 65536),
    maxInputHeight: integer('maxInputHeight', pick('maxInputHeight'), 12000, 64, 65536),
    maxOutputPixels: integer('maxOutputPixels', pick('maxOutputPixels'), 16777216, 10000, 268402689),
    timeoutSec,
    allowedInputFormats: Object.freeze(allowedInputFormats),
    blockUntrustedSharpLoaders: blockRaw !== false,
    // Encoder/resampling controls are explicit because they are the dominant
    // cold-derivative CPU cost. Defaults preserve the historical high-quality
    // output; catalog/throughput deployments can trade a little compression
    // efficiency for several-fold faster WebP encoding.
    webpEffort: integer('webpEffort', pick('webpEffort', 'encoderEffort'), 4, 0, 6),
    webpSmartSubsample: smartRaw !== false,
    resizeKernel,
    pngCompressionLevel: integer('pngCompressionLevel', pick('pngCompressionLevel'), 9, 0, 9),
    jpegChromaSubsampling,
    avifEffort: integer('avifEffort', pick('avifEffort'), 4, 0, 9),
    avifChromaSubsampling,
    sharpConcurrency: integer('sharpConcurrency', pick('sharpConcurrency'), 0, 0, 1024),
    sharpCache: sharpCacheRaw,
  });
}

function sharpInput(input, limits, extra = {}) {
  return getSharp()(input, {
    failOn: 'warning',
    limitInputPixels: limits.maxInputPixels,
    limitInputChannels: 4,
    sequentialRead: true,
    animated: false,
    ...extra,
  }).timeout({ seconds: limits.timeoutSec });
}

function normalizeInputBytes(input) {
  // Never accept a string here: Sharp would treat it as a filesystem path,
  // turning an image-bytes API into an accidental local-file read primitive.
  if (input instanceof Uint8Array) return bufferView(input);
  if (input instanceof ArrayBuffer) return Buffer.from(input);
  if (ArrayBuffer.isView(input)) return Buffer.from(input.buffer, input.byteOffset, input.byteLength);
  throw processingError('ARCHX_UNSUPPORTED_IMAGE', 'input image must be bytes');
}

function assertInputWithinLimits(input, limits) {
  const bytes = normalizeInputBytes(input);
  if (!bytes.length) throw processingError('ARCHX_UNSUPPORTED_IMAGE', 'empty input image');
  if (bytes.length > limits.maxInputBytes) {
    throw processingError('ARCHX_INPUT_TOO_LARGE', 'input image exceeds the configured byte budget');
  }
  const sniffed = sniffImageInfo(bytes);
  if (!sniffed || !limits.allowedInputFormats.includes(sniffed.format)) {
    throw processingError('ARCHX_UNSUPPORTED_IMAGE', 'unsupported input image format');
  }
  if (sniffed.width && sniffed.height &&
      (sniffed.width > limits.maxInputWidth || sniffed.height > limits.maxInputHeight ||
       sniffed.width * sniffed.height > limits.maxInputPixels)) {
    throw processingError('ARCHX_INPUT_TOO_LARGE', 'input image exceeds the configured dimension budget');
  }
  if (limits.blockUntrustedSharpLoaders) ensureUntrustedSharpLoadersBlocked();
  return { bytes, sniffed };
}

function normalizedSharpFormat(format) {
  return format === 'heif' ? 'avif' : format;
}

function assertMetadataWithinLimits(meta, limits, sniffed = null) {
  const format = normalizedSharpFormat(meta?.format);
  if (!meta || !limits.allowedInputFormats.includes(format) || !meta.width || !meta.height ||
      (sniffed && format !== sniffed.format)) {
    throw processingError('ARCHX_UNSUPPORTED_IMAGE', 'unsupported input image format');
  }
  if ((meta.pages || 1) > 1 || (meta.channels || 3) > 4) {
    throw processingError('ARCHX_UNSUPPORTED_IMAGE', 'animated or multi-channel input images are not accepted');
  }
  if (!Number.isSafeInteger(meta.width) || !Number.isSafeInteger(meta.height) ||
      meta.width > limits.maxInputWidth || meta.height > limits.maxInputHeight ||
      meta.width * meta.height > limits.maxInputPixels) {
    throw processingError('ARCHX_INPUT_TOO_LARGE', 'input image exceeds the configured dimension budget');
  }
}

/** Bounded Sharp metadata read used by ingest/build tooling. Width/height are
 * reported in displayed orientation (EXIF rotations 5–8 swap the axes). */
export async function inspectImageMetadata(input, opts = {}) {
  const limits = normalizeProcessingOptions(opts);
  const { bytes, sniffed } = assertInputWithinLimits(input, limits);
  let meta;
  try { meta = await sharpInput(bytes, limits).metadata(); }
  catch (err) { throw mapSharpError(err); }
  assertMetadataWithinLimits(meta, limits, sniffed);
  const rotated = meta.orientation >= 5 && meta.orientation <= 8;
  return Object.freeze({
    format: normalizedSharpFormat(meta.format),
    width: rotated ? meta.height : meta.width,
    height: rotated ? meta.width : meta.height,
    orientation: meta.orientation || 1,
    hasAlpha: !!meta.hasAlpha,
    channels: meta.channels || null,
    pages: meta.pages || 1,
  });
}


/**
 * Build an SVG watermark layer (diagonal tiled text + corner credit) at the
 * *output* size. It is composited BEFORE scrambling/encryption, so even an
 * attacker who captures the payload, steals the session key and perfectly
 * un-shuffles it offline still ends up with a watermarked copy — the client
 * side watermark alone could not guarantee that.
 */
function watermarkSvg(w, h, wm) {
  const cfg = typeof wm === 'string' ? { text: wm } : wm;
  const text = escapeXml(cfg.text || '');
  if (!text) return null;
  const color = escapeXml(cfg.color || '#ffffff');
  const fs = Math.max(13, Math.round(Math.min(w, h) / 13));
  const numeric = (value, fallback, min, max) => {
    const n = Number(value ?? fallback);
    return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : fallback;
  };
  const angle = numeric(cfg.angle, -24, -360, 360);
  const opacity = numeric(cfg.opacity, 0.15, 0, 1);
  const cornerOpacity = numeric(cfg.cornerOpacity, 0.9, 0, 1);
  let body = '';
  if (cfg.tile !== false) {
    const rows = [];
    const diag = Math.hypot(w, h);
    // Tile along BOTH axes of the rotated frame. Stepping only
    // vertically (pre-1.13) left a single centered copy per row, so
    // short text on a wide image marked a central band and left the
    // side margins completely clean. The advance estimate (~0.58em
    // per character for the bold sans used here) only spaces copies;
    // slight overlap or gap is harmless for a forensic overlay.
    const stepX = Math.max(fs * 2, fs * (0.58 * String(cfg.text || '').length + 1.6));
    // Brick-stagger alternate rows by half a step (as the client
    // painters do): aligned columns would leave continuous unmarked
    // diagonal alleys between text columns that a crop could thread.
    for (let y = -diag / 2, rowIdx = 0; y < diag / 2; y += fs * 4.2, rowIdx++) {
      const stagger = (rowIdx & 1) ? stepX * 0.5 : 0;
      for (let x = -diag / 2 - stepX + stagger; x < diag / 2 + stepX; x += stepX) {
        rows.push(`<text x="${(x + stepX / 2).toFixed(0)}" y="${y.toFixed(0)}" text-anchor="middle">${text}</text>`);
      }
    }
    body += `<g transform="translate(${w / 2} ${h / 2}) rotate(${angle})" opacity="${opacity}" font-size="${fs}" font-weight="700">${rows.join('')}</g>`;
  }
  if (cfg.corner !== false) {
    const cfs = Math.max(10, Math.round(Math.min(w, h) / 34));
    body += `<g opacity="${cornerOpacity}" font-size="${cfs}" font-weight="600"><text x="${w - 11}" y="${h - 10}" text-anchor="end" stroke="rgba(0,0,0,0.65)" stroke-width="3" paint-order="stroke">${text}</text></g>`;
  }
  return Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}"><g font-family="Arial, Helvetica, sans-serif" fill="${color}">${body}</g></svg>`);
}

// Bounded LRU of RASTERIZED watermark overlays (raw RGBA). The old
// path re-parsed the SVG and re-rasterized dozens of <text> glyphs
// through Pango inside a full libvips composite on EVERY derivative
// (~37 ms at 960x640 measured; even caching a rasterized PNG left a
// ~20 ms composite). The overlay depends only on (w, h, svg bytes):
// rasterize once, then blend in JS (~2 ms) with standard 'over'
// alpha. Against libvips composite the blend agrees to <=1 LSB
// (rounding); finished derivatives are re-encoded anyway, and cache
// keys version the change. Caps keep the cache <= 4 entries / 32 MB.
const watermarkOverlayCache = new Map();
let watermarkOverlayCacheBytes = 0;
async function watermarkOverlayRaw(w, h, svg) {
  const digest = sha256Bytes(svg);
  let hex = '';
  for (let i = 0; i < 12; i++) hex += digest[i].toString(16).padStart(2, '0');
  const key = `${w}x${h}:${hex}`;
  const hit = watermarkOverlayCache.get(key);
  if (hit) {
    watermarkOverlayCache.delete(key);
    watermarkOverlayCache.set(key, hit);
    return hit;
  }
  const data = await getSharp()(svg).ensureAlpha().raw().toBuffer();
  // Watermark glyphs cover a few percent of pixels; precompute the
  // nonzero-alpha offsets once so each blend touches only those
  // pixels instead of scanning the whole frame (same math, same
  // output bytes — alpha-0 pixels are identity by definition).
  const sparse = [];
  for (let i = 3; i < data.length; i += 4) if (data[i] !== 0) sparse.push(i - 3);
  const entry = { data, sparse: Uint32Array.from(sparse), bytes: data.length };
  watermarkOverlayCache.set(key, entry);
  watermarkOverlayCacheBytes += data.length;
  while (watermarkOverlayCache.size > 4 || watermarkOverlayCacheBytes > 32 * 1024 * 1024) {
    const [oldKey, old] = watermarkOverlayCache.entries().next().value;
    watermarkOverlayCache.delete(oldKey);
    watermarkOverlayCacheBytes -= old.bytes;
  }
  return entry;
}

function blendOverlayInPlace(dst, overlayEntry) {
  const overlay = overlayEntry.data ?? overlayEntry;
  const n = Math.min(dst.length, overlay.length);
  const offsets = overlayEntry.sparse;
  const count = offsets ? offsets.length : (n >> 2);
  for (let k = 0; k < count; k++) {
    const i = offsets ? offsets[k] : k * 4;
    if (i + 3 >= n) continue;
    const a = overlay[i + 3];
    if (a === 255) {
      dst[i] = overlay[i]; dst[i + 1] = overlay[i + 1]; dst[i + 2] = overlay[i + 2]; dst[i + 3] = 255;
      continue;
    }
    const sa = dst[i + 3];
    if (sa === 255) {
      const ia = 255 - a;
      dst[i] = (overlay[i] * a + dst[i] * ia + 127) / 255 | 0;
      dst[i + 1] = (overlay[i + 1] * a + dst[i + 1] * ia + 127) / 255 | 0;
      dst[i + 2] = (overlay[i + 2] * a + dst[i + 2] * ia + 127) / 255 | 0;
    } else {
      // General 'over' for translucent bases (premultiplied form).
      const oa = a * 255 + sa * (255 - a); // out alpha x255
      if (oa === 0) continue;
      const t = sa * (255 - a);
      dst[i] = (overlay[i] * a * 255 + dst[i] * t + (oa >> 1)) / oa | 0;
      dst[i + 1] = (overlay[i + 1] * a * 255 + dst[i + 1] * t + (oa >> 1)) / oa | 0;
      dst[i + 2] = (overlay[i + 2] * a * 255 + dst[i + 2] * t + (oa >> 1)) / oa | 0;
      dst[i + 3] = (oa + 127) / 255 | 0;
    }
  }
}

/**
 * @param {Buffer} input master image bytes
 * @param {object} opts { grid, key, maxWidth, quality, lossless, format, aesKey, container }
 * `quality` defaults to 95 (delivery-size pixels should look like the source,
 * not like a recompressed thumbnail); pass `lossless:true` for bit-exact
 * WebP/PNG pixels at the delivered size when payload size matters less.
 * @returns {Promise<{bytes:Buffer, header:object}>} bytes = .archx container (or plain scrambled image when container:false)
 */
function validateScrambleOpts(opts) {
  const grid = opts.grid ?? 8;
  if (!Number.isInteger(grid) || grid < 2 || grid > 32) throw new TypeError('Archx image processing: grid must be an integer from 2 to 32');
  const planVersion = opts.planVersion ?? 2; // 128-bit seed; v1 (32-bit) stays available explicitly
  if (planVersion !== 1 && planVersion !== 2) {
    throw new TypeError('Archx image processing: planVersion must be 1 or 2');
  }
  const key = opts.key ?? '';
  if (typeof key !== 'string') throw new TypeError('Archx image processing: key must be a string');
  const maxWidth = opts.maxWidth ?? 1600;
  if (maxWidth !== 0 && (!Number.isInteger(maxWidth) || maxWidth < 64 || maxWidth > 8192)) {
    throw new TypeError('Archx image processing: maxWidth must be 0 or an integer from 64 to 8192');
  }
  if (opts.lossless !== undefined && typeof opts.lossless !== 'boolean') {
    throw new TypeError('Archx image processing: lossless must be boolean');
  }
  if (opts.quality !== undefined && opts.quality !== 'lossless' &&
      (!Number.isInteger(opts.quality) || opts.quality < 1 || opts.quality > 100)) {
    throw new TypeError('Archx image processing: quality must be lossless or an integer from 1 to 100');
  }
  if (opts.format !== undefined && !['webp', 'png', 'jpeg', 'avif'].includes(opts.format)) {
    throw new TypeError("Archx image processing: format must be 'webp', 'png', 'jpeg', or 'avif'");
  }
  if (opts.container !== undefined && typeof opts.container !== 'boolean') {
    throw new TypeError('Archx image processing: container must be boolean');
  }
  if (opts.aesKey != null && typeof opts.aesKey !== 'string') {
    throw new TypeError('Archx image processing: aesKey must be a base64 string');
  }
  if (opts.forensicSeed != null && !['string', 'number'].includes(typeof opts.forensicSeed)) {
    throw new TypeError('Archx image processing: forensicSeed must be a string or number');
  }
  const lossless = opts.lossless === true || opts.quality === 'lossless';
  const quality = lossless ? 100 : (opts.quality ?? 95);
  return { grid, planVersion, key, maxWidth, lossless, quality };
}

/**
 * Stage 1 of derivative production: decode + orient + resize to the
 * exact RGBA raster the scramble stage consumes. This is the reusable
 * front half — it depends only on the master bytes, target width, and
 * processing limits (NOT on any per-viewer mark — the visible watermark
 * moved to stage 2 in 1.13), so per-token/per-viewer delivery can cache
 * one base frame per geometry and skip the master decode + resample on
 * every view. `finishDerivative` is stage 2.
 */
export async function prepareDerivativeBase(input, opts = {}) {
  const limits = normalizeProcessingOptions(opts);
  const { bytes: inputBytes, sniffed } = assertInputWithinLimits(input, limits);
  const { grid, maxWidth } = validateScrambleOpts(opts);

  let srcMeta;
  try { srcMeta = await sharpInput(inputBytes, limits).metadata(); }
  catch (err) { throw mapSharpError(err); }
  assertMetadataWithinLimits(srcMeta, limits, sniffed);
  const rotated = srcMeta.orientation >= 5 && srcMeta.orientation <= 8;
  const srcW = rotated ? srcMeta.height : srcMeta.width;
  const srcH = rotated ? srcMeta.width : srcMeta.height;
  let scale = 1;
  if (maxWidth) scale = Math.min(scale, maxWidth / srcW);
  scale = Math.min(scale, Math.sqrt(limits.maxOutputPixels / (srcW * srcH)));
  let tw = Math.max(1, Math.floor(srcW * scale));
  let th = Math.max(1, Math.floor(srcH * scale));
  // `maxOutputPixels` is a hard CPU/memory budget, including the grid padding
  // that will be present in the encoded scrambled payload. Rounding either
  // dimension upward could otherwise exceed it by a few pixels.
  const paddedPixels = () => Math.ceil(tw / grid) * grid * Math.ceil(th / grid) * grid;
  while (paddedPixels() > limits.maxOutputPixels) {
    const shrink = Math.sqrt(limits.maxOutputPixels / paddedPixels());
    const nextW = Math.max(1, Math.floor(tw * shrink));
    const nextH = Math.max(1, Math.floor(th * shrink));
    if (nextW === tw && nextH === th) {
      if (tw >= th && tw > 1) tw--;
      else if (th > 1) th--;
      else break;
    } else {
      tw = nextW;
      th = nextH;
    }
  }

  let pipeline = sharpInput(inputBytes, limits);
  // Bake EXIF orientation only when the master actually carries one:
  // libvips autorotate costs a full extra frame pass (~60% of the decode
  // stage at 960px) even for orientation-1 images. The pipeline re-encodes
  // from raw pixels below, so no master metadata can leak through skipping.
  if (srcMeta.orientation && srcMeta.orientation !== 1) pipeline = pipeline.rotate();
  pipeline = pipeline.resize({
      width: tw,
      height: th,
      withoutEnlargement: true,
      kernel: getSharp().kernel[limits.resizeKernel],
    });

  // The visible watermark is applied in stage 2 (finishDerivative), NOT
  // here: a per-viewer watermark ({viewer} expansion) baked into the
  // stage-1 base would make the base itself per-viewer, defeating the
  // base cache and — when a v1.12 cache-key bug collapsed object
  // watermarks — leaking one viewer's identity into another's pixels.
  // A clean base depends only on (master, geometry).

  let data, info;
  try { ({ data, info } = await pipeline.ensureAlpha().raw().toBuffer({ resolveWithObject: true })); }
  catch (err) { throw mapSharpError(err); }
  if (!info?.width || !info?.height || info.channels !== 4 || data.length < info.width * info.height * 4) {
    throw processingError('ARCHX_UNSUPPORTED_IMAGE', 'decoded image did not produce RGBA pixels');
  }
  const w = info.width;
  const h = info.height;
  return { data, w, h, hasAlpha: !!srcMeta.hasAlpha, watermarked: false };
}

/**
 * Stage 2: forensic + StegoMark marks, tile scramble, encode, optional
 * AES-GCM, container wrap. Marks mutate pixels, so a shared/cached base
 * is copied first (a ~1 ms memcpy vs re-decoding the master); a base
 * produced inline by scrambleImage is used in place exactly as before,
 * keeping single-call output byte-identical.
 */
export async function finishDerivative(base, opts = {}, owned = false) {
  const limits = normalizeProcessingOptions(opts);
  const { grid, planVersion, key, lossless, quality } = validateScrambleOpts(opts);
  if (!base || !(base.data instanceof Uint8Array) ||
      !Number.isSafeInteger(base.w) || !Number.isSafeInteger(base.h) ||
      base.w < 1 || base.h < 1 || base.data.length < base.w * base.h * 4) {
    throw new TypeError('Archx image processing: finishDerivative requires a prepareDerivativeBase result');
  }
  const w = base.w;
  const h = base.h;
  const srcMeta = { hasAlpha: !!base.hasAlpha };

  // Marks below mutate pixels in place; a cached/shared base must not
  // be poisoned by one viewer's marks. Copy-on-write: the base buffer
  // is only duplicated when an in-place mark actually runs (the old
  // code copied 8.3 MB at 1080p unconditionally, then usually
  // orphaned that copy when the watermark composite returned a fresh
  // buffer — and copied pointlessly when no mark was enabled at all).
  let rawPixels = base.data;
  let ownsPixels = !!owned;
  const ensureMutablePixels = () => {
    if (!ownsPixels) {
      rawPixels = Buffer.from(rawPixels);
      ownsPixels = true;
    }
  };

  // Server-baked visible watermark, composited pre-scramble so that NO
  // extraction route — screenshot, canvas grab, or full payload
  // reconstruction with a stolen session key — can produce an unmarked
  // copy. Applied here (stage 2) so the cached stage-1 base stays
  // viewer-independent; forensic/Stego marks layer over it exactly as
  // when it was baked into the base.
  let watermarked = !!base.watermarked;
  if (!watermarked && opts.watermark) {
    const svg = watermarkSvg(w, h, opts.watermark);
    if (svg) {
      try {
        const overlay = await watermarkOverlayRaw(w, h, svg);
        ensureMutablePixels();
        blendOverlayInPlace(rawPixels, overlay);
      } catch (err) { throw mapSharpError(err); }
      watermarked = true;
    }
  }
  let forensicMarked = false;
  if (opts.forensicSeed) {
    ensureMutablePixels(); // applyForensicBlocks mutates in place
    const fx = typeof opts.forensic === 'object' && opts.forensic ? opts.forensic : {};
    rawPixels = applyForensicBlocks(rawPixels, w, h, opts.forensicSeed, {
      blockSize: fx.blockSize ?? 32,
      delta: fx.delta ?? 2,
      signsVersion: fx.signsVersion ?? 3,
    });
    forensicMarked = true;
  }

  // Blind steganographic ownership fingerprint (pre-scramble): a suspect
  // screenshot/export can later be tested with detectStegoFingerprint() or
  // `archx-detect` and attributed to this image / viewer / issued token.
  let stegoMarked = false;
  let resolvedStegoFingerprint = null;
  const stegoCfg = typeof opts.steganography === 'object' && opts.steganography ? opts.steganography : {};
  const stegoPayload = opts.stegoPayload ?? stegoCfg.payload ??
    (opts.steganography === true ? key || 'archx' : null);
  if (stegoPayload != null && stegoPayload !== '') {
    // The forensic layout key must be an explicit secret, NEVER defaulted
    // to the tile-scramble key: in static deployments the scramble key is
    // published (manifest) so browsers can unscramble, and keying the
    // watermark layout with it lets anyone subtract the mark or forge
    // another buyer's fingerprint. An explicitly empty key remains the
    // caller's choice (unkeyed layout); an omitted key is an error.
    const effectiveStegoKey = opts.stegoKey ?? stegoCfg.key;
    if (effectiveStegoKey == null) {
      throw new TypeError('Archx image processing: stegoKey is required when a StegoMark payload is embedded (use a dedicated secret, never the scramble key)');
    }
    if (effectiveStegoKey !== '' && effectiveStegoKey === key) {
      throw new TypeError('Archx image processing: stegoKey must differ from the scramble key (the scramble key is public wherever clients unscramble)');
    }
    const stegoProfile = opts.stegoProfile ?? stegoCfg.profile ?? 'standard';
    ensureMutablePixels(); // embed below runs with inPlace: true
    rawPixels = embedStegoFingerprint(rawPixels, w, h, stegoPayload, {
      key: effectiveStegoKey,
      profile: stegoProfile,
      strength: opts.stegoStrength ?? stegoCfg.strength ?? 6,
      gridX: stegoCfg.gridX ?? (stegoProfile === 'robust' ? 20 : 24),
      gridY: stegoCfg.gridY ?? (stegoProfile === 'robust' ? 14 : 16),
      layoutVersion: opts.stegoLayoutVersion ?? stegoCfg.layoutVersion ?? 3,
      legacyCode: !!(opts.stegoLegacyCode ?? stegoCfg.legacyCode),
      inPlace: true,
    });
    stegoMarked = true;
    resolvedStegoFingerprint = stegoFingerprint(stegoPayload);
  }

  const ownershipCfg = (opts.ownership && typeof opts.ownership === 'object' && opts.ownership.owner)
    ? opts.ownership : null;
  const contentFingerprint = (opts.contentFingerprint || ownershipCfg)
    ? computePerceptualFingerprint(rawPixels, w, h)
    : null;
  // Ownership metadata (v1.18): the signed claim binds THIS finished
  // derivative's perceptual hash + stego fingerprint. It is computed
  // over the final pre-scramble pixels — exactly what a leaked copy
  // looks like — and written into the payload's EXIF/XMP. Metadata
  // is the declarative layer only; see server/ownership.js.
  let ownershipToken = null;
  if (ownershipCfg) {
    ownershipToken = ownershipCfg.privateKey
      ? signOwnershipClaim({
        owner: String(ownershipCfg.owner),
        imageId: ownershipCfg.imageId ?? base.imageId ?? '',
        perceptualHash: contentFingerprint,
        stegoFingerprint: resolvedStegoFingerprint,
      }, ownershipCfg.privateKey)
      : null;
  }

  const { pw, ph } = paddedSize(w, h, grid);
  const plan = buildScramblePlan(grid, key, planVersion);
  // Fused pad+scramble writes the encoder's raw input in a single pass:
  // no pad copy, no scramble copy, no Buffer.from copy. Buffer.allocUnsafe
  // is safe here because every output pixel is written by the tile loop.
  const scrambled = Buffer.allocUnsafe(pw * ph * 4);
  scramblePixelsPadded(rawPixels, w, h, plan, scrambled);

  const format = opts.format ?? 'webp';
  let encoder = getSharp()(scrambled, { raw: { width: pw, height: ph, channels: 4 } })
    .timeout({ seconds: limits.timeoutSec });
  // For opaque masters the synthesized alpha band carries zero information:
  // PNG would store/ship it (+~12% bytes) and libwebp still pays to analyze
  // it (~15% of catalog encode time) before dropping it. Dropping it before
  // the encoder changes no decoded pixel. JPEG flattens anyway.
  if (format !== 'jpeg' && !srcMeta.hasAlpha) encoder = encoder.removeAlpha();
  if (format === 'png') {
    encoder = encoder.png({ compressionLevel: limits.pngCompressionLevel, adaptiveFiltering: true });
  } else if (format === 'jpeg') {
    // 4:4:4 remains the quality default because it keeps colour edges/text
    // crisp; throughput deployments may explicitly choose 4:2:0.
    encoder = encoder.jpeg({
      quality,
      chromaSubsampling: limits.jpegChromaSubsampling,
      mozjpeg: true,
    });
  } else if (format === 'avif') {
    // Opt-in: AVIF is roughly 40-55% smaller than WebP on scrambled tiles at
    // comparable quality but encodes 8-70x slower, so it suits precomputed
    // catalogs (archx-build) far better than on-demand token delivery.
    encoder = encoder.avif(lossless
      ? { lossless: true, effort: limits.avifEffort, chromaSubsampling: limits.avifChromaSubsampling }
      : { quality, effort: limits.avifEffort, chromaSubsampling: limits.avifChromaSubsampling });
  } else if (lossless) {
    encoder = encoder.webp({ lossless: true, alphaQuality: 100, effort: limits.webpEffort });
  } else {
    encoder = encoder.webp({
      quality,
      alphaQuality: 100,
      smartSubsample: limits.webpSmartSubsample,
      effort: limits.webpEffort,
    });
  }
  if (ownershipCfg) {
    encoder = applyOwnershipMetadata(encoder, {
      owner: String(ownershipCfg.owner),
      copyright: ownershipCfg.copyright,
      artist: ownershipCfg.artist,
      token: ownershipToken,
    });
  }
  let payload;
  try { payload = await encoder.toBuffer(); }
  catch (err) { throw mapSharpError(err); }
  const mime = format === 'png' ? 'image/png' : format === 'jpeg' ? 'image/jpeg'
    : format === 'avif' ? 'image/avif' : 'image/webp';

  const header = {
    v: 1, w, h, pw, ph, grid, mime, scrambled: true, encrypted: false,
    ...(planVersion === 2 ? { pv: 2 } : {}),
    ...(watermarked ? { wm: 1 } : {}),
    ...(forensicMarked ? { fx: 1 } : {}),
    ...(stegoMarked ? { sg: 1 } : {}),
  };
  if (opts.aesKey) {
    const { cipher, iv } = await encryptPayload(payload, opts.aesKey);
    payload = Buffer.from(cipher);
    header.encrypted = true;
    header.iv = iv;
  }
  if (opts.container === false) {
    if (header.encrypted) throw new Error('encrypted output requires an .archx container');
    return { bytes: payload, header, stegoFingerprint: resolvedStegoFingerprint, perceptualFingerprint: contentFingerprint, ownershipToken };
  }
  return {
    bytes: bufferView(encodeContainer(header, payload)),
    header,
    stegoFingerprint: resolvedStegoFingerprint,
    perceptualFingerprint: contentFingerprint,
    ownershipToken,
  };
}

export async function scrambleImage(input, opts = {}) {
  const base = await prepareDerivativeBase(input, opts);
  return finishDerivative(base, opts, true);
}

/** Reverse a plain (unencrypted, container-less) scrambled image. Test/ops helper. */
export async function unscrambleImage(scrambledBytes, { grid = 8, key = '', w, h, planVersion = 2, ...processingOpts } = {}) {
  if (!Number.isInteger(grid) || grid < 2 || grid > 32) throw new TypeError('Archx image processing: grid must be an integer from 2 to 32');
  if (planVersion !== 1 && planVersion !== 2) throw new TypeError('Archx image processing: planVersion must be 1 or 2');
  if (typeof key !== 'string') throw new TypeError('Archx image processing: key must be a string');
  if ((w !== undefined && (!Number.isSafeInteger(w) || w < 1)) ||
      (h !== undefined && (!Number.isSafeInteger(h) || h < 1)) || ((w == null) !== (h == null))) {
    throw new TypeError('Archx image processing: w and h must be positive integers');
  }
  const limits = normalizeProcessingOptions(processingOpts);
  const { bytes: inputBytes } = assertInputWithinLimits(scrambledBytes, limits);
  let data, info;
  try {
    ({ data, info } = await sharpInput(inputBytes, limits).ensureAlpha().raw().toBuffer({ resolveWithObject: true }));
  } catch (err) { throw mapSharpError(err); }
  if (!info?.width || !info?.height || info.channels !== 4 || info.width % grid !== 0 || info.height % grid !== 0 ||
      data.length < info.width * info.height * 4 || (w && (w > info.width || h > info.height))) {
    throw processingError('ARCHX_UNSUPPORTED_IMAGE', 'scrambled image geometry is invalid');
  }
  const plan = buildScramblePlan(grid, key, planVersion);
  const raw = scramblePixels(data, info.width, info.height, plan, 'unscramble');
  let out = getSharp()(bufferView(raw), { raw: { width: info.width, height: info.height, channels: 4 } })
    .timeout({ seconds: limits.timeoutSec });
  if (w && h && (w !== info.width || h !== info.height)) {
    out = out.extract({ left: 0, top: 0, width: w, height: h });
  }
  try { return await out.png().toBuffer(); }
  catch (err) { throw mapSharpError(err); }
}

/* ---------------- off-thread StegoMark detection ----------------
 * `detectStegoFingerprint` with auto profile/layout + geometry search
 * evaluates thousands of hypotheses synchronously — measured at ~6 s
 * of blocked event loop on unmarked images. That is an offline
 * forensic cost; on a server it is a self-inflicted stall. This
 * wrapper runs the identical detector in a single reusable
 * worker_threads worker (lazily spawned, respawned after crashes). */
let detectWorker = null;
let detectSeq = 0;
const detectQueue = [];
let detectActive = null;
let detectWorkerConfig = {
  maxPending: 64,
  timeoutMs: 120_000,
  // A job-COUNT cap alone does not bound memory: every queued job
  // holds a full RGBA copy. Queued bytes are capped too (default
  // 512 MiB across active + queued jobs), single suspects are capped
  // at 50 MP, and a job that waits longer than queueTimeoutMs is
  // rejected at dispatch instead of starting stale forensic work.
  maxQueuedBytes: 512 * 1024 * 1024,
  maxPixels: 50_000_000,
  queueTimeoutMs: 300_000,
};
let detectQueuedBytes = 0;

/**
 * Bound the forensic detect worker: pending jobs (active + queued)
 * are capped so a request flood cannot grow memory without limit,
 * and each job has a hard timeout after which the worker is
 * recycled (a pathological suspect must not wedge forensic
 * capacity forever). Returns the effective config + live depth.
 */
export function configureStegoDetectWorker({ maxPending, timeoutMs, maxQueuedBytes, maxPixels, queueTimeoutMs } = {}) {
  if (maxPending !== undefined) {
    if (!Number.isSafeInteger(maxPending) || maxPending < 1 || maxPending > 4096) {
      throw new TypeError('Archx stego detection: maxPending must be an integer in [1, 4096]');
    }
    detectWorkerConfig.maxPending = maxPending;
  }
  if (timeoutMs !== undefined) {
    if (!Number.isFinite(timeoutMs) || timeoutMs < 100 || timeoutMs > 3_600_000) {
      throw new TypeError('Archx stego detection: timeoutMs must be in [100, 3600000]');
    }
    detectWorkerConfig.timeoutMs = timeoutMs;
  }
  if (maxQueuedBytes !== undefined) {
    if (!Number.isSafeInteger(maxQueuedBytes) || maxQueuedBytes < 16_384 || maxQueuedBytes > 16 * 1024 * 1024 * 1024) {
      throw new TypeError('Archx stego detection: maxQueuedBytes must be an integer in [16384, 16GiB]');
    }
    detectWorkerConfig.maxQueuedBytes = maxQueuedBytes;
  }
  if (maxPixels !== undefined) {
    if (!Number.isSafeInteger(maxPixels) || maxPixels < 4096 || maxPixels > 268_402_689) {
      throw new TypeError('Archx stego detection: maxPixels must be an integer in [4096, 268402689]');
    }
    detectWorkerConfig.maxPixels = maxPixels;
  }
  if (queueTimeoutMs !== undefined) {
    if (!Number.isFinite(queueTimeoutMs) || queueTimeoutMs < 0 || queueTimeoutMs > 3_600_000) {
      throw new TypeError('Archx stego detection: queueTimeoutMs must be in [0, 3600000]');
    }
    detectWorkerConfig.queueTimeoutMs = queueTimeoutMs;
  }
  return {
    ...detectWorkerConfig,
    pending: detectQueue.length + (detectActive ? 1 : 0),
    queuedBytes: detectQueuedBytes,
  };
}

function releaseJobBytes(job) {
  if (job && job.bytesLen) {
    detectQueuedBytes = Math.max(0, detectQueuedBytes - job.bytesLen);
    job.bytesLen = 0;
  }
}

function failDetectWorker(err) {
  const jobs = [...(detectActive ? [detectActive] : []), ...detectQueue];
  detectActive = null;
  detectQueue.length = 0;
  if (detectWorker) {
    try { detectWorker.terminate(); } catch { /* already gone */ }
    detectWorker = null;
  }
  for (const job of jobs) {
    if (job.timer) clearTimeout(job.timer);
    releaseJobBytes(job);
    job.reject(err);
  }
}

function pumpDetectQueue() {
  if (detectActive || detectQueue.length === 0) return;
  const job = detectQueue.shift();
  if (detectWorkerConfig.queueTimeoutMs > 0 && Date.now() - job.enqueuedAt > detectWorkerConfig.queueTimeoutMs) {
    releaseJobBytes(job);
    job.reject(new Error(`Archx stego detection queue wait exceeded ${detectWorkerConfig.queueTimeoutMs}ms`));
    pumpDetectQueue();
    return;
  }
  detectActive = job;
  let worker;
  try {
    worker = ensureDetectWorker();
  } catch (err) {
    detectActive = null;
    releaseJobBytes(job);
    job.reject(err);
    pumpDetectQueue();
    return;
  }
  job.timer = setTimeout(() => {
    if (detectActive !== job) return;
    detectActive = null;
    releaseJobBytes(job);
    try { worker.terminate(); } catch { /* already gone */ }
    if (detectWorker === worker) detectWorker = null;
    job.reject(new Error(`Archx stego detection timed out after ${job.timeoutMs}ms`));
    pumpDetectQueue();
  }, job.timeoutMs);
  job.timer.unref?.();
  try {
    worker.postMessage(job.message, job.transfer);
  } catch (err) {
    clearTimeout(job.timer);
    detectActive = null;
    releaseJobBytes(job);
    job.reject(err);
    pumpDetectQueue();
  }
}

function ensureDetectWorker() {
  if (detectWorker) return detectWorker;
  const worker = new Worker(new URL('./detect-worker.js', import.meta.url), { type: 'module' });
  worker.unref();
  worker.on('message', (msg) => {
    const job = detectActive;
    if (!job || msg?.id !== job.id) return;
    detectActive = null;
    releaseJobBytes(job);
    if (job.timer) clearTimeout(job.timer);
    if (msg.ok) job.resolve(msg.result);
    else job.reject(new Error(`Archx stego detection failed: ${msg.error || 'worker error'}`));
    pumpDetectQueue();
  });
  worker.on('error', (err) => {
    if (detectWorker === worker) failDetectWorker(err);
  });
  worker.on('exit', (code) => {
    // A recycled (timed-out) worker's exit can arrive AFTER its
    // replacement is already serving jobs; only the CURRENT
    // worker's exit may fail pending work.
    if (detectWorker !== worker) return;
    if (code !== 0 && (detectActive || detectQueue.length)) {
      failDetectWorker(new Error(`Archx stego detection worker exited (${code})`));
    } else detectWorker = null;
  });
  detectWorker = worker;
  return worker;
}

function enqueueDetectJob(messageBytes, w, h, kind, payload, options) {
  // All size validation happens BEFORE the defensive copy: an
  // oversized or inconsistent request must fail without allocating
  // or queueing anything. The detector consumes RGBA (w*h*4).
  const pixels = w * h;
  if (!Number.isSafeInteger(pixels) || pixels < 1 || pixels > detectWorkerConfig.maxPixels
      || !Number.isSafeInteger(pixels * 4) || messageBytes.length < pixels * 4) {
    return Promise.reject(new TypeError(
      `Archx stego detection: rgba must hold w*h*4 bytes and at most ${detectWorkerConfig.maxPixels} pixels`,
    ));
  }
  const pending = detectQueue.length + (detectActive ? 1 : 0);
  if (pending >= detectWorkerConfig.maxPending) {
    return Promise.reject(new Error(
      `Archx stego detection queue is full (${detectWorkerConfig.maxPending} pending); retry later or raise maxPending`,
    ));
  }
  if (detectQueuedBytes + messageBytes.length > detectWorkerConfig.maxQueuedBytes) {
    return Promise.reject(new Error(
      `Archx stego detection queued-byte budget exceeded (${detectWorkerConfig.maxQueuedBytes} bytes); retry later or raise maxQueuedBytes`,
    ));
  }
  const id = ++detectSeq;
  const timeoutMs = Number.isFinite(options?.timeoutMs) && options.timeoutMs >= 100
    ? Math.min(options.timeoutMs, 3_600_000)
    : detectWorkerConfig.timeoutMs;
  return new Promise((resolve, reject) => {
    // Copy into a standalone buffer so caller mutation cannot race
    // the worker, then TRANSFER it (zero-copy handoff).
    const copy = new Uint8Array(messageBytes.length);
    copy.set(messageBytes);
    detectQueuedBytes += copy.length;
    detectQueue.push({
      id, resolve, reject, timeoutMs, timer: null,
      enqueuedAt: Date.now(), bytesLen: copy.length,
      message: { id, kind, rgba: copy, w, h, ...payload },
      transfer: [copy.buffer],
    });
    pumpDetectQueue();
  });
}

export function detectStegoFingerprintInWorker(rgba, w, h, options = {}) {
  const bytes = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  if (!Number.isSafeInteger(w) || !Number.isSafeInteger(h) || w < 1 || h < 1
      || !Number.isSafeInteger(w * h * 4) || bytes.length < w * h * 4) {
    return Promise.reject(new TypeError('Archx stego detection: rgba/w/h are inconsistent (RGBA w*h*4 required)'));
  }
  const { timeoutMs, ...detectOptions } = options || {};
  return enqueueDetectJob(bytes, w, h, 'detect', { options: detectOptions }, { timeoutMs });
}

/**
 * Screen one suspect against MANY keys in a single worker job: the
 * pixel buffer crosses the thread boundary once, the luma/integral
 * planes are built once, each key gets a fast native screen, and
 * only keys showing signal escalate to the full search. This is
 * the supported shape for "which recipient key marked this leak?"
 * sweeps — never a loop of full detects on a request path.
 */
export function batchDetectStegoInWorker(rgba, w, h, keys, options = {}) {
  const bytes = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  if (!Number.isSafeInteger(w) || !Number.isSafeInteger(h) || w < 1 || h < 1
      || !Number.isSafeInteger(w * h * 4) || bytes.length < w * h * 4) {
    return Promise.reject(new TypeError('Archx stego detection: rgba/w/h are inconsistent (RGBA w*h*4 required)'));
  }
  if (!Array.isArray(keys) || keys.length === 0 || keys.length > 512
      || keys.some((k) => typeof k !== 'string' || k.length > 1024)
      || keys.reduce((sum, k) => sum + k.length, 0) > 262_144) {
    return Promise.reject(new TypeError('Archx stego detection: keys must be 1..512 strings of at most 1024 chars (256K total)'));
  }
  const { timeoutMs, escalateTop, ...detectOptions } = options || {};
  return enqueueDetectJob(bytes, w, h, 'batch', {
    keys: [...keys],
    escalateTop: Number.isSafeInteger(escalateTop) && escalateTop >= 0 ? Math.min(escalateTop, 32) : 2,
    options: detectOptions,
  }, { timeoutMs });
}

export function closeStegoDetectWorker() {
  if (detectWorker) failDetectWorker(new Error('Archx stego detection worker closed'));
}
