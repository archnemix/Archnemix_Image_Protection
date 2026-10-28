/**
 * Server-side image scrambling (Node + sharp).
 * Takes a master image, down-scales it to web resolution, strips metadata,
 * tile-scrambles its pixels, and (optionally) AES-GCM-encrypts the result
 * inside an .archx container. The master file itself is never sent.
 */
import sharp from 'sharp';
import {
  buildScramblePlan, paddedSize, scramblePixels, scramblePixelsPadded,
  encodeContainer, encryptPayload, generateKeyBase64, applyForensicBlocks,
  embedStegoFingerprint, stegoFingerprint, sniffImageInfo,
  perceptualFingerprint as computePerceptualFingerprint,
} from '../src/scramble.js';

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

/**
 * Restrict libvips' native file loaders to the formats Archx actually uses.
 * Sharp/libvips choose a loader by sniffing content, so an extension check
 * alone cannot stop a GIF/TIFF/SVG/PDF parser from being reached. This is a
 * process-global Sharp setting; the internally generated SVG watermark and
 * the explicitly allowed master formats are unblocked.
 */
export function configureSharpSecurity(allowedFormats = ['jpeg', 'png', 'webp', 'avif']) {
  if (typeof sharp.block !== 'function' || typeof sharp.unblock !== 'function') return false;
  if (!sharpLoadersBlocked) {
    sharp.block({ operation: ['VipsForeignLoad'] });
    sharpLoadersBlocked = true;
  }
  const wanted = new Set(['VipsForeignLoadSvg']);
  for (const format of allowedFormats || []) {
    const operation = SHARP_LOADERS[String(format).toLowerCase()];
    if (operation) wanted.add(operation);
  }
  const fresh = [...wanted].filter((operation) => !sharpLoadersUnblocked.has(operation));
  if (fresh.length) {
    sharp.unblock({ operation: fresh });
    for (const operation of fresh) sharpLoadersUnblocked.add(operation);
  }
  return true;
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
    maxInputPixels: integer('maxInputPixels', pick('maxInputPixels'), 40000000, 10000, 268402689),
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
  return sharp(input, {
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
  if (limits.blockUntrustedSharpLoaders) configureSharpSecurity(limits.allowedInputFormats);
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
    for (let y = -diag / 2; y < diag / 2; y += fs * 4.2) {
      rows.push(`<text x="0" y="${y.toFixed(0)}" text-anchor="middle">${text}</text>`);
    }
    body += `<g transform="translate(${w / 2} ${h / 2}) rotate(${angle})" opacity="${opacity}" font-size="${fs}" font-weight="700">${rows.join('')}</g>`;
  }
  if (cfg.corner !== false) {
    const cfs = Math.max(10, Math.round(Math.min(w, h) / 34));
    body += `<g opacity="${cornerOpacity}" font-size="${cfs}" font-weight="600"><text x="${w - 11}" y="${h - 10}" text-anchor="end" stroke="rgba(0,0,0,0.65)" stroke-width="3" paint-order="stroke">${text}</text></g>`;
  }
  return Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}"><g font-family="Arial, Helvetica, sans-serif" fill="${color}">${body}</g></svg>`);
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
  const planVersion = opts.planVersion ?? 1;
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
 * Stage 1 of derivative production: decode + orient + resize (+ optional
 * visible watermark composite) to the exact RGBA raster the scramble
 * stage consumes. This is the reusable front half — it depends only on
 * the master bytes, target width, watermark, and processing limits, so
 * per-token/per-viewer delivery can cache the base frame and skip the
 * master decode + resample on every view. `finishDerivative` is stage 2.
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
      kernel: sharp.kernel[limits.resizeKernel],
    });

  // Server-baked visible watermark: composited pre-scramble so that NO
  // extraction route — screenshot, canvas grab, or full payload
  // reconstruction with a stolen session key — can produce an unmarked copy.
  let watermarked = false;
  if (opts.watermark) {
    const svg = watermarkSvg(tw, th, opts.watermark);
    if (svg) {
      pipeline = pipeline.composite([{ input: svg, top: 0, left: 0 }]);
      watermarked = true;
    }
  }

  let data, info;
  try { ({ data, info } = await pipeline.ensureAlpha().raw().toBuffer({ resolveWithObject: true })); }
  catch (err) { throw mapSharpError(err); }
  if (!info?.width || !info?.height || info.channels !== 4 || data.length < info.width * info.height * 4) {
    throw processingError('ARCHX_UNSUPPORTED_IMAGE', 'decoded image did not produce RGBA pixels');
  }
  const w = info.width;
  const h = info.height;
  return { data, w, h, hasAlpha: !!srcMeta.hasAlpha, watermarked };
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
  const watermarked = !!base.watermarked;
  const srcMeta = { hasAlpha: !!base.hasAlpha };

  // Block-level forensic mark (also pre-scramble): survives into any
  // reconstructed copy and can be correlated against the viewing session.
  // `data` is a fresh Sharp-owned Buffer for this call. Reusing its view
  // avoids an otherwise pointless full-frame copy before the mark/scramble
  // stages; the caller-supplied compressed master is never mutated.
  // Marks below mutate pixels in place; a cached/shared base must not be
  // poisoned by one viewer's marks, so non-owned bases are copied first.
  let rawPixels = owned ? base.data : Buffer.from(base.data);
  let forensicMarked = false;
  if (opts.forensicSeed) {
    const fx = typeof opts.forensic === 'object' && opts.forensic ? opts.forensic : {};
    rawPixels = applyForensicBlocks(rawPixels, w, h, opts.forensicSeed, {
      blockSize: fx.blockSize ?? 32,
      delta: fx.delta ?? 2,
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
    rawPixels = embedStegoFingerprint(rawPixels, w, h, stegoPayload, {
      key: effectiveStegoKey,
      profile: stegoProfile,
      strength: opts.stegoStrength ?? stegoCfg.strength ?? 6,
      gridX: stegoCfg.gridX ?? (stegoProfile === 'robust' ? 20 : 24),
      gridY: stegoCfg.gridY ?? (stegoProfile === 'robust' ? 14 : 16),
      inPlace: true,
    });
    stegoMarked = true;
    resolvedStegoFingerprint = stegoFingerprint(stegoPayload);
  }

  const contentFingerprint = opts.contentFingerprint
    ? computePerceptualFingerprint(rawPixels, w, h)
    : null;

  const { pw, ph } = paddedSize(w, h, grid);
  const plan = buildScramblePlan(grid, key, planVersion);
  // Fused pad+scramble writes the encoder's raw input in a single pass:
  // no pad copy, no scramble copy, no Buffer.from copy. Buffer.allocUnsafe
  // is safe here because every output pixel is written by the tile loop.
  const scrambled = Buffer.allocUnsafe(pw * ph * 4);
  scramblePixelsPadded(rawPixels, w, h, plan, scrambled);

  const format = opts.format ?? 'webp';
  let encoder = sharp(scrambled, { raw: { width: pw, height: ph, channels: 4 } })
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
    return { bytes: payload, header, stegoFingerprint: resolvedStegoFingerprint, perceptualFingerprint: contentFingerprint };
  }
  return {
    bytes: bufferView(encodeContainer(header, payload)),
    header,
    stegoFingerprint: resolvedStegoFingerprint,
    perceptualFingerprint: contentFingerprint,
  };
}

export async function scrambleImage(input, opts = {}) {
  const base = await prepareDerivativeBase(input, opts);
  return finishDerivative(base, opts, true);
}

/** Reverse a plain (unencrypted, container-less) scrambled image. Test/ops helper. */
export async function unscrambleImage(scrambledBytes, { grid = 8, key = '', w, h, planVersion = 1, ...processingOpts } = {}) {
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
  let out = sharp(bufferView(raw), { raw: { width: info.width, height: info.height, channels: 4 } })
    .timeout({ seconds: limits.timeoutSec });
  if (w && h && (w !== info.width || h !== info.height)) {
    out = out.extract({ left: 0, top: 0, width: w, height: h });
  }
  try { return await out.png().toBuffer(); }
  catch (err) { throw mapSharpError(err); }
}
