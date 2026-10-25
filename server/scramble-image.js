/**
 * Server-side image scrambling (Node + sharp).
 * Takes a master image, down-scales it to web resolution, strips metadata,
 * tile-scrambles its pixels, and (optionally) AES-GCM-encrypts the result
 * inside an .archx container. The master file itself is never sent.
 */
import sharp from 'sharp';
import {
  buildScramblePlan, paddedSize, scramblePixels,
  encodeContainer, encryptPayload, generateKeyBase64, applyForensicBlocks,
  embedStegoFingerprint, stegoFingerprint,
} from '../src/scramble.js';

export { generateKeyBase64 };

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
  const nested = opts.processing && typeof opts.processing === 'object' ? opts.processing : {};
  const pick = (...names) => {
    for (const name of names) {
      if (opts[name] != null) return opts[name];
      if (nested[name] != null) return nested[name];
    }
    return undefined;
  };
  const integer = (name, value, fallback, min, max) => {
    const n = value == null ? fallback : Number(value);
    if (!Number.isFinite(n) || n < min || n > max) {
      throw new TypeError(`Archx image processing: ${name} must be from ${min} to ${max}`);
    }
    return Math.floor(n);
  };
  const timeoutRaw = pick('processingTimeoutSec', 'timeoutSec');
  const timeoutSec = timeoutRaw == null ? 10 : Number(timeoutRaw);
  if (!Number.isFinite(timeoutSec) || timeoutSec < 1 || timeoutSec > 120) {
    throw new TypeError('Archx image processing: processingTimeoutSec must be from 1 to 120');
  }
  const allowedRaw = pick('allowedInputFormats') ?? ['jpeg', 'png', 'webp', 'avif'];
  const allowedInputFormats = [...new Set((Array.isArray(allowedRaw) ? allowedRaw : []).map((f) => String(f).toLowerCase()))]
    .filter((f) => ['jpeg', 'png', 'webp', 'avif', 'gif', 'tiff'].includes(f));
  if (!allowedInputFormats.length) {
    throw new TypeError('Archx image processing: allowedInputFormats must contain a supported format');
  }
  return Object.freeze({
    maxInputBytes: integer('maxInputBytes', pick('maxInputBytes'), 50 * 1024 * 1024, 1024, 500 * 1024 * 1024),
    maxInputPixels: integer('maxInputPixels', pick('maxInputPixels'), 40000000, 10000, 268402689),
    maxInputWidth: integer('maxInputWidth', pick('maxInputWidth'), 12000, 64, 65536),
    maxInputHeight: integer('maxInputHeight', pick('maxInputHeight'), 12000, 64, 65536),
    maxOutputPixels: integer('maxOutputPixels', pick('maxOutputPixels'), 16777216, 10000, 268402689),
    timeoutSec,
    allowedInputFormats: Object.freeze(allowedInputFormats),
  });
}

function sharpInput(input, limits, extra = {}) {
  return sharp(input, {
    failOn: 'warning',
    limitInputPixels: limits.maxInputPixels,
    sequentialRead: true,
    animated: false,
    ...extra,
  }).timeout({ seconds: limits.timeoutSec });
}

function assertInputWithinLimits(input, limits) {
  const length = input?.length ?? input?.byteLength ?? 0;
  if (!length) throw processingError('ARCHX_UNSUPPORTED_IMAGE', 'empty input image');
  if (length > limits.maxInputBytes) {
    throw processingError('ARCHX_INPUT_TOO_LARGE', 'input image exceeds the configured byte budget');
  }
}

function assertMetadataWithinLimits(meta, limits) {
  if (!meta || !limits.allowedInputFormats.includes(meta.format) || !meta.width || !meta.height) {
    throw processingError('ARCHX_UNSUPPORTED_IMAGE', 'unsupported input image format');
  }
  if ((meta.pages || 1) > 1 || (meta.channels || 3) > 4) {
    throw processingError('ARCHX_UNSUPPORTED_IMAGE', 'animated or multi-channel input images are not accepted');
  }
  if (meta.width > limits.maxInputWidth || meta.height > limits.maxInputHeight ||
      meta.width * meta.height > limits.maxInputPixels) {
    throw processingError('ARCHX_INPUT_TOO_LARGE', 'input image exceeds the configured dimension budget');
  }
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
  const angle = cfg.angle ?? -24;
  let body = '';
  if (cfg.tile !== false) {
    const rows = [];
    const diag = Math.hypot(w, h);
    for (let y = -diag / 2; y < diag / 2; y += fs * 4.2) {
      rows.push(`<text x="0" y="${y.toFixed(0)}" text-anchor="middle">${text}</text>`);
    }
    body += `<g transform="translate(${w / 2} ${h / 2}) rotate(${angle})" opacity="${cfg.opacity ?? 0.15}" font-size="${fs}" font-weight="700">${rows.join('')}</g>`;
  }
  if (cfg.corner !== false) {
    const cfs = Math.max(10, Math.round(Math.min(w, h) / 34));
    body += `<g opacity="${cfg.cornerOpacity ?? 0.9}" font-size="${cfs}" font-weight="600"><text x="${w - 11}" y="${h - 10}" text-anchor="end" stroke="rgba(0,0,0,0.65)" stroke-width="3" paint-order="stroke">${text}</text></g>`;
  }
  return Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}"><g font-family="Arial, Helvetica, sans-serif" fill="${color}">${body}</g></svg>`);
}

/** Pad a raw RGBA buffer (w×h) into pw×ph with black. */
function padRaw(raw, w, h, pw, ph) {
  if (w === pw && h === ph) return raw;
  const out = new Uint8Array(pw * ph * 4);
  for (let i = 3; i < out.length; i += 4) out[i] = 255; // opaque black pad
  for (let y = 0; y < h; y++) {
    out.set(raw.subarray(y * w * 4, (y + 1) * w * 4), y * pw * 4);
  }
  return out;
}

/**
 * @param {Buffer} input master image bytes
 * @param {object} opts { grid, key, maxWidth, quality, lossless, format, aesKey, container }
 * `quality` defaults to 95 (delivery-size pixels should look like the source,
 * not like a recompressed thumbnail); pass `lossless:true` for bit-exact
 * WebP/PNG pixels at the delivered size when payload size matters less.
 * @returns {Promise<{bytes:Buffer, header:object}>} bytes = .archx container (or plain scrambled image when container:false)
 */
export async function scrambleImage(input, opts = {}) {
  const limits = normalizeProcessingOptions(opts);
  assertInputWithinLimits(input, limits);
  const grid = opts.grid ?? 8;
  if (!Number.isInteger(grid) || grid < 2 || grid > 32) throw new TypeError('Archx image processing: grid must be an integer from 2 to 32');
  const key = opts.key ?? '';
  const maxWidth = opts.maxWidth ?? 1600;
  if (maxWidth !== 0 && (!Number.isInteger(maxWidth) || maxWidth < 64 || maxWidth > 8192)) {
    throw new TypeError('Archx image processing: maxWidth must be 0 or an integer from 64 to 8192');
  }
  const lossless = !!opts.lossless || opts.quality === 'lossless';
  const quality = lossless
    ? 100
    : Math.max(1, Math.min(100, Number(opts.quality ?? 95) || 95));

  let srcMeta;
  try { srcMeta = await sharpInput(input, limits).metadata(); }
  catch (err) { throw mapSharpError(err); }
  assertMetadataWithinLimits(srcMeta, limits);
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

  let pipeline = sharpInput(input, limits).rotate() // bake EXIF orientation, drop metadata
    .resize({
      width: tw,
      height: th,
      withoutEnlargement: true,
      kernel: sharp.kernel.lanczos3, // high-quality downscale, like a good <img> pipeline
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

  // Block-level forensic mark (also pre-scramble): survives into any
  // reconstructed copy and can be correlated against the viewing session.
  let rawPixels = new Uint8Array(data);
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
    rawPixels = embedStegoFingerprint(rawPixels, w, h, stegoPayload, {
      key: opts.stegoKey ?? stegoCfg.key ?? key,
      strength: opts.stegoStrength ?? stegoCfg.strength ?? 6,
      gridX: stegoCfg.gridX ?? 24,
      gridY: stegoCfg.gridY ?? 16,
    });
    stegoMarked = true;
    resolvedStegoFingerprint = stegoFingerprint(stegoPayload);
  }

  const { pw, ph } = paddedSize(w, h, grid);
  const padded = padRaw(rawPixels, w, h, pw, ph);
  const plan = buildScramblePlan(grid, key);
  const scrambled = scramblePixels(padded, pw, ph, plan, 'scramble');

  const format = opts.format ?? 'webp';
  let encoder = sharp(Buffer.from(scrambled), { raw: { width: pw, height: ph, channels: 4 } })
    .timeout({ seconds: limits.timeoutSec });
  if (format === 'png') {
    encoder = encoder.png({ compressionLevel: 9, adaptiveFiltering: true });
  } else if (format === 'jpeg') {
    // 4:4:4 keeps colour edges/text crisp instead of chroma-subsampled slurry.
    encoder = encoder.jpeg({ quality, chromaSubsampling: '4:4:4', mozjpeg: true });
  } else if (lossless) {
    encoder = encoder.webp({ lossless: true, alphaQuality: 100, effort: 4 });
  } else {
    encoder = encoder.webp({ quality, alphaQuality: 100, smartSubsample: true, effort: 4 });
  }
  let payload;
  try { payload = await encoder.toBuffer(); }
  catch (err) { throw mapSharpError(err); }
  const mime = format === 'png' ? 'image/png' : format === 'jpeg' ? 'image/jpeg' : 'image/webp';

  const header = {
    v: 1, w, h, pw, ph, grid, mime, scrambled: true, encrypted: false,
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
    return { bytes: payload, header, stegoFingerprint: resolvedStegoFingerprint };
  }
  return {
    bytes: Buffer.from(encodeContainer(header, payload)),
    header,
    stegoFingerprint: resolvedStegoFingerprint,
  };
}

/** Reverse a plain (unencrypted, container-less) scrambled image. Test/ops helper. */
export async function unscrambleImage(scrambledBytes, { grid = 8, key = '', w, h, ...processingOpts } = {}) {
  const limits = normalizeProcessingOptions(processingOpts);
  assertInputWithinLimits(scrambledBytes, limits);
  let data, info;
  try {
    ({ data, info } = await sharpInput(scrambledBytes, limits).ensureAlpha().raw().toBuffer({ resolveWithObject: true }));
  } catch (err) { throw mapSharpError(err); }
  const plan = buildScramblePlan(grid, key);
  const raw = scramblePixels(new Uint8Array(data), info.width, info.height, plan, 'unscramble');
  let out = sharp(Buffer.from(raw), { raw: { width: info.width, height: info.height, channels: 4 } })
    .timeout({ seconds: limits.timeoutSec });
  if (w && h && (w !== info.width || h !== info.height)) {
    out = out.extract({ left: 0, top: 0, width: w, height: h });
  }
  return out.png().toBuffer();
}
