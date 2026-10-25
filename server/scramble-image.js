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
  const grid = opts.grid ?? 8;
  const key = opts.key ?? '';
  const maxWidth = opts.maxWidth ?? 1600;
  const lossless = !!opts.lossless || opts.quality === 'lossless';
  const quality = lossless
    ? 100
    : Math.max(1, Math.min(100, Number(opts.quality ?? 95) || 95));

  let pipeline = sharp(input).rotate(); // bake EXIF orientation, drop metadata
  if (maxWidth) {
    pipeline = pipeline.resize({
      width: maxWidth,
      withoutEnlargement: true,
      kernel: sharp.kernel.lanczos3, // high-quality downscale, like a good <img> pipeline
    });
  }

  // Server-baked visible watermark: composited pre-scramble so that NO
  // extraction route — screenshot, canvas grab, or full payload
  // reconstruction with a stolen session key — can produce an unmarked copy.
  let watermarked = false;
  if (opts.watermark) {
    const srcMeta = await sharp(input).metadata();
    const rotated = srcMeta.orientation >= 5 && srcMeta.orientation <= 8;
    const srcW = rotated ? srcMeta.height : srcMeta.width;
    const srcH = rotated ? srcMeta.width : srcMeta.height;
    const scale = maxWidth ? Math.min(1, maxWidth / srcW) : 1;
    const tw = Math.max(1, Math.round(srcW * scale));
    const th = Math.max(1, Math.round(srcH * scale));
    const svg = watermarkSvg(tw, th, opts.watermark);
    if (svg) {
      pipeline = pipeline.composite([{ input: svg, top: 0, left: 0 }]);
      watermarked = true;
    }
  }

  const { data, info } = await pipeline.ensureAlpha().raw().toBuffer({ resolveWithObject: true });
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
  let encoder = sharp(Buffer.from(scrambled), { raw: { width: pw, height: ph, channels: 4 } });
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
  let payload = await encoder.toBuffer();
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
export async function unscrambleImage(scrambledBytes, { grid = 8, key = '', w, h } = {}) {
  const { data, info } = await sharp(scrambledBytes).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const plan = buildScramblePlan(grid, key);
  const raw = scramblePixels(new Uint8Array(data), info.width, info.height, plan, 'unscramble');
  let out = sharp(Buffer.from(raw), { raw: { width: info.width, height: info.height, channels: 4 } });
  if (w && h && (w !== info.width || h !== info.height)) {
    out = out.extract({ left: 0, top: 0, width: w, height: h });
  }
  return out.png().toBuffer();
}
