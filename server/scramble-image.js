/**
 * Server-side image scrambling (Node + sharp).
 * Takes a master image, down-scales it to web resolution, strips metadata,
 * tile-scrambles its pixels, and (optionally) AES-GCM-encrypts the result
 * inside an .archx container. The master file itself is never sent.
 */
import sharp from 'sharp';
import {
  buildScramblePlan, paddedSize, scramblePixels,
  encodeContainer, encryptPayload, generateKeyBase64,
} from '../src/scramble.js';

export { generateKeyBase64 };

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
 * @param {object} opts { grid, key, maxWidth, quality, format, aesKey, container }
 * @returns {Promise<{bytes:Buffer, header:object}>} bytes = .archx container (or plain scrambled image when container:false)
 */
export async function scrambleImage(input, opts = {}) {
  const grid = opts.grid ?? 8;
  const key = opts.key ?? '';
  const maxWidth = opts.maxWidth ?? 1600;
  const quality = opts.quality ?? 82;

  let pipeline = sharp(input).rotate(); // bake EXIF orientation, drop metadata
  if (maxWidth) pipeline = pipeline.resize({ width: maxWidth, withoutEnlargement: true });
  const { data, info } = await pipeline.ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const w = info.width;
  const h = info.height;
  const { pw, ph } = paddedSize(w, h, grid);
  const padded = padRaw(new Uint8Array(data), w, h, pw, ph);
  const plan = buildScramblePlan(grid, key);
  const scrambled = scramblePixels(padded, pw, ph, plan, 'scramble');

  const format = opts.format ?? 'webp';
  let encoder = sharp(Buffer.from(scrambled), { raw: { width: pw, height: ph, channels: 4 } });
  encoder = format === 'png' ? encoder.png() : format === 'jpeg' ? encoder.jpeg({ quality }) : encoder.webp({ quality });
  let payload = await encoder.toBuffer();
  const mime = format === 'png' ? 'image/png' : format === 'jpeg' ? 'image/jpeg' : 'image/webp';

  const header = {
    v: 1, w, h, pw, ph, grid, mime, scrambled: true, encrypted: false,
  };
  if (opts.aesKey) {
    const { cipher, iv } = await encryptPayload(payload, opts.aesKey);
    payload = Buffer.from(cipher);
    header.encrypted = true;
    header.iv = iv;
  }
  if (opts.container === false) {
    if (header.encrypted) throw new Error('encrypted output requires an .archx container');
    return { bytes: payload, header };
  }
  return { bytes: Buffer.from(encodeContainer(header, payload)), header };
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
