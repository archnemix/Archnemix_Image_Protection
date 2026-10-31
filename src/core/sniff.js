/**
 * Zero-dependency image header sniffing (format + dimensions) and a
 * bounded BMP decoder. Runs BEFORE any native decoder sees bytes.
 */
import { asBytes, utf8Lenient } from './bytes.js';


const IMAGE_FORMAT_MIME = Object.freeze({
  jpeg: 'image/jpeg', png: 'image/png', webp: 'image/webp', avif: 'image/avif',
  gif: 'image/gif', bmp: 'image/bmp', tiff: 'image/tiff', svg: 'image/svg+xml',
});

function readU16LE(u8, off) { return u8[off] | (u8[off + 1] << 8); }
function readU16BE(u8, off) { return (u8[off] << 8) | u8[off + 1]; }
function readU32LE(u8, off) {
  return (u8[off] | (u8[off + 1] << 8) | (u8[off + 2] << 16) | (u8[off + 3] << 24)) >>> 0;
}
function readU32BE(u8, off) {
  return ((u8[off] << 24) | (u8[off + 1] << 16) | (u8[off + 2] << 8) | u8[off + 3]) >>> 0;
}
function asciiAt(u8, off, text) {
  if (off < 0 || off + text.length > u8.length) return false;
  for (let i = 0; i < text.length; i++) if (u8[off + i] !== text.charCodeAt(i)) return false;
  return true;
}
function avifDimensions(u8) {
  // Bounded ISO-BMFF walk: meta -> iprp -> ipco -> ispe. This is only a
  // pre-decode budget check; the real decoder remains authoritative.
  const containers = new Set(['meta', 'iprp', 'ipco']);
  const walk = (start, end, depth) => {
    let off = start;
    while (off + 8 <= end && off + 8 <= u8.length) {
      let size = readU32BE(u8, off);
      const type = String.fromCharCode(u8[off + 4], u8[off + 5], u8[off + 6], u8[off + 7]);
      let header = 8;
      if (size === 1) {
        if (off + 16 > u8.length) return null;
        const big = readU32BE(u8, off + 8) * 4294967296 + readU32BE(u8, off + 12);
        if (!Number.isSafeInteger(big) || big < 16) return null;
        size = big; header = 16;
      } else if (size === 0) size = end - off;
      if (size < header || off + size > end) return null;
      const payload = off + header;
      if (type === 'ispe' && size >= header + 12) {
        const width = readU32BE(u8, payload + 4);
        const height = readU32BE(u8, payload + 8);
        if (width > 0 && height > 0) return { width, height };
      }
      if (depth < 5 && containers.has(type)) {
        const childStart = type === 'meta' ? payload + 4 : payload;
        const found = walk(childStart, off + size, depth + 1);
        if (found) return found;
      }
      off += size;
    }
    return null;
  };
  return walk(0, u8.length, 0);
}

/**
 * Sniff an encoded image's format and (for the common web formats) its
 * declared dimensions *before* handing bytes to a native decoder. A tiny
 * compressed file can declare an enormous pixel grid; checking only after
 * createImageBitmap()/Sharp has decoded it is too late to bound memory.
 * Returns `{ format, mime, width, height }`, with dimensions null when the
 * format is recognised but its header is not cheaply/safely parsed here.
 */
export function sniffImageInfo(bytes) {
  const u8 = asBytes(bytes);
  const done = (format, width = null, height = null) => Object.freeze({
    format, mime: IMAGE_FORMAT_MIME[format] || '', width, height,
  });
  if (u8.length >= 24 && u8[0] === 0x89 && asciiAt(u8, 1, 'PNG') && u8[4] === 0x0d && u8[5] === 0x0a) {
    return done('png', readU32BE(u8, 16), readU32BE(u8, 20));
  }
  if (u8.length >= 3 && u8[0] === 0xff && u8[1] === 0xd8 && u8[2] === 0xff) {
    let off = 2;
    const sof = new Set([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf]);
    while (off + 4 <= u8.length) {
      if (u8[off] !== 0xff) { off++; continue; }
      let markerAt = off + 1;
      while (markerAt < u8.length && u8[markerAt] === 0xff) markerAt++;
      if (markerAt >= u8.length) break;
      const marker = u8[markerAt];
      if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { off = markerAt + 1; continue; }
      if (marker === 0xda || markerAt + 3 > u8.length) break;
      const len = readU16BE(u8, markerAt + 1);
      if (len < 2) break;
      if (sof.has(marker) && len >= 7 && markerAt + 8 <= u8.length) {
        return done('jpeg', readU16BE(u8, markerAt + 6), readU16BE(u8, markerAt + 4));
      }
      off = markerAt + 1 + len;
    }
    return done('jpeg');
  }
  if (u8.length >= 10 && (asciiAt(u8, 0, 'GIF87a') || asciiAt(u8, 0, 'GIF89a'))) {
    return done('gif', readU16LE(u8, 6), readU16LE(u8, 8));
  }
  if (u8.length >= 26 && asciiAt(u8, 0, 'BM')) {
    const width = readU32LE(u8, 18) | 0;
    const height = Math.abs(readU32LE(u8, 22) | 0);
    return done('bmp', width > 0 ? width : null, height > 0 ? height : null);
  }
  if (u8.length >= 20 && asciiAt(u8, 0, 'RIFF') && asciiAt(u8, 8, 'WEBP')) {
    if (asciiAt(u8, 12, 'VP8X') && u8.length >= 30) {
      return done('webp', 1 + (u8[24] | (u8[25] << 8) | (u8[26] << 16)), 1 + (u8[27] | (u8[28] << 8) | (u8[29] << 16)));
    }
    if (asciiAt(u8, 12, 'VP8L') && u8.length >= 25 && u8[20] === 0x2f) {
      const bits = readU32LE(u8, 21);
      return done('webp', (bits & 0x3fff) + 1, ((bits >>> 14) & 0x3fff) + 1);
    }
    if (asciiAt(u8, 12, 'VP8 ') && u8.length >= 30 && u8[23] === 0x9d && u8[24] === 0x01 && u8[25] === 0x2a) {
      return done('webp', readU16LE(u8, 26) & 0x3fff, readU16LE(u8, 28) & 0x3fff);
    }
    return done('webp');
  }
  if (u8.length >= 12 && asciiAt(u8, 4, 'ftyp')) {
    let isAvif = false;
    for (let off = 8; off + 4 <= Math.min(u8.length, 64); off += 4) {
      if (asciiAt(u8, off, 'avif') || asciiAt(u8, off, 'avis')) { isAvif = true; break; }
    }
    if (isAvif) {
      const dims = avifDimensions(u8);
      return done('avif', dims?.width || null, dims?.height || null);
    }
  }
  if ((u8.length >= 4 && u8[0] === 0x49 && u8[1] === 0x49 && u8[2] === 0x2a && u8[3] === 0) ||
      (u8.length >= 4 && u8[0] === 0x4d && u8[1] === 0x4d && u8[2] === 0 && u8[3] === 0x2a)) {
    return done('tiff');
  }
  const head = utf8Lenient.decode(u8.subarray(0, Math.min(1024, u8.length))).trimStart().toLowerCase();
  if (head.startsWith('<svg') || (head.startsWith('<?xml') && head.includes('<svg'))) return done('svg');
  return null;
}

export function sniffImageFormat(bytes) {
  return sniffImageInfo(bytes)?.format || null;
}

/**
 * Strict, bounded decoder for ordinary uncompressed BMP screenshots.
 * Supports 24/32-bit BI_RGB files with a BITMAPINFOHEADER-or-later DIB
 * header; palette, RLE, bitfield, and truncated/oversized files fail closed.
 * This exists for offline `archx-detect` investigations because Sharp does
 * not expose a BMP input decoder. It is not a general BMP implementation.
 */
export function decodeBmpImage(bytes, { maxPixels = 100000000 } = {}) {
  if (!Number.isSafeInteger(maxPixels) || maxPixels < 1) {
    throw new RangeError('Archx: BMP pixel limit is invalid');
  }
  const u8 = asBytes(bytes);
  const fail = (message) => { throw new TypeError(`Archx: invalid BMP image (${message})`); };
  if (u8.length < 54 || u8[0] !== 0x42 || u8[1] !== 0x4d) fail('missing BM header');
  const view = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  const fileSize = view.getUint32(2, true);
  if (fileSize !== 0 && fileSize > u8.length) fail('declared file size exceeds input');
  const dataOffset = view.getUint32(10, true);
  const dibSize = view.getUint32(14, true);
  if (dibSize < 40 || dibSize > 124 || 14 + dibSize > u8.length) fail('unsupported DIB header');
  if (dataOffset < 14 + dibSize || dataOffset >= u8.length) fail('invalid pixel-data offset');
  const width = view.getInt32(18, true);
  const signedHeight = view.getInt32(22, true);
  const planes = view.getUint16(26, true);
  const bitsPerPixel = view.getUint16(28, true);
  const compression = view.getUint32(30, true);
  const declaredImageSize = view.getUint32(34, true);
  const height = Math.abs(signedHeight);
  if (width <= 0 || height <= 0 || planes !== 1) fail('invalid dimensions/planes');
  if (![24, 32].includes(bitsPerPixel) || compression !== 0) fail('only uncompressed 24/32-bit BI_RGB is supported');
  const pixels = width * height;
  if (!Number.isSafeInteger(pixels) || pixels > maxPixels) fail('pixel limit exceeded');
  const bytesPerPixel = bitsPerPixel / 8;
  const stride = Math.floor(((bitsPerPixel * width + 31) / 32)) * 4;
  const pixelBytes = stride * height;
  if (!Number.isSafeInteger(pixelBytes) || dataOffset + pixelBytes > u8.length) fail('truncated pixel data');
  if (declaredImageSize !== 0 && declaredImageSize < pixelBytes) fail('declared image size is too small');
  const data = new Uint8Array(pixels * 4);
  const topDown = signedHeight < 0;
  for (let y = 0; y < height; y++) {
    const sourceY = topDown ? y : height - 1 - y;
    let source = dataOffset + sourceY * stride;
    let dest = y * width * 4;
    for (let x = 0; x < width; x++) {
      data[dest] = u8[source + 2];
      data[dest + 1] = u8[source + 1];
      data[dest + 2] = u8[source];
      // Many 32-bit BMPs leave the fourth byte reserved/zero rather than
      // using it as alpha; screenshots are opaque, so preserve nonzero alpha
      // and normalize the reserved-zero form to opaque.
      data[dest + 3] = bitsPerPixel === 32 && u8[source + 3] !== 0 ? u8[source + 3] : 255;
      source += bytesPerPixel;
      dest += 4;
    }
  }
  return Object.freeze({ data, width, height, channels: 4 });
}
