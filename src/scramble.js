/**
 * Archnemix Image Protection — shared scramble / container / crypto core.
 *
 * This module is isomorphic: the exact same code runs in the browser
 * (to un-scramble while painting) and in Node (to scramble on the server).
 * Keeping one implementation guarantees both sides agree on the permutation.
 *
 * Scramble scheme (v1)
 * --------------------
 * The (padded) image is cut into a `grid × grid` matrix of equal tiles.
 * A key-seeded PRNG produces:
 *   - `order[]`  : order[scrambledPos] = originalPos   (Fisher–Yates shuffle)
 *   - `flips[]`  : per scrambled-position { fx, fy } mirror flags
 * Mirrors are their own inverse, so un-scrambling applies the same flags.
 * 0/180° rotations are covered because fx+fy together == 180° rotation.
 * 90° rotations are intentionally not used: tiles are not square in
 * general, and a 90° turn would change a tile's aspect ratio.
 *
 * The scrambled payload is still a *valid* image file (WebP/PNG/JPEG) —
 * it just looks like a shuffled mosaic. Anyone who captures it from the
 * Network tab gets garbage unless they also obtain the key *and* re-implement
 * this exact un-shuffle. That stops bulk scrapers, download extensions and
 * casual DevTools theft cold. (A determined reverser who reads this file can
 * un-shuffle one image at web resolution — see docs/RESEARCH.md for why no
 * web-only scheme can do better than "very expensive to steal".)
 */

export const ARCHX_MAGIC = 'ARCHX1';
export const DEFAULT_GRID = 8;

/* ------------------------------------------------------------------ */
/* Seeded PRNG                                                          */
/* ------------------------------------------------------------------ */

/** cyrb53 string hash -> 53-bit integer seed. */
export function hashSeed(str, seed = 0) {
  let h1 = 0xdeadbeef ^ seed;
  let h2 = 0x41c6ce57 ^ seed;
  const s = String(str);
  for (let i = 0, ch; i < s.length; i++) {
    ch = s.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return 4294967296 * (2097151 & h2) + (h1 >>> 0);
}

/** mulberry32 — tiny fast deterministic PRNG. */
export function mulberry32(seed) {
  let a = seed >>> 0;
  return function next() {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/* ------------------------------------------------------------------ */
/* Scramble plan                                                        */
/* ------------------------------------------------------------------ */

/** cyrb128 — 128-bit string hash (public-domain algorithm) for plan v2 seeds. */
export function cyrb128(str) {
  const s = String(str);
  let h1 = 1779033703, h2 = 3144134277, h3 = 1013904242, h4 = 2773480762;
  for (let i = 0, k; i < s.length; i++) {
    k = s.charCodeAt(i);
    h1 = h2 ^ Math.imul(h1 ^ k, 597399067);
    h2 = h3 ^ Math.imul(h2 ^ k, 2869860233);
    h3 = h4 ^ Math.imul(h3 ^ k, 951274213);
    h4 = h1 ^ Math.imul(h4 ^ k, 2716044179);
  }
  h1 = Math.imul(h3 ^ (h1 >>> 18), 597399067);
  h2 = Math.imul(h4 ^ (h2 >>> 22), 2869860233);
  h3 = Math.imul(h1 ^ (h3 >>> 17), 951274213);
  h4 = Math.imul(h2 ^ (h4 >>> 19), 2716044179);
  return [(h1 ^ h2 ^ h3 ^ h4) >>> 0, (h2 ^ h1) >>> 0, (h3 ^ h1) >>> 0, (h4 ^ h1) >>> 0];
}

/** sfc32 — small fast counter-based PRNG with a 128-bit state. */
export function sfc32(a, b, c, d) {
  return function next() {
    a >>>= 0; b >>>= 0; c >>>= 0; d >>>= 0;
    let t = (a + b | 0) + d | 0;
    d = (d + 1) | 0;
    a = b ^ (b >>> 9);
    b = (c + (c << 3)) | 0;
    c = (c << 21) | (c >>> 11);
    c = (c + t) | 0;
    return (t >>> 0) / 4294967296;
  };
}

/**
 * Build the deterministic scramble plan for a key.
 * @param {number} grid tiles per side (2..32)
 * @param {string} key  secret seed material
 * @param {number} [version=1] plan derivation version. **1** is the legacy
 *   32-bit-seed plan (kept for payload compatibility). **2** derives the
 *   permutation from a 128-bit seed (cyrb128 + sfc32), so recovering the
 *   permutation by seed brute force is infeasible; the tile permutation is
 *   still obfuscation, not encryption — use the AES-GCM layer for secrecy.
 * @returns {{grid:number,count:number,version:number,order:number[],inverse:number[],flips:{fx:boolean,fy:boolean}[]}}
 *   order[scrambledPos]   = originalPos
 *   inverse[originalPos]  = scrambledPos
 */
export function buildScramblePlan(grid = DEFAULT_GRID, key = '', version = 1) {
  if (version !== 1 && version !== 2) throw new TypeError('Archx: scramble plan version must be 1 or 2');
  const g = Math.max(2, Math.min(32, grid | 0));
  const count = g * g;
  let rand;
  if (version === 2) {
    rand = sfc32(...cyrb128(String(key) + '::archx-grid2-' + g));
    for (let i = 0; i < 8; i++) rand(); // diffuse the state before shuffling
  } else {
    rand = mulberry32(hashSeed(String(key) + '::archx-grid-' + g));
  }
  const order = Array.from({ length: count }, (_, i) => i);
  for (let i = count - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }
  const flips = Array.from({ length: count }, () => ({
    fx: rand() < 0.5,
    fy: rand() < 0.5,
  }));
  const inverse = new Array(count);
  order.forEach((orig, scrambledPos) => { inverse[orig] = scrambledPos; });
  return { grid: g, count, version, order, inverse, flips };
}

/** Pixel rect of tile `index` in a padded image of tile size tw×th. */
export function tileRect(index, grid, tw, th) {
  return { x: (index % grid) * tw, y: Math.floor(index / grid) * th, w: tw, h: th };
}

/** Padded dimensions so both sides divide exactly by `grid`. */
export function paddedSize(w, h, grid) {
  if (!Number.isInteger(w) || !Number.isInteger(h) || w < 1 || h < 1 ||
      !Number.isInteger(grid) || grid < 2 || grid > 32) {
    throw new RangeError('Archx: invalid image/grid dimensions');
  }
  const tw = Math.ceil(w / grid);
  const th = Math.ceil(h / grid);
  return { tw, th, pw: tw * grid, ph: th * grid };
}

function asBytes(bytes) {
  if (bytes instanceof Uint8Array) return bytes;
  if (bytes instanceof ArrayBuffer) return new Uint8Array(bytes);
  if (ArrayBuffer.isView(bytes)) return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return new Uint8Array(bytes || []);
}

// Shared codec instances: constructing these per call is measurable churn
// on the per-image path (sniff + container decode) and entirely avoidable.
const utf8Encoder = new TextEncoder();
const utf8Fatal = new TextDecoder('utf-8', { fatal: true });
const utf8Lenient = new TextDecoder('utf-8', { fatal: false });
// Methods captured at module evaluation and called with explicit receivers,
// so a TextDecoder/TextEncoder prototype hook installed after this module
// loads cannot skim container headers or token JSON in the browser bundle.
const textDecodeCall = TextDecoder.prototype.decode;
const textEncodeCall = TextEncoder.prototype.encode;
function utf8Encode(str) { return textEncodeCall.call(utf8Encoder, str); }
function utf8DecodeFatal(bytes) { return textDecodeCall.call(utf8Fatal, bytes); }

/* ------------------------------------------------------------------ */
/* SHA-256 + HMAC (FIPS 180-4 / RFC 2104), synchronous and portable.   */
/* Exists so StegoMark codeword tags can be keyed with a real MAC in   */
/* both Node and the browser bundle, where WebCrypto is async-only.   */
/* ------------------------------------------------------------------ */
const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export function sha256Bytes(message) {
  const msg = asBytes(message);
  const bitLenHi = Math.floor(msg.length / 0x20000000);
  const bitLenLo = msg.length << 3;
  const paddedLen = (((msg.length + 9 + 63) >> 6) << 6);
  const buf = new Uint8Array(paddedLen);
  buf.set(msg, 0);
  buf[msg.length] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(paddedLen - 4, bitLenLo >>> 0, false);
  dv.setUint32(paddedLen - 8, bitLenHi >>> 0, false);
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let block = 0; block < paddedLen; block += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(block + t * 4, false);
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
      const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
    for (let t = 0; t < 64; t++) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (hh + s1 + ch + SHA256_K[t] + w[t]) >>> 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (s0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + temp1) >>> 0;
      d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + hh) >>> 0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  [h0, h1, h2, h3, h4, h5, h6, h7].forEach((word, i) => odv.setUint32(i * 4, word, false));
  return out;
}

export function hmacSha256Bytes(key, message) {
  let keyBytes = asBytes(key);
  if (keyBytes.length > 64) keyBytes = sha256Bytes(keyBytes);
  const inner = new Uint8Array(64 + asBytes(message).length);
  const outer = new Uint8Array(64 + 32);
  for (let i = 0; i < 64; i++) {
    const kb = i < keyBytes.length ? keyBytes[i] : 0;
    inner[i] = kb ^ 0x36;
    outer[i] = kb ^ 0x5c;
  }
  inner.set(asBytes(message), 64);
  outer.set(sha256Bytes(inner), 64);
  return sha256Bytes(outer);
}

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

/* ------------------------------------------------------------------ */
/* Base64 helpers (browser + Node)                                      */
/* ------------------------------------------------------------------ */

export function bytesToBase64(bytes) {
  const u8 = asBytes(bytes);
  if (typeof Buffer !== 'undefined') return Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength).toString('base64');
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < u8.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

export function base64ToBytes(b64) {
  if (typeof b64 !== 'string') throw new TypeError('Archx: base64 value must be a string');
  let normalized = b64.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.endsWith('==') ? 2 : normalized.endsWith('=') ? 1 : 0;
  if (normalized.includes('=') && normalized.indexOf('=') !== normalized.length - padding) {
    throw new Error('Archx: invalid base64 value');
  }
  if (normalized.length % 4 === 1 || !/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
    throw new Error('Archx: invalid base64 value');
  }
  if (normalized.length % 4) normalized += '='.repeat(4 - (normalized.length % 4));
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(normalized, 'base64'));
  const bin = atob(normalized);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/* ------------------------------------------------------------------ */
/* .archx container format                                              */
/* ------------------------------------------------------------------ */

/**
 * Layout:  "ARCHX1" | uint32BE headerLen | header JSON (utf8) | payload
 * Header:  { v, w, h, pw, ph, grid, mime, scrambled, encrypted, iv? }
 * Payload: image file bytes (scrambled pixels), optionally AES-GCM encrypted.
 * The content-type on the wire is application/octet-stream — DevTools does
 * not classify it as an image at all.
 */
export const MAX_ARCHX_HEADER_BYTES = 16384;
const ARCHX_MAGIC_BYTES = Object.freeze([...ARCHX_MAGIC].map((c) => c.charCodeAt(0)));
const ARCHX_HEADER_FIELDS = new Set([
  'v', 'w', 'h', 'pw', 'ph', 'grid', 'mime', 'scrambled', 'encrypted', 'iv', 'wm', 'fx', 'sg', 'pv',
]);
const ARCHX_MIME_FORMATS = Object.freeze({
  'image/webp': 'webp', 'image/png': 'png', 'image/jpeg': 'jpeg', 'image/avif': 'avif',
});

/** Validate the version-1 .archx header before any payload bytes are decoded. */
export function validateArchxHeader(header) {
  const fail = (message) => { throw new Error(`Archx: invalid .archx header (${message})`); };
  if (!header || typeof header !== 'object' || Array.isArray(header)) fail('not an object');
  for (const field of Object.keys(header)) if (!ARCHX_HEADER_FIELDS.has(field)) fail(`unknown field ${field}`);
  if (header.v !== 1) fail('unsupported version');
  for (const field of ['w', 'h', 'pw', 'ph']) {
    if (!Number.isSafeInteger(header[field]) || header[field] < 1 || header[field] > 65536) fail(`bad ${field}`);
  }
  if (!Number.isInteger(header.grid) || header.grid < 2 || header.grid > 32) fail('bad grid');
  if (header.pv !== undefined && header.pv !== 1 && header.pv !== 2) fail('bad plan version');
  const padded = paddedSize(header.w, header.h, header.grid);
  if (header.pw !== padded.pw || header.ph !== padded.ph) fail('padded dimensions do not match');
  if (!ARCHX_MIME_FORMATS[header.mime]) fail('unsupported MIME type');
  if (typeof header.scrambled !== 'boolean' || typeof header.encrypted !== 'boolean') fail('bad flags');
  for (const field of ['wm', 'fx', 'sg']) {
    if (header[field] !== undefined && header[field] !== 0 && header[field] !== 1 && header[field] !== true && header[field] !== false) {
      fail(`bad ${field} flag`);
    }
  }
  if (header.encrypted) {
    if (typeof header.iv !== 'string') fail('missing IV');
    try { if (base64ToBytes(header.iv).length !== 12) fail('bad IV length'); }
    catch (err) { if (/invalid \.archx header/.test(err.message)) throw err; fail('bad IV encoding'); }
  } else if (header.iv !== undefined) fail('unexpected IV');
  return header;
}

export function encodeContainer(header, payload) {
  validateArchxHeader(header);
  const headerBytes = utf8Encode(JSON.stringify(header));
  if (headerBytes.length > MAX_ARCHX_HEADER_BYTES) throw new Error('Archx: .archx header is too large');
  const body = asBytes(payload);
  if (!body.length) throw new Error('Archx: .archx payload is empty');
  const out = new Uint8Array(6 + 4 + headerBytes.length + body.length);
  out.set(ARCHX_MAGIC_BYTES, 0);
  new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(6, headerBytes.length, false);
  out.set(headerBytes, 10);
  out.set(body, 10 + headerBytes.length);
  return out;
}

export function isArchxContainer(bytes) {
  if (!bytes) return false;
  const u8 = asBytes(bytes);
  return u8.length >= 10 && ARCHX_MAGIC_BYTES.every((c, i) => u8[i] === c);
}

let coreJsonParse = null;
/**
 * Supply the JSON parser used for container headers (which carry the
 * per-response AES key for encrypted containers). The browser client passes
 * its load-time-captured native JSON.parse so a JSON.parse hook installed
 * later cannot skim keys; Node/library use can leave the default. Passing a
 * non-function resets to the ambient JSON.parse.
 */
export function useJsonParser(fn) {
  coreJsonParse = typeof fn === 'function' ? fn : null;
}

export function decodeContainer(bytes) {
  const u8 = asBytes(bytes);
  if (!isArchxContainer(u8)) throw new Error('Archx: not an .archx container');
  const headerLen = new DataView(u8.buffer, u8.byteOffset, u8.byteLength).getUint32(6, false);
  if (!Number.isSafeInteger(headerLen) || headerLen < 2 || headerLen > MAX_ARCHX_HEADER_BYTES ||
      10 + headerLen >= u8.length) {
    throw new Error('Archx: invalid .archx header length');
  }
  let header;
  try {
    header = (coreJsonParse || JSON.parse)(utf8DecodeFatal(u8.subarray(10, 10 + headerLen)));
  } catch { throw new Error('Archx: invalid .archx header encoding'); }
  validateArchxHeader(header);
  const payload = u8.subarray(10 + headerLen);
  if (!payload.length) throw new Error('Archx: invalid .archx payload');
  return { header, payload };
}

/* ------------------------------------------------------------------ */
/* AES-GCM payload encryption (WebCrypto — available in Node ≥19 too)   */
/* ------------------------------------------------------------------ */

const keyCache = new Map(); // base64 key -> Promise<CryptoKey>; deliberately small and LRU-bounded
const AES_KEY_CACHE_MAX = 16;

// The browser client captures SubtleCrypto methods at load and injects
// them here (mirroring useJsonParser) so a SubtleCrypto hook installed
// later cannot skim keys/plaintext: calls go through the captured
// prototype methods with the captured subtle object as receiver.
let coreWebCrypto = null; // { subtle, importKey?, encrypt?, decrypt?, digest?, getRandomValues? }
export function useWebCrypto(injected) {
  if (!injected || typeof injected !== 'object' || !injected.subtle) {
    coreWebCrypto = null;
  } else {
    coreWebCrypto = {
      subtle: injected.subtle,
      importKey: typeof injected.importKey === 'function' ? injected.importKey : null,
      encrypt: typeof injected.encrypt === 'function' ? injected.encrypt : null,
      decrypt: typeof injected.decrypt === 'function' ? injected.decrypt : null,
      digest: typeof injected.digest === 'function' ? injected.digest : null,
      getRandomValues: typeof injected.getRandomValues === 'function' ? injected.getRandomValues : null,
      cryptoObj: injected.cryptoObj || null,
    };
  }
  keyCache.clear(); // CryptoKeys belong to the subtle instance that made them
}
function subtleCall(name, args) {
  if (coreWebCrypto) {
    const fn = coreWebCrypto[name];
    if (fn) return fn.call(coreWebCrypto.subtle, ...args);
    return coreWebCrypto.subtle[name](...args);
  }
  return globalThis.crypto.subtle[name](...args);
}
function randomFill(bytes) {
  if (coreWebCrypto?.getRandomValues) {
    return coreWebCrypto.getRandomValues.call(coreWebCrypto.cryptoObj || globalThis.crypto, bytes);
  }
  return globalThis.crypto.getRandomValues(bytes);
}

async function importAesKey(keyBase64) {
  if (typeof keyBase64 !== 'string' || !keyBase64) throw new TypeError('Archx: AES key must be a base64 string');
  const cached = keyCache.get(keyBase64);
  if (cached) {
    keyCache.delete(keyBase64); keyCache.set(keyBase64, cached);
    return cached;
  }
  const pending = (async () => {
    const raw = base64ToBytes(keyBase64);
    try {
      if (![16, 24, 32].includes(raw.length)) {
        throw new Error('Archx: AES key must be 16/24/32 bytes (base64)');
      }
      return await subtleCall('importKey', [
        'raw', raw, { name: 'AES-GCM', length: raw.length * 8 }, false, ['encrypt', 'decrypt'],
      ]);
    } finally {
      raw.fill(0); // key material now lives only in the non-extractable CryptoKey
    }
  })();
  keyCache.set(keyBase64, pending);
  while (keyCache.size > AES_KEY_CACHE_MAX) keyCache.delete(keyCache.keys().next().value);
  try { return await pending; }
  catch (err) { if (keyCache.get(keyBase64) === pending) keyCache.delete(keyBase64); throw err; }
}

/** Generate a fresh 256-bit key, base64-encoded. */
export function generateKeyBase64() {
  const raw = new Uint8Array(32);
  randomFill(raw);
  const encoded = bytesToBase64(raw);
  raw.fill(0);
  return encoded;
}

export async function encryptPayload(plainBytes, keyBase64) {
  const key = await importAesKey(keyBase64);
  const iv = new Uint8Array(12);
  randomFill(iv);
  const cipher = await subtleCall('encrypt', [
    { name: 'AES-GCM', iv }, key, asBytes(plainBytes),
  ]);
  return { cipher: new Uint8Array(cipher), iv: bytesToBase64(iv) };
}

export async function decryptPayload(cipherBytes, keyBase64, ivBase64) {
  const cipher = asBytes(cipherBytes);
  const iv = base64ToBytes(ivBase64);
  if (iv.length !== 12) throw new Error('Archx: AES-GCM IV must be 12 bytes');
  if (cipher.length < 17) throw new Error('Archx: AES-GCM payload is too short');
  const key = await importAesKey(keyBase64);
  const plain = await subtleCall('decrypt', [
    { name: 'AES-GCM', iv }, key, cipher,
  ]);
  return new Uint8Array(plain);
}

/* ------------------------------------------------------------------ */
/* Block-level forensic watermark                                       */
/* ------------------------------------------------------------------ */

/**
 * A seeded ±delta luminance pattern applied per macro-block. Unlike 1px
 * noise, block-level shifts have a chance of surviving WebP/JPEG
 * re-encoding and screen-resolution screenshots well enough to be
 * *correlated* later: given a suspect image and a candidate viewing
 * session, resize/align the suspect to the payload geometry and compare
 * its block means against the unwatermarked reference (or a flat-field
 * estimate) — the seeded sign pattern either matches or it doesn't.
 * This is a tracing aid, not magic: cropping, heavy filtering or a camera
 * photo will weaken or destroy it. The visible watermark remains the
 * primary deterrent; this is the quiet second witness.
 */
// Sign derivation v2 (default since 1.13) seeds through cyrb128+sfc32
// (128-bit); v1 reproduces the pre-1.13 mulberry32(hashSeed(...>>>0))
// sequence whose 32-bit state truncated any seed's entropy. Verifiers
// (forensicScore) score against BOTH derivations, so marks embedded
// before 1.13 keep verifying.
export function forensicBlockSigns(seed, count, version = 2) {
  const rand = version === 1
    ? mulberry32(hashSeed(String(seed) + '::archx-forensic'))
    : sfc32(...cyrb128(String(seed) + '::archx-forensic'));
  return Array.from({ length: count }, () => (rand() < 0.5 ? -1 : 1));
}

export function applyForensicBlocks(rgba, w, h, seed, { blockSize = 32, delta = 2, signsVersion = 2 } = {}) {
  const bs = Math.max(8, blockSize | 0);
  const bx = Math.ceil(w / bs);
  const by = Math.ceil(h / bs);
  const signs = forensicBlockSigns(seed, bx * by, signsVersion === 1 ? 1 : 2);
  const out = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  for (let byi = 0; byi < by; byi++) {
    for (let bxi = 0; bxi < bx; bxi++) {
      const d = signs[byi * bx + bxi] * delta;
      if (!d) continue;
      const x0 = bxi * bs, y0 = byi * bs;
      const x1 = Math.min(w, x0 + bs), y1 = Math.min(h, y0 + bs);
      for (let y = y0; y < y1; y++) {
        let i = (y * w + x0) * 4;
        for (let x = x0; x < x1; x++, i += 4) {
          out[i] = Math.max(0, Math.min(255, out[i] + d));
          out[i + 1] = Math.max(0, Math.min(255, out[i + 1] + d));
          out[i + 2] = Math.max(0, Math.min(255, out[i + 2] + d));
        }
      }
    }
  }
  return out;
}

/**
 * Score how well `candidate` matches the forensic pattern for `seed`,
 * using `reference` (same geometry, unmarked) as the baseline.
 * Returns { score: -1..1, matched, total } — a genuine marked copy
 * typically scores > 0.7 even after lossy re-encoding at the same size.
 */
export function forensicScore(candidate, reference, w, h, seed, { blockSize = 32 } = {}) {
  const bs = Math.max(8, blockSize | 0);
  const bx = Math.ceil(w / bs);
  const by = Math.ceil(h / bs);
  // Per-block mean signs are computed once and scored against both sign
  // derivations (v2 default since 1.13, v1 for pre-1.13 marks); the
  // stronger correlation wins and reports which derivation matched.
  const blockSigns = new Int8Array(bx * by); // sign+2 encoding; 0 = not computed
  let total = 0;
  for (let byi = 0; byi < by; byi++) {
    for (let bxi = 0; bxi < bx; bxi++) {
      const x0 = bxi * bs, y0 = byi * bs;
      const x1 = Math.min(w, x0 + bs), y1 = Math.min(h, y0 + bs);
      let diff = 0, n = 0;
      for (let y = y0; y < y1; y += 2) {
        let i = (y * w + x0) * 4;
        for (let x = x0; x < x1; x += 2, i += 8) {
          diff += ((candidate[i] + candidate[i + 1] + candidate[i + 2]) -
                   (reference[i] + reference[i + 1] + reference[i + 2])) / 3;
          n++;
        }
      }
      if (!n) continue;
      blockSigns[byi * bx + bxi] = Math.sign(diff / n) + 2;
      total++;
    }
  }
  let best = { score: 0, matched: 0, total, signsVersion: 2 };
  for (const version of [2, 1]) {
    const signs = forensicBlockSigns(seed, bx * by, version);
    let matched = 0, signedSum = 0;
    for (let i = 0; i < blockSigns.length; i++) {
      if (!blockSigns[i]) continue;
      const hit = blockSigns[i] - 2 === signs[i];
      signedSum += hit ? 1 : -1;
      if (hit) matched++;
    }
    const score = total ? signedSum / total : 0;
    if (version === 2 || score > best.score) best = { score, matched, total, signsVersion: version };
  }
  return best;
}

/* ------------------------------------------------------------------ */
/* Blind steganographic ownership fingerprint                          */
/* ------------------------------------------------------------------ */

/**
 * Archx StegoMark: a keyed, redundant, *blindly decodable* payload hidden in
 * delivered pixels. It complements (not replaces) the reference-based
 * forensic blocks above: the owner can feed a suspect screenshot/export to
 * `detectStegoFingerprint()` / `archx-detect` and recover a 48-bit
 * fingerprint identifying the image / viewer / token — no original needed.
 *
 * Scheme: the image is divided into a macro-cell grid (default 24×16).
 * A 64-bit codeword (48-bit fingerprint + CRC-16) is assigned to cells via a
 * keyed permutation, so every code bit is repeated across several cells and
 * survives local cropping/damage. Each cell encodes its bit as a 4-band
 * alternating luminance pattern (+−+− vs −+−+), sign-flipped by a keyed
 * per-cell polarity and broken into four short row segments with keyed signs
 * so the mark does not form long, visible vertical stripes. Detection uses a
 * third-difference of each segment's band means, which cancels smooth image
 * content (gradients) while responding to the embedded alternation, then
 * soft-votes across repetitions and checks CRC.
 *
 * Honest limits: this is classical spread-spectrum-style marking, not a
 * neural Light Field Messaging system. It is designed to survive ordinary
 * re-encoding, mild resizing and screenshots well enough to *attribute*
 * copies; determined denoising / diffusion regeneration can weaken or
 * remove it. Treat a positive decode as evidence, not as DRM.
 */
export function stegoFingerprint(value) {
  const s = String(value ?? '');
  if (/^[0-9a-fA-F]{12}$/.test(s)) return s.toLowerCase();
  // SHA-256 (first 6 bytes), not the cyrb53 pair used before 1.13: the
  // payload->ID map gets full avalanche, so near-identical payloads no
  // longer land in correlated ID neighborhoods. Only NEW embeds see new
  // IDs for non-hex payloads — bits already in pixels are extracted
  // as-is at detection, so issued registries stay valid.
  const digest = sha256Bytes(utf8Encode('archx-stego-fp-v2:' + s));
  let hex = '';
  for (let i = 0; i < 6; i++) hex += digest[i].toString(16).padStart(2, '0');
  return hex;
}

/**
 * Pre-1.13 payload→fingerprint derivation (paired cyrb53 hashes), kept
 * so identity-string lookups against marks embedded before 1.13 still
 * resolve. Registries that stored the issued fingerprint never need
 * this; 12-hex payloads pass through identically in both derivations.
 */
export function legacyStegoFingerprint(value) {
  const s = String(value ?? '');
  if (/^[0-9a-fA-F]{12}$/.test(s)) return s.toLowerCase();
  const a = hashSeed('archx-stego:' + s, 0x51ab);
  const b = hashSeed('archx-stego:' + s, 0x9e37);
  const lo = Math.floor(a % 0x1000000).toString(16).padStart(6, '0');
  const hi = Math.floor(b % 0x1000000).toString(16).padStart(6, '0');
  return lo + hi;
}

const STEGO_CRC16_TABLE = (() => {
  const table = new Uint16Array(256);
  for (let byte = 0; byte < 256; byte++) {
    let crc = byte << 8;
    for (let i = 0; i < 8; i++) {
      crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
    table[byte] = crc;
  }
  return table;
})();

function stegoCrc16(bytes) {
  let crc = 0xffff;
  for (const byte of bytes) {
    crc = ((crc << 8) ^ STEGO_CRC16_TABLE[((crc >> 8) ^ byte) & 255]) & 0xffff;
  }
  return crc;
}

// Codeword v2 acceptance tag: the first 16 bits of HMAC-SHA256 over the
// 48-bit fingerprint under the (secret) stego key. CRC-16 is linear, so
// the bitwise majority of several buyers' codewords sits close to another
// valid codeword and blind repair can "find" a third party's fingerprint
// in a collusion average (phantom framing). A keyed MAC avalanches:
// MAC(majority) agrees with majority(MACs) only at chance (~50%/bit), so
// hybrids fall outside any sane repair budget, while detection stays a
// single O(1) pass under one shared per-image key — no per-viewer keys
// or registry-sized search needed. CRC-16 remains as the *repair*
// oracle in the robust profile (its syndrome algebra is what makes
// bounded correction fast) and as the legacy-v1 acceptance predicate.
const STEGO_MAC_DOMAIN = utf8Encode('archx-stego-v2:');
function stegoMac16(key, payloadBytes) {
  const msg = new Uint8Array(STEGO_MAC_DOMAIN.length + payloadBytes.length);
  msg.set(STEGO_MAC_DOMAIN, 0);
  msg.set(payloadBytes, STEGO_MAC_DOMAIN.length);
  const mac = hmacSha256Bytes(utf8Encode(String(key ?? '')), msg);
  return (mac[0] << 8) | mac[1];
}

function stegoBytesToBits(bytes) {
  const bits = new Uint8Array(bytes.length * 8);
  bytes.forEach((byte, i) => {
    for (let b = 0; b < 8; b++) bits[i * 8 + b] = (byte >> (7 - b)) & 1;
  });
  return bits;
}

// Robust profile codeword: the same public 48-bit fingerprint and CRC-16,
// followed by a second keyed CRC over the payload+CRC and a short marker.
// The detector uses the extra redundancy only after the ordinary CRC has
// identified a plausible partially damaged vector. This is still a heuristic
// forensic mark—not an unremovable or guaranteed identifier.
function robustLegacyKeyedCrc(first8, key) {
  const keyByte = Math.floor(hashSeed('archx-stego-robust:' + String(key ?? ''), 0x51ab) % 256);
  const keyed = new Uint8Array(9);
  keyed.set(first8, 0);
  keyed[8] = keyByte;
  return stegoCrc16(keyed);
}

// Trailing sync marker of the robust codeword, as bits (bytes 10-11).
const ROBUST_MARKER_BITS = stegoBytesToBits(new Uint8Array([0xa5, 0x5a]));

function robustStegoCodeBits(fingerprint, key, tag = 'mac') {
  const payload = new Uint8Array(6);
  for (let i = 0; i < 6; i++) payload[i] = parseInt(fingerprint.slice(i * 2, i * 2 + 2), 16);
  const crc = stegoCrc16(payload);
  const first = [...payload, (crc >> 8) & 255, crc & 255];
  // v2: bytes 8-9 are the keyed MAC acceptance tag (avalanche) instead of
  // the legacy one-key-byte CRC (linear, so collusion majorities could
  // stay within repair distance of a phantom fingerprint).
  const check = tag === 'crc' ? robustLegacyKeyedCrc(first, key) : stegoMac16(key, payload);
  return stegoBytesToBits(new Uint8Array([
    ...first,
    (check >> 8) & 255,
    check & 255,
    0xa5,
    0x5a,
  ]));
}

function robustStegoBytesValid(bytes, key, tag = 'mac') {
  if (!bytes || bytes.length !== 12) return false;
  // Order matters for the exhaustive repair search: the marker and the
  // linear CRC reject ~all random candidates before any HMAC runs.
  if (bytes[10] !== 0xa5 || bytes[11] !== 0x5a) return false;
  if (stegoCrc16(bytes.subarray(0, 6)) !== ((bytes[6] << 8) | bytes[7])) return false;
  const expected = tag === 'crc'
    ? robustLegacyKeyedCrc(bytes.subarray(0, 8), key)
    : stegoMac16(key, bytes.subarray(0, 6));
  return expected === ((bytes[8] << 8) | bytes[9]);
}

function robustStegoBitsValid(bits, key, tag = 'mac') {
  if (!bits || bits.length !== 96) return false;
  const bytes = new Uint8Array(12);
  for (let i = 0; i < 12; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = (byte << 1) | bits[i * 8 + b];
    bytes[i] = byte;
  }
  return robustStegoBytesValid(bytes, key, tag);
}

function robustStegoFingerprintFromBits(bits) {
  let fingerprint = '';
  for (let i = 0; i < 6; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = (byte << 1) | bits[i * 8 + b];
    fingerprint += byte.toString(16).padStart(2, '0');
  }
  return fingerprint;
}

function repairRobustViaFirstCrc(scores, hard, key, tag = 'mac') {
  const first = Uint8Array.from(hard.subarray(0, 64));
  const syndromeOf = (bits) => {
    const bytes = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
      let byte = 0;
      for (let b = 0; b < 8; b++) byte = (byte << 1) | bits[i * 8 + b];
      bytes[i] = byte;
    }
    return stegoCrc16(bytes.subarray(0, 6)) ^ ((bytes[6] << 8) | bytes[7]);
  };
  const target = syndromeOf(first);
  const buildCanonical = (correctedFirst) => {
    // Prefilter before paying for the acceptance MAC: the canonical
    // codeword's first 64 bits ARE correctedFirst (syndrome-zero), and
    // the trailing marker is a constant — so most junk syndrome
    // candidates can be rejected on marker disagreement alone, without
    // an HMAC each (tens of thousands on unmarked geometry searches).
    let flips = 0;
    let markerFlips = 0;
    let softCost = 0;
    for (let i = 0; i < 64; i++) {
      if (correctedFirst[i] === hard[i]) continue;
      flips++;
      softCost += Math.abs(scores[i] || 0);
    }
    for (let j = 0; j < 16; j++) {
      if (ROBUST_MARKER_BITS[j] === hard[80 + j]) continue;
      markerFlips++;
      flips++;
      softCost += Math.abs(scores[80 + j] || 0);
    }
    if (markerFlips > 2 || flips > 8) return null;
    const fingerprint = robustStegoFingerprintFromBits(correctedFirst);
    const canonical = robustStegoCodeBits(fingerprint, key, tag);
    let tagFlips = markerFlips;
    for (let i = 64; i < 80; i++) {
      if (canonical[i] === hard[i]) continue;
      flips++;
      tagFlips++;
      softCost += Math.abs(scores[i] || 0);
    }
    // The acceptance tag must be OBSERVED, not synthesized: bits 64..95
    // (tag + marker) may carry a couple of vote errors, but regenerating
    // them wholesale would let a LEGACY (CRC2) mark be claimed by the
    // 'mac' pass — its CRC2 differs from the synthesized MAC in ~8 bits,
    // which the old flips<=8 budget cheerfully paid, mislabeling the
    // scheme and short-circuiting the CRC fallback. Candidates whose
    // tag needs >2 flips fall through to the exhaustive search, which
    // pays for every flipped tag bit out of the gate-capped budget.
    return flips <= 8 && tagFlips <= 2 ? { bits: canonical, flips, softCost } : null;
  };
  if (target === 0) return buildCanonical(first);

  const columns = new Uint16Array(64);
  for (let i = 0; i < 64; i++) {
    first[i] ^= 1;
    columns[i] = syndromeOf(first) ^ target;
    first[i] ^= 1;
  }
  const weakest = Array.from({ length: 64 }, (_, index) => index)
    .sort((a, b) => Math.abs(scores[a]) - Math.abs(scores[b]))
    .slice(0, 32);
  // Interleave the weakest candidates between halves so a meet-in-the-middle
  // search can represent up to three likely errors on each side.
  const leftCandidates = weakest.filter((_, index) => index % 2 === 0);
  const rightCandidates = weakest.filter((_, index) => index % 2 === 1);
  const subsetMaps = (candidates) => {
    const byWeight = Array.from({ length: 4 }, () => new Map());
    const visit = (start, chosen, syndrome, cost) => {
      const map = byWeight[chosen.length];
      const previous = map.get(syndrome);
      if (!previous || cost < previous.cost) map.set(syndrome, { indices: [...chosen], cost });
      if (chosen.length >= 3) return;
      for (let i = start; i < candidates.length; i++) {
        const bit = candidates[i];
        chosen.push(bit);
        visit(i + 1, chosen, syndrome ^ columns[bit], cost + Math.abs(scores[bit] || 0));
        chosen.pop();
      }
    };
    visit(0, [], 0, 0);
    return byWeight;
  };
  const leftMaps = subsetMaps(leftCandidates);
  const rightMaps = subsetMaps(rightCandidates);
  // Rank every first-CRC syndrome solution by the soft cost of the complete
  // canonical 96-bit codeword. Accepting the first low-weight CRC collision
  // would be unsafe: the second CRC and marker observations must also be
  // close to the candidate before it can become an attribution.
  let bestCanonical = null;
  for (let total = 1; total <= 6; total++) {
    for (let leftWeight = 0; leftWeight <= Math.min(3, total); leftWeight++) {
      const rightWeight = total - leftWeight;
      if (rightWeight < 0 || rightWeight > 3) continue;
      for (const [syndrome, left] of leftMaps[leftWeight]) {
        const right = rightMaps[rightWeight].get(target ^ syndrome);
        if (!right) continue;
        const corrected = Uint8Array.from(first);
        for (const bit of [...left.indices, ...right.indices]) corrected[bit] ^= 1;
        if (syndromeOf(corrected) !== 0) continue;
        const candidate = buildCanonical(corrected);
        if (!candidate) continue;
        if (!bestCanonical || candidate.softCost < bestCanonical.softCost ||
            (candidate.softCost === bestCanonical.softCost && candidate.flips < bestCanonical.flips)) {
          bestCanonical = candidate;
        }
      }
    }
  }
  return bestCanonical ? { bits: bestCanonical.bits, flips: bestCanonical.flips } : null;
}

function repairRobustStegoBits(scores, hard, key, maxFlips = 5, tag = 'mac') {
  const bits = Uint8Array.from(hard);
  const bytes = new Uint8Array(12);
  for (let i = 0; i < 12; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = (byte << 1) | bits[i * 8 + b];
    bytes[i] = byte;
  }
  if (robustStegoBytesValid(bytes, key, tag)) return { bits, flips: 0, tagScheme: tag };
  const syndromeRepair = repairRobustViaFirstCrc(scores, bits, key, tag);
  if (syndromeRepair) return { ...syndromeRepair, tagScheme: tag };
  // Byte-level flips plus the table CRC keep an exhaustive search of the
  // 24 weakest bits to five flips practical during offline geometry search.
  const candidates = Array.from({ length: bits.length }, (_, index) => index)
    .sort((a, b) => Math.abs(scores[a]) - Math.abs(scores[b]))
    .slice(0, 24);
  const flip = (index) => {
    bits[index] ^= 1;
    bytes[index >> 3] ^= 1 << (7 - (index & 7));
  };
  const search = (start, depth, targetDepth) => {
    if (depth === targetDepth) return robustStegoBytesValid(bytes, key, tag);
    for (let i = start; i <= candidates.length - (targetDepth - depth); i++) {
      flip(candidates[i]);
      if (search(i + 1, depth + 1, targetDepth)) return true;
      flip(candidates[i]);
    }
    return false;
  };
  for (let flips = 1; flips <= maxFlips; flips++) {
    if (search(0, 0, flips)) return { bits: Uint8Array.from(bits), flips, tagScheme: tag };
  }
  return null;
}

function stegoCodeBits(fingerprint, key, tag = 'mac') {
  const bytes = new Uint8Array(6);
  for (let i = 0; i < 6; i++) bytes[i] = parseInt(fingerprint.slice(i * 2, i * 2 + 2), 16);
  const check = tag === 'crc' ? stegoCrc16(bytes) : stegoMac16(key, bytes);
  const all = [...bytes, (check >> 8) & 255, check & 255];
  const bits = new Uint8Array(64);
  all.forEach((byte, i) => {
    for (let b = 0; b < 8; b++) bits[i * 8 + b] = (byte >> (7 - b)) & 1;
  });
  return bits;
}

function stegoBitsToBytes(bits) {
  const bytes = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = (byte << 1) | bits[i * 8 + b];
    bytes[i] = byte;
  }
  return bytes;
}

function stegoCrcValid(bits) {
  const bytes = stegoBitsToBytes(bits);
  return stegoCrc16(bytes.subarray(0, 6)) === ((bytes[6] << 8) | bytes[7]);
}

function stegoMacValid(bits, key) {
  const bytes = stegoBitsToBytes(bits);
  return stegoMac16(key, bytes.subarray(0, 6)) === ((bytes[6] << 8) | bytes[7]);
}

/**
 * Soft-decision repair: if the voted codeword fails its tag, try flipping
 * the least-reliable bits (singles, pairs, triples). Real marks usually
 * need 0–2 repairs after re-encoding; random images are still rejected by
 * the caller's signal/agreement thresholds, not by the tag alone. The MAC
 * predicate runs first; the legacy CRC predicate is a flagged fallback so
 * pre-v1.12 marks stay detectable (under stricter caller gates).
 */
function correctStegoBits(bits, reliability, key, maxDepth = 3) {
  const macCache = new Map();
  const macOf = (candidate) => {
    const bytes = stegoBitsToBytes(candidate);
    const cacheKey = ((bytes[0] << 16) | (bytes[1] << 8) | bytes[2]) + ':' +
      ((bytes[3] << 16) | (bytes[4] << 8) | bytes[5]);
    let mac = macCache.get(cacheKey);
    if (mac === undefined) {
      mac = stegoMac16(key, bytes.subarray(0, 6));
      macCache.set(cacheKey, mac);
    }
    return mac === ((bytes[6] << 8) | bytes[7]);
  };
  const search = (valid, depthCap) => {
    if (valid(bits)) return { bits, corrections: 0 };
    const weakest = [...bits.keys()]
      .sort((a, b) => reliability[a] - reliability[b])
      .slice(0, 20);
    let best = null;
    const visit = (start, chosen) => {
      if (chosen.length) {
        const candidate = new Uint8Array(bits);
        let cost = 0;
        for (const i of chosen) { candidate[i] ^= 1; cost += reliability[i]; }
        if (valid(candidate) && (!best || cost < best.cost)) {
          best = { bits: candidate, corrections: chosen.length, cost };
        }
      }
      if (chosen.length >= depthCap) return;
      for (let i = start; i < weakest.length; i++) visit(i + 1, [...chosen, weakest[i]]);
    };
    visit(0, []);
    return best;
  };
  const macBest = search(macOf, maxDepth);
  if (macBest) return { ...macBest, tagScheme: 'mac' };
  // Legacy standard candidates are gated to <=1 correction downstream, so
  // a deeper CRC search could only manufacture rejected candidates.
  const crcBest = search(stegoCrcValid, Math.min(1, maxDepth));
  if (crcBest) return { ...crcBest, tagScheme: 'crc' };
  return { bits, corrections: -1, tagScheme: null };
}

const STEGO_ROW_SEGMENTS = 4;

// Layout seed v2 (1.13+): the cell permutation/polarity PRNG is seeded
// through cyrb128+sfc32 (128-bit state). The pre-1.13 layouts seeded
// mulberry32 with hashSeed(...) >>> 0, truncating every stego key —
// however strong — to a 2^32 layout space (GPU-brute-forceable from a
// known clean/marked pair). Version 1 below reproduces those sequences
// bit-exactly so existing marks keep detecting; detection tries v2
// first, then v1 ("auto").
function layoutRand(seedString, version, legacyHashSeedArg) {
  if (version === 1) return mulberry32(hashSeed(seedString, legacyHashSeedArg));
  return sfc32(...cyrb128(seedString));
}

function stegoLayout(cellCount, key, version = 2) {
  const rand = layoutRand(String(key) + '::archx-stego-layout', version);
  const order = Array.from({ length: cellCount }, (_, i) => i);
  for (let i = cellCount - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }
  const polarity = new Int8Array(cellCount);
  for (let i = 0; i < cellCount; i++) polarity[i] = rand() < 0.5 ? -1 : 1;
  const segmentPolarity = new Int8Array(cellCount * STEGO_ROW_SEGMENTS);
  for (let i = 0; i < segmentPolarity.length; i++) segmentPolarity[i] = rand() < 0.5 ? -1 : 1;
  return { order, polarity, segmentPolarity };
}

function stegoGrid(w, h, gridX, gridY) {
  let gx = Math.max(4, Math.min(64, Math.round(gridX || 24)));
  let gy = Math.max(4, Math.min(64, Math.round(gridY || 16)));
  gx = Math.min(gx, Math.max(4, Math.floor(w / 8)));
  gy = Math.min(gy, Math.max(4, Math.floor(h / 8)));
  while (gx * gy < 64 && (gx < Math.floor(w / 4) || gy < Math.floor(h / 4))) {
    if (gx <= gy && gx < Math.floor(w / 4)) gx++; else gy++;
  }
  return { gx, gy };
}

function robustStegoLayout(cellCount, key, version = 2) {
  const order = Array.from({ length: cellCount }, (_, i) => i);
  const polarity = new Int8Array(cellCount);
  const segmentPolarity = new Int8Array(cellCount * STEGO_ROW_SEGMENTS);
  const rand = layoutRand('archx-stego-robust-layout:' + String(key ?? ''), version, 0x51ab);
  for (let i = cellCount - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }
  for (let i = 0; i < cellCount; i++) {
    polarity[i] = rand() > 0.5 ? 1 : -1;
    for (let segment = 0; segment < STEGO_ROW_SEGMENTS; segment++) {
      segmentPolarity[i * STEGO_ROW_SEGMENTS + segment] = rand() > 0.5 ? 1 : -1;
    }
  }
  return { order, polarity, segmentPolarity };
}

export function embedStegoFingerprint(rgba, w, h, payload, {
  key = '', strength = 6, gridX, gridY, profile = 'standard', inPlace = false,
  // Codeword v2 (keyed MAC acceptance tag) is the default; legacyCode
  // reproduces pre-v1.12 CRC-tagged codewords for compatibility testing.
  legacyCode = false,
  // Layout seed space: 2 = 128-bit (default since 1.13); 1 reproduces
  // the pre-1.13 32-bit-truncated layout for compatibility testing.
  layoutVersion = 2,
} = {}) {
  const src = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  if (src.length < w * h * 4) throw new Error('Archx stego: pixel buffer is smaller than w×h×4');
  if (w < 64 || h < 64) throw new Error('Archx stego: image too small (minimum 64×64)');
  const robust = profile === 'robust';
  const effectiveGridX = gridX ?? (robust ? 20 : 24);
  const effectiveGridY = gridY ?? (robust ? 14 : 16);
  const rowSegments = STEGO_ROW_SEGMENTS;
  const columnBands = 4;
  const fingerprint = stegoFingerprint(payload);
  const tag = legacyCode ? 'crc' : 'mac';
  const bits = robust ? robustStegoCodeBits(fingerprint, key, tag) : stegoCodeBits(fingerprint, key, tag);
  const { gx, gy } = stegoGrid(w, h, effectiveGridX, effectiveGridY);
  const cellCount = gx * gy;
  const { order, polarity, segmentPolarity } = robust
    ? robustStegoLayout(cellCount, key, layoutVersion === 1 ? 1 : 2)
    : stegoLayout(cellCount, key, layoutVersion === 1 ? 1 : 2);
  // The server pipeline owns a disposable Sharp buffer, so it may opt out of
  // this full-frame copy. Cell statistics are computed before that cell is
  // written, which makes the in-place path byte-for-byte equivalent.
  const out = inPlace ? src : new Uint8Array(src);
  const baseAmp = Math.max(1, Math.min(16, Number(strength) || 6));
  const amp = robust ? Math.min(16, baseAmp * 1.35) : baseAmp;

  for (let cy = 0; cy < gy; cy++) {
    const y0 = Math.floor((cy * h) / gy);
    const y1 = Math.floor(((cy + 1) * h) / gy);
    for (let cx = 0; cx < gx; cx++) {
      const x0 = Math.floor((cx * w) / gx);
      const x1 = Math.floor(((cx + 1) * w) / gx);
      if (x1 - x0 < 4 || y1 - y0 < 2) continue;
      const cell = cy * gx + cx;
      const bit = bits[order[cell] % bits.length];
      const pol = polarity[cell];

      // Perceptual masking: textured cells can hide a stronger mark than
      // flat sky/skin. Sample local luminance spread to scale amplitude.
      let sum = 0, sum2 = 0, n = 0;
      for (let y = y0; y < y1; y += 2) {
        let i = (y * w + x0) * 4;
        for (let x = x0; x < x1; x += 2, i += 8) {
          const lum = (src[i] * 77 + src[i + 1] * 150 + src[i + 2] * 29) >> 8;
          sum += lum; sum2 += lum * lum; n++;
        }
      }
      const mean = n ? sum / n : 0;
      const std = n ? Math.sqrt(Math.max(0, sum2 / n - mean * mean)) : 0;
      const cellAmp = amp * Math.max(0.35, Math.min(1, 0.35 + std / 55));
      const cellW = x1 - x0;
      const cellH = y1 - y0;

      for (let y = y0; y < y1; y++) {
        const segment = Math.min(
          rowSegments - 1,
          Math.floor(((y - y0) * rowSegments) / cellH),
        );
        const segmentSign = segmentPolarity[cell * rowSegments + segment];
        let i = (y * w + x0) * 4;
        for (let x = x0; x < x1; x++, i += 4) {
          const band = Math.min(columnBands - 1, Math.floor(((x - x0) * columnBands) / cellW));
          const pattern = (band % 2 === 0 ? 1 : -1) * (bit ? 1 : -1) * pol * segmentSign;
          const delta = cellAmp * pattern;
          // Clamp per channel: a saturated red channel must not suppress the
          // mark in green/blue, or flat synthetic/saturated areas decode with
          // a systematic one-direction bias.
          out[i] = Math.max(0, Math.min(255, src[i] + delta));
          out[i + 1] = Math.max(0, Math.min(255, src[i + 1] + delta));
          out[i + 2] = Math.max(0, Math.min(255, src[i + 2] + delta));
        }
      }
    }
  }
  return out;
}

function flipPixelsHorizontal(src, w, h) {
  const flipped = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) {
    const row = y * w * 4;
    for (let x = 0; x < w; x++) {
      const si = row + x * 4;
      const di = row + (w - 1 - x) * 4;
      flipped[di] = src[si]; flipped[di + 1] = src[si + 1];
      flipped[di + 2] = src[si + 2]; flipped[di + 3] = src[si + 3];
    }
  }
  return flipped;
}

export function detectStegoFingerprint(rgba, w, h, {
  key = '', gridX, gridY, profile = 'standard', searchOffsets = false, searchGeometry = false,
  // Mirrored-suspect recovery is on by default for every profile (one
  // extra bounded pass on flipped pixels, only when the forward pass
  // found nothing); set false to disable.
  searchMirror = true,
  // Layout seed space: 'auto' (default) tries the 128-bit v2 layouts,
  // then the pre-1.13 32-bit layouts; pass 1 or 2 to pin one space
  // (halves worst-case cost on unmarked suspects).
  layoutVersion = 'auto',
  _mirrorProbe = false,
  _layoutVersion = 0,
} = {}) {
  const concreteLayout = _layoutVersion === 1 || _layoutVersion === 2
    ? _layoutVersion
    : (layoutVersion === 1 || layoutVersion === 2 ? layoutVersion : 0);
  if (!concreteLayout) {
    const shared = { key, gridX, gridY, profile, searchOffsets, searchGeometry, searchMirror, _mirrorProbe };
    const v2 = detectStegoFingerprint(rgba, w, h, { ...shared, _layoutVersion: 2 });
    if (v2?.found) return v2;
    const v1 = detectStegoFingerprint(rgba, w, h, { ...shared, _layoutVersion: 1 });
    if (v1?.found) return v1;
    return (v1?.confidence ?? 0) > (v2?.confidence ?? 0) ? v1 : v2;
  }
  if (profile === 'auto') {
    const standard = detectStegoFingerprint(rgba, w, h, {
      key, gridX, gridY, profile: 'standard', searchOffsets, searchGeometry: false, searchMirror: false, _mirrorProbe: true, _layoutVersion: concreteLayout,
    });
    if (standard?.found && standard.confidence >= 0.9 && !searchGeometry) return standard;
    const robust = detectStegoFingerprint(rgba, w, h, {
      key, gridX, gridY, profile: 'robust', searchOffsets, searchGeometry: false, searchMirror: false, _mirrorProbe: true, _layoutVersion: concreteLayout,
    });
    const initial = robust?.found && !standard?.found
      ? robust
      : standard?.found && !robust?.found
        ? standard
        : (robust?.confidence ?? 0) > (standard?.confidence ?? 0) ? robust : standard;
    if (!searchGeometry || initial?.found) return initial;
    const standardGeometry = detectStegoFingerprint(rgba, w, h, {
      key, gridX, gridY, profile: 'standard', searchOffsets, searchGeometry: true, searchMirror: false, _mirrorProbe: true, _layoutVersion: concreteLayout,
    });
    if (standardGeometry?.found) return standardGeometry;
    const robustGeometry = detectStegoFingerprint(rgba, w, h, {
      key, gridX, gridY, profile: 'robust', searchOffsets, searchGeometry: true, searchMirror: false, _mirrorProbe: true, _layoutVersion: concreteLayout,
    });
    if (robustGeometry?.found) return robustGeometry;
    // Last bounded candidate: a horizontally mirrored suspect (a common
    // zero-cost evasion). The probe inherits the geometry search so
    // compound flip+crop/resize suspects recover too; it only runs after
    // the full forward geometry search failed (offline forensic mode).
    if (searchMirror && !_mirrorProbe) try {
      const src = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
      if (src.length >= w * h * 4 && Number.isSafeInteger(w * h * 4)) {
        const flipped = flipPixelsHorizontal(src, w, h);
        for (const candidateProfile of ['standard', 'robust']) {
          const fast = detectStegoFingerprint(flipped, w, h, {
            key, gridX, gridY, profile: candidateProfile, searchOffsets,
            searchGeometry: false, searchMirror: false, _mirrorProbe: true, _layoutVersion: concreteLayout,
          });
          if (fast?.found) return { ...fast, mirrored: true };
        }
        for (const candidateProfile of ['standard', 'robust']) {
          const mirrored = detectStegoFingerprint(flipped, w, h, {
            key, gridX, gridY, profile: candidateProfile, searchOffsets,
            searchGeometry: true, searchMirror: false, _mirrorProbe: true, _layoutVersion: concreteLayout,
          });
          if (mirrored?.found) return { ...mirrored, mirrored: true };
        }
      }
    } catch { /* mirror probe is best-effort */ }
    return (robustGeometry?.confidence ?? 0) > (standardGeometry?.confidence ?? 0)
      ? robustGeometry
      : standardGeometry;
  }
  const src = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  if (src.length < w * h * 4) throw new Error('Archx stego: pixel buffer is smaller than w×h×4');
  const robust = profile === 'robust';
  const effectiveProfile = robust ? 'robust' : 'standard';
  const codeLength = robust ? 96 : 64;
  const rowSegments = STEGO_ROW_SEGMENTS;
  const columnBands = 4;
  const effectiveGridX = gridX ?? (robust ? 20 : 24);
  const effectiveGridY = gridY ?? (robust ? 14 : 16);
  const { gx, gy } = stegoGrid(w, h, effectiveGridX, effectiveGridY);
  const cellCount = gx * gy;
  const { order, polarity, segmentPolarity } = robust
    ? robustStegoLayout(cellCount, key, concreteLayout)
    : stegoLayout(cellCount, key, concreteLayout);
  const cw = w / gx, ch = h / gy;
  // One luma plane for every probe below: geometry search evaluates
  // thousands of candidates over the same pixels, and recomputing
  // (r*77+g*150+b*29)>>8 per sample was ~30% of detector wall time.
  const luma = new Uint8Array(w * h);
  for (let p = 0, i = 0; p < luma.length; p++, i += 4) {
    luma[p] = (src[i] * 77 + src[i + 1] * 150 + src[i + 2] * 29) >> 8;
  }
  // Summed-area table over the luma plane: every cell band/segment mean
  // becomes four array reads instead of a strided pixel walk shared by
  // thousands of geometry probes. Full-population means (the previous
  // estimator sampled on a stride) — same gates, lower estimator noise.
  const integral = new Float64Array((w + 1) * (h + 1));
  for (let y = 0; y < h; y++) {
    let rowSum = 0;
    const srcRow = y * w;
    const outRow = (y + 1) * (w + 1);
    const prevRow = y * (w + 1);
    for (let x = 0; x < w; x++) {
      rowSum += luma[srcRow + x];
      integral[outRow + x + 1] = integral[prevRow + x + 1] + rowSum;
    }
  }
  const rectSum = (rx0, ry0, rx1, ry1) =>
    integral[ry1 * (w + 1) + rx1] - integral[ry0 * (w + 1) + rx1] -
    integral[ry1 * (w + 1) + rx0] + integral[ry0 * (w + 1) + rx0];
  const fractions = searchOffsets ? [-0.25, -0.125, 0, 0.125, 0.25] : [0];

  // Reused scratch across this call's (synchronous) evaluate() probes:
  // geometry search runs thousands of candidates, and allocating the
  // vote/sum typed arrays per cell/evaluate was pure GC churn.
  const _sums = new Float64Array(rowSegments * columnBands);
  const _counts = new Uint32Array(rowSegments * columnBands);
  const _bitScores = new Float64Array(codeLength);
  const _bitCounts = new Uint16Array(codeLength);
  const _votedBits = new Uint8Array(codeLength);
  const _reliability = new Float64Array(codeLength);
  const _voteScores = new Float64Array(codeLength);
  const _groups = Array.from({ length: codeLength }, () => []);
  const _segmentResponses = [];
  const evaluate = ({ fx = 0, fy = 0, scale = 1, scaleX = scale, scaleY = scale, originX = null, originY = null } = {}) => {
    const cellW0 = cw * scaleX;
    const cellH0 = ch * scaleY;
    const ox = originX ?? fx * cw;
    const oy = originY ?? fy * ch;
    const bitScores = _bitScores.fill(0);
    const bitCounts = _bitCounts.fill(0);
    const cellScores = [];
    for (let cy = 0; cy < gy; cy++) {
      const rawY0 = oy + cy * cellH0;
      const rawY1 = rawY0 + cellH0;
      const y0 = Math.max(0, Math.round(rawY0));
      const y1 = Math.min(h, Math.round(rawY1));
      if (y1 - y0 < 2 || (y1 - y0) / cellH0 < 0.45) continue;
      for (let cx = 0; cx < gx; cx++) {
        const rawX0 = ox + cx * cellW0;
        const rawX1 = rawX0 + cellW0;
        const x0 = Math.max(0, Math.round(rawX0));
        const x1 = Math.min(w, Math.round(rawX1));
        if (x1 - x0 < 4 || (x1 - x0) / cellW0 < 0.45) continue;
        const sums = _sums.fill(0);
        const counts = _counts.fill(0);
        const cellW = x1 - x0;
        const cellH = y1 - y0;
        for (let segment = 0; segment < rowSegments; segment++) {
          const ry0 = Math.max(y0, Math.round(rawY0 + (segment * cellH0) / rowSegments));
          const ry1 = Math.min(y1, Math.round(rawY0 + ((segment + 1) * cellH0) / rowSegments));
          if (ry1 <= ry0) continue;
          for (let band = 0; band < columnBands; band++) {
            const rx0 = Math.max(x0, Math.round(rawX0 + (band * cellW0) / columnBands));
            const rx1 = Math.min(x1, Math.round(rawX0 + ((band + 1) * cellW0) / columnBands));
            if (rx1 <= rx0) continue;
            const idx = segment * columnBands + band;
            sums[idx] = rectSum(rx0, ry0, rx1, ry1);
            counts[idx] = (rx1 - rx0) * (ry1 - ry0);
          }
        }
        // Third-difference responds to +−+− alternation and cancels linear /
        // quadratic image content. Evaluate each short row segment under its
        // keyed sign, then average. Positive result means code bit = 1.
        let segmentScoreSum = 0;
        let segmentWeightSum = 0;
        let validSegments = 0;
        const robustSegmentResponses = robust ? (_segmentResponses.length = 0, _segmentResponses) : null;
        const cellIndex = cy * gx + cx;
        for (let segment = 0; segment < rowSegments; segment++) {
          const base = segment * columnBands;
          let complete = true;
          for (let band = 0; band < columnBands; band++) {
            if (counts[base + band] === 0) { complete = false; break; }
          }
          if (!complete) continue;
          validSegments++;
          const m0 = sums[base] / counts[base];
          const m1 = sums[base + 1] / counts[base + 1];
          const weight = Math.min(counts[base], counts[base + 1], counts[base + 2], counts[base + 3]);
          // Both profiles use the third-difference response: it cancels smooth
          // image gradients that otherwise swamp a two-band difference. The
          // robust profile gains low-frequency resilience from its larger
          // macro-cells/bands, redundant 96-bit codeword, and higher amplitude.
          const response = (-(-m0 + 3 * m1 - 3 * (sums[base + 2] / counts[base + 2]) + (sums[base + 3] / counts[base + 3])) / 8);
          const signedResponse = response *
            polarity[cellIndex] * segmentPolarity[cellIndex * rowSegments + segment];
          if (robust) robustSegmentResponses.push(signedResponse);
          segmentScoreSum += signedResponse * weight;
          segmentWeightSum += weight;
        }
        if (!segmentWeightSum || validSegments < 2) continue;
        let rawScore = segmentScoreSum / segmentWeightSum;
        if (robust) {
          // Median across row segments: one segment crossed by a hard image
          // edge should not dominate the whole macro-cell in the robust path.
          const values = robustSegmentResponses.sort((a, b) => a - b);
          const middle = Math.floor(values.length / 2);
          rawScore = values.length % 2
            ? values[middle]
            : (values[middle - 1] + values[middle]) / 2;
        }
        // Clip outliers: one hard image edge crossing a cell can otherwise
        // outvote five correctly-marked repetitions of the same code bit.
        const score = Math.max(-12, Math.min(12, rawScore));
        const bitIndex = order[cy * gx + cx] % codeLength;
        bitScores[bitIndex] += score;
        bitCounts[bitIndex]++;
        cellScores.push({ bitIndex, score });
      }
    }
    const votedBits = _votedBits.fill(0);
    const reliability = _reliability.fill(0);
    const voteScores = _voteScores.fill(0);
    if (robust) {
      // Robust repetitions are fewer than in the standard 64-bit layout.
      // Median voting prevents one hard image edge (already clipped to ±12)
      // from outvoting the other repetitions of the same code bit; the
      // standard profile retains its original summed-vote decoder exactly.
      const groups = _groups;
      for (const group of groups) group.length = 0;
      for (const { bitIndex, score } of cellScores) groups[bitIndex].push(score);
      for (let i = 0; i < codeLength; i++) {
        const values = groups[i].sort((a, b) => a - b);
        if (!values.length) continue;
        const middle = Math.floor(values.length / 2);
        voteScores[i] = values.length % 2
          ? values[middle]
          : (values[middle - 1] + values[middle]) / 2;
        votedBits[i] = voteScores[i] >= 0 ? 1 : 0;
        reliability[i] = Math.abs(voteScores[i]);
      }
    } else {
      for (let i = 0; i < codeLength; i++) {
        voteScores[i] = bitScores[i] / Math.max(1, bitCounts[i]);
        votedBits[i] = bitScores[i] >= 0 ? 1 : 0;
        reliability[i] = Math.abs(voteScores[i]);
      }
    }
    // Search-budget hint (outcome-preserving): the standard gates only
    // accept 2-3 corrections when raw signal is clearly genuine, so on
    // weak candidates a deep MAC search would manufacture rejects at
    // full HMAC cost across every geometry probe.
    const meanAbsPre = voteScores.reduce((s, v) => s + Math.abs(v), 0) / codeLength;
    const preAgreeing = cellScores.filter(({ bitIndex, score }) => (score >= 0) === !!votedBits[bitIndex]).length;
    const preAgreement = cellScores.length ? preAgreeing / cellScores.length : 0;
    const standardDepth = meanAbsPre >= 2.0 && preAgreement >= 0.82 ? 3 : 1;
    // Repair pre-gate: the flip search (CRC syndrome / MAC verification)
    // is most of detector wall time on hopeless probes, and several
    // acceptance inputs cannot change under repair — meanAbs and bit
    // coverage are vote-level facts, and flipping at most K bits can
    // raise agreement by at most the K largest per-bit disagree counts.
    // When even that bound misses the found-gates, the candidate is
    // rejected without running the search (tag fields then report
    // "not evaluated": corrections -1, tagScheme null).
    const minBitCountPre = Math.min(...bitCounts);
    const observedBitsPre = bitCounts.reduce((count, value) => count + (value > 0 ? 1 : 0), 0);
    const coverageOkPre = robust
      ? observedBitsPre >= 88 && cellScores.length >= 128
      : minBitCountPre >= 2 && cellScores.length >= codeLength * 3;
    let agreementBound = preAgreement;
    if (cellScores.length) {
      const disagreeByBit = new Uint16Array(codeLength);
      for (const { bitIndex, score } of cellScores) {
        if ((score >= 0) !== !!votedBits[bitIndex]) disagreeByBit[bitIndex]++;
      }
      const gains = [...disagreeByBit].sort((a, b) => b - a);
      const maxFlips = robust ? 5 : standardDepth;
      let gainSum = 0;
      for (let i = 0; i < Math.min(maxFlips, gains.length); i++) gainSum += gains[i];
      agreementBound = (preAgreeing + gainSum) / cellScores.length;
    }
    const repairable = meanAbsPre >= 1.2 && cellScores.length >= 96 && coverageOkPre && agreementBound >= 0.72;
    const corrected = !repairable
      ? { bits: votedBits, corrections: -1, tagScheme: null }
      : robust
      ? (() => {
          // Depth caps that cannot change outcomes: 4-5 corrections are
          // only acceptable for MAC candidates with meanAbs>=3.5 and
          // agreement>=0.95 (robustCorrectionOk below), and never for
          // legacy CRC candidates — searching deeper in other regimes
          // only manufactures rejects at full combinatorial cost.
          const macDepth = meanAbsPre >= 3.5 && agreementBound >= 0.95 ? 5 : 3;
          const repaired = repairRobustStegoBits(reliability, votedBits, key, macDepth, 'mac') ||
            repairRobustStegoBits(reliability, votedBits, key, 3, 'crc');
          return repaired
            ? { bits: repaired.bits, corrections: repaired.flips, tagScheme: repaired.tagScheme }
            : { bits: votedBits, corrections: -1, tagScheme: null };
        })()
      : correctStegoBits(votedBits, reliability, key, standardDepth);
    const bits = corrected.bits;
    const fingerprint = robust
      ? robustStegoFingerprintFromBits(bits)
      : [...stegoBitsToBytes(bits).subarray(0, 6)].map((b) => b.toString(16).padStart(2, '0')).join('');
    // The correctors only return corrections >= 0 for a candidate that
    // passed its acceptance predicate (MAC tag, or legacy CRC fallback).
    const crcValid = corrected.corrections >= 0;
    const agreeing = cellScores.filter(({ bitIndex, score }) => (score >= 0) === !!bits[bitIndex]).length;
    const agreement = cellScores.length ? agreeing / cellScores.length : 0;
    const meanAbs = meanAbsPre;
    // Unmarked photos naturally show ~0.60–0.68 self-agreement (majority
    // vote bias) and weak mean signal; genuine marks sit far above both.
    const evidence = Math.max(0, agreement - 0.64) * 2.4 +
      Math.min(0.55, Math.max(0, meanAbs - 1.4) / 8) -
      Math.max(0, corrected.corrections) * 0.04;
    const confidence = crcValid
      ? Math.max(0, Math.min(0.99, 0.42 + evidence))
      : Math.max(0, Math.min(0.49, evidence));
    const minBitCount = Math.min(...bitCounts);
    const observedBits = bitCounts.reduce((count, value) => count + (value > 0 ? 1 : 0), 0);
    // A center crop can remove every repetition of a few robust code bits.
    // Accept that bounded case only when at least 88/96 bits were observed
    // and the dual-CRC/marker codeword plus signal thresholds all validate.
    // The standard profile requires dense evidence — >=3 cells per bit on
    // average and >=2 for every bit: with ~1-2 cells per bit, majority
    // "agreement" is near-tautological and the CRC corrector can flip
    // low-reliability bits into a false positive on unmarked noise (found
    // by fuzzing; genuine marks measure ~6 cells/bit, agreement >= 0.84).
    const bitCoverageOk = robust
      ? observedBits >= 88 && cellScores.length >= 128
      : minBitCount >= 2 && cellScores.length >= codeLength * 3;
    // The robust syndrome decoder can search farther than the standard
    // decoder. To prefer "not found" over a wrong attribution, candidates
    // needing four or five corrections must also show strong raw signal and
    // cell agreement; a weak, heavily repaired candidate is not evidence.
    const correctionCount = Math.max(0, corrected.corrections);
    // Legacy (pre-v1.12, CRC-tagged) candidates are held to stricter gates:
    // their linear tag is exactly what collusion-phantom repair exploits,
    // so a legacy standard decode must be nearly repair-free with very
    // high agreement, and a legacy robust decode loses the 4-5 tier.
    const legacyScheme = corrected.tagScheme === 'crc';
    const robustCorrectionOk = !robust || correctionCount <= 3 ||
      (!legacyScheme && correctionCount <= 5 && meanAbs >= 3.5 && agreement >= 0.95);
    // Same principle for the standard decoder: a candidate needing 2+
    // repaired bits must carry clearly genuine raw signal, or the repair
    // search itself manufactures the CRC match (false attribution).
    const standardCorrectionOk = robust || (legacyScheme
      ? correctionCount <= 1 && agreement >= 0.95
      : correctionCount <= 1 || (meanAbs >= 2.0 && agreement >= 0.85));
    const found = crcValid && agreement >= 0.72 && meanAbs >= 1.2 &&
      cellScores.length >= 96 && bitCoverageOk && robustCorrectionOk && standardCorrectionOk;
    return {
      found,
      fingerprint,
      profile: effectiveProfile,
      tagScheme: corrected.tagScheme ?? null,
      layoutVersion: concreteLayout,
      observedBits,
      minBitRepetitions: minBitCount,
      crcValid,
      corrections: Math.max(0, corrected.corrections),
      // Confidence describes the ACCEPTED verdict: a candidate the gates
      // rejected must never report near-certain confidence, or downstream
      // tooling will treat a manufactured CRC match as an attribution.
      confidence: Math.round((found ? confidence : Math.min(0.49, confidence)) * 1000) / 1000,
      agreement: Math.round(agreement * 1000) / 1000,
      meanSignal: Math.round(meanAbs * 100) / 100,
      cells: cellScores.length,
      offset: {
        x: Math.round((ox / cellW0) * 1000) / 1000,
        y: Math.round((oy / cellH0) * 1000) / 1000,
      },
      geometry: {
        scaleX: Math.round(scaleX * 1000) / 1000,
        scaleY: Math.round(scaleY * 1000) / 1000,
        originX: Math.round(ox * 10) / 10,
        originY: Math.round(oy * 10) / 10,
      },
      grid: { x: gx, y: gy },
      _evidence: evidence,
      _originX: ox,
      _originY: oy,
      _scaleX: scaleX,
      _scaleY: scaleY,
    };
  };

  let best = null;
  const consider = (candidate) => {
    const better = !best ||
      (candidate.found && !best.found) ||
      (candidate.found === best.found && candidate._evidence > best._evidence) ||
      (candidate.found === best.found && candidate._evidence === best._evidence && candidate.confidence > best.confidence);
    if (better) best = candidate;
    return candidate;
  };

  for (const fx of fractions) for (const fy of fractions) {
    consider(evaluate({ fx, fy }));
    if (best.found && best.confidence >= 0.92 && fx === 0 && fy === 0) break;
  }

  // Uniform crop+resize changes the suspect-pixel size and origin of the
  // original macro-cell grid. Search a bounded set of retained-area scales
  // (80–125%) at left/center/right and top/center/bottom origins, then refine
  // the strongest geometries by sub-cell offsets. This intentionally does
  // NOT claim perspective/rotation recovery: a phone photo usually needs
  // manual deskew/crop to the displayed rectangle before detection.
  if (searchGeometry && !best?.found) {
    const scaleValues = [0.8, 0.85, 0.9, 0.95, 1, 1.05, 1 / 0.9, 1 / 0.85, 1.25];
    // 3-decimal precision: rounding to 1 decimal (pre-1.13) silently
    // rewrote half the table (0.85->0.9, 1/0.9->1.1, ...), and at
    // 1.1 vs the true 1.111 for an unresized 90% center crop the cell
    // grid drifts ~10px across the frame — enough to lose the mark.
    const unique = (values) => [...new Set(values.map((v) => Math.round(v * 1000) / 1000))];
    const originRange = (span, extent) => {
      const min = Math.min(0, extent - span);
      const max = Math.max(0, extent - span);
      return { min, max, center: (min + max) / 2 };
    };

    // First rank independent X/Y retained-area scales at edge/center origins.
    // This catches one-axis crops (e.g. only the left edge was removed) as
    // well as symmetric crops. Geometry search is an offline forensic mode,
    // so a few hundred bounded candidates are acceptable.
    const scaleCandidates = [];
    // Native-resolution crops (no resize): the signal is pristine but the
    // grid is offset by whole cells — searchOffsets only covers ±1 cell.
    // Roam ±4 cells at scale 1; the sub-cell refinement below polishes.
    for (let cellX = -4; cellX <= 4; cellX++) {
      for (let cellY = -4; cellY <= 4; cellY++) {
        if (cellX === 0 && cellY === 0) continue;
        scaleCandidates.push(consider(evaluate({
          scaleX: 1, scaleY: 1, originX: cellX * cw, originY: cellY * ch,
        })));
      }
    }
    for (const scaleX of scaleValues) {
      const rangeX = originRange(gx * cw * scaleX, w);
      for (const scaleY of scaleValues) {
        const rangeY = originRange(gy * ch * scaleY, h);
        for (const originX of unique([rangeX.min, rangeX.center, rangeX.max])) {
          for (const originY of unique([rangeY.min, rangeY.center, rangeY.max])) {
            scaleCandidates.push(consider(evaluate({
              scaleX, scaleY, originX, originY,
            })));
          }
        }
      }
    }

    // Then try edge/center origins for the strongest scale pairs.
    const originCandidates = [];
    const seenPairs = new Set();
    for (const candidate of scaleCandidates.sort((a, b) => b._evidence - a._evidence)) {
      const key = `${Math.round(candidate._scaleX * 1000)}:${Math.round(candidate._scaleY * 1000)}`;
      if (seenPairs.has(key)) continue;
      seenPairs.add(key);
      const rangeX = originRange(gx * cw * candidate._scaleX, w);
      const rangeY = originRange(gy * ch * candidate._scaleY, h);
      // Quarter points as well as edges/center: an asymmetric crop (e.g.
      // 14% off the left, 4% off the right) lands between center and edge
      // and previously desynchronized every candidate.
      const quarter = (range) => unique([
        range.min,
        range.min + (range.max - range.min) * 0.25,
        range.center,
        range.min + (range.max - range.min) * 0.75,
        range.max,
      ]);
      for (const originX of quarter(rangeX)) {
        for (const originY of quarter(rangeY)) {
          originCandidates.push(consider(evaluate({
            scaleX: candidate._scaleX,
            scaleY: candidate._scaleY,
            originX,
            originY,
          })));
        }
      }
      if (seenPairs.size >= 4) break;
    }

    // Finally refine the best three geometries by sub-cell offsets.
    const refinements = [];
    const seenGeometries = new Set();
    for (const candidate of originCandidates.sort((a, b) => b._evidence - a._evidence)) {
      const key = `${Math.round(candidate._scaleX * 1000)}:${Math.round(candidate._scaleY * 1000)}:` +
        `${Math.round(candidate._originX)}:${Math.round(candidate._originY)}`;
      if (seenGeometries.has(key)) continue;
      seenGeometries.add(key);
      refinements.push(candidate);
      if (refinements.length >= 3) break;
    }
    for (const coarseCandidate of refinements) {
      for (const fx of fractions) for (const fy of fractions) {
        consider(evaluate({
          scaleX: coarseCandidate._scaleX,
          scaleY: coarseCandidate._scaleY,
          originX: coarseCandidate._originX + fx * cw * coarseCandidate._scaleX,
          originY: coarseCandidate._originY + fy * ch * coarseCandidate._scaleY,
        }));
      }
    }

    // Fine scale refinement around the leaders. The coarse scale grid is
    // 5%-stepped; an 82%-retained crop sits between 0.80 and 0.85, and a
    // 2–3% scale error drifts the macro-cell grid by up to ~0.7 cell at
    // the far edge — enough to desync voting even at the right origin.
    // Walk ±3.5% in ~1.2% steps on each axis around the best geometries,
    // re-centering the origin so the grid center stays anchored.
    if (!best?.found) {
      const fineFactors = [0.965, 0.977, 0.988, 1.012, 1.023, 1.035];
      const leaders = refinements.slice(0, 2);
      for (const leader of leaders) {
        for (const fxScale of [1, ...fineFactors]) {
          for (const fyScale of [1, ...fineFactors]) {
            if (fxScale === 1 && fyScale === 1) continue;
            const scaleX = leader._scaleX * fxScale;
            const scaleY = leader._scaleY * fyScale;
            consider(evaluate({
              scaleX,
              scaleY,
              originX: leader._originX + (gx * cw * (leader._scaleX - scaleX)) / 2,
              originY: leader._originY + (gy * ch * (leader._scaleY - scaleY)) / 2,
            }));
            if (best?.found) break;
          }
          if (best?.found) break;
        }
      }
    }
  }

  if (best) {
    delete best._evidence;
    delete best._originX;
    delete best._originY;
    delete best._scaleX;
    delete best._scaleY;
  }
  // Explicit-profile mirror recovery (compound flip+geometry included,
  // since the probe inherits this call's search options).
  if (!best?.found && searchMirror && !_mirrorProbe) {
    try {
      const src = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
      if (src.length >= w * h * 4 && Number.isSafeInteger(w * h * 4)) {
        const mirrored = detectStegoFingerprint(flipPixelsHorizontal(src, w, h), w, h, {
          key, gridX, gridY, profile, searchOffsets, searchGeometry,
          searchMirror: false, _mirrorProbe: true, _layoutVersion: concreteLayout,
        });
        if (mirrored?.found) return { ...mirrored, mirrored: true };
      }
    } catch { /* mirror probe is best-effort */ }
  }
  return best;
}

/* ------------------------------------------------------------------ */
/* Pixel-level scramble on raw RGBA buffers (used by server + tests)    */
/* ------------------------------------------------------------------ */

/**
 * Scramble/unscramble a raw RGBA pixel buffer in-place style (returns new buffer).
 * The browser client does NOT use this hot path (it un-scrambles with cheap
 * drawImage calls); this exists for the Node server fallback and unit tests.
 * @param {Uint8Array|Buffer} rgba  pw*ph*4 bytes (already padded)
 * @param {'scramble'|'unscramble'} direction
 */
export function scramblePixels(rgba, pw, ph, plan, direction = 'scramble') {
  if (direction !== 'scramble' && direction !== 'unscramble') {
    throw new TypeError('Archx: scramble direction is invalid');
  }
  const grid = plan?.grid;
  const count = plan?.count;
  if (!Number.isSafeInteger(pw) || !Number.isSafeInteger(ph) || pw < 1 || ph < 1 ||
      !Number.isInteger(grid) || grid < 2 || grid > 32 || count !== grid * grid ||
      pw % grid !== 0 || ph % grid !== 0 || !Array.isArray(plan.order) ||
      !Array.isArray(plan.inverse) || !Array.isArray(plan.flips) ||
      plan.order.length !== count || plan.inverse.length !== count || plan.flips.length !== count) {
    throw new RangeError('Archx: invalid scramble geometry');
  }
  const tw = pw / grid;
  const th = ph / grid;
  const src = asBytes(rgba);
  const expected = pw * ph * 4;
  if (!Number.isSafeInteger(expected) || src.length < expected) {
    throw new RangeError('Archx: RGBA buffer is smaller than the padded image');
  }
  const out = new Uint8Array(expected);
  const useWords = src.byteOffset % 4 === 0 && src.byteLength % 4 === 0;
  const src32 = useWords ? new Uint32Array(src.buffer, src.byteOffset, src.byteLength / 4) : null;
  const out32 = useWords ? new Uint32Array(out.buffer) : null;
  for (let dest = 0; dest < count; dest++) {
    // scramble: dest is scrambled pos, source = order[dest]
    // unscramble: dest is original pos, source = inverse[dest]
    const source = direction === 'scramble' ? plan.order[dest] : plan.inverse[dest];
    if (!Number.isInteger(source) || source < 0 || source >= count) {
      throw new RangeError('Archx: invalid scramble plan');
    }
    const flipPos = direction === 'scramble' ? dest : source;
    const flip = plan.flips[flipPos];
    if (!flip || typeof flip !== 'object') throw new RangeError('Archx: invalid scramble plan');
    const { fx, fy } = flip;
    const sx = (source % grid) * tw;
    const sy = Math.floor(source / grid) * th;
    const dx = (dest % grid) * tw;
    const dy = Math.floor(dest / grid) * th;
    for (let y = 0; y < th; y++) {
      const yy = fy ? th - 1 - y : y;
      const srcRow = (sy + yy) * pw + sx;
      const dstRow = (dy + y) * pw + dx;
      if (useWords && !fx) {
        out32.set(src32.subarray(srcRow, srcRow + tw), dstRow);
      } else if (useWords) {
        for (let x = 0; x < tw; x++) out32[dstRow + x] = src32[srcRow + (tw - 1 - x)];
      } else {
        for (let x = 0; x < tw; x++) {
          const xx = fx ? tw - 1 - x : x;
          const si = (srcRow + xx) * 4;
          const di = (dstRow + x) * 4;
          out[di] = src[si]; out[di + 1] = src[si + 1];
          out[di + 2] = src[si + 2]; out[di + 3] = src[si + 3];
        }
      }
    }
  }
  return out;
}

/**
 * Fused pad + scramble: read a raw RGBA buffer of w×h (NOT pre-padded) and
 * write the scrambled pw×ph result, treating out-of-bounds source pixels as
 * opaque black (the same padding `padRaw` + `scramblePixels` produced).
 * One output allocation and one pass replace the pad copy, the scramble
 * copy, and the caller's Buffer.from copy. `out`, when given, must hold at
 * least pw*ph*4 bytes and is fully overwritten; the written bytes are
 * identical to `scramblePixels(pad(rgba), pw, ph, plan, 'scramble')`.
 * @param {Uint8Array|Buffer} rgba w*h*4 bytes (unpadded)
 * @param {Uint8Array|Buffer} [out] optional destination buffer
 * @returns {Uint8Array|Buffer} the destination buffer
 */
export function scramblePixelsPadded(rgba, w, h, plan, out = null) {
  const grid = plan?.grid;
  const count = plan?.count;
  if (!Number.isSafeInteger(w) || !Number.isSafeInteger(h) || w < 1 || h < 1 ||
      !Number.isInteger(grid) || grid < 2 || grid > 32 || count !== grid * grid ||
      !Array.isArray(plan.order) || !Array.isArray(plan.flips) ||
      plan.order.length !== count || plan.flips.length !== count) {
    throw new RangeError('Archx: invalid scramble geometry');
  }
  const tw = Math.ceil(w / grid);
  const th = Math.ceil(h / grid);
  const pw = tw * grid;
  const ph = th * grid;
  const src = asBytes(rgba);
  if (!Number.isSafeInteger(w * h * 4) || src.length < w * h * 4) {
    throw new RangeError('Archx: RGBA buffer is smaller than the image');
  }
  const expected = pw * ph * 4;
  const target = out ? asBytes(out) : new Uint8Array(expected);
  if (!Number.isSafeInteger(expected) || target.length < expected) {
    throw new RangeError('Archx: scramble output buffer is too small');
  }
  const useWords = src.byteOffset % 4 === 0 && src.byteLength % 4 === 0 &&
    target.byteOffset % 4 === 0 && target.byteLength % 4 === 0;
  const src32 = useWords ? new Uint32Array(src.buffer, src.byteOffset, src.byteLength / 4) : null;
  const out32 = useWords ? new Uint32Array(target.buffer, target.byteOffset, target.byteLength / 4) : null;
  // Padding = KEYED SHIFTED WRAP + per-channel noise. History of this
  // strip: black (pre-1.11) identified every edge tile + flip; edge
  // replication (1.11) duplicated rows exactly; interior reflection
  // (1.12) left a palindromic seam — a pad row mirrored its edge row
  // with mean-abs-diff ~0.6 vs ~17 for real texture, again naming the
  // boundary tiles and their vertical flip. Now pad pixels sample the
  // image's own interior from a plan-keyed toroidal offset (no seam, no
  // palindrome, no aligned duplicate: each pad row also gets a keyed
  // horizontal phase), plus keyed noise in [-3,3] per channel. A solver
  // without the scramble key cannot predict or cleanly correlate the
  // fill; a solver WITH the key never needed the oracle. Display is
  // unaffected — the padded region is cropped before presentation, and
  // unscrambling never regenerates pad content.
  let padSeedState = 0x9e3779b9;
  for (let i = 0; i < count; i++) {
    padSeedState = Math.imul(padSeedState ^ (plan.order[i] * 2654435761), 2246822519);
    padSeedState = Math.imul(padSeedState ^ ((plan.flips[i].fx ? 2 : 0) + (plan.flips[i].fy ? 1 : 0) + 1), 3266489917);
  }
  const padRand = mulberry32(padSeedState >>> 0);
  const padShiftY = h > 3 ? 1 + Math.floor(padRand() * (h - 2)) : 0;
  const padShiftX = w > 3 ? 1 + Math.floor(padRand() * (w - 2)) : 0;
  const padPhaseSeed = Math.floor(padRand() * 0xffffffff) | 0;
  const wrapPos = (c, n) => ((c % n) + n) % n;
  const padRowPhase = (srcY) => {
    let hash = (padPhaseSeed ^ Math.imul(srcY + 1, 374761393)) | 0;
    hash = Math.imul(hash ^ (hash >>> 13), 1274126177);
    return w > 1 ? ((hash >>> 8) % w) : 0;
  };
  const padNoise = (gx, gy, channel) => {
    let hash = (padPhaseSeed ^ Math.imul(gx + 1, 374761393) ^ Math.imul(gy + 1, 668265263) ^ Math.imul(channel + 1, 2246822519)) | 0;
    hash = Math.imul(hash ^ (hash >>> 13), 1274126177);
    return ((hash >>> 16) % 7) - 3;
  };
  const writePixel = (di, si) => {
    target[di] = src[si]; target[di + 1] = src[si + 1];
    target[di + 2] = src[si + 2]; target[di + 3] = src[si + 3];
  };
  const writePadPixel = (di, si, gx, gy) => {
    target[di] = Math.max(0, Math.min(255, src[si] + padNoise(gx, gy, 0)));
    target[di + 1] = Math.max(0, Math.min(255, src[si + 1] + padNoise(gx, gy, 1)));
    target[di + 2] = Math.max(0, Math.min(255, src[si + 2] + padNoise(gx, gy, 2)));
    target[di + 3] = src[si + 3];
  };
  for (let dest = 0; dest < count; dest++) {
    const source = plan.order[dest];
    if (!Number.isInteger(source) || source < 0 || source >= count) {
      throw new RangeError('Archx: invalid scramble plan');
    }
    const flip = plan.flips[dest];
    if (!flip || typeof flip !== 'object') throw new RangeError('Archx: invalid scramble plan');
    const { fx, fy } = flip;
    const sx = (source % grid) * tw;
    const sy = Math.floor(source / grid) * th;
    const dx = (dest % grid) * tw;
    const dy = Math.floor(dest / grid) * th;
    for (let y = 0; y < th; y++) {
      const rawY = sy + (fy ? th - 1 - y : y);
      const rowIsPad = rawY >= h;
      const srcY = rowIsPad ? wrapPos(padShiftY + (rawY - h), h) : rawY;
      const rowPhase = padRowPhase(srcY);
      const dstRow = (dy + y) * pw + dx;
      if (useWords && !fx && !rowIsPad) {
        const avail = Math.max(0, Math.min(tw, w - sx));
        if (avail > 0) out32.set(src32.subarray(srcY * w + sx, srcY * w + sx + avail), dstRow);
        for (let x = avail; x < tw; x++) {
          const rawX = sx + x;
          const srcX = wrapPos(padShiftX + rowPhase + (rawX - w), w);
          writePadPixel((dstRow + x) * 4, (srcY * w + srcX) * 4, rawX, rawY);
        }
      } else if (useWords && !rowIsPad && !((sx + tw) > w)) {
        for (let x = 0; x < tw; x++) {
          out32[dstRow + x] = src32[srcY * w + sx + (tw - 1 - x)];
        }
      } else {
        for (let x = 0; x < tw; x++) {
          const rawX = sx + (fx ? tw - 1 - x : x);
          const colIsPad = rawX >= w;
          const srcX = colIsPad ? wrapPos(padShiftX + rowPhase + (rawX - w), w) : rawX;
          if (rowIsPad || colIsPad) {
            writePadPixel((dstRow + x) * 4, (srcY * w + srcX) * 4, rawX, rawY);
          } else {
            writePixel((dstRow + x) * 4, (srcY * w + srcX) * 4);
          }
        }
      }
    }
  }
  return target;
}

/* ------------------------------------------------------------------ */
/* Perceptual content fingerprint (soft binding)                       */
/* ------------------------------------------------------------------ */

/**
 * Compute a 64-bit DCT perceptual hash of an RGBA image.
 *
 * This is a C2PA-style *soft binding*: register it beside an image/order ID,
 * and a resized/re-encoded/mildly edited suspect copy can often still be
 * matched after metadata or even a pixel watermark has been stripped. It is
 * deliberately tiny and dependency-free. It is not cryptographic identity,
 * not proof of ownership by itself, and modern regeneration/cropping/
 * adversarial perturbation can move a copy beyond a safe threshold. Treat a
 * close distance as investigative evidence to corroborate, not a verdict.
 *
 * @param {Uint8Array|Buffer} rgba w*h*4 bytes
 * @returns {string} 16 lowercase hex characters
 */
// Module-static DCT basis (same Math.cos values, computed once instead
// of 256 transcendental calls per fingerprint).
const DCT_COSINES_32x8 = (() => {
  const table = new Float64Array(32 * 8);
  for (let x = 0; x < 32; x++) {
    for (let u = 0; u < 8; u++) table[x * 8 + u] = Math.cos(((2 * x + 1) * u * Math.PI) / (2 * 32));
  }
  return table;
})();

export function perceptualFingerprint(rgba, w, h) {
  if (!Number.isSafeInteger(w) || !Number.isSafeInteger(h) || w < 1 || h < 1) {
    throw new RangeError('Archx: invalid image dimensions for perceptual fingerprint');
  }
  const src = asBytes(rgba);
  const expected = w * h * 4;
  if (!Number.isSafeInteger(expected) || src.length < expected) {
    throw new RangeError('Archx: RGBA buffer is smaller than the image');
  }
  const SIZE = 32;
  const small = new Float64Array(SIZE * SIZE);
  const weights = new Float64Array(SIZE * SIZE);

  // Area-average to 32×32. Area weighting is slower than nearest-neighbour
  // sampling but makes the fingerprint materially steadier across the exact
  // resampling choices of browsers, Sharp, and social-media transcoders.
  // The per-column/per-row overlap spans are precomputed once (they depend
  // only on x / y); the accumulation order — and therefore every float —
  // is unchanged, so fingerprints stay bit-identical to the direct form.
  const spansFor = (n) => {
    const spans = new Array(n);
    for (let s = 0; s < n; s++) {
      const s0 = (s * SIZE) / n;
      const s1 = ((s + 1) * SIZE) / n;
      const start = Math.floor(s0);
      const end = Math.min(SIZE - 1, Math.ceil(s1) - 1);
      const wts = new Float64Array(end - start + 1);
      for (let o = start; o <= end; o++) wts[o - start] = Math.min(s1, o + 1) - Math.max(s0, o);
      spans[s] = { start, wts };
    }
    return spans;
  };
  const colSpans = spansFor(w);
  const rowSpans = spansFor(h);
  for (let y = 0; y < h; y++) {
    const rowSpan = rowSpans[y];
    const rowOffset = y * w * 4;
    for (let x = 0; x < w; x++) {
      const i = rowOffset + x * 4;
      const alpha = src[i + 3] / 255;
      const gray = ((src[i] * 54 + src[i + 1] * 183 + src[i + 2] * 19) / 256) * alpha;
      const colSpan = colSpans[x];
      for (let oyi = 0; oyi < rowSpan.wts.length; oyi++) {
        const wy = rowSpan.wts[oyi];
        if (wy <= 0) continue;
        const rowBase = (rowSpan.start + oyi) * SIZE + colSpan.start;
        for (let oxi = 0; oxi < colSpan.wts.length; oxi++) {
          const wx = colSpan.wts[oxi];
          if (wx <= 0) continue;
          const idx = rowBase + oxi;
          const weight = wx * wy;
          small[idx] += gray * weight;
          weights[idx] += weight;
        }
      }
    }
  }
  for (let i = 0; i < small.length; i++) {
    small[i] = weights[i] > 0 ? small[i] / weights[i] : 0;
  }

  const cosines = DCT_COSINES_32x8;
  const rowDct = new Float64Array(SIZE * 8);
  for (let y = 0; y < SIZE; y++) {
    for (let u = 0; u < 8; u++) {
      let sum = 0;
      for (let x = 0; x < SIZE; x++) sum += small[y * SIZE + x] * cosines[x * 8 + u];
      rowDct[y * 8 + u] = sum;
    }
  }
  const coefficients = new Float64Array(64);
  for (let v = 0; v < 8; v++) {
    for (let u = 0; u < 8; u++) {
      let sum = 0;
      for (let y = 0; y < SIZE; y++) sum += rowDct[y * 8 + u] * cosines[y * 8 + v];
      coefficients[v * 8 + u] = sum;
    }
  }
  const sorted = [...coefficients.slice(1)].sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];
  let bits = 0n;
  for (let i = 0; i < 64; i++) {
    if (coefficients[i] > median) bits |= 1n << BigInt(63 - i);
  }
  return bits.toString(16).padStart(16, '0');
}

export function normalizePerceptualFingerprint(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().toLowerCase();
  return /^[0-9a-f]{16}$/.test(normalized) ? normalized : null;
}

export function perceptualFingerprintDistance(a, b) {
  const left = normalizePerceptualFingerprint(a);
  const right = normalizePerceptualFingerprint(b);
  if (!left || !right) throw new TypeError('Archx: perceptual fingerprint must be 16 hex characters');
  let xor = BigInt('0x' + left) ^ BigInt('0x' + right);
  let distance = 0;
  while (xor > 0n) {
    distance += Number(xor & 1n);
    xor >>= 1n;
  }
  return distance;
}

export function comparePerceptualFingerprints(a, b, { maxDistance = 10 } = {}) {
  if (!Number.isInteger(maxDistance) || maxDistance < 0 || maxDistance > 64) {
    throw new RangeError('Archx: perceptual fingerprint maxDistance must be an integer from 0 to 64');
  }
  const distance = perceptualFingerprintDistance(a, b);
  return Object.freeze({
    distance,
    similarity: 1 - distance / 64,
    match: distance <= maxDistance,
  });
}
