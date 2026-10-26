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

/**
 * Build the deterministic scramble plan for a key.
 * @param {number} grid tiles per side (2..32)
 * @param {string} key  secret seed material
 * @returns {{grid:number,count:number,order:number[],inverse:number[],flips:{fx:boolean,fy:boolean}[]}}
 *   order[scrambledPos]   = originalPos
 *   inverse[originalPos]  = scrambledPos
 */
export function buildScramblePlan(grid = DEFAULT_GRID, key = '') {
  const g = Math.max(2, Math.min(32, grid | 0));
  const count = g * g;
  const rand = mulberry32(hashSeed(String(key) + '::archx-grid-' + g));
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
  return { grid: g, count, order, inverse, flips };
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
  const head = new TextDecoder('utf-8', { fatal: false }).decode(u8.subarray(0, Math.min(1024, u8.length))).trimStart().toLowerCase();
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
  'v', 'w', 'h', 'pw', 'ph', 'grid', 'mime', 'scrambled', 'encrypted', 'iv', 'wm', 'fx', 'sg',
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
  const headerBytes = new TextEncoder().encode(JSON.stringify(header));
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
    header = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(u8.subarray(10, 10 + headerLen)));
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

async function importAesKey(keyBase64) {
  if (typeof keyBase64 !== 'string' || !keyBase64) throw new TypeError('Archx: AES key must be a base64 string');
  const cached = keyCache.get(keyBase64);
  if (cached) {
    keyCache.delete(keyBase64); keyCache.set(keyBase64, cached);
    return cached;
  }
  const pending = (async () => {
    const raw = base64ToBytes(keyBase64);
    if (![16, 24, 32].includes(raw.length)) {
      throw new Error('Archx: AES key must be 16/24/32 bytes (base64)');
    }
    return globalThis.crypto.subtle.importKey(
      'raw', raw, { name: 'AES-GCM', length: raw.length * 8 }, false, ['encrypt', 'decrypt'],
    );
  })();
  keyCache.set(keyBase64, pending);
  while (keyCache.size > AES_KEY_CACHE_MAX) keyCache.delete(keyCache.keys().next().value);
  try { return await pending; }
  catch (err) { if (keyCache.get(keyBase64) === pending) keyCache.delete(keyBase64); throw err; }
}

/** Generate a fresh 256-bit key, base64-encoded. */
export function generateKeyBase64() {
  const raw = new Uint8Array(32);
  globalThis.crypto.getRandomValues(raw);
  return bytesToBase64(raw);
}

export async function encryptPayload(plainBytes, keyBase64) {
  const key = await importAesKey(keyBase64);
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);
  const cipher = await globalThis.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, asBytes(plainBytes),
  );
  return { cipher: new Uint8Array(cipher), iv: bytesToBase64(iv) };
}

export async function decryptPayload(cipherBytes, keyBase64, ivBase64) {
  const cipher = asBytes(cipherBytes);
  const iv = base64ToBytes(ivBase64);
  if (iv.length !== 12) throw new Error('Archx: AES-GCM IV must be 12 bytes');
  if (cipher.length < 17) throw new Error('Archx: AES-GCM payload is too short');
  const key = await importAesKey(keyBase64);
  const plain = await globalThis.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv }, key, cipher,
  );
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
export function forensicBlockSigns(seed, count) {
  const rand = mulberry32(hashSeed(String(seed) + '::archx-forensic'));
  return Array.from({ length: count }, () => (rand() < 0.5 ? -1 : 1));
}

export function applyForensicBlocks(rgba, w, h, seed, { blockSize = 32, delta = 2 } = {}) {
  const bs = Math.max(8, blockSize | 0);
  const bx = Math.ceil(w / bs);
  const by = Math.ceil(h / bs);
  const signs = forensicBlockSigns(seed, bx * by);
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
  const signs = forensicBlockSigns(seed, bx * by);
  let matched = 0, total = 0, signedSum = 0;
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
      const mean = diff / n;
      total++;
      signedSum += Math.sign(mean) === signs[byi * bx + bxi] ? 1 : -1;
      if (Math.sign(mean) === signs[byi * bx + bxi]) matched++;
    }
  }
  return { score: total ? signedSum / total : 0, matched, total };
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
  const a = hashSeed('archx-stego:' + s, 0x51ab);
  const b = hashSeed('archx-stego:' + s, 0x9e37);
  const lo = Math.floor(a % 0x1000000).toString(16).padStart(6, '0');
  const hi = Math.floor(b % 0x1000000).toString(16).padStart(6, '0');
  return lo + hi;
}

function stegoCrc16(bytes) {
  let crc = 0xffff;
  for (const byte of bytes) {
    crc ^= byte << 8;
    for (let i = 0; i < 8; i++) {
      crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return crc;
}

function stegoCodeBits(fingerprint) {
  const bytes = new Uint8Array(6);
  for (let i = 0; i < 6; i++) bytes[i] = parseInt(fingerprint.slice(i * 2, i * 2 + 2), 16);
  const crc = stegoCrc16(bytes);
  const all = [...bytes, (crc >> 8) & 255, crc & 255];
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

/**
 * Soft-decision repair: if the voted codeword fails CRC, try flipping the
 * least-reliable bits (singles, pairs, triples). Real marks usually need
 * 0–2 repairs after re-encoding; random images are still rejected by the
 * caller's signal/agreement thresholds, not by CRC alone.
 */
function correctStegoBits(bits, reliability) {
  if (stegoCrcValid(bits)) return { bits, corrections: 0 };
  const weakest = [...bits.keys()]
    .sort((a, b) => reliability[a] - reliability[b])
    .slice(0, 20);
  let best = null;
  const visit = (start, chosen) => {
    if (chosen.length) {
      const candidate = new Uint8Array(bits);
      let cost = 0;
      for (const i of chosen) { candidate[i] ^= 1; cost += reliability[i]; }
      if (stegoCrcValid(candidate) && (!best || cost < best.cost)) {
        best = { bits: candidate, corrections: chosen.length, cost };
      }
    }
    if (chosen.length >= 3) return;
    for (let i = start; i < weakest.length; i++) visit(i + 1, [...chosen, weakest[i]]);
  };
  visit(0, []);
  return best || { bits, corrections: -1 };
}

const STEGO_ROW_SEGMENTS = 4;

function stegoLayout(cellCount, key) {
  const rand = mulberry32(hashSeed(String(key) + '::archx-stego-layout'));
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

export function embedStegoFingerprint(rgba, w, h, payload, {
  key = '', strength = 6, gridX = 24, gridY = 16,
} = {}) {
  const src = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  if (src.length < w * h * 4) throw new Error('Archx stego: pixel buffer is smaller than w×h×4');
  if (w < 64 || h < 64) throw new Error('Archx stego: image too small (minimum 64×64)');
  const fingerprint = stegoFingerprint(payload);
  const bits = stegoCodeBits(fingerprint);
  const { gx, gy } = stegoGrid(w, h, gridX, gridY);
  const cellCount = gx * gy;
  const { order, polarity, segmentPolarity } = stegoLayout(cellCount, key);
  const out = new Uint8Array(src);
  const amp = Math.max(1, Math.min(16, Number(strength) || 6));

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
          STEGO_ROW_SEGMENTS - 1,
          Math.floor(((y - y0) * STEGO_ROW_SEGMENTS) / cellH),
        );
        const segmentSign = segmentPolarity[cell * STEGO_ROW_SEGMENTS + segment];
        let i = (y * w + x0) * 4;
        for (let x = x0; x < x1; x++, i += 4) {
          const band = Math.min(3, Math.floor(((x - x0) * 4) / cellW));
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

export function detectStegoFingerprint(rgba, w, h, {
  key = '', gridX = 24, gridY = 16, searchOffsets = false, searchGeometry = false,
} = {}) {
  const src = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  if (src.length < w * h * 4) throw new Error('Archx stego: pixel buffer is smaller than w×h×4');
  const { gx, gy } = stegoGrid(w, h, gridX, gridY);
  const cellCount = gx * gy;
  const { order, polarity, segmentPolarity } = stegoLayout(cellCount, key);
  const cw = w / gx, ch = h / gy;
  const fractions = searchOffsets ? [-0.25, -0.125, 0, 0.125, 0.25] : [0];

  const evaluate = ({ fx = 0, fy = 0, scale = 1, scaleX = scale, scaleY = scale, originX = null, originY = null } = {}) => {
    const cellW0 = cw * scaleX;
    const cellH0 = ch * scaleY;
    const ox = originX ?? fx * cw;
    const oy = originY ?? fy * ch;
    const bitScores = new Float64Array(64);
    const bitCounts = new Uint16Array(64);
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
        const sums = new Float64Array(STEGO_ROW_SEGMENTS * 4);
        const counts = new Uint32Array(STEGO_ROW_SEGMENTS * 4);
        const cellW = x1 - x0;
        const cellH = y1 - y0;
        const step = Math.max(1, Math.floor(Math.min(cellW, cellH) / 12));
        for (let y = y0; y < y1; y += step) {
          const segment = Math.max(0, Math.min(
            STEGO_ROW_SEGMENTS - 1,
            Math.floor(((y - rawY0) * STEGO_ROW_SEGMENTS) / cellH0),
          ));
          let i = (y * w + x0) * 4;
          for (let x = x0; x < x1; x += step, i += step * 4) {
            const band = Math.max(0, Math.min(3, Math.floor(((x - rawX0) * 4) / cellW0)));
            const idx = segment * 4 + band;
            sums[idx] += (src[i] * 77 + src[i + 1] * 150 + src[i + 2] * 29) >> 8;
            counts[idx]++;
          }
        }
        // Third-difference responds to +−+− alternation and cancels linear /
        // quadratic image content. Evaluate each short row segment under its
        // keyed sign, then average. Positive result means code bit = 1.
        let segmentScoreSum = 0;
        let segmentWeightSum = 0;
        let validSegments = 0;
        const cellIndex = cy * gx + cx;
        for (let segment = 0; segment < STEGO_ROW_SEGMENTS; segment++) {
          const base = segment * 4;
          if (counts[base] === 0 || counts[base + 1] === 0 || counts[base + 2] === 0 || counts[base + 3] === 0) continue;
          validSegments++;
          const m0 = sums[base] / counts[base];
          const m1 = sums[base + 1] / counts[base + 1];
          const m2 = sums[base + 2] / counts[base + 2];
          const m3 = sums[base + 3] / counts[base + 3];
          const weight = Math.min(counts[base], counts[base + 1], counts[base + 2], counts[base + 3]);
          segmentScoreSum += (-(-m0 + 3 * m1 - 3 * m2 + m3) / 8) *
            polarity[cellIndex] * segmentPolarity[cellIndex * STEGO_ROW_SEGMENTS + segment] * weight;
          segmentWeightSum += weight;
        }
        if (!segmentWeightSum || validSegments < 2) continue;
        const rawScore = segmentScoreSum / segmentWeightSum;
        // Clip outliers: one hard image edge crossing a cell can otherwise
        // outvote five correctly-marked repetitions of the same code bit.
        const score = Math.max(-12, Math.min(12, rawScore));
        const bitIndex = order[cy * gx + cx] % 64;
        bitScores[bitIndex] += score;
        bitCounts[bitIndex]++;
        cellScores.push({ bitIndex, score });
      }
    }
    const votedBits = new Uint8Array(64);
    const reliability = new Float64Array(64);
    for (let i = 0; i < 64; i++) {
      votedBits[i] = bitScores[i] >= 0 ? 1 : 0;
      reliability[i] = Math.abs(bitScores[i]) / Math.max(1, bitCounts[i]);
    }
    const corrected = correctStegoBits(votedBits, reliability);
    const bits = corrected.bits;
    const bytes = stegoBitsToBytes(bits);
    const fingerprint = [...bytes.subarray(0, 6)].map((b) => b.toString(16).padStart(2, '0')).join('');
    const crcValid = stegoCrcValid(bits);
    const agreeing = cellScores.filter(({ bitIndex, score }) => (score >= 0) === !!bits[bitIndex]).length;
    const agreement = cellScores.length ? agreeing / cellScores.length : 0;
    const meanAbs = bitScores.reduce((s, v, i) => s + Math.abs(v) / Math.max(1, bitCounts[i]), 0) / 64;
    // Unmarked photos naturally show ~0.60–0.68 self-agreement (majority
    // vote bias) and weak mean signal; genuine marks sit far above both.
    const evidence = Math.max(0, agreement - 0.64) * 2.4 +
      Math.min(0.55, Math.max(0, meanAbs - 1.4) / 8) -
      Math.max(0, corrected.corrections) * 0.04;
    const confidence = crcValid
      ? Math.max(0, Math.min(0.99, 0.42 + evidence))
      : Math.max(0, Math.min(0.49, evidence));
    const minBitCount = Math.min(...bitCounts);
    return {
      found: crcValid && agreement >= 0.72 && meanAbs >= 1.2 &&
        cellScores.length >= 96 && minBitCount >= 1,
      fingerprint,
      crcValid,
      corrections: Math.max(0, corrected.corrections),
      confidence: Math.round(confidence * 1000) / 1000,
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
    const unique = (values) => [...new Set(values.map((v) => Math.round(v * 10) / 10))];
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
      for (const originX of unique([rangeX.min, rangeX.center, rangeX.max])) {
        for (const originY of unique([rangeY.min, rangeY.center, rangeY.max])) {
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
  }

  if (best) {
    delete best._evidence;
    delete best._originX;
    delete best._originY;
    delete best._scaleX;
    delete best._scaleY;
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
  for (let y = 0; y < h; y++) {
    const y0 = (y * SIZE) / h;
    const y1 = ((y + 1) * SIZE) / h;
    const oyStart = Math.floor(y0);
    const oyEnd = Math.min(SIZE - 1, Math.ceil(y1) - 1);
    const rowOffset = y * w * 4;
    for (let x = 0; x < w; x++) {
      const i = rowOffset + x * 4;
      const alpha = src[i + 3] / 255;
      const gray = ((src[i] * 54 + src[i + 1] * 183 + src[i + 2] * 19) / 256) * alpha;
      const x0 = (x * SIZE) / w;
      const x1 = ((x + 1) * SIZE) / w;
      const oxStart = Math.floor(x0);
      const oxEnd = Math.min(SIZE - 1, Math.ceil(x1) - 1);
      for (let oy = oyStart; oy <= oyEnd; oy++) {
        const wy = Math.min(y1, oy + 1) - Math.max(y0, oy);
        if (wy <= 0) continue;
        for (let ox = oxStart; ox <= oxEnd; ox++) {
          const wx = Math.min(x1, ox + 1) - Math.max(x0, ox);
          if (wx <= 0) continue;
          const idx = oy * SIZE + ox;
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

  const cosines = Array.from({ length: SIZE }, (_, x) =>
    Array.from({ length: 8 }, (_, u) => Math.cos(((2 * x + 1) * u * Math.PI) / (2 * SIZE))));
  const rowDct = new Float64Array(SIZE * 8);
  for (let y = 0; y < SIZE; y++) {
    for (let u = 0; u < 8; u++) {
      let sum = 0;
      for (let x = 0; x < SIZE; x++) sum += small[y * SIZE + x] * cosines[x][u];
      rowDct[y * 8 + u] = sum;
    }
  }
  const coefficients = new Float64Array(64);
  for (let v = 0; v < 8; v++) {
    for (let u = 0; u < 8; u++) {
      let sum = 0;
      for (let y = 0; y < SIZE; y++) sum += rowDct[y * 8 + u] * cosines[y][v];
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
