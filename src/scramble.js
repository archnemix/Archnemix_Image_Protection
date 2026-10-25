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
  const tw = Math.ceil(w / grid);
  const th = Math.ceil(h / grid);
  return { tw, th, pw: tw * grid, ph: th * grid };
}

/* ------------------------------------------------------------------ */
/* Base64 helpers (browser + Node)                                      */
/* ------------------------------------------------------------------ */

export function bytesToBase64(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (typeof Buffer !== 'undefined') return Buffer.from(u8).toString('base64');
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < u8.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

export function base64ToBytes(b64) {
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(String(b64), 'base64'));
  const bin = atob(String(b64));
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
export function encodeContainer(header, payload) {
  const headerBytes = new TextEncoder().encode(JSON.stringify(header));
  const body = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
  const out = new Uint8Array(6 + 4 + headerBytes.length + body.length);
  out.set(new TextEncoder().encode(ARCHX_MAGIC), 0);
  new DataView(out.buffer).setUint32(6, headerBytes.length, false);
  out.set(headerBytes, 10);
  out.set(body, 10 + headerBytes.length);
  return out;
}

export function isArchxContainer(bytes) {
  if (!bytes || bytes.length < 10) return false;
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return ARCHX_MAGIC.split('').every((c, i) => u8[i] === c.charCodeAt(0));
}

export function decodeContainer(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (!isArchxContainer(u8)) throw new Error('Archx: not an .archx container');
  const headerLen = new DataView(u8.buffer, u8.byteOffset).getUint32(6, false);
  const header = JSON.parse(new TextDecoder().decode(u8.subarray(10, 10 + headerLen)));
  const payload = u8.subarray(10 + headerLen);
  return { header, payload };
}

/* ------------------------------------------------------------------ */
/* AES-GCM payload encryption (WebCrypto — available in Node ≥19 too)   */
/* ------------------------------------------------------------------ */

const keyCache = new Map();

async function importAesKey(keyBase64) {
  if (keyCache.has(keyBase64)) return keyCache.get(keyBase64);
  const raw = base64ToBytes(keyBase64);
  if (![16, 24, 32].includes(raw.length)) {
    throw new Error('Archx: AES key must be 16/24/32 bytes (base64)');
  }
  const key = await globalThis.crypto.subtle.importKey(
    'raw', raw, { name: 'AES-GCM', length: raw.length * 8 }, false, ['encrypt', 'decrypt'],
  );
  keyCache.set(keyBase64, key);
  return key;
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
    { name: 'AES-GCM', iv }, key,
    plainBytes instanceof Uint8Array ? plainBytes : new Uint8Array(plainBytes),
  );
  return { cipher: new Uint8Array(cipher), iv: bytesToBase64(iv) };
}

export async function decryptPayload(cipherBytes, keyBase64, ivBase64) {
  const key = await importAesKey(keyBase64);
  const plain = await globalThis.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(ivBase64) }, key,
    cipherBytes instanceof Uint8Array ? cipherBytes : new Uint8Array(cipherBytes),
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
  const { grid, count } = plan;
  const tw = pw / grid;
  const th = ph / grid;
  const src = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  const out = new Uint8Array(src.length);
  for (let dest = 0; dest < count; dest++) {
    // scramble: dest is scrambled pos, source = order[dest]
    // unscramble: dest is original pos, source = inverse[dest]
    const source = direction === 'scramble' ? plan.order[dest] : plan.inverse[dest];
    const flipPos = direction === 'scramble' ? dest : source;
    const { fx, fy } = plan.flips[flipPos];
    const sx = (source % grid) * tw;
    const sy = Math.floor(source / grid) * th;
    const dx = (dest % grid) * tw;
    const dy = Math.floor(dest / grid) * th;
    for (let y = 0; y < th; y++) {
      const yy = fy ? th - 1 - y : y;
      for (let x = 0; x < tw; x++) {
        const xx = fx ? tw - 1 - x : x;
        const si = ((sy + yy) * pw + (sx + xx)) * 4;
        const di = ((dy + y) * pw + (dx + x)) * 4;
        out[di] = src[si]; out[di + 1] = src[si + 1];
        out[di + 2] = src[si + 2]; out[di + 3] = src[si + 3];
      }
    }
  }
  return out;
}
