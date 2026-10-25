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
  key = '', gridX = 24, gridY = 16, searchOffsets = false,
} = {}) {
  const src = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  if (src.length < w * h * 4) throw new Error('Archx stego: pixel buffer is smaller than w×h×4');
  const { gx, gy } = stegoGrid(w, h, gridX, gridY);
  const cellCount = gx * gy;
  const { order, polarity, segmentPolarity } = stegoLayout(cellCount, key);
  const cw = w / gx, ch = h / gy;
  const fractions = searchOffsets ? [-0.25, -0.125, 0, 0.125, 0.25] : [0];

  const evaluate = (fx, fy) => {
    const dx = fx * cw, dy = fy * ch;
    const bitScores = new Float64Array(64);
    const bitCounts = new Uint16Array(64);
    const cellScores = [];
    for (let cy = 0; cy < gy; cy++) {
      const y0 = Math.max(0, Math.round(cy * ch + dy));
      const y1 = Math.min(h, Math.round((cy + 1) * ch + dy));
      for (let cx = 0; cx < gx; cx++) {
        const x0 = Math.max(0, Math.round(cx * cw + dx));
        const x1 = Math.min(w, Math.round((cx + 1) * cw + dx));
        if (x1 - x0 < 4 || y1 - y0 < 2) continue;
        const sums = new Float64Array(STEGO_ROW_SEGMENTS * 4);
        const counts = new Uint32Array(STEGO_ROW_SEGMENTS * 4);
        const cellW = x1 - x0;
        const cellH = y1 - y0;
        const step = Math.max(1, Math.floor(Math.min(cellW, cellH) / 12));
        for (let y = y0; y < y1; y += step) {
          const segment = Math.min(
            STEGO_ROW_SEGMENTS - 1,
            Math.floor(((y - y0) * STEGO_ROW_SEGMENTS) / cellH),
          );
          let i = (y * w + x0) * 4;
          for (let x = x0; x < x1; x += step, i += step * 4) {
            const band = Math.min(3, Math.floor(((x - x0) * 4) / cellW));
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
        const cellIndex = cy * gx + cx;
        for (let segment = 0; segment < STEGO_ROW_SEGMENTS; segment++) {
          const base = segment * 4;
          if (counts[base] === 0 || counts[base + 1] === 0 || counts[base + 2] === 0 || counts[base + 3] === 0) continue;
          const m0 = sums[base] / counts[base];
          const m1 = sums[base + 1] / counts[base + 1];
          const m2 = sums[base + 2] / counts[base + 2];
          const m3 = sums[base + 3] / counts[base + 3];
          const weight = Math.min(counts[base], counts[base + 1], counts[base + 2], counts[base + 3]);
          segmentScoreSum += (-(-m0 + 3 * m1 - 3 * m2 + m3) / 8) *
            polarity[cellIndex] * segmentPolarity[cellIndex * STEGO_ROW_SEGMENTS + segment] * weight;
          segmentWeightSum += weight;
        }
        if (!segmentWeightSum) continue;
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
    return {
      found: crcValid && agreement >= 0.72 && meanAbs >= 1.2,
      fingerprint,
      crcValid,
      corrections: Math.max(0, corrected.corrections),
      confidence: Math.round(confidence * 1000) / 1000,
      agreement: Math.round(agreement * 1000) / 1000,
      meanSignal: Math.round(meanAbs * 100) / 100,
      cells: cellScores.length,
      offset: { x: fx, y: fy },
      grid: { x: gx, y: gy },
      _evidence: evidence,
    };
  };

  let best = null;
  for (const fx of fractions) for (const fy of fractions) {
    const candidate = evaluate(fx, fy);
    const better = !best ||
      (candidate.found && !best.found) ||
      (candidate.found === best.found && candidate._evidence > best._evidence) ||
      (candidate.found === best.found && candidate._evidence === best._evidence && candidate.confidence > best.confidence);
    if (better) best = candidate;
    if (best.found && best.confidence >= 0.92 && fx === 0 && fy === 0) break;
  }
  if (best) delete best._evidence;
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
