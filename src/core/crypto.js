/**
 * Synchronous cryptographic primitives: seeded PRNGs, portable
 * SHA-256/HMAC (with an injectable hardware fast path), and the
 * WebCrypto AES-256-GCM payload seal. Isomorphic (browser + Node).
 */
import { asBytes, utf8Encode, base64ToBytes, bytesToBase64 } from './bytes.js';


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
 * sfc32 seeded from the first 128 bits of SHA-256(seedString), warmed
 * for 12 rounds so the early outputs are fully diffused. Used by the
 * v3 stego-layout / forensic-sign derivations (the v2 derivations use
 * cyrb128's 128-bit state directly; v1 is the pre-1.13 32-bit path).
 */
export function sha256SeededPrng(seedString) {
  const digest = sha256Bytes(utf8Encode(String(seedString)));
  const view = new DataView(digest.buffer, digest.byteOffset, 16);
  const rand = sfc32(
    view.getUint32(0, false), view.getUint32(4, false),
    view.getUint32(8, false), view.getUint32(12, false),
  );
  for (let i = 0; i < 12; i++) rand();
  return rand;
}


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

let syncCryptoImpl = null;
/**
 * Inject synchronous SHA-256/HMAC-SHA256 implementations (Node hosts
 * pass node:crypto — see server/node-crypto.js). The detector's
 * bit-repair loop verifies up to ~20k HMACs per probe and layout
 * derivation hashes constantly; hardware SHA beats the portable
 * pure-JS fallback ~3x there. Implementations MUST be exact
 * FIPS 180-4 / RFC 2104 — outputs feed key derivation and tag checks.
 * Pass null to restore the built-in implementations.
 */
export function useSyncCrypto(impl) {
  syncCryptoImpl = impl && typeof impl.sha256 === 'function' && typeof impl.hmacSha256 === 'function'
    ? impl
    : null;
}

export function sha256Bytes(message) {
  if (syncCryptoImpl) return syncCryptoImpl.sha256(asBytes(message));
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
  if (syncCryptoImpl) return syncCryptoImpl.hmacSha256(asBytes(key), asBytes(message));
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


// The browser client captures SubtleCrypto methods at load and injects
// them here (mirroring useJsonParser) so a SubtleCrypto hook installed
// later cannot skim keys/plaintext: calls go through the captured
// prototype methods with the captured subtle object as receiver.
let coreWebCrypto = null; // { subtle, importKey?, encrypt?, decrypt?, digest?, getRandomValues? }
const keyCache = new Map(); // base64 key -> Promise<CryptoKey>; deliberately small and LRU-bounded
const AES_KEY_CACHE_MAX = 16;

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
