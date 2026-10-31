var __typeError = (msg) => {
  throw TypeError(msg);
};
var __accessCheck = (obj, member, msg) => member.has(obj) || __typeError("Cannot " + msg);
var __privateGet = (obj, member, getter) => (__accessCheck(obj, member, "read from private field"), getter ? getter.call(obj) : member.get(obj));
var __privateAdd = (obj, member, value) => member.has(obj) ? __typeError("Cannot add the same private member more than once") : member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
var __privateSet = (obj, member, value, setter) => (__accessCheck(obj, member, "write to private field"), setter ? setter.call(obj, value) : member.set(obj, value), value);
var __privateMethod = (obj, member, method) => (__accessCheck(obj, member, "access private method"), method);
var __privateWrapper = (obj, member, setter, getter) => ({
  set _(value) {
    __privateSet(obj, member, value, setter);
  },
  get _() {
    return __privateGet(obj, member, getter);
  }
});

// src/core/bytes.js
function asBytes(bytes) {
  if (bytes instanceof Uint8Array) return bytes;
  if (bytes instanceof ArrayBuffer) return new Uint8Array(bytes);
  if (ArrayBuffer.isView(bytes)) return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return new Uint8Array(bytes || []);
}
var utf8Encoder = new TextEncoder();
var utf8Fatal = new TextDecoder("utf-8", { fatal: true });
var utf8Lenient = new TextDecoder("utf-8", { fatal: false });
var textDecodeCall = TextDecoder.prototype.decode;
var textEncodeCall = TextEncoder.prototype.encode;
function utf8Encode(str) {
  return textEncodeCall.call(utf8Encoder, str);
}
function utf8DecodeFatal(bytes) {
  return textDecodeCall.call(utf8Fatal, bytes);
}
function bytesToBase64(bytes) {
  const u8 = asBytes(bytes);
  if (typeof Buffer !== "undefined") return Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength).toString("base64");
  if (typeof u8.toBase64 === "function") return u8.toBase64();
  let bin = "";
  const CHUNK = 32768;
  for (let i = 0; i < u8.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}
function base64ToBytes(b64) {
  if (typeof b64 !== "string") throw new TypeError("Archx: base64 value must be a string");
  let normalized = b64.replace(/\s+/g, "").replace(/-/g, "+").replace(/_/g, "/");
  const padding = normalized.endsWith("==") ? 2 : normalized.endsWith("=") ? 1 : 0;
  if (normalized.includes("=") && normalized.indexOf("=") !== normalized.length - padding) {
    throw new Error("Archx: invalid base64 value");
  }
  if (normalized.length % 4 === 1 || !/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
    throw new Error("Archx: invalid base64 value");
  }
  if (normalized.length % 4) normalized += "=".repeat(4 - normalized.length % 4);
  if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(normalized, "base64"));
  if (typeof Uint8Array.fromBase64 === "function") return Uint8Array.fromBase64(normalized);
  const bin = atob(normalized);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// src/core/crypto.js
function hashSeed(str, seed = 0) {
  let h1 = 3735928559 ^ seed;
  let h2 = 1103547991 ^ seed;
  const s = String(str);
  for (let i = 0, ch; i < s.length; i++) {
    ch = s.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ h1 >>> 16, 2246822507) ^ Math.imul(h2 ^ h2 >>> 13, 3266489909);
  h2 = Math.imul(h2 ^ h2 >>> 16, 2246822507) ^ Math.imul(h1 ^ h1 >>> 13, 3266489909);
  return 4294967296 * (2097151 & h2) + (h1 >>> 0);
}
function mulberry32(seed) {
  let a = seed >>> 0;
  return function next() {
    a |= 0;
    a = a + 1831565813 | 0;
    let t = Math.imul(a ^ a >>> 15, 1 | a);
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };
}
function cyrb128(str) {
  const s = String(str);
  let h1 = 1779033703, h2 = 3144134277, h3 = 1013904242, h4 = 2773480762;
  for (let i = 0, k; i < s.length; i++) {
    k = s.charCodeAt(i);
    h1 = h2 ^ Math.imul(h1 ^ k, 597399067);
    h2 = h3 ^ Math.imul(h2 ^ k, 2869860233);
    h3 = h4 ^ Math.imul(h3 ^ k, 951274213);
    h4 = h1 ^ Math.imul(h4 ^ k, 2716044179);
  }
  h1 = Math.imul(h3 ^ h1 >>> 18, 597399067);
  h2 = Math.imul(h4 ^ h2 >>> 22, 2869860233);
  h3 = Math.imul(h1 ^ h3 >>> 17, 951274213);
  h4 = Math.imul(h2 ^ h4 >>> 19, 2716044179);
  return [(h1 ^ h2 ^ h3 ^ h4) >>> 0, (h2 ^ h1) >>> 0, (h3 ^ h1) >>> 0, (h4 ^ h1) >>> 0];
}
function sfc32(a, b, c, d) {
  return function next() {
    a >>>= 0;
    b >>>= 0;
    c >>>= 0;
    d >>>= 0;
    let t = (a + b | 0) + d | 0;
    d = d + 1 | 0;
    a = b ^ b >>> 9;
    b = c + (c << 3) | 0;
    c = c << 21 | c >>> 11;
    c = c + t | 0;
    return (t >>> 0) / 4294967296;
  };
}
function sha256SeededPrng(seedString) {
  const digest = sha256Bytes(utf8Encode(String(seedString)));
  const view = new DataView(digest.buffer, digest.byteOffset, 16);
  const rand = sfc32(
    view.getUint32(0, false),
    view.getUint32(4, false),
    view.getUint32(8, false),
    view.getUint32(12, false)
  );
  for (let i = 0; i < 12; i++) rand();
  return rand;
}
var SHA256_K = new Uint32Array([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]);
var syncCryptoImpl = null;
function useSyncCrypto(impl) {
  syncCryptoImpl = impl && typeof impl.sha256 === "function" && typeof impl.hmacSha256 === "function" ? impl : null;
}
function sha256Bytes(message) {
  if (syncCryptoImpl) return syncCryptoImpl.sha256(asBytes(message));
  const msg = asBytes(message);
  const bitLenHi = Math.floor(msg.length / 536870912);
  const bitLenLo = msg.length << 3;
  const paddedLen = msg.length + 9 + 63 >> 6 << 6;
  const buf = new Uint8Array(paddedLen);
  buf.set(msg, 0);
  buf[msg.length] = 128;
  const dv = new DataView(buf.buffer);
  dv.setUint32(paddedLen - 4, bitLenLo >>> 0, false);
  dv.setUint32(paddedLen - 8, bitLenHi >>> 0, false);
  let h0 = 1779033703, h1 = 3144134277, h2 = 1013904242, h3 = 2773480762;
  let h4 = 1359893119, h5 = 2600822924, h6 = 528734635, h7 = 1541459225;
  const w = new Uint32Array(64);
  const rotr = (x, n) => x >>> n | x << 32 - n;
  for (let block = 0; block < paddedLen; block += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(block + t * 4, false);
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ w[t - 15] >>> 3;
      const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ w[t - 2] >>> 10;
      w[t] = w[t - 16] + s0 + w[t - 7] + s1 >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
    for (let t = 0; t < 64; t++) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = e & f ^ ~e & g;
      const temp1 = hh + s1 + ch + SHA256_K[t] + w[t] >>> 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = a & b ^ a & c ^ b & c;
      const temp2 = s0 + maj >>> 0;
      hh = g;
      g = f;
      f = e;
      e = d + temp1 >>> 0;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2 >>> 0;
    }
    h0 = h0 + a >>> 0;
    h1 = h1 + b >>> 0;
    h2 = h2 + c >>> 0;
    h3 = h3 + d >>> 0;
    h4 = h4 + e >>> 0;
    h5 = h5 + f >>> 0;
    h6 = h6 + g >>> 0;
    h7 = h7 + hh >>> 0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  [h0, h1, h2, h3, h4, h5, h6, h7].forEach((word, i) => odv.setUint32(i * 4, word, false));
  return out;
}
function hmacSha256Bytes(key, message) {
  if (syncCryptoImpl) return syncCryptoImpl.hmacSha256(asBytes(key), asBytes(message));
  let keyBytes = asBytes(key);
  if (keyBytes.length > 64) keyBytes = sha256Bytes(keyBytes);
  const inner = new Uint8Array(64 + asBytes(message).length);
  const outer = new Uint8Array(64 + 32);
  for (let i = 0; i < 64; i++) {
    const kb = i < keyBytes.length ? keyBytes[i] : 0;
    inner[i] = kb ^ 54;
    outer[i] = kb ^ 92;
  }
  inner.set(asBytes(message), 64);
  outer.set(sha256Bytes(inner), 64);
  return sha256Bytes(outer);
}
var coreWebCrypto = null;
var keyCache = /* @__PURE__ */ new Map();
var AES_KEY_CACHE_MAX = 16;
function useWebCrypto(injected) {
  if (!injected || typeof injected !== "object" || !injected.subtle) {
    coreWebCrypto = null;
  } else {
    coreWebCrypto = {
      subtle: injected.subtle,
      importKey: typeof injected.importKey === "function" ? injected.importKey : null,
      encrypt: typeof injected.encrypt === "function" ? injected.encrypt : null,
      decrypt: typeof injected.decrypt === "function" ? injected.decrypt : null,
      digest: typeof injected.digest === "function" ? injected.digest : null,
      getRandomValues: typeof injected.getRandomValues === "function" ? injected.getRandomValues : null,
      cryptoObj: injected.cryptoObj || null
    };
  }
  keyCache.clear();
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
  if (typeof keyBase64 !== "string" || !keyBase64) throw new TypeError("Archx: AES key must be a base64 string");
  const cached = keyCache.get(keyBase64);
  if (cached) {
    keyCache.delete(keyBase64);
    keyCache.set(keyBase64, cached);
    return cached;
  }
  const pending = (async () => {
    const raw = base64ToBytes(keyBase64);
    try {
      if (![16, 24, 32].includes(raw.length)) {
        throw new Error("Archx: AES key must be 16/24/32 bytes (base64)");
      }
      return await subtleCall("importKey", [
        "raw",
        raw,
        { name: "AES-GCM", length: raw.length * 8 },
        false,
        ["encrypt", "decrypt"]
      ]);
    } finally {
      raw.fill(0);
    }
  })();
  keyCache.set(keyBase64, pending);
  while (keyCache.size > AES_KEY_CACHE_MAX) keyCache.delete(keyCache.keys().next().value);
  try {
    return await pending;
  } catch (err) {
    if (keyCache.get(keyBase64) === pending) keyCache.delete(keyBase64);
    throw err;
  }
}
function generateKeyBase64() {
  const raw = new Uint8Array(32);
  randomFill(raw);
  const encoded = bytesToBase64(raw);
  raw.fill(0);
  return encoded;
}
async function encryptPayload(plainBytes, keyBase64) {
  const key = await importAesKey(keyBase64);
  const iv = new Uint8Array(12);
  randomFill(iv);
  const cipher = await subtleCall("encrypt", [
    { name: "AES-GCM", iv },
    key,
    asBytes(plainBytes)
  ]);
  return { cipher: new Uint8Array(cipher), iv: bytesToBase64(iv) };
}
async function decryptPayload(cipherBytes, keyBase64, ivBase64) {
  const cipher = asBytes(cipherBytes);
  const iv = base64ToBytes(ivBase64);
  if (iv.length !== 12) throw new Error("Archx: AES-GCM IV must be 12 bytes");
  if (cipher.length < 17) throw new Error("Archx: AES-GCM payload is too short");
  const key = await importAesKey(keyBase64);
  const plain = await subtleCall("decrypt", [
    { name: "AES-GCM", iv },
    key,
    cipher
  ]);
  return new Uint8Array(plain);
}

// src/core/plan.js
var DEFAULT_GRID = 8;
function buildScramblePlan(grid = DEFAULT_GRID, key = "", version = 2) {
  if (version !== 1 && version !== 2) throw new TypeError("Archx: scramble plan version must be 1 or 2");
  const g = Math.max(2, Math.min(32, grid | 0));
  const count = g * g;
  let rand;
  if (version === 2) {
    rand = sfc32(...cyrb128(String(key) + "::archx-grid2-" + g));
    for (let i = 0; i < 8; i++) rand();
  } else {
    rand = mulberry32(hashSeed(String(key) + "::archx-grid-" + g));
  }
  const order = Array.from({ length: count }, (_, i) => i);
  for (let i = count - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }
  const flips = Array.from({ length: count }, () => ({
    fx: rand() < 0.5,
    fy: rand() < 0.5
  }));
  const inverse = new Array(count);
  order.forEach((orig, scrambledPos) => {
    inverse[orig] = scrambledPos;
  });
  return { grid: g, count, version, order, inverse, flips };
}
function tileRect(index, grid, tw, th) {
  return { x: index % grid * tw, y: Math.floor(index / grid) * th, w: tw, h: th };
}
function paddedSize(w, h, grid) {
  if (!Number.isInteger(w) || !Number.isInteger(h) || w < 1 || h < 1 || !Number.isInteger(grid) || grid < 2 || grid > 32) {
    throw new RangeError("Archx: invalid image/grid dimensions");
  }
  const tw = Math.ceil(w / grid);
  const th = Math.ceil(h / grid);
  return { tw, th, pw: tw * grid, ph: th * grid };
}
function scramblePixels(rgba, pw, ph, plan, direction = "scramble") {
  if (direction !== "scramble" && direction !== "unscramble") {
    throw new TypeError("Archx: scramble direction is invalid");
  }
  const grid = plan?.grid;
  const count = plan?.count;
  if (!Number.isSafeInteger(pw) || !Number.isSafeInteger(ph) || pw < 1 || ph < 1 || !Number.isInteger(grid) || grid < 2 || grid > 32 || count !== grid * grid || pw % grid !== 0 || ph % grid !== 0 || !Array.isArray(plan.order) || !Array.isArray(plan.inverse) || !Array.isArray(plan.flips) || plan.order.length !== count || plan.inverse.length !== count || plan.flips.length !== count) {
    throw new RangeError("Archx: invalid scramble geometry");
  }
  const tw = pw / grid;
  const th = ph / grid;
  const src = asBytes(rgba);
  const expected = pw * ph * 4;
  if (!Number.isSafeInteger(expected) || src.length < expected) {
    throw new RangeError("Archx: RGBA buffer is smaller than the padded image");
  }
  const out = new Uint8Array(expected);
  const useWords = src.byteOffset % 4 === 0 && src.byteLength % 4 === 0;
  const src32 = useWords ? new Uint32Array(src.buffer, src.byteOffset, src.byteLength / 4) : null;
  const out32 = useWords ? new Uint32Array(out.buffer) : null;
  for (let dest = 0; dest < count; dest++) {
    const source = direction === "scramble" ? plan.order[dest] : plan.inverse[dest];
    if (!Number.isInteger(source) || source < 0 || source >= count) {
      throw new RangeError("Archx: invalid scramble plan");
    }
    const flipPos = direction === "scramble" ? dest : source;
    const flip = plan.flips[flipPos];
    if (!flip || typeof flip !== "object") throw new RangeError("Archx: invalid scramble plan");
    const { fx, fy } = flip;
    const sx = source % grid * tw;
    const sy = Math.floor(source / grid) * th;
    const dx = dest % grid * tw;
    const dy = Math.floor(dest / grid) * th;
    for (let y = 0; y < th; y++) {
      const yy = fy ? th - 1 - y : y;
      const srcRow = (sy + yy) * pw + sx;
      const dstRow = (dy + y) * pw + dx;
      if (useWords && !fx) {
        out32.set(src32.subarray(srcRow, srcRow + tw), dstRow);
      } else if (useWords) {
        out32.set(src32.subarray(srcRow, srcRow + tw), dstRow);
        out32.subarray(dstRow, dstRow + tw).reverse();
      } else {
        for (let x = 0; x < tw; x++) {
          const xx = fx ? tw - 1 - x : x;
          const si = (srcRow + xx) * 4;
          const di = (dstRow + x) * 4;
          out[di] = src[si];
          out[di + 1] = src[si + 1];
          out[di + 2] = src[si + 2];
          out[di + 3] = src[si + 3];
        }
      }
    }
  }
  return out;
}
function scramblePixelsPadded(rgba, w, h, plan, out = null) {
  const grid = plan?.grid;
  const count = plan?.count;
  if (!Number.isSafeInteger(w) || !Number.isSafeInteger(h) || w < 1 || h < 1 || !Number.isInteger(grid) || grid < 2 || grid > 32 || count !== grid * grid || !Array.isArray(plan.order) || !Array.isArray(plan.flips) || plan.order.length !== count || plan.flips.length !== count) {
    throw new RangeError("Archx: invalid scramble geometry");
  }
  const tw = Math.ceil(w / grid);
  const th = Math.ceil(h / grid);
  const pw = tw * grid;
  const ph = th * grid;
  const src = asBytes(rgba);
  if (!Number.isSafeInteger(w * h * 4) || src.length < w * h * 4) {
    throw new RangeError("Archx: RGBA buffer is smaller than the image");
  }
  const expected = pw * ph * 4;
  const target = out ? asBytes(out) : new Uint8Array(expected);
  if (!Number.isSafeInteger(expected) || target.length < expected) {
    throw new RangeError("Archx: scramble output buffer is too small");
  }
  const useWords = src.byteOffset % 4 === 0 && src.byteLength % 4 === 0 && target.byteOffset % 4 === 0 && target.byteLength % 4 === 0;
  const src32 = useWords ? new Uint32Array(src.buffer, src.byteOffset, src.byteLength / 4) : null;
  const out32 = useWords ? new Uint32Array(target.buffer, target.byteOffset, target.byteLength / 4) : null;
  let padSeedState = 2654435769;
  for (let i = 0; i < count; i++) {
    padSeedState = Math.imul(padSeedState ^ plan.order[i] * 2654435761, 2246822519);
    padSeedState = Math.imul(padSeedState ^ (plan.flips[i].fx ? 2 : 0) + (plan.flips[i].fy ? 1 : 0) + 1, 3266489917);
  }
  const padRand = mulberry32(padSeedState >>> 0);
  let padShiftY = h > 3 ? 1 + Math.floor(padRand() * (h - 2)) : 0;
  let padShiftX = w > 3 ? 1 + Math.floor(padRand() * (w - 2)) : 0;
  if (h > 8 && w > 4) {
    let best = padShiftY, bestScore = Infinity;
    for (let c = 0; c < 24; c++) {
      const cand = 1 + Math.floor(padRand() * (h - 2));
      let ma0 = 0, ma1 = 0, ma2 = 0, mb0 = 0, mb1 = 0, mb2 = 0, n = 0;
      for (let x = 0; x < w; x += 3) {
        const a = ((h - 1) * w + x) * 4, b = (cand * w + x) * 4;
        ma0 += src[a];
        ma1 += src[a + 1];
        ma2 += src[a + 2];
        mb0 += src[b];
        mb1 += src[b + 1];
        mb2 += src[b + 2];
        n++;
      }
      ma0 /= n;
      ma1 /= n;
      ma2 /= n;
      mb0 /= n;
      mb1 /= n;
      mb2 /= n;
      let s = 0;
      for (let x = 0; x < w; x += 3) {
        const a = ((h - 1) * w + x) * 4, b = (cand * w + x) * 4;
        s += Math.abs(src[a] - ma0 - (src[b] - mb0)) + Math.abs(src[a + 1] - ma1 - (src[b + 1] - mb1)) + Math.abs(src[a + 2] - ma2 - (src[b + 2] - mb2));
      }
      const score = s / (3 * n);
      if (score < bestScore) {
        bestScore = score;
        best = cand;
      }
    }
    padShiftY = best;
  }
  if (w > 8 && h > 4) {
    let best = padShiftX, bestScore = Infinity;
    for (let c = 0; c < 24; c++) {
      const cand = 1 + Math.floor(padRand() * (w - 2));
      let ma0 = 0, ma1 = 0, ma2 = 0, mb0 = 0, mb1 = 0, mb2 = 0, n = 0;
      for (let y = 0; y < h; y += 3) {
        const a = (y * w + w - 1) * 4, b = (y * w + cand) * 4;
        ma0 += src[a];
        ma1 += src[a + 1];
        ma2 += src[a + 2];
        mb0 += src[b];
        mb1 += src[b + 1];
        mb2 += src[b + 2];
        n++;
      }
      ma0 /= n;
      ma1 /= n;
      ma2 /= n;
      mb0 /= n;
      mb1 /= n;
      mb2 /= n;
      let s = 0;
      for (let y = 0; y < h; y += 3) {
        const a = (y * w + w - 1) * 4, b = (y * w + cand) * 4;
        s += Math.abs(src[a] - ma0 - (src[b] - mb0)) + Math.abs(src[a + 1] - ma1 - (src[b + 1] - mb1)) + Math.abs(src[a + 2] - ma2 - (src[b + 2] - mb2));
      }
      const score = s / (3 * n);
      if (score < bestScore) {
        bestScore = score;
        best = cand;
      }
    }
    padShiftX = best;
  }
  const padPhaseSeed = Math.floor(padRand() * 4294967295) | 0;
  const wrapPos = (c, n) => (c % n + n) % n;
  const PAD_NOISE_LUT = [-3, -2, -1, 1, 2, 3];
  const padNoise = (gx, gy, channel) => {
    let hash = padPhaseSeed ^ Math.imul((gx >> 3) + 1, 374761393) ^ Math.imul((gy >> 3) + 1, 668265263) ^ Math.imul(channel + 1, 2246822519) | 0;
    hash = Math.imul(hash ^ hash >>> 13, 1274126177);
    return PAD_NOISE_LUT[(hash >>> 16) % 6];
  };
  const ANCHOR_R = 16;
  const rowPrefixCache = /* @__PURE__ */ new Map();
  const colPrefixCache = /* @__PURE__ */ new Map();
  const rowPrefix = (y) => {
    let p = rowPrefixCache.get(y);
    if (!p) {
      p = new Float64Array(3 * (w + 1));
      const base = y * w * 4;
      for (let x = 0; x < w; x++) {
        const si = base + x * 4;
        p[x + 1] = p[x] + src[si];
        p[w + 1 + x + 1] = p[w + 1 + x] + src[si + 1];
        p[2 * (w + 1) + x + 1] = p[2 * (w + 1) + x] + src[si + 2];
      }
      rowPrefixCache.set(y, p);
    }
    return p;
  };
  const colPrefix = (x) => {
    let p = colPrefixCache.get(x);
    if (!p) {
      p = new Float64Array(3 * (h + 1));
      for (let y = 0; y < h; y++) {
        const si = (y * w + x) * 4;
        p[y + 1] = p[y] + src[si];
        p[h + 1 + y + 1] = p[h + 1 + y] + src[si + 1];
        p[2 * (h + 1) + y + 1] = p[2 * (h + 1) + y] + src[si + 2];
      }
      colPrefixCache.set(x, p);
    }
    return p;
  };
  const _boxA = [0, 0, 0];
  const _boxB = [0, 0, 0];
  const rowBox = (y, cx, out2) => {
    const p = rowPrefix(y);
    const x0 = Math.max(0, cx - ANCHOR_R), x1 = Math.min(w, cx + ANCHOR_R + 1);
    const n = Math.max(1, x1 - x0);
    out2[0] = (p[x1] - p[x0]) / n;
    out2[1] = (p[w + 1 + x1] - p[w + 1 + x0]) / n;
    out2[2] = (p[2 * (w + 1) + x1] - p[2 * (w + 1) + x0]) / n;
  };
  const colBox = (x, cy, out2) => {
    const p = colPrefix(x);
    const y0 = Math.max(0, cy - ANCHOR_R), y1 = Math.min(h, cy + ANCHOR_R + 1);
    const n = Math.max(1, y1 - y0);
    out2[0] = (p[y1] - p[y0]) / n;
    out2[1] = (p[h + 1 + y1] - p[h + 1 + y0]) / n;
    out2[2] = (p[2 * (h + 1) + y1] - p[2 * (h + 1) + y0]) / n;
  };
  const writePixel = (di, si) => {
    target[di] = src[si];
    target[di + 1] = src[si + 1];
    target[di + 2] = src[si + 2];
    target[di + 3] = src[si + 3];
  };
  const PAD_FEATHER = [0.45, 0.3, 0.15];
  const writePadPixel = (di, srcX, srcY, rawX, rawY) => {
    const si = (srcY * w + srcX) * 4;
    let fade = 0, edgeSi = -1;
    if (rawY >= h) {
      rowBox(h - 1, srcX, _boxA);
      rowBox(srcY, srcX, _boxB);
      const d = rawY - h;
      if (d < 3) {
        fade = PAD_FEATHER[d];
        edgeSi = ((h - 1) * w + srcX) * 4;
      }
    } else {
      colBox(w - 1, rawY, _boxA);
      colBox(srcX, rawY, _boxB);
      const d = rawX - w;
      if (d < 3) {
        fade = PAD_FEATHER[d];
        edgeSi = (rawY * w + w - 1) * 4;
      }
    }
    for (let c = 0; c < 3; c++) {
      let v = src[si + c] + Math.round(_boxA[c] - _boxB[c]);
      if (fade) v = v * (1 - fade) + src[edgeSi + c] * fade;
      target[di + c] = Math.max(0, Math.min(255, Math.round(v) + padNoise(rawX, rawY, c)));
    }
    target[di + 3] = src[si + 3];
  };
  for (let dest = 0; dest < count; dest++) {
    const source = plan.order[dest];
    if (!Number.isInteger(source) || source < 0 || source >= count) {
      throw new RangeError("Archx: invalid scramble plan");
    }
    const flip = plan.flips[dest];
    if (!flip || typeof flip !== "object") throw new RangeError("Archx: invalid scramble plan");
    const { fx, fy } = flip;
    const sx = source % grid * tw;
    const sy = Math.floor(source / grid) * th;
    const dx = dest % grid * tw;
    const dy = Math.floor(dest / grid) * th;
    for (let y = 0; y < th; y++) {
      const rawY = sy + (fy ? th - 1 - y : y);
      const rowIsPad = rawY >= h;
      const srcY = rowIsPad ? wrapPos(padShiftY + (rawY - h), h) : rawY;
      const dstRow = (dy + y) * pw + dx;
      if (useWords && !fx && !rowIsPad) {
        const avail = Math.max(0, Math.min(tw, w - sx));
        if (avail > 0) out32.set(src32.subarray(srcY * w + sx, srcY * w + sx + avail), dstRow);
        for (let x = avail; x < tw; x++) {
          const rawX = sx + x;
          const srcX = wrapPos(padShiftX + (rawX - w), w);
          writePadPixel((dstRow + x) * 4, srcX, srcY, rawX, rawY);
        }
      } else if (useWords && !rowIsPad && !(sx + tw > w)) {
        out32.set(src32.subarray(srcY * w + sx, srcY * w + sx + tw), dstRow);
        out32.subarray(dstRow, dstRow + tw).reverse();
      } else {
        for (let x = 0; x < tw; x++) {
          const rawX = sx + (fx ? tw - 1 - x : x);
          const colIsPad = rawX >= w;
          const srcX = colIsPad ? wrapPos(padShiftX + (rawX - w), w) : rawX;
          if (rowIsPad || colIsPad) {
            writePadPixel((dstRow + x) * 4, srcX, srcY, rawX, rawY);
          } else {
            writePixel((dstRow + x) * 4, (srcY * w + srcX) * 4);
          }
        }
      }
    }
  }
  return target;
}

// src/core/sniff.js
var IMAGE_FORMAT_MIME = Object.freeze({
  jpeg: "image/jpeg",
  png: "image/png",
  webp: "image/webp",
  avif: "image/avif",
  gif: "image/gif",
  bmp: "image/bmp",
  tiff: "image/tiff",
  svg: "image/svg+xml"
});
function readU16LE(u8, off) {
  return u8[off] | u8[off + 1] << 8;
}
function readU16BE(u8, off) {
  return u8[off] << 8 | u8[off + 1];
}
function readU32LE(u8, off) {
  return (u8[off] | u8[off + 1] << 8 | u8[off + 2] << 16 | u8[off + 3] << 24) >>> 0;
}
function readU32BE(u8, off) {
  return (u8[off] << 24 | u8[off + 1] << 16 | u8[off + 2] << 8 | u8[off + 3]) >>> 0;
}
function asciiAt(u8, off, text) {
  if (off < 0 || off + text.length > u8.length) return false;
  for (let i = 0; i < text.length; i++) if (u8[off + i] !== text.charCodeAt(i)) return false;
  return true;
}
function avifDimensions(u8) {
  const containers = /* @__PURE__ */ new Set(["meta", "iprp", "ipco"]);
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
        size = big;
        header = 16;
      } else if (size === 0) size = end - off;
      if (size < header || off + size > end) return null;
      const payload = off + header;
      if (type === "ispe" && size >= header + 12) {
        const width = readU32BE(u8, payload + 4);
        const height = readU32BE(u8, payload + 8);
        if (width > 0 && height > 0) return { width, height };
      }
      if (depth < 5 && containers.has(type)) {
        const childStart = type === "meta" ? payload + 4 : payload;
        const found = walk(childStart, off + size, depth + 1);
        if (found) return found;
      }
      off += size;
    }
    return null;
  };
  return walk(0, u8.length, 0);
}
function sniffImageInfo(bytes) {
  const u8 = asBytes(bytes);
  const done = (format, width = null, height = null) => Object.freeze({
    format,
    mime: IMAGE_FORMAT_MIME[format] || "",
    width,
    height
  });
  if (u8.length >= 24 && u8[0] === 137 && asciiAt(u8, 1, "PNG") && u8[4] === 13 && u8[5] === 10) {
    return done("png", readU32BE(u8, 16), readU32BE(u8, 20));
  }
  if (u8.length >= 3 && u8[0] === 255 && u8[1] === 216 && u8[2] === 255) {
    let off = 2;
    const sof = /* @__PURE__ */ new Set([192, 193, 194, 195, 197, 198, 199, 201, 202, 203, 205, 206, 207]);
    while (off + 4 <= u8.length) {
      if (u8[off] !== 255) {
        off++;
        continue;
      }
      let markerAt = off + 1;
      while (markerAt < u8.length && u8[markerAt] === 255) markerAt++;
      if (markerAt >= u8.length) break;
      const marker = u8[markerAt];
      if (marker === 216 || marker === 1 || marker >= 208 && marker <= 215) {
        off = markerAt + 1;
        continue;
      }
      if (marker === 218 || markerAt + 3 > u8.length) break;
      const len = readU16BE(u8, markerAt + 1);
      if (len < 2) break;
      if (sof.has(marker) && len >= 7 && markerAt + 8 <= u8.length) {
        return done("jpeg", readU16BE(u8, markerAt + 6), readU16BE(u8, markerAt + 4));
      }
      off = markerAt + 1 + len;
    }
    return done("jpeg");
  }
  if (u8.length >= 10 && (asciiAt(u8, 0, "GIF87a") || asciiAt(u8, 0, "GIF89a"))) {
    return done("gif", readU16LE(u8, 6), readU16LE(u8, 8));
  }
  if (u8.length >= 26 && asciiAt(u8, 0, "BM")) {
    const width = readU32LE(u8, 18) | 0;
    const height = Math.abs(readU32LE(u8, 22) | 0);
    return done("bmp", width > 0 ? width : null, height > 0 ? height : null);
  }
  if (u8.length >= 20 && asciiAt(u8, 0, "RIFF") && asciiAt(u8, 8, "WEBP")) {
    if (asciiAt(u8, 12, "VP8X") && u8.length >= 30) {
      return done("webp", 1 + (u8[24] | u8[25] << 8 | u8[26] << 16), 1 + (u8[27] | u8[28] << 8 | u8[29] << 16));
    }
    if (asciiAt(u8, 12, "VP8L") && u8.length >= 25 && u8[20] === 47) {
      const bits = readU32LE(u8, 21);
      return done("webp", (bits & 16383) + 1, (bits >>> 14 & 16383) + 1);
    }
    if (asciiAt(u8, 12, "VP8 ") && u8.length >= 30 && u8[23] === 157 && u8[24] === 1 && u8[25] === 42) {
      return done("webp", readU16LE(u8, 26) & 16383, readU16LE(u8, 28) & 16383);
    }
    return done("webp");
  }
  if (u8.length >= 12 && asciiAt(u8, 4, "ftyp")) {
    let isAvif = false;
    for (let off = 8; off + 4 <= Math.min(u8.length, 64); off += 4) {
      if (asciiAt(u8, off, "avif") || asciiAt(u8, off, "avis")) {
        isAvif = true;
        break;
      }
    }
    if (isAvif) {
      const dims = avifDimensions(u8);
      return done("avif", dims?.width || null, dims?.height || null);
    }
  }
  if (u8.length >= 4 && u8[0] === 73 && u8[1] === 73 && u8[2] === 42 && u8[3] === 0 || u8.length >= 4 && u8[0] === 77 && u8[1] === 77 && u8[2] === 0 && u8[3] === 42) {
    return done("tiff");
  }
  const head = utf8Lenient.decode(u8.subarray(0, Math.min(1024, u8.length))).trimStart().toLowerCase();
  if (head.startsWith("<svg") || head.startsWith("<?xml") && head.includes("<svg")) return done("svg");
  return null;
}
function sniffImageFormat(bytes) {
  return sniffImageInfo(bytes)?.format || null;
}
function decodeBmpImage(bytes, { maxPixels = 1e8 } = {}) {
  if (!Number.isSafeInteger(maxPixels) || maxPixels < 1) {
    throw new RangeError("Archx: BMP pixel limit is invalid");
  }
  const u8 = asBytes(bytes);
  const fail = (message) => {
    throw new TypeError(`Archx: invalid BMP image (${message})`);
  };
  if (u8.length < 54 || u8[0] !== 66 || u8[1] !== 77) fail("missing BM header");
  const view = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  const fileSize = view.getUint32(2, true);
  if (fileSize !== 0 && fileSize > u8.length) fail("declared file size exceeds input");
  const dataOffset = view.getUint32(10, true);
  const dibSize = view.getUint32(14, true);
  if (dibSize < 40 || dibSize > 124 || 14 + dibSize > u8.length) fail("unsupported DIB header");
  if (dataOffset < 14 + dibSize || dataOffset >= u8.length) fail("invalid pixel-data offset");
  const width = view.getInt32(18, true);
  const signedHeight = view.getInt32(22, true);
  const planes = view.getUint16(26, true);
  const bitsPerPixel = view.getUint16(28, true);
  const compression = view.getUint32(30, true);
  const declaredImageSize = view.getUint32(34, true);
  const height = Math.abs(signedHeight);
  if (width <= 0 || height <= 0 || planes !== 1) fail("invalid dimensions/planes");
  if (![24, 32].includes(bitsPerPixel) || compression !== 0) fail("only uncompressed 24/32-bit BI_RGB is supported");
  const pixels = width * height;
  if (!Number.isSafeInteger(pixels) || pixels > maxPixels) fail("pixel limit exceeded");
  const bytesPerPixel = bitsPerPixel / 8;
  const stride = Math.floor((bitsPerPixel * width + 31) / 32) * 4;
  const pixelBytes = stride * height;
  if (!Number.isSafeInteger(pixelBytes) || dataOffset + pixelBytes > u8.length) fail("truncated pixel data");
  if (declaredImageSize !== 0 && declaredImageSize < pixelBytes) fail("declared image size is too small");
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
      data[dest + 3] = bitsPerPixel === 32 && u8[source + 3] !== 0 ? u8[source + 3] : 255;
      source += bytesPerPixel;
      dest += 4;
    }
  }
  return Object.freeze({ data, width, height, channels: 4 });
}

// src/core/container.js
var ARCHX_MAGIC = "ARCHX1";
var MAX_ARCHX_HEADER_BYTES = 16384;
var ARCHX_MAGIC_BYTES = Object.freeze([...ARCHX_MAGIC].map((c) => c.charCodeAt(0)));
var ARCHX_HEADER_FIELDS = /* @__PURE__ */ new Set([
  "v",
  "w",
  "h",
  "pw",
  "ph",
  "grid",
  "mime",
  "scrambled",
  "encrypted",
  "iv",
  "wm",
  "fx",
  "sg",
  "pv"
]);
var ARCHX_MIME_FORMATS = Object.freeze({
  "image/webp": "webp",
  "image/png": "png",
  "image/jpeg": "jpeg",
  "image/avif": "avif"
});
function validateArchxHeader(header) {
  const fail = (message) => {
    throw new Error(`Archx: invalid .archx header (${message})`);
  };
  if (!header || typeof header !== "object" || Array.isArray(header)) fail("not an object");
  for (const field of Object.keys(header)) if (!ARCHX_HEADER_FIELDS.has(field)) fail(`unknown field ${field}`);
  if (header.v !== 1) fail("unsupported version");
  for (const field of ["w", "h", "pw", "ph"]) {
    if (!Number.isSafeInteger(header[field]) || header[field] < 1 || header[field] > 65536) fail(`bad ${field}`);
  }
  if (!Number.isInteger(header.grid) || header.grid < 2 || header.grid > 32) fail("bad grid");
  if (header.pv !== void 0 && header.pv !== 1 && header.pv !== 2) fail("bad plan version");
  const padded = paddedSize(header.w, header.h, header.grid);
  if (header.pw !== padded.pw || header.ph !== padded.ph) fail("padded dimensions do not match");
  if (!ARCHX_MIME_FORMATS[header.mime]) fail("unsupported MIME type");
  if (typeof header.scrambled !== "boolean" || typeof header.encrypted !== "boolean") fail("bad flags");
  for (const field of ["wm", "fx", "sg"]) {
    if (header[field] !== void 0 && header[field] !== 0 && header[field] !== 1 && header[field] !== true && header[field] !== false) {
      fail(`bad ${field} flag`);
    }
  }
  if (header.encrypted) {
    if (typeof header.iv !== "string") fail("missing IV");
    try {
      if (base64ToBytes(header.iv).length !== 12) fail("bad IV length");
    } catch (err) {
      if (/invalid \.archx header/.test(err.message)) throw err;
      fail("bad IV encoding");
    }
  } else if (header.iv !== void 0) fail("unexpected IV");
  return header;
}
function encodeContainer(header, payload) {
  validateArchxHeader(header);
  const headerBytes = utf8Encode(JSON.stringify(header));
  if (headerBytes.length > MAX_ARCHX_HEADER_BYTES) throw new Error("Archx: .archx header is too large");
  const body = asBytes(payload);
  if (!body.length) throw new Error("Archx: .archx payload is empty");
  const out = new Uint8Array(6 + 4 + headerBytes.length + body.length);
  out.set(ARCHX_MAGIC_BYTES, 0);
  new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(6, headerBytes.length, false);
  out.set(headerBytes, 10);
  out.set(body, 10 + headerBytes.length);
  return out;
}
function isArchxContainer(bytes) {
  if (!bytes) return false;
  const u8 = asBytes(bytes);
  return u8.length >= 10 && ARCHX_MAGIC_BYTES.every((c, i) => u8[i] === c);
}
var coreJsonParse = null;
function useJsonParser(fn) {
  coreJsonParse = typeof fn === "function" ? fn : null;
}
function decodeContainer(bytes) {
  const u8 = asBytes(bytes);
  if (!isArchxContainer(u8)) throw new Error("Archx: not an .archx container");
  const headerLen = new DataView(u8.buffer, u8.byteOffset, u8.byteLength).getUint32(6, false);
  if (!Number.isSafeInteger(headerLen) || headerLen < 2 || headerLen > MAX_ARCHX_HEADER_BYTES || 10 + headerLen >= u8.length) {
    throw new Error("Archx: invalid .archx header length");
  }
  let header;
  try {
    header = (coreJsonParse || JSON.parse)(utf8DecodeFatal(u8.subarray(10, 10 + headerLen)));
  } catch {
    throw new Error("Archx: invalid .archx header encoding");
  }
  validateArchxHeader(header);
  const payload = u8.subarray(10 + headerLen);
  if (!payload.length) throw new Error("Archx: invalid .archx payload");
  return { header, payload };
}

// src/core/forensic.js
function forensicBlockSigns(seed, count, version = 3) {
  const rand = version === 1 ? mulberry32(hashSeed(String(seed) + "::archx-forensic")) : version === 2 ? sfc32(...cyrb128(String(seed) + "::archx-forensic")) : sha256SeededPrng(String(seed) + "::archx-forensic-v3");
  return Array.from({ length: count }, () => rand() < 0.5 ? -1 : 1);
}
function applyForensicBlocks(rgba, w, h, seed, { blockSize = 32, delta = 2, signsVersion = 3 } = {}) {
  const bs = Math.max(8, blockSize | 0);
  const bx = Math.ceil(w / bs);
  const by = Math.ceil(h / bs);
  const signs = forensicBlockSigns(seed, bx * by, signsVersion === 1 ? 1 : signsVersion === 2 ? 2 : 3);
  const out = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  const lutPos = new Uint8Array(256);
  const lutNeg = new Uint8Array(256);
  for (let v = 0; v < 256; v++) {
    lutPos[v] = Math.max(0, Math.min(255, v + delta));
    lutNeg[v] = Math.max(0, Math.min(255, v - delta));
  }
  for (let byi = 0; byi < by; byi++) {
    for (let bxi = 0; bxi < bx; bxi++) {
      const sign = signs[byi * bx + bxi];
      const d = sign * delta;
      if (!d) continue;
      const lut = sign > 0 ? lutPos : lutNeg;
      const x0 = bxi * bs, y0 = byi * bs;
      const x1 = Math.min(w, x0 + bs), y1 = Math.min(h, y0 + bs);
      for (let y = y0; y < y1; y++) {
        let i = (y * w + x0) * 4;
        for (let x = x0; x < x1; x++, i += 4) {
          out[i] = lut[out[i]];
          out[i + 1] = lut[out[i + 1]];
          out[i + 2] = lut[out[i + 2]];
        }
      }
    }
  }
  return out;
}
function forensicScore(candidate, reference, w, h, seed, { blockSize = 32 } = {}) {
  const bs = Math.max(8, blockSize | 0);
  const bx = Math.ceil(w / bs);
  const by = Math.ceil(h / bs);
  const blockSigns = new Int8Array(bx * by);
  let total = 0;
  for (let byi = 0; byi < by; byi++) {
    for (let bxi = 0; bxi < bx; bxi++) {
      const x0 = bxi * bs, y0 = byi * bs;
      const x1 = Math.min(w, x0 + bs), y1 = Math.min(h, y0 + bs);
      let diff = 0, n = 0;
      for (let y = y0; y < y1; y += 2) {
        let i = (y * w + x0) * 4;
        for (let x = x0; x < x1; x += 2, i += 8) {
          diff += (candidate[i] + candidate[i + 1] + candidate[i + 2] - (reference[i] + reference[i + 1] + reference[i + 2])) / 3;
          n++;
        }
      }
      if (!n) continue;
      blockSigns[byi * bx + bxi] = Math.sign(diff / n) + 2;
      total++;
    }
  }
  let best = { score: 0, matched: 0, total, signsVersion: 3 };
  for (const version of [3, 2, 1]) {
    const signs = forensicBlockSigns(seed, bx * by, version);
    let matched = 0, signedSum = 0;
    for (let i = 0; i < blockSigns.length; i++) {
      if (!blockSigns[i]) continue;
      const hit = blockSigns[i] - 2 === signs[i];
      signedSum += hit ? 1 : -1;
      if (hit) matched++;
    }
    const score = total ? signedSum / total : 0;
    if (version === 3 || score > best.score) best = { score, matched, total, signsVersion: version };
  }
  return best;
}

// src/core/bch.js
var GF_POLY = 285;
var N = 255;
var K = 131;
var T = 18;
var DATA_BITS = 64;
var PAD = K - DATA_BITS;
var BCH_CODE_BITS = N - PAD;
var BCH_MAX_2E_PLUS_S = 2 * T;
var EXP = new Uint8Array(512);
var LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 256) x ^= GF_POLY;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
}
var gfMul = (a, b) => a && b ? EXP[LOG[a] + LOG[b]] : 0;
var gfDiv = (a, b) => a ? EXP[LOG[a] - LOG[b] + 255] : 0;
var gfPow = (a, p) => a ? EXP[LOG[a] * p % 255] : 0;
var GENERATOR = (() => {
  let g = [1];
  for (let j = 1; j <= 2 * T; j++) {
    const root = EXP[j];
    const next = new Array(g.length + 1).fill(0);
    for (let i = 0; i < g.length; i++) {
      next[i] ^= gfMul(g[i], root);
      next[i + 1] ^= g[i];
    }
    g = next;
  }
  const seen = /* @__PURE__ */ new Set();
  let gen = [1];
  for (let j = 1; j <= 2 * T; j++) {
    if (seen.has(j)) continue;
    const coset = [];
    let c = j;
    while (!seen.has(c)) {
      seen.add(c);
      coset.push(c);
      c = c * 2 % 255;
    }
    for (const member of coset) {
      const root = EXP[member];
      const next = new Array(gen.length + 1).fill(0);
      for (let i = 0; i < gen.length; i++) {
        next[i] ^= gfMul(gen[i], root);
        next[i + 1] ^= gen[i];
      }
      gen = next;
    }
  }
  const degree = gen.length - 1;
  const bits = new Uint8Array(degree + 1);
  for (let i = 0; i <= degree; i++) {
    const coef = gen[degree - i];
    if (coef !== 0 && coef !== 1) throw new Error("Archx BCH: generator is not binary");
    bits[i] = coef;
  }
  if (degree !== N - K) throw new Error(`Archx BCH: generator degree ${degree}, expected ${N - K}`);
  return bits;
})();
function syndromes(codeword) {
  const out = new Uint8Array(2 * T);
  for (let j = 1; j <= 2 * T; j++) {
    let s = 0;
    for (let i = 0; i < N; i++) {
      if (!codeword[i]) continue;
      s ^= EXP[j * (254 - i) % 255];
    }
    out[j - 1] = s;
  }
  return out;
}
function bchEncode64(dataBits) {
  if (!dataBits || dataBits.length !== DATA_BITS) {
    throw new Error(`Archx BCH: data must be exactly ${DATA_BITS} bits`);
  }
  const work = new Uint8Array(N);
  work.set(dataBits, PAD);
  for (let i = 0; i < K; i++) {
    if (!work[i]) continue;
    for (let j = 0; j <= N - K; j++) work[i + j] ^= GENERATOR[j];
  }
  const out = new Uint8Array(BCH_CODE_BITS);
  out.set(dataBits, 0);
  out.set(work.subarray(K), DATA_BITS);
  return out;
}
function berlekampMassey(seq) {
  let C = [1];
  let B = [1];
  let L = 0;
  let m = 1;
  let b = 1;
  for (let n = 0; n < seq.length; n++) {
    let d = seq[n];
    for (let i = 1; i <= L; i++) d ^= gfMul(C[i] || 0, seq[n - i]);
    if (d === 0) {
      m++;
      continue;
    }
    const prevC = C.slice();
    const scale = gfDiv(d, b);
    while (C.length < B.length + m) C.push(0);
    for (let i = 0; i < B.length; i++) C[i + m] ^= gfMul(scale, B[i]);
    if (2 * L <= n) {
      L = n + 1 - L;
      B = prevC;
      b = d;
      m = 1;
    } else {
      m++;
    }
  }
  C.length = L + 1;
  return C;
}
function evalPolyAscending(coefs, x) {
  let acc = 0;
  for (let i = coefs.length - 1; i >= 0; i--) acc = gfMul(acc, x) ^ (coefs[i] || 0);
  return acc;
}
function bchDecode188(received, erasures = []) {
  if (!received || received.length !== BCH_CODE_BITS) return null;
  const erasureList = [...new Set(erasures)].filter((i) => i >= 0 && i < BCH_CODE_BITS);
  if (erasureList.length > 2 * T) return null;
  const full = new Uint8Array(N);
  full.set(received, PAD);
  const syn = syndromes(full);
  const s = erasureList.length;
  if (syn.every((v) => v === 0)) {
    return { data: Uint8Array.from(full.subarray(PAD, PAD + DATA_BITS)), errors: 0, erasures: s };
  }
  let gamma = [1];
  for (const ti of erasureList) {
    const X = EXP[(254 - (ti + PAD)) % 255];
    const next = new Array(gamma.length + 1).fill(0);
    for (let i = 0; i < gamma.length; i++) {
      next[i] ^= gamma[i];
      next[i + 1] ^= gfMul(gamma[i], X);
    }
    gamma = next;
  }
  const fsyn = [];
  for (let i = s; i < 2 * T; i++) {
    let acc = 0;
    for (let j = 0; j <= Math.min(i, gamma.length - 1); j++) {
      acc ^= gfMul(gamma[j], syn[i - j]);
    }
    fsyn.push(acc);
  }
  const errLoc = berlekampMassey(fsyn);
  const errDeg = errLoc.length - 1;
  if (2 * errDeg + s > 2 * T) return null;
  const lambda = new Array(errLoc.length + gamma.length - 1).fill(0);
  for (let i = 0; i < errLoc.length; i++) {
    for (let j = 0; j < gamma.length; j++) lambda[i + j] ^= gfMul(errLoc[i], gamma[j]);
  }
  const lambdaDeg = lambda.length - 1;
  const positions = [];
  for (let i = 0; i < N; i++) {
    if (evalPolyAscending(lambda, EXP[(i + 1) % 255]) === 0) positions.push(i);
  }
  if (positions.length !== lambdaDeg) return null;
  const deg = lambdaDeg;
  const locators = positions.map((pos) => EXP[(254 - pos) % 255]);
  const rows = [];
  for (let j = 0; j < deg; j++) {
    const row = new Array(deg + 1);
    for (let l = 0; l < deg; l++) row[l] = gfPow(locators[l], j + 1);
    row[deg] = syn[j];
    rows.push(row);
  }
  for (let col = 0, row = 0; col < deg && row < deg; col++) {
    let pivot = -1;
    for (let r = row; r < deg; r++) if (rows[r][col] !== 0) {
      pivot = r;
      break;
    }
    if (pivot < 0) return null;
    [rows[row], rows[pivot]] = [rows[pivot], rows[row]];
    const inv = gfDiv(1, rows[row][col]);
    for (let c = col; c <= deg; c++) rows[row][c] = gfMul(rows[row][c], inv);
    for (let r = 0; r < deg; r++) {
      if (r === row || rows[r][col] === 0) continue;
      const factor = rows[r][col];
      for (let c = col; c <= deg; c++) rows[r][c] ^= gfMul(factor, rows[row][c]);
    }
    row++;
  }
  const erasureSet = new Set(erasureList.map((ti) => ti + PAD));
  let errors = 0;
  for (let l = 0; l < deg; l++) {
    const Y = rows[l][deg];
    if (Y !== 0 && Y !== 1) return null;
    const pos = positions[l];
    if (!erasureSet.has(pos)) {
      if (Y !== 1) return null;
      errors++;
    }
    if (Y === 1) full[pos] ^= 1;
  }
  if (2 * errors + s > 2 * T) return null;
  if (!syndromes(full).every((v) => v === 0)) return null;
  for (let i = 0; i < PAD; i++) if (full[i]) return null;
  return { data: Uint8Array.from(full.subarray(PAD, PAD + DATA_BITS)), errors, erasures: s };
}
function highestBit(mask) {
  const hi = Number(mask >> 32n);
  return hi ? 63 - Math.clz32(hi) : 31 - Math.clz32(Number(mask & 0xffffffffn));
}
var GEN_ROWS = (() => {
  const rows = new Array(BCH_CODE_BITS).fill(0n);
  for (let i = 0; i < DATA_BITS; i++) {
    const unit = new Uint8Array(DATA_BITS);
    unit[i] = 1;
    const code = bchEncode64(unit);
    for (let j = 0; j < BCH_CODE_BITS; j++) if (code[j]) rows[j] |= 1n << BigInt(i);
  }
  return rows;
})();
function bchSolveObserved(received, observedOrder) {
  if (!received || received.length !== BCH_CODE_BITS) return null;
  const basis = new Array(DATA_BITS).fill(null);
  let rank = 0;
  const used = [];
  for (const j of observedOrder) {
    if (rank === DATA_BITS) break;
    if (j < 0 || j >= BCH_CODE_BITS) continue;
    let mask = GEN_ROWS[j];
    let value = received[j] ? 1 : 0;
    while (mask !== 0n) {
      const pivot = highestBit(mask);
      if (!basis[pivot]) {
        basis[pivot] = { mask, value };
        rank++;
        used.push(j);
        mask = 0n;
        break;
      }
      mask ^= basis[pivot].mask;
      value ^= basis[pivot].value;
    }
  }
  if (rank < DATA_BITS) return null;
  const data = new Uint8Array(DATA_BITS);
  for (let col = 0; col < DATA_BITS; col++) {
    const row = basis[col];
    if (!row) return null;
    let v = row.value;
    let mask = row.mask & ~(1n << BigInt(col));
    while (mask !== 0n) {
      const bit = highestBit(mask);
      v ^= data[bit] & 1;
      mask &= ~(1n << BigInt(bit));
    }
    data[col] = v;
  }
  const code = bchEncode64(data);
  let mismatches = 0;
  for (const j of observedOrder) {
    if (j >= 0 && j < BCH_CODE_BITS && (code[j] ? 1 : 0) !== (received[j] ? 1 : 0)) mismatches++;
  }
  return { data, mismatches, basis: used };
}
function bchIsdSolve(received, observedOrder, { maxMismatches = Infinity, verify = null, trials = 400, seedSalt = 0 } = {}) {
  if (!received || received.length !== BCH_CODE_BITS) return null;
  if (!observedOrder || observedOrder.length < DATA_BITS + 8) return null;
  let seed = 2166136261 ^ Math.imul(seedSalt + 1, 2654435769);
  for (let i = 0; i < observedOrder.length; i++) {
    seed ^= (observedOrder[i] + 1) * 257 + (received[observedOrder[i]] ? 1 : 0);
    seed = Math.imul(seed, 16777619);
  }
  const rnd = () => {
    seed |= 0;
    seed = seed + 1831565813 | 0;
    let t = Math.imul(seed ^ seed >>> 15, 1 | seed);
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };
  const score = (sol) => {
    if (!sol) return null;
    const code = bchEncode64(sol.data);
    let mismatches = 0;
    for (const j of observedOrder) {
      if (j >= 0 && j < BCH_CODE_BITS && (code[j] ? 1 : 0) !== (received[j] ? 1 : 0)) mismatches++;
    }
    if (mismatches > maxMismatches) return null;
    if (verify && !verify(sol.data)) return null;
    return { data: sol.data, mismatches };
  };
  const keepTop = Math.min(24, Math.max(0, observedOrder.length - DATA_BITS));
  const shuffleTo = Math.min(observedOrder.length, 110);
  for (let t = 0; t < trials; t++) {
    const order = [...observedOrder];
    const lo = t % 10 === 9 ? 0 : keepTop;
    for (let i = shuffleTo - 1; i > lo; i--) {
      const j = lo + Math.floor(rnd() * (i - lo + 1));
      const tmp = order[i];
      order[i] = order[j];
      order[j] = tmp;
    }
    const hit = score(bchSolveObserved(received, order));
    if (hit) return { ...hit, isdTrials: t + 1 };
  }
  return null;
}
function bchOsdSolve(received, observedOrder, { maxMismatches = Infinity, verify = null } = {}) {
  if (!received || received.length !== BCH_CODE_BITS) return null;
  const score = (sol) => {
    if (!sol) return null;
    const code = bchEncode64(sol.data);
    let mismatches = 0;
    for (const j of observedOrder) {
      if (j >= 0 && j < BCH_CODE_BITS && (code[j] ? 1 : 0) !== (received[j] ? 1 : 0)) mismatches++;
    }
    if (mismatches > maxMismatches) return null;
    if (verify && !verify(sol.data)) return null;
    return { data: sol.data, mismatches };
  };
  const s0 = bchSolveObserved(received, observedOrder);
  const direct = score(s0);
  if (direct) return { ...direct, osdFlips: 0 };
  if (!s0 || !s0.basis || s0.basis.length < DATA_BITS) return null;
  const weakest = s0.basis.slice(-24);
  const rx = Uint8Array.from(received);
  const trial = (positions) => {
    for (const p of positions) rx[p] ^= 1;
    const out = score(bchSolveObserved(rx, observedOrder));
    for (const p of positions) rx[p] ^= 1;
    return out;
  };
  for (const p of weakest) {
    const hit = trial([p]);
    if (hit) return { ...hit, osdFlips: 1 };
  }
  const pairZone = weakest.slice(-10);
  for (let i = 0; i < pairZone.length; i++) {
    for (let j = i + 1; j < pairZone.length; j++) {
      const hit = trial([pairZone[i], pairZone[j]]);
      if (hit) return { ...hit, osdFlips: 2 };
    }
  }
  return null;
}

// src/core/stego-code.js
function stegoFingerprint(value) {
  const s = String(value ?? "");
  if (/^[0-9a-fA-F]{12}$/.test(s)) return s.toLowerCase();
  const digest = sha256Bytes(utf8Encode("archx-stego-fp-v2:" + s));
  let hex = "";
  for (let i = 0; i < 6; i++) hex += digest[i].toString(16).padStart(2, "0");
  return hex;
}
function legacyStegoFingerprint(value) {
  const s = String(value ?? "");
  if (/^[0-9a-fA-F]{12}$/.test(s)) return s.toLowerCase();
  const a = hashSeed("archx-stego:" + s, 20907);
  const b = hashSeed("archx-stego:" + s, 40503);
  const lo = Math.floor(a % 16777216).toString(16).padStart(6, "0");
  const hi = Math.floor(b % 16777216).toString(16).padStart(6, "0");
  return lo + hi;
}
var STEGO_CRC16_TABLE = (() => {
  const table = new Uint16Array(256);
  for (let byte = 0; byte < 256; byte++) {
    let crc = byte << 8;
    for (let i = 0; i < 8; i++) {
      crc = crc & 32768 ? (crc << 1 ^ 4129) & 65535 : crc << 1 & 65535;
    }
    table[byte] = crc;
  }
  return table;
})();
function stegoCrc16(bytes) {
  let crc = 65535;
  for (const byte of bytes) {
    crc = (crc << 8 ^ STEGO_CRC16_TABLE[(crc >> 8 ^ byte) & 255]) & 65535;
  }
  return crc;
}
var STEGO_MAC_DOMAIN = utf8Encode("archx-stego-v2:");
function stegoMac16(key, payloadBytes) {
  const msg = new Uint8Array(STEGO_MAC_DOMAIN.length + payloadBytes.length);
  msg.set(STEGO_MAC_DOMAIN, 0);
  msg.set(payloadBytes, STEGO_MAC_DOMAIN.length);
  const mac = hmacSha256Bytes(utf8Encode(String(key ?? "")), msg);
  return mac[0] << 8 | mac[1];
}
function stegoBytesToBits(bytes) {
  const bits = new Uint8Array(bytes.length * 8);
  bytes.forEach((byte, i) => {
    for (let b = 0; b < 8; b++) bits[i * 8 + b] = byte >> 7 - b & 1;
  });
  return bits;
}
function robustLegacyKeyedCrc(first8, key) {
  const keyByte = Math.floor(hashSeed("archx-stego-robust:" + String(key ?? ""), 20907) % 256);
  const keyed = new Uint8Array(9);
  keyed.set(first8, 0);
  keyed[8] = keyByte;
  return stegoCrc16(keyed);
}
var ROBUST_MARKER_BITS = stegoBytesToBits(new Uint8Array([165, 90]));
function robustStegoCodeBits(fingerprint, key, tag = "mac") {
  const payload = new Uint8Array(6);
  for (let i = 0; i < 6; i++) payload[i] = parseInt(fingerprint.slice(i * 2, i * 2 + 2), 16);
  const crc = stegoCrc16(payload);
  const first = [...payload, crc >> 8 & 255, crc & 255];
  const check = tag === "crc" ? robustLegacyKeyedCrc(first, key) : stegoMac16(key, payload);
  return stegoBytesToBits(new Uint8Array([
    ...first,
    check >> 8 & 255,
    check & 255,
    165,
    90
  ]));
}
function robustStegoBytesValid(bytes, key, tag = "mac") {
  if (!bytes || bytes.length !== 12) return false;
  if (bytes[10] !== 165 || bytes[11] !== 90) return false;
  if (stegoCrc16(bytes.subarray(0, 6)) !== (bytes[6] << 8 | bytes[7])) return false;
  const expected = tag === "crc" ? robustLegacyKeyedCrc(bytes.subarray(0, 8), key) : stegoMac16(key, bytes.subarray(0, 6));
  return expected === (bytes[8] << 8 | bytes[9]);
}
function robustStegoFingerprintFromBits(bits) {
  let fingerprint = "";
  for (let i = 0; i < 6; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = byte << 1 | bits[i * 8 + b];
    fingerprint += byte.toString(16).padStart(2, "0");
  }
  return fingerprint;
}
function stegoCodeBits(fingerprint, key, tag = "mac") {
  const bytes = new Uint8Array(6);
  for (let i = 0; i < 6; i++) bytes[i] = parseInt(fingerprint.slice(i * 2, i * 2 + 2), 16);
  const check = tag === "crc" ? stegoCrc16(bytes) : stegoMac16(key, bytes);
  const all = [...bytes, check >> 8 & 255, check & 255];
  const bits = new Uint8Array(64);
  all.forEach((byte, i) => {
    for (let b = 0; b < 8; b++) bits[i * 8 + b] = byte >> 7 - b & 1;
  });
  return bits;
}
function stegoBitsToBytes(bits) {
  const bytes = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = byte << 1 | bits[i * 8 + b];
    bytes[i] = byte;
  }
  return bytes;
}
function stegoCrcValid(bits) {
  const bytes = stegoBitsToBytes(bits);
  return stegoCrc16(bytes.subarray(0, 6)) === (bytes[6] << 8 | bytes[7]);
}
function correctStegoBits(bits, reliability, key, maxDepth = 3) {
  const macCache = /* @__PURE__ */ new Map();
  const macOf = (candidate) => {
    const bytes = stegoBitsToBytes(candidate);
    const cacheKey = (bytes[0] << 16 | bytes[1] << 8 | bytes[2]) + ":" + (bytes[3] << 16 | bytes[4] << 8 | bytes[5]);
    let mac = macCache.get(cacheKey);
    if (mac === void 0) {
      mac = stegoMac16(key, bytes.subarray(0, 6));
      macCache.set(cacheKey, mac);
    }
    return mac === (bytes[6] << 8 | bytes[7]);
  };
  const search = (valid, depthCap) => {
    if (valid(bits)) return { bits, corrections: 0 };
    const weakest = [...bits.keys()].sort((a, b) => reliability[a] - reliability[b]).slice(0, 20);
    let best = null;
    const visit = (start, chosen) => {
      if (chosen.length) {
        const candidate = new Uint8Array(bits);
        let cost = 0;
        for (const i of chosen) {
          candidate[i] ^= 1;
          cost += reliability[i];
        }
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
  if (macBest) return { ...macBest, tagScheme: "mac" };
  const crcBest = search(stegoCrcValid, Math.min(1, maxDepth));
  if (crcBest) return { ...crcBest, tagScheme: "crc" };
  return { bits, corrections: -1, tagScheme: null };
}
var STEGO_ROW_SEGMENTS = 4;
function layoutRand(seedString, version, legacyHashSeedArg) {
  if (version === 1) return mulberry32(hashSeed(seedString, legacyHashSeedArg));
  if (version === 2) return sfc32(...cyrb128(seedString));
  return sha256SeededPrng(seedString);
}
function stegoLayout(cellCount, key, version = 2) {
  const rand = layoutRand(String(key) + "::archx-stego-layout", version);
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
    if (gx <= gy && gx < Math.floor(w / 4)) gx++;
    else gy++;
  }
  return { gx, gy };
}
function robustStegoLayout(cellCount, key, version = 2) {
  const order = Array.from({ length: cellCount }, (_, i) => i);
  const polarity = new Int8Array(cellCount);
  const segmentPolarity = new Int8Array(cellCount * STEGO_ROW_SEGMENTS);
  const rand = layoutRand("archx-stego-robust-layout:" + String(key ?? ""), version, 20907);
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
var STEGO_V4_CODE_BITS = BCH_CODE_BITS;
var _v4PermCache = /* @__PURE__ */ new Map();
function stegoV4InterleaveOrder(key) {
  const cacheKey = String(key ?? "");
  let perm = _v4PermCache.get(cacheKey);
  if (perm) return perm;
  const rand = sha256SeededPrng("archx-stego-v4-interleave:" + cacheKey);
  perm = Array.from({ length: BCH_CODE_BITS }, (_, i) => i);
  for (let i = perm.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [perm[i], perm[j]] = [perm[j], perm[i]];
  }
  if (_v4PermCache.size >= 64) _v4PermCache.clear();
  _v4PermCache.set(cacheKey, perm);
  return perm;
}
function bchStegoCodeBits(fingerprint, key) {
  const payload = new Uint8Array(6);
  for (let i = 0; i < 6; i++) payload[i] = parseInt(fingerprint.slice(i * 2, i * 2 + 2), 16);
  const mac = stegoMac16(key, payload);
  const data = stegoBytesToBits(new Uint8Array([...payload, mac >> 8 & 255, mac & 255]));
  const code = bchEncode64(data);
  const perm = stegoV4InterleaveOrder(key);
  const wire = new Uint8Array(BCH_CODE_BITS);
  for (let i = 0; i < BCH_CODE_BITS; i++) wire[i] = code[perm[i]];
  return wire;
}
function bchStegoDecode(wireBits, erasures, key) {
  if (!wireBits || wireBits.length !== BCH_CODE_BITS) return null;
  const perm = stegoV4InterleaveOrder(key);
  const plain = new Uint8Array(BCH_CODE_BITS);
  for (let i = 0; i < BCH_CODE_BITS; i++) plain[perm[i]] = wireBits[i] ? 1 : 0;
  const plainErasures = (erasures || []).map((i) => perm[i]).filter((i) => i !== void 0);
  const decoded = bchDecode188(plain, plainErasures);
  if (!decoded) return null;
  const bytes = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = byte << 1 | decoded.data[i * 8 + b];
    bytes[i] = byte;
  }
  if (stegoMac16(key, bytes.subarray(0, 6)) !== (bytes[6] << 8 | bytes[7])) return null;
  const code = bchEncode64(decoded.data);
  const bits = new Uint8Array(BCH_CODE_BITS);
  for (let i = 0; i < BCH_CODE_BITS; i++) bits[i] = code[perm[i]];
  let fingerprint = "";
  for (let i = 0; i < 6; i++) fingerprint += bytes[i].toString(16).padStart(2, "0");
  return { fingerprint, bits, errors: decoded.errors, erasures: decoded.erasures };
}
function bchStegoSolveObserved(wireBits, observedOrderWire, key, { maxMismatches = Infinity, osd = true, isdTrials = 0, seedSalt = 0 } = {}) {
  if (!wireBits || wireBits.length !== BCH_CODE_BITS) return null;
  if (!observedOrderWire || observedOrderWire.length < 65) return null;
  const capLimit = Math.max(3, Math.floor((observedOrderWire.length - 64) * 0.34));
  if (maxMismatches > capLimit) maxMismatches = capLimit;
  const perm = stegoV4InterleaveOrder(key);
  const plain = new Uint8Array(BCH_CODE_BITS);
  for (let i = 0; i < BCH_CODE_BITS; i++) plain[perm[i]] = wireBits[i] ? 1 : 0;
  const plainOrder = observedOrderWire.map((i) => perm[i]).filter((i) => i !== void 0);
  const macOk = (dataBits) => {
    let mac = 0;
    const fpBytes = new Uint8Array(6);
    for (let i = 0; i < 6; i++) {
      let byte = 0;
      for (let b = 0; b < 8; b++) byte = byte << 1 | dataBits[i * 8 + b];
      fpBytes[i] = byte;
    }
    for (let b = 0; b < 16; b++) mac = mac << 1 | dataBits[48 + b];
    return stegoMac16(key, fpBytes) === mac;
  };
  let solved = osd ? bchOsdSolve(plain, plainOrder, { maxMismatches, verify: macOk }) : (() => {
    const d = bchSolveObserved(plain, plainOrder);
    return d && macOk(d.data) ? d : null;
  })();
  if (!solved && isdTrials > 0) {
    solved = bchIsdSolve(plain, plainOrder, { maxMismatches, verify: macOk, trials: isdTrials, seedSalt });
  }
  if (!solved) return null;
  const bytes = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = byte << 1 | solved.data[i * 8 + b];
    bytes[i] = byte;
  }
  if (stegoMac16(key, bytes.subarray(0, 6)) !== (bytes[6] << 8 | bytes[7])) return null;
  const code = bchEncode64(solved.data);
  const bits = new Uint8Array(BCH_CODE_BITS);
  for (let i = 0; i < BCH_CODE_BITS; i++) bits[i] = code[perm[i]];
  let fingerprint = "";
  for (let i = 0; i < 6; i++) fingerprint += bytes[i].toString(16).padStart(2, "0");
  return {
    fingerprint,
    bits,
    mismatches: solved.mismatches,
    erasures: BCH_CODE_BITS - plainOrder.length
  };
}

// src/core/stego-embed.js
function embedStegoFingerprint(rgba, w, h, payload, {
  key = "",
  strength = 6,
  gridX,
  gridY,
  profile = "standard",
  inPlace = false,
  // Codeword v2 (keyed MAC acceptance tag) is the default; legacyCode
  // reproduces pre-v1.12 CRC-tagged codewords for compatibility testing.
  legacyCode = false,
  // Layout space: 3 = SHA-256-seeded repetition code (default),
  // 2 = 128-bit cyrb128, 1 = pre-1.13 32-bit-truncated (both kept
  // for compatibility testing), 4 = v1.20 BCH(188,64) code over the
  // v3 cell layout (corrects 2e+s <= 36; needs a v1.20+ detector).
  layoutVersion = 3
} = {}) {
  const src = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  if (src.length < w * h * 4) throw new Error("Archx stego: pixel buffer is smaller than w\xD7h\xD74");
  if (w < 64 || h < 64) throw new Error("Archx stego: image too small (minimum 64\xD764)");
  const robust = profile === "robust";
  const effectiveGridX = gridX ?? (robust ? 20 : 24);
  const effectiveGridY = gridY ?? (robust ? 14 : 16);
  const rowSegments = STEGO_ROW_SEGMENTS;
  const columnBands = 4;
  const fingerprint = stegoFingerprint(payload);
  const v4 = layoutVersion === 4;
  if (v4 && legacyCode) throw new Error("Archx stego: layoutVersion 4 always uses the keyed MAC payload (legacyCode is v1-v3 only)");
  const tag = legacyCode ? "crc" : "mac";
  const bits = v4 ? bchStegoCodeBits(fingerprint, key) : robust ? robustStegoCodeBits(fingerprint, key, tag) : stegoCodeBits(fingerprint, key, tag);
  const { gx, gy } = stegoGrid(w, h, effectiveGridX, effectiveGridY);
  const cellCount = gx * gy;
  const seedVersion = v4 || layoutVersion === 3 ? 3 : layoutVersion === 2 ? 2 : 1;
  const { order, polarity, segmentPolarity } = robust ? robustStegoLayout(cellCount, key, seedVersion) : stegoLayout(cellCount, key, seedVersion);
  const out = inPlace ? src : new Uint8Array(src);
  const baseAmp = Math.max(1, Math.min(16, Number(strength) || 6));
  const amp = robust ? Math.min(16, baseAmp * 1.35) : baseAmp;
  for (let cy = 0; cy < gy; cy++) {
    const y0 = Math.floor(cy * h / gy);
    const y1 = Math.floor((cy + 1) * h / gy);
    for (let cx = 0; cx < gx; cx++) {
      const x0 = Math.floor(cx * w / gx);
      const x1 = Math.floor((cx + 1) * w / gx);
      if (x1 - x0 < 4 || y1 - y0 < 2) continue;
      const cell = cy * gx + cx;
      const bit = bits[order[cell] % bits.length];
      const pol = polarity[cell];
      let sum = 0, sum2 = 0, n = 0;
      for (let y = y0; y < y1; y += 2) {
        let i = (y * w + x0) * 4;
        for (let x = x0; x < x1; x += 2, i += 8) {
          const lum = src[i] * 77 + src[i + 1] * 150 + src[i + 2] * 29 >> 8;
          sum += lum;
          sum2 += lum * lum;
          n++;
        }
      }
      const mean = n ? sum / n : 0;
      const std = n ? Math.sqrt(Math.max(0, sum2 / n - mean * mean)) : 0;
      const cellAmp = v4 ? Math.min(16, amp * Math.max(0.4, Math.min(1.2, 0.4 + std / 40))) : Math.min(16, amp * Math.max(0.4, Math.min(1.4, 0.4 + std / 36)));
      const cellW = x1 - x0;
      const cellH = y1 - y0;
      const lutPos = new Uint8Array(256);
      const lutNeg = new Uint8Array(256);
      for (let v = 0; v < 256; v++) {
        lutPos[v] = Math.max(0, Math.min(255, v + cellAmp));
        lutNeg[v] = Math.max(0, Math.min(255, v - cellAmp));
      }
      const bandStart = [0, 0, 0, 0];
      for (let b = 1; b < columnBands; b++) bandStart[b] = Math.ceil(b * cellW / columnBands);
      const cellSign = (bit ? 1 : -1) * pol;
      for (let y = y0; y < y1; y++) {
        const segment = Math.min(
          rowSegments - 1,
          Math.floor((y - y0) * rowSegments / cellH)
        );
        const segmentSign = segmentPolarity[cell * rowSegments + segment];
        const rowPositive = cellSign * segmentSign > 0;
        let i = (y * w + x0) * 4;
        for (let b = 0; b < columnBands; b++) {
          const xs = x0 + bandStart[b];
          const xe = x0 + (b + 1 < columnBands ? bandStart[b + 1] : cellW);
          const lut = b % 2 === 0 === rowPositive ? lutPos : lutNeg;
          for (let x = xs; x < xe; x++, i += 4) {
            out[i] = lut[src[i]];
            out[i + 1] = lut[src[i + 1]];
            out[i + 2] = lut[src[i + 2]];
          }
        }
      }
    }
  }
  return out;
}

// src/core/pixels.js
function buildLumaIntegral(src, w, h) {
  const luma = new Uint8Array(w * h);
  const integral = w * h <= 16e6 ? new Uint32Array((w + 1) * (h + 1)) : new Float64Array((w + 1) * (h + 1));
  for (let y = 0; y < h; y++) {
    let rowSum = 0;
    let i = y * w * 4;
    const lumaRow = y * w;
    const outRow = (y + 1) * (w + 1);
    const prevRow = y * (w + 1);
    for (let x = 0; x < w; x++, i += 4) {
      const v = src[i] * 77 + src[i + 1] * 150 + src[i + 2] * 29 >> 8;
      luma[lumaRow + x] = v;
      rowSum += v;
      integral[outRow + x + 1] = integral[prevRow + x + 1] + rowSum;
    }
  }
  return { luma, integral };
}
var wordView = (u8, words) => u8.byteOffset % 4 === 0 && u8.byteLength >= words * 4 ? new Uint32Array(u8.buffer, u8.byteOffset, words) : null;
function flipPixels(src, w, h, flipX, flipY) {
  const flipped = new Uint8Array(w * h * 4);
  const src32 = wordView(src, w * h);
  if (src32) {
    const out32 = new Uint32Array(flipped.buffer);
    if (flipX && flipY) {
      out32.set(src32);
      out32.reverse();
      return flipped;
    }
    for (let y = 0; y < h; y++) {
      const sy = flipY ? h - 1 - y : y;
      out32.set(src32.subarray(sy * w, sy * w + w), y * w);
      if (flipX) out32.subarray(y * w, y * w + w).reverse();
    }
    return flipped;
  }
  for (let y = 0; y < h; y++) {
    const sy = flipY ? h - 1 - y : y;
    const srow = sy * w * 4;
    const drow = y * w * 4;
    for (let x = 0; x < w; x++) {
      const sx = flipX ? w - 1 - x : x;
      const si = srow + sx * 4;
      const di = drow + x * 4;
      flipped[di] = src[si];
      flipped[di + 1] = src[si + 1];
      flipped[di + 2] = src[si + 2];
      flipped[di + 3] = src[si + 3];
    }
  }
  return flipped;
}
var MIRROR_AXES = [["x", true, false], ["y", false, true], ["xy", true, true]];
function mirroredVariant(entry, srcTop, w, h, axis, flipX, flipY) {
  const slot = axis === "x" ? "flipped" : axis === "y" ? "flippedY" : "flippedXY";
  if (!entry[slot]) entry[slot] = flipPixels(srcTop, w, h, flipX, flipY);
  return entry[slot];
}
function rotatePixels90(src, w, h, clockwise) {
  const out = new Uint8Array(w * h * 4);
  const nw = h;
  const src32 = wordView(src, w * h);
  if (src32) {
    const out32 = new Uint32Array(out.buffer);
    const T2 = 32;
    for (let ty = 0; ty < h; ty += T2) {
      const yEnd = Math.min(h, ty + T2);
      for (let tx = 0; tx < w; tx += T2) {
        const xEnd = Math.min(w, tx + T2);
        for (let y = ty; y < yEnd; y++) {
          const sRow = y * w;
          const dx = clockwise ? h - 1 - y : y;
          for (let x = tx; x < xEnd; x++) {
            const dy = clockwise ? x : w - 1 - x;
            out32[dy * nw + dx] = src32[sRow + x];
          }
        }
      }
    }
    return out;
  }
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const si = (y * w + x) * 4;
      const dx = clockwise ? h - 1 - y : y;
      const dy = clockwise ? x : w - 1 - x;
      const di = (dy * nw + dx) * 4;
      out[di] = src[si];
      out[di + 1] = src[si + 1];
      out[di + 2] = src[si + 2];
      out[di + 3] = src[si + 3];
    }
  }
  return out;
}
function rotatedVariant(entry, srcTop, w, h, clockwise) {
  const slot = clockwise ? "rotCw" : "rotCcw";
  if (!entry[slot]) entry[slot] = rotatePixels90(srcTop, w, h, clockwise);
  return entry[slot];
}
function transposePixels(src, w, h, anti) {
  const out = new Uint8Array(w * h * 4);
  const src32 = wordView(src, w * h);
  if (src32) {
    const out32 = new Uint32Array(out.buffer);
    const T2 = 32;
    for (let ty = 0; ty < h; ty += T2) {
      const yEnd = Math.min(h, ty + T2);
      for (let tx = 0; tx < w; tx += T2) {
        const xEnd = Math.min(w, tx + T2);
        for (let y = ty; y < yEnd; y++) {
          const sRow = y * w;
          for (let x = tx; x < xEnd; x++) {
            const di = anti ? (w - 1 - x) * h + (h - 1 - y) : x * h + y;
            out32[di] = src32[sRow + x];
          }
        }
      }
    }
    return out;
  }
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const si = (y * w + x) * 4;
      const di = anti ? ((w - 1 - x) * h + (h - 1 - y)) * 4 : (x * h + y) * 4;
      out[di] = src[si];
      out[di + 1] = src[si + 1];
      out[di + 2] = src[si + 2];
      out[di + 3] = src[si + 3];
    }
  }
  return out;
}
function transposedVariant(entry, srcTop, w, h, anti) {
  const slot = anti ? "trAnti" : "trMain";
  if (!entry[slot]) entry[slot] = transposePixels(srcTop, w, h, anti);
  return entry[slot];
}
function resampleRgba(src, w, h, nw, nh) {
  const out = new Uint8Array(nw * nh * 4);
  const sx = w / nw, sy = h / nh;
  const colX0 = new Int32Array(nw), colX1 = new Int32Array(nw);
  const colWx = new Float64Array(nw), colInvWx = new Float64Array(nw);
  for (let x = 0; x < nw; x++) {
    const fx = Math.min(w - 1, Math.max(0, (x + 0.5) * sx - 0.5));
    const x0 = Math.floor(fx);
    colX0[x] = x0;
    colX1[x] = Math.min(w - 1, x0 + 1);
    colWx[x] = fx - x0;
    colInvWx[x] = 1 - colWx[x];
  }
  for (let y = 0; y < nh; y++) {
    const fy = Math.min(h - 1, Math.max(0, (y + 0.5) * sy - 0.5));
    const y0 = Math.floor(fy), y1 = Math.min(h - 1, y0 + 1), wy = fy - y0;
    const invWy = 1 - wy;
    const row0 = y0 * w, row1 = y1 * w;
    let di = y * nw * 4;
    for (let x = 0; x < nw; x++, di += 4) {
      const wx = colWx[x], invWx = colInvWx[x];
      const i00 = (row0 + colX0[x]) * 4, i10 = (row0 + colX1[x]) * 4;
      const i01 = (row1 + colX0[x]) * 4, i11 = (row1 + colX1[x]) * 4;
      for (let c = 0; c < 4; c++) {
        out[di + c] = (src[i00 + c] * invWx + src[i10 + c] * wx) * invWy + (src[i01 + c] * invWx + src[i11 + c] * wx) * wy;
      }
    }
  }
  return out;
}
function rotateRgba(src, w, h, angleRad) {
  const out = new Uint8Array(w * h * 4);
  const cx = (w - 1) / 2, cy = (h - 1) / 2;
  const cos = Math.cos(angleRad), sin = Math.sin(angleRad);
  for (let y = 0; y < h; y++) {
    const dy = y - cy;
    const dySin = dy * sin, dyCos = dy * cos;
    let di = y * w * 4;
    for (let x = 0; x < w; x++, di += 4) {
      const dx = x - cx;
      const fx = cx + dx * cos + dySin;
      const fy = cy - dx * sin + dyCos;
      const sx = Math.min(w - 1, Math.max(0, fx));
      const sy = Math.min(h - 1, Math.max(0, fy));
      const x0 = Math.floor(sx), y0 = Math.floor(sy);
      const x1 = Math.min(w - 1, x0 + 1), y1 = Math.min(h - 1, y0 + 1);
      const wx = sx - x0, wy = sy - y0;
      const invWx = 1 - wx, invWy = 1 - wy;
      const i00 = (y0 * w + x0) * 4, i10 = (y0 * w + x1) * 4;
      const i01 = (y1 * w + x0) * 4, i11 = (y1 * w + x1) * 4;
      for (let c = 0; c < 4; c++) {
        out[di + c] = (src[i00 + c] * invWx + src[i10 + c] * wx) * invWy + (src[i01 + c] * invWx + src[i11 + c] * wx) * wy;
      }
    }
  }
  return out;
}

// src/core/stego-detect.js
function repairRobustViaFirstCrc(scores, hard, key, tag = "mac") {
  const first = Uint8Array.from(hard.subarray(0, 64));
  const syndromeOf = (bits) => {
    const bytes = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
      let byte = 0;
      for (let b = 0; b < 8; b++) byte = byte << 1 | bits[i * 8 + b];
      bytes[i] = byte;
    }
    return stegoCrc16(bytes.subarray(0, 6)) ^ (bytes[6] << 8 | bytes[7]);
  };
  const target = syndromeOf(first);
  const buildCanonical = (correctedFirst) => {
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
    return flips <= 8 && tagFlips <= 2 ? { bits: canonical, flips, softCost } : null;
  };
  if (target === 0) return buildCanonical(first);
  const columns = new Uint16Array(64);
  for (let i = 0; i < 64; i++) {
    first[i] ^= 1;
    columns[i] = syndromeOf(first) ^ target;
    first[i] ^= 1;
  }
  const weakest = Array.from({ length: 64 }, (_, index) => index).sort((a, b) => Math.abs(scores[a]) - Math.abs(scores[b])).slice(0, 32);
  const leftCandidates = weakest.filter((_, index) => index % 2 === 0);
  const rightCandidates = weakest.filter((_, index) => index % 2 === 1);
  const subsetMaps = (candidates) => {
    const byWeight = Array.from({ length: 4 }, () => /* @__PURE__ */ new Map());
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
        if (!bestCanonical || candidate.softCost < bestCanonical.softCost || candidate.softCost === bestCanonical.softCost && candidate.flips < bestCanonical.flips) {
          bestCanonical = candidate;
        }
      }
    }
  }
  return bestCanonical ? { bits: bestCanonical.bits, flips: bestCanonical.flips } : null;
}
function repairRobustStegoBits(scores, hard, key, maxFlips = 5, tag = "mac") {
  const bits = Uint8Array.from(hard);
  const bytes = new Uint8Array(12);
  for (let i = 0; i < 12; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = byte << 1 | bits[i * 8 + b];
    bytes[i] = byte;
  }
  if (robustStegoBytesValid(bytes, key, tag)) return { bits, flips: 0, tagScheme: tag };
  const syndromeRepair = repairRobustViaFirstCrc(scores, bits, key, tag);
  if (syndromeRepair) return { ...syndromeRepair, tagScheme: tag };
  const candidates = Array.from({ length: bits.length }, (_, index) => index).sort((a, b) => Math.abs(scores[a]) - Math.abs(scores[b])).slice(0, 24);
  const flip = (index) => {
    bits[index] ^= 1;
    bytes[index >> 3] ^= 1 << 7 - (index & 7);
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
var STEGO_TIMEOUT = Symbol("archx-stego-timeout");
function detectStegoFingerprint(rgba, w, h, {
  key = "",
  gridX,
  gridY,
  profile = "standard",
  searchOffsets = false,
  searchGeometry = false,
  // Mirrored-suspect recovery is on by default for every profile (one
  // extra bounded pass on flipped pixels, only when the forward pass
  // found nothing); set false to disable.
  searchMirror = true,
  searchRotation = true,
  // Small-angle deskew search (offline forensic opt-in): sweeps
  // ±6° on a downscaled proxy, refines by raw signal, then confirms
  // at full resolution. Off by default (cost); the CLI exposes --tilt.
  searchTilt = false,
  // Optional wall-clock budget for the WHOLE search (all layouts,
  // profiles, and probes share one deadline). On expiry the best
  // candidate so far is returned with `timedOut: true` instead of
  // running unbounded forensic stages. 0 (default) = unlimited.
  maxTimeMs = 0,
  // Layout space: 'auto' (default) screens v3 (SHA-256-seeded),
  // v4 (v1.20 BCH code over the v3 layout), then v2/v1 legacy
  // seeds — native screens for all layouts first, then geometry
  // searches with the deadline sliced fairly across layouts;
  // pass 1-4 to pin one space (full budget to that one search,
  // roughly proportionally lower worst-case cost).
  layoutVersion = "auto",
  _mirrorProbe = false,
  _tiltProbe = false,
  _layoutVersion = 0,
  _planes = null,
  _deadline = 0
} = {}) {
  const deadline = _deadline > 0 ? _deadline : Number.isFinite(maxTimeMs) && maxTimeMs > 0 ? Date.now() + maxTimeMs : 0;
  const deadlineHit = () => deadline > 0 && Date.now() > deadline;
  const concreteLayout = _layoutVersion === 1 || _layoutVersion === 2 || _layoutVersion === 3 || _layoutVersion === 4 ? _layoutVersion : layoutVersion === 1 || layoutVersion === 2 || layoutVersion === 3 || layoutVersion === 4 ? layoutVersion : 0;
  const planesCache = _planes || /* @__PURE__ */ new Map();
  const srcTop = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  const planesEntry = (buf) => {
    let entry = planesCache.get(buf);
    if (!entry) {
      entry = { flipped: null, luma: null, integral: null };
      planesCache.set(buf, entry);
    }
    return entry;
  };
  if (!concreteLayout) {
    const order2 = [3, 4, 2, 1];
    const shared = { key, gridX, gridY, profile, searchOffsets, searchMirror, searchRotation, _mirrorProbe, _tiltProbe, _planes: planesCache };
    let best2 = null;
    const consider2 = (attempt) => {
      if (attempt && (!best2 || (attempt.confidence ?? 0) > (best2.confidence ?? 0))) best2 = attempt;
    };
    for (const version of order2) {
      const attempt = detectStegoFingerprint(srcTop, w, h, {
        ...shared,
        searchGeometry: false,
        searchTilt: false,
        _layoutVersion: version,
        _deadline: deadline
      });
      if (attempt?.found) return attempt;
      consider2(attempt);
      if (attempt?.timedOut || deadlineHit()) {
        if (best2 && !best2.timedOut) best2 = { ...best2, timedOut: true };
        return best2;
      }
    }
    if (searchGeometry || searchTilt) {
      for (let i = 0; i < order2.length; i++) {
        let slice = deadline;
        if (deadline > 0) {
          const remainingMs = deadline - Date.now();
          if (remainingMs <= 0) break;
          slice = Math.min(deadline, Date.now() + Math.max(1500, Math.ceil(remainingMs / (order2.length - i))));
        }
        const attempt = detectStegoFingerprint(srcTop, w, h, {
          ...shared,
          searchGeometry,
          searchTilt,
          _layoutVersion: order2[i],
          _deadline: slice
        });
        if (attempt?.found) return attempt;
        consider2(attempt);
        if (deadlineHit()) break;
      }
      if (best2 && deadlineHit() && !best2.timedOut) best2 = { ...best2, timedOut: true };
    }
    return best2;
  }
  if (profile === "auto") {
    const standard = detectStegoFingerprint(srcTop, w, h, {
      key,
      gridX,
      gridY,
      profile: "standard",
      searchOffsets,
      searchGeometry: false,
      searchMirror: false,
      searchRotation: false,
      searchTilt: false,
      _mirrorProbe: true,
      _tiltProbe: true,
      _layoutVersion: concreteLayout,
      _planes: planesCache,
      _deadline: deadline
    });
    if (standard?.found && standard.confidence >= 0.9 && !searchGeometry) return standard;
    const robust2 = detectStegoFingerprint(srcTop, w, h, {
      key,
      gridX,
      gridY,
      profile: "robust",
      searchOffsets,
      searchGeometry: false,
      searchMirror: false,
      searchRotation: false,
      searchTilt: false,
      _mirrorProbe: true,
      _tiltProbe: true,
      _layoutVersion: concreteLayout,
      _planes: planesCache,
      _deadline: deadline
    });
    const initial = robust2?.found && !standard?.found ? robust2 : standard?.found && !robust2?.found ? standard : (robust2?.confidence ?? 0) > (standard?.confidence ?? 0) ? robust2 : standard;
    if (!searchGeometry || initial?.found) return initial;
    if (deadlineHit()) return initial?.timedOut ? initial : { ...initial, timedOut: true };
    const standardGeometry = detectStegoFingerprint(srcTop, w, h, {
      key,
      gridX,
      gridY,
      profile: "standard",
      searchOffsets,
      searchGeometry: true,
      searchMirror: false,
      searchRotation: false,
      searchTilt,
      _mirrorProbe: true,
      _layoutVersion: concreteLayout,
      _planes: planesCache,
      _deadline: deadline
    });
    if (standardGeometry?.found) return standardGeometry;
    const robustGeometry = detectStegoFingerprint(srcTop, w, h, {
      key,
      gridX,
      gridY,
      profile: "robust",
      searchOffsets,
      searchGeometry: true,
      searchMirror: false,
      searchRotation: false,
      searchTilt,
      _mirrorProbe: true,
      _layoutVersion: concreteLayout,
      _planes: planesCache,
      _deadline: deadline
    });
    if (robustGeometry?.found) return robustGeometry;
    if ((searchMirror || searchRotation) && !_mirrorProbe) try {
      if (srcTop.length >= w * h * 4 && Number.isSafeInteger(w * h * 4)) {
        const entry = planesEntry(srcTop);
        for (const [axis, fx, fy] of searchMirror ? MIRROR_AXES : []) {
          const variant = mirroredVariant(entry, srcTop, w, h, axis, fx, fy);
          for (const candidateProfile of ["standard", "robust"]) {
            const fast = detectStegoFingerprint(variant, w, h, {
              key,
              gridX,
              gridY,
              profile: candidateProfile,
              searchOffsets,
              searchGeometry: false,
              searchMirror: false,
              searchRotation: false,
              searchTilt: false,
              _mirrorProbe: true,
              _tiltProbe: true,
              _layoutVersion: concreteLayout,
              _planes: planesCache,
              _deadline: deadline
            });
            if (fast?.found) return { ...fast, mirrored: true, mirrorAxis: axis };
          }
        }
        if (searchRotation) for (const clockwise of [false, true]) {
          const variant = rotatedVariant(entry, srcTop, w, h, clockwise);
          for (const candidateProfile of ["standard", "robust"]) {
            const fast = detectStegoFingerprint(variant, h, w, {
              key,
              gridX,
              gridY,
              profile: candidateProfile,
              searchOffsets,
              searchGeometry: false,
              searchMirror: false,
              searchRotation: false,
              searchTilt: false,
              _mirrorProbe: true,
              _tiltProbe: true,
              _layoutVersion: concreteLayout,
              _planes: planesCache,
              _deadline: deadline
            });
            if (fast?.found) return { ...fast, rotated: clockwise ? 270 : 90 };
          }
        }
        if (searchRotation) for (const anti of [false, true]) {
          const variant = transposedVariant(entry, srcTop, w, h, anti);
          for (const candidateProfile of ["standard", "robust"]) {
            const fast = detectStegoFingerprint(variant, h, w, {
              key,
              gridX,
              gridY,
              profile: candidateProfile,
              searchOffsets,
              searchGeometry: false,
              searchMirror: false,
              searchRotation: false,
              searchTilt: false,
              _mirrorProbe: true,
              _tiltProbe: true,
              _layoutVersion: concreteLayout,
              _planes: planesCache,
              _deadline: deadline
            });
            if (fast?.found) return { ...fast, transposed: anti ? "anti" : "main" };
          }
        }
        for (const [axis, fx, fy] of searchMirror ? MIRROR_AXES : []) {
          if (axis !== "x" && !searchGeometry) continue;
          const variant = mirroredVariant(entry, srcTop, w, h, axis, fx, fy);
          for (const candidateProfile of ["standard", "robust"]) {
            const mirrored = detectStegoFingerprint(variant, w, h, {
              key,
              gridX,
              gridY,
              profile: candidateProfile,
              searchOffsets,
              searchGeometry: true,
              searchMirror: false,
              searchRotation: false,
              searchTilt: false,
              _mirrorProbe: true,
              _tiltProbe: true,
              _layoutVersion: concreteLayout,
              _planes: planesCache,
              _deadline: deadline
            });
            if (mirrored?.found) return { ...mirrored, mirrored: true, mirrorAxis: axis };
          }
        }
        if (searchRotation && searchGeometry) for (const clockwise of [false, true]) {
          const variant = rotatedVariant(entry, srcTop, w, h, clockwise);
          for (const candidateProfile of ["robust"]) {
            const rotated = detectStegoFingerprint(variant, h, w, {
              key,
              gridX,
              gridY,
              profile: candidateProfile,
              searchOffsets,
              searchGeometry: true,
              searchMirror: false,
              searchRotation: false,
              searchTilt: false,
              _mirrorProbe: true,
              _tiltProbe: true,
              _layoutVersion: concreteLayout,
              _planes: planesCache,
              _deadline: deadline
            });
            if (rotated?.found) return { ...rotated, rotated: clockwise ? 270 : 90 };
          }
        }
        if (searchRotation && searchGeometry) for (const anti of [false, true]) {
          const variant = transposedVariant(entry, srcTop, w, h, anti);
          for (const candidateProfile of ["robust"]) {
            const transposed = detectStegoFingerprint(variant, h, w, {
              key,
              gridX,
              gridY,
              profile: candidateProfile,
              searchOffsets,
              searchGeometry: true,
              searchMirror: false,
              searchRotation: false,
              searchTilt: false,
              _mirrorProbe: true,
              _tiltProbe: true,
              _layoutVersion: concreteLayout,
              _planes: planesCache,
              _deadline: deadline
            });
            if (transposed?.found) return { ...transposed, transposed: anti ? "anti" : "main" };
          }
        }
      }
    } catch {
    }
    return (robustGeometry?.confidence ?? 0) > (standardGeometry?.confidence ?? 0) ? robustGeometry : standardGeometry;
  }
  const src = srcTop;
  if (src.length < w * h * 4) throw new Error("Archx stego: pixel buffer is smaller than w\xD7h\xD74");
  const robust = profile === "robust";
  const effectiveProfile = robust ? "robust" : "standard";
  const isV4 = concreteLayout === 4;
  const codeLength = isV4 ? STEGO_V4_CODE_BITS : robust ? 96 : 64;
  const rowSegments = STEGO_ROW_SEGMENTS;
  const columnBands = 4;
  const effectiveGridX = gridX ?? (robust ? 20 : 24);
  const effectiveGridY = gridY ?? (robust ? 14 : 16);
  const { gx, gy } = stegoGrid(w, h, effectiveGridX, effectiveGridY);
  const cellCount = gx * gy;
  const { order, polarity, segmentPolarity } = robust ? robustStegoLayout(cellCount, key, isV4 ? 3 : concreteLayout) : stegoLayout(cellCount, key, isV4 ? 3 : concreteLayout);
  const cw = w / gx, ch = h / gy;
  const planes = planesEntry(src);
  if (!planes.luma) {
    const built = buildLumaIntegral(src, w, h);
    planes.luma = built.luma;
    planes.integral = built.integral;
  }
  const integral = planes.integral;
  const rectSum = (rx0, ry0, rx1, ry1) => integral[ry1 * (w + 1) + rx1] - integral[ry0 * (w + 1) + rx1] - integral[ry1 * (w + 1) + rx0] + integral[ry0 * (w + 1) + rx0];
  const fractions = searchOffsets ? [-0.25, -0.125, 0, 0.125, 0.25] : [0];
  const _sums = new Float64Array(rowSegments * columnBands);
  const _counts = new Uint32Array(rowSegments * columnBands);
  const _bitScores = new Float64Array(codeLength);
  const _bitCounts = new Uint16Array(codeLength);
  const _votedBits = new Uint8Array(codeLength);
  const _reliability = new Float64Array(codeLength);
  const _voteScores = new Float64Array(codeLength);
  const _groups = Array.from({ length: codeLength }, () => []);
  const _cellBitIdx = new Uint16Array(gx * gy);
  const _cellScore = new Float32Array(gx * gy);
  const _disagreeByBit = new Uint16Array(codeLength);
  const _segmentResponses = [];
  let _evalTick = 0;
  let osdEscalations = 0;
  let isdEscalations = 0;
  const forensicStash = [];
  const deepForensicTry = (s, trials, salt) => {
    const cap = Math.max(4, Math.floor((s.order.length - 64) * 0.3));
    const hit = bchStegoSolveObserved(s.votes, s.order, key, {
      maxMismatches: cap,
      osd: true,
      isdTrials: trials,
      seedSalt: salt
    });
    if (!hit) return null;
    let agreeing = 0;
    for (let ci = 0; ci < s.cellLen; ci++) {
      if (s.cellScore[ci] >= 0 === !!hit.bits[s.cellBitIdx[ci]]) agreeing++;
    }
    const agreement = s.cellLen ? agreeing / s.cellLen : 0;
    const mismRate = hit.mismatches / Math.max(1, s.order.length - 64);
    const tierOk = mismRate <= 0.1 || mismRate <= 0.2 && s.meanAbs >= 2 && agreement >= 0.82 || s.meanAbs >= 2.5 && agreement >= 0.82;
    if (!(agreement >= 0.72 && s.meanAbs >= 1.2 && tierOk)) return null;
    const bchBudget = Math.round(120 * mismRate);
    const evidence2 = Math.max(0, agreement - 0.64) * 2.4 + Math.min(0.55, Math.max(0, s.meanAbs - 1.4) / 8) - bchBudget / 6 * 0.04;
    const deep = {
      ...s.result,
      found: true,
      fingerprint: hit.fingerprint,
      tagScheme: "mac",
      erasureDecoded: true,
      crcValid: true,
      corrections: hit.mismatches,
      agreement: Math.round(agreement * 1e3) / 1e3,
      confidence: Math.round(Math.max(0, Math.min(0.99, 0.42 + evidence2)) * 1e3) / 1e3
    };
    delete deep._evidence;
    delete deep._originX;
    delete deep._originY;
    delete deep._scaleX;
    delete deep._scaleY;
    return deep;
  };
  const STASH_DEEP_MIN_EVIDENCE = 0.6;
  const evaluate = ({ fx = 0, fy = 0, scale = 1, scaleX = scale, scaleY = scale, originX = null, originY = null, erasure = false } = {}) => {
    if (deadline && (++_evalTick & 15) === 0 && Date.now() > deadline) throw STEGO_TIMEOUT;
    const cellW0 = cw * scaleX;
    const cellH0 = ch * scaleY;
    const ox = originX ?? fx * cw;
    const oy = originY ?? fy * ch;
    const bitScores = _bitScores.fill(0);
    const bitCounts = _bitCounts.fill(0);
    let cellLen = 0;
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
          const ry0 = Math.max(y0, Math.round(rawY0 + segment * cellH0 / rowSegments));
          const ry1 = Math.min(y1, Math.round(rawY0 + (segment + 1) * cellH0 / rowSegments));
          if (ry1 <= ry0) continue;
          for (let band = 0; band < columnBands; band++) {
            const rx0 = Math.max(x0, Math.round(rawX0 + band * cellW0 / columnBands));
            const rx1 = Math.min(x1, Math.round(rawX0 + (band + 1) * cellW0 / columnBands));
            if (rx1 <= rx0) continue;
            const idx = segment * columnBands + band;
            sums[idx] = rectSum(rx0, ry0, rx1, ry1);
            counts[idx] = (rx1 - rx0) * (ry1 - ry0);
          }
        }
        let segmentScoreSum = 0;
        let segmentWeightSum = 0;
        let validSegments = 0;
        const robustSegmentResponses = robust ? (_segmentResponses.length = 0, _segmentResponses) : null;
        const cellIndex = cy * gx + cx;
        for (let segment = 0; segment < rowSegments; segment++) {
          const base = segment * columnBands;
          let complete = true;
          for (let band = 0; band < columnBands; band++) {
            if (counts[base + band] === 0) {
              complete = false;
              break;
            }
          }
          if (!complete) continue;
          validSegments++;
          const m0 = sums[base] / counts[base];
          const m1 = sums[base + 1] / counts[base + 1];
          const weight = Math.min(counts[base], counts[base + 1], counts[base + 2], counts[base + 3]);
          const response = -(-m0 + 3 * m1 - 3 * (sums[base + 2] / counts[base + 2]) + sums[base + 3] / counts[base + 3]) / 8;
          const signedResponse = response * polarity[cellIndex] * segmentPolarity[cellIndex * rowSegments + segment];
          if (robust) robustSegmentResponses.push(signedResponse);
          segmentScoreSum += signedResponse * weight;
          segmentWeightSum += weight;
        }
        if (!segmentWeightSum || validSegments < 2) continue;
        let rawScore = segmentScoreSum / segmentWeightSum;
        if (robust) {
          const values = robustSegmentResponses.sort((a, b) => a - b);
          const middle = Math.floor(values.length / 2);
          rawScore = values.length % 2 ? values[middle] : (values[middle - 1] + values[middle]) / 2;
        }
        const score = Math.max(-12, Math.min(12, rawScore));
        const bitIndex = order[cy * gx + cx] % codeLength;
        bitScores[bitIndex] += score;
        bitCounts[bitIndex]++;
        _cellBitIdx[cellLen] = bitIndex;
        _cellScore[cellLen] = score;
        cellLen++;
      }
    }
    const votedBits = _votedBits.fill(0);
    const reliability = _reliability.fill(0);
    const voteScores = _voteScores.fill(0);
    if (robust) {
      const groups = _groups;
      for (const group of groups) group.length = 0;
      for (let ci = 0; ci < cellLen; ci++) groups[_cellBitIdx[ci]].push(_cellScore[ci]);
      for (let i = 0; i < codeLength; i++) {
        const values = groups[i].sort((a, b) => a - b);
        if (!values.length) continue;
        const middle = Math.floor(values.length / 2);
        voteScores[i] = values.length % 2 ? values[middle] : (values[middle - 1] + values[middle]) / 2;
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
    const meanAbsPre = voteScores.reduce((s, v) => s + Math.abs(v), 0) / codeLength;
    let preAgreeing = 0;
    for (let ci = 0; ci < cellLen; ci++) {
      if (_cellScore[ci] >= 0 === !!votedBits[_cellBitIdx[ci]]) preAgreeing++;
    }
    const preAgreement = cellLen ? preAgreeing / cellLen : 0;
    const standardDepth = meanAbsPre >= 2 && preAgreement >= 0.82 ? 3 : 1;
    const minBitCountPre = Math.min(...bitCounts);
    const observedBitsPre = bitCounts.reduce((count, value) => count + (value > 0 ? 1 : 0), 0);
    const coverageOkPre = isV4 ? observedBitsPre >= 88 && cellLen >= 96 : robust ? observedBitsPre >= 88 && cellLen >= 128 : minBitCountPre >= 2 && cellLen >= codeLength * 3;
    let agreementBound = preAgreement;
    if (cellLen) {
      const disagreeByBit = _disagreeByBit.fill(0);
      for (let ci = 0; ci < cellLen; ci++) {
        if (_cellScore[ci] >= 0 !== !!votedBits[_cellBitIdx[ci]]) disagreeByBit[_cellBitIdx[ci]]++;
      }
      const gains = [...disagreeByBit].sort((a, b) => b - a);
      const maxFlips = robust ? 5 : standardDepth;
      let gainSum = 0;
      for (let i = 0; i < Math.min(maxFlips, gains.length); i++) gainSum += gains[i];
      agreementBound = (preAgreeing + gainSum) / cellLen;
    }
    const repairable = isV4 ? meanAbsPre >= 1.2 && cellLen >= 96 && coverageOkPre : meanAbsPre >= 1.2 && cellLen >= 96 && coverageOkPre && agreementBound >= 0.72;
    const erasureDecode = () => {
      const erasedPayload = [];
      let erasedTotal = 0;
      for (let i = 0; i < codeLength; i++) {
        if (bitCounts[i] === 0) {
          erasedTotal++;
          if (i < 48) erasedPayload.push(i);
        }
      }
      if (!erasedTotal || erasedTotal > 32 || erasedPayload.length > 20) return null;
      const deep = erasedTotal > 24;
      if (meanAbsPre < 2 || preAgreement < (deep ? 0.9 : 0.8) || cellLen < 96) return null;
      const budget = deep && !(preAgreement >= 0.95 && meanAbsPre >= 4) ? 2 : 3;
      const weak = [];
      for (let i = 0; i < 48; i++) if (bitCounts[i] > 0) weak.push(i);
      weak.sort((a, b) => reliability[a] - reliability[b]);
      const weakPool = weak.slice(0, 16);
      const bits2 = Uint8Array.from(votedBits);
      const payload = new Uint8Array(6);
      const tryCandidate = (flips) => {
        for (let i = 0; i < 6; i++) {
          let byte = 0;
          for (let b = 0; b < 8; b++) byte = byte << 1 | bits2[i * 8 + b];
          payload[i] = byte;
        }
        const crc = stegoCrc16(payload);
        let mismatches = 0;
        for (let i = 48; i < 64 && mismatches + flips <= budget; i++) {
          if (!bitCounts[i]) continue;
          const byte = i < 56 ? crc >> 8 & 255 : crc & 255;
          if ((byte >> 7 - (i & 7) & 1) !== votedBits[i]) mismatches++;
        }
        if (flips + mismatches > budget) return null;
        const mac = stegoMac16(key, payload);
        const checkBytes = [crc >> 8 & 255, crc & 255, mac >> 8 & 255, mac & 255];
        for (let i = 64; i < 80 && mismatches + flips <= budget; i++) {
          if (!bitCounts[i]) continue;
          const expected = checkBytes[i - 48 >> 3] >> 7 - (i & 7) & 1;
          if (expected !== votedBits[i]) mismatches++;
        }
        for (let i = 80; i < 96 && mismatches + flips <= budget; i++) {
          if (bitCounts[i] && ROBUST_MARKER_BITS[i - 80] !== votedBits[i]) mismatches++;
        }
        if (flips + mismatches > budget) return null;
        const decoded = new Uint8Array(96);
        decoded.set(bits2.subarray(0, 48), 0);
        for (let i = 48; i < 80; i++) decoded[i] = checkBytes[i - 48 >> 3] >> 7 - (i & 7) & 1;
        for (let i = 80; i < 96; i++) decoded[i] = ROBUST_MARKER_BITS[i - 80];
        return { bits: decoded, corrections: flips + mismatches, tagScheme: "mac", erasureDecoded: true, erasedBits: erasedTotal };
      };
      const enumerate = (flipSet) => {
        for (const i of flipSet) bits2[i] ^= 1;
        const combos = 1 << erasedPayload.length;
        for (let mask = 0; mask < combos; mask++) {
          for (let j = 0; j < erasedPayload.length; j++) {
            bits2[erasedPayload[j]] = mask >> j & 1;
          }
          const hit2 = tryCandidate(flipSet.length);
          if (hit2) return hit2;
        }
        for (const i of flipSet) bits2[i] ^= 1;
        return null;
      };
      let hit = enumerate([]);
      if (!hit && erasedPayload.length <= 17) {
        for (const i of weakPool) {
          hit = enumerate([i]);
          if (hit) break;
        }
      }
      if (!hit && erasedPayload.length <= 14) {
        outer: for (let a = 0; a < weakPool.length; a++) {
          for (let b = a + 1; b < weakPool.length; b++) {
            hit = enumerate([weakPool[a], weakPool[b]]);
            if (hit) break outer;
          }
        }
      }
      return hit;
    };
    const standardErasureAssist = () => {
      let sparse = 0;
      for (let i = 0; i < codeLength; i++) if (bitCounts[i] < 2) sparse++;
      const erased = codeLength - observedBitsPre;
      if (sparse < 1 || sparse > 6 || observedBitsPre < 60) return null;
      if (meanAbsPre < 2 || preAgreement < 0.85 || cellLen < codeLength * 3) return null;
      const fixed = correctStegoBits(votedBits, reliability, key, 3);
      if (fixed.corrections < 0 || fixed.tagScheme !== "mac") return null;
      return { ...fixed, erasureDecoded: true, erasedBits: erased };
    };
    const bchAttempt = () => {
      if (!repairable) return null;
      const zeroVote = [];
      const byReliability = [];
      for (let i = 0; i < codeLength; i++) {
        if (bitCounts[i] === 0) zeroVote.push(i);
        else byReliability.push(i);
      }
      byReliability.sort((a, b) => reliability[a] - reliability[b]);
      if (zeroVote.length <= 36) {
        const erasureSets = [zeroVote];
        if (zeroVote.length <= 28) erasureSets.push([...zeroVote, ...byReliability.slice(0, 8)]);
        if (zeroVote.length <= 20) erasureSets.push([...zeroVote, ...byReliability.slice(0, 16)]);
        for (const set of erasureSets) {
          const hit = bchStegoDecode(votedBits, set, key);
          if (hit) {
            return {
              bits: hit.bits,
              corrections: hit.errors,
              tagScheme: "mac",
              erasureDecoded: hit.erasures > 0,
              _bchBudget: 2 * hit.errors + hit.erasures,
              _fingerprint: hit.fingerprint
            };
          }
        }
      }
      const observedOrder = [...byReliability].reverse();
      if (observedOrder.length >= 72 && (zeroVote.length >= 4 || preAgreement >= 0.8)) {
        const mismCap = Math.max(4, Math.floor((observedOrder.length - 64) * 0.3));
        const allowOsd = preAgreement >= 0.85 && osdEscalations < 48;
        if (allowOsd) osdEscalations++;
        const allowIsd = preAgreement >= 0.95 && meanAbsPre >= 2 && observedOrder.length >= 100 && isdEscalations < 8;
        if (allowIsd) isdEscalations++;
        const ml = bchStegoSolveObserved(votedBits, observedOrder, key, {
          maxMismatches: mismCap,
          osd: allowOsd,
          isdTrials: allowIsd ? 600 : 0,
          seedSalt: isdEscalations
        });
        if (ml && ml.mismatches <= mismCap) {
          const mismRate = ml.mismatches / Math.max(1, observedOrder.length - 64);
          return {
            bits: ml.bits,
            corrections: ml.mismatches,
            tagScheme: "mac",
            erasureDecoded: true,
            _mismRate: mismRate,
            _bchBudget: Math.round(120 * mismRate),
            _fingerprint: ml.fingerprint
          };
        }
      }
      return null;
    };
    let corrected = isV4 ? bchAttempt() : erasure ? robust ? erasureDecode() : standardErasureAssist() : null;
    if (!corrected) corrected = isV4 ? { bits: votedBits, corrections: -1, tagScheme: null } : !repairable ? { bits: votedBits, corrections: -1, tagScheme: null } : robust ? (() => {
      const macDepth = meanAbsPre >= 3.5 ? 5 : 3;
      const repaired = repairRobustStegoBits(reliability, votedBits, key, macDepth, "mac") || repairRobustStegoBits(reliability, votedBits, key, 3, "crc");
      return repaired ? { bits: repaired.bits, corrections: repaired.flips, tagScheme: repaired.tagScheme } : { bits: votedBits, corrections: -1, tagScheme: null };
    })() : correctStegoBits(votedBits, reliability, key, standardDepth);
    const bits = corrected.bits;
    const fingerprint = isV4 ? corrected._fingerprint || "" : robust ? robustStegoFingerprintFromBits(bits) : [...stegoBitsToBytes(bits).subarray(0, 6)].map((b) => b.toString(16).padStart(2, "0")).join("");
    const crcValid = corrected.corrections >= 0;
    let agreeing = 0;
    for (let ci = 0; ci < cellLen; ci++) {
      if (_cellScore[ci] >= 0 === !!bits[_cellBitIdx[ci]]) agreeing++;
    }
    const agreement = cellLen ? agreeing / cellLen : 0;
    const meanAbs = meanAbsPre;
    const evidence = Math.max(0, agreement - 0.64) * 2.4 + Math.min(0.55, Math.max(0, meanAbs - 1.4) / 8) - (isV4 ? (corrected._bchBudget || 0) / 6 : Math.max(0, corrected.corrections)) * 0.04;
    const confidence = crcValid ? Math.max(0, Math.min(0.99, 0.42 + evidence)) : Math.max(0, Math.min(0.49, evidence));
    const minBitCount = Math.min(...bitCounts);
    const observedBits = bitCounts.reduce((count, value) => count + (value > 0 ? 1 : 0), 0);
    const bitCoverageOk = isV4 ? observedBits >= 150 && cellLen >= 128 || corrected.erasureDecoded === true && observedBits >= 96 && cellLen >= 110 : robust ? observedBits >= 88 && cellLen >= 128 || // Erasure decodes trade coverage for cryptographic certainty:
    // the payload + recomputed CRC/MAC/marker must agree with every
    // observed check bit (<=3 disagreements), which noise cannot
    // manufacture — but a floor of 76 observed bits stays.
    corrected.erasureDecoded === true && observedBits >= 64 : minBitCount >= 2 && cellLen >= codeLength * 3 || corrected.erasureDecoded === true && observedBits >= 60 && cellLen >= codeLength * 3;
    const correctionCount = Math.max(0, corrected.corrections);
    const legacyScheme = corrected.tagScheme === "crc";
    const robustCorrectionOk = isV4 || !robust || correctionCount <= 3 || !legacyScheme && correctionCount <= 5 && meanAbs >= 3.5 && agreement >= 0.85;
    const standardCorrectionOk = isV4 || robust || (legacyScheme ? correctionCount <= 1 && agreement >= 0.95 : correctionCount <= 1 || meanAbs >= 2 && agreement >= 0.85);
    const bchBudget = corrected._bchBudget || 0;
    const v4CorrectionOk = !isV4 || (corrected._mismRate != null ? corrected._mismRate <= 0.1 || corrected._mismRate <= 0.2 && meanAbs >= 2 && agreement >= 0.82 || meanAbs >= 2.5 && agreement >= 0.82 : bchBudget <= 12 || bchBudget <= 24 && meanAbs >= 2.5 && agreement >= 0.82 || meanAbs >= 3.5 && agreement >= 0.88);
    const found = crcValid && agreement >= 0.72 && meanAbs >= 1.2 && cellLen >= 96 && bitCoverageOk && robustCorrectionOk && standardCorrectionOk && v4CorrectionOk;
    const _result = {
      found,
      fingerprint,
      profile: effectiveProfile,
      tagScheme: corrected.tagScheme ?? null,
      layoutVersion: concreteLayout,
      erasureDecoded: corrected.erasureDecoded === true,
      erasedBits: codeLength - observedBits,
      observedBits,
      minBitRepetitions: minBitCount,
      crcValid,
      corrections: Math.max(0, corrected.corrections),
      // Confidence describes the ACCEPTED verdict: a candidate the gates
      // rejected must never report near-certain confidence, or downstream
      // tooling will treat a manufactured CRC match as an attribution.
      confidence: Math.round((found ? confidence : Math.min(0.49, confidence)) * 1e3) / 1e3,
      agreement: Math.round(agreement * 1e3) / 1e3,
      meanSignal: Math.round(meanAbs * 100) / 100,
      cells: cellLen,
      offset: {
        x: Math.round(ox / cellW0 * 1e3) / 1e3,
        y: Math.round(oy / cellH0 * 1e3) / 1e3
      },
      geometry: {
        scaleX: Math.round(scaleX * 1e3) / 1e3,
        scaleY: Math.round(scaleY * 1e3) / 1e3,
        originX: Math.round(ox * 10) / 10,
        originY: Math.round(oy * 10) / 10
      },
      grid: { x: gx, y: gy },
      _evidence: evidence,
      _originX: ox,
      _originY: oy,
      _scaleX: scaleX,
      _scaleY: scaleY
    };
    if (isV4 && !found && observedBits >= 96 && cellLen >= 110 && meanAbs >= 1.2 && (forensicStash.length < 3 || evidence > forensicStash[forensicStash.length - 1].evidence)) {
      const geoKey = `${_result.geometry.scaleX}|${_result.geometry.scaleY}|${Math.round(_result.geometry.originX / 4)}|${Math.round(_result.geometry.originY / 4)}`;
      const dup = forensicStash.findIndex((e) => e.geoKey === geoKey);
      if (dup < 0 || evidence > forensicStash[dup].evidence) {
        const ord = [];
        for (let i = 0; i < codeLength; i++) if (bitCounts[i] > 0) ord.push(i);
        ord.sort((a, b) => reliability[b] - reliability[a]);
        const entry = {
          result: _result,
          evidence,
          meanAbs,
          cellLen,
          geoKey,
          votes: Uint8Array.from(votedBits),
          order: ord,
          cellScore: _cellScore.slice(0, cellLen),
          cellBitIdx: _cellBitIdx.slice(0, cellLen)
        };
        if (dup >= 0) forensicStash[dup] = entry;
        else forensicStash.push(entry);
        forensicStash.sort((a, b) => b.evidence - a.evidence);
        if (forensicStash.length > 3) forensicStash.length = 3;
      }
    }
    return _result;
  };
  let best = null;
  const consider = (candidate) => {
    const better = !best || candidate.found && !best.found || candidate.found === best.found && candidate._evidence > best._evidence || candidate.found === best.found && candidate._evidence === best._evidence && candidate.confidence > best.confidence;
    if (better) best = candidate;
    return candidate;
  };
  try {
    for (const fx of fractions) for (const fy of fractions) {
      consider(evaluate({ fx, fy }));
      if (best.found && best.confidence >= 0.92 && fx === 0 && fy === 0) break;
    }
    if (searchGeometry && !best?.found && (searchMirror || searchRotation) && !_mirrorProbe) {
      try {
        if (srcTop.length >= w * h * 4 && Number.isSafeInteger(w * h * 4)) {
          const entry = planesEntry(srcTop);
          for (const [axis, fx, fy] of searchMirror ? MIRROR_AXES : []) {
            const variant = mirroredVariant(entry, srcTop, w, h, axis, fx, fy);
            const mirrored = detectStegoFingerprint(variant, w, h, {
              key,
              gridX,
              gridY,
              profile,
              searchOffsets,
              searchGeometry: false,
              searchMirror: false,
              searchRotation: false,
              searchTilt: false,
              _mirrorProbe: true,
              _tiltProbe: true,
              _layoutVersion: concreteLayout,
              _planes: planesCache,
              _deadline: deadline
            });
            if (mirrored?.found) return { ...mirrored, mirrored: true, mirrorAxis: axis };
          }
          for (const clockwise of searchRotation ? [false, true] : []) {
            const variant = rotatedVariant(entry, srcTop, w, h, clockwise);
            const rotated = detectStegoFingerprint(variant, h, w, {
              key,
              gridX,
              gridY,
              profile,
              searchOffsets,
              searchGeometry: false,
              searchMirror: false,
              searchRotation: false,
              searchTilt: false,
              _mirrorProbe: true,
              _tiltProbe: true,
              _layoutVersion: concreteLayout,
              _planes: planesCache,
              _deadline: deadline
            });
            if (rotated?.found) return { ...rotated, rotated: clockwise ? 270 : 90 };
          }
          for (const anti of searchRotation ? [false, true] : []) {
            const variant = transposedVariant(entry, srcTop, w, h, anti);
            const transposed = detectStegoFingerprint(variant, h, w, {
              key,
              gridX,
              gridY,
              profile,
              searchOffsets,
              searchGeometry: false,
              searchMirror: false,
              searchRotation: false,
              searchTilt: false,
              _mirrorProbe: true,
              _tiltProbe: true,
              _layoutVersion: concreteLayout,
              _planes: planesCache,
              _deadline: deadline
            });
            if (transposed?.found) return { ...transposed, transposed: anti ? "anti" : "main" };
          }
        }
      } catch (probeErr) {
        if (probeErr === STEGO_TIMEOUT) throw probeErr;
      }
    }
    if (searchGeometry && !best?.found) {
      const scaleValues = [0.8, 0.85, 0.9, 0.95, 1, 1.05, 1 / 0.9, 1 / 0.85, 1.2, 1.25];
      const unique = (values) => [...new Set(values.map((v) => Math.round(v * 1e3) / 1e3))];
      const originRange = (span, extent) => {
        const min = Math.min(0, extent - span);
        const max = Math.max(0, extent - span);
        return { min, max, center: (min + max) / 2 };
      };
      const scaleCandidates = [];
      for (let cellX = -4; cellX <= 4; cellX++) {
        for (let cellY = -4; cellY <= 4; cellY++) {
          if (cellX === 0 && cellY === 0) continue;
          scaleCandidates.push(consider(evaluate({
            scaleX: 1,
            scaleY: 1,
            originX: cellX * cw,
            originY: cellY * ch
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
                scaleX,
                scaleY,
                originX,
                originY
              })));
            }
          }
        }
      }
      if (!best?.found) {
        const deepScales = [0.65, 0.7, 0.75, 1 / 0.88, 1 / 0.75, 1.38, 1 / 0.7, 1 / 0.65];
        for (const scaleX of deepScales) {
          const rangeX = originRange(gx * cw * scaleX, w);
          for (const scaleY of deepScales) {
            const rangeY = originRange(gy * ch * scaleY, h);
            for (const originX of unique([rangeX.min, rangeX.center, rangeX.max])) {
              for (const originY of unique([rangeY.min, rangeY.center, rangeY.max])) {
                scaleCandidates.push(consider(evaluate({
                  scaleX,
                  scaleY,
                  originX,
                  originY
                })));
              }
            }
          }
        }
      }
      if (!best?.found) {
        const seedPairs = [];
        for (const s of [0.55, 0.6, 2 / 3, 1.5, 1 / 0.6, 16 / 9, 1 / 0.55]) seedPairs.push([s, s]);
        for (const s of [1 / 0.75, 1 / 0.7, 1.5, 1 / 0.65, 1 / 0.6, 16 / 9]) {
          seedPairs.push([s, 1], [1, s]);
        }
        for (const s of [0.65, 0.7, 0.75]) seedPairs.push([s, 1], [1, s]);
        for (const [scaleX, scaleY] of seedPairs) {
          const rangeX = originRange(gx * cw * scaleX, w);
          const rangeY = originRange(gy * ch * scaleY, h);
          for (const originX of unique([rangeX.min, rangeX.center, rangeX.max])) {
            for (const originY of unique([rangeY.min, rangeY.center, rangeY.max])) {
              scaleCandidates.push(consider(evaluate({ scaleX, scaleY, originX, originY })));
            }
          }
          if (best?.found) break;
        }
      }
      const originCandidates = [];
      const seenPairs = /* @__PURE__ */ new Set();
      for (const candidate of scaleCandidates.sort((a, b) => b._evidence - a._evidence)) {
        const key2 = `${Math.round(candidate._scaleX * 1e3)}:${Math.round(candidate._scaleY * 1e3)}`;
        if (seenPairs.has(key2)) continue;
        seenPairs.add(key2);
        const rangeX = originRange(gx * cw * candidate._scaleX, w);
        const rangeY = originRange(gy * ch * candidate._scaleY, h);
        const quarter = (range) => unique([
          range.min,
          range.min + (range.max - range.min) * 0.25,
          range.center,
          range.min + (range.max - range.min) * 0.75,
          range.max
        ]);
        for (const originX of quarter(rangeX)) {
          for (const originY of quarter(rangeY)) {
            originCandidates.push(consider(evaluate({
              scaleX: candidate._scaleX,
              scaleY: candidate._scaleY,
              originX,
              originY
            })));
          }
        }
        if (seenPairs.size >= 4) break;
      }
      const refinements = [];
      const seenGeometries = /* @__PURE__ */ new Set();
      for (const candidate of originCandidates.sort((a, b) => b._evidence - a._evidence)) {
        const key2 = `${Math.round(candidate._scaleX * 1e3)}:${Math.round(candidate._scaleY * 1e3)}:${Math.round(candidate._originX)}:${Math.round(candidate._originY)}`;
        if (seenGeometries.has(key2)) continue;
        seenGeometries.add(key2);
        refinements.push(candidate);
        if (refinements.length >= 3) break;
      }
      for (const coarseCandidate of refinements) {
        for (const fx of fractions) for (const fy of fractions) {
          consider(evaluate({
            scaleX: coarseCandidate._scaleX,
            scaleY: coarseCandidate._scaleY,
            originX: coarseCandidate._originX + fx * cw * coarseCandidate._scaleX,
            originY: coarseCandidate._originY + fy * ch * coarseCandidate._scaleY
          }));
        }
      }
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
                originX: leader._originX + gx * cw * (leader._scaleX - scaleX) / 2,
                originY: leader._originY + gy * ch * (leader._scaleY - scaleY) / 2
              }));
              if (best?.found) break;
            }
            if (best?.found) break;
          }
        }
      }
      if (!best?.found) {
        const descendFrom = (seed) => {
          let cur = seed;
          for (let round = 0; round < 2 && cur && !best?.found; round++) {
            const beforeScaleX = cur._scaleX, beforeScaleY = cur._scaleY;
            for (const f of [0.9, 0.94, 0.97, 1.03, 1.06, 1.11]) {
              const sx = cur._scaleX * f;
              consider(evaluate({
                scaleX: sx,
                scaleY: cur._scaleY,
                originX: cur._originX + gx * cw * (cur._scaleX - sx) / 2,
                originY: cur._originY
              }));
              const sy = cur._scaleY * f;
              consider(evaluate({
                scaleX: cur._scaleX,
                scaleY: sy,
                originX: cur._originX,
                originY: cur._originY + gy * ch * (cur._scaleY - sy) / 2
              }));
              if (best?.found) return;
            }
            cur = best;
            if (cur._scaleX === beforeScaleX && cur._scaleY === beforeScaleY) break;
          }
        };
        const descentSeeds = [];
        const descentSeen = /* @__PURE__ */ new Set();
        for (const cand of [best, ...originCandidates, ...scaleCandidates].filter(Boolean).sort((a, b) => b.meanSignal - a.meanSignal || b._evidence - a._evidence)) {
          const k = `${Math.round(cand._scaleX * 100)}:${Math.round(cand._scaleY * 100)}`;
          if (descentSeen.has(k)) continue;
          descentSeen.add(k);
          descentSeeds.push(cand);
          if (descentSeeds.length >= 6) break;
        }
        for (const leader of descentSeeds) {
          descendFrom(leader);
          if (best?.found) break;
        }
        if (!best?.found && best) {
          const rangeX = originRange(gx * cw * best._scaleX, w);
          const rangeY = originRange(gy * ch * best._scaleY, h);
          const roam = (r) => unique([r.min, r.min + (r.max - r.min) * 0.25, r.center, r.min + (r.max - r.min) * 0.75, r.max]);
          for (const originX of roam(rangeX)) {
            for (const originY of roam(rangeY)) {
              consider(evaluate({ scaleX: best._scaleX, scaleY: best._scaleY, originX, originY }));
            }
          }
        }
        if (!best?.found && best) {
          const landed = best;
          for (const fx of fractions) for (const fy of fractions) {
            consider(evaluate({
              scaleX: landed._scaleX,
              scaleY: landed._scaleY,
              originX: landed._originX + fx * cw * landed._scaleX,
              originY: landed._originY + fy * ch * landed._scaleY
            }));
            if (best?.found) break;
          }
        }
      }
    }
    if (best && !best.found && best.cells >= 96 && (robust && best.meanSignal >= 2 && best.agreement >= 0.8 || !robust && best.meanSignal >= 2 && best.agreement >= 0.85 && best.observedBits >= 60)) {
      consider(evaluate({
        scaleX: best._scaleX,
        scaleY: best._scaleY,
        originX: best._originX,
        originY: best._originY,
        erasure: true
      }));
    }
    if (best) {
      delete best._evidence;
      delete best._originX;
      delete best._originY;
      delete best._scaleX;
      delete best._scaleY;
    }
    if (!best?.found && searchTilt && !_tiltProbe) {
      try {
        if (srcTop.length >= w * h * 4 && Number.isSafeInteger(w * h * 4)) {
          const entry = planesEntry(srcTop);
          const confirmAt = (degreesCw, variants = false) => {
            const warpedFull = rotateRgba(srcTop, w, h, -degreesCw * Math.PI / 180);
            return detectStegoFingerprint(warpedFull, w, h, {
              key,
              gridX,
              gridY,
              profile,
              searchOffsets: true,
              searchGeometry,
              searchMirror: variants && searchMirror,
              searchRotation: variants && searchRotation,
              searchTilt: false,
              _tiltProbe: true,
              _layoutVersion: concreteLayout,
              _planes: planesCache,
              _deadline: deadline
            });
          };
          let tiltCandidates = entry.tiltCandidates || null;
          let tiltScreenHit = null;
          if (!tiltCandidates) {
            const proxyScale = Math.min(1, 960 / w);
            const pw = Math.max(64, Math.round(w * proxyScale));
            const ph = Math.max(64, Math.round(h * proxyScale));
            const proxy = proxyScale < 1 ? resampleRgba(srcTop, w, h, pw, ph) : srcTop;
            const cropCenter = (buf, bw, bh, frac) => {
              if (frac >= 1) return { buf, w: bw, h: bh };
              const cw2 = Math.max(64, Math.round(bw * frac));
              const ch2 = Math.max(64, Math.round(bh * frac));
              const ox = Math.round((bw - cw2) / 2), oy = Math.round((bh - ch2) / 2);
              const out = new Uint8Array(cw2 * ch2 * 4);
              for (let y = 0; y < ch2; y++) {
                out.set(buf.subarray(((oy + y) * bw + ox) * 4, ((oy + y) * bw + ox + cw2) * 4), y * cw2 * 4);
              }
              return { buf: out, w: cw2, h: ch2 };
            };
            const quickDetect = (degreesCw) => {
              const warped = rotateRgba(proxy, pw, ph, -degreesCw * Math.PI / 180);
              let bestHit = null;
              for (const frac of [1, 0.96, 0.92]) {
                const view = cropCenter(warped, pw, ph, frac);
                const hit = detectStegoFingerprint(view.buf, view.w, view.h, {
                  key,
                  gridX,
                  gridY,
                  profile,
                  searchOffsets: true,
                  searchGeometry: false,
                  searchMirror: false,
                  searchRotation: false,
                  searchTilt: false,
                  _mirrorProbe: true,
                  _tiltProbe: true,
                  _layoutVersion: concreteLayout,
                  _planes: planesCache,
                  _deadline: deadline
                });
                if (hit?.found) return hit;
                if (!bestHit || (hit?.meanSignal ?? 0) > (bestHit.meanSignal ?? 0)) bestHit = hit;
              }
              return bestHit;
            };
            const samples = [];
            for (let angle = -6; angle <= 6.001; angle += 0.5) {
              if (deadlineHit()) throw STEGO_TIMEOUT;
              if (Math.abs(angle) < 1e-9) continue;
              const hit = quickDetect(angle);
              if (hit?.found) {
                tiltScreenHit = { hit, angle };
                break;
              }
              samples.push([angle, hit?.meanSignal ?? 0]);
            }
            if (tiltScreenHit) {
              tiltCandidates = [tiltScreenHit.angle];
            } else if (samples.length >= 5) {
              const signals = samples.map((s) => s[1]);
              const sorted = [...signals].sort((a, b) => a - b);
              const baseline = sorted[Math.floor(sorted.length / 2)] ?? 0;
              let maxIdx = 0;
              for (let i = 1; i < signals.length; i++) if (signals[i] > signals[maxIdx]) maxIdx = i;
              const peak = signals[maxIdx];
              if (peak >= 1.2 && peak > baseline + 0.15) {
                const thresh = baseline + 0.25 * (peak - baseline);
                let lo = maxIdx, hi = maxIdx;
                while (lo > 0 && signals[lo - 1] > thresh) lo--;
                while (hi < signals.length - 1 && signals[hi + 1] > thresh) hi++;
                let wSum = 0, aSum = 0;
                for (let i = lo; i <= hi; i++) {
                  const weight = (signals[i] - baseline) ** 2;
                  wSum += weight;
                  aSum += weight * samples[i][0];
                }
                const centroid = wSum > 0 ? aSum / wSum : samples[maxIdx][0];
                tiltCandidates = [...new Set([
                  centroid,
                  samples[maxIdx][0],
                  centroid - 0.3,
                  centroid + 0.3
                ].map((a) => Math.round(a * 100) / 100))];
              }
            }
            entry.tiltCandidates = tiltCandidates;
          }
          if (tiltCandidates) {
            for (const angle of tiltCandidates) {
              const full = confirmAt(angle);
              if (full?.found) return { ...full, deskewed: Math.round(angle * 100) / 100 };
            }
            if (searchMirror || searchRotation) {
              const full = confirmAt(tiltCandidates[0], true);
              if (full?.found) return { ...full, deskewed: Math.round(tiltCandidates[0] * 100) / 100 };
            }
            if (tiltScreenHit) return { ...tiltScreenHit.hit, deskewed: Math.round(tiltScreenHit.angle * 100) / 100 };
          }
        }
      } catch (tiltErr) {
        if (tiltErr === STEGO_TIMEOUT) throw tiltErr;
      }
    }
    if (!best?.found && (searchMirror || searchRotation) && !_mirrorProbe) {
      try {
        if (srcTop.length >= w * h * 4 && Number.isSafeInteger(w * h * 4)) {
          const entry = planesEntry(srcTop);
          for (const [axis, fx, fy] of searchMirror ? MIRROR_AXES : []) {
            const variant = mirroredVariant(entry, srcTop, w, h, axis, fx, fy);
            const mirrored = detectStegoFingerprint(variant, w, h, {
              key,
              gridX,
              gridY,
              profile,
              searchOffsets,
              searchGeometry,
              searchMirror: false,
              searchRotation: false,
              searchTilt: false,
              _mirrorProbe: true,
              _tiltProbe: true,
              _layoutVersion: concreteLayout,
              _planes: planesCache,
              _deadline: deadline
            });
            if (mirrored?.found) return { ...mirrored, mirrored: true, mirrorAxis: axis };
          }
          for (const clockwise of searchRotation ? [false, true] : []) {
            const variant = rotatedVariant(entry, srcTop, w, h, clockwise);
            const rotated = detectStegoFingerprint(variant, h, w, {
              key,
              gridX,
              gridY,
              profile,
              searchOffsets,
              searchGeometry,
              searchMirror: false,
              searchRotation: false,
              searchTilt: false,
              _mirrorProbe: true,
              _tiltProbe: true,
              _layoutVersion: concreteLayout,
              _planes: planesCache,
              _deadline: deadline
            });
            if (rotated?.found) return { ...rotated, rotated: clockwise ? 270 : 90 };
          }
          for (const anti of searchRotation ? [false, true] : []) {
            const variant = transposedVariant(entry, srcTop, w, h, anti);
            const transposed = detectStegoFingerprint(variant, h, w, {
              key,
              gridX,
              gridY,
              profile,
              searchOffsets,
              searchGeometry,
              searchMirror: false,
              searchRotation: false,
              searchTilt: false,
              _mirrorProbe: true,
              _tiltProbe: true,
              _layoutVersion: concreteLayout,
              _planes: planesCache,
              _deadline: deadline
            });
            if (transposed?.found) return { ...transposed, transposed: anti ? "anti" : "main" };
          }
        }
      } catch (probeErr) {
        if (probeErr === STEGO_TIMEOUT) throw probeErr;
      }
    }
  } catch (err) {
    if (err !== STEGO_TIMEOUT) throw err;
    if (!best) {
      return {
        found: false,
        fingerprint: "",
        profile: effectiveProfile,
        tagScheme: null,
        layoutVersion: concreteLayout,
        erasureDecoded: false,
        erasedBits: 0,
        observedBits: 0,
        minBitRepetitions: 0,
        crcValid: false,
        corrections: 0,
        confidence: 0,
        agreement: 0,
        meanSignal: 0,
        cells: 0,
        offset: { x: 0, y: 0 },
        geometry: { scaleX: 1, scaleY: 1, originX: 0, originY: 0 },
        grid: { x: gx, y: gy },
        timedOut: true
      };
    }
    if (isV4 && !best?.found && forensicStash.length && !_mirrorProbe && !_tiltProbe && forensicStash[0].evidence >= STASH_DEEP_MIN_EVIDENCE) {
      try {
        const deep = deepForensicTry(forensicStash[0], 2500, 97);
        if (deep) return deep;
      } catch {
      }
    }
    delete best._evidence;
    delete best._originX;
    delete best._originY;
    delete best._scaleX;
    delete best._scaleY;
    best.timedOut = true;
    return best;
  }
  if (!best?.found && isV4 && !_mirrorProbe && !_tiltProbe) {
    for (let si = 0; si < forensicStash.length; si++) {
      if (deadlineHit()) break;
      const s = forensicStash[si];
      if (s.evidence < STASH_DEEP_MIN_EVIDENCE) continue;
      try {
        const deep = deepForensicTry(s, 4e3, 77 + si);
        if (deep) return deep;
      } catch {
      }
    }
  }
  return best;
}

// src/core/stego-assay.js
function assayStegoEmbed(rgba, w, h, {
  key = "",
  profile = "robust",
  strength = 6,
  gridX,
  gridY,
  verify = false,
  layoutVersion = 3
} = {}) {
  const src = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  const robust = profile === "robust";
  const effectiveGridX = gridX ?? (robust ? 20 : 24);
  const effectiveGridY = gridY ?? (robust ? 14 : 16);
  const { gx, gy } = stegoGrid(w, h, effectiveGridX, effectiveGridY);
  const { luma, integral } = buildLumaIntegral(src, w, h);
  const rectSum = (x0, y0, x1, y1) => integral[y1 * (w + 1) + x1] - integral[y0 * (w + 1) + x1] - integral[y1 * (w + 1) + x0] + integral[y0 * (w + 1) + x0];
  let smoothCells = 0;
  let binaryCells = 0;
  let cells = 0;
  for (let cy = 0; cy < gy; cy++) {
    const y0 = Math.floor(cy * h / gy), y1 = Math.floor((cy + 1) * h / gy);
    for (let cx = 0; cx < gx; cx++) {
      const x0 = Math.floor(cx * w / gx), x1 = Math.floor((cx + 1) * w / gx);
      const n = (x1 - x0) * (y1 - y0);
      if (n < 16) continue;
      cells++;
      const mean = rectSum(x0, y0, x1, y1) / n;
      let extreme = 0;
      let sq = 0;
      const step = Math.max(1, Math.floor(n / 256));
      let sampled = 0;
      for (let y = y0; y < y1; y += 2) {
        for (let x = x0; x < x1; x += 2 * step) {
          const v = luma[y * w + x];
          sq += (v - mean) * (v - mean);
          if (v < 64 || v > 191) extreme++;
          sampled++;
        }
      }
      const std = sampled ? Math.sqrt(sq / sampled) : 0;
      if (std < 8) smoothCells++;
      if (sampled && extreme / sampled > 0.85 && std > 40) binaryCells++;
    }
  }
  const smoothFraction = cells ? smoothCells / cells : 0;
  const binaryFraction = cells ? binaryCells / cells : 0;
  const measure = (atStrength) => {
    const marked = embedStegoFingerprint(src, w, h, "archx-assay", {
      key,
      profile,
      strength: atStrength,
      gridX,
      gridY,
      layoutVersion
    });
    let mse = 0, maxDelta = 0;
    for (let i = 0; i < src.length; i += 4) {
      for (let c = 0; c < 3; c++) {
        const d = marked[i + c] - src[i + c];
        mse += d * d;
        if (Math.abs(d) > maxDelta) maxDelta = Math.abs(d);
      }
    }
    mse /= src.length / 4 * 3;
    const psnr = mse === 0 ? Infinity : Math.round(10 * Math.log10(255 * 255 / mse) * 10) / 10;
    return { marked, psnr, maxDelta };
  };
  const base = measure(strength);
  const result = {
    profile,
    strength,
    layoutVersion,
    grid: { x: gx, y: gy },
    psnr: base.psnr,
    maxChannelDelta: base.maxDelta,
    smoothFraction: Math.round(smoothFraction * 1e3) / 1e3,
    binaryFraction: Math.round(binaryFraction * 1e3) / 1e3,
    contentClass: binaryFraction > 0.35 ? "binary-graphic" : smoothFraction > 0.7 ? "flat-minimal" : "photo-textured",
    verifiedAtStrength: null,
    recommendedStrength: strength,
    warnings: []
  };
  const codeBits = layoutVersion === 4 ? 188 : robust ? 96 : 64;
  if (gx * gy < codeBits) {
    result.warnings.push(`grid has only ${gx * gy} cells for a ${codeBits}-bit codeword: some bits get no cell at this size \u2014 use a larger delivery size`);
  }
  if (result.contentClass === "binary-graphic") {
    result.warnings.push("near-binary high-contrast content (UI/text/periodic graphics) is StegoMark's documented weak class; expect poor recovery without much higher strength");
  }
  if (result.psnr < 32) {
    result.warnings.push(`predicted PSNR ${result.psnr} dB at strength ${strength}: macro-cell shading may be visible on smooth gradients \u2014 judge on your own catalog, not on the word "invisible"`);
  }
  if (verify) {
    for (const candidate of [strength, strength + 2, strength + 4, 16]) {
      if (candidate > 16) break;
      const trial = candidate === strength ? base : measure(candidate);
      const hit = detectStegoFingerprint(trial.marked, w, h, { key, profile, gridX, gridY, layoutVersion });
      if (hit.found) {
        result.verifiedAtStrength = candidate;
        result.recommendedStrength = candidate;
        if (candidate !== strength) result.psnr = trial.psnr;
        break;
      }
    }
    if (result.verifiedAtStrength === null) {
      result.warnings.push("detector did NOT recover a fresh mark even at maximum strength: this content class is outside the embedder envelope \u2014 rely on visible marks/metadata, not StegoMark");
    }
  }
  return Object.freeze(result);
}
function assayStegoCollusion(rgba, w, h, candidates, {
  key = "",
  profile = "robust",
  gridX,
  gridY,
  layoutVersion = 3,
  geometry = null
} = {}) {
  const src = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  if (!Number.isSafeInteger(w * h * 4) || src.length < w * h * 4) {
    throw new Error("Archx stego assay: pixel buffer is smaller than w\xD7h\xD74");
  }
  if (w < 64 || h < 64) throw new Error("Archx stego assay: image too small (minimum 64\xD764)");
  if (!Array.isArray(candidates) || candidates.length === 0 || candidates.length > 4096) {
    throw new Error("Archx stego assay: candidates must be an array of 1..4096 entries");
  }
  const robust = profile === "robust";
  const v4 = layoutVersion === 4;
  const layout = layoutVersion === 1 ? 1 : layoutVersion === 2 ? 2 : 3;
  const rowSegments = STEGO_ROW_SEGMENTS;
  const columnBands = 4;
  const effectiveGridX = gridX ?? (robust ? 20 : 24);
  const effectiveGridY = gridY ?? (robust ? 14 : 16);
  const { gx, gy } = stegoGrid(w, h, effectiveGridX, effectiveGridY);
  const cellCount = gx * gy;
  const cw = w / gx, ch = h / gy;
  const scaleX = geometry?.scaleX > 0 ? geometry.scaleX : 1;
  const scaleY = geometry?.scaleY > 0 ? geometry.scaleY : 1;
  const originX = geometry?.originX ?? 0;
  const originY = geometry?.originY ?? 0;
  const { integral } = buildLumaIntegral(src, w, h);
  const rectSum = (rx0, ry0, rx1, ry1) => integral[ry1 * (w + 1) + rx1] - integral[ry0 * (w + 1) + rx1] - integral[ry1 * (w + 1) + rx0] + integral[ry0 * (w + 1) + rx0];
  const readingsByKey = /* @__PURE__ */ new Map();
  const readCells = (readKey) => {
    const { order, polarity, segmentPolarity } = robust ? robustStegoLayout(cellCount, readKey, layout) : stegoLayout(cellCount, readKey, layout);
    const readings = new Float64Array(cellCount);
    readings.fill(NaN);
    const cellW0 = cw * scaleX, cellH0 = ch * scaleY;
    for (let cy = 0; cy < gy; cy++) {
      const rawY0 = originY + cy * cellH0;
      const y0 = Math.max(0, Math.round(rawY0));
      const y1 = Math.min(h, Math.round(rawY0 + cellH0));
      if (y1 - y0 < 2 || (y1 - y0) / cellH0 < 0.45) continue;
      for (let cx = 0; cx < gx; cx++) {
        const rawX0 = originX + cx * cellW0;
        const x0 = Math.max(0, Math.round(rawX0));
        const x1 = Math.min(w, Math.round(rawX0 + cellW0));
        if (x1 - x0 < 4 || (x1 - x0) / cellW0 < 0.45) continue;
        const cellIndex = cy * gx + cx;
        const responses = [];
        let scoreSum = 0, weightSum = 0, validSegments = 0;
        for (let segment = 0; segment < rowSegments; segment++) {
          const ry0 = Math.max(y0, Math.round(rawY0 + segment * cellH0 / rowSegments));
          const ry1 = Math.min(y1, Math.round(rawY0 + (segment + 1) * cellH0 / rowSegments));
          if (ry1 <= ry0) continue;
          const means = [];
          let weight = Infinity, complete = true;
          for (let band = 0; band < columnBands; band++) {
            const rx0 = Math.max(x0, Math.round(rawX0 + band * cellW0 / columnBands));
            const rx1 = Math.min(x1, Math.round(rawX0 + (band + 1) * cellW0 / columnBands));
            if (rx1 <= rx0) {
              complete = false;
              break;
            }
            means[band] = rectSum(rx0, ry0, rx1, ry1) / ((rx1 - rx0) * (ry1 - ry0));
            weight = Math.min(weight, (rx1 - rx0) * (ry1 - ry0));
          }
          if (!complete) continue;
          validSegments++;
          const response = -(-means[0] + 3 * means[1] - 3 * means[2] + means[3]) / 8;
          const signed = response * polarity[cellIndex] * segmentPolarity[cellIndex * rowSegments + segment];
          responses.push(signed);
          scoreSum += signed * weight;
          weightSum += weight;
        }
        if (!weightSum || validSegments < 2) continue;
        if (robust && responses.length >= 3) {
          const sorted = [...responses].sort((a, b) => a - b);
          readings[cellIndex] = sorted[Math.floor(sorted.length / 2)];
        } else {
          readings[cellIndex] = scoreSum / weightSum;
        }
      }
    }
    return { readings, order };
  };
  const prepared = candidates.map((candidate) => {
    const candKey = candidate?.key ?? key;
    if (!readingsByKey.has(candKey)) readingsByKey.set(candKey, readCells(candKey));
    const fingerprint = stegoFingerprint(candidate?.payload ?? "");
    const bits = v4 ? bchStegoCodeBits(fingerprint, candKey) : robust ? robustStegoCodeBits(fingerprint, candKey, "mac") : stegoCodeBits(fingerprint, candKey, "mac");
    return { candidate, candKey, fingerprint, bits };
  });
  const constantBitsByKey = /* @__PURE__ */ new Map();
  for (const p of prepared) {
    if (!constantBitsByKey.has(p.candKey)) {
      const group = prepared.filter((q) => q.candKey === p.candKey);
      const constants = new Uint8Array(p.bits.length);
      if (group.length > 1) {
        for (let b = 0; b < constants.length; b++) {
          constants[b] = group.every((q) => q.bits[b] === group[0].bits[b]) ? 1 : 0;
        }
      }
      constantBitsByKey.set(p.candKey, constants);
    }
  }
  const results = prepared.map(({ candidate, candKey, fingerprint, bits }) => {
    const { readings, order } = readingsByKey.get(candKey);
    const constants = constantBitsByKey.get(candKey);
    const bitSum = new Float64Array(bits.length);
    const bitCount = new Uint16Array(bits.length);
    let cells = 0, agree = 0;
    for (let cell = 0; cell < cellCount; cell++) {
      const reading = readings[cell];
      if (!Number.isFinite(reading)) continue;
      const bitIndex = order[cell] % bits.length;
      bitSum[bitIndex] += reading;
      bitCount[bitIndex]++;
      if (reading >= 0 === (bits[bitIndex] === 1)) agree++;
      cells++;
    }
    let usedBits = 0, signedSum = 0, absSum = 0;
    for (let b = 0; b < bits.length; b++) {
      if (constants[b] || bitCount[b] === 0) continue;
      const soft = bitSum[b] / bitCount[b];
      signedSum += soft * (bits[b] ? 1 : -1);
      absSum += soft * soft;
      usedBits++;
    }
    const score = usedBits ? signedSum / usedBits : 0;
    const sigma = usedBits ? Math.sqrt(absSum / usedBits) : 0;
    const zScore = sigma > 0 ? score * Math.sqrt(usedBits) / sigma : 0;
    return {
      id: candidate?.id ?? null,
      fingerprint,
      score: Math.round(score * 1e3) / 1e3,
      zScore: Math.round(zScore * 100) / 100,
      cellAgreement: cells ? Math.round(agree / cells * 1e3) / 1e3 : 0,
      cells,
      bits: usedBits
    };
  });
  results.sort((a, b) => b.zScore - a.zScore);
  return {
    results,
    cells: results[0]?.cells ?? 0,
    geometry: { scaleX, scaleY, originX, originY },
    profile: robust ? "robust" : "standard"
  };
}

// src/core/perceptual.js
var DCT_COSINES_32x8 = (() => {
  const table = new Float64Array(32 * 8);
  for (let x = 0; x < 32; x++) {
    for (let u = 0; u < 8; u++) table[x * 8 + u] = Math.cos((2 * x + 1) * u * Math.PI / (2 * 32));
  }
  return table;
})();
var _weightsCache = /* @__PURE__ */ new Map();
function cachedWeights(w, h, SIZE, colSpans, rowSpans) {
  const key = w + "x" + h;
  let table = _weightsCache.get(key);
  if (table) return table;
  const { starts: colStart, offsets: colOff, wts: colWts } = colSpans;
  const { starts: rowStart, offsets: rowOff, wts: rowWts } = rowSpans;
  table = new Float64Array(SIZE * SIZE);
  for (let y = 0; y < h; y++) {
    const oyBase = rowOff[y], oyCount = rowOff[y + 1] - oyBase;
    const oRow = rowStart[y];
    for (let x = 0; x < w; x++) {
      const oxBase = colOff[x], oxCount = colOff[x + 1] - oxBase;
      const oCol = colStart[x];
      for (let oyi = 0; oyi < oyCount; oyi++) {
        const wy = rowWts[oyBase + oyi];
        if (wy <= 0) continue;
        const rowBase = (oRow + oyi) * SIZE + oCol;
        for (let oxi = 0; oxi < oxCount; oxi++) {
          const wx = colWts[oxBase + oxi];
          if (wx <= 0) continue;
          table[rowBase + oxi] += wx * wy;
        }
      }
    }
  }
  _weightsCache.set(key, table);
  if (_weightsCache.size > 4) _weightsCache.delete(_weightsCache.keys().next().value);
  return table;
}
function perceptualFingerprint(rgba, w, h) {
  if (!Number.isSafeInteger(w) || !Number.isSafeInteger(h) || w < 1 || h < 1) {
    throw new RangeError("Archx: invalid image dimensions for perceptual fingerprint");
  }
  const src = asBytes(rgba);
  const expected = w * h * 4;
  if (!Number.isSafeInteger(expected) || src.length < expected) {
    throw new RangeError("Archx: RGBA buffer is smaller than the image");
  }
  const SIZE = 32;
  const small = new Float64Array(SIZE * SIZE);
  const spansFor = (n) => {
    const starts = new Int32Array(n);
    const offsets = new Int32Array(n + 1);
    const flat = [];
    for (let s = 0; s < n; s++) {
      const s0 = s * SIZE / n;
      const s1 = (s + 1) * SIZE / n;
      const start = Math.floor(s0);
      const end = Math.min(SIZE - 1, Math.ceil(s1) - 1);
      starts[s] = start;
      offsets[s] = flat.length;
      for (let o = start; o <= end; o++) flat.push(Math.min(s1, o + 1) - Math.max(s0, o));
    }
    offsets[n] = flat.length;
    return { starts, offsets, wts: Float64Array.from(flat) };
  };
  const colSpans = spansFor(w);
  const rowSpans = spansFor(h);
  const weights = cachedWeights(w, h, SIZE, colSpans, rowSpans);
  const { starts: colStart, offsets: colOff, wts: colWts } = colSpans;
  const { starts: rowStart, offsets: rowOff, wts: rowWts } = rowSpans;
  for (let y = 0; y < h; y++) {
    const rowOffset = y * w * 4;
    const oyBase = rowOff[y], oyCount = rowOff[y + 1] - oyBase;
    const oRow = rowStart[y];
    for (let x = 0; x < w; x++) {
      const i = rowOffset + x * 4;
      const gray = src[i + 3] === 255 ? (src[i] * 54 + src[i + 1] * 183 + src[i + 2] * 19) / 256 : (src[i] * 54 + src[i + 1] * 183 + src[i + 2] * 19) / 256 * (src[i + 3] / 255);
      const oxBase = colOff[x], oxCount = colOff[x + 1] - oxBase;
      const oCol = colStart[x];
      for (let oyi = 0; oyi < oyCount; oyi++) {
        const wy = rowWts[oyBase + oyi];
        if (wy <= 0) continue;
        const rowBase = (oRow + oyi) * SIZE + oCol;
        for (let oxi = 0; oxi < oxCount; oxi++) {
          const wx = colWts[oxBase + oxi];
          if (wx <= 0) continue;
          const idx = rowBase + oxi;
          small[idx] += gray * (wx * wy);
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
  return bits.toString(16).padStart(16, "0");
}
function normalizePerceptualFingerprint(value) {
  if (typeof value !== "string") return null;
  const normalized = value.trim().toLowerCase();
  return /^[0-9a-f]{16}$/.test(normalized) ? normalized : null;
}
function perceptualFingerprintDistance(a, b) {
  const left = normalizePerceptualFingerprint(a);
  const right = normalizePerceptualFingerprint(b);
  if (!left || !right) throw new TypeError("Archx: perceptual fingerprint must be 16 hex characters");
  let xor = BigInt("0x" + left) ^ BigInt("0x" + right);
  let distance = 0;
  while (xor > 0n) {
    distance += Number(xor & 1n);
    xor >>= 1n;
  }
  return distance;
}
function comparePerceptualFingerprints(a, b, { maxDistance = 10 } = {}) {
  if (!Number.isInteger(maxDistance) || maxDistance < 0 || maxDistance > 64) {
    throw new RangeError("Archx: perceptual fingerprint maxDistance must be an integer from 0 to 64");
  }
  const distance = perceptualFingerprintDistance(a, b);
  return Object.freeze({
    distance,
    similarity: 1 - distance / 64,
    match: distance <= maxDistance
  });
}

// src/client/native.js
var NATIVES = (() => {
  const g = globalThis;
  const grab = (obj, name) => {
    try {
      return obj && typeof obj[name] === "function" ? obj[name] : null;
    } catch {
      return null;
    }
  };
  const canvasProto = typeof HTMLCanvasElement !== "undefined" ? HTMLCanvasElement.prototype : null;
  const ctx2dProto = typeof CanvasRenderingContext2D !== "undefined" ? CanvasRenderingContext2D.prototype : null;
  const docProto = typeof Document !== "undefined" ? Document.prototype : null;
  const gl1Proto = typeof WebGLRenderingContext !== "undefined" ? WebGLRenderingContext.prototype : null;
  const gl2Proto = typeof WebGL2RenderingContext !== "undefined" ? WebGL2RenderingContext.prototype : null;
  const glMethods = {
    texImage2D: grab(gl2Proto, "texImage2D") || grab(gl1Proto, "texImage2D"),
    readPixels: grab(gl2Proto, "readPixels") || grab(gl1Proto, "readPixels"),
    drawArrays: grab(gl2Proto, "drawArrays") || grab(gl1Proto, "drawArrays"),
    drawElements: grab(gl2Proto, "drawElements") || grab(gl1Proto, "drawElements"),
    createTexture: grab(gl2Proto, "createTexture") || grab(gl1Proto, "createTexture"),
    bindTexture: grab(gl2Proto, "bindTexture") || grab(gl1Proto, "bindTexture"),
    bindFramebuffer: grab(gl2Proto, "bindFramebuffer") || grab(gl1Proto, "bindFramebuffer"),
    createFramebuffer: grab(gl2Proto, "createFramebuffer") || grab(gl1Proto, "createFramebuffer"),
    framebufferTexture2D: grab(gl2Proto, "framebufferTexture2D") || grab(gl1Proto, "framebufferTexture2D"),
    createShader: grab(gl2Proto, "createShader") || grab(gl1Proto, "createShader"),
    shaderSource: grab(gl2Proto, "shaderSource") || grab(gl1Proto, "shaderSource"),
    compileShader: grab(gl2Proto, "compileShader") || grab(gl1Proto, "compileShader"),
    createProgram: grab(gl2Proto, "createProgram") || grab(gl1Proto, "createProgram"),
    linkProgram: grab(gl2Proto, "linkProgram") || grab(gl1Proto, "linkProgram"),
    useProgram: grab(gl2Proto, "useProgram") || grab(gl1Proto, "useProgram"),
    getContextAttributes: grab(gl2Proto, "getContextAttributes") || grab(gl1Proto, "getContextAttributes"),
    // Uniform setters + draw-setup (red-team C1): these were called
    // directly, so a post-load prototype hook on uniform1f could
    // silently zero the temporal/lens modulation mid-draw and
    // microtask-read a clean frame. All render-path GL calls now go
    // through the captured functions (glNative).
    uniform1f: grab(gl2Proto, "uniform1f") || grab(gl1Proto, "uniform1f"),
    uniform2f: grab(gl2Proto, "uniform2f") || grab(gl1Proto, "uniform2f"),
    uniform1i: grab(gl2Proto, "uniform1i") || grab(gl1Proto, "uniform1i"),
    viewport: grab(gl2Proto, "viewport") || grab(gl1Proto, "viewport"),
    activeTexture: grab(gl2Proto, "activeTexture") || grab(gl1Proto, "activeTexture"),
    texParameteri: grab(gl2Proto, "texParameteri") || grab(gl1Proto, "texParameteri"),
    pixelStorei: grab(gl2Proto, "pixelStorei") || grab(gl1Proto, "pixelStorei"),
    generateMipmap: grab(gl2Proto, "generateMipmap") || grab(gl1Proto, "generateMipmap"),
    getUniformLocation: grab(gl2Proto, "getUniformLocation") || grab(gl1Proto, "getUniformLocation"),
    attachShader: grab(gl2Proto, "attachShader") || grab(gl1Proto, "attachShader"),
    getShaderParameter: grab(gl2Proto, "getShaderParameter") || grab(gl1Proto, "getShaderParameter"),
    getProgramParameter: grab(gl2Proto, "getProgramParameter") || grab(gl1Proto, "getProgramParameter"),
    createBuffer: grab(gl2Proto, "createBuffer") || grab(gl1Proto, "createBuffer"),
    bindBuffer: grab(gl2Proto, "bindBuffer") || grab(gl1Proto, "bindBuffer"),
    bufferData: grab(gl2Proto, "bufferData") || grab(gl1Proto, "bufferData"),
    enableVertexAttribArray: grab(gl2Proto, "enableVertexAttribArray") || grab(gl1Proto, "enableVertexAttribArray"),
    vertexAttribPointer: grab(gl2Proto, "vertexAttribPointer") || grab(gl1Proto, "vertexAttribPointer"),
    getExtension: grab(gl2Proto, "getExtension") || grab(gl1Proto, "getExtension")
  };
  const elementProto = typeof Element !== "undefined" ? Element.prototype : null;
  const streamProto = typeof ReadableStream !== "undefined" ? ReadableStream.prototype : null;
  const readerProto = (() => {
    try {
      const reader = new ReadableStream().getReader();
      const proto = Object.getPrototypeOf(reader);
      try {
        reader.releaseLock();
      } catch {
      }
      return proto;
    } catch {
      return null;
    }
  })();
  const subtleObj = (() => {
    try {
      return g.crypto?.subtle || null;
    } catch {
      return null;
    }
  })();
  const subtleProto = subtleObj ? Object.getPrototypeOf(subtleObj) : null;
  const grabDescriptor = (obj, name) => {
    try {
      return Object.getOwnPropertyDescriptor(obj, name) || null;
    } catch {
      return null;
    }
  };
  const canvasWidthDesc = grabDescriptor(canvasProto, "width");
  const canvasHeightDesc = grabDescriptor(canvasProto, "height");
  const smoothingQualityDesc = grabDescriptor(ctx2dProto, "imageSmoothingQuality");
  return Object.freeze({
    fnToString: Function.prototype.toString,
    // Dispatch primitive: `fn.call(...)` resolves Function.prototype.call
    // AT CALL TIME, so a post-load hook there intercepts every "captured
    // native" invocation despite the captures. All sensitive dispatch
    // goes through the captured Reflect.apply instead (nativeCall).
    reflectApply: grab(g.Reflect, "apply"),
    fnCall: Function.prototype.call,
    fnApply: Function.prototype.apply,
    fnBind: Function.prototype.bind,
    canvasWidthGet: canvasWidthDesc?.get || null,
    canvasWidthSet: canvasWidthDesc?.set || null,
    canvasHeightGet: canvasHeightDesc?.get || null,
    canvasHeightSet: canvasHeightDesc?.set || null,
    smoothingQualityGet: smoothingQualityDesc?.get || null,
    smoothingQualitySet: smoothingQualityDesc?.set || null,
    fetch: grab(g, "fetch"),
    // Extra hooks an external review demonstrated: a patched JSON.parse can
    // log every container header (which carries the per-response AES key),
    // a patched attachShadow can downgrade closed roots to open, and a
    // patched SubtleCrypto/getReader can skim plaintext or stream chunks.
    // Capture and USE the pristine versions on sensitive paths.
    jsonParse: (() => {
      try {
        return typeof JSON !== "undefined" && typeof JSON.parse === "function" ? JSON.parse : null;
      } catch {
        return null;
      }
    })(),
    attachShadow: grab(elementProto, "attachShadow"),
    streamGetReader: grab(streamProto, "getReader"),
    streamReaderRead: grab(readerProto, "read"),
    responseText: typeof Response !== "undefined" ? grab(Response.prototype, "text") : null,
    textDecode: typeof TextDecoder !== "undefined" ? grab(TextDecoder.prototype, "decode") : null,
    textEncode: typeof TextEncoder !== "undefined" ? grab(TextEncoder.prototype, "encode") : null,
    // WebCrypto: captured so core AES + DPoP signing bypass post-load hooks.
    cryptoObj: (() => {
      try {
        return g.crypto || null;
      } catch {
        return null;
      }
    })(),
    subtle: subtleObj,
    subtleImportKey: grab(subtleProto, "importKey"),
    subtleEncrypt: grab(subtleProto, "encrypt"),
    subtleDecrypt: grab(subtleProto, "decrypt"),
    subtleDigest: grab(subtleProto, "digest"),
    subtleSign: grab(subtleProto, "sign"),
    subtleGenerateKey: grab(subtleProto, "generateKey"),
    subtleExportKey: grab(subtleProto, "exportKey"),
    getRandomValues: (() => {
      try {
        return typeof g.crypto?.getRandomValues === "function" ? g.crypto.getRandomValues : null;
      } catch {
        return null;
      }
    })(),
    glGetContextAttributes: glMethods.getContextAttributes,
    createImageBitmap: grab(g, "createImageBitmap"),
    ImageCtor: typeof Image !== "undefined" ? Image : null,
    createObjectURL: typeof URL !== "undefined" ? grab(URL, "createObjectURL") : null,
    revokeObjectURL: typeof URL !== "undefined" ? grab(URL, "revokeObjectURL") : null,
    canvasGetContext: grab(canvasProto, "getContext"),
    canvasToDataURL: grab(canvasProto, "toDataURL"),
    canvasToBlob: grab(canvasProto, "toBlob"),
    ctxDrawImage: grab(ctx2dProto, "drawImage"),
    ctxGetImageData: grab(ctx2dProto, "getImageData"),
    ctxPutImageData: grab(ctx2dProto, "putImageData"),
    // 2D transform/state (red-team C2): save/restore/translate/scale
    // were called directly on the OFF-DOM unscramble buffer's context,
    // so a post-load restore() hook received `this.canvas` — the full
    // clean padded frame. Sensitive paths use ctxNative() now.
    ctxSave: grab(ctx2dProto, "save"),
    ctxRestore: grab(ctx2dProto, "restore"),
    ctxTranslate: grab(ctx2dProto, "translate"),
    ctxScale: grab(ctx2dProto, "scale"),
    ctxRotate: grab(ctx2dProto, "rotate"),
    ctxSetTransform: grab(ctx2dProto, "setTransform"),
    docCreateElement: grab(docProto, "createElement"),
    glTexImage2D: glMethods.texImage2D,
    glReadPixels: glMethods.readPixels,
    glDrawArrays: glMethods.drawArrays,
    glDrawElements: glMethods.drawElements,
    webgl: Object.freeze(glMethods),
    webgl1: Object.freeze(Object.fromEntries(Object.keys(glMethods).map((name) => [name, grab(gl1Proto, name)]))),
    webgl2: Object.freeze(Object.fromEntries(Object.keys(glMethods).map((name) => [name, grab(gl2Proto, name)])))
  });
})();
try {
  useJsonParser(NATIVES.jsonParse);
} catch {
}
try {
  useWebCrypto(NATIVES.subtle ? {
    subtle: NATIVES.subtle,
    importKey: NATIVES.subtleImportKey,
    encrypt: NATIVES.subtleEncrypt,
    decrypt: NATIVES.subtleDecrypt,
    digest: NATIVES.subtleDigest,
    getRandomValues: NATIVES.getRandomValues,
    cryptoObj: NATIVES.cryptoObj
  } : null);
} catch {
}
var SUBTLE_CAPTURED = {
  importKey: "subtleImportKey",
  encrypt: "subtleEncrypt",
  decrypt: "subtleDecrypt",
  digest: "subtleDigest",
  sign: "subtleSign",
  generateKey: "subtleGenerateKey",
  exportKey: "subtleExportKey"
};
function nativeCall(fn, receiver, args) {
  return NATIVES.reflectApply ? NATIVES.reflectApply(fn, receiver, args) : fn.call(receiver, ...args);
}
function subtleDo(name, ...args) {
  const fn = NATIVES[SUBTLE_CAPTURED[name]];
  if (fn && NATIVES.subtle) return nativeCall(fn, NATIVES.subtle, args);
  const subtle = globalThis.crypto?.subtle;
  return subtle[name](...args);
}
var sharedTextEncoder = (() => {
  try {
    return new TextEncoder();
  } catch {
    return null;
  }
})();
function utf8EncodeCaptured(str) {
  return NATIVES.textEncode && sharedTextEncoder ? nativeCall(NATIVES.textEncode, sharedTextEncoder, [str]) : new TextEncoder().encode(str);
}
function isNativeFn(fn) {
  if (typeof fn !== "function") return false;
  try {
    return /\[native code\]/.test(nativeCall(NATIVES.fnToString, fn, []));
  } catch {
    return false;
  }
}
function nativeFetch(url, options) {
  return NATIVES.fetch ? nativeCall(NATIVES.fetch, globalThis, [url, options]) : fetch(url, options);
}
function nativeCreateImageBitmap(source, opts) {
  return NATIVES.createImageBitmap ? nativeCall(NATIVES.createImageBitmap, globalThis, [source, opts]) : createImageBitmap(source, opts);
}
function setCanvasSize(canvas, width, height) {
  if (NATIVES.canvasWidthSet && NATIVES.canvasHeightSet) {
    nativeCall(NATIVES.canvasWidthSet, canvas, [width]);
    nativeCall(NATIVES.canvasHeightSet, canvas, [height]);
  } else {
    canvas.width = width;
    canvas.height = height;
  }
}
function makeCanvas(ownerDocument) {
  const doc = ownerDocument || document;
  return NATIVES.docCreateElement ? nativeCall(NATIVES.docCreateElement, doc, ["canvas"]) : doc.createElement("canvas");
}
function getNativeContext(canvas, type, attrs) {
  return NATIVES.canvasGetContext ? nativeCall(NATIVES.canvasGetContext, canvas, [type, attrs]) : canvas.getContext(type, attrs);
}
function nativeDrawImage(ctx, ...args) {
  return NATIVES.ctxDrawImage ? nativeCall(NATIVES.ctxDrawImage, ctx, args) : ctx.drawImage(...args);
}
function nativeGetImageData(ctx, x, y, w, h) {
  return NATIVES.ctxGetImageData ? nativeCall(NATIVES.ctxGetImageData, ctx, [x, y, w, h]) : ctx.getImageData(x, y, w, h);
}
function nativePutImageData(ctx, data, x, y) {
  return NATIVES.ctxPutImageData ? nativeCall(NATIVES.ctxPutImageData, ctx, [data, x, y]) : ctx.putImageData(data, x, y);
}
function nativeGlDrawArrays(gl, mode, first, count) {
  return NATIVES.glDrawArrays ? nativeCall(NATIVES.glDrawArrays, gl, [mode, first, count]) : gl.drawArrays(mode, first, count);
}
function glNative(gl, name, ...args) {
  const fn = NATIVES.webgl?.[name];
  return fn ? nativeCall(fn, gl, args) : gl[name](...args);
}
var CTX_NATIVE = {
  save: "ctxSave",
  restore: "ctxRestore",
  translate: "ctxTranslate",
  scale: "ctxScale",
  rotate: "ctxRotate",
  setTransform: "ctxSetTransform"
};
function ctxNative(ctx, name, ...args) {
  const fn = NATIVES[CTX_NATIVE[name]];
  return fn ? nativeCall(fn, ctx, args) : ctx[name](...args);
}

// src/client/temporal.js
var TEMPORAL_INTERLACE_PROFILES = Object.freeze({
  balanced60: Object.freeze({
    engine: "auto",
    layout: "checker",
    cellSize: 2,
    phases: 2,
    fill: "lowres",
    fillBlock: 12,
    fillStrength: 1,
    refreshHz: 60,
    minPhaseHz: 30,
    optimizeRefresh: true,
    respectReducedMotion: true,
    chroma: true
  }),
  pixels60: Object.freeze({
    engine: "auto",
    layout: "pixels",
    cellSize: 1,
    phases: 2,
    fill: "lowres",
    fillBlock: 8,
    fillStrength: 1,
    refreshHz: 60,
    minPhaseHz: 30,
    optimizeRefresh: true,
    respectReducedMotion: true,
    chroma: true
  }),
  strips60: Object.freeze({
    engine: "auto",
    layout: "strips",
    axis: "rows",
    cellSize: 2,
    phases: 2,
    fill: "lowres",
    fillBlock: 12,
    fillStrength: 1,
    refreshHz: 60,
    minPhaseHz: 30,
    optimizeRefresh: true,
    respectReducedMotion: true,
    chroma: true
  }),
  blocks60: Object.freeze({
    engine: "auto",
    layout: "blocks",
    cellSize: 8,
    phases: 2,
    fill: "lowres",
    fillBlock: 16,
    fillStrength: 1,
    refreshHz: 60,
    minPhaseHz: 30,
    optimizeRefresh: true,
    respectReducedMotion: true,
    chroma: true
  }),
  // Higher-cost capture-resistant profile: three phases mean each spatial
  // subset is fully present only once per three display frames (about 20 Hz
  // per subset on a 60 Hz display), hidden cells use keyed noise instead of a
  // locally useful average, and the active subset is not gain-compensated.
  // This is visibly harsher and still cannot stop multi-frame/video capture;
  // it is an explicit quality/security trade-off, not a new guarantee.
  fortress60: Object.freeze({
    engine: "auto",
    layout: "blocks",
    cellSize: 6,
    phases: 3,
    fill: "noise",
    fillBlock: 10,
    fillStrength: 1,
    noiseStrength: 0.55,
    hiddenScale: 0,
    activeGain: 1,
    refreshHz: 60,
    minPhaseHz: 20,
    optimizeRefresh: true,
    respectReducedMotion: true,
    chroma: true
  })
});
function clampTemporalNumber(value, fallback, min, max) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback;
}
function normalizeTemporalInterlace(raw) {
  if (raw == null || raw === false) return null;
  let input = {};
  let profileName = "balanced60";
  if (raw === true) {
    input = {};
  } else if (typeof raw === "string") {
    if (["false", "off", "none", "disabled"].includes(raw.toLowerCase())) return null;
    profileName = TEMPORAL_INTERLACE_PROFILES[raw] ? raw : "balanced60";
  } else if (isPlainClientObject(raw)) {
    input = raw;
    if (input.enabled === false || input.profile === false) return null;
    if (typeof input.profile === "string" && ["false", "off", "none", "disabled"].includes(input.profile.toLowerCase())) return null;
    if (input.enabled === void 0 && input.on === false) return null;
    if (typeof input.profile === "string" && TEMPORAL_INTERLACE_PROFILES[input.profile]) {
      profileName = input.profile;
    }
  } else {
    return null;
  }
  const merged = { ...TEMPORAL_INTERLACE_PROFILES[profileName] };
  for (const [key, value] of Object.entries(input)) {
    if (value !== void 0) merged[key] = value;
  }
  const engineRaw = String(merged.engine || merged.drawingMode || merged.renderMode || "auto").toLowerCase();
  const engine = ["shader", "gpu", "webgl", "fragment-shader"].includes(engineRaw) ? "shader" : ["frames", "frame", "pre-rendered", "prerendered", "canvas", "canvas2d", "2d"].includes(engineRaw) ? "frames" : "auto";
  const layoutRaw = String(merged.layout || merged.pattern || "checker").toLowerCase();
  const layout = layoutRaw === "bands" || layoutRaw === "stripes" ? "strips" : layoutRaw === "pixel" || layoutRaw === "pixel-level" ? "pixels" : layoutRaw === "squares" || layoutRaw === "checkerboard" ? "checker" : layoutRaw === "random-blocks" || layoutRaw === "random" ? "blocks" : ["pixels", "strips", "blocks", "checker"].includes(layoutRaw) ? layoutRaw : "checker";
  const requestedPhases = Math.round(clampTemporalNumber(merged.phases, 2, 2, 4));
  const refreshHz = clampTemporalNumber(merged.refreshHz ?? merged.displayHz, 60, 24, 480);
  const minPhaseHz = clampTemporalNumber(merged.minPhaseHz ?? merged.minimumPhaseHz, 30, 1, 240);
  const optimizeRefresh = merged.optimizeRefresh !== false && merged.optimizeForRefresh !== false;
  const maxPhasesAtRefresh = Math.max(2, Math.floor(refreshHz / minPhaseHz));
  const phases = optimizeRefresh ? Math.min(requestedPhases, maxPhasesAtRefresh) : requestedPhases;
  const hasCellInput = input.cellSize !== void 0 || input.stripSize !== void 0 || input.block !== void 0;
  const layoutDefaultCell = layout === "pixels" ? 1 : layout === "blocks" ? 8 : 2;
  const cellSize = Math.round(clampTemporalNumber(
    merged.cellSize ?? merged.stripSize ?? merged.block,
    hasCellInput ? layoutDefaultCell : TEMPORAL_INTERLACE_PROFILES[profileName].cellSize || layoutDefaultCell,
    1,
    64
  ));
  let effectiveCellSize = cellSize;
  if (!hasCellInput && input.layout !== void 0) effectiveCellSize = layoutDefaultCell;
  const fillRaw = String(merged.fill || merged.hiddenFill || "lowres").toLowerCase();
  const fill = ["blur", "pixelate", "pixelated", "local-average"].includes(fillRaw) ? "lowres" : fillRaw === "complementary" || fillRaw === "complement" ? "noise" : ["lowres", "dim", "black", "noise"].includes(fillRaw) ? fillRaw : "lowres";
  const fillStrength = clampTemporalNumber(merged.fillStrength, 1, 0, 1);
  const hiddenScale = clampTemporalNumber(merged.hiddenScale ?? merged.hiddenBrightness, 0.3, 0, 1);
  const hiddenEffectiveScale = fill === "black" ? 1 - fillStrength : fill === "dim" ? 1 - fillStrength + fillStrength * hiddenScale : 1;
  const compensation = clampTemporalNumber(
    merged.compensation ?? merged.brightnessCompensation,
    0.5,
    0,
    1
  );
  const exactGain = phases - (phases - 1) * hiddenEffectiveScale;
  const computedGain = fill === "black" || fill === "dim" ? 1 + compensation * (exactGain - 1) : 1;
  const activeGain = clampTemporalNumber(merged.activeGain, computedGain, 0.25, 4);
  return Object.freeze({
    profile: profileName,
    engine,
    layout,
    axis: merged.axis === "columns" || merged.axis === "vertical" ? "columns" : "rows",
    cellSize: effectiveCellSize,
    phases,
    requestedPhases,
    refreshHz,
    minPhaseHz,
    optimizeRefresh,
    phaseHz: refreshHz / phases,
    fill,
    fillBlock: Math.round(clampTemporalNumber(merged.fillBlock ?? merged.lowresBlock, 12, 2, 128)),
    fillStrength,
    hiddenScale,
    activeGain,
    noiseStrength: clampTemporalNumber(merged.noiseStrength ?? merged.strength, 0.16, 0, 0.65),
    chroma: merged.chroma !== false,
    respectReducedMotion: merged.respectReducedMotion !== false
  });
}
var limiter = {
  max: 6,
  active: 0,
  queue: [],
  queueHead: 0,
  run(fn) {
    return new Promise((resolve, reject) => {
      const job = () => {
        this.active++;
        Promise.resolve().then(fn).then(resolve, reject).finally(() => {
          this.active--;
          const next = this.queueHead < this.queue.length ? this.queue[this.queueHead++] : null;
          if (this.queueHead >= this.queue.length) {
            this.queue.length = 0;
            this.queueHead = 0;
          } else if (this.queueHead > 1024 && this.queueHead * 2 >= this.queue.length) {
            this.queue.splice(0, this.queueHead);
            this.queueHead = 0;
          }
          if (next) next();
        });
      };
      if (this.active < this.max) job();
      else this.queue.push(job);
    });
  }
};

// src/client/options.js
var DEFAULT_SOURCE_WIDTH_BUCKETS = Object.freeze([
  160,
  240,
  320,
  480,
  640,
  800,
  960,
  1200,
  1440,
  1600,
  1920,
  2240,
  2560
]);
var DEFAULTS = {
  mode: "shield",
  // 'lite' | 'shield' | 'vault' | 'fortress' | 'custom'
  renderer: "auto",
  // 'auto' | 'canvas' | 'webgl' — direct renderer flag (lets custom setups skip preset modes)
  fit: "cover",
  // 'cover' | 'contain' | 'fill'
  lazy: true,
  rootMargin: "500px",
  unloadOnExit: false,
  // gallery mode turns this on for huge grids
  shadow: "closed",
  // 'closed' | 'open' | 'none'
  grid: DEFAULT_GRID,
  scrambled: false,
  // source pixels are tile-scrambled
  planVersion: 1,
  // scramble plan derivation for container-less scrambled sources (1 = legacy 32-bit seed, 2 = 128-bit seed); .archx headers carry their own `pv` and win
  key: null,
  // scramble seed and/or AES key (see docs)
  aesKey: null,
  // base64 AES key for encrypted .archx payloads
  tokenEndpoint: null,
  // e.g. '/archx/token/'  (+ image id)
  tokenMethod: "POST",
  // token mint method; POST + X-Archx-Request avoids simple cross-site GET minting
  tokenTransport: "header",
  // 'header' | 'query' | 'auto' — header keeps bearer tokens out of image URLs/logs
  tokenBatch: false,
  // coalesce simultaneous POST mints into {basePath}/tokens (catalog/gallery presets enable it)
  tokenBatchEndpoint: null,
  // explicit batch endpoint; otherwise derived by replacing a trailing /token segment
  tokenBatchSize: 50,
  // maximum mints per batch HTTP request
  tokenBatchDelayMs: 8,
  // quiet-period coalescing window for gallery/page bursts
  tokenBatchMaxDelayMs: 50,
  // hard cap so a continuous trickle cannot starve the first mint
  assetManifest: null,
  // archx-build manifest URL or object for { assetId } sources
  assetManifestMaxBytes: 8 * 1024 * 1024,
  assetHttpCache: "default",
  // manifest/variant fetches may use browser/CDN HTTP caching
  assetIntegrity: "auto",
  // 'auto' | 'require' | 'off' — verify per-variant SHA-256 digests from the manifest
  assetManifestIntegrity: null,
  // optional 'sha256-<hex>' pin for a fetched manifest (archx-build prints it)
  httpCache: "no-store",
  // direct URL sources; token mint/payload requests always remain no-store
  fetchPriority: null,
  // null | 'high' | 'low' | 'auto' (hero images may use high; leave auto for galleries)
  proofOfPossession: "auto",
  // 'auto' | 'required' | 'off' — bind tokens to a non-extractable page key when WebCrypto allows
  allowedTokenOrigins: null,
  // exact extra origins allowed for token-returned payload URLs (endpoint origin is always allowed)
  fetchTimeoutMs: 2e4,
  // per-request network deadline (mint, payload, and direct sources)
  maxResponseBytes: 64 * 1024 * 1024,
  maxDecodedPixels: 4e7,
  // pre-decode header budget + post-decode bitmap budget
  maxDecodedDimension: 16384,
  onExtract: "black",
  // 'black' | 'lowres' | 'scrambled'
  taintReadback: "auto",
  // 'auto' | 'off' — origin-taint 2D display canvases so even prototype-call readbacks throw
  taintUrl: null,
  // explicit cross-origin 1x1 image URL for tainting; auto-derived from a cross-origin token endpoint when null
  splitCanvases: false,
  // shield+: one canvas per tile (hero images)
  splitGrid: 3,
  maxBackingWidth: 1920,
  // never paint a wider backing store than this
  dprCap: 3,
  // match modern retina/mobile displays instead of upscaling a 2x canvas
  sourceOversample: 2,
  // fetch a 2x derivative then supersample down (server entitlement still caps the signed width)
  maxSourceWidth: 2560,
  // client-side ceiling before the server's own entitlement cap
  sourceWidthBuckets: null,
  // canonical requested widths (catalog/gallery presets supply a ladder)
  qualityProfile: "high",
  // 'original' | 'high' | 'balanced' | 'catalog' | 'fast' (sets requestQuality + sampling unless overridden)
  requestQuality: null,
  // 1..100 | 'lossless' — honoured only when the server opts in with allowClientQuality
  networkAware: false,
  // honour Save-Data / slow effectiveType with a smaller derivative (Network Information API)
  cacheBitmap: true,
  // reuse a decoded bitmap for the same source in this page session
  bitmapCacheMaxEntries: 40,
  bitmapCacheMaxBytes: 256 * 1024 * 1024,
  // approximate decoded RGBA bytes in the shared LRU
  cachePayload: true,
  // retain the scrambled bytes privately so repaint/strict-memory recovery needs NO network reload
  cacheScope: null,
  // set per authenticated viewer/tenant so SPA account switches cannot reuse another viewer's bitmap
  reloadOnResize: "upscale",
  // 'never' | 'upscale' | 'always' — ordinary resizes repaint locally, never remint tokens
  resizeUpscaleFactor: 1.75,
  // only a much larger box may justify a fresh derivative under 'upscale'
  renderLoop: "auto",
  // 'auto' (static images draw on demand; temporal shield animates) | 'static' | 'continuous'
  temporalShield: null,
  // true | { strength, block, pattern, chroma, respectReducedMotion } — complementary frames a single screenshot cannot average
  temporalInterlace: null,
  // true | 'balanced60'|'pixels60'|'strips60'|'blocks60' | { profile, engine, layout, phases, cellSize, fill, refreshHz, ... }
  cameraShield: null,
  // experimental alias/profile for temporalShield aimed at rolling-shutter/Bayer cameras
  watermark: null,
  // string | { text, opacity, tile, corner }
  forensic: true,
  // invisible per-session block pattern (shield/vault/fortress)
  sessionId: null,
  // defaults to a random per-page-view id
  brand: "\xA9 Protected \xB7 Archnemix",
  retries: 2,
  credentials: "same-origin",
  integrity: "monitor",
  // 'off' | 'monitor' | 'lock' — hooked-API policy
  automation: "monitor",
  // 'off' | 'monitor' | 'lock' — headless/bot policy
  memory: "standard",
  // 'standard' | 'strict' — strict wipes decoded bitmaps ASAP
  localScramble: false,
  // fortress: GPU texture holds scrambled pixels even for plain sources
  lens: null,
  // anti-screenshot pointer lens: true | { radius, idlePixelate }
  captureShield: null,
  // true | { dynamicTrace, temporalPattern, text, opacity } (fortress enables)
  strikes: null,
  // attempt lockout: { blurAt, lockAt, lockMs } (fortress enables)
  debug: false,
  // enables _debug() internals hook — NEVER in production
  guards: {
    contextMenu: true,
    drag: true,
    copy: true,
    longPress: true,
    print: true,
    blurOnBlur: true,
    // blur while window unfocused (snipping tools)
    screenshotKeys: true,
    // best-effort PrintScreen reaction
    devtools: false
    // opt-in: blur while DevTools appears open
  },
  onAttempt: null,
  // (kind, instance) => void  — hook your logging
  onChallenge: null,
  // async ({id, reason}) => proofToken — server step-up (Turnstile/WebAuthn) integration
  onLoad: null,
  onError: null,
  onClick: null,
  onEvent: null,
  // (sanitizedEvent, instance) => void — generic monitoring/plugin hook; never receives tokens/keys/pixels
  alt: ""
};
var globalConfig = structuredCloneSafe(DEFAULTS);
function structuredCloneSafe(obj) {
  return JSON.parse(JSON.stringify(obj, (k, v) => typeof v === "function" ? void 0 : v));
}
function mergeOptions(opts = {}) {
  const clean = {};
  for (const [k, v] of Object.entries(opts)) if (v !== void 0) clean[k] = v;
  const merged = { ...globalConfig, ...clean };
  merged.guards = { ...globalConfig.guards };
  if (opts.guards) {
    for (const [k, v] of Object.entries(opts.guards)) if (v !== void 0) merged.guards[k] = v;
  }
  const qualityProfiles = {
    original: { requestQuality: "lossless", sourceOversample: 2, dprCap: 3 },
    high: { requestQuality: 95, sourceOversample: 2, dprCap: 3 },
    balanced: { requestQuality: 90, sourceOversample: 1.5, dprCap: 2.5 },
    catalog: { requestQuality: 88, sourceOversample: 1, dprCap: 2 },
    fast: { requestQuality: 82, sourceOversample: 1.25, dprCap: 2 }
  };
  const qp = qualityProfiles[merged.qualityProfile];
  if (qp) {
    if (clean.requestQuality === void 0 && merged.requestQuality == null) merged.requestQuality = qp.requestQuality;
    if (clean.sourceOversample === void 0 && clean.qualityProfile !== void 0) merged.sourceOversample = qp.sourceOversample;
    if (clean.dprCap === void 0 && clean.qualityProfile !== void 0) merged.dprCap = qp.dprCap;
  }
  const rendererValue = String(merged.renderer || "auto").toLowerCase();
  merged.renderer = rendererValue === "canvas2d" ? "canvas" : rendererValue === "canvas" || rendererValue === "webgl" ? rendererValue : "auto";
  const AUTOMATION_ALIASES = {
    allow: "off",
    ignore: "off",
    off: "off",
    none: "off",
    warn: "monitor",
    report: "monitor",
    degrade: "monitor",
    monitor: "monitor",
    block: "lock",
    deny: "lock",
    lock: "lock"
  };
  merged.automation = AUTOMATION_ALIASES[String(merged.automation ?? "monitor").toLowerCase()] ?? "monitor";
  const customRequested = merged.mode === "custom" || clean.mode === void 0 && clean.renderer !== void 0;
  if (customRequested) {
    merged.requestedMode = "custom";
    merged.mode = merged.renderer === "webgl" ? "vault" : "shield";
  }
  if (merged.mode === "lite" && clean.forensic === void 0) merged.forensic = false;
  if (merged.mode === "fortress") {
    merged.requestedMode = "fortress";
    merged.mode = "vault";
    if (clean.onExtract === void 0) merged.onExtract = "black";
    if (clean.integrity === void 0) merged.integrity = "lock";
    if (clean.memory === void 0) merged.memory = "strict";
    if (clean.localScramble === void 0) merged.localScramble = true;
    if (clean.forensic === void 0) merged.forensic = true;
    if (clean.captureShield === void 0) merged.captureShield = true;
    if (clean.temporalShield === void 0 && clean.cameraShield === void 0 && !normalizeTemporalInterlace(merged.temporalInterlace)) {
      merged.temporalShield = { strength: 0.16, block: 2, pattern: "checker", chroma: true };
    }
    if (clean.strikes === void 0) merged.strikes = { blurAt: 3, lockAt: 6, lockMs: 3e4 };
    if (!opts.guards || opts.guards.devtools === void 0) merged.guards.devtools = true;
  }
  return merged;
}
function sanitizeOptionsView(opts) {
  if (!opts) return opts;
  const sensitive = /* @__PURE__ */ new Set([
    "key",
    "aeskey",
    "cachescope",
    "sessionid",
    "token",
    "accesstoken",
    "refreshtoken",
    "secret",
    "password",
    "authorization",
    "cookie",
    "assetmanifest",
    "tainturl"
  ]);
  const seen = /* @__PURE__ */ new WeakMap();
  const clone = (value, keyName = "") => {
    if (sensitive.has(String(keyName).toLowerCase())) return value ? "[redacted]" : value;
    if (!value || typeof value !== "object") return value;
    if (seen.has(value)) return "[circular]";
    if (Array.isArray(value)) {
      const out2 = [];
      seen.set(value, out2);
      for (const item of value) out2.push(clone(item));
      return out2;
    }
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return value;
    const out = {};
    seen.set(value, out);
    for (const [k, v] of Object.entries(value)) out[k] = clone(v, k);
    return out;
  };
  return clone(opts);
}
var PRESETS = Object.freeze({
  gallery: Object.freeze({
    mode: "lite",
    qualityProfile: "catalog",
    sourceOversample: 1,
    dprCap: 2,
    lazy: true,
    unloadOnExit: true,
    cacheBitmap: true,
    cachePayload: true,
    renderLoop: "static",
    reloadOnResize: "never",
    tokenBatch: true,
    tokenBatchDelayMs: 20,
    tokenBatchMaxDelayMs: 150,
    sourceWidthBuckets: DEFAULT_SOURCE_WIDTH_BUCKETS,
    httpCache: "default",
    networkAware: true,
    bitmapCacheMaxEntries: 24,
    bitmapCacheMaxBytes: 128 * 1024 * 1024,
    guards: Object.freeze({ blurOnBlur: false })
  }),
  catalog: Object.freeze({
    mode: "lite",
    qualityProfile: "catalog",
    sourceOversample: 1,
    dprCap: 2,
    lazy: true,
    unloadOnExit: true,
    cacheBitmap: true,
    cachePayload: true,
    renderLoop: "static",
    reloadOnResize: "never",
    tokenBatch: true,
    tokenBatchDelayMs: 20,
    tokenBatchMaxDelayMs: 150,
    sourceWidthBuckets: DEFAULT_SOURCE_WIDTH_BUCKETS,
    httpCache: "default",
    networkAware: true,
    assetHttpCache: "default",
    bitmapCacheMaxEntries: 24,
    bitmapCacheMaxBytes: 128 * 1024 * 1024,
    guards: Object.freeze({ blurOnBlur: false })
  }),
  editorial: Object.freeze({
    mode: "shield",
    qualityProfile: "original",
    cacheBitmap: true,
    cachePayload: true,
    renderLoop: "static",
    reloadOnResize: "upscale",
    forensic: true
  }),
  commerce: Object.freeze({
    mode: "vault",
    qualityProfile: "original",
    onExtract: "black",
    cacheBitmap: true,
    cachePayload: true,
    renderLoop: "static",
    reloadOnResize: "upscale",
    forensic: true,
    captureShield: Object.freeze({ dynamicTrace: true, temporalPattern: true })
  }),
  marketplace: Object.freeze({
    mode: "vault",
    qualityProfile: "high",
    onExtract: "black",
    tokenBatch: true,
    cacheBitmap: true,
    cachePayload: true,
    renderLoop: "static",
    reloadOnResize: "upscale",
    forensic: true,
    captureShield: Object.freeze({ dynamicTrace: true, temporalPattern: true })
  }),
  screenshotResistant: Object.freeze({
    mode: "fortress",
    qualityProfile: "original",
    lens: true,
    temporalShield: Object.freeze({ strength: 0.16, block: 2, pattern: "checker", chroma: true }),
    captureShield: Object.freeze({ dynamicTrace: true, temporalPattern: true }),
    cacheBitmap: true,
    cachePayload: true,
    renderLoop: "auto",
    strikes: Object.freeze({ blurAt: 3, lockAt: 6, lockMs: 3e4 })
  })
});
function preset(name = "editorial", overrides = {}) {
  const base = PRESETS[name];
  if (!base) throw new Error(`Archx: unknown preset "${name}" (known: ${Object.keys(PRESETS).join(", ")})`);
  return {
    ...base,
    ...overrides,
    guards: { ...base.guards || {}, ...overrides.guards || {} }
  };
}
var pageSessionId = null;
function resetPageSession() {
  pageSessionId = null;
}
function sessionId() {
  if (globalConfig.sessionId) return globalConfig.sessionId;
  if (!pageSessionId) {
    const a = new Uint8Array(8);
    crypto.getRandomValues(a);
    pageSessionId = [...a].map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  return pageSessionId;
}
function getGlobalConfig() {
  return globalConfig;
}
function setGlobalConfig(next) {
  globalConfig = next;
}

// src/client/sampling.js
function fitRects(srcW, srcH, dstW, dstH, fit) {
  if (fit === "fill") return { sx: 0, sy: 0, sw: srcW, sh: srcH, dx: 0, dy: 0, dw: dstW, dh: dstH };
  const srcRatio = srcW / srcH;
  const dstRatio = dstW / dstH;
  if (fit === "contain") {
    let dw = dstW, dh = dstW / srcRatio;
    if (dh > dstH) {
      dh = dstH;
      dw = dstH * srcRatio;
    }
    return { sx: 0, sy: 0, sw: srcW, sh: srcH, dx: (dstW - dw) / 2, dy: (dstH - dh) / 2, dw, dh };
  }
  let sw = srcW, sh = srcH;
  if (srcRatio > dstRatio) sw = srcH * dstRatio;
  else sh = srcW / dstRatio;
  return { sx: (srcW - sw) / 2, sy: (srcH - sh) / 2, sw, sh, dx: 0, dy: 0, dw: dstW, dh: dstH };
}
function cyrb53(str, seed = 0) {
  let h1 = 3735928559 ^ seed;
  let h2 = 1103547991 ^ seed;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ h1 >>> 16, 2246822507) ^ Math.imul(h2 ^ h2 >>> 13, 3266489909);
  h2 = Math.imul(h2 ^ h2 >>> 16, 2246822507) ^ Math.imul(h1 ^ h1 >>> 13, 3266489909);
  return 4294967296 * (2097151 & h2) + (h1 >>> 0);
}
function cacheDigest(parts) {
  const raw = JSON.stringify(parts);
  return `v1:${raw.length}:${cyrb53(raw, 1).toString(36)}:${cyrb53(raw, 2).toString(36)}`;
}
function boundedInteger(value, fallback, min, max) {
  return Number.isInteger(value) && value >= min && value <= max ? value : fallback;
}
function normalizeSourceWidthBuckets(value) {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.filter((width) => Number.isInteger(width) && width >= 64 && width <= 16384))].sort((a, b) => a - b).slice(0, 64);
}
function canonicalSourceWidth(value, bucketsValue, maxWidth) {
  const max = Math.max(1, Math.floor(Number(maxWidth) || 1));
  const requested = Math.max(1, Math.min(max, Math.ceil(Number(value) || 1)));
  const buckets = normalizeSourceWidthBuckets(bucketsValue);
  if (!buckets.length) return requested;
  for (const bucket of buckets) {
    if (bucket >= requested && bucket <= max) return bucket;
  }
  const atOrBelowMax = buckets.filter((bucket) => bucket <= max);
  return atOrBelowMax.length ? atOrBelowMax[atOrBelowMax.length - 1] : requested;
}
function networkConnectionInfo() {
  try {
    const conn = typeof navigator !== "undefined" ? navigator.connection : null;
    if (!conn || typeof conn !== "object") return null;
    return {
      saveData: conn.saveData === true,
      effectiveType: typeof conn.effectiveType === "string" ? conn.effectiveType : ""
    };
  } catch {
    return null;
  }
}
function effectiveSampling(o) {
  let dprCap = Number.isFinite(Number(o.dprCap)) && Number(o.dprCap) > 0 ? Number(o.dprCap) : DEFAULTS.dprCap;
  let oversample = Number.isFinite(Number(o.sourceOversample)) && Number(o.sourceOversample) > 0 ? Number(o.sourceOversample) : 1;
  let requestQuality = o.requestQuality === "lossless" || Number.isInteger(o.requestQuality) && o.requestQuality >= 1 && o.requestQuality <= 100 ? o.requestQuality : null;
  if (o.networkAware === true) {
    const conn = networkConnectionInfo();
    const constrained = !!conn && (conn.saveData || conn.effectiveType === "slow-2g" || conn.effectiveType === "2g");
    const moderate = !!conn && !constrained && conn.effectiveType === "3g";
    if (constrained) {
      dprCap = Math.min(dprCap, 1);
      oversample = Math.min(oversample, 1);
      if (Number.isInteger(requestQuality)) requestQuality = Math.min(requestQuality, 72);
    } else if (moderate) {
      dprCap = Math.min(dprCap, 1.5);
      oversample = Math.min(oversample, 1);
      if (Number.isInteger(requestQuality)) requestQuality = Math.min(requestQuality, 82);
    }
  }
  return { dprCap, oversample, requestQuality };
}
var taintImageCache = /* @__PURE__ */ new Map();
function resolveTaintUrl(o, src) {
  if (o.taintReadback === "off" || o.taintReadback === false) return null;
  try {
    if (o.taintUrl) {
      const url = resolveHttpUrl(o.taintUrl, { label: "taint image URL" });
      return typeof location !== "undefined" && url.origin === location.origin ? null : url.href;
    }
    const endpointRaw = src && typeof src === "object" && src.tokenEndpoint || o.tokenEndpoint;
    if (!endpointRaw || typeof location === "undefined") return null;
    const endpoint = resolveHttpUrl(endpointRaw, { label: "token endpoint" });
    if (endpoint.origin === location.origin) return null;
    const segments = endpoint.pathname.split("/").filter(Boolean);
    if (segments[segments.length - 1] !== "token") return null;
    segments[segments.length - 1] = "taint.png";
    endpoint.pathname = `/${segments.join("/")}`;
    endpoint.search = "";
    endpoint.hash = "";
    return endpoint.href;
  } catch {
    return null;
  }
}
function loadTaintImage(url) {
  let entry = taintImageCache.get(url);
  if (entry) return entry;
  entry = { img: null, promise: null };
  entry.promise = new Promise((resolve) => {
    try {
      const img = new Image();
      img.referrerPolicy = "no-referrer";
      const timer = setTimeout(() => resolve(entry.img), 3e3);
      img.onload = () => {
        clearTimeout(timer);
        entry.img = img;
        resolve(img);
      };
      img.onerror = () => {
        clearTimeout(timer);
        resolve(null);
      };
      img.src = url;
    } catch {
      resolve(null);
    }
  });
  taintImageCache.set(url, entry);
  return entry;
}
async function ensureTaintImage(o, src) {
  const url = resolveTaintUrl(o, src);
  if (!url) return null;
  const entry = loadTaintImage(url);
  if (entry.img) return entry.img;
  return Promise.race([
    entry.promise,
    new Promise((resolve) => setTimeout(() => resolve(entry.img), 1500))
  ]);
}
function normalizedHttpCache(value, fallback = "no-store") {
  const mode = String(value ?? fallback).toLowerCase();
  return ["default", "no-store", "reload", "no-cache", "force-cache", "only-if-cached"].includes(mode) ? mode : fallback;
}
function fetchPriorityInit(options = {}) {
  const priority = String(options.fetchPriority || "").toLowerCase();
  return ["high", "low", "auto"].includes(priority) ? { priority } : {};
}

// src/client/network.js
var tokenBatchSequence = 0;
function deriveTokenBatchEndpoint(endpointUrl, options = {}) {
  if (options.tokenBatchEndpoint) {
    const batchUrl2 = resolveHttpUrl(options.tokenBatchEndpoint, {
      base: endpointUrl.href,
      label: "batch token endpoint"
    });
    if (batchUrl2.search || batchUrl2.hash) {
      throw nonRetryableError("Archx: batch token endpoint must not contain a query or fragment");
    }
    return batchUrl2;
  }
  const segments = endpointUrl.pathname.split("/").filter(Boolean);
  if (segments[segments.length - 1] !== "token") return null;
  const batchUrl = new URL(endpointUrl.href);
  segments[segments.length - 1] = "tokens";
  batchUrl.pathname = `/${segments.join("/")}`;
  batchUrl.search = "";
  batchUrl.hash = "";
  return batchUrl;
}
function queueTokenBatchRequest({
  batchUrl,
  item,
  headers,
  credentials,
  controls,
  signal,
  options
}) {
  const batchSize = boundedInteger(options.tokenBatchSize, DEFAULTS.tokenBatchSize, 1, 500);
  const delayMs = boundedInteger(options.tokenBatchDelayMs, DEFAULTS.tokenBatchDelayMs, 0, 1e3);
  const maxDelayMs = Math.max(
    delayMs,
    boundedInteger(options.tokenBatchMaxDelayMs, DEFAULTS.tokenBatchMaxDelayMs, 0, 5e3)
  );
  const groupKey = cacheDigest([
    "token-batch",
    1,
    options.cacheScope || "",
    batchUrl.href,
    credentials,
    headers?.["X-Archx-Proof-Key"] || "",
    controls.fetchTimeoutMs,
    controls.retries,
    batchSize
  ]);
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason || new Error("Archx: request aborted"));
      return;
    }
    let group = tokenBatchQueues.get(groupKey);
    if (!group) {
      group = {
        key: groupKey,
        batchUrl,
        headers,
        credentials,
        controls,
        options,
        entries: [],
        timer: 0,
        firstQueuedAt: Date.now(),
        controller: null,
        started: false
      };
      tokenBatchQueues.set(groupKey, group);
    }
    const entry = {
      ref: `r${tokenBatchSequence++}`,
      item,
      resolve,
      reject,
      signal,
      cancelled: false,
      onAbort: null
    };
    entry.onAbort = () => {
      if (entry.cancelled) return;
      entry.cancelled = true;
      reject(signal?.reason || new Error("Archx: request aborted"));
      if (!group.started) {
        group.entries = group.entries.filter((candidate) => candidate !== entry);
        if (!group.entries.length) {
          clearTimeout(group.timer);
          if (tokenBatchQueues.get(groupKey) === group) tokenBatchQueues.delete(groupKey);
        }
      } else if (group.entries.every((candidate) => candidate.cancelled)) {
        try {
          group.controller?.abort(signal?.reason);
        } catch {
          group.controller?.abort();
        }
      }
    };
    signal?.addEventListener?.("abort", entry.onAbort, { once: true });
    group.entries.push(entry);
    if (group.entries.length >= batchSize) {
      clearTimeout(group.timer);
      void flushTokenBatch(group);
    } else {
      clearTimeout(group.timer);
      const elapsed = Date.now() - group.firstQueuedAt;
      const wait = Math.max(0, Math.min(delayMs, maxDelayMs - elapsed));
      group.timer = setTimeout(() => {
        void flushTokenBatch(group);
      }, wait);
    }
  });
}
async function flushTokenBatch(group) {
  if (group.started) return;
  group.started = true;
  clearTimeout(group.timer);
  if (tokenBatchQueues.get(group.key) === group) tokenBatchQueues.delete(group.key);
  const active = group.entries.filter((entry) => !entry.cancelled);
  if (!active.length) return;
  group.controller = new AbortController();
  const settle = (entry, fn, value) => {
    entry.signal?.removeEventListener?.("abort", entry.onAbort);
    if (!entry.cancelled) fn(value);
  };
  try {
    const body = JSON.stringify({
      items: active.map((entry) => ({ ref: entry.ref, ...entry.item }))
    });
    const response = await fetchBounded(group.batchUrl.href, {
      method: "POST",
      credentials: group.credentials,
      cache: "no-store",
      redirect: "error",
      headers: { ...group.headers, "Content-Type": "application/json" },
      body,
      signal: group.controller.signal,
      ...fetchPriorityInit(group.options)
    }, {
      retries: Math.min(1, group.controls.retries),
      maxBytes: Math.min(2 * 1024 * 1024, Math.max(65536, active.length * 16384)),
      timeoutMs: group.controls.fetchTimeoutMs,
      validateResponse: (res) => assertResponseFinalOrigin(res, /* @__PURE__ */ new Set([group.batchUrl.origin]))
    });
    const parsed = parseBoundedJson(response.bytes);
    if (!isPlainClientObject(parsed.tokens || {}) || !isPlainClientObject(parsed.errors || {})) {
      throw nonRetryableError("Archx: batch token endpoint returned an invalid response");
    }
    for (const entry of active) {
      const raw = parsed.tokens?.[entry.ref];
      const failure = parsed.errors?.[entry.ref];
      if (isPlainClientObject(raw)) {
        settle(entry, entry.resolve, raw);
      } else if (isPlainClientObject(failure) && Number.isInteger(failure.status)) {
        const err = new Error("Archx fetch failed: HTTP " + failure.status);
        err.status = failure.status;
        err.archxBatchItem = true;
        if (failure.status < 500 && ![408, 425, 429].includes(failure.status)) err.nonRetryable = true;
        settle(entry, entry.reject, err);
      } else {
        settle(entry, entry.reject, nonRetryableError("Archx: batch token response is incomplete"));
      }
    }
  } catch (err) {
    for (const entry of active) settle(entry, entry.reject, err);
  }
}
function fetchControls(o = {}) {
  return {
    maxResponseBytes: boundedInteger(o.maxResponseBytes, DEFAULTS.maxResponseBytes, 1024, 512 * 1024 * 1024),
    fetchTimeoutMs: boundedInteger(o.fetchTimeoutMs, DEFAULTS.fetchTimeoutMs, 100, 12e4),
    maxDecodedPixels: boundedInteger(o.maxDecodedPixels, DEFAULTS.maxDecodedPixels, 1e4, 268402689),
    maxDecodedDimension: boundedInteger(o.maxDecodedDimension, DEFAULTS.maxDecodedDimension, 64, 65536),
    retries: boundedInteger(o.retries, 2, 0, 5),
    credentials: ["omit", "same-origin", "include"].includes(o.credentials) ? o.credentials : "same-origin"
  };
}
function nonRetryableError(message, code = "ARCHX_INVALID_RESPONSE") {
  const err = new Error(message);
  err.code = code;
  err.nonRetryable = true;
  return err;
}
function signalWithTimeout(parentSignal, timeoutMs) {
  const ms = Math.max(0, Math.floor(Number(timeoutMs) || 0));
  try {
    if (typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function" && typeof AbortSignal.any === "function") {
      const signals = [];
      if (parentSignal) signals.push(parentSignal);
      if (ms > 0) signals.push(AbortSignal.timeout(ms));
      return {
        signal: signals.length === 1 ? signals[0] : AbortSignal.any(signals),
        cleanup() {
        }
      };
    }
  } catch {
  }
  const controller = new AbortController();
  let timer = 0;
  const onParentAbort = () => {
    try {
      controller.abort(parentSignal?.reason);
    } catch {
      controller.abort();
    }
  };
  if (parentSignal?.aborted) onParentAbort();
  else parentSignal?.addEventListener?.("abort", onParentAbort, { once: true });
  if (ms > 0) {
    timer = setTimeout(() => {
      let reason;
      try {
        reason = new DOMException("Archx fetch timed out", "TimeoutError");
      } catch {
      }
      try {
        controller.abort(reason);
      } catch {
        controller.abort();
      }
    }, ms);
  }
  return {
    signal: controller.signal,
    cleanup() {
      if (timer) clearTimeout(timer);
      parentSignal?.removeEventListener?.("abort", onParentAbort);
    }
  };
}
async function readResponseBytes(response, maxBytes) {
  const limit = Math.max(1, Math.floor(Number(maxBytes) || 1));
  const lengthRaw = response.headers?.get?.("content-length");
  if (lengthRaw != null) {
    const declared = Number(lengthRaw);
    if (!Number.isSafeInteger(declared) || declared < 0 || declared > limit) {
      try {
        await response.body?.cancel?.();
      } catch {
      }
      throw nonRetryableError("Archx: response exceeds the configured byte limit", "ARCHX_RESPONSE_TOO_LARGE");
    }
  }
  if (!response.body?.getReader) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length > limit) {
      throw nonRetryableError("Archx: response exceeds the configured byte limit", "ARCHX_RESPONSE_TOO_LARGE");
    }
    return bytes;
  }
  const reader = NATIVES.streamGetReader ? nativeCall(NATIVES.streamGetReader, response.body, []) : response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (; ; ) {
      const { done, value } = NATIVES.streamReaderRead ? await nativeCall(NATIVES.streamReaderRead, reader, []) : await reader.read();
      if (done) break;
      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value || []);
      total += chunk.length;
      if (total > limit) {
        try {
          await reader.cancel();
        } catch {
        }
        throw nonRetryableError("Archx: response exceeds the configured byte limit", "ARCHX_RESPONSE_TOO_LARGE");
      }
      if (chunk.length) chunks.push(chunk);
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
    }
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}
async function fetchBounded(url, options = {}, controls = {}) {
  const retries = boundedInteger(controls.retries, 0, 0, 5);
  const maxBytes = controls.maxBytes ?? DEFAULTS.maxResponseBytes;
  const timeoutMs = controls.timeoutMs ?? DEFAULTS.fetchTimeoutMs;
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    const timeout = signalWithTimeout(options.signal, timeoutMs);
    try {
      const response = await nativeFetch(url, { ...options, signal: timeout.signal });
      if (controls.validateResponse) controls.validateResponse(response);
      if (controls.allowedStatuses?.has(response.status)) {
        try {
          await response.body?.cancel?.();
        } catch {
        }
        return { response, bytes: null };
      }
      if (!response.ok) {
        try {
          await response.body?.cancel?.();
        } catch {
        }
        const err = new Error("Archx fetch failed: HTTP " + response.status);
        err.status = response.status;
        try {
          err.challengeRequired = response.headers?.get?.("x-archx-challenge") === "required";
        } catch {
        }
        throw err;
      }
      const bytes = await readResponseBytes(response, maxBytes);
      return { response, bytes };
    } catch (err) {
      lastErr = err;
      if (options.signal?.aborted || err?.nonRetryable) throw err;
      const retryableHttp = err?.status == null || err.status >= 500 || [408, 425, 429].includes(err.status);
      if (!retryableHttp || attempt >= retries) throw err;
      await new Promise((resolve) => setTimeout(resolve, 250 * (attempt + 1)));
    } finally {
      timeout.cleanup();
    }
  }
  throw lastErr;
}
function isPlainClientObject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}
var sharedFatalDecoder = (() => {
  try {
    return new TextDecoder("utf-8", { fatal: true });
  } catch {
    return null;
  }
})();
function parseBoundedJson(bytes) {
  let value;
  try {
    const text = NATIVES.textDecode && sharedFatalDecoder ? nativeCall(NATIVES.textDecode, sharedFatalDecoder, [bytes]) : new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    value = (NATIVES.jsonParse || JSON.parse)(text);
  } catch {
    throw nonRetryableError("Archx: token endpoint returned invalid JSON");
  }
  if (!isPlainClientObject(value)) throw nonRetryableError("Archx: token endpoint returned an invalid response");
  return value;
}
function resolveHttpUrl(raw, { base, label = "URL", protocols = ["http:", "https:"] } = {}) {
  if (typeof raw !== "string" || !raw || raw.length > 16384 || /[\u0000-\u0020\u007f]/.test(raw)) {
    throw nonRetryableError(`Archx: invalid ${label}`);
  }
  let url;
  try {
    const fallbackBase = typeof document !== "undefined" ? document.baseURI : void 0;
    url = new URL(raw, base || fallbackBase);
  } catch {
    throw nonRetryableError(`Archx: invalid ${label}`);
  }
  if (!protocols.includes(url.protocol) || url.username || url.password) {
    throw nonRetryableError(`Archx: disallowed ${label}`);
  }
  return url;
}
function exactOriginSet(values, endpointUrl) {
  const origins = /* @__PURE__ */ new Set();
  if (endpointUrl?.origin) origins.add(endpointUrl.origin);
  const list = values == null ? [] : Array.isArray(values) ? values : [values];
  for (const value of list) {
    if (typeof value !== "string" || !value || value.length > 512) {
      throw nonRetryableError("Archx: allowedTokenOrigins must contain exact origins");
    }
    let parsed;
    try {
      parsed = new URL(value);
    } catch {
      throw nonRetryableError("Archx: allowedTokenOrigins must contain exact origins");
    }
    const trimmed = value.endsWith("/") ? value.slice(0, -1) : value;
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.origin !== trimmed) {
      throw nonRetryableError("Archx: allowedTokenOrigins must contain exact origins");
    }
    origins.add(parsed.origin);
  }
  return origins;
}
function assertResponseFinalOrigin(response, origins) {
  if (!response?.url) return;
  let finalUrl;
  try {
    finalUrl = new URL(response.url);
  } catch {
    throw nonRetryableError("Archx: response redirected to an invalid URL");
  }
  if (!["http:", "https:"].includes(finalUrl.protocol) || !origins.has(finalUrl.origin)) {
    throw nonRetryableError("Archx: response came from an untrusted origin");
  }
}
function validTokenString(value, { min = 1, max = 512, pattern = null } = {}) {
  return typeof value === "string" && value.length >= min && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value) && (!pattern || pattern.test(value));
}
function bytesToBase64Url(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
  if (typeof view.toBase64 === "function") return view.toBase64({ alphabet: "base64url", omitPadding: true });
  let binary = "";
  const chunkSize = 32768;
  for (let i = 0; i < view.length; i += chunkSize) {
    binary += String.fromCharCode(...view.subarray(i, Math.min(view.length, i + chunkSize)));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
var proofKeyPromise = null;
function getProofKey(required = false) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle?.generateKey || !subtle?.exportKey || !subtle?.sign || !subtle?.digest || !globalThis.crypto?.getRandomValues) {
    if (required) return Promise.reject(nonRetryableError("Archx: proof-of-possession requires WebCrypto"));
    return Promise.resolve(null);
  }
  if (!proofKeyPromise) {
    proofKeyPromise = (async () => {
      const pair = await subtleDo(
        "generateKey",
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign", "verify"]
      );
      const exported = await subtleDo("exportKey", "jwk", pair.publicKey);
      if (!exported || exported.kty !== "EC" || exported.crv !== "P-256" || typeof exported.x !== "string" || typeof exported.y !== "string") {
        throw new Error("unsupported proof public key");
      }
      const jwk = { kty: "EC", crv: "P-256", x: exported.x, y: exported.y };
      const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
      const thumbprint = bytesToBase64Url(await subtleDo("digest", "SHA-256", utf8EncodeCaptured(canonical)));
      return Object.freeze({
        privateKey: pair.privateKey,
        jwk: Object.freeze(jwk),
        jkt: thumbprint,
        header: bytesToBase64Url(utf8EncodeCaptured(JSON.stringify(jwk)))
      });
    })().catch((err) => {
      proofKeyPromise = null;
      throw err;
    });
  }
  return proofKeyPromise.catch((err) => {
    if (required) throw nonRetryableError("Archx: proof-of-possession key generation failed");
    return null;
  });
}
async function createProofHeader(proofKey, accessToken, payloadUrl) {
  if (!proofKey || !accessToken) return null;
  const subtle = globalThis.crypto?.subtle;
  if (!subtle?.sign || !subtle?.digest) throw nonRetryableError("Archx: proof-of-possession signing is unavailable");
  const now = Date.now();
  const random = new Uint8Array(18);
  globalThis.crypto.getRandomValues(random);
  const proof = {
    jwk: proofKey.jwk,
    jti: bytesToBase64Url(random),
    iat: now,
    exp: now + 6e4,
    htm: "GET",
    htu: payloadUrl.pathname,
    ath: bytesToBase64Url(await subtleDo("digest", "SHA-256", utf8EncodeCaptured(accessToken)))
  };
  const payloadPart = bytesToBase64Url(utf8EncodeCaptured(JSON.stringify(proof)));
  const signingInput = `v1.${payloadPart}`;
  const signature = await subtleDo(
    "sign",
    { name: "ECDSA", hash: "SHA-256" },
    proofKey.privateKey,
    utf8EncodeCaptured(signingInput)
  );
  return `${signingInput}.${bytesToBase64Url(signature)}`;
}
function parseTokenResponse(raw, options, endpointUrl) {
  if (!isPlainClientObject(raw)) throw nonRetryableError("Archx: token endpoint returned an invalid response");
  if (!validTokenString(raw.key, { min: 1, max: 512 })) throw nonRetryableError("Archx: token response has an invalid key");
  if (!Number.isInteger(raw.grid) || raw.grid < 2 || raw.grid > 32) throw nonRetryableError("Archx: token response has an invalid grid");
  if (raw.aesKey !== void 0 && !validTokenString(raw.aesKey, { min: 16, max: 256 })) {
    throw nonRetryableError("Archx: token response has an invalid AES key");
  }
  if (raw.exp !== void 0 && (!Number.isSafeInteger(raw.exp) || raw.exp <= Date.now() - 3e5)) {
    throw nonRetryableError("Archx: token response is expired");
  }
  const separateToken = raw.token;
  if (separateToken !== void 0 && !validTokenString(separateToken, { min: 16, max: 8192, pattern: /^[A-Za-z0-9._~-]+$/ })) {
    throw nonRetryableError("Archx: token response has an invalid token");
  }
  const rawUrl = raw.cleanUrl ?? raw.url;
  const candidate = resolveHttpUrl(rawUrl, { base: endpointUrl.href, label: "token payload URL" });
  const allowedOrigins = exactOriginSet(options.allowedTokenOrigins, endpointUrl);
  if (!allowedOrigins.has(candidate.origin)) {
    throw nonRetryableError("Archx: token payload URL points to an untrusted origin");
  }
  const payloadUrl = new URL(candidate.href);
  const queryTokens = payloadUrl.searchParams.getAll("t");
  if (queryTokens.length > 1) throw nonRetryableError("Archx: token payload URL is ambiguous");
  const requestedTransport = String(options.tokenTransport || "header").toLowerCase();
  const transport = ["header", "query", "auto"].includes(requestedTransport) ? requestedTransport : "header";
  let headerToken = null;
  let accessToken = separateToken || queryTokens[0] || null;
  if (transport === "header" || transport === "auto" && separateToken) {
    headerToken = separateToken || null;
    if (queryTokens.length === 1) {
      if (headerToken && headerToken !== queryTokens[0]) throw nonRetryableError("Archx: token response is ambiguous");
      headerToken = queryTokens[0];
      payloadUrl.searchParams.delete("t");
    }
    if (!validTokenString(headerToken, { min: 16, max: 8192, pattern: /^[A-Za-z0-9._~-]+$/ })) {
      throw nonRetryableError("Archx: token response did not include a header token");
    }
    accessToken = headerToken;
  } else {
    if (separateToken && queryTokens.length === 1 && separateToken !== queryTokens[0]) {
      throw nonRetryableError("Archx: token response is ambiguous");
    }
    if (queryTokens.length === 0) {
      if (!separateToken) throw nonRetryableError("Archx: token response did not include a payload token");
      payloadUrl.searchParams.set("t", separateToken);
    }
  }
  const extra = { key: raw.key, grid: raw.grid };
  if (raw.aesKey !== void 0) extra.aesKey = raw.aesKey;
  return Object.freeze({ extra: Object.freeze(extra), payloadUrl, headerToken, accessToken, allowedOrigins });
}
var tokenBatchQueues = /* @__PURE__ */ new Map();

// src/client/assets.js
var ASSET_MANIFEST_CACHE_MAX = 8;
var assetManifestCache = /* @__PURE__ */ new Map();
var assetManifestObjectCache = /* @__PURE__ */ new WeakMap();
async function sha256Hex(bytes) {
  try {
    if (typeof crypto === "undefined" || !crypto.subtle?.digest) return null;
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const digest = await subtleDo("digest", "SHA-256", view);
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  } catch {
    return null;
  }
}
function normalizeManifestIntegrityPin(value) {
  if (value == null || value === "") return null;
  if (typeof value !== "string") throw nonRetryableError("Archx: assetManifestIntegrity is invalid");
  const hex = value.startsWith("sha256-") ? value.slice("sha256-".length) : value;
  if (!/^[0-9a-f]{64}$/.test(hex)) throw nonRetryableError("Archx: assetManifestIntegrity is invalid");
  return hex;
}
function normalizeAssetIntegrityMode(value) {
  if (value === true) return "require";
  if (value === false || value === "off") return "off";
  if (value === "require") return "require";
  return "auto";
}
async function verifyAssetVariantIntegrity(variant, bytes, options) {
  const mode = normalizeAssetIntegrityMode(options.assetIntegrity);
  if (mode === "off") return;
  if (!variant.sha256) {
    if (mode === "require") throw nonRetryableError("Archx: asset variant has no integrity digest");
    return;
  }
  const digest = await sha256Hex(bytes);
  if (!digest) {
    if (mode === "require") {
      throw nonRetryableError("Archx: asset integrity cannot be verified in this browser");
    }
    return;
  }
  if (digest !== variant.sha256) {
    throw nonRetryableError("Archx: asset variant integrity check failed");
  }
}
function normalizeAssetManifest(raw, baseUrl) {
  if (!isPlainClientObject(raw) || raw.version !== 1 || !isPlainClientObject(raw.assets)) {
    throw nonRetryableError("Archx: asset manifest is invalid");
  }
  const entries = Object.entries(raw.assets);
  if (!entries.length || entries.length > 1e5) {
    throw nonRetryableError("Archx: asset manifest has an invalid asset count");
  }
  const assets = /* @__PURE__ */ new Map();
  for (const [id, assetRaw] of entries) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(id) || !isPlainClientObject(assetRaw)) {
      throw nonRetryableError("Archx: asset manifest contains an invalid asset");
    }
    if (assetRaw.id !== void 0 && assetRaw.id !== id) {
      throw nonRetryableError("Archx: asset manifest contains a mismatched asset id");
    }
    const width = assetRaw.width;
    const height = assetRaw.height;
    if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) || width < 1 || height < 1 || width > 65536 || height > 65536) {
      throw nonRetryableError("Archx: asset manifest contains invalid dimensions");
    }
    if (!validTokenString(assetRaw.key, { min: 1, max: 512 })) {
      throw nonRetryableError("Archx: asset manifest contains an invalid key");
    }
    if (!Number.isInteger(assetRaw.grid) || assetRaw.grid < 2 || assetRaw.grid > 32) {
      throw nonRetryableError("Archx: asset manifest contains an invalid grid");
    }
    if (assetRaw.planVersion !== void 0 && assetRaw.planVersion !== 1 && assetRaw.planVersion !== 2) {
      throw nonRetryableError("Archx: asset manifest contains an invalid plan version");
    }
    if (assetRaw.aesKey !== void 0 && !validTokenString(assetRaw.aesKey, { min: 16, max: 256 })) {
      throw nonRetryableError("Archx: asset manifest contains an invalid AES key");
    }
    if (!Array.isArray(assetRaw.variants) || !assetRaw.variants.length || assetRaw.variants.length > 32) {
      throw nonRetryableError("Archx: asset manifest contains invalid variants");
    }
    const variants = assetRaw.variants.map((variantRaw) => {
      if (!isPlainClientObject(variantRaw) || !Number.isSafeInteger(variantRaw.width) || !Number.isSafeInteger(variantRaw.height) || variantRaw.width < 1 || variantRaw.height < 1 || variantRaw.width > 65536 || variantRaw.height > 65536 || typeof variantRaw.url !== "string" || !variantRaw.url || variantRaw.url.length > 16384) {
        throw nonRetryableError("Archx: asset manifest contains an invalid variant");
      }
      if (variantRaw.sha256 !== void 0 && variantRaw.sha256 !== null && (typeof variantRaw.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(variantRaw.sha256))) {
        throw nonRetryableError("Archx: asset manifest contains an invalid variant digest");
      }
      const url = resolveHttpUrl(variantRaw.url, { base: baseUrl?.href, label: "asset variant URL" });
      return Object.freeze({
        width: variantRaw.width,
        height: variantRaw.height,
        url,
        bytes: Number.isSafeInteger(variantRaw.bytes) && variantRaw.bytes > 0 ? variantRaw.bytes : null,
        sha256: typeof variantRaw.sha256 === "string" ? variantRaw.sha256 : null
      });
    }).sort((a, b) => a.width - b.width || a.height - b.height);
    assets.set(id, Object.freeze({
      id,
      width,
      height,
      key: assetRaw.key,
      grid: assetRaw.grid,
      ...assetRaw.planVersion !== void 0 ? { planVersion: assetRaw.planVersion } : {},
      ...assetRaw.aesKey !== void 0 ? { aesKey: assetRaw.aesKey } : {},
      variants: Object.freeze(variants)
    }));
  }
  return Object.freeze({ version: 1, assets });
}
async function loadAssetManifest(manifestSource, options, controls) {
  const pin = normalizeManifestIntegrityPin(options.assetManifestIntegrity);
  if (isPlainClientObject(manifestSource)) {
    if (pin) throw nonRetryableError("Archx: assetManifestIntegrity requires a fetched manifest URL");
    let normalized = assetManifestObjectCache.get(manifestSource);
    if (!normalized) {
      const base = typeof document !== "undefined" ? new URL(document.baseURI) : new URL("http://archx.local/");
      normalized = normalizeAssetManifest(manifestSource, base);
      assetManifestObjectCache.set(manifestSource, normalized);
    }
    return normalized;
  }
  const manifestUrl = resolveHttpUrl(manifestSource, { label: "asset manifest URL" });
  if (manifestUrl.hash) throw nonRetryableError("Archx: asset manifest URL must not contain a fragment");
  const maxBytes = boundedInteger(
    options.assetManifestMaxBytes,
    DEFAULTS.assetManifestMaxBytes,
    1024,
    64 * 1024 * 1024
  );
  const cacheMode = normalizedHttpCache(options.assetHttpCache, "default");
  const cacheKey = cacheDigest([
    "asset-manifest",
    1,
    options.cacheScope || "",
    manifestUrl.href,
    controls.credentials,
    cacheMode,
    maxBytes,
    controls.fetchTimeoutMs,
    controls.retries,
    pin || ""
  ]);
  let pending = assetManifestCache.get(cacheKey);
  if (pending) {
    assetManifestCache.delete(cacheKey);
    assetManifestCache.set(cacheKey, pending);
  }
  if (!pending) {
    pending = (async () => {
      const response = await fetchBounded(manifestUrl.href, {
        method: "GET",
        credentials: controls.credentials,
        cache: cacheMode,
        redirect: "error",
        ...fetchPriorityInit(options)
      }, {
        retries: controls.retries,
        maxBytes,
        timeoutMs: controls.fetchTimeoutMs,
        validateResponse: (res) => assertResponseFinalOrigin(res, /* @__PURE__ */ new Set([manifestUrl.origin]))
      });
      if (pin) {
        const digest = await sha256Hex(response.bytes);
        if (!digest) {
          throw nonRetryableError("Archx: asset manifest integrity cannot be verified in this browser");
        }
        if (digest !== pin) throw nonRetryableError("Archx: asset manifest integrity check failed");
      }
      return normalizeAssetManifest(parseBoundedJson(response.bytes), manifestUrl);
    })();
    assetManifestCache.set(cacheKey, pending);
    while (assetManifestCache.size > ASSET_MANIFEST_CACHE_MAX) {
      const oldest = assetManifestCache.keys().next().value;
      if (oldest === cacheKey) break;
      assetManifestCache.delete(oldest);
    }
    pending.catch(() => {
      if (assetManifestCache.get(cacheKey) === pending) assetManifestCache.delete(cacheKey);
    });
  }
  return pending;
}
function chooseAssetVariant(asset, neededWidth) {
  const wanted = Math.max(1, Math.ceil(Number(neededWidth) || 1));
  return asset.variants.find((variant) => variant.width >= wanted) || asset.variants[asset.variants.length - 1];
}

// src/client/bitmap-cache.js
var bitmapCacheBytes = 0;
function bitmapEstimatedBytes(result) {
  const bitmap = result?.bitmap;
  const w = bitmap?.width || bitmap?.naturalWidth || result?.meta?.padW || 0;
  const h = bitmap?.height || bitmap?.naturalHeight || result?.meta?.padH || 0;
  const bytes = w * h * 4;
  return Number.isFinite(bytes) && bytes > 0 ? Math.ceil(bytes) : 0;
}
function closeBitmapQuietly(bitmap) {
  try {
    bitmap?.close?.();
  } catch {
  }
}
function evictBitmapEntry(key, entry) {
  if (bitmapCache.get(key) === entry) bitmapCache.delete(key);
  if (entry.settled && entry.bytes) {
    bitmapCacheBytes = Math.max(0, bitmapCacheBytes - entry.bytes);
    entry.bytes = 0;
  }
  if (entry.refs <= 0 && entry.result?.bitmap) closeBitmapQuietly(entry.result.bitmap);
}
function trimBitmapCache(maxEntries = DEFAULTS.bitmapCacheMaxEntries, maxBytes = DEFAULTS.bitmapCacheMaxBytes) {
  const entryLimit = Math.max(0, Math.floor(Number(maxEntries) || 0));
  const byteLimit = Math.max(0, Math.floor(Number(maxBytes) || 0));
  while (bitmapCache.size > entryLimit || byteLimit > 0 && bitmapCacheBytes > byteLimit) {
    const oldest = bitmapCache.keys().next().value;
    if (oldest === void 0) break;
    evictBitmapEntry(oldest, bitmapCache.get(oldest));
  }
}
function cachePut(key, promise, opts = {}) {
  const existing = bitmapCache.get(key);
  if (existing?.promise === promise) return existing;
  if (existing) evictBitmapEntry(key, existing);
  const entry = { key, promise, result: null, refs: 1, bytes: 0, settled: false };
  bitmapCache.set(key, entry);
  promise.then((result) => {
    entry.result = result;
    entry.settled = true;
    entry.bytes = bitmapEstimatedBytes(result);
    if (bitmapCache.get(key) === entry) {
      bitmapCacheBytes += entry.bytes;
      trimBitmapCache(opts.bitmapCacheMaxEntries, opts.bitmapCacheMaxBytes);
    } else if (entry.refs <= 0) closeBitmapQuietly(result?.bitmap);
  }, () => {
    entry.settled = true;
    entry.refs = 0;
    if (bitmapCache.get(key) === entry) bitmapCache.delete(key);
  });
  trimBitmapCache(opts.bitmapCacheMaxEntries, opts.bitmapCacheMaxBytes);
  return entry;
}
function cacheGetEntry(key, { acquire = false } = {}) {
  const entry = bitmapCache.get(key);
  if (!entry) return null;
  bitmapCache.delete(key);
  bitmapCache.set(key, entry);
  if (acquire) entry.refs++;
  return entry;
}
function cacheReleaseEntry(entry) {
  if (!entry) return;
  entry.refs = Math.max(0, entry.refs - 1);
  if (entry.refs <= 0 && bitmapCache.get(entry.key) !== entry && entry.result?.bitmap) {
    closeBitmapQuietly(entry.result.bitmap);
  }
}
function clearBitmapCache() {
  for (const [key, entry] of [...bitmapCache]) evictBitmapEntry(key, entry);
  bitmapCache.clear();
  bitmapCacheBytes = 0;
}
var bitmapCache = /* @__PURE__ */ new Map();

// src/client/draw.js
function asByteArray(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  throw nonRetryableError("Archx: image source must be bytes");
}
function setSmoothing(ctx, enabled) {
  ctx.imageSmoothingEnabled = enabled;
  if (enabled) {
    try {
      ctx.imageSmoothingQuality = "high";
    } catch {
    }
  }
}
function drawImageHighQuality(ctx, source, sx, sy, sw, sh, dx, dy, dw, dh) {
  if (sw <= 0 || sh <= 0 || dw <= 0 || dh <= 0) return;
  const scaleX = dw / sw;
  const scaleY = dh / sh;
  const exact = Math.abs(scaleX - 1) < 0.01 && Math.abs(scaleY - 1) < 0.01;
  if (Math.min(scaleX, scaleY) >= 0.5) {
    setSmoothing(ctx, !exact);
    nativeDrawImage(ctx, source, sx, sy, sw, sh, dx, dy, dw, dh);
    return;
  }
  const intermediate = makeCanvas();
  setCanvasSize(intermediate, Math.max(1, Math.ceil(dw * 2)), Math.max(1, Math.ceil(dh * 2)));
  const ictx = getNativeContext(intermediate, "2d");
  drawImageHighQuality(
    ictx,
    source,
    sx,
    sy,
    sw,
    sh,
    0,
    0,
    intermediate.width,
    intermediate.height
  );
  setSmoothing(ctx, true);
  nativeDrawImage(ctx, intermediate, 0, 0, intermediate.width, intermediate.height, dx, dy, dw, dh);
  setCanvasSize(intermediate, 0, 0);
}
function unscrambleToCanvas(bitmap, meta, targetW, targetH) {
  const canvas = makeCanvas();
  setCanvasSize(canvas, Math.max(1, targetW), Math.max(1, targetH));
  const ctx = getNativeContext(canvas, "2d");
  if (!meta.plan) {
    drawImageHighQuality(ctx, bitmap, 0, 0, bitmap.width, bitmap.height, 0, 0, targetW, targetH);
    return canvas;
  }
  const { plan, origW, origH, padW, padH } = meta;
  const twSrc = bitmap.width / plan.grid;
  const thSrc = bitmap.height / plan.grid;
  const targetPadW = targetW * (padW / origW);
  const targetPadH = targetH * (padH / origH);
  const intermediateScale = Math.max(0.05, Math.min(
    2,
    bitmap.width / Math.max(1, targetPadW),
    bitmap.height / Math.max(1, targetPadH)
  ));
  const tileW = Math.max(1, Math.round(targetPadW * intermediateScale / plan.grid));
  const tileH = Math.max(1, Math.round(targetPadH * intermediateScale / plan.grid));
  const padded = makeCanvas();
  setCanvasSize(padded, tileW * plan.grid, tileH * plan.grid);
  const pctx = getNativeContext(padded, "2d");
  const exactScale = Math.abs(tileW - twSrc) < 0.01 && Math.abs(tileH - thSrc) < 0.01;
  setSmoothing(pctx, !exactScale);
  const insetX = exactScale ? 0 : Math.min(0.5, twSrc * 0.01);
  const insetY = exactScale ? 0 : Math.min(0.5, thSrc * 0.01);
  for (let orig = 0; orig < plan.count; orig++) {
    const scrambledPos = plan.inverse[orig];
    const s = tileRect(scrambledPos, plan.grid, twSrc, thSrc);
    const dx = orig % plan.grid * tileW;
    const dy = Math.floor(orig / plan.grid) * tileH;
    const { fx, fy } = plan.flips[scrambledPos];
    ctxNative(pctx, "save");
    ctxNative(pctx, "translate", dx + (fx ? tileW : 0), dy + (fy ? tileH : 0));
    ctxNative(pctx, "scale", fx ? -1 : 1, fy ? -1 : 1);
    nativeDrawImage(
      pctx,
      bitmap,
      s.x + insetX,
      s.y + insetY,
      s.w - insetX * 2,
      s.h - insetY * 2,
      0,
      0,
      tileW,
      tileH
    );
    ctxNative(pctx, "restore");
  }
  drawImageHighQuality(
    ctx,
    padded,
    0,
    0,
    padded.width * (origW / padW),
    padded.height * (origH / padH),
    0,
    0,
    targetW,
    targetH
  );
  setCanvasSize(padded, 0, 0);
  return canvas;
}
function scrambleCanvasLocally(source, grid, key) {
  const w = source.width, h = source.height;
  const { tw, th, pw, ph } = paddedSize(w, h, grid);
  const plan = buildScramblePlan(grid, key, 2);
  const cleanPadded = makeCanvas();
  setCanvasSize(cleanPadded, pw, ph);
  const cctx = getNativeContext(cleanPadded, "2d");
  setSmoothing(cctx, false);
  nativeDrawImage(cctx, source, 0, 0);
  const shiftFor = (orderIdx, len) => len > 1 ? (len >> 1) + plan.order[(orderIdx % plan.count + plan.count) % plan.count] % Math.max(1, len >> 1) : 0;
  const wrapCols = (shiftX) => {
    let dx = w;
    let sx = shiftX % Math.max(1, w);
    while (dx < pw) {
      const seg = Math.min(w - sx, pw - dx);
      nativeDrawImage(cctx, source, sx, 0, seg, h, dx, 0, seg, h);
      dx += seg;
      sx = 0;
    }
  };
  const wrapRows = (shiftY) => {
    let dy = h;
    let sy = shiftY % Math.max(1, h);
    while (dy < ph) {
      const seg = Math.min(h - sy, ph - dy);
      nativeDrawImage(cctx, cleanPadded, 0, sy, pw, seg, 0, dy, pw, seg);
      dy += seg;
      sy = 0;
    }
  };
  if (pw > w && w > 0) {
    ctxNative(cctx, "save");
    cctx.fillStyle = "#000";
    cctx.fillRect(w, 0, pw - w, h);
    cctx.globalAlpha = 0.96;
    wrapCols(shiftFor(0, w));
    cctx.globalAlpha = 0.45;
    wrapCols(shiftFor(1, w));
    cctx.globalAlpha = 0.35;
    nativeDrawImage(cctx, source, w - 1, 0, 1, h, w, 0, Math.min(3, pw - w), h);
    ctxNative(cctx, "restore");
  }
  if (ph > h && h > 0) {
    ctxNative(cctx, "save");
    cctx.fillStyle = "#000";
    cctx.fillRect(0, h, pw, ph - h);
    cctx.globalAlpha = 0.96;
    wrapRows(shiftFor(plan.count - 1, h));
    cctx.globalAlpha = 0.45;
    wrapRows(shiftFor(plan.count - 2, h));
    cctx.globalAlpha = 0.35;
    nativeDrawImage(cctx, cleanPadded, 0, h - 1, pw, 1, 0, h, pw, Math.min(3, ph - h));
    ctxNative(cctx, "restore");
  }
  const scrambled = makeCanvas();
  setCanvasSize(scrambled, pw, ph);
  const ctx = getNativeContext(scrambled, "2d");
  setSmoothing(ctx, false);
  ctx.fillStyle = "#000";
  ctx.fillRect(0, 0, pw, ph);
  for (let dest = 0; dest < plan.count; dest++) {
    const orig = plan.order[dest];
    const s = tileRect(orig, plan.grid, tw, th);
    const d = tileRect(dest, plan.grid, tw, th);
    const { fx, fy } = plan.flips[dest];
    ctxNative(ctx, "save");
    ctxNative(ctx, "translate", d.x + (fx ? tw : 0), d.y + (fy ? th : 0));
    ctxNative(ctx, "scale", fx ? -1 : 1, fy ? -1 : 1);
    nativeDrawImage(ctx, cleanPadded, s.x, s.y, tw, th, 0, 0, tw, th);
    ctxNative(ctx, "restore");
  }
  setCanvasSize(cleanPadded, 0, 0);
  return { canvas: scrambled, meta: { plan, origW: w, origH: h, padW: pw, padH: ph } };
}

// src/client/events.js
var globalEventListeners = /* @__PURE__ */ new Set();
var installedPlugins = /* @__PURE__ */ new Map();
function sanitizeClientEvent(type, details = {}, instance = null) {
  let mode = null;
  try {
    mode = instance?.options?.requestedMode || instance?.options?.mode || null;
  } catch {
  }
  const cleanText = (value, max = 160) => {
    if (value == null) return null;
    const text = String(value).replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, max);
    return text || null;
  };
  return Object.freeze({
    schemaVersion: 1,
    service: "archx-client",
    type: cleanText(type, 80) || "archx.event",
    at: (/* @__PURE__ */ new Date()).toISOString(),
    mode: cleanText(mode, 32),
    kind: cleanText(details.kind, 120),
    reason: cleanText(details.reason, 160),
    outcome: cleanText(details.outcome, 48),
    issues: Array.isArray(details.issues) ? Object.freeze(details.issues.slice(0, 40).map((issue) => cleanText(issue, 120)).filter(Boolean)) : null
  });
}
function emitClientEvent(type, details = {}, instance = null) {
  const event = sanitizeClientEvent(type, details, instance);
  const invoke = (listener) => {
    try {
      const result = listener(event, instance);
      if (result && typeof result.catch === "function") result.catch(() => {
      });
    } catch {
    }
  };
  for (const listener of [...globalEventListeners]) invoke(listener);
  for (const plugin of installedPlugins.values()) {
    if (typeof plugin.onEvent === "function") invoke(plugin.onEvent);
  }
  try {
    const perInstance = instance?.options?.onEvent;
    if (typeof perInstance === "function") invoke(perInstance);
  } catch {
  }
  return event;
}
function onClientEvent(listener) {
  if (typeof listener !== "function") throw new TypeError("Archx.on: listener must be a function");
  globalEventListeners.add(listener);
  return () => {
    globalEventListeners.delete(listener);
  };
}
function offClientEvent(listener) {
  return globalEventListeners.delete(listener);
}
function usePlugin(plugin) {
  if (!plugin || typeof plugin !== "object") throw new TypeError("Archx.use: plugin must be an object");
  const name = typeof plugin.name === "string" && plugin.name.trim() ? plugin.name.trim().slice(0, 80) : `plugin-${installedPlugins.size + 1}`;
  if (plugin.onEvent !== void 0 && typeof plugin.onEvent !== "function") {
    throw new TypeError("Archx.use: plugin.onEvent must be a function when supplied");
  }
  if (plugin.setup !== void 0 && typeof plugin.setup !== "function") {
    throw new TypeError("Archx.use: plugin.setup must be a function when supplied");
  }
  if (plugin.teardown !== void 0 && typeof plugin.teardown !== "function") {
    throw new TypeError("Archx.use: plugin.teardown must be a function when supplied");
  }
  const previous = installedPlugins.get(name);
  if (previous?.teardown) {
    try {
      previous.teardown();
    } catch {
    }
  }
  const record = Object.freeze({ name, onEvent: plugin.onEvent || null, teardown: plugin.teardown || null });
  installedPlugins.set(name, record);
  if (typeof plugin.setup === "function") {
    try {
      plugin.setup(Object.freeze({ on: onClientEvent, off: offClientEvent, version: VERSION }));
    } catch {
      installedPlugins.delete(name);
      throw new Error(`Archx.use: plugin "${name}" setup failed`);
    }
  }
  emitClientEvent("archx.plugin_installed", { kind: name, outcome: "installed" });
  return Object.freeze({
    name,
    remove() {
      const current = installedPlugins.get(name);
      if (!current) return false;
      installedPlugins.delete(name);
      try {
        current.teardown?.();
      } catch {
      }
      return true;
    }
  });
}
function listPlugins() {
  return Object.freeze([...installedPlugins.keys()]);
}

// src/client/integrity.js
var AUDIT_WEBGL_METHODS = [
  "texImage2D",
  "readPixels",
  "drawArrays",
  "drawElements",
  "createTexture",
  "bindTexture",
  "bindFramebuffer",
  "createFramebuffer",
  "framebufferTexture2D",
  "createShader",
  "shaderSource",
  "compileShader",
  "createProgram",
  "linkProgram",
  "useProgram",
  "getContextAttributes",
  "uniform1f",
  "uniform2f",
  "uniform1i",
  "viewport",
  "activeTexture",
  "texParameteri",
  "pixelStorei",
  "generateMipmap",
  "getUniformLocation",
  "attachShader",
  "getShaderParameter",
  "getProgramParameter",
  "createBuffer",
  "bindBuffer",
  "bufferData",
  "enableVertexAttribArray",
  "vertexAttribPointer",
  "getExtension"
];
var readerProtoCache;
function currentReaderRead() {
  try {
    if (readerProtoCache === void 0) {
      readerProtoCache = Object.getPrototypeOf(new ReadableStream().getReader());
    }
    return readerProtoCache?.read ?? null;
  } catch {
    return null;
  }
}
function currentDescriptorAccessor(ctorName, prop, kind) {
  try {
    const ctor = ctorName === "HTMLCanvasElement" ? typeof HTMLCanvasElement !== "undefined" ? HTMLCanvasElement : null : typeof CanvasRenderingContext2D !== "undefined" ? CanvasRenderingContext2D : null;
    if (!ctor) return null;
    return Object.getOwnPropertyDescriptor(ctor.prototype, prop)?.[kind] || null;
  } catch {
    return null;
  }
}
function auditIntegrity() {
  const g = globalThis;
  const current = [
    ["fetch", g.fetch, NATIVES.fetch],
    ["createImageBitmap", g.createImageBitmap, NATIVES.createImageBitmap],
    ["URL.createObjectURL", typeof URL !== "undefined" ? URL.createObjectURL : null, NATIVES.createObjectURL],
    ["HTMLCanvasElement.prototype.getContext", typeof HTMLCanvasElement !== "undefined" ? HTMLCanvasElement.prototype.getContext : null, NATIVES.canvasGetContext],
    ["HTMLCanvasElement.prototype.toDataURL", typeof HTMLCanvasElement !== "undefined" ? HTMLCanvasElement.prototype.toDataURL : null, NATIVES.canvasToDataURL],
    ["HTMLCanvasElement.prototype.toBlob", typeof HTMLCanvasElement !== "undefined" ? HTMLCanvasElement.prototype.toBlob : null, NATIVES.canvasToBlob],
    ["CanvasRenderingContext2D.prototype.drawImage", typeof CanvasRenderingContext2D !== "undefined" ? CanvasRenderingContext2D.prototype.drawImage : null, NATIVES.ctxDrawImage],
    ["CanvasRenderingContext2D.prototype.getImageData", typeof CanvasRenderingContext2D !== "undefined" ? CanvasRenderingContext2D.prototype.getImageData : null, NATIVES.ctxGetImageData],
    ["CanvasRenderingContext2D.prototype.putImageData", typeof CanvasRenderingContext2D !== "undefined" ? CanvasRenderingContext2D.prototype.putImageData : null, NATIVES.ctxPutImageData],
    ["CanvasRenderingContext2D.prototype.save", typeof CanvasRenderingContext2D !== "undefined" ? CanvasRenderingContext2D.prototype.save : null, NATIVES.ctxSave],
    ["CanvasRenderingContext2D.prototype.restore", typeof CanvasRenderingContext2D !== "undefined" ? CanvasRenderingContext2D.prototype.restore : null, NATIVES.ctxRestore],
    ["CanvasRenderingContext2D.prototype.translate", typeof CanvasRenderingContext2D !== "undefined" ? CanvasRenderingContext2D.prototype.translate : null, NATIVES.ctxTranslate],
    ["CanvasRenderingContext2D.prototype.scale", typeof CanvasRenderingContext2D !== "undefined" ? CanvasRenderingContext2D.prototype.scale : null, NATIVES.ctxScale],
    ["CanvasRenderingContext2D.prototype.rotate", typeof CanvasRenderingContext2D !== "undefined" ? CanvasRenderingContext2D.prototype.rotate : null, NATIVES.ctxRotate],
    ["CanvasRenderingContext2D.prototype.setTransform", typeof CanvasRenderingContext2D !== "undefined" ? CanvasRenderingContext2D.prototype.setTransform : null, NATIVES.ctxSetTransform],
    ["Function.prototype.call", Function.prototype.call, NATIVES.fnCall],
    ["Function.prototype.apply", Function.prototype.apply, NATIVES.fnApply],
    ["Function.prototype.bind", Function.prototype.bind, NATIVES.fnBind],
    ["Function.prototype.toString", Function.prototype.toString, NATIVES.fnToString],
    ["Reflect.apply", typeof Reflect !== "undefined" ? Reflect.apply : null, NATIVES.reflectApply],
    ["HTMLCanvasElement.prototype.width.get", currentDescriptorAccessor("HTMLCanvasElement", "width", "get"), NATIVES.canvasWidthGet],
    ["HTMLCanvasElement.prototype.width.set", currentDescriptorAccessor("HTMLCanvasElement", "width", "set"), NATIVES.canvasWidthSet],
    ["HTMLCanvasElement.prototype.height.get", currentDescriptorAccessor("HTMLCanvasElement", "height", "get"), NATIVES.canvasHeightGet],
    ["HTMLCanvasElement.prototype.height.set", currentDescriptorAccessor("HTMLCanvasElement", "height", "set"), NATIVES.canvasHeightSet],
    ["CanvasRenderingContext2D.prototype.imageSmoothingQuality.get", currentDescriptorAccessor("CanvasRenderingContext2D", "imageSmoothingQuality", "get"), NATIVES.smoothingQualityGet],
    ["CanvasRenderingContext2D.prototype.imageSmoothingQuality.set", currentDescriptorAccessor("CanvasRenderingContext2D", "imageSmoothingQuality", "set"), NATIVES.smoothingQualitySet],
    ["Document.prototype.createElement", typeof Document !== "undefined" ? Document.prototype.createElement : null, NATIVES.docCreateElement],
    ["JSON.parse", typeof JSON !== "undefined" ? JSON.parse : null, NATIVES.jsonParse],
    ["Element.prototype.attachShadow", typeof Element !== "undefined" ? Element.prototype.attachShadow : null, NATIVES.attachShadow],
    ["ReadableStream.prototype.getReader", typeof ReadableStream !== "undefined" ? ReadableStream.prototype.getReader : null, NATIVES.streamGetReader],
    ["ReadableStreamDefaultReader.prototype.read", currentReaderRead(), NATIVES.streamReaderRead],
    ["Response.prototype.text", typeof Response !== "undefined" ? Response.prototype.text : null, NATIVES.responseText],
    ["TextDecoder.prototype.decode", typeof TextDecoder !== "undefined" ? TextDecoder.prototype.decode : null, NATIVES.textDecode],
    ["TextEncoder.prototype.encode", typeof TextEncoder !== "undefined" ? TextEncoder.prototype.encode : null, NATIVES.textEncode],
    ["SubtleCrypto.prototype.importKey", NATIVES.subtle ? Object.getPrototypeOf(NATIVES.subtle).importKey : null, NATIVES.subtleImportKey],
    ["SubtleCrypto.prototype.decrypt", NATIVES.subtle ? Object.getPrototypeOf(NATIVES.subtle).decrypt : null, NATIVES.subtleDecrypt],
    ["SubtleCrypto.prototype.encrypt", NATIVES.subtle ? Object.getPrototypeOf(NATIVES.subtle).encrypt : null, NATIVES.subtleEncrypt],
    ["SubtleCrypto.prototype.digest", NATIVES.subtle ? Object.getPrototypeOf(NATIVES.subtle).digest : null, NATIVES.subtleDigest],
    ["SubtleCrypto.prototype.sign", NATIVES.subtle ? Object.getPrototypeOf(NATIVES.subtle).sign : null, NATIVES.subtleSign],
    ["SubtleCrypto.prototype.generateKey", NATIVES.subtle ? Object.getPrototypeOf(NATIVES.subtle).generateKey : null, NATIVES.subtleGenerateKey],
    ["SubtleCrypto.prototype.exportKey", NATIVES.subtle ? Object.getPrototypeOf(NATIVES.subtle).exportKey : null, NATIVES.subtleExportKey],
    ["Crypto.prototype.getRandomValues", (() => {
      try {
        return globalThis.crypto?.getRandomValues || null;
      } catch {
        return null;
      }
    })(), NATIVES.getRandomValues]
  ];
  for (const [label, ctor, capturedMap] of [
    ["WebGLRenderingContext", typeof WebGLRenderingContext !== "undefined" ? WebGLRenderingContext : null, NATIVES.webgl1],
    ["WebGL2RenderingContext", typeof WebGL2RenderingContext !== "undefined" ? WebGL2RenderingContext : null, NATIVES.webgl2]
  ]) {
    for (const method of AUDIT_WEBGL_METHODS) {
      current.push([
        `${label}.prototype.${method}`,
        ctor ? ctor.prototype[method] : null,
        capturedMap?.[method] ?? null
      ]);
    }
  }
  const issues = [];
  for (const [name, now, captured] of current) {
    if (!captured && !now) continue;
    if (now !== captured || captured && !isNativeFn(captured)) issues.push(name);
  }
  return issues;
}
function auditIntegrityDetails() {
  const issues = auditIntegrity();
  const capturedByName = /* @__PURE__ */ new Map([
    ["fetch", NATIVES.fetch],
    ["createImageBitmap", NATIVES.createImageBitmap],
    ["URL.createObjectURL", NATIVES.createObjectURL],
    ["HTMLCanvasElement.prototype.getContext", NATIVES.canvasGetContext],
    ["HTMLCanvasElement.prototype.toDataURL", NATIVES.canvasToDataURL],
    ["HTMLCanvasElement.prototype.toBlob", NATIVES.canvasToBlob],
    ["CanvasRenderingContext2D.prototype.drawImage", NATIVES.ctxDrawImage],
    ["CanvasRenderingContext2D.prototype.getImageData", NATIVES.ctxGetImageData],
    ["CanvasRenderingContext2D.prototype.putImageData", NATIVES.ctxPutImageData],
    ["CanvasRenderingContext2D.prototype.save", NATIVES.ctxSave],
    ["CanvasRenderingContext2D.prototype.restore", NATIVES.ctxRestore],
    ["CanvasRenderingContext2D.prototype.translate", NATIVES.ctxTranslate],
    ["CanvasRenderingContext2D.prototype.scale", NATIVES.ctxScale],
    ["CanvasRenderingContext2D.prototype.rotate", NATIVES.ctxRotate],
    ["CanvasRenderingContext2D.prototype.setTransform", NATIVES.ctxSetTransform],
    ["Function.prototype.call", NATIVES.fnCall],
    ["Function.prototype.apply", NATIVES.fnApply],
    ["Function.prototype.bind", NATIVES.fnBind],
    ["Function.prototype.toString", NATIVES.fnToString],
    ["Reflect.apply", NATIVES.reflectApply],
    ["HTMLCanvasElement.prototype.width.get", NATIVES.canvasWidthGet],
    ["HTMLCanvasElement.prototype.width.set", NATIVES.canvasWidthSet],
    ["HTMLCanvasElement.prototype.height.get", NATIVES.canvasHeightGet],
    ["HTMLCanvasElement.prototype.height.set", NATIVES.canvasHeightSet],
    ["CanvasRenderingContext2D.prototype.imageSmoothingQuality.get", NATIVES.smoothingQualityGet],
    ["CanvasRenderingContext2D.prototype.imageSmoothingQuality.set", NATIVES.smoothingQualitySet],
    ["Document.prototype.createElement", NATIVES.docCreateElement],
    ["JSON.parse", NATIVES.jsonParse],
    ["Element.prototype.attachShadow", NATIVES.attachShadow],
    ["ReadableStream.prototype.getReader", NATIVES.streamGetReader],
    ["ReadableStreamDefaultReader.prototype.read", NATIVES.streamReaderRead],
    ["Response.prototype.text", NATIVES.responseText],
    ["TextDecoder.prototype.decode", NATIVES.textDecode],
    ["TextEncoder.prototype.encode", NATIVES.textEncode],
    ["SubtleCrypto.prototype.importKey", NATIVES.subtleImportKey],
    ["SubtleCrypto.prototype.decrypt", NATIVES.subtleDecrypt],
    ["SubtleCrypto.prototype.encrypt", NATIVES.subtleEncrypt],
    ["SubtleCrypto.prototype.digest", NATIVES.subtleDigest],
    ["SubtleCrypto.prototype.sign", NATIVES.subtleSign],
    ["SubtleCrypto.prototype.generateKey", NATIVES.subtleGenerateKey],
    ["SubtleCrypto.prototype.exportKey", NATIVES.subtleExportKey],
    ["Crypto.prototype.getRandomValues", NATIVES.getRandomValues]
  ]);
  for (const [label, capturedMap] of [
    ["WebGLRenderingContext", NATIVES.webgl1],
    ["WebGL2RenderingContext", NATIVES.webgl2]
  ]) {
    for (const [method, fn] of Object.entries(capturedMap || {})) {
      capturedByName.set(`${label}.prototype.${method}`, fn);
    }
  }
  const capturedNonNative = issues.filter((name) => {
    const captured = capturedByName.get(name);
    return !!captured && !isNativeFn(captured);
  });
  return Object.freeze({
    ok: issues.length === 0,
    issues: Object.freeze(issues),
    capturedNonNative: Object.freeze(capturedNonNative),
    changedSinceLoad: Object.freeze(issues.filter((name) => !capturedNonNative.includes(name))),
    checked: Object.freeze([
      "fetch",
      "createImageBitmap",
      "URL.createObjectURL",
      "canvas context/readback",
      "CanvasRenderingContext2D draw/readback",
      "Document.createElement",
      "WebGL/WebGL2 texture, framebuffer, shader/program, draw, and readback methods"
    ]),
    note: "Tripwire only: a clean result does not prove the absence of pre-load, native-looking, extension, CDP, or modified-browser hooks."
  });
}
function captureEarlyIntegritySnapshot() {
  const snapshot = Object.freeze({
    fetch: globalThis.fetch || null,
    createImageBitmap: globalThis.createImageBitmap || null,
    canvasGetContext: typeof HTMLCanvasElement !== "undefined" ? HTMLCanvasElement.prototype.getContext : null,
    webglDrawArrays: typeof WebGLRenderingContext !== "undefined" ? WebGLRenderingContext.prototype.drawArrays : null,
    webgl2DrawArrays: typeof WebGL2RenderingContext !== "undefined" ? WebGL2RenderingContext.prototype.drawArrays : null,
    webglReadPixels: typeof WebGLRenderingContext !== "undefined" ? WebGLRenderingContext.prototype.readPixels : null,
    webgl2ReadPixels: typeof WebGL2RenderingContext !== "undefined" ? WebGL2RenderingContext.prototype.readPixels : null,
    fnCall: Function.prototype.call,
    fnApply: Function.prototype.apply,
    fnBind: Function.prototype.bind,
    reflectApply: typeof Reflect !== "undefined" ? Reflect.apply : null,
    ctxSave: typeof CanvasRenderingContext2D !== "undefined" ? CanvasRenderingContext2D.prototype.save : null,
    ctxRestore: typeof CanvasRenderingContext2D !== "undefined" ? CanvasRenderingContext2D.prototype.restore : null,
    canvasWidthSet: (() => {
      try {
        return Object.getOwnPropertyDescriptor(HTMLCanvasElement.prototype, "width")?.set || null;
      } catch {
        return null;
      }
    })(),
    canvasHeightSet: (() => {
      try {
        return Object.getOwnPropertyDescriptor(HTMLCanvasElement.prototype, "height")?.set || null;
      } catch {
        return null;
      }
    })(),
    at: Date.now()
  });
  return snapshot;
}
function verifyEarlyIntegritySnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== "object") return Object.freeze({ ok: false, issues: Object.freeze(["missing-snapshot"]) });
  const checks = [
    ["fetch", globalThis.fetch || null, snapshot.fetch],
    ["createImageBitmap", globalThis.createImageBitmap || null, snapshot.createImageBitmap],
    ["HTMLCanvasElement.prototype.getContext", typeof HTMLCanvasElement !== "undefined" ? HTMLCanvasElement.prototype.getContext : null, snapshot.canvasGetContext],
    ["WebGLRenderingContext.prototype.drawArrays", typeof WebGLRenderingContext !== "undefined" ? WebGLRenderingContext.prototype.drawArrays : null, snapshot.webglDrawArrays],
    ["WebGL2RenderingContext.prototype.drawArrays", typeof WebGL2RenderingContext !== "undefined" ? WebGL2RenderingContext.prototype.drawArrays : null, snapshot.webgl2DrawArrays],
    ["WebGLRenderingContext.prototype.readPixels", typeof WebGLRenderingContext !== "undefined" ? WebGLRenderingContext.prototype.readPixels : null, snapshot.webglReadPixels],
    ["WebGL2RenderingContext.prototype.readPixels", typeof WebGL2RenderingContext !== "undefined" ? WebGL2RenderingContext.prototype.readPixels : null, snapshot.webgl2ReadPixels],
    ["Function.prototype.call", Function.prototype.call, snapshot.fnCall],
    ["Function.prototype.apply", Function.prototype.apply, snapshot.fnApply],
    ["Function.prototype.bind", Function.prototype.bind, snapshot.fnBind],
    ["Reflect.apply", typeof Reflect !== "undefined" ? Reflect.apply : null, snapshot.reflectApply],
    ["CanvasRenderingContext2D.prototype.save", typeof CanvasRenderingContext2D !== "undefined" ? CanvasRenderingContext2D.prototype.save : null, snapshot.ctxSave],
    ["CanvasRenderingContext2D.prototype.restore", typeof CanvasRenderingContext2D !== "undefined" ? CanvasRenderingContext2D.prototype.restore : null, snapshot.ctxRestore],
    ["HTMLCanvasElement.prototype.width.set", currentDescriptorAccessor("HTMLCanvasElement", "width", "set"), snapshot.canvasWidthSet],
    ["HTMLCanvasElement.prototype.height.set", currentDescriptorAccessor("HTMLCanvasElement", "height", "set"), snapshot.canvasHeightSet]
  ];
  const issues = checks.filter(([, now, before]) => (before || now) && now !== before).map(([name]) => name);
  return Object.freeze({ ok: issues.length === 0, issues: Object.freeze(issues), snapshotAt: snapshot.at || null });
}
function detectAutomation() {
  const signals = [];
  try {
    if (typeof navigator !== "undefined") {
      if (navigator.webdriver) signals.push("webdriver");
      if (/HeadlessChrome|PhantomJS|Headless/i.test(navigator.userAgent || "")) signals.push("headless-ua");
      if (navigator.languages && navigator.languages.length === 0) signals.push("no-languages");
    }
    if (typeof window !== "undefined" && window.outerWidth === 0 && window.outerHeight === 0) signals.push("zero-outer-size");
  } catch {
  }
  return signals;
}

// src/client/registry.js
var instances = /* @__PURE__ */ new Set();
var hostToInstance = /* @__PURE__ */ new WeakMap();

// src/client/observers.js
function getVisibilityObserver(rootMargin = "500px") {
  const margin = typeof rootMargin === "string" && rootMargin.length <= 64 ? rootMargin : "500px";
  let observer = visibilityObservers.get(margin);
  if (!observer) {
    const callback = (entries) => {
      for (const e of entries) {
        const inst = hostToInstance.get(e.target);
        if (inst) inst._onVisibility(e.isIntersecting);
      }
    };
    try {
      observer = new IntersectionObserver(callback, { rootMargin: margin });
    } catch {
      observer = new IntersectionObserver(callback, { rootMargin: "500px" });
    }
    visibilityObservers.set(margin, observer);
  }
  return observer;
}
var sharedResizeObserver = null;
function getResizeObserver() {
  if (!sharedResizeObserver) {
    sharedResizeObserver = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const inst = hostToInstance.get(entry.target);
        if (inst) inst._onResize(entry);
      }
    });
  }
  return sharedResizeObserver;
}
var globalGuardsInstalled = false;
function installGlobalGuards() {
  if (globalGuardsInstalled || typeof window === "undefined") return;
  globalGuardsInstalled = true;
  const blackoutAll = (ms, kind) => instances.forEach((i) => i._momentaryBlackout(ms, kind));
  let lastCaptureKeyAt = 0;
  const onCaptureKey = (e) => {
    const key = String(e.key || "");
    const shotKey = key === "PrintScreen" || e.code === "PrintScreen";
    const macShot = e.metaKey && e.shiftKey && ["3", "4", "5"].includes(key);
    const snipShortcut = (e.metaKey || e.ctrlKey) && e.shiftKey && key.toLowerCase() === "s";
    if (!shotKey && !macShot && !snipShortcut) return;
    if (shotKey && navigator.clipboard?.writeText) {
      navigator.clipboard.writeText("").catch(() => {
      });
    }
    const now = Date.now();
    if (now - lastCaptureKeyAt < 250) return;
    lastCaptureKeyAt = now;
    blackoutAll(1200, "screenshot-key");
  };
  window.addEventListener("keydown", onCaptureKey, true);
  window.addEventListener("keyup", onCaptureKey, true);
  document.addEventListener("freeze", () => blackoutAll(1500, "screenshot-key"), true);
  window.addEventListener("blur", () => instances.forEach((i) => i._setRisk("blur", true)), true);
  window.addEventListener("focus", () => instances.forEach((i) => i._setRisk("blur", false)), true);
  document.addEventListener("visibilitychange", () => {
    instances.forEach((i) => i._setRisk("hidden", document.hidden));
  });
  if (window.matchMedia) {
    const mq = window.matchMedia("print");
    const onPrint = (m) => instances.forEach((i) => i._setRisk("print", m.matches));
    if (mq.addEventListener) mq.addEventListener("change", onPrint);
  }
  window.addEventListener("beforeprint", () => instances.forEach((i) => i._setRisk("print", true)));
  window.addEventListener("afterprint", () => instances.forEach((i) => i._setRisk("print", false)));
}
var devtoolsTimer = null;
function ensureDevtoolsWatcher() {
  if (devtoolsTimer) return;
  const check = () => {
    if (typeof document !== "undefined" && document.hidden) return;
    const open = window.outerWidth - window.innerWidth > 170 || window.outerHeight - window.innerHeight > 200;
    instances.forEach((i) => {
      if (i.options.guards.devtools) i._setRisk("devtools", open);
    });
  };
  check();
  window.addEventListener("resize", check, true);
  devtoolsTimer = setInterval(check, 400);
}
var glContextsInUse = 0;
var GL_CONTEXT_BUDGET = 8;
var $ = (t) => typeof t === "string" ? document.querySelector(t) : t;
var visibilityObservers = /* @__PURE__ */ new Map();
function glSlotsInUse() {
  return glContextsInUse;
}
function acquireGlSlot() {
  glContextsInUse++;
}
function releaseGlSlot() {
  glContextsInUse = Math.max(0, glContextsInUse - 1);
}

// src/client/styles.js
var SHADOW_CSS = `
  :host { display:block; }
  * { box-sizing: border-box; }
  .wrap {
    position:relative; width:100%; height:100%; overflow:hidden;
    background:#0b0e14; isolation:isolate;
    -webkit-touch-callout:none; -webkit-user-select:none; user-select:none;
    -webkit-user-drag:none;
  }
  .wrap.loading { background: linear-gradient(110deg,#12161f 30%,#1c2333 45%,#12161f 60%);
    background-size:200% 100%; animation: archx-shimmer 1.4s linear infinite; }
  @keyframes archx-shimmer { to { background-position:-200% 0; } }
  canvas.main, .tiles { position:absolute; inset:0; width:100%; height:100%; display:block; }
  .tiles { display:grid; }
  .tiles canvas { width:100%; height:100%; display:block; }
  .shield { position:absolute; inset:0; z-index:3; background:transparent; }
  .trace { position:absolute; inset:-20%; z-index:2; pointer-events:none; overflow:hidden; opacity:0; }
  .wrap.trace-on:not(.loading) .trace { opacity:1; }
  .wrap.blackout .trace { opacity:0 !important; }
  .trace.temporal::before { content:""; position:absolute; inset:0;
    background:repeating-linear-gradient(90deg, rgba(255,255,255,.028) 0 1px, transparent 1px 5px);
    animation:archx-trace-phase 1.4s linear infinite; }
  .trace-inner { position:absolute; inset:0; display:flex; flex-direction:column;
    justify-content:space-around; align-items:center; white-space:nowrap;
    color:rgba(255,255,255,var(--trace-opacity,.08));
    text-shadow:0 1px 2px rgba(0,0,0,.18);
    font:700 14px/1.2 system-ui,sans-serif; letter-spacing:.04em;
    transform:rotate(-17deg); transform-origin:center;
    animation:archx-trace-drift 14s ease-in-out infinite alternate; }
  @keyframes archx-trace-drift {
    from { transform:rotate(-17deg) translate(-1.5%,-1%); }
    to { transform:rotate(-17deg) translate(1.5%,1%); }
  }
  @keyframes archx-trace-phase { to { background-position:15px 0; } }
  @media (prefers-reduced-motion: reduce) {
    .trace-inner, .trace.temporal::before { animation:none; }
  }
  .risk { position:absolute; inset:0; z-index:4; pointer-events:none; opacity:0; transition:opacity .18s;
    backdrop-filter: blur(18px) brightness(.25) saturate(0); background:rgba(0,0,0,.55); }
  .wrap.risk-on .risk { opacity:1; }
  .wrap.risk-on canvas.main, .wrap.risk-on .tiles { filter: blur(22px) brightness(.2) saturate(0); }
  .wrap.blackout canvas.main, .wrap.blackout .tiles { opacity:0 !important; }
  .wrap.blackout { background:#000 !important; }
  .err { position:absolute; inset:0; display:none; place-items:center; color:#8b94a7;
    font:13px/1.5 system-ui,sans-serif; text-align:center; padding:16px; z-index:5; }
  .wrap.error .err { display:grid; }
  .badge { position:absolute; right:8px; bottom:8px; z-index:2; pointer-events:none;
    font:600 10px/1 system-ui,sans-serif; letter-spacing:.08em; color:rgba(255,255,255,.85);
    background:rgba(5,8,15,.55); padding:5px 7px; border-radius:99px; display:none; }
  .wrap.show-badge .badge { display:block; }
  @media print {
    .wrap { background:#000 !important; }
    canvas.main, .tiles { opacity:0 !important; visibility:hidden !important; }
  }
`;

// src/client/viewer.js
var _options, _host, _root, _wrap, _canvas, _tilesEl, _shieldEl, _source, _bitmap, _meta, _abort, _decoy, _decoySize, _gl, _raf, _loaded, _destroyed, _glBudgetWarned, _taintWarned, _canaryDone, _canaryPause, _canaryProbe, _canaryWait, _canaryNextTry, _preserveFlagged, _integrityHardLock, _glReleasing, _taintImage, _risk, _blackoutTimer, _resizeTimer, _visibilityObs, _realCtx, _attemptHandler, _loading, _visible, _unloaded, _glProg, _glLoc, _glTex, _glMap, _glWm, _glWmOn, _glSource, _glMeta, _frameCanvas, _lensBase, _lensPoint, _lensRaf, _lensCells, _lensCoverage, _lensRadiusScale, _lensRadiusAt, _traceEl, _traceTimer, _strikes, _lockedUntil, _lockTimer, _integrityIssues, _bitmapReleased, _loadedOnce, _cachedBytes, _cachedExtra, _bitmapCacheEntry, _prefetchedTokenMint, _renderedW, _renderedH, _deviceBox, _glFrameBudget, _glFrames, _temporalSign, _temporalPhase, _temporalRaf, _temporalFrames, _temporalIndex, _temporalEngineActual, _phaseBag, _signBalance, _dutyIndex, _biasSeed, _biasFrames, _lastInteractAt, _idleSkip, _temporalInterlaceCache, _ProtectedImage_instances, registerStrike_fn, trackLensTravel_fn, lensRadiusPx_fn, requestLensFrame_fn, tokenSourceId_fn, isTokenSource_fn, isAssetSource_fn, shouldUpgradeDerivative_fn, temporalConfig_fn, waitForStableSize_fn, tokenMintContext_fn, prefetchTokenBatchMint_fn, securityGate_fn, releaseSourceBitmap_fn, setupTemporalFrames_fn, nextPhase_fn, paintTemporal2d_fn, startTemporal2d_fn, stopTemporal2d_fn, paintLens2d_fn, prepareDecoy_fn, getDecoy_fn, taintContext_fn, fresh2dCanvas_fn, prepareGlSource_fn, flagPreserveRewrite_fn, paintBlackout_fn, canaryPresentable_fn, captureCanaryProbe_fn, checkCanaryProbe_fn, glContinuous_fn;
var ProtectedImage = class {
  constructor(target, source, options = {}) {
    __privateAdd(this, _ProtectedImage_instances);
    /* Everything sensitive is a #private field: page scripts and extension
     * content scripts that obtain an instance (or its host element) get no
     * handle to the canvas, bitmap, options/secrets, or shadow internals. */
    __privateAdd(this, _options);
    __privateAdd(this, _host);
    __privateAdd(this, _root);
    __privateAdd(this, _wrap);
    __privateAdd(this, _canvas);
    __privateAdd(this, _tilesEl);
    __privateAdd(this, _shieldEl);
    __privateAdd(this, _source);
    __privateAdd(this, _bitmap, null);
    __privateAdd(this, _meta, null);
    __privateAdd(this, _abort, new AbortController());
    __privateAdd(this, _decoy, null);
    __privateAdd(this, _decoySize, null);
    __privateAdd(this, _gl, null);
    __privateAdd(this, _raf, 0);
    __privateAdd(this, _loaded, false);
    __privateAdd(this, _destroyed, false);
    __privateAdd(this, _glBudgetWarned, false);
    __privateAdd(this, _taintWarned, false);
    __privateAdd(this, _canaryDone, false);
    __privateAdd(this, _canaryPause, false);
    __privateAdd(this, _canaryProbe, null);
    __privateAdd(this, _canaryWait, 0);
    __privateAdd(this, _canaryNextTry, 1);
    __privateAdd(this, _preserveFlagged, false);
    __privateAdd(this, _integrityHardLock, false);
    __privateAdd(this, _glReleasing, false);
    __privateAdd(this, _taintImage, null);
    __privateAdd(this, _risk, /* @__PURE__ */ new Set());
    __privateAdd(this, _blackoutTimer, 0);
    __privateAdd(this, _resizeTimer, 0);
    __privateAdd(this, _visibilityObs, null);
    __privateAdd(this, _realCtx, null);
    __privateAdd(this, _attemptHandler, null);
    __privateAdd(this, _loading, false);
    __privateAdd(this, _visible, false);
    __privateAdd(this, _unloaded, false);
    __privateAdd(this, _glProg, null);
    __privateAdd(this, _glLoc, null);
    __privateAdd(this, _glTex, null);
    __privateAdd(this, _glMap, null);
    __privateAdd(this, _glWm, null);
    __privateAdd(this, _glWmOn, 0);
    __privateAdd(this, _glSource, null);
    __privateAdd(this, _glMeta, null);
    __privateAdd(this, _frameCanvas, null);
    __privateAdd(this, _lensBase, null);
    __privateAdd(this, _lensPoint, null);
    __privateAdd(this, _lensRaf, 0);
    __privateAdd(this, _lensCells, []);
    __privateAdd(this, _lensCoverage, new Float64Array(64).fill(-1e15));
    __privateAdd(this, _lensRadiusScale, 1);
    __privateAdd(this, _lensRadiusAt, 0);
    __privateAdd(this, _traceEl, null);
    __privateAdd(this, _traceTimer, 0);
    __privateAdd(this, _strikes, 0);
    __privateAdd(this, _lockedUntil, 0);
    __privateAdd(this, _lockTimer, 0);
    __privateAdd(this, _integrityIssues, []);
    __privateAdd(this, _bitmapReleased, false);
    __privateAdd(this, _loadedOnce, false);
    __privateAdd(this, _cachedBytes, null);
    __privateAdd(this, _cachedExtra, null);
    __privateAdd(this, _bitmapCacheEntry, null);
    __privateAdd(this, _prefetchedTokenMint, null);
    __privateAdd(this, _renderedW, 0);
    __privateAdd(this, _renderedH, 0);
    __privateAdd(this, _deviceBox, null);
    __privateAdd(this, _glFrameBudget, 0);
    __privateAdd(this, _glFrames, 0);
    __privateAdd(this, _temporalSign, 1);
    __privateAdd(this, _temporalPhase, 0);
    __privateAdd(this, _temporalRaf, 0);
    __privateAdd(this, _temporalFrames, null);
    __privateAdd(this, _temporalIndex, 0);
    __privateAdd(this, _temporalEngineActual, null);
    __privateAdd(this, _phaseBag, []);
    __privateAdd(this, _signBalance, 0);
    __privateAdd(this, _dutyIndex, 0);
    __privateAdd(this, _biasSeed, Math.random() * 100);
    __privateAdd(this, _biasFrames, 0);
    __privateAdd(this, _lastInteractAt, 0);
    __privateAdd(this, _idleSkip, 0);
    __privateAdd(this, _temporalInterlaceCache);
    __privateSet(this, _options, mergeOptions(options));
    __privateSet(this, _source, source);
    const host = $(target);
    if (!host) throw new Error("Archx: target element not found: " + target);
    if (hostToInstance.has(host)) {
      throw new Error("Archx: target element already hosts a live protected image; destroy it or use a fresh host");
    }
    __privateSet(this, _host, host);
    host.classList.add("archx-host");
    if (__privateGet(this, _options).alt) {
      host.setAttribute("role", "img");
      host.setAttribute("aria-label", __privateGet(this, _options).alt);
    }
    this._buildDom();
    this._attachGuards();
    this._startCaptureTrace();
    hostToInstance.set(host, this);
    instances.add(this);
    installGlobalGuards();
    if (__privateGet(this, _options).guards.devtools) ensureDevtoolsWatcher();
    this.ready = this._init();
  }
  /** Sanitised, secret-free view of the effective options. */
  get options() {
    return sanitizeOptionsView(__privateGet(this, _options));
  }
  /* ---------------- DOM ---------------- */
  _buildDom() {
    const o = __privateGet(this, _options);
    let root;
    if (o.shadow === "none") {
      root = __privateGet(this, _host);
    } else {
      try {
        const attachInit = { mode: o.shadow === "open" ? "open" : "closed" };
        root = NATIVES.attachShadow ? nativeCall(NATIVES.attachShadow, __privateGet(this, _host), [attachInit]) : __privateGet(this, _host).attachShadow(attachInit);
      } catch {
        throw new Error('Archx: unable to attach the requested shadow root; use a fresh host element or shadow:"none" explicitly');
      }
    }
    __privateSet(this, _root, root);
    const doc = __privateGet(this, _host).ownerDocument;
    let style = null;
    let adoptedStyles = false;
    if (root !== __privateGet(this, _host) && typeof CSSStyleSheet !== "undefined" && "adoptedStyleSheets" in root) {
      try {
        const sheet = new CSSStyleSheet();
        sheet.replaceSync(SHADOW_CSS);
        root.adoptedStyleSheets = [...root.adoptedStyleSheets, sheet];
        adoptedStyles = true;
      } catch {
      }
    }
    if (!adoptedStyles) {
      style = doc.createElement("style");
      style.textContent = SHADOW_CSS;
    }
    const wrap = doc.createElement("div");
    wrap.className = "wrap loading" + (o.showBadge ? " show-badge" : "");
    wrap.innerHTML = `
      <div class="tiles" hidden></div>
      <canvas class="main" aria-hidden="true"></canvas>
      <div class="badge">ARCHX&nbsp;PROTECTED</div>
      <div class="trace" aria-hidden="true"><div class="trace-inner"><span></span><span></span><span></span><span></span><span></span></div></div>
      <div class="shield"></div>
      <div class="risk"></div>
      <div class="err"><span>\u26A0<br>Protected image unavailable</span></div>`;
    if (style) root.append(style, wrap);
    else root.append(wrap);
    __privateSet(this, _wrap, wrap);
    __privateSet(this, _canvas, wrap.querySelector("canvas.main"));
    __privateSet(this, _tilesEl, wrap.querySelector(".tiles"));
    __privateSet(this, _shieldEl, wrap.querySelector(".shield"));
    __privateSet(this, _traceEl, wrap.querySelector(".trace"));
    if (o.aspectRatio) __privateGet(this, _host).style.aspectRatio = String(o.aspectRatio);
    if (o.width) __privateGet(this, _host).style.width = typeof o.width === "number" ? o.width + "px" : o.width;
    if (o.height) __privateGet(this, _host).style.height = typeof o.height === "number" ? o.height + "px" : o.height;
  }
  _attachGuards() {
    const o = __privateGet(this, _options);
    const sig = { signal: __privateGet(this, _abort).signal };
    const attempt = (kind) => {
      try {
        o.onAttempt && o.onAttempt(kind, this);
      } catch {
      }
      __privateGet(this, _host).dispatchEvent(new CustomEvent("archx-attempt", { detail: { kind }, bubbles: true }));
      emitClientEvent("archx.attempt", { kind, outcome: "detected" }, this);
      __privateMethod(this, _ProtectedImage_instances, registerStrike_fn).call(this, kind);
    };
    __privateSet(this, _attemptHandler, attempt);
    if (o.guards.contextMenu) {
      __privateGet(this, _wrap).addEventListener("contextmenu", (e) => {
        e.preventDefault();
        e.stopPropagation();
        attempt("contextmenu");
      }, sig);
    }
    if (o.guards.drag) {
      __privateGet(this, _wrap).addEventListener("dragstart", (e) => {
        e.preventDefault();
        attempt("drag");
      }, sig);
    }
    if (o.guards.copy) {
      __privateGet(this, _wrap).addEventListener("copy", (e) => {
        e.preventDefault();
        attempt("copy");
      }, sig);
      __privateGet(this, _wrap).addEventListener("selectstart", (e) => e.preventDefault(), sig);
    }
    if (o.guards.longPress) {
      let timer = 0;
      __privateGet(this, _wrap).addEventListener("pointerdown", (e) => {
        if (e.pointerType !== "touch") return;
        timer = setTimeout(() => {
          attempt("longpress");
          this._momentaryBlackout(700, "longpress");
        }, 450);
      }, sig);
      const clear = () => clearTimeout(timer);
      __privateGet(this, _wrap).addEventListener("pointerup", clear, sig);
      __privateGet(this, _wrap).addEventListener("pointercancel", clear, sig);
      __privateGet(this, _wrap).addEventListener("pointermove", clear, sig);
    }
    const interact = () => {
      __privateSet(this, _lastInteractAt, performance.now());
    };
    __privateGet(this, _wrap).addEventListener("pointermove", interact, { ...sig, passive: true });
    __privateGet(this, _wrap).addEventListener("pointerdown", interact, { ...sig, passive: true });
    __privateGet(this, _wrap).addEventListener("touchmove", interact, { ...sig, passive: true });
    __privateGet(this, _wrap).addEventListener("wheel", interact, { ...sig, passive: true });
    __privateGet(this, _shieldEl).addEventListener("click", (e) => {
      if (o.onClick) {
        try {
          o.onClick(e, this);
        } catch {
        }
      }
      if (!o.swallowClick) {
        __privateGet(this, _host).dispatchEvent(new MouseEvent("click", { bubbles: true, clientX: e.clientX, clientY: e.clientY }));
      }
    }, sig);
    if (o.lens) {
      const updateLens = (e) => {
        if (!e.isTrusted) return;
        const r = __privateGet(this, _wrap).getBoundingClientRect();
        if (r.width <= 0 || r.height <= 0) return;
        __privateSet(this, _lensPoint, {
          x: Math.max(0, Math.min(1, (e.clientX - r.left) / r.width)),
          y: Math.max(0, Math.min(1, (e.clientY - r.top) / r.height))
        });
        __privateMethod(this, _ProtectedImage_instances, trackLensTravel_fn).call(this, __privateGet(this, _lensPoint));
        __privateMethod(this, _ProtectedImage_instances, requestLensFrame_fn).call(this);
      };
      __privateGet(this, _shieldEl).addEventListener("pointermove", updateLens, sig);
      __privateGet(this, _shieldEl).addEventListener("pointerdown", updateLens, sig);
      __privateGet(this, _shieldEl).addEventListener("pointerleave", () => {
        __privateSet(this, _lensPoint, null);
        __privateMethod(this, _ProtectedImage_instances, requestLensFrame_fn).call(this);
      }, sig);
    }
  }
  /**
   * Dynamic capture trace (Fortress / captureShield): a low-opacity,
   * slowly drifting session+time code above the pixels. It cannot stop an
   * OS screenshot, browser-extension capture, DevTools/CDP capture, or a
   * camera pointed at another screen — no web API can — but it makes those
   * captures attributable and makes multi-frame/multi-device stitching less
   * clean. `temporalPattern` adds a shifting phase pattern for the same reason.
   */
  _startCaptureTrace() {
    const raw = __privateGet(this, _options).captureShield;
    if (!raw || !__privateGet(this, _traceEl) || __privateGet(this, _traceTimer)) return;
    const cfg = raw === true ? {} : raw;
    if (!cfg || cfg.dynamicTrace === false) return;
    __privateGet(this, _wrap).classList.add("trace-on");
    __privateGet(this, _traceEl).classList.toggle("temporal", !!cfg.temporalPattern);
    __privateGet(this, _traceEl).style.setProperty("--trace-opacity", String(cfg.opacity ?? 0.08));
    const update = () => {
      if (__privateGet(this, _destroyed) || !__privateGet(this, _traceEl)) return;
      if (__privateGet(this, _host).ownerDocument?.hidden) return;
      if (__privateGet(this, _loadedOnce) && !__privateGet(this, _visible)) return;
      const wm = __privateGet(this, _options).watermark;
      const wmText = typeof wm === "string" ? wm : wm?.text;
      let template = cfg.text || wmText || `${__privateGet(this, _options).brand} \xB7 {session} \xB7 {time}`;
      if (!template.includes("{time}")) template += " \xB7 {time}";
      const text = String(template).replaceAll("{session}", sessionId().slice(0, 6)).replaceAll("{time}", (/* @__PURE__ */ new Date()).toISOString().slice(11, 19));
      const inner = __privateGet(this, _traceEl).querySelector(".trace-inner");
      if (inner) {
        const width = __privateGet(this, _wrap).clientWidth || __privateGet(this, _host).clientWidth || 320;
        inner.style.fontSize = `${Math.max(10, Math.min(24, Math.round(width / 18)))}px`;
        inner.querySelectorAll("span").forEach((span) => {
          span.textContent = text;
        });
      }
    };
    update();
    __privateSet(this, _traceTimer, setInterval(update, Math.max(1e3, cfg.updateMs ?? 4e3)));
  }
  _onVisibility(visible) {
    __privateSet(this, _visible, visible);
    if (visible && !__privateGet(this, _loaded) && !__privateGet(this, _loading)) this._load();
    if (visible && __privateGet(this, _loaded) && __privateGet(this, _unloaded)) {
      __privateSet(this, _unloaded, false);
      if (__privateGet(this, _gl)) this._startGlLoop(2);
      else if (__privateGet(this, _bitmap)) this._render();
      else this._load();
    }
    if (!visible && __privateGet(this, _options).unloadOnExit && __privateGet(this, _loaded)) this._unloadPixels();
    if (!visible) __privateMethod(this, _ProtectedImage_instances, stopTemporal2d_fn).call(this);
    else if (__privateGet(this, _temporalFrames)) __privateMethod(this, _ProtectedImage_instances, startTemporal2d_fn).call(this);
    if (__privateGet(this, _gl)) visible ? this._startGlLoop(2) : this._stopGlLoop();
  }
  _onResize(entry) {
    const box = entry?.devicePixelContentBoxSize?.[0];
    if (box && box.inlineSize > 0 && box.blockSize > 0) {
      __privateSet(this, _deviceBox, { w: box.inlineSize, h: box.blockSize });
    }
    clearTimeout(__privateGet(this, _resizeTimer));
    __privateSet(this, _resizeTimer, setTimeout(() => {
      if (__privateGet(this, _destroyed)) return;
      const previousW = __privateGet(this, _renderedW);
      const previousH = __privateGet(this, _renderedH);
      const upgrade = __privateMethod(this, _ProtectedImage_instances, shouldUpgradeDerivative_fn).call(this, previousW, previousH);
      if (__privateGet(this, _gl)) {
        this._startGlLoop(2);
        if (upgrade) void this._load({ force: true });
        return;
      }
      if (__privateGet(this, _bitmap)) {
        this._render();
        if (upgrade) void this._load({ force: true });
      } else if (__privateGet(this, _loaded) && __privateGet(this, _bitmapReleased) && __privateGet(this, _visible)) {
        const policy = __privateGet(this, _options).reloadOnResize;
        if (policy === "always") void this._load({ force: __privateMethod(this, _ProtectedImage_instances, isTokenSource_fn).call(this) || __privateMethod(this, _ProtectedImage_instances, isAssetSource_fn).call(this) });
        else if (policy === "upscale" && __privateGet(this, _meta)) {
          const { w, h } = this._backingSize();
          const f = Math.max(1, __privateGet(this, _options).resizeUpscaleFactor || 1.75);
          if (w > previousW * f || h > previousH * f) {
            void this._load({ force: __privateMethod(this, _ProtectedImage_instances, isTokenSource_fn).call(this) || __privateMethod(this, _ProtectedImage_instances, isAssetSource_fn).call(this) });
          }
        }
      }
    }, 90));
  }
  async _init() {
    const resizeObserver = getResizeObserver();
    try {
      resizeObserver.observe(__privateGet(this, _host), { box: "device-pixel-content-box" });
    } catch {
      resizeObserver.observe(__privateGet(this, _host));
    }
    if (__privateGet(this, _options).lazy && "IntersectionObserver" in window) {
      __privateSet(this, _visibilityObs, getVisibilityObserver(__privateGet(this, _options).rootMargin));
      __privateGet(this, _visibilityObs).observe(__privateGet(this, _host));
      const r = __privateGet(this, _host).getBoundingClientRect();
      if (r.bottom > 0 && r.top < innerHeight) this._load();
    } else {
      __privateSet(this, _visible, true);
      await this._load();
    }
    return this;
  }
  async _resolveBytes(force = false) {
    const o = __privateGet(this, _options);
    const src = __privateGet(this, _source);
    const extra = {};
    const controls = fetchControls(o);
    const strict = o.memory === "strict";
    const cacheBitmap = o.cacheBitmap !== false && !strict;
    if (!force && __privateGet(this, _cachedBytes)) {
      return { ...await this._bytesToBitmap(__privateGet(this, _cachedBytes), __privateGet(this, _cachedExtra) || {}), extra: __privateGet(this, _cachedExtra) || {} };
    }
    if (src && typeof src === "object" && !(src instanceof Blob) && !(src instanceof ArrayBuffer) && !ArrayBuffer.isView(src) && (src.assetId || src.asset)) {
      const assetId = src.assetId || src.asset;
      if (typeof assetId !== "string" || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(assetId)) {
        throw nonRetryableError("Archx: asset id is invalid");
      }
      const manifestSource = src.manifest || o.assetManifest;
      if (!manifestSource) throw new Error("Archx: assetManifest required for {assetId} sources");
      const manifest = await loadAssetManifest(manifestSource, o, controls);
      const asset = manifest.assets.get(assetId);
      if (!asset) throw nonRetryableError("Archx: asset id is not present in the manifest");
      const rect = __privateGet(this, _host).getBoundingClientRect?.();
      const cssWidth = rect?.width || __privateGet(this, _host).clientWidth || 800;
      const cssHeight = rect?.height || __privateGet(this, _host).clientHeight || cssWidth * 0.75;
      const { dprCap, oversample } = effectiveSampling(o);
      const pixelScale = Math.min(devicePixelRatio || 1, dprCap) * Math.max(1, oversample);
      const maxSourceWidth = boundedInteger(o.maxSourceWidth, DEFAULTS.maxSourceWidth, 64, 16384);
      const boxW = canonicalSourceWidth(cssWidth * pixelScale, o.sourceWidthBuckets, maxSourceWidth);
      const boxH = canonicalSourceWidth(cssHeight * pixelScale, o.sourceWidthBuckets, maxSourceWidth);
      const fit = ["cover", "contain", "fill"].includes(o.fit) ? o.fit : "cover";
      const aspect = asset.width / asset.height;
      const neededWidth = fit === "contain" ? Math.min(boxW, boxH * aspect) : fit === "fill" ? boxW : Math.max(boxW, boxH * aspect);
      const variant = chooseAssetVariant(asset, neededWidth);
      const assetExtra = {
        key: asset.key,
        grid: asset.grid,
        ...asset.planVersion !== void 0 ? { planVersion: asset.planVersion } : {},
        ...asset.aesKey !== void 0 ? { aesKey: asset.aesKey } : {}
      };
      const assetCacheMode = normalizedHttpCache(o.assetHttpCache, "default");
      const assetCacheKey = cacheDigest([
        "asset",
        2,
        o.cacheScope || "",
        assetId,
        variant.url.href,
        variant.width,
        variant.sha256 || "",
        normalizeAssetIntegrityMode(o.assetIntegrity),
        asset.key,
        asset.grid,
        asset.aesKey || "",
        controls.credentials,
        assetCacheMode,
        controls.maxResponseBytes,
        controls.maxDecodedPixels,
        controls.maxDecodedDimension
      ]);
      if (!force && cacheBitmap) {
        const hitEntry = cacheGetEntry(assetCacheKey, { acquire: true });
        if (hitEntry) {
          const hit = await hitEntry.promise;
          return { ...hit, extra: hit.extra || assetExtra, cacheEntry: hitEntry };
        }
      }
      const assetPromise = (async () => {
        const { bytes: buf } = await fetchBounded(variant.url.href, {
          method: "GET",
          credentials: controls.credentials,
          cache: assetCacheMode,
          signal: __privateGet(this, _abort).signal,
          ...fetchPriorityInit(o)
        }, {
          retries: controls.retries,
          maxBytes: controls.maxResponseBytes,
          timeoutMs: controls.fetchTimeoutMs,
          validateResponse: (res) => {
            if (!res.url) return;
            let finalUrl;
            try {
              finalUrl = new URL(res.url);
            } catch {
              throw nonRetryableError("Archx: asset response URL is invalid");
            }
            if (!["http:", "https:"].includes(finalUrl.protocol) || finalUrl.username || finalUrl.password) {
              throw nonRetryableError("Archx: asset response URL is disallowed");
            }
          }
        });
        await verifyAssetVariantIntegrity(variant, buf, o);
        if (o.cachePayload !== false) {
          __privateSet(this, _cachedBytes, buf);
          __privateSet(this, _cachedExtra, assetExtra);
        }
        return { ...await this._bytesToBitmap(buf, assetExtra), extra: assetExtra };
      })();
      const cacheEntry = cacheBitmap ? cachePut(assetCacheKey, assetPromise, o) : null;
      const result = await assetPromise;
      return { ...result, cacheEntry };
    }
    const tokenId = __privateMethod(this, _ProtectedImage_instances, tokenSourceId_fn).call(this);
    if (tokenId != null) {
      if (typeof tokenId !== "string" || !tokenId || tokenId.length > 256 || /[\u0000-\u001f\u007f]/.test(tokenId)) {
        throw nonRetryableError("Archx: token image id is invalid");
      }
      const {
        endpointUrl,
        boxW,
        boxH,
        fit,
        requestQuality,
        tokenMethod,
        tokenTransport,
        proofMode,
        proofKey,
        mintUrl,
        tokenCacheKey
      } = await __privateMethod(this, _ProtectedImage_instances, tokenMintContext_fn).call(this, controls);
      if (!force && cacheBitmap) {
        const hitEntry = cacheGetEntry(tokenCacheKey, { acquire: true });
        if (hitEntry) {
          __privateSet(this, _prefetchedTokenMint, null);
          const hit = await hitEntry.promise;
          return { ...hit, extra: hit.extra || {}, cacheEntry: hitEntry };
        }
      }
      const mintHeaders = proofKey ? { "X-Archx-Request": "token", "X-Archx-Proof-Key": proofKey.header } : { "X-Archx-Request": "token" };
      const batchUrl = o.tokenBatch === true && tokenMethod === "POST" ? deriveTokenBatchEndpoint(endpointUrl, o) : null;
      const requestMint = async (tokenAttempt) => {
        if (batchUrl && tokenAttempt === 0) {
          try {
            const prefetched = __privateGet(this, _prefetchedTokenMint)?.key === tokenCacheKey ? __privateGet(this, _prefetchedTokenMint).promise : null;
            __privateSet(this, _prefetchedTokenMint, null);
            return await (prefetched || queueTokenBatchRequest({
              batchUrl,
              item: {
                id: tokenId,
                w: boxW,
                bw: boxW,
                bh: boxH,
                fit,
                ...requestQuality != null ? { q: requestQuality } : {}
              },
              headers: mintHeaders,
              credentials: controls.credentials,
              controls,
              signal: __privateGet(this, _abort).signal,
              options: o
            }));
          } catch (err) {
            const endpointUnsupported = !err?.archxBatchItem && [404, 405, 501].includes(err?.status);
            if (__privateGet(this, _abort).signal.aborted || !endpointUnsupported) throw err;
          }
        }
        const doMintFetch = (headers) => fetchBounded(mintUrl.href, {
          method: tokenMethod,
          credentials: controls.credentials,
          cache: "no-store",
          redirect: "error",
          headers,
          signal: __privateGet(this, _abort).signal,
          ...fetchPriorityInit(o)
        }, {
          retries: controls.retries,
          maxBytes: 65536,
          timeoutMs: controls.fetchTimeoutMs,
          validateResponse: (res) => assertResponseFinalOrigin(res, /* @__PURE__ */ new Set([endpointUrl.origin]))
        });
        let mint;
        try {
          mint = await doMintFetch(mintHeaders);
        } catch (err) {
          if (!err?.challengeRequired || typeof o.onChallenge !== "function" || __privateGet(this, _destroyed)) throw err;
          const proof = await o.onChallenge({ id: tokenId, reason: "suspicious-scraping" });
          if (typeof proof !== "string" || !proof || proof.length > 8192) throw err;
          mint = await doMintFetch({ ...mintHeaders, "X-Archx-Challenge": proof });
        }
        return parseBoundedJson(mint.bytes);
      };
      const tokenPromise = (async () => {
        for (let tokenAttempt = 0; tokenAttempt <= 1; tokenAttempt++) {
          const parsed = parseTokenResponse(await requestMint(tokenAttempt), o, mintUrl);
          const payloadHeaders = parsed.headerToken ? { "X-Archx-Token": parsed.headerToken } : {};
          if (proofKey) {
            const proof = await createProofHeader(proofKey, parsed.accessToken, parsed.payloadUrl);
            if (!proof) throw nonRetryableError("Archx: proof-of-possession could not be created");
            payloadHeaders["X-Archx-Proof"] = proof;
          }
          const payload = await fetchBounded(parsed.payloadUrl.href, {
            method: "GET",
            credentials: controls.credentials,
            cache: "no-store",
            redirect: "error",
            headers: payloadHeaders,
            signal: __privateGet(this, _abort).signal,
            ...fetchPriorityInit(o)
          }, {
            retries: 0,
            maxBytes: controls.maxResponseBytes,
            timeoutMs: controls.fetchTimeoutMs,
            allowedStatuses: /* @__PURE__ */ new Set([401, 403]),
            validateResponse: (res) => assertResponseFinalOrigin(res, parsed.allowedOrigins)
          });
          if (payload.bytes == null) {
            if (tokenAttempt === 0) continue;
            const err = new Error("Archx fetch failed: HTTP " + payload.response.status);
            err.status = payload.response.status;
            throw err;
          }
          const buf = payload.bytes;
          if (o.cachePayload !== false) {
            __privateSet(this, _cachedBytes, buf);
            __privateSet(this, _cachedExtra, parsed.extra);
          }
          return { ...await this._bytesToBitmap(buf, parsed.extra), extra: parsed.extra };
        }
        throw new Error("Archx: token request failed");
      })();
      const cacheEntry = cacheBitmap ? cachePut(tokenCacheKey, tokenPromise, o) : null;
      const result = await tokenPromise;
      return { ...result, cacheEntry };
    }
    if (typeof src === "string") {
      let sourceUrl;
      try {
        if (!src || /[\u0000-\u001f\u007f]/.test(src) || !src.startsWith("data:") && src.length > 16384 || src.startsWith("data:") && src.length > controls.maxResponseBytes * 2 + 1024) {
          throw new Error("invalid source URL");
        }
        sourceUrl = new URL(src, typeof document !== "undefined" ? document.baseURI : void 0);
        if (!["http:", "https:", "blob:", "data:"].includes(sourceUrl.protocol) || sourceUrl.username || sourceUrl.password) {
          throw new Error("disallowed source URL");
        }
      } catch {
        throw nonRetryableError("Archx: image source URL is invalid");
      }
      const cacheKey = cacheDigest([
        "url",
        1,
        o.cacheScope || "",
        sourceUrl.href,
        controls.credentials,
        normalizedHttpCache(o.httpCache, "no-store"),
        o.grid,
        o.scrambled === true,
        o.key || "",
        o.aesKey || "",
        controls.maxResponseBytes,
        controls.maxDecodedPixels,
        controls.maxDecodedDimension
      ]);
      if (!force && cacheBitmap) {
        const hitEntry = cacheGetEntry(cacheKey, { acquire: true });
        if (hitEntry) {
          const hit = await hitEntry.promise;
          return { ...hit, extra: hit.extra || extra, cacheEntry: hitEntry };
        }
      }
      const promise = (async () => {
        const { bytes: buf } = await fetchBounded(sourceUrl.href, {
          credentials: controls.credentials,
          cache: normalizedHttpCache(o.httpCache, "no-store"),
          signal: __privateGet(this, _abort).signal,
          ...fetchPriorityInit(o)
        }, {
          retries: controls.retries,
          maxBytes: controls.maxResponseBytes,
          timeoutMs: controls.fetchTimeoutMs,
          validateResponse: (res) => {
            if (!res.url) return;
            let finalUrl;
            try {
              finalUrl = new URL(res.url);
            } catch {
              throw nonRetryableError("Archx: image response URL is invalid");
            }
            if (!["http:", "https:", "blob:", "data:"].includes(finalUrl.protocol)) {
              throw nonRetryableError("Archx: image response URL is disallowed");
            }
          }
        });
        if (o.cachePayload !== false) {
          __privateSet(this, _cachedBytes, buf);
          __privateSet(this, _cachedExtra, extra);
        }
        return this._bytesToBitmap(buf, extra);
      })();
      const cacheEntry = cacheBitmap ? cachePut(cacheKey, promise, o) : null;
      const result = await promise;
      return { ...result, extra, cacheEntry };
    }
    if (src instanceof Blob) {
      if (!Number.isSafeInteger(src.size) || src.size < 1 || src.size > controls.maxResponseBytes) {
        throw nonRetryableError("Archx: Blob source exceeds the configured byte limit", "ARCHX_RESPONSE_TOO_LARGE");
      }
      const buf = asByteArray(await src.arrayBuffer());
      if (buf.length > controls.maxResponseBytes) throw nonRetryableError("Archx: Blob source exceeds the configured byte limit", "ARCHX_RESPONSE_TOO_LARGE");
      if (o.cachePayload !== false) {
        __privateSet(this, _cachedBytes, buf);
        __privateSet(this, _cachedExtra, extra);
      }
      return { ...await this._bytesToBitmap(buf, extra), extra };
    }
    if (src instanceof ArrayBuffer || ArrayBuffer.isView(src)) {
      const bytes = asByteArray(src);
      if (!bytes.length || bytes.length > controls.maxResponseBytes) {
        throw nonRetryableError("Archx: byte source exceeds the configured byte limit", "ARCHX_RESPONSE_TOO_LARGE");
      }
      if (o.cachePayload !== false) {
        __privateSet(this, _cachedBytes, bytes);
        __privateSet(this, _cachedExtra, extra);
      }
      return { ...await this._bytesToBitmap(bytes, extra), extra };
    }
    throw new Error("Archx: unsupported source type");
  }
  async _bytesToBitmap(buf, extra = {}) {
    const o = __privateGet(this, _options);
    const controls = fetchControls(o);
    const bytes = asByteArray(buf);
    if (!bytes.length || bytes.length > controls.maxResponseBytes) {
      throw nonRetryableError("Archx: image payload exceeds the configured byte limit", "ARCHX_RESPONSE_TOO_LARGE");
    }
    let header = null;
    let payload = bytes;
    if (isArchxContainer(bytes)) {
      const decoded = decodeContainer(bytes);
      header = decoded.header;
      if (header.pw > controls.maxDecodedDimension || header.ph > controls.maxDecodedDimension || header.pw * header.ph > controls.maxDecodedPixels) {
        throw nonRetryableError("Archx: image dimensions exceed the configured decode budget", "ARCHX_RESPONSE_TOO_LARGE");
      }
      payload = decoded.payload;
      if (header.encrypted) {
        const aesKey = extra.aesKey || o.aesKey;
        if (typeof aesKey !== "string" || !aesKey) throw new Error("Archx: encrypted .archx payload needs aesKey");
        payload = asByteArray(await decryptPayload(payload, aesKey, header.iv));
        if (!payload.length || payload.length > controls.maxResponseBytes) {
          throw nonRetryableError("Archx: decrypted image exceeds the configured byte limit", "ARCHX_RESPONSE_TOO_LARGE");
        }
      }
    }
    const sniffed = sniffImageInfo(payload);
    const browserRasterFormats = /* @__PURE__ */ new Set(["png", "jpeg", "webp", "avif", "gif", "bmp"]);
    if (!sniffed || !browserRasterFormats.has(sniffed.format)) {
      throw nonRetryableError("Archx: unsupported or unrecognized image payload");
    }
    if (header && sniffed.mime !== header.mime) {
      throw nonRetryableError("Archx: .archx payload format does not match its header");
    }
    if (sniffed.width && sniffed.height) {
      if (sniffed.width > controls.maxDecodedDimension || sniffed.height > controls.maxDecodedDimension || sniffed.width * sniffed.height > controls.maxDecodedPixels) {
        throw nonRetryableError("Archx: image dimensions exceed the configured decode budget", "ARCHX_RESPONSE_TOO_LARGE");
      }
      if (header && !(sniffed.width === header.pw && sniffed.height === header.ph || sniffed.width === header.ph && sniffed.height === header.pw)) {
        throw nonRetryableError("Archx: .archx payload dimensions do not match its header");
      }
    }
    const scrambled = header ? header.scrambled : o.scrambled === true;
    const grid = header?.grid ?? extra.grid ?? o.grid;
    if (!Number.isInteger(grid) || grid < 2 || grid > 32) throw nonRetryableError("Archx: invalid scramble grid");
    const keyValue = extra.key ?? o.key ?? "";
    if (!["string", "number", "bigint"].includes(typeof keyValue)) throw nonRetryableError("Archx: invalid scramble key");
    const key = String(keyValue);
    const planVersion = header?.pv ?? o.planVersion ?? 1;
    if (planVersion !== 1 && planVersion !== 2) throw nonRetryableError("Archx: invalid scramble plan version");
    const blob = new Blob([payload], { type: header?.mime || sniffed.mime });
    let bitmap;
    try {
      bitmap = await nativeCreateImageBitmap(blob);
    } catch (err) {
      if (__privateGet(this, _destroyed) || __privateGet(this, _abort).signal.aborted) throw err;
      bitmap = await this._bitmapViaImage(blob, controls.fetchTimeoutMs);
    }
    const bitmapW = bitmap?.width || bitmap?.naturalWidth || 0;
    const bitmapH = bitmap?.height || bitmap?.naturalHeight || 0;
    if (!Number.isSafeInteger(bitmapW) || !Number.isSafeInteger(bitmapH) || bitmapW < 1 || bitmapH < 1 || bitmapW > controls.maxDecodedDimension || bitmapH > controls.maxDecodedDimension || bitmapW * bitmapH > controls.maxDecodedPixels) {
      closeBitmapQuietly(bitmap);
      throw nonRetryableError("Archx: decoded image exceeds the configured dimension budget", "ARCHX_RESPONSE_TOO_LARGE");
    }
    let meta;
    if (scrambled) {
      let origW;
      let origH;
      let padW;
      let padH;
      if (header) {
        if (bitmapW === header.pw && bitmapH === header.ph) {
          ({ w: origW, h: origH, pw: padW, ph: padH } = header);
        } else if (bitmapW === header.ph && bitmapH === header.pw && header.pw !== header.ph) {
          origW = header.h;
          origH = header.w;
          padW = bitmapW;
          padH = bitmapH;
        } else {
          closeBitmapQuietly(bitmap);
          throw nonRetryableError("Archx: decoded image dimensions do not match its .archx header");
        }
      } else {
        if (bitmapW % grid !== 0 || bitmapH % grid !== 0) {
          closeBitmapQuietly(bitmap);
          throw nonRetryableError("Archx: scrambled image dimensions are not divisible by the grid");
        }
        origW = bitmapW;
        origH = bitmapH;
        padW = bitmapW;
        padH = bitmapH;
      }
      meta = { plan: buildScramblePlan(grid, key, planVersion), origW, origH, padW, padH };
    } else {
      meta = { plan: null, origW: bitmapW, origH: bitmapH, padW: bitmapW, padH: bitmapH };
    }
    return { bitmap, meta, header };
  }
  _bitmapViaImage(blob, timeoutMs = DEFAULTS.fetchTimeoutMs) {
    return new Promise((resolve, reject) => {
      const url = NATIVES.createObjectURL ? nativeCall(NATIVES.createObjectURL, URL, [blob]) : URL.createObjectURL(blob);
      const img = new (NATIVES.ImageCtor || Image)();
      let settled = false;
      const finish = (fn, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        img.onload = null;
        img.onerror = null;
        NATIVES.revokeObjectURL ? nativeCall(NATIVES.revokeObjectURL, URL, [url]) : URL.revokeObjectURL(url);
        fn(value);
      };
      const timer = setTimeout(() => {
        try {
          img.src = "";
        } catch {
        }
        finish(reject, new Error("Archx: image decode timed out"));
      }, Math.max(100, Math.floor(Number(timeoutMs) || DEFAULTS.fetchTimeoutMs)));
      img.onload = () => finish(resolve, img);
      img.onerror = () => finish(reject, new Error("Archx: image decode failed"));
      img.src = url;
    });
  }
  async _load({ force = false } = {}) {
    if (__privateGet(this, _loading) || __privateGet(this, _destroyed)) return;
    if (!force && __privateGet(this, _loadedOnce) && __privateGet(this, _bitmap) && __privateGet(this, _meta)) {
      this._render();
      __privateSet(this, _loaded, true);
      __privateSet(this, _unloaded, false);
      __privateGet(this, _wrap).classList.remove("loading", "error");
      return;
    }
    if (!__privateMethod(this, _ProtectedImage_instances, securityGate_fn).call(this)) {
      __privateGet(this, _wrap).classList.remove("loading");
      __privateGet(this, _wrap).classList.add("error");
      emitClientEvent("archx.blocked", {
        reason: "integrity-automation-or-lockout-policy",
        outcome: "blocked",
        issues: __privateGet(this, _integrityIssues)
      }, this);
      __privateGet(this, _host).dispatchEvent(new CustomEvent("archx-error", {
        detail: { error: new Error("Archx: blocked by integrity/automation/lockout policy") },
        bubbles: true
      }));
      return;
    }
    __privateSet(this, _loading, true);
    try {
      if (!__privateGet(this, _loadedOnce)) await __privateMethod(this, _ProtectedImage_instances, waitForStableSize_fn).call(this);
      if (__privateGet(this, _destroyed)) return;
      await __privateMethod(this, _ProtectedImage_instances, prefetchTokenBatchMint_fn).call(this, force);
      if (__privateGet(this, _destroyed)) return;
      const result = await limiter.run(() => this._resolveBytes(force));
      if (__privateGet(this, _destroyed)) {
        if (result?.cacheEntry) cacheReleaseEntry(result.cacheEntry);
        else closeBitmapQuietly(result?.bitmap);
        return;
      }
      const { bitmap, meta, cacheEntry = null } = result;
      const previousEntry = __privateGet(this, _bitmapCacheEntry);
      const previousBitmap = __privateGet(this, _bitmap);
      if (cacheEntry && cacheEntry === previousEntry) {
        cacheReleaseEntry(cacheEntry);
      } else {
        __privateSet(this, _bitmapCacheEntry, cacheEntry);
        if (previousEntry) cacheReleaseEntry(previousEntry);
        else if (previousBitmap && previousBitmap !== bitmap) closeBitmapQuietly(previousBitmap);
      }
      __privateSet(this, _bitmap, bitmap);
      __privateSet(this, _meta, meta);
      __privateSet(this, _loadedOnce, true);
      __privateSet(this, _bitmapReleased, false);
      __privateSet(this, _glSource, null);
      __privateSet(this, _glMeta, null);
      __privateSet(this, _decoy, null);
      __privateSet(this, _decoySize, null);
      if (!__privateGet(this, _options).aspectRatio && !__privateGet(this, _options).height) {
        __privateGet(this, _host).style.aspectRatio = meta.origW + " / " + meta.origH;
      }
      if (__privateGet(this, _options).mode !== "vault") {
        __privateSet(this, _taintImage, await ensureTaintImage(__privateGet(this, _options), __privateGet(this, _source)));
        if (__privateGet(this, _destroyed)) return;
        if (!__privateGet(this, _taintImage) && !__privateGet(this, _taintWarned) && __privateGet(this, _options).taintReadback !== "off" && __privateGet(this, _options).taintReadback !== false) {
          __privateSet(this, _taintWarned, true);
          __privateGet(this, _host).dispatchEvent(new CustomEvent("archx-taint-unavailable", {
            detail: { mode: __privateGet(this, _options).mode },
            bubbles: true
          }));
        }
      }
      this._render();
      __privateSet(this, _loaded, true);
      __privateSet(this, _unloaded, false);
      __privateGet(this, _wrap).classList.remove("loading", "error");
      __privateGet(this, _host).dispatchEvent(new CustomEvent("archx-load", { bubbles: true }));
      emitClientEvent("archx.loaded", { outcome: "loaded" }, this);
      try {
        __privateGet(this, _options).onLoad && __privateGet(this, _options).onLoad(this);
      } catch {
      }
    } catch (err) {
      if (__privateGet(this, _destroyed)) return;
      __privateGet(this, _wrap).classList.remove("loading");
      __privateGet(this, _wrap).classList.add("error");
      emitClientEvent("archx.error", { reason: "load-failed", outcome: "error" }, this);
      __privateGet(this, _host).dispatchEvent(new CustomEvent("archx-error", { detail: { error: err }, bubbles: true }));
      try {
        __privateGet(this, _options).onError && __privateGet(this, _options).onError(err, this);
      } catch {
      }
    } finally {
      __privateSet(this, _loading, false);
    }
  }
  _unloadPixels() {
    if (__privateGet(this, _gl)) {
      this._stopGlLoop();
      try {
        const lose = __privateGet(this, _gl).getExtension && glNative(__privateGet(this, _gl), "getExtension", "WEBGL_lose_context");
        if (lose?.loseContext) {
          __privateSet(this, _glReleasing, true);
          lose.loseContext();
        }
      } catch {
      }
    }
    if (__privateGet(this, _canvas)) {
      __privateGet(this, _canvas).width = 0;
      __privateGet(this, _canvas).height = 0;
    }
    if (__privateGet(this, _bitmap) && __privateGet(this, _cachedBytes)) {
      if (__privateGet(this, _bitmapCacheEntry)) cacheReleaseEntry(__privateGet(this, _bitmapCacheEntry));
      else closeBitmapQuietly(__privateGet(this, _bitmap));
      __privateSet(this, _bitmapCacheEntry, null);
      __privateSet(this, _bitmap, null);
      __privateSet(this, _bitmapReleased, true);
    }
    __privateSet(this, _unloaded, true);
  }
  /* ---------------- rendering ---------------- */
  _backingSize() {
    const o = __privateGet(this, _options);
    const rect = __privateGet(this, _host).getBoundingClientRect();
    const cssW = Math.max(1, Math.round(rect.width || __privateGet(this, _host).clientWidth || 320));
    const cssH = Math.max(1, Math.round(rect.height || __privateGet(this, _host).clientHeight || Math.round(cssW * (__privateGet(this, _meta).origH / __privateGet(this, _meta).origW)) || 240));
    const deviceW = __privateGet(this, _deviceBox) && __privateGet(this, _deviceBox).w > 0 ? __privateGet(this, _deviceBox).w : 0;
    let scale = Math.min(window.devicePixelRatio || 1, o.dprCap);
    if (deviceW) scale = Math.min(scale, deviceW / cssW);
    if (cssW * scale > o.maxBackingWidth) scale = o.maxBackingWidth / cssW;
    const maxScaleBySource = __privateGet(this, _meta).origW * 1 / cssW;
    const w = Math.max(1, Math.round(cssW * Math.min(scale, Math.max(maxScaleBySource, 0.25))));
    const h = Math.max(1, Math.round(cssH * (w / cssW)));
    return { w, h, cssW, cssH };
  }
  _render() {
    if (!__privateGet(this, _bitmap) || __privateGet(this, _destroyed)) return;
    const mode = __privateGet(this, _options).mode;
    const temporal = __privateMethod(this, _ProtectedImage_instances, temporalConfig_fn).call(this);
    let wantsWebGL = __privateGet(this, _options).renderer === "webgl" || __privateGet(this, _options).renderer !== "canvas" && mode === "vault";
    if (temporal?.engine === "shader") wantsWebGL = true;
    else if (temporal?.engine === "frames") wantsWebGL = false;
    __privateSet(this, _temporalEngineActual, null);
    if (wantsWebGL) {
      if (this._tryRenderWebGL()) {
        if (temporal) __privateSet(this, _temporalEngineActual, "shader");
        return;
      }
    }
    if (temporal) __privateSet(this, _temporalEngineActual, "frames");
    if (__privateGet(this, _options).splitCanvases && !__privateGet(this, _options).lens && !temporal) this._renderSplit();
    else this._render2d();
  }
  /** Private, capped, un-scrambled working canvas (wiped after use). */
  _workingCanvas(w, h) {
    const meta = __privateGet(this, _meta);
    const fit = fitRects(meta.origW, meta.origH, w, h, __privateGet(this, _options).fit);
    const fullW = Math.max(1, Math.round(meta.origW / fit.sw * fit.dw));
    const fullH = Math.max(1, Math.round(meta.origH / fit.sh * fit.dh));
    return { full: unscrambleToCanvas(__privateGet(this, _bitmap), meta, fullW, fullH), fit, fullW, fullH };
  }
  _render2d() {
    if (__privateGet(this, _integrityHardLock)) {
      __privateMethod(this, _ProtectedImage_instances, paintBlackout_fn).call(this);
      return;
    }
    const { w, h } = this._backingSize();
    const canvas = __privateGet(this, _canvas);
    __privateGet(this, _tilesEl).hidden = true;
    canvas.hidden = false;
    canvas.width = w;
    canvas.height = h;
    __privateSet(this, _renderedW, w);
    __privateSet(this, _renderedH, h);
    const ctx = getNativeContext(canvas, "2d", { alpha: false });
    __privateSet(this, _realCtx, ctx);
    __privateMethod(this, _ProtectedImage_instances, taintContext_fn).call(this, ctx);
    const { full, fit } = this._workingCanvas(w, h);
    const temporalCfg = __privateMethod(this, _ProtectedImage_instances, temporalConfig_fn).call(this);
    __privateSet(this, _temporalEngineActual, temporalCfg ? "frames" : null);
    if (temporalCfg) {
      const frame = makeCanvas(__privateGet(this, _host).ownerDocument);
      frame.width = w;
      frame.height = h;
      const fctx = getNativeContext(frame, "2d");
      fctx.fillStyle = "#000";
      fctx.fillRect(0, 0, w, h);
      setSmoothing(fctx, true);
      nativeDrawImage(
        fctx,
        full,
        fit.sx * (full.width / __privateGet(this, _meta).origW),
        fit.sy * (full.height / __privateGet(this, _meta).origH),
        fit.sw * (full.width / __privateGet(this, _meta).origW),
        fit.sh * (full.height / __privateGet(this, _meta).origH),
        fit.dx,
        fit.dy,
        fit.dw,
        fit.dh
      );
      this._bakeOverlays(fctx, w, h);
      __privateMethod(this, _ProtectedImage_instances, prepareDecoy_fn).call(this, full, w, h);
      full.width = 0;
      full.height = 0;
      if (__privateGet(this, _options).lens) {
        if (__privateGet(this, _frameCanvas)) {
          __privateGet(this, _frameCanvas).width = 0;
          __privateGet(this, _frameCanvas).height = 0;
        }
        __privateSet(this, _frameCanvas, frame);
        const cfg = typeof __privateGet(this, _options).lens === "object" ? __privateGet(this, _options).lens : {};
        const factor = cfg.idlePixelate ?? 18;
        const base = makeCanvas(__privateGet(this, _host).ownerDocument);
        base.width = Math.max(8, Math.round(w / factor));
        base.height = Math.max(8, Math.round(h / factor));
        nativeDrawImage(getNativeContext(base, "2d"), frame, 0, 0, base.width, base.height);
        __privateSet(this, _lensBase, base);
        __privateMethod(this, _ProtectedImage_instances, setupTemporalFrames_fn).call(this, frame, temporalCfg);
      } else {
        __privateMethod(this, _ProtectedImage_instances, setupTemporalFrames_fn).call(this, frame, temporalCfg);
        frame.width = 0;
        frame.height = 0;
      }
      this._poison(canvas, ctx);
      __privateMethod(this, _ProtectedImage_instances, releaseSourceBitmap_fn).call(this);
      return;
    }
    if (__privateGet(this, _options).lens) {
      const frame = makeCanvas(__privateGet(this, _host).ownerDocument);
      frame.width = w;
      frame.height = h;
      const fctx = getNativeContext(frame, "2d");
      fctx.fillStyle = "#000";
      fctx.fillRect(0, 0, w, h);
      setSmoothing(fctx, true);
      nativeDrawImage(
        fctx,
        full,
        fit.sx * (full.width / __privateGet(this, _meta).origW),
        fit.sy * (full.height / __privateGet(this, _meta).origH),
        fit.sw * (full.width / __privateGet(this, _meta).origW),
        fit.sh * (full.height / __privateGet(this, _meta).origH),
        fit.dx,
        fit.dy,
        fit.dw,
        fit.dh
      );
      this._bakeOverlays(fctx, w, h);
      __privateMethod(this, _ProtectedImage_instances, prepareDecoy_fn).call(this, full, w, h);
      full.width = 0;
      full.height = 0;
      if (__privateGet(this, _frameCanvas)) {
        __privateGet(this, _frameCanvas).width = 0;
        __privateGet(this, _frameCanvas).height = 0;
      }
      __privateSet(this, _frameCanvas, frame);
      const cfg = typeof __privateGet(this, _options).lens === "object" ? __privateGet(this, _options).lens : {};
      const factor = cfg.idlePixelate ?? 18;
      const base = makeCanvas(__privateGet(this, _host).ownerDocument);
      base.width = Math.max(8, Math.round(w / factor));
      base.height = Math.max(8, Math.round(h / factor));
      nativeDrawImage(getNativeContext(base, "2d"), frame, 0, 0, base.width, base.height);
      __privateSet(this, _lensBase, base);
      __privateMethod(this, _ProtectedImage_instances, paintLens2d_fn).call(this);
      this._poison(canvas, ctx);
      __privateMethod(this, _ProtectedImage_instances, releaseSourceBitmap_fn).call(this);
      return;
    }
    ctx.fillStyle = "#000";
    ctx.fillRect(0, 0, w, h);
    setSmoothing(ctx, true);
    nativeDrawImage(
      ctx,
      full,
      fit.sx * (full.width / __privateGet(this, _meta).origW),
      fit.sy * (full.height / __privateGet(this, _meta).origH),
      fit.sw * (full.width / __privateGet(this, _meta).origW),
      fit.sh * (full.height / __privateGet(this, _meta).origH),
      fit.dx,
      fit.dy,
      fit.dw,
      fit.dh
    );
    this._bakeOverlays(ctx, w, h);
    __privateMethod(this, _ProtectedImage_instances, prepareDecoy_fn).call(this, full, w, h);
    full.width = 0;
    full.height = 0;
    this._poison(canvas, ctx);
    __privateMethod(this, _ProtectedImage_instances, releaseSourceBitmap_fn).call(this);
  }
  _renderSplit() {
    if (__privateGet(this, _integrityHardLock)) {
      __privateMethod(this, _ProtectedImage_instances, paintBlackout_fn).call(this);
      return;
    }
    const { w, h } = this._backingSize();
    __privateSet(this, _renderedW, w);
    __privateSet(this, _renderedH, h);
    const g = Math.max(2, Math.min(6, __privateGet(this, _options).splitGrid | 0));
    const { full, fit } = this._workingCanvas(w, h);
    const composed = makeCanvas();
    composed.width = w;
    composed.height = h;
    const cctx = getNativeContext(composed, "2d");
    cctx.fillStyle = "#000";
    cctx.fillRect(0, 0, w, h);
    setSmoothing(cctx, true);
    nativeDrawImage(
      cctx,
      full,
      fit.sx * (full.width / __privateGet(this, _meta).origW),
      fit.sy * (full.height / __privateGet(this, _meta).origH),
      fit.sw * (full.width / __privateGet(this, _meta).origW),
      fit.sh * (full.height / __privateGet(this, _meta).origH),
      fit.dx,
      fit.dy,
      fit.dw,
      fit.dh
    );
    this._bakeOverlays(cctx, w, h);
    __privateGet(this, _canvas).hidden = true;
    __privateGet(this, _tilesEl).hidden = false;
    __privateGet(this, _tilesEl).style.gridTemplateColumns = `repeat(${g},1fr)`;
    __privateGet(this, _tilesEl).style.gridTemplateRows = `repeat(${g},1fr)`;
    __privateGet(this, _tilesEl).replaceChildren();
    const tw = Math.ceil(w / g), th = Math.ceil(h / g);
    for (let i = 0; i < g * g; i++) {
      const c = makeCanvas();
      c.width = tw;
      c.height = th;
      const tctx = getNativeContext(c, "2d", { alpha: false });
      __privateMethod(this, _ProtectedImage_instances, taintContext_fn).call(this, tctx);
      nativeDrawImage(tctx, composed, i % g * tw, Math.floor(i / g) * th, tw, th, 0, 0, tw, th);
      __privateGet(this, _tilesEl).appendChild(c);
      __privateMethod(this, _ProtectedImage_instances, prepareDecoy_fn).call(this, full, w, h);
      this._poison(c, tctx);
    }
    composed.width = 0;
    full.width = 0;
    full.height = 0;
    __privateMethod(this, _ProtectedImage_instances, releaseSourceBitmap_fn).call(this);
  }
  _bakeOverlays(ctx, w, h) {
    const o = __privateGet(this, _options);
    const wm = o.watermark;
    if (wm) {
      const cfg = typeof wm === "string" ? { text: wm } : wm;
      const text = String(cfg.text || "").replace("{session}", sessionId().slice(0, 6));
      if (text) {
        ctx.save();
        ctx.fillStyle = cfg.color || "#ffffff";
        if (cfg.tile !== false) {
          ctx.globalAlpha = cfg.opacity ?? 0.16;
          const fs = Math.max(12, Math.round(Math.min(w, h) / 14));
          ctx.font = `700 ${fs}px system-ui, sans-serif`;
          ctx.translate(w / 2, h / 2);
          ctx.rotate(-Math.PI / 7);
          ctx.textAlign = "center";
          const stepY = fs * 4.2;
          const stepX = Math.max(fs * 3, ctx.measureText(text).width + fs * 2.2);
          const diag = Math.hypot(w, h);
          let row = 0;
          for (let y = -diag / 2; y < diag / 2; y += stepY, row++) {
            const x0 = row % 2 * (stepX / 2) - diag / 2;
            for (let x = x0; x < diag / 2 + stepX; x += stepX) ctx.fillText(text, x, y);
          }
          ctx.restore();
          ctx.save();
        }
        if (cfg.corner !== false) {
          ctx.globalAlpha = cfg.cornerOpacity ?? 0.85;
          const fs = Math.max(10, Math.round(Math.min(w, h) / 34));
          ctx.font = `600 ${fs}px system-ui, sans-serif`;
          ctx.textAlign = "right";
          ctx.shadowColor = "rgba(0,0,0,.8)";
          ctx.shadowBlur = 4;
          ctx.fillText(text, w - 10, h - 10);
        }
        ctx.restore();
      }
    }
    if (o.forensic) {
      const rand = mulberry32(hashSeed(sessionId() + "|" + (typeof __privateGet(this, _source) === "string" ? __privateGet(this, _source) : "blob") + "|fx"));
      ctx.save();
      const bs = Math.max(16, Math.round(Math.min(w, h) / 18));
      for (let y = 0; y < h; y += bs) {
        for (let x = 0; x < w; x += bs) {
          ctx.fillStyle = rand() < 0.5 ? "rgba(0,0,0,0.016)" : "rgba(255,255,255,0.016)";
          ctx.fillRect(x, y, bs, bs);
        }
      }
      for (let i = 0; i < 160; i++) {
        const v = Math.floor(rand() * 255);
        ctx.fillStyle = `rgba(${v},${v},${v},0.035)`;
        ctx.fillRect(Math.floor(rand() * w), Math.floor(rand() * h), 1, 1);
      }
      ctx.restore();
    }
  }
  _makeDecoy(cleanCanvas, w, h) {
    const o = __privateGet(this, _options);
    const kind = o.onExtract;
    const decoy = makeCanvas();
    const ctx = getNativeContext(decoy, "2d");
    if (kind === "lowres") {
      const tinyW = 72;
      const tinyH = Math.max(1, Math.round(h / w * tinyW));
      const tiny = makeCanvas();
      tiny.width = tinyW;
      tiny.height = tinyH;
      nativeDrawImage(getNativeContext(tiny, "2d"), cleanCanvas, 0, 0, tinyW, tinyH);
      decoy.width = w;
      decoy.height = h;
      ctx.imageSmoothingEnabled = false;
      nativeDrawImage(ctx, tiny, 0, 0, w, h);
      tiny.width = 0;
      ctx.save();
      const markSize = Math.max(14, w / 18);
      ctx.font = `700 ${markSize}px system-ui,sans-serif`;
      ctx.textAlign = "center";
      ctx.translate(w / 2, h / 2);
      ctx.rotate(-Math.PI / 8);
      ctx.fillStyle = "rgba(0,0,0,0.58)";
      ctx.fillRect(-w * 0.75, -markSize * 0.92, w * 1.5, markSize * 1.45);
      ctx.globalAlpha = 0.96;
      ctx.fillStyle = "#fff";
      ctx.fillText(String((typeof o.watermark === "string" ? o.watermark : o.watermark?.text) || o.brand), 0, 0);
      ctx.restore();
      return decoy;
    }
    if (kind === "scrambled") {
      decoy.width = w;
      decoy.height = h;
      const tinyW = 144;
      const tinyH = Math.max(1, Math.round(h / Math.max(1, w) * tinyW));
      const tiny = makeCanvas();
      tiny.width = tinyW;
      tiny.height = tinyH;
      nativeDrawImage(getNativeContext(tiny, "2d"), cleanCanvas, 0, 0, tinyW, tinyH);
      const staging = makeCanvas();
      staging.width = w;
      staging.height = h;
      const stagingCtx = getNativeContext(staging, "2d");
      stagingCtx.imageSmoothingEnabled = false;
      nativeDrawImage(stagingCtx, tiny, 0, 0, w, h);
      tiny.width = 0;
      tiny.height = 0;
      const g = 8;
      const plan = buildScramblePlan(g, "decoy-" + sessionId(), 2);
      const tw = staging.width / g, th = staging.height / g;
      const dw = w / g, dh = h / g;
      for (let dest = 0; dest < plan.count; dest++) {
        const source = plan.order[dest];
        nativeDrawImage(
          ctx,
          staging,
          source % g * tw,
          Math.floor(source / g) * th,
          tw,
          th,
          dest % g * dw,
          Math.floor(dest / g) * dh,
          dw + 1,
          dh + 1
        );
      }
      staging.width = 0;
      staging.height = 0;
      ctx.save();
      const markSize = Math.max(14, w / 18);
      ctx.font = `700 ${markSize}px system-ui,sans-serif`;
      ctx.textAlign = "center";
      ctx.translate(w / 2, h / 2);
      ctx.rotate(-Math.PI / 8);
      ctx.fillStyle = "rgba(0,0,0,0.58)";
      ctx.fillRect(-w * 0.75, -markSize * 0.92, w * 1.5, markSize * 1.45);
      ctx.globalAlpha = 0.96;
      ctx.fillStyle = "#fff";
      ctx.fillText(String((typeof o.watermark === "string" ? o.watermark : o.watermark?.text) || o.brand), 0, 0);
      ctx.restore();
      return decoy;
    }
    decoy.width = Math.max(320, Math.min(w, 800));
    decoy.height = Math.max(200, Math.round(decoy.width * (h / Math.max(w, 1))));
    ctx.fillStyle = "#05070c";
    ctx.fillRect(0, 0, decoy.width, decoy.height);
    ctx.fillStyle = "#e8ecf4";
    ctx.textAlign = "center";
    ctx.font = `700 ${Math.max(16, decoy.width / 16)}px system-ui,sans-serif`;
    ctx.fillText("PROTECTED IMAGE", decoy.width / 2, decoy.height / 2 - 8);
    ctx.font = `500 ${Math.max(11, decoy.width / 34)}px system-ui,sans-serif`;
    ctx.fillStyle = "#8b94a7";
    ctx.fillText(
      String((typeof o.watermark === "string" ? o.watermark : o.watermark?.text) || o.brand),
      decoy.width / 2,
      decoy.height / 2 + Math.max(20, decoy.width / 22)
    );
    ctx.fillText("This image is displayed with Archnemix Image Protection.", decoy.width / 2, decoy.height / 2 + Math.max(42, decoy.width / 13));
    return decoy;
  }
  _poison(canvas, ctx) {
    const decoy = () => __privateMethod(this, _ProtectedImage_instances, getDecoy_fn).call(this);
    const realToDataURL = NATIVES.canvasToDataURL || HTMLCanvasElement.prototype.toDataURL;
    const realToBlob = NATIVES.canvasToBlob || HTMLCanvasElement.prototype.toBlob;
    const self = this;
    const define = (name, fn) => {
      try {
        Object.defineProperty(canvas, name, { value: fn, writable: false, configurable: false });
      } catch {
        try {
          canvas[name] = fn;
        } catch {
        }
      }
    };
    define("toDataURL", function(type, quality) {
      var _a;
      __privateGet(_a = self, _attemptHandler).call(_a, "extract-dataurl");
      const d = decoy();
      return d ? nativeCall(realToDataURL, d, [type, quality]) : "data:,";
    });
    define("toBlob", function(cb, type, quality) {
      var _a;
      __privateGet(_a = self, _attemptHandler).call(_a, "extract-blob");
      const d = decoy();
      if (d) nativeCall(realToBlob, d, [cb, type, quality]);
      else if (cb) cb(new Blob([], { type: type || "image/png" }));
    });
    if ("captureStream" in canvas) {
      define("captureStream", function() {
        var _a;
        __privateGet(_a = self, _attemptHandler).call(_a, "extract-stream");
        const d = decoy();
        if (d && d.captureStream) return d.captureStream(1);
        throw new DOMException("Protected canvas", "SecurityError");
      });
    }
    if (ctx && ctx.getImageData) {
      const poisonedGet = function(sx, sy, sw, sh) {
        var _a;
        __privateGet(_a = self, _attemptHandler).call(_a, "extract-pixels");
        const w = Math.max(1, Math.abs(sw | 0)), h = Math.max(1, Math.abs(sh | 0));
        const data = new Uint8ClampedArray(w * h * 4);
        for (let i = 3; i < data.length; i += 4) data[i] = 255;
        return new ImageData(data, w, h);
      };
      try {
        Object.defineProperty(ctx, "getImageData", { value: poisonedGet, writable: false, configurable: false });
      } catch {
        try {
          ctx.getImageData = poisonedGet;
        } catch {
        }
      }
    }
  }
  _tryRenderWebGL() {
    if (__privateGet(this, _integrityHardLock)) return false;
    if (glSlotsInUse() >= GL_CONTEXT_BUDGET && !__privateGet(this, _gl)) {
      if (!__privateGet(this, _glBudgetWarned)) {
        __privateSet(this, _glBudgetWarned, true);
        __privateGet(this, _host).dispatchEvent(new CustomEvent("archx-webgl-budget", {
          detail: { inUse: glSlotsInUse(), budget: GL_CONTEXT_BUDGET },
          bubbles: true
        }));
        emitClientEvent("archx.webgl_budget", { outcome: "canvas2d-fallback" }, this);
      }
      return false;
    }
    const canvas = __privateGet(this, _canvas);
    __privateGet(this, _tilesEl).hidden = true;
    canvas.hidden = false;
    let gl = __privateGet(this, _gl);
    if (!gl) {
      gl = getNativeContext(canvas, "webgl2", {
        preserveDrawingBuffer: false,
        antialias: false,
        alpha: false,
        depth: false,
        stencil: false,
        powerPreference: "low-power"
      });
      if (!gl) return false;
      try {
        const attrs = NATIVES.glGetContextAttributes ? nativeCall(NATIVES.glGetContextAttributes, gl, []) : glNative(gl, "getContextAttributes");
        if (attrs && attrs.preserveDrawingBuffer === true) {
          const lose = gl.getExtension && glNative(gl, "getExtension", "WEBGL_lose_context");
          try {
            lose && lose.loseContext && lose.loseContext();
          } catch {
          }
          __privateMethod(this, _ProtectedImage_instances, flagPreserveRewrite_fn).call(this, "attributes");
          __privateMethod(this, _ProtectedImage_instances, fresh2dCanvas_fn).call(this);
          return false;
        }
      } catch {
      }
      __privateSet(this, _gl, gl);
      acquireGlSlot();
      this._poison(canvas, null);
      canvas.addEventListener("webglcontextlost", (e) => {
        e.preventDefault();
        __privateSet(this, _gl, null);
        releaseGlSlot();
        __privateSet(this, _glSource, null);
        __privateSet(this, _glMeta, null);
        __privateSet(this, _canaryDone, false);
        if (__privateGet(this, _glReleasing)) {
          __privateSet(this, _glReleasing, false);
          __privateMethod(this, _ProtectedImage_instances, fresh2dCanvas_fn).call(this);
          return;
        }
        __privateMethod(this, _ProtectedImage_instances, fresh2dCanvas_fn).call(this);
        if (__privateGet(this, _bitmap)) this._render2d();
        else {
          __privateSet(this, _loaded, false);
          this._load();
        }
      }, { signal: __privateGet(this, _abort).signal });
      if (!this._initGl(gl)) {
        __privateSet(this, _gl, null);
        releaseGlSlot();
        __privateMethod(this, _ProtectedImage_instances, fresh2dCanvas_fn).call(this);
        return false;
      }
    }
    __privateMethod(this, _ProtectedImage_instances, prepareGlSource_fn).call(this);
    this._uploadGlTexture(gl);
    if (__privateGet(this, _glSource) && __privateGet(this, _glSource) !== __privateGet(this, _bitmap)) {
      try {
        __privateGet(this, _glSource).width = 0;
        __privateGet(this, _glSource).height = 0;
      } catch {
      }
    }
    __privateSet(this, _glSource, null);
    const decoyH = Math.max(1, Math.round(320 * __privateGet(this, _meta).origH / __privateGet(this, _meta).origW));
    const wantRealDecoy = __privateGet(this, _options).onExtract === "lowres" || __privateGet(this, _options).onExtract === "scrambled";
    if (!__privateGet(this, _decoy) && __privateGet(this, _bitmap) && wantRealDecoy) {
      const { full } = this._workingCanvas(320, decoyH);
      __privateMethod(this, _ProtectedImage_instances, prepareDecoy_fn).call(this, full, full.width, full.height);
      full.width = 0;
    } else if (!__privateGet(this, _decoySize)) {
      __privateSet(this, _decoySize, { w: 320, h: decoyH });
    }
    this._startGlLoop();
    __privateMethod(this, _ProtectedImage_instances, releaseSourceBitmap_fn).call(this);
    return true;
  }
  _initGl(gl) {
    const vs = `#version 300 es
      layout(location=0) in vec2 p; out vec2 vUv;
      void main(){ vUv = p*0.5+0.5; vUv.y = 1.0-vUv.y; gl_Position = vec4(p,0.,1.); }`;
    const fs = `#version 300 es
      precision highp float;
      uniform sampler2D uTex; uniform sampler2D uMap; uniform sampler2D uWm;
      uniform float uGrid; uniform vec2 uCrop; uniform vec2 uFitScale; uniform vec2 uFitOffset;
      uniform float uScrambled; uniform float uSeed; uniform float uWmOn;
      uniform float uLensOn; uniform float uLensActive; uniform vec2 uLensCenter;
      uniform float uLensRadius; uniform vec2 uResolution; uniform float uLocked;
      uniform float uTemporalOn; uniform float uTemporalSign;
      uniform float uTemporalStrength; uniform float uTemporalBlock;
      uniform float uTemporalPattern; uniform float uTemporalChroma;
      uniform float uTemporalDuty; uniform float uTemporalBias; uniform float uBiasSeed;
      uniform float uInterlaceOn; uniform float uInterlacePhase;
      uniform float uInterlacePhases; uniform float uInterlaceLayout;
      uniform float uInterlaceCell; uniform float uInterlaceAxis;
      uniform float uInterlaceFill; uniform float uInterlaceFillBlock;
      uniform float uInterlaceFillStrength; uniform float uInterlaceHiddenScale;
      uniform float uInterlaceActiveGain; uniform float uInterlaceNoiseStrength;
      uniform float uInterlaceBias;
      in vec2 vUv; out vec4 frag;
      float hash(vec2 q){ return fract(sin(dot(q, vec2(127.1,311.7))+uSeed)*43758.5453); }
      float biasHash(vec2 q){ return fract(sin(dot(q, vec2(269.5,183.3))+uBiasSeed)*43758.5453); }
      vec3 hash3(vec2 q){
        return vec3(hash(q), hash(q+19.19), hash(q+47.47));
      }
      vec2 mapToSource(vec2 imageUv){
        vec2 srcUv = imageUv;
        if(uScrambled>0.5){
          vec2 paddedUv = imageUv * uCrop; // orig->padded space
          vec2 tile = floor(paddedUv*uGrid);
          vec2 local = fract(paddedUv*uGrid);
          vec4 m = texelFetch(uMap, ivec2(tile), 0);
          vec2 srcTile = m.rg*255.0;
          if(m.b>0.5) local.x = 1.0-local.x;
          if(m.a>0.5) local.y = 1.0-local.y;
          srcUv = (srcTile+local)/uGrid;
          // Clamp inside the source tile so filtering never blends across
          // scrambled-tile boundaries -> no seams.
          vec2 texel = 1.0 / vec2(textureSize(uTex, 0));
          srcUv = clamp(srcUv, srcTile/uGrid + texel*0.75, (srcTile+1.0)/uGrid - texel*0.75);
        }
        return srcUv;
      }
      vec4 sampleImage(vec2 imageUv){
        vec2 texSize = vec2(textureSize(uTex, 0));
        vec2 srcUv = mapToSource(imageUv);
        vec2 srcPx = srcUv * texSize;
        float footprint = max(length(dFdx(srcPx)), length(dFdy(srcPx)));
        // At ~1:1, fetch the exact texel instead of bilinear-blending two
        // neighbours; this is the difference between crisp type/edges and mush.
        if(footprint > 0.70 && footprint < 1.45){
          ivec2 p = ivec2(clamp(floor(srcPx), vec2(0.0), texSize - 1.0));
          return texelFetch(uTex, p, 0);
        }
        // When minifying, a small 2x2 supersample around the fragment footprint
        // preserves substantially more detail than one bilinear tap (and, for a
        // scrambled texture, avoids cross-tile mipmap bleeding).
        if(footprint >= 1.45){
          vec2 duvX = dFdx(imageUv);
          vec2 duvY = dFdy(imageUv);
          vec4 sum = vec4(0.0);
          sum += texture(uTex, mapToSource(imageUv - 0.25*duvX - 0.25*duvY));
          sum += texture(uTex, mapToSource(imageUv + 0.25*duvX - 0.25*duvY));
          sum += texture(uTex, mapToSource(imageUv - 0.25*duvX + 0.25*duvY));
          sum += texture(uTex, mapToSource(imageUv + 0.25*duvX + 0.25*duvY));
          return sum * 0.25;
        }
        return texture(uTex, srcUv);
      }
      void main(){
        if(uLocked>0.5){ frag=vec4(0.,0.,0.,1.); return; }
        vec2 uv = vUv*uFitScale + uFitOffset;
        if(uv.x<0.0||uv.x>1.0||uv.y<0.0||uv.y>1.0){ frag=vec4(0.,0.,0.,1.); return; }
        // Pointer lens: outside the trusted-pointer disc we sample a heavily
        // quantised (pixelated) version, so a single screenshot/frame grab
        // only ever contains one small sharp region.
        vec2 effUv = uv;
        float lensOutside = 0.0;
        float lensDistPx = 0.0;
        if(uLensOn>0.5){
          vec2 centerPx = vec2(uLensCenter.x, 1.0-uLensCenter.y) * uResolution;
          lensDistPx = distance(gl_FragCoord.xy, centerPx);
          if(uLensActive<0.5 || lensDistPx > uLensRadius){
            float block = max(uResolution.x, uResolution.y) / 34.0;
            vec2 qxy = (floor(gl_FragCoord.xy / block) + 0.5) * block;
            vec2 qUv = vec2(qxy.x / uResolution.x, 1.0 - qxy.y / uResolution.y);
            effUv = qUv * uFitScale + uFitOffset;
            lensOutside = 1.0;
          }
        }
        vec4 c = sampleImage(effUv);
        c.rgb += (hash(gl_FragCoord.xy)-0.5)*(2.0/255.0); // forensic grain
        if(lensOutside>0.5) c.rgb *= 0.82;
        // Literal temporal interlace: each spatial cell belongs to exactly
        // one phase. Inactive cells retain only the configured fill. This
        // runs before the watermark so attribution is present in every
        // presented phase and in a one-frame capture.
        if(uInterlaceOn>0.5){
          vec2 interlaceCell = floor(gl_FragCoord.xy / max(uInterlaceCell, 1.0));
          float assigned = 0.0;
          if(uInterlaceLayout<0.5){
            assigned = mod(interlaceCell.x + (uInterlacePhases<2.5 ? interlaceCell.y : 2.0*interlaceCell.y), uInterlacePhases);
          } else if(uInterlaceLayout<1.5){
            assigned = mod(uInterlaceAxis>0.5 ? interlaceCell.x : interlaceCell.y, uInterlacePhases);
          } else if(uInterlaceLayout<2.5){
            assigned = min(floor(hash(interlaceCell + 913.7) * uInterlacePhases), uInterlacePhases - 1.0);
          } else {
            assigned = mod(interlaceCell.x + interlaceCell.y, uInterlacePhases);
          }
          // Cycle-zero-mean block bias (noise fill only): without it the
          // per-pixel cycle multiset is {c, c+d1, c+d2} and the temporal
          // median of a short screen recording is exactly c whenever the
          // hidden deltas straddle it (~50% of pixels at 3 phases). A
          // per-24px-block offset b, +b*(P-1)/P on the active phase and
          // -b/P hidden, keeps the cycle mean exact while moving every
          // cycle statistic off c. biasHash re-seeds every 90 frames, so
          // longer recordings face a drifting bias, not a fixed offset.
          float iBias = 0.0;
          if(uInterlaceFill>2.5 && uInterlaceFill<3.5){
            vec2 biasCell = floor(gl_FragCoord.xy / 24.0);
            iBias = (biasHash(biasCell) * 2.0 - 1.0) * uInterlaceBias * uInterlaceFillStrength;
          }
          if(abs(assigned-uInterlacePhase)<0.5){
            c.rgb = c.rgb * uInterlaceActiveGain + vec3(iBias * (uInterlacePhases - 1.0) / max(uInterlacePhases, 1.0));
          } else {
            vec3 fillColor = c.rgb;
            if(uInterlaceFill<0.5){
              vec2 qxy = (floor(gl_FragCoord.xy / max(uInterlaceFillBlock, 1.0)) + 0.5) * uInterlaceFillBlock;
              vec2 qUv = vec2(qxy.x / uResolution.x, 1.0 - qxy.y / uResolution.y);
              vec2 fillUv = qUv * uFitScale + uFitOffset;
              if(fillUv.x>=0.0 && fillUv.x<=1.0 && fillUv.y>=0.0 && fillUv.y<=1.0){
                fillColor = sampleImage(fillUv).rgb;
              }
            } else if(uInterlaceFill<1.5){
              fillColor = c.rgb * uInterlaceHiddenScale;
            } else if(uInterlaceFill<2.5){
              fillColor = vec3(0.0);
            } else {
              vec3 delta;
              if(uTemporalChroma>0.5){
                float v = hash(interlaceCell) - 0.5;
                delta = vec3(v, -0.62*v, 0.78*v);
              } else {
                delta = hash3(interlaceCell) - 0.5;
              }
              fillColor = c.rgb + delta * uInterlaceNoiseStrength * uTemporalSign - vec3(iBias / max(uInterlacePhases, 1.0) / max(uInterlaceFillStrength, 0.02));
            }
            c.rgb = mix(c.rgb, fillColor, uInterlaceFillStrength);
          }
        }
        if(uWmOn>0.5){
          vec4 wm = texture(uWm, vUv);
          c.rgb = mix(c.rgb, wm.rgb, wm.a);
        }
        if(uLensOn>0.5 && uLensActive>0.5 && abs(lensDistPx-uLensRadius)<1.5){
          c.rgb = mix(c.rgb, vec3(1.0), 0.35);
        }
        // Temporal shield: complementary per-block noise flips sign every
        // presented frame. The eye integrates the pair toward the image;
        // one screenshot/extension capture keeps a single noisy frame.
        if(uTemporalOn>0.5){
          vec2 blockCell = floor(gl_FragCoord.xy / max(uTemporalBlock, 1.0));
          vec3 delta;
          if(uTemporalPattern>1.5){
            // Horizontal bands interact strongly with rolling-shutter rows.
            float v = hash(vec2(0.0, blockCell.y)) - 0.5;
            delta = uTemporalChroma>0.5 ? vec3(v, -0.62*v, 0.78*v) : hash3(vec2(0.0, blockCell.y)) - 0.5;
          } else if(uTemporalPattern>0.5){
            float parity = mod(blockCell.x + blockCell.y, 2.0) > 0.5 ? 1.0 : -1.0;
            if(uTemporalChroma>0.5){
              float v = (0.35 + 0.65*hash(blockCell)) * parity;
              delta = vec3(v, -0.62*v, 0.78*v) * 0.5;
            } else {
              delta = (0.35 + 0.65*hash3(blockCell)) * parity * 0.5;
            }
          } else if(uTemporalChroma>0.5){
            float v = hash(blockCell) - 0.5;
            delta = vec3(v, -0.62*v, 0.78*v);
          } else {
            delta = hash3(blockCell) - 0.5;
          }
          c.rgb += delta * uTemporalStrength * uTemporalSign;
          // Asymmetric duty bias: a slowly-drifting per-block offset b is
          // applied +2b/3 on one frame and -b/3 on the next two. The
          // temporal MEAN the eye integrates is exactly c, but the sample
          // MEDIAN of any short capture converges to c - b/3, not c \u2014
          // median-filter recovery of the active/interlace subsets is
          // permanently biased, and b re-rolls every ~90 frames so even
          // long-window medians keep chasing a moving target.
          vec2 biasCell = floor(gl_FragCoord.xy / 24.0);
          float b = biasHash(biasCell) - 0.5;
          c.rgb += vec3(b) * uTemporalBias * uTemporalDuty;
        }
        frag = vec4(c.rgb, 1.0);
      }`;
    const compile = (type, srcText) => {
      const s = glNative(gl, "createShader", type);
      glNative(gl, "shaderSource", s, srcText);
      glNative(gl, "compileShader", s);
      if (!glNative(gl, "getShaderParameter", s, gl.COMPILE_STATUS)) return null;
      return s;
    };
    const v = compile(gl.VERTEX_SHADER, vs);
    const f = compile(gl.FRAGMENT_SHADER, fs);
    if (!v || !f) return false;
    const prog = glNative(gl, "createProgram");
    glNative(gl, "attachShader", prog, v);
    glNative(gl, "attachShader", prog, f);
    glNative(gl, "linkProgram", prog);
    if (!glNative(gl, "getProgramParameter", prog, gl.LINK_STATUS)) return false;
    glNative(gl, "useProgram", prog);
    __privateSet(this, _glProg, prog);
    __privateSet(this, _glLoc, {});
    [
      "uTex",
      "uMap",
      "uWm",
      "uGrid",
      "uCrop",
      "uFitScale",
      "uFitOffset",
      "uScrambled",
      "uSeed",
      "uWmOn",
      "uLensOn",
      "uLensActive",
      "uLensCenter",
      "uLensRadius",
      "uResolution",
      "uLocked",
      "uTemporalOn",
      "uTemporalSign",
      "uTemporalStrength",
      "uTemporalBlock",
      "uTemporalPattern",
      "uTemporalChroma",
      "uTemporalDuty",
      "uTemporalBias",
      "uBiasSeed",
      "uInterlaceOn",
      "uInterlacePhase",
      "uInterlacePhases",
      "uInterlaceLayout",
      "uInterlaceCell",
      "uInterlaceAxis",
      "uInterlaceFill",
      "uInterlaceFillBlock",
      "uInterlaceFillStrength",
      "uInterlaceHiddenScale",
      "uInterlaceActiveGain",
      "uInterlaceNoiseStrength",
      "uInterlaceBias"
    ].forEach((n) => {
      __privateGet(this, _glLoc)[n] = glNative(gl, "getUniformLocation", prog, n);
    });
    const buf = glNative(gl, "createBuffer");
    glNative(gl, "bindBuffer", gl.ARRAY_BUFFER, buf);
    glNative(gl, "bufferData", gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
    glNative(gl, "enableVertexAttribArray", 0);
    glNative(gl, "vertexAttribPointer", 0, 2, gl.FLOAT, false, 0, 0);
    __privateSet(this, _glTex, glNative(gl, "createTexture"));
    __privateSet(this, _glMap, glNative(gl, "createTexture"));
    __privateSet(this, _glWm, glNative(gl, "createTexture"));
    return true;
  }
  _uploadGlTexture(gl) {
    const meta = __privateGet(this, _glMeta) || __privateGet(this, _meta);
    const source = __privateGet(this, _glSource) || __privateGet(this, _bitmap);
    const texImage = (...args) => NATIVES.glTexImage2D ? nativeCall(NATIVES.glTexImage2D, gl, args) : glNative(gl, "texImage2D", ...args);
    glNative(gl, "activeTexture", gl.TEXTURE0);
    glNative(gl, "bindTexture", gl.TEXTURE_2D, __privateGet(this, _glTex));
    glNative(gl, "texParameteri", gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    glNative(gl, "texParameteri", gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    glNative(gl, "texParameteri", gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    glNative(gl, "texParameteri", gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    glNative(gl, "pixelStorei", gl.UNPACK_FLIP_Y_WEBGL, false);
    texImage(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, source);
    if (!meta.plan) {
      try {
        glNative(gl, "generateMipmap", gl.TEXTURE_2D);
        glNative(gl, "texParameteri", gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR_MIPMAP_LINEAR);
      } catch {
      }
    }
    glNative(gl, "activeTexture", gl.TEXTURE1);
    glNative(gl, "bindTexture", gl.TEXTURE_2D, __privateGet(this, _glMap));
    glNative(gl, "texParameteri", gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
    glNative(gl, "texParameteri", gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
    glNative(gl, "texParameteri", gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    glNative(gl, "texParameteri", gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    if (meta.plan) {
      const g = meta.plan.grid;
      const data = new Uint8Array(g * g * 4);
      for (let orig = 0; orig < meta.plan.count; orig++) {
        const scrambledPos = meta.plan.inverse[orig];
        data[orig * 4] = scrambledPos % g;
        data[orig * 4 + 1] = Math.floor(scrambledPos / g);
        data[orig * 4 + 2] = meta.plan.flips[scrambledPos].fx ? 255 : 0;
        data[orig * 4 + 3] = meta.plan.flips[scrambledPos].fy ? 255 : 0;
      }
      texImage(gl.TEXTURE_2D, 0, gl.RGBA, g, g, 0, gl.RGBA, gl.UNSIGNED_BYTE, data);
    }
    glNative(gl, "activeTexture", gl.TEXTURE2);
    glNative(gl, "bindTexture", gl.TEXTURE_2D, __privateGet(this, _glWm));
    glNative(gl, "texParameteri", gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    glNative(gl, "texParameteri", gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    glNative(gl, "texParameteri", gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    glNative(gl, "texParameteri", gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    const wm = __privateGet(this, _options).watermark;
    __privateSet(this, _glWmOn, 0);
    if (wm) {
      const cfg = typeof wm === "string" ? { text: wm } : wm;
      const text = String(cfg.text || "").replace("{session}", sessionId().slice(0, 6));
      if (text) {
        const c = makeCanvas();
        const texW = Math.max(256, Math.min(1024, __privateGet(this, _canvas)?.width || 1024));
        c.width = texW;
        c.height = Math.max(64, Math.round(texW * meta.origH / meta.origW));
        const ctx = getNativeContext(c, "2d");
        ctx.clearRect(0, 0, c.width, c.height);
        ctx.fillStyle = cfg.color || "#ffffff";
        if (cfg.tile !== false) {
          ctx.save();
          ctx.globalAlpha = cfg.opacity ?? 0.16;
          const fs = Math.max(18, Math.round(Math.min(c.width, c.height) / 12));
          ctx.font = `700 ${fs}px system-ui,sans-serif`;
          ctx.textAlign = "center";
          ctx.translate(c.width / 2, c.height / 2);
          ctx.rotate(-Math.PI / 7);
          const diag = Math.hypot(c.width, c.height);
          const stepX = Math.max(fs * 3, ctx.measureText(text).width + fs * 2.2);
          let row = 0;
          for (let y = -diag / 2; y < diag / 2; y += fs * 4.2, row++) {
            const x0 = row % 2 * (stepX / 2) - diag / 2;
            for (let x = x0; x < diag / 2 + stepX; x += stepX) ctx.fillText(text, x, y);
          }
          ctx.restore();
        }
        if (cfg.corner !== false) {
          ctx.save();
          ctx.globalAlpha = cfg.cornerOpacity ?? 0.9;
          const fs = Math.max(14, Math.round(Math.min(c.width, c.height) / 30));
          ctx.font = `600 ${fs}px system-ui,sans-serif`;
          ctx.textAlign = "right";
          ctx.shadowColor = "rgba(0,0,0,.85)";
          ctx.shadowBlur = 5;
          ctx.fillText(text, c.width - 14, c.height - 14);
          ctx.restore();
        }
        texImage(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, c);
        c.width = 0;
        c.height = 0;
        __privateSet(this, _glWmOn, 1);
      }
    }
  }
  /**
   * Draw-on-demand WebGL. A static protected photograph does not need a
   * 60fps GPU loop: we present a couple of frames (so the first composite is
   * never blank) and then stop. Continuous presentation is reserved for the
   * temporal shield (or explicit renderLoop:'continuous').
   */
  _startGlLoop(frames = 2) {
    if (!__privateGet(this, _gl)) return;
    if (!__privateGet(this, _lastInteractAt)) __privateSet(this, _lastInteractAt, performance.now());
    if (__privateMethod(this, _ProtectedImage_instances, glContinuous_fn).call(this)) __privateSet(this, _glFrameBudget, Infinity);
    else __privateSet(this, _glFrameBudget, Math.max(__privateGet(this, _glFrameBudget), Math.max(1, frames | 0)));
    if (__privateGet(this, _raf)) return;
    const gl = __privateGet(this, _gl);
    const draw = () => {
      __privateSet(this, _raf, 0);
      if (__privateGet(this, _destroyed) || !__privateGet(this, _gl)) return;
      if (__privateGet(this, _canaryPause) && __privateGet(this, _canaryProbe)) {
        if (__privateGet(this, _canaryWait) > 0) {
          __privateWrapper(this, _canaryWait)._--;
          __privateSet(this, _raf, requestAnimationFrame(draw));
          return;
        }
        __privateMethod(this, _ProtectedImage_instances, checkCanaryProbe_fn).call(this, gl);
      }
      if (__privateGet(this, _integrityHardLock)) return;
      const { w, h } = this._backingSize();
      if (__privateGet(this, _canvas).width !== w || __privateGet(this, _canvas).height !== h) {
        __privateGet(this, _canvas).width = w;
        __privateGet(this, _canvas).height = h;
      }
      __privateSet(this, _renderedW, w);
      __privateSet(this, _renderedH, h);
      glNative(gl, "viewport", 0, 0, w, h);
      glNative(gl, "useProgram", __privateGet(this, _glProg));
      const L = __privateGet(this, _glLoc);
      const meta = __privateGet(this, _glMeta) || __privateGet(this, _meta);
      glNative(gl, "uniform1i", L.uTex, 0);
      glNative(gl, "uniform1i", L.uMap, 1);
      glNative(gl, "uniform1i", L.uWm, 2);
      glNative(gl, "uniform1f", L.uGrid, meta.plan ? meta.plan.grid : 1);
      glNative(gl, "uniform2f", L.uCrop, meta.origW / meta.padW, meta.origH / meta.padH);
      const srcRatio = meta.origW / meta.origH;
      const dstRatio = w / h;
      let sx = 1, sy = 1, ox = 0, oy = 0;
      if (__privateGet(this, _options).fit === "cover") {
        if (srcRatio > dstRatio) {
          sx = dstRatio / srcRatio;
          ox = (1 - sx) / 2;
        } else {
          sy = srcRatio / dstRatio;
          oy = (1 - sy) / 2;
        }
      } else if (__privateGet(this, _options).fit === "contain") {
        if (srcRatio > dstRatio) {
          const s = srcRatio / dstRatio;
          sy = s;
          oy = -(s - 1) / 2;
          sx = 1;
          ox = 0;
        } else {
          const s = dstRatio / srcRatio;
          sx = s;
          ox = -(s - 1) / 2;
        }
      }
      glNative(gl, "uniform2f", L.uFitScale, sx, sy);
      glNative(gl, "uniform2f", L.uFitOffset, ox, oy);
      glNative(gl, "uniform1f", L.uScrambled, meta.plan ? 1 : 0);
      glNative(gl, "uniform1f", L.uSeed, hashSeed(sessionId()) % 1e3 / 37 + Math.random() * 997);
      glNative(gl, "uniform1f", L.uWmOn, __privateGet(this, _glWmOn) || 0);
      const lensCfg = typeof __privateGet(this, _options).lens === "object" && __privateGet(this, _options).lens ? __privateGet(this, _options).lens : {};
      glNative(gl, "uniform1f", L.uLensOn, __privateGet(this, _options).lens ? 1 : 0);
      glNative(gl, "uniform1f", L.uLensActive, __privateGet(this, _lensPoint) ? 1 : 0);
      glNative(gl, "uniform2f", L.uLensCenter, __privateGet(this, _lensPoint)?.x ?? -10, __privateGet(this, _lensPoint)?.y ?? -10);
      glNative(gl, "uniform1f", L.uLensRadius, __privateMethod(this, _ProtectedImage_instances, lensRadiusPx_fn).call(this, w, h, lensCfg.radius ?? 0.3));
      glNative(gl, "uniform2f", L.uResolution, w, h);
      glNative(gl, "uniform1f", L.uLocked, Date.now() < __privateGet(this, _lockedUntil) ? 1 : 0);
      const temporal = __privateMethod(this, _ProtectedImage_instances, temporalConfig_fn).call(this);
      if (temporal && performance.now() - __privateGet(this, _lastInteractAt) > 5e3) {
        if (__privateWrapper(this, _idleSkip)._++ % 3 !== 0) {
          __privateSet(this, _raf, requestAnimationFrame(draw));
          return;
        }
      } else {
        __privateSet(this, _idleSkip, 0);
      }
      const interlace = temporal?.interlace || null;
      const interlacePhases = interlace?.phases || 2;
      const interlacePhase = (__privateGet(this, _temporalPhase) % interlacePhases + interlacePhases) % interlacePhases;
      glNative(gl, "uniform1f", L.uTemporalOn, temporal?.noise ? 1 : 0);
      glNative(gl, "uniform1f", L.uTemporalSign, __privateGet(this, _temporalSign));
      glNative(gl, "uniform1f", L.uTemporalStrength, temporal ? temporal.strength * (0.75 + Math.random() * 0.5) : 0);
      glNative(gl, "uniform1f", L.uTemporalDuty, [2 / 3, -1 / 3, -1 / 3][__privateGet(this, _dutyIndex) % 3]);
      glNative(gl, "uniform1f", L.uTemporalBias, temporal ? temporal.strength * 0.55 : 0);
      glNative(gl, "uniform1f", L.uBiasSeed, __privateGet(this, _biasSeed));
      glNative(gl, "uniform1f", L.uTemporalBlock, temporal ? temporal.block : 1);
      glNative(gl, "uniform1f", L.uTemporalPattern, temporal ? temporal.patternCode : 0);
      glNative(gl, "uniform1f", L.uTemporalChroma, temporal?.chroma ? 1 : 0);
      glNative(gl, "uniform1f", L.uInterlaceOn, interlace ? 1 : 0);
      glNative(gl, "uniform1f", L.uInterlacePhase, interlacePhase);
      glNative(gl, "uniform1f", L.uInterlacePhases, interlacePhases);
      glNative(
        gl,
        "uniform1f",
        L.uInterlaceLayout,
        interlace?.layout === "pixels" ? 0 : interlace?.layout === "strips" ? 1 : interlace?.layout === "blocks" ? 2 : 3
      );
      glNative(gl, "uniform1f", L.uInterlaceCell, interlace?.cellSize || 1);
      glNative(gl, "uniform1f", L.uInterlaceAxis, interlace?.axis === "columns" ? 1 : 0);
      glNative(
        gl,
        "uniform1f",
        L.uInterlaceFill,
        interlace?.fill === "dim" ? 1 : interlace?.fill === "black" ? 2 : interlace?.fill === "noise" ? 3 : 0
      );
      glNative(gl, "uniform1f", L.uInterlaceFillBlock, interlace?.fillBlock || 12);
      glNative(gl, "uniform1f", L.uInterlaceFillStrength, interlace?.fillStrength ?? 1);
      glNative(gl, "uniform1f", L.uInterlaceHiddenScale, interlace?.hiddenScale ?? 0.3);
      glNative(gl, "uniform1f", L.uInterlaceActiveGain, interlace?.activeGain ?? 1);
      glNative(gl, "uniform1f", L.uInterlaceNoiseStrength, interlace?.noiseStrength ?? 0.16);
      glNative(gl, "uniform1f", L.uInterlaceBias, interlace ? (interlace.noiseStrength ?? 0.16) * 0.55 : 0);
      nativeGlDrawArrays(gl, gl.TRIANGLE_STRIP, 0, 4);
      __privateWrapper(this, _glFrames)._++;
      if (!__privateGet(this, _canaryDone) && !__privateGet(this, _canaryPause) && __privateGet(this, _glFrames) >= __privateGet(this, _canaryNextTry)) {
        __privateSet(this, _canaryNextTry, __privateGet(this, _glFrames) + 30);
        if (__privateMethod(this, _ProtectedImage_instances, canaryPresentable_fn).call(this)) __privateMethod(this, _ProtectedImage_instances, captureCanaryProbe_fn).call(this, gl, w, h);
      }
      if (temporal) {
        let nextSign = Math.random() < 0.5 ? 1 : -1;
        if (Math.abs(__privateGet(this, _signBalance) + nextSign) > 2) nextSign = -nextSign;
        __privateSet(this, _temporalSign, nextSign);
        __privateSet(this, _signBalance, __privateGet(this, _signBalance) + nextSign);
        __privateWrapper(this, _dutyIndex)._++;
        if (++__privateWrapper(this, _biasFrames)._ >= 90) {
          __privateSet(this, _biasFrames, 0);
          __privateSet(this, _biasSeed, Math.random() * 100);
        }
        __privateWrapper(this, _temporalIndex)._++;
        __privateSet(this, _temporalPhase, __privateMethod(this, _ProtectedImage_instances, nextPhase_fn).call(this, interlace ? interlacePhases : 2));
      }
      if (__privateGet(this, _glFrameBudget) !== Infinity && __privateGet(this, _glFrameBudget) > 0) __privateWrapper(this, _glFrameBudget)._--;
      const keepGoing = __privateMethod(this, _ProtectedImage_instances, glContinuous_fn).call(this) || __privateGet(this, _glFrameBudget) > 0 || __privateGet(this, _canaryPause);
      if (keepGoing && __privateGet(this, _visible) && !__privateGet(this, _destroyed) && !__privateGet(this, _unloaded)) {
        __privateSet(this, _raf, requestAnimationFrame(draw));
      }
    };
    __privateSet(this, _raf, requestAnimationFrame(draw));
  }
  _stopGlLoop() {
    if (__privateGet(this, _raf)) cancelAnimationFrame(__privateGet(this, _raf));
    __privateSet(this, _raf, 0);
    __privateSet(this, _glFrameBudget, 0);
  }
  /* ---------------- risk reactions ---------------- */
  _setRisk(kind, on) {
    const g = __privateGet(this, _options).guards;
    const relevant = kind === "blur" && g.blurOnBlur || kind === "hidden" && g.blurOnBlur || kind === "print" && g.print || kind === "devtools" && g.devtools;
    if (!relevant) return;
    if (on) __privateGet(this, _risk).add(kind);
    else __privateGet(this, _risk).delete(kind);
    __privateGet(this, _wrap).classList.toggle("risk-on", __privateGet(this, _risk).size > 0);
  }
  _momentaryBlackout(ms, kind) {
    if (kind === "screenshot-key" && !__privateGet(this, _options).guards.screenshotKeys) return;
    __privateGet(this, _wrap).classList.add("blackout");
    if (__privateGet(this, _attemptHandler)) __privateGet(this, _attemptHandler).call(this, kind);
    clearTimeout(__privateGet(this, _blackoutTimer));
    __privateSet(this, _blackoutTimer, setTimeout(() => __privateGet(this, _wrap).classList.remove("blackout"), ms));
  }
  /* ---------------- public per-instance API ---------------- */
  get loaded() {
    return __privateGet(this, _loaded);
  }
  get element() {
    return __privateGet(this, _host);
  }
  /**
   * Test/debug hook — returns internals ONLY when this instance was created
   * with `debug: true`. There is deliberately no way to switch this on for
   * an existing instance from outside (options are private + sanitised).
   * Never enable in production pages.
   */
  _debug() {
    if (__privateGet(this, _options).debug !== true) return null;
    const temporal = __privateMethod(this, _ProtectedImage_instances, temporalConfig_fn).call(this);
    return {
      canvas: __privateGet(this, _canvas),
      tiles: [...__privateGet(this, _tilesEl).querySelectorAll("canvas")],
      wrap: __privateGet(this, _wrap),
      meta: __privateGet(this, _meta),
      integrityIssues: [...__privateGet(this, _integrityIssues)],
      strikes: __privateGet(this, _strikes),
      locked: Date.now() < __privateGet(this, _lockedUntil),
      lens: __privateGet(this, _lensPoint) ? { ...__privateGet(this, _lensPoint) } : null,
      bitmapReleased: __privateGet(this, _bitmapReleased),
      glScrambledTexture: !!(__privateGet(this, _glMeta) && __privateGet(this, _glMeta).plan),
      captureTraceOn: __privateGet(this, _wrap).classList.contains("trace-on"),
      traceText: __privateGet(this, _traceEl)?.textContent?.trim() || "",
      loadedOnce: __privateGet(this, _loadedOnce),
      cachedPayload: !!__privateGet(this, _cachedBytes),
      renderedSize: { w: __privateGet(this, _renderedW), h: __privateGet(this, _renderedH) },
      glFrames: __privateGet(this, _glFrames),
      glContinuous: __privateGet(this, _gl) ? __privateMethod(this, _ProtectedImage_instances, glContinuous_fn).call(this) : false,
      canary: {
        done: __privateGet(this, _canaryDone),
        pause: __privateGet(this, _canaryPause),
        wait: __privateGet(this, _canaryWait),
        presentable: __privateGet(this, _gl) ? __privateMethod(this, _ProtectedImage_instances, canaryPresentable_fn).call(this) : false,
        preserveFlagged: __privateGet(this, _preserveFlagged),
        hardLock: __privateGet(this, _integrityHardLock)
      },
      idleMs: __privateGet(this, _lastInteractAt) ? Math.round(performance.now() - __privateGet(this, _lastInteractAt)) : -1,
      glBudget: __privateGet(this, _glFrameBudget) === Infinity ? "inf" : __privateGet(this, _glFrameBudget),
      rafPending: !!__privateGet(this, _raf),
      visible: __privateGet(this, _visible),
      unloaded: __privateGet(this, _unloaded),
      temporalOn: !!temporal,
      temporalPattern: temporal?.pattern || null,
      temporalChroma: !!temporal?.chroma,
      temporalFrames2d: !!__privateGet(this, _temporalFrames),
      temporalNoise: !!temporal?.noise,
      temporalEngineRequested: temporal?.engine || null,
      temporalEngineActual: __privateGet(this, _temporalEngineActual),
      temporalPhase: __privateGet(this, _temporalPhase),
      temporalIndex: __privateGet(this, _temporalIndex),
      temporalFrameCount: __privateGet(this, _temporalFrames)?.length || 0,
      temporalInterlace: temporal?.interlace ? { ...temporal.interlace } : null,
      tokenMethod: __privateGet(this, _options).tokenMethod,
      tokenTransport: __privateGet(this, _options).tokenTransport,
      proofOfPossession: __privateGet(this, _options).proofOfPossession,
      cacheScopeSet: !!__privateGet(this, _options).cacheScope
    };
  }
  async reload(newSource) {
    if (newSource !== void 0) {
      __privateSet(this, _source, newSource);
      __privateSet(this, _cachedBytes, null);
      __privateSet(this, _cachedExtra, null);
      __privateSet(this, _loadedOnce, false);
    }
    __privateSet(this, _loaded, false);
    __privateGet(this, _wrap).classList.add("loading");
    await this._load({ force: true });
    return this;
  }
  destroy() {
    __privateSet(this, _destroyed, true);
    instances.delete(this);
    __privateGet(this, _abort).abort();
    __privateMethod(this, _ProtectedImage_instances, stopTemporal2d_fn).call(this, true);
    __privateSet(this, _cachedBytes, null);
    __privateSet(this, _cachedExtra, null);
    this._stopGlLoop();
    if (__privateGet(this, _gl)) {
      try {
        glNative(__privateGet(this, _gl), "getExtension", "WEBGL_lose_context")?.loseContext();
      } catch {
      }
      releaseGlSlot();
      __privateSet(this, _gl, null);
    }
    clearTimeout(__privateGet(this, _resizeTimer));
    __privateSet(this, _resizeTimer, 0);
    try {
      sharedResizeObserver?.unobserve(__privateGet(this, _host));
    } catch {
    }
    try {
      __privateGet(this, _visibilityObs)?.unobserve(__privateGet(this, _host));
    } catch {
    }
    __privateSet(this, _visibilityObs, null);
    if (__privateGet(this, _canvas)) {
      __privateGet(this, _canvas).width = 0;
      __privateGet(this, _canvas).height = 0;
    }
    if (__privateGet(this, _decoy)) {
      __privateGet(this, _decoy).width = 0;
      __privateSet(this, _decoy, null);
    }
    if (__privateGet(this, _frameCanvas)) {
      __privateGet(this, _frameCanvas).width = 0;
      __privateGet(this, _frameCanvas).height = 0;
      __privateSet(this, _frameCanvas, null);
    }
    if (__privateGet(this, _lensBase)) {
      __privateGet(this, _lensBase).width = 0;
      __privateGet(this, _lensBase).height = 0;
      __privateSet(this, _lensBase, null);
    }
    if (__privateGet(this, _lensRaf)) cancelAnimationFrame(__privateGet(this, _lensRaf));
    if (__privateGet(this, _traceTimer)) clearInterval(__privateGet(this, _traceTimer));
    __privateSet(this, _traceTimer, 0);
    clearTimeout(__privateGet(this, _lockTimer));
    if (__privateGet(this, _bitmapCacheEntry)) cacheReleaseEntry(__privateGet(this, _bitmapCacheEntry));
    else closeBitmapQuietly(__privateGet(this, _bitmap));
    __privateSet(this, _bitmapCacheEntry, null);
    __privateSet(this, _bitmap, null);
    __privateGet(this, _root).replaceChildren?.();
    if (hostToInstance.get(__privateGet(this, _host)) === this) hostToInstance.delete(__privateGet(this, _host));
  }
};
_options = new WeakMap();
_host = new WeakMap();
_root = new WeakMap();
_wrap = new WeakMap();
_canvas = new WeakMap();
_tilesEl = new WeakMap();
_shieldEl = new WeakMap();
_source = new WeakMap();
_bitmap = new WeakMap();
_meta = new WeakMap();
_abort = new WeakMap();
_decoy = new WeakMap();
_decoySize = new WeakMap();
_gl = new WeakMap();
_raf = new WeakMap();
_loaded = new WeakMap();
_destroyed = new WeakMap();
_glBudgetWarned = new WeakMap();
_taintWarned = new WeakMap();
_canaryDone = new WeakMap();
_canaryPause = new WeakMap();
_canaryProbe = new WeakMap();
_canaryWait = new WeakMap();
_canaryNextTry = new WeakMap();
_preserveFlagged = new WeakMap();
_integrityHardLock = new WeakMap();
_glReleasing = new WeakMap();
_taintImage = new WeakMap();
_risk = new WeakMap();
_blackoutTimer = new WeakMap();
_resizeTimer = new WeakMap();
_visibilityObs = new WeakMap();
_realCtx = new WeakMap();
_attemptHandler = new WeakMap();
_loading = new WeakMap();
_visible = new WeakMap();
_unloaded = new WeakMap();
_glProg = new WeakMap();
_glLoc = new WeakMap();
_glTex = new WeakMap();
_glMap = new WeakMap();
_glWm = new WeakMap();
_glWmOn = new WeakMap();
_glSource = new WeakMap();
_glMeta = new WeakMap();
_frameCanvas = new WeakMap();
_lensBase = new WeakMap();
_lensPoint = new WeakMap();
_lensRaf = new WeakMap();
_lensCells = new WeakMap();
_lensCoverage = new WeakMap();
_lensRadiusScale = new WeakMap();
_lensRadiusAt = new WeakMap();
_traceEl = new WeakMap();
_traceTimer = new WeakMap();
_strikes = new WeakMap();
_lockedUntil = new WeakMap();
_lockTimer = new WeakMap();
_integrityIssues = new WeakMap();
_bitmapReleased = new WeakMap();
_loadedOnce = new WeakMap();
_cachedBytes = new WeakMap();
_cachedExtra = new WeakMap();
_bitmapCacheEntry = new WeakMap();
_prefetchedTokenMint = new WeakMap();
_renderedW = new WeakMap();
_renderedH = new WeakMap();
_deviceBox = new WeakMap();
_glFrameBudget = new WeakMap();
_glFrames = new WeakMap();
_temporalSign = new WeakMap();
_temporalPhase = new WeakMap();
_temporalRaf = new WeakMap();
_temporalFrames = new WeakMap();
_temporalIndex = new WeakMap();
_temporalEngineActual = new WeakMap();
_phaseBag = new WeakMap();
_signBalance = new WeakMap();
_dutyIndex = new WeakMap();
_biasSeed = new WeakMap();
_biasFrames = new WeakMap();
_lastInteractAt = new WeakMap();
_idleSkip = new WeakMap();
_temporalInterlaceCache = new WeakMap();
_ProtectedImage_instances = new WeakSet();
/** Strike accounting: repeated extraction attempts escalate to lockout. */
registerStrike_fn = function(kind) {
  const serious = /^(extract-|contextmenu|drag|copy|longpress|integrity|automation|lens-scan)/.test(kind);
  if (!serious) return;
  __privateWrapper(this, _strikes)._++;
  const policy = __privateGet(this, _options).strikes;
  if (!policy) return;
  const blurAt = policy.blurAt ?? 3;
  const lockAt = policy.lockAt ?? 6;
  const lockMs = policy.lockMs ?? 3e4;
  if (__privateGet(this, _strikes) >= lockAt) {
    __privateSet(this, _lockedUntil, Date.now() + lockMs);
    __privateGet(this, _wrap).classList.add("blackout");
    this._stopGlLoop();
    clearTimeout(__privateGet(this, _lockTimer));
    __privateSet(this, _lockTimer, setTimeout(() => {
      __privateSet(this, _lockedUntil, 0);
      __privateSet(this, _strikes, 0);
      __privateGet(this, _wrap).classList.remove("blackout");
      if (__privateGet(this, _gl) && __privateGet(this, _visible)) this._startGlLoop();
      else if (__privateGet(this, _frameCanvas)) __privateMethod(this, _ProtectedImage_instances, paintLens2d_fn).call(this);
    }, lockMs));
  } else if (__privateGet(this, _strikes) >= blurAt) {
    __privateGet(this, _wrap).classList.add("risk-on");
    setTimeout(() => {
      if (!__privateGet(this, _risk).size && Date.now() >= __privateGet(this, _lockedUntil)) __privateGet(this, _wrap).classList.remove("risk-on");
    }, 4e3);
  }
};
/** Heuristic: a lens swept rapidly across many cells == stitching attempt.
 * Accounting uses every cell the revealed DISC touches, not just the cell
 * under its center: with a ~30%-radius lens one park position exposes
 * ~28% of the frame, so center-only counting let a stitcher harvest the
 * whole image in 3-4 parks without ever tripping the threshold. */
trackLensTravel_fn = function(point) {
  const now = performance.now();
  const cfg = typeof __privateGet(this, _options).lens === "object" && __privateGet(this, _options).lens ? __privateGet(this, _options).lens : {};
  const cells = 8;
  const bw = __privateGet(this, _canvas)?.width || 1;
  const bh = __privateGet(this, _canvas)?.height || 1;
  const radiusPx = Math.max(24, Math.min(bw, bh) * (cfg.radius ?? 0.3));
  const rx = radiusPx / bw, ry = radiusPx / bh;
  const reachX = rx + 0.75 / cells, reachY = ry + 0.75 / cells;
  for (let cy = 0; cy < cells; cy++) {
    for (let cx = 0; cx < cells; cx++) {
      const ccx = (cx + 0.5) / cells, ccy = (cy + 0.5) / cells;
      const dx = (ccx - point.x) / Math.max(reachX, 1e-6);
      const dy = (ccy - point.y) / Math.max(reachY, 1e-6);
      if (dx * dx + dy * dy <= 1) __privateGet(this, _lensCells).push({ cell: cy * cells + cx, now });
    }
  }
  __privateSet(this, _lensCells, __privateGet(this, _lensCells).filter((c) => now - c.now < 8e3));
  const distinct = new Set(__privateGet(this, _lensCells).map((c) => c.cell)).size;
  const threshold = cfg.scanCells ?? 46;
  if (distinct >= threshold) {
    __privateSet(this, _lensCells, []);
    if (__privateGet(this, _attemptHandler)) __privateGet(this, _attemptHandler).call(this, "lens-scan");
    return;
  }
  const visited = new Set(__privateGet(this, _lensCells).map((c) => c.cell));
  for (const cell of visited) __privateGet(this, _lensCoverage)[cell] = now;
  let covered = 0;
  for (let i = 0; i < 64; i++) if (now - __privateGet(this, _lensCoverage)[i] < 12e4) covered++;
  const cumulativeThreshold = cfg.scanCellsCumulative ?? 56;
  if (covered >= cumulativeThreshold) {
    __privateSet(this, _lensCoverage, new Float64Array(64).fill(-1e15));
    __privateSet(this, _lensCells, []);
    if (__privateGet(this, _attemptHandler)) __privateGet(this, _attemptHandler).call(this, "lens-scan");
  }
};
// Lens radius with a slow +-6% jitter (re-rolled at most 4x/second):
// stitched captures of overlapping parks get inconsistent disc rims,
// so seams ghost instead of aligning pixel-exactly.
lensRadiusPx_fn = function(w, h, frac) {
  const now = performance.now();
  if (now - __privateGet(this, _lensRadiusAt) > 250) {
    __privateSet(this, _lensRadiusAt, now);
    __privateSet(this, _lensRadiusScale, 0.94 + Math.random() * 0.12);
  }
  return Math.max(24, Math.min(w, h) * frac * __privateGet(this, _lensRadiusScale));
};
requestLensFrame_fn = function() {
  if (__privateGet(this, _gl)) {
    this._startGlLoop(2);
    return;
  }
  if (__privateGet(this, _lensRaf) || !__privateGet(this, _frameCanvas)) return;
  __privateSet(this, _lensRaf, requestAnimationFrame(() => {
    __privateSet(this, _lensRaf, 0);
    __privateMethod(this, _ProtectedImage_instances, paintLens2d_fn).call(this);
  }));
};
// Token sources are { id }; { imageId } is accepted as an alias so the
// shape the TypeScript surface long documented keeps working.
tokenSourceId_fn = function() {
  const src = __privateGet(this, _source);
  if (!src || typeof src !== "object" || src instanceof Blob || src instanceof ArrayBuffer || ArrayBuffer.isView(src)) return null;
  return src.id ?? src.imageId ?? null;
};
isTokenSource_fn = function() {
  return !!__privateMethod(this, _ProtectedImage_instances, tokenSourceId_fn).call(this);
};
isAssetSource_fn = function() {
  const src = __privateGet(this, _source);
  return !!(src && typeof src === "object" && !(src instanceof Blob) && !(src instanceof ArrayBuffer) && !ArrayBuffer.isView(src) && (src.assetId || src.asset));
};
/**
 * Only a token source can produce a *different, larger* derivative. For it,
 * a large host growth (or explicit reloadOnResize:'always') may justify one
 * fresh mint; every ordinary resize remains a local repaint.
 */
shouldUpgradeDerivative_fn = function(previousW, previousH) {
  if (!__privateGet(this, _loadedOnce) || !__privateGet(this, _meta) || !__privateGet(this, _visible) || !__privateMethod(this, _ProtectedImage_instances, isTokenSource_fn).call(this) && !__privateMethod(this, _ProtectedImage_instances, isAssetSource_fn).call(this)) return false;
  const policy = __privateGet(this, _options).reloadOnResize;
  if (policy === "never") return false;
  let size;
  try {
    size = this._backingSize();
  } catch {
    return false;
  }
  if (policy === "always") return size.w !== previousW || size.h !== previousH;
  if (policy !== "upscale") return false;
  const factor = Math.max(1, __privateGet(this, _options).resizeUpscaleFactor || 1.75);
  return !!(previousW && size.w > previousW * factor || previousH && size.h > previousH * factor);
};
/* ---------------- source resolution ---------------- */
/**
 * Effective temporal config, or null when disabled / reduced-motion.
 * Legacy temporalShield/cameraShield complementary noise and the newer
 * literal temporalInterlace can be used independently or combined.
 */
temporalConfig_fn = function() {
  const o = __privateGet(this, _options);
  const reducedMotion = typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
  let raw = o.cameraShield || o.temporalShield;
  if (raw == null && o.captureShield && typeof o.captureShield === "object") {
    raw = o.captureShield.temporalDither;
  }
  let noise = null;
  if (raw) {
    const cfg = raw === true ? {} : raw;
    const respected = !cfg || cfg.respectReducedMotion === false || !reducedMotion;
    if (cfg && cfg.enabled !== false && respected) {
      const pattern2 = ["blocks", "checker", "bands"].includes(cfg.pattern) ? cfg.pattern : "blocks";
      const engineRaw = String(cfg.engine || cfg.drawingMode || "auto").toLowerCase();
      noise = {
        strength: Math.max(0, Math.min(0.45, Number(cfg.strength ?? 0.16))),
        block: Math.max(1, Math.min(16, Math.round(Number(cfg.block ?? 2)))),
        pattern: pattern2,
        chroma: cfg.chroma === true,
        engine: ["shader", "gpu", "webgl"].includes(engineRaw) ? "shader" : ["frames", "canvas", "canvas2d", "2d"].includes(engineRaw) ? "frames" : "auto"
      };
    }
  }
  if (__privateGet(this, _temporalInterlaceCache) === void 0) {
    __privateSet(this, _temporalInterlaceCache, normalizeTemporalInterlace(o.temporalInterlace));
  }
  let interlace = __privateGet(this, _temporalInterlaceCache);
  if (interlace && interlace.respectReducedMotion && reducedMotion) interlace = null;
  if (!noise && !interlace) return null;
  const legacyPattern = interlace?.layout === "strips" ? "bands" : interlace?.layout === "checker" || interlace?.layout === "pixels" ? "checker" : "blocks";
  const pattern = noise?.pattern || legacyPattern;
  return {
    strength: noise?.strength ?? 0,
    block: noise?.block ?? interlace?.cellSize ?? 2,
    pattern,
    patternCode: pattern === "checker" ? 1 : pattern === "bands" ? 2 : 0,
    chroma: noise?.chroma ?? interlace?.chroma ?? false,
    noise: !!noise,
    interlace,
    engine: interlace?.engine || noise?.engine || "auto",
    phases: interlace?.phases || 2
  };
};
waitForStableSize_fn = async function() {
  if (typeof requestAnimationFrame !== "function") return;
  let last = "";
  let stable = 0;
  for (let i = 0; i < 14 && !__privateGet(this, _destroyed); i++) {
    const r = __privateGet(this, _host).getBoundingClientRect?.();
    const key = `${Math.round(r?.width || 0)}x${Math.round(r?.height || 0)}`;
    if (r && r.width > 2 && r.height > 2 && key === last) {
      if (++stable >= 2) break;
    } else stable = 0;
    last = key;
    await new Promise((res) => requestAnimationFrame(res));
  }
};
tokenMintContext_fn = async function(controls) {
  const o = __privateGet(this, _options);
  const src = __privateGet(this, _source) || {};
  const tokenId = __privateMethod(this, _ProtectedImage_instances, tokenSourceId_fn).call(this);
  const endpointRaw = src.tokenEndpoint || o.tokenEndpoint;
  if (!endpointRaw) throw new Error("Archx: tokenEndpoint required for {id} sources");
  const endpointUrl = resolveHttpUrl(endpointRaw, { label: "token endpoint" });
  if (endpointUrl.search || endpointUrl.hash) throw nonRetryableError("Archx: token endpoint must not contain a query or fragment");
  const rect = __privateGet(this, _host).getBoundingClientRect?.();
  const cssWidth = rect?.width || __privateGet(this, _host).clientWidth || 800;
  const cssHeight = rect?.height || __privateGet(this, _host).clientHeight || cssWidth * 0.75;
  const { dprCap, oversample, requestQuality } = effectiveSampling(o);
  const pixelScale = Math.min(devicePixelRatio || 1, dprCap) * Math.max(1, oversample);
  const maxSourceWidth = boundedInteger(o.maxSourceWidth, DEFAULTS.maxSourceWidth, 64, 16384);
  const boxW = canonicalSourceWidth(cssWidth * pixelScale, o.sourceWidthBuckets, maxSourceWidth);
  const boxH = canonicalSourceWidth(cssHeight * pixelScale, o.sourceWidthBuckets, maxSourceWidth);
  const fit = ["cover", "contain", "fill"].includes(o.fit) ? o.fit : "cover";
  const tokenMethod = String(o.tokenMethod || "POST").toUpperCase() === "GET" ? "GET" : "POST";
  const tokenTransport = ["header", "query", "auto"].includes(String(o.tokenTransport || "header").toLowerCase()) ? String(o.tokenTransport || "header").toLowerCase() : "header";
  const proofSetting = o.proofOfPossession;
  const proofMode = proofSetting === false || proofSetting === "off" ? "off" : proofSetting === true || proofSetting === "required" ? "required" : "auto";
  const proofKey = proofMode === "off" ? null : await getProofKey(proofMode === "required");
  const mintUrl = new URL(endpointUrl.href);
  mintUrl.pathname = `${mintUrl.pathname.replace(/\/?$/, "/")}${encodeURIComponent(tokenId)}`;
  mintUrl.searchParams.set("w", String(boxW));
  mintUrl.searchParams.set("bw", String(boxW));
  mintUrl.searchParams.set("bh", String(boxH));
  mintUrl.searchParams.set("fit", fit);
  if (requestQuality != null) mintUrl.searchParams.set("q", String(requestQuality));
  const tokenCacheKey = cacheDigest([
    "token",
    1,
    o.cacheScope || "",
    endpointUrl.origin,
    endpointUrl.pathname,
    tokenId,
    boxW,
    boxH,
    fit,
    requestQuality,
    tokenMethod,
    tokenTransport,
    proofKey?.jkt || proofMode,
    controls.credentials,
    o.allowedTokenOrigins || null,
    o.grid,
    o.scrambled === true,
    o.key || "",
    o.aesKey || "",
    controls.maxResponseBytes,
    controls.maxDecodedPixels,
    controls.maxDecodedDimension
  ]);
  return {
    endpointUrl,
    boxW,
    boxH,
    fit,
    requestQuality,
    tokenMethod,
    tokenTransport,
    proofMode,
    proofKey,
    mintUrl,
    tokenCacheKey
  };
};
prefetchTokenBatchMint_fn = async function(force = false) {
  const o = __privateGet(this, _options);
  if (o.tokenBatch !== true || __privateGet(this, _prefetchedTokenMint) || __privateGet(this, _destroyed)) return;
  if (!force && __privateGet(this, _cachedBytes)) return;
  const tokenId = __privateMethod(this, _ProtectedImage_instances, tokenSourceId_fn).call(this);
  if (!tokenId || typeof tokenId !== "string" || tokenId.length > 256 || /[\u0000-\u001f\u007f]/.test(tokenId)) return;
  const controls = fetchControls(o);
  let context;
  try {
    context = await __privateMethod(this, _ProtectedImage_instances, tokenMintContext_fn).call(this, controls);
  } catch {
    return;
  }
  if (__privateGet(this, _destroyed) || __privateGet(this, _prefetchedTokenMint) || context.tokenMethod !== "POST") return;
  const batchUrl = deriveTokenBatchEndpoint(context.endpointUrl, o);
  if (!batchUrl) return;
  const cacheBitmap = o.cacheBitmap !== false && o.memory !== "strict";
  if (!force && cacheBitmap && cacheGetEntry(context.tokenCacheKey)) return;
  const headers = context.proofKey ? { "X-Archx-Request": "token", "X-Archx-Proof-Key": context.proofKey.header } : { "X-Archx-Request": "token" };
  const promise = queueTokenBatchRequest({
    batchUrl,
    item: {
      id: tokenId,
      w: context.boxW,
      bw: context.boxW,
      bh: context.boxH,
      fit: context.fit,
      ...context.requestQuality != null ? { q: context.requestQuality } : {}
    },
    headers,
    credentials: controls.credentials,
    controls,
    signal: __privateGet(this, _abort).signal,
    options: o
  });
  promise.catch(() => {
  });
  __privateSet(this, _prefetchedTokenMint, { key: context.tokenCacheKey, promise });
};
/** Hook/automation gate. Returns true if loading may proceed. */
securityGate_fn = function() {
  const o = __privateGet(this, _options);
  if (Date.now() < __privateGet(this, _lockedUntil)) return false;
  if (!["off", "monitor", "lock"].includes(o.integrity)) {
    if (__privateGet(this, _attemptHandler)) __privateGet(this, _attemptHandler).call(this, "integrity:invalid-mode");
    return false;
  }
  if (o.integrity !== "off") {
    __privateSet(this, _integrityIssues, auditIntegrity());
    if (__privateGet(this, _integrityIssues).length) {
      if (__privateGet(this, _attemptHandler)) __privateGet(this, _attemptHandler).call(this, "integrity:" + __privateGet(this, _integrityIssues).join(","));
      if (o.integrity === "lock") return false;
    }
  }
  if (o.automation !== "off") {
    const signals = detectAutomation();
    if (signals.length) {
      if (__privateGet(this, _attemptHandler)) __privateGet(this, _attemptHandler).call(this, "automation:" + signals.join(","));
      if (o.automation === "lock") return false;
    }
  }
  return true;
};
/** Strict-memory mode: drop the decoded source as soon as pixels are painted. */
releaseSourceBitmap_fn = function() {
  if (__privateGet(this, _options).memory !== "strict" || !__privateGet(this, _bitmap)) return;
  if (__privateGet(this, _bitmapCacheEntry)) cacheReleaseEntry(__privateGet(this, _bitmapCacheEntry));
  else closeBitmapQuietly(__privateGet(this, _bitmap));
  __privateSet(this, _bitmapCacheEntry, null);
  __privateSet(this, _bitmap, null);
  __privateSet(this, _bitmapReleased, true);
};
/**
 * Build pre-rendered phase frames for Canvas2D. Legacy temporalShield
 * keeps its original two complementary-noise frames. temporalInterlace
 * instead assigns each spatial cell to exactly one phase; cells outside
 * the current phase receive the configured low-detail/dim/black/noise fill.
 */
setupTemporalFrames_fn = function(frame, cfg) {
  __privateMethod(this, _ProtectedImage_instances, stopTemporal2d_fn).call(this, true);
  const w = frame.width, h = frame.height;
  const fctx = getNativeContext(frame, "2d");
  let src;
  try {
    src = nativeGetImageData(fctx, 0, 0, w, h);
  } catch {
    return;
  }
  const interlace = cfg.interlace;
  const phases = Math.max(2, Math.min(4, cfg.phases || 2));
  const needNoise = !!cfg.noise || interlace?.fill === "noise";
  const noiseBlock = Math.max(1, cfg.block || 1);
  const nbw = Math.ceil(w / noiseBlock), nbh = Math.ceil(h / noiseBlock);
  const offsets = needNoise ? new Float32Array(nbw * nbh * 3) : null;
  const amp = (cfg.noise ? cfg.strength : interlace?.noiseStrength || 0) * 255;
  if (offsets) {
    for (let by = 0; by < nbh; by++) {
      for (let bx = 0; bx < nbw; bx++) {
        const oi = (by * nbw + bx) * 3;
        if (cfg.pattern === "bands" && bx > 0) {
          offsets[oi] = offsets[oi - 3];
          offsets[oi + 1] = offsets[oi - 2];
          offsets[oi + 2] = offsets[oi - 1];
          continue;
        }
        const parity = cfg.pattern === "checker" ? bx + by & 1 ? 1 : -1 : 1;
        if (cfg.chroma) {
          const scalar = cfg.pattern === "checker" ? (0.35 + Math.random() * 0.65) * amp * parity : (Math.random() * 2 - 1) * amp;
          offsets[oi] = scalar;
          offsets[oi + 1] = -0.62 * scalar;
          offsets[oi + 2] = 0.78 * scalar;
        } else if (cfg.pattern === "checker") {
          offsets[oi] = (0.35 + Math.random() * 0.65) * amp * parity;
          offsets[oi + 1] = (0.35 + Math.random() * 0.65) * amp * parity;
          offsets[oi + 2] = (0.35 + Math.random() * 0.65) * amp * parity;
        } else {
          offsets[oi] = (Math.random() * 2 - 1) * amp;
          offsets[oi + 1] = (Math.random() * 2 - 1) * amp;
          offsets[oi + 2] = (Math.random() * 2 - 1) * amp;
        }
      }
    }
  }
  const cell = Math.max(1, interlace?.cellSize || noiseBlock);
  const bw = Math.ceil(w / cell), bh = Math.ceil(h / cell);
  let assignments = null;
  if (interlace) {
    assignments = new Uint8Array(bw * bh);
    for (let by = 0; by < bh; by++) {
      for (let bx = 0; bx < bw; bx++) {
        let phase = 0;
        if (interlace.layout === "strips") {
          phase = (interlace.axis === "columns" ? bx : by) % phases;
        } else if (interlace.layout === "blocks") {
          phase = Math.random() * phases | 0;
        } else if (interlace.layout === "pixels") {
          phase = (bx + (phases === 2 ? by : 2 * by)) % phases;
        } else {
          phase = (bx + by) % phases;
        }
        assignments[by * bw + bx] = phase;
      }
    }
  }
  let lowData = null;
  let lowW = 0;
  let lowH = 0;
  let lowBlock = 1;
  if (interlace?.fill === "lowres") {
    lowBlock = Math.max(1, interlace.fillBlock || 12);
    lowW = Math.max(1, Math.ceil(w / lowBlock));
    lowH = Math.max(1, Math.ceil(h / lowBlock));
    try {
      const low = makeCanvas(__privateGet(this, _host).ownerDocument);
      low.width = lowW;
      low.height = lowH;
      const lowCtx = getNativeContext(low, "2d");
      setSmoothing(lowCtx, true);
      nativeDrawImage(lowCtx, frame, 0, 0, lowW, lowH);
      lowData = nativeGetImageData(lowCtx, 0, 0, lowW, lowH).data;
      low.width = 0;
      low.height = 0;
    } catch {
      lowData = null;
    }
  }
  const biasBlock = 24;
  const bbw = Math.ceil(w / biasBlock), bbh = Math.ceil(h / biasBlock);
  const biasAmp = (interlace?.noiseStrength || 0) * 255 * 0.55;
  const biases = interlace && interlace.fill === "noise" && biasAmp > 0 ? new Float32Array(bbw * bbh) : null;
  if (biases) for (let i = 0; i < biases.length; i++) biases[i] = (Math.random() * 2 - 1) * biasAmp;
  const colBias = biases ? new Int32Array(w) : null;
  if (colBias) for (let x = 0; x < w; x++) colBias[x] = Math.min(bbw - 1, Math.floor(x / biasBlock));
  const colNoiseOi = offsets ? new Int32Array(w) : null;
  if (colNoiseOi) for (let x = 0; x < w; x++) colNoiseOi[x] = Math.min(nbw - 1, Math.floor(x / noiseBlock)) * 3;
  const scratch = fctx.createImageData(w, h);
  const mk = (phase) => {
    const sign = (phase % 2 ? -1 : 1) * [1, 0.6, 1.3, 0.85][phase % 4];
    const c = makeCanvas(__privateGet(this, _host).ownerDocument);
    c.width = w;
    c.height = h;
    const cctx = getNativeContext(c, "2d");
    const out = scratch;
    const s = src.data, d = out.data;
    if (!interlace) {
      for (let by = 0; by < nbh; by++) {
        const y0 = by * noiseBlock;
        const y1 = Math.min(h, y0 + noiseBlock);
        for (let y = y0; y < y1; y++) {
          let p = y * w * 4;
          for (let bx = 0; bx < nbw; bx++) {
            const oi = (by * nbw + bx) * 3;
            const x1 = Math.min(w, (bx + 1) * noiseBlock);
            for (let x = bx * noiseBlock; x < x1; x++, p += 4) {
              d[p] = s[p] + sign * offsets[oi];
              d[p + 1] = s[p + 1] + sign * offsets[oi + 1];
              d[p + 2] = s[p + 2] + sign * offsets[oi + 2];
              d[p + 3] = 255;
            }
          }
        }
      }
      nativePutImageData(cctx, out, 0, 0);
      return c;
    }
    const gain = interlace.activeGain || 1;
    const fillMix = interlace.fillStrength;
    for (let by = 0; by < bh; by++) {
      const y0 = by * cell;
      const y1 = Math.min(h, y0 + cell);
      for (let bx = 0; bx < bw; bx++) {
        const active = assignments[by * bw + bx] === phase;
        const x0 = bx * cell;
        const x1 = Math.min(w, x0 + cell);
        for (let y = y0; y < y1; y++) {
          let p = (y * w + x0) * 4;
          const lowY = lowData ? Math.min(lowH - 1, Math.floor(y / lowBlock)) : 0;
          const rowNoiseOi = offsets ? Math.min(nbh - 1, Math.floor(y / noiseBlock)) * nbw * 3 : 0;
          const rowBiasOff = biases ? Math.min(bbh - 1, Math.floor(y / biasBlock)) * bbw : 0;
          for (let x = x0; x < x1; x++, p += 4) {
            const sr = s[p], sg = s[p + 1], sb = s[p + 2];
            const bv = biases ? biases[rowBiasOff + colBias[x]] : 0;
            let r, g, b;
            if (active) {
              const ab = bv * fillMix * (phases - 1) / phases;
              r = sr * gain + ab;
              g = sg * gain + ab;
              b = sb * gain + ab;
            } else {
              let fr = sr, fg = sg, fb = sb;
              if (interlace.fill === "lowres" && lowData) {
                const lowX = Math.min(lowW - 1, Math.floor(x / lowBlock));
                const li = (lowY * lowW + lowX) * 4;
                fr = lowData[li];
                fg = lowData[li + 1];
                fb = lowData[li + 2];
              } else if (interlace.fill === "dim") {
                fr = sr * interlace.hiddenScale;
                fg = sg * interlace.hiddenScale;
                fb = sb * interlace.hiddenScale;
              } else if (interlace.fill === "black") {
                fr = 0;
                fg = 0;
                fb = 0;
              } else if (interlace.fill === "noise" && offsets) {
                const oi = rowNoiseOi + colNoiseOi[x];
                const hb = bv / phases;
                fr = sr - hb + sign * offsets[oi];
                fg = sg - hb + sign * offsets[oi + 1];
                fb = sb - hb + sign * offsets[oi + 2];
              }
              r = sr + (fr - sr) * fillMix;
              g = sg + (fg - sg) * fillMix;
              b = sb + (fb - sb) * fillMix;
            }
            if (cfg.noise && offsets) {
              const oi = rowNoiseOi + colNoiseOi[x];
              r += sign * offsets[oi];
              g += sign * offsets[oi + 1];
              b += sign * offsets[oi + 2];
            }
            d[p] = r;
            d[p + 1] = g;
            d[p + 2] = b;
            d[p + 3] = 255;
          }
        }
      }
    }
    nativePutImageData(cctx, out, 0, 0);
    return c;
  };
  __privateSet(this, _temporalFrames, Array.from({ length: phases }, (_, phase) => mk(phase)));
  __privateSet(this, _temporalIndex, 0);
  __privateSet(this, _temporalPhase, 0);
  __privateSet(this, _temporalSign, 1);
  __privateMethod(this, _ProtectedImage_instances, paintTemporal2d_fn).call(this);
  if (__privateGet(this, _visible)) __privateMethod(this, _ProtectedImage_instances, startTemporal2d_fn).call(this);
};
// Next temporal phase from a shuffled bag: every phase appears once per
// cycle (so the eye still integrates the full set at the same rate) but
// the ORDER is unpredictable, so fixed-cadence capture cannot parity-lock
// onto a stable subsequence.
nextPhase_fn = function(phases) {
  if (!__privateGet(this, _phaseBag).length || __privateGet(this, _phaseBag)[0] >= phases) {
    __privateSet(this, _phaseBag, Array.from({ length: phases }, (_, i) => i));
    for (let i = phases - 1; i > 0; i--) {
      const j = Math.random() * (i + 1) | 0;
      [__privateGet(this, _phaseBag)[i], __privateGet(this, _phaseBag)[j]] = [__privateGet(this, _phaseBag)[j], __privateGet(this, _phaseBag)[i]];
    }
  }
  return __privateGet(this, _phaseBag).pop();
};
paintTemporal2d_fn = function() {
  const ctx = __privateGet(this, _realCtx);
  const frames = __privateGet(this, _temporalFrames);
  if (!ctx || !frames?.length || __privateGet(this, _destroyed) || !__privateGet(this, _canvas)) return;
  const phase = __privateGet(this, _temporalPhase) % frames.length;
  if (__privateGet(this, _options).lens && __privateGet(this, _frameCanvas)) {
    __privateMethod(this, _ProtectedImage_instances, paintLens2d_fn).call(this);
    return;
  }
  if (Date.now() < __privateGet(this, _lockedUntil)) {
    ctx.fillStyle = "#000";
    ctx.fillRect(0, 0, __privateGet(this, _canvas).width, __privateGet(this, _canvas).height);
    return;
  }
  nativeDrawImage(ctx, frames[phase], 0, 0);
};
startTemporal2d_fn = function() {
  if (__privateGet(this, _temporalRaf) || !__privateGet(this, _temporalFrames) || __privateGet(this, _destroyed)) return;
  const step = () => {
    __privateSet(this, _temporalRaf, 0);
    if (__privateGet(this, _destroyed) || !__privateGet(this, _temporalFrames) || !__privateGet(this, _visible)) return;
    __privateWrapper(this, _temporalIndex)._++;
    __privateSet(this, _temporalPhase, __privateMethod(this, _ProtectedImage_instances, nextPhase_fn).call(this, __privateGet(this, _temporalFrames).length));
    __privateMethod(this, _ProtectedImage_instances, paintTemporal2d_fn).call(this);
    __privateSet(this, _temporalRaf, requestAnimationFrame(step));
  };
  __privateSet(this, _temporalRaf, requestAnimationFrame(step));
};
stopTemporal2d_fn = function(wipe = false) {
  if (__privateGet(this, _temporalRaf)) cancelAnimationFrame(__privateGet(this, _temporalRaf));
  __privateSet(this, _temporalRaf, 0);
  if (wipe && __privateGet(this, _temporalFrames)) {
    for (const f of __privateGet(this, _temporalFrames)) {
      f.width = 0;
      f.height = 0;
    }
    __privateSet(this, _temporalFrames, null);
  }
};
paintLens2d_fn = function() {
  const ctx = __privateGet(this, _realCtx);
  const frame = __privateGet(this, _frameCanvas);
  if (!ctx || !frame || __privateGet(this, _destroyed)) return;
  const w = frame.width, h = frame.height;
  if (Date.now() < __privateGet(this, _lockedUntil)) {
    ctx.fillStyle = "#000";
    ctx.fillRect(0, 0, w, h);
    return;
  }
  ctx.fillStyle = "#000";
  ctx.fillRect(0, 0, w, h);
  if (__privateGet(this, _lensBase)) {
    ctx.imageSmoothingEnabled = false;
    nativeDrawImage(ctx, __privateGet(this, _lensBase), 0, 0, w, h);
    ctx.fillStyle = "rgba(4,6,12,0.18)";
    ctx.fillRect(0, 0, w, h);
  }
  const point = __privateGet(this, _lensPoint);
  if (point) {
    const cfg = typeof __privateGet(this, _options).lens === "object" ? __privateGet(this, _options).lens : {};
    const radius = __privateMethod(this, _ProtectedImage_instances, lensRadiusPx_fn).call(this, w, h, cfg.radius ?? 0.3);
    const cx = point.x * w, cy = point.y * h;
    ctx.save();
    ctx.beginPath();
    ctx.arc(cx, cy, radius, 0, Math.PI * 2);
    ctx.clip();
    const phaseFrames = __privateGet(this, _temporalFrames);
    const sharpSource = phaseFrames?.length ? phaseFrames[__privateGet(this, _temporalPhase) % phaseFrames.length] : frame;
    nativeDrawImage(ctx, sharpSource, 0, 0);
    ctx.restore();
    ctx.save();
    ctx.strokeStyle = "rgba(255,255,255,0.35)";
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.arc(cx, cy, radius, 0, Math.PI * 2);
    ctx.stroke();
    ctx.restore();
  }
};
// Record the decoy size and build REAL decoys (lowres/scrambled)
// eagerly while clean pixels exist; the default black policy defers
// to #getDecoy() on first intercepted readback (most sessions never
// have one, saving a full-size placeholder canvas per instance).
prepareDecoy_fn = function(cleanCanvas, w, h) {
  __privateSet(this, _decoySize, { w, h });
  if (__privateGet(this, _decoy) || !cleanCanvas) return;
  const kind = __privateGet(this, _options).onExtract;
  if (kind === "lowres" || kind === "scrambled") {
    __privateSet(this, _decoy, this._makeDecoy(cleanCanvas, w, h));
  }
};
getDecoy_fn = function() {
  if (__privateGet(this, _decoy)) return __privateGet(this, _decoy);
  let size = __privateGet(this, _decoySize);
  if (!size) {
    try {
      const { w, h } = this._backingSize();
      size = { w, h };
    } catch {
      size = { w: 320, h: 200 };
    }
  }
  try {
    __privateSet(this, _decoy, this._makeDecoy(null, Math.max(1, size.w), Math.max(1, size.h)));
  } catch {
    const c = makeCanvas(__privateGet(this, _host).ownerDocument);
    c.width = 1;
    c.height = 1;
    __privateSet(this, _decoy, c);
  }
  return __privateGet(this, _decoy);
};
/**
 * Poison read-back APIs on ONE canvas instance (prototypes untouched, so
 * the rest of the host page's canvases keep working). Naïve grabbers and
 * extensions calling canvas.toDataURL() etc. receive the decoy.
 * Note: HTMLCanvasElement.prototype.toDataURL.call(canvas) bypasses any
 * instance patch on a 2D canvas — vault/WebGL mode exists for that threat.
 */
/**
 * Draw the cross-origin 1x1 taint pixel into a fresh 2D bitmap BEFORE
 * any image pixels cover it. The pixel itself is invisible in the final
 * composition; its only effect is flipping origin-clean to false so the
 * browser itself rejects every readback (see resolveTaintUrl). Must be
 * re-applied after any canvas resize, which resets the flag.
 */
taintContext_fn = function(ctx) {
  const img = __privateGet(this, _taintImage);
  if (!img || !ctx) return;
  try {
    nativeDrawImage(ctx, img, 0, 0, 1, 1);
  } catch {
  }
};
/* ---------------- WebGL vault ---------------- */
/** A canvas that already owns a WebGL context can never become a 2D
 * canvas — fallback therefore swaps in a fresh element inside the shadow. */
fresh2dCanvas_fn = function() {
  const fresh = makeCanvas(__privateGet(this, _host).ownerDocument);
  fresh.className = "main";
  fresh.setAttribute("aria-hidden", "true");
  __privateGet(this, _canvas).replaceWith(fresh);
  __privateSet(this, _canvas, fresh);
  __privateSet(this, _realCtx, null);
  return fresh;
};
/** Decide what the GPU texture will hold (scrambled whenever possible). */
prepareGlSource_fn = function() {
  if (__privateGet(this, _glMeta)) return;
  const o = __privateGet(this, _options);
  if (!__privateGet(this, _meta).plan && o.localScramble) {
    const { w, h } = this._backingSize();
    const { full } = this._workingCanvas(w, h);
    const local = scrambleCanvasLocally(full, o.grid, "local:" + sessionId());
    __privateMethod(this, _ProtectedImage_instances, prepareDecoy_fn).call(this, full, full.width, full.height);
    full.width = 0;
    full.height = 0;
    __privateSet(this, _glSource, local.canvas);
    __privateSet(this, _glMeta, local.meta);
    return;
  }
  __privateSet(this, _glSource, __privateGet(this, _bitmap));
  __privateSet(this, _glMeta, __privateGet(this, _meta));
};
// A rewritten/preserved drawing buffer breaks the vault's core
// readback guarantee. Under integrity:'lock' (fortress default) that is
// fatal for this instance — blackout instead of silently gifting an
// untainted 2D fallback; under 'monitor' it is a strike + event.
flagPreserveRewrite_fn = function(source) {
  if (__privateGet(this, _preserveFlagged)) return;
  __privateSet(this, _preserveFlagged, true);
  __privateGet(this, _host).dispatchEvent(new CustomEvent("archx-integrity", {
    detail: { issue: "preserveDrawingBuffer-rewritten", source },
    bubbles: true
  }));
  if (__privateGet(this, _attemptHandler)) __privateGet(this, _attemptHandler).call(this, "integrity:preserve-drawing-buffer");
  if (__privateGet(this, _options).integrity === "lock") {
    __privateSet(this, _integrityHardLock, true);
    this._stopGlLoop();
    if (__privateGet(this, _gl)) {
      try {
        const lose = __privateGet(this, _gl).getExtension && glNative(__privateGet(this, _gl), "getExtension", "WEBGL_lose_context");
        if (lose?.loseContext) {
          __privateSet(this, _glReleasing, true);
          lose.loseContext();
        }
      } catch {
      }
    }
    __privateMethod(this, _ProtectedImage_instances, paintBlackout_fn).call(this);
  }
};
paintBlackout_fn = function() {
  try {
    __privateGet(this, _wrap).classList.add("blackout");
    if (!__privateGet(this, _canvas) || __privateGet(this, _destroyed)) return;
    const { w, h } = this._backingSize();
    __privateGet(this, _tilesEl).hidden = true;
    __privateGet(this, _canvas).hidden = false;
    if (__privateGet(this, _canvas).width !== w || __privateGet(this, _canvas).height !== h) {
      __privateGet(this, _canvas).width = w;
      __privateGet(this, _canvas).height = h;
    }
    const ctx = getNativeContext(__privateGet(this, _canvas), "2d", { alpha: false });
    if (ctx) {
      ctx.fillStyle = "#000";
      ctx.fillRect(0, 0, w, h);
    }
  } catch {
  }
};
// The clear-at-composite only happens for a canvas that was actually
// presented. A below-fold canvas (our visibility observer uses a 500px
// rootMargin, so the loop runs before the element is on screen) keeps
// its drawing buffer indefinitely — indistinguishable from a forced
// preserve. The canary therefore only runs when the canvas is provably
// inside the layout viewport, and defers (never flags) otherwise.
canaryPresentable_fn = function() {
  try {
    if (typeof document !== "undefined" && document.visibilityState === "hidden") return false;
    const el = __privateGet(this, _canvas) || __privateGet(this, _wrap);
    if (!el?.getBoundingClientRect) return false;
    const r = el.getBoundingClientRect();
    if (!(r.width > 0 && r.height > 0)) return false;
    const vw = window.innerWidth || document.documentElement?.clientWidth || 0;
    const vh = window.innerHeight || document.documentElement?.clientHeight || 0;
    if (!(vw > 0 && vh > 0)) return false;
    const overlapX = Math.min(r.right, vw) - Math.max(r.left, 0);
    const overlapY = Math.min(r.bottom, vh) - Math.max(r.top, 0);
    return overlapX >= 8 && overlapY >= 8;
  } catch {
    return false;
  }
};
// One-time behavioral probe (per GL context): on a genuine
// preserveDrawingBuffer:false swapchain, the drawing buffer is cleared
// at composite time, so a readPixels two frames later (before drawing)
// returns clear color. If our painted pixels are still there, a
// getContext proxy preserved the buffer even if getContextAttributes
// was spoofed to deny it.
captureCanaryProbe_fn = function(gl, w, h) {
  try {
    if (!NATIVES.glReadPixels || w < 8 || h < 8) {
      __privateSet(this, _canaryDone, true);
      return;
    }
    const points = [[0.5, 0.5], [0.25, 0.25], [0.75, 0.25], [0.25, 0.75], [0.75, 0.75]];
    const probe = [];
    const px = new Uint8Array(4);
    for (const [fx, fy] of points) {
      const x = Math.min(w - 1, Math.max(0, Math.round(fx * w)));
      const y = Math.min(h - 1, Math.max(0, Math.round(fy * h)));
      nativeCall(NATIVES.glReadPixels, gl, [x, y, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, px]);
      if (px[0] + px[1] + px[2] > 24) probe.push({ x, y, r: px[0], g: px[1], b: px[2] });
    }
    if (probe.length) {
      __privateSet(this, _canaryProbe, probe);
      __privateSet(this, _canaryPause, true);
      __privateSet(this, _canaryWait, 2);
    } else __privateSet(this, _canaryDone, true);
  } catch {
    __privateSet(this, _canaryDone, true);
  }
};
checkCanaryProbe_fn = function(gl) {
  const probe = __privateGet(this, _canaryProbe);
  __privateSet(this, _canaryProbe, null);
  __privateSet(this, _canaryPause, false);
  if (!probe?.length || !NATIVES.glReadPixels) {
    __privateSet(this, _canaryDone, true);
    return;
  }
  if (!__privateMethod(this, _ProtectedImage_instances, canaryPresentable_fn).call(this)) return;
  __privateSet(this, _canaryDone, true);
  try {
    const px = new Uint8Array(4);
    let preserved = true;
    for (const p of probe) {
      nativeCall(NATIVES.glReadPixels, gl, [p.x, p.y, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, px]);
      if (px[0] !== p.r || px[1] !== p.g || px[2] !== p.b) {
        preserved = false;
        break;
      }
    }
    if (preserved) __privateMethod(this, _ProtectedImage_instances, flagPreserveRewrite_fn).call(this, "canary");
  } catch {
  }
};
glContinuous_fn = function() {
  const loop = __privateGet(this, _options).renderLoop;
  if (loop === "continuous") return true;
  if (loop === "static") return false;
  return !!__privateMethod(this, _ProtectedImage_instances, temporalConfig_fn).call(this);
};

// src/client/loaders.js
function loadImage(target, source, options) {
  const inst = new ProtectedImage(target, source, options);
  return inst;
}
async function preloadAssets(assetIds, options = {}) {
  if (!Array.isArray(assetIds)) throw new Error("Archx: preloadAssets requires an array of asset ids");
  const ids = [...new Set(assetIds.filter(
    (id) => typeof id === "string" && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(id)
  ))].slice(0, 500);
  const o = mergeOptions(options);
  const controls = fetchControls(o);
  if (o.networkAware === true && networkConnectionInfo()?.saveData) {
    return Object.freeze({
      preloaded: Object.freeze([]),
      failed: Object.freeze([]),
      skipped: "save-data"
    });
  }
  const manifestSource = options.assetManifest || o.assetManifest;
  if (!manifestSource) throw new Error("Archx: assetManifest required for preloadAssets");
  const manifest = await loadAssetManifest(manifestSource, o, controls);
  const { dprCap } = effectiveSampling(o);
  const viewportWidth = typeof window !== "undefined" ? window.innerWidth || 1280 : 1280;
  const deviceRatio = typeof devicePixelRatio !== "undefined" ? devicePixelRatio || 1 : 1;
  const defaultWidth = Math.ceil(Math.min(viewportWidth * Math.min(deviceRatio, dprCap), 2560));
  const wantedWidth = canonicalSourceWidth(
    boundedInteger(options.width, defaultWidth, 1, 16384),
    o.sourceWidthBuckets,
    boundedInteger(o.maxSourceWidth, DEFAULTS.maxSourceWidth, 64, 16384)
  );
  const cacheMode = normalizedHttpCache(o.assetHttpCache, "default");
  const preloaded = [];
  const failed = [];
  let cursor = 0;
  const workers = Array.from({ length: Math.min(4, ids.length) }, async () => {
    while (cursor < ids.length) {
      const id = ids[cursor++];
      try {
        const asset = manifest.assets.get(id);
        if (!asset) throw new Error("asset id is not present in the manifest");
        const variant = chooseAssetVariant(asset, wantedWidth);
        const { bytes } = await fetchBounded(variant.url.href, {
          method: "GET",
          credentials: controls.credentials,
          cache: cacheMode,
          ...fetchPriorityInit({ ...o, fetchPriority: o.fetchPriority || "low" })
        }, {
          retries: controls.retries,
          maxBytes: controls.maxResponseBytes,
          timeoutMs: controls.fetchTimeoutMs,
          validateResponse: (res) => {
            if (!res.url) return;
            let finalUrl;
            try {
              finalUrl = new URL(res.url);
            } catch {
              throw nonRetryableError("Archx: asset response URL is invalid");
            }
            if (!["http:", "https:"].includes(finalUrl.protocol) || finalUrl.username || finalUrl.password) {
              throw nonRetryableError("Archx: asset response URL is disallowed");
            }
          }
        });
        await verifyAssetVariantIntegrity(variant, bytes, o);
        preloaded.push(id);
      } catch (err) {
        failed.push(Object.freeze({ id, error: String(err?.message || err).slice(0, 200) }));
      }
    }
  });
  await Promise.all(workers);
  return Object.freeze({
    preloaded: Object.freeze(preloaded),
    failed: Object.freeze(failed)
  });
}
function loadGallery(container, items, options = {}) {
  const host = $(container);
  if (!host) throw new Error("Archx: gallery container not found");
  const galleryDefaults = {
    mode: "lite",
    qualityProfile: "catalog",
    unloadOnExit: true,
    sourceOversample: 1,
    dprCap: 2,
    cachePayload: true,
    reloadOnResize: "never",
    tokenBatch: true,
    tokenBatchDelayMs: 20,
    tokenBatchMaxDelayMs: 150,
    sourceWidthBuckets: DEFAULT_SOURCE_WIDTH_BUCKETS,
    networkAware: true,
    httpCache: "default",
    bitmapCacheMaxEntries: 24,
    bitmapCacheMaxBytes: 128 * 1024 * 1024
  };
  const made = items.map((item) => {
    const cell = document.createElement("div");
    cell.className = options.itemClass || "archx-gallery-item";
    host.appendChild(cell);
    const isObj = item && typeof item === "object" && ("src" in item || "id" in item || "assetId" in item || "asset" in item);
    const src = isObj && "src" in item ? item.src : item;
    const per = isObj ? { alt: item.alt || "", ...item.options || {} } : {};
    return new ProtectedImage(cell, src, { ...galleryDefaults, ...options, ...per });
  });
  return { instances: made, ready: Promise.allSettled(made.map((i) => i.ready)) };
}
function protectAll(selectorOrNodes = "img[data-protect], [data-archx-src]", options = {}) {
  const nodes = typeof selectorOrNodes === "string" ? [...document.querySelectorAll(selectorOrNodes)] : [...selectorOrNodes];
  return nodes.map((node) => {
    const src = node.dataset.archxSrc || node.currentSrc || node.getAttribute("src");
    const host = document.createElement("div");
    host.className = node.className || "";
    if (node.getAttribute("style")) host.setAttribute("style", node.getAttribute("style"));
    const w = node.getAttribute("width"), h = node.getAttribute("height");
    if (w && h) host.style.aspectRatio = w + " / " + h;
    node.replaceWith(host);
    return new ProtectedImage(host, src, { alt: node.getAttribute("alt") || "", ...options });
  });
}
function defineElement() {
  if (typeof customElements === "undefined" || customElements.get("archx-image")) return;
  const elementInstances = /* @__PURE__ */ new WeakMap();
  const elementInners = /* @__PURE__ */ new WeakMap();
  const boolAttr = (el, name) => {
    if (!el.hasAttribute(name)) return void 0;
    const v = String(el.getAttribute(name) ?? "").trim().toLowerCase();
    return !(v === "false" || v === "0" || v === "off" || v === "no");
  };
  class ArchxImage extends HTMLElement {
    static get observedAttributes() {
      return ["src", "image-id", "asset-id", "asset-manifest", "mode", "renderer", "preset", "quality-profile", "watermark", "alt", "fit", "grid", "key", "scrambled", "lens", "capture-shield", "temporal-shield", "camera-shield", "temporal-interlace", "temporal-interlace-engine", "temporal-interlace-layout", "temporal-interlace-phases", "temporal-interlace-cell-size", "temporal-interlace-fill", "temporal-interlace-refresh-hz", "render-loop", "reload-on-resize", "on-extract", "token-endpoint", "token-method", "token-transport", "token-batch", "fetch-priority", "proof-of-possession", "cache-scope", "taint-readback", "taint-url", "plan-version"];
    }
    connectedCallback() {
      if (elementInstances.has(this)) return;
      this.style.display = this.style.display || "block";
      const inner = document.createElement("div");
      inner.style.width = "100%";
      inner.style.height = "100%";
      this.appendChild(inner);
      elementInners.set(this, inner);
      const id = this.getAttribute("image-id");
      const assetId = this.getAttribute("asset-id");
      const src = assetId ? { assetId } : id ? { id } : this.getAttribute("src");
      let presetOptions = {};
      const presetName = this.getAttribute("preset");
      if (presetName) {
        try {
          presetOptions = preset(presetName);
        } catch {
        }
      }
      let temporalInterlace = presetOptions.temporalInterlace;
      const interlaceAttr = this.getAttribute("temporal-interlace");
      const hasInterlaceDetails = [
        "temporal-interlace-engine",
        "temporal-interlace-layout",
        "temporal-interlace-phases",
        "temporal-interlace-cell-size",
        "temporal-interlace-fill",
        "temporal-interlace-refresh-hz"
      ].some((name) => this.hasAttribute(name));
      if (interlaceAttr != null || hasInterlaceDetails) {
        if (interlaceAttr === "false" || interlaceAttr === "off" || interlaceAttr === "none") {
          temporalInterlace = false;
        } else {
          const details = {};
          if (interlaceAttr && interlaceAttr !== "true") details.profile = interlaceAttr;
          const engine = this.getAttribute("temporal-interlace-engine");
          const layout = this.getAttribute("temporal-interlace-layout");
          const phases = this.getAttribute("temporal-interlace-phases");
          const cellSize = this.getAttribute("temporal-interlace-cell-size");
          const fill = this.getAttribute("temporal-interlace-fill");
          const refreshHz = this.getAttribute("temporal-interlace-refresh-hz");
          if (engine) details.engine = engine;
          if (layout) details.layout = layout;
          if (phases) details.phases = Number(phases);
          if (cellSize) details.cellSize = Number(cellSize);
          if (fill) details.fill = fill;
          if (refreshHz) details.refreshHz = Number(refreshHz);
          temporalInterlace = Object.keys(details).length ? details : true;
        }
      }
      const cameraAttr = boolAttr(this, "camera-shield");
      const inst = new ProtectedImage(inner, src, {
        ...presetOptions,
        mode: this.getAttribute("mode") || presetOptions.mode,
        renderer: this.getAttribute("renderer") || presetOptions.renderer,
        qualityProfile: this.getAttribute("quality-profile") || presetOptions.qualityProfile,
        watermark: this.getAttribute("watermark") || void 0,
        alt: this.getAttribute("alt") || "",
        fit: this.getAttribute("fit") || void 0,
        grid: this.getAttribute("grid") ? Number(this.getAttribute("grid")) : void 0,
        key: this.getAttribute("key") || void 0,
        scrambled: boolAttr(this, "scrambled"),
        lens: boolAttr(this, "lens") ?? presetOptions.lens,
        captureShield: boolAttr(this, "capture-shield") ?? presetOptions.captureShield,
        temporalShield: boolAttr(this, "temporal-shield") ?? presetOptions.temporalShield,
        cameraShield: cameraAttr === true ? { pattern: "checker", chroma: true } : cameraAttr === false ? false : presetOptions.cameraShield,
        temporalInterlace,
        renderLoop: this.getAttribute("render-loop") || presetOptions.renderLoop,
        reloadOnResize: this.getAttribute("reload-on-resize") || presetOptions.reloadOnResize,
        onExtract: this.getAttribute("on-extract") || presetOptions.onExtract,
        tokenEndpoint: this.getAttribute("token-endpoint") || void 0,
        tokenMethod: this.getAttribute("token-method") || void 0,
        tokenTransport: this.getAttribute("token-transport") || void 0,
        tokenBatch: this.hasAttribute("token-batch") ? this.getAttribute("token-batch") !== "false" : presetOptions.tokenBatch,
        assetManifest: this.getAttribute("asset-manifest") || presetOptions.assetManifest,
        assetIntegrity: this.getAttribute("asset-integrity") || presetOptions.assetIntegrity,
        assetManifestIntegrity: this.getAttribute("asset-manifest-integrity") || presetOptions.assetManifestIntegrity,
        networkAware: this.hasAttribute("network-aware") ? this.getAttribute("network-aware") !== "false" : presetOptions.networkAware,
        taintReadback: this.getAttribute("taint-readback") || presetOptions.taintReadback,
        taintUrl: this.getAttribute("taint-url") || presetOptions.taintUrl,
        planVersion: this.hasAttribute("plan-version") ? Number(this.getAttribute("plan-version")) : presetOptions.planVersion,
        fetchPriority: this.getAttribute("fetch-priority") || presetOptions.fetchPriority,
        proofOfPossession: this.getAttribute("proof-of-possession") || void 0,
        cacheScope: this.getAttribute("cache-scope") || void 0
      });
      elementInstances.set(this, inst);
      this.ready = inst.ready;
    }
    disconnectedCallback() {
      const inst = elementInstances.get(this);
      if (inst) {
        inst.destroy();
        elementInstances.delete(this);
        elementInners.delete(this);
      }
    }
    attributeChangedCallback(name, oldV, newV) {
      const inst = elementInstances.get(this);
      if (!inst || oldV === newV) return;
      if (name === "src") {
        if (newV) inst.reload(newV);
        return;
      }
      if (name === "image-id") {
        if (newV) inst.reload({ id: newV });
        return;
      }
      if (name === "asset-id") {
        if (newV) inst.reload({ assetId: newV });
        return;
      }
      try {
        inst.destroy();
      } catch {
      }
      elementInstances.delete(this);
      const inner = elementInners.get(this);
      if (inner) inner.remove();
      elementInners.delete(this);
      this.connectedCallback();
    }
  }
  customElements.define("archx-image", ArchxImage);
}

// src/archx.js
var VERSION2 = "1.22.0";
var Archx = {
  version: VERSION2,
  ProtectedImage,
  presets: PRESETS,
  preset,
  sourceWidthBuckets: DEFAULT_SOURCE_WIDTH_BUCKETS,
  temporalInterlaceProfiles: TEMPORAL_INTERLACE_PROFILES,
  normalizeTemporalInterlace,
  config(partial = {}) {
    const clean = {};
    for (const [k, v] of Object.entries(partial)) if (v !== void 0) clean[k] = v;
    const current = getGlobalConfig();
    setGlobalConfig({ ...current, ...clean, guards: { ...current.guards, ...partial.guards || {} } });
    return sanitizeOptionsView(getGlobalConfig());
  },
  load: {
    image: loadImage,
    gallery: loadGallery
  },
  // Friendly aliases
  image: loadImage,
  gallery: loadGallery,
  protectAll,
  /** Warm manifest + HTTP caches for {assetId} sources without mounting viewers. */
  preloadAssets,
  defineElement,
  /** Number of live protected images (the registry itself stays private). */
  get instanceCount() {
    return instances.size;
  },
  /** Prevent future reuse of shared decoded bitmaps (call on logout/account switch). */
  clearCaches() {
    clearBitmapCache();
    assetManifestCache.clear();
    resetPageSession();
  },
  /** Names of browser APIs that currently look monkey-patched. */
  auditIntegrity,
  auditIntegrityDetails,
  captureEarlyIntegritySnapshot,
  verifyEarlyIntegritySnapshot,
  /** Sanitized global monitoring hooks (never tokens, keys, pixels, or raw errors). */
  on: onClientEvent,
  off: offClientEvent,
  use: usePlugin,
  plugins: listPlugins,
  /** Cheap headless/automation signals present in this browser. */
  detectAutomation
};
if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", defineElement, { once: true });
  } else defineElement();
}
var archx_default = Archx;

// src/index.js
var index_default = archx_default;
export {
  ARCHX_MAGIC,
  DEFAULT_GRID,
  DEFAULT_SOURCE_WIDTH_BUCKETS,
  MAX_ARCHX_HEADER_BYTES,
  PRESETS,
  ProtectedImage,
  TEMPORAL_INTERLACE_PROFILES,
  VERSION2 as VERSION,
  applyForensicBlocks,
  assayStegoCollusion,
  assayStegoEmbed,
  auditIntegrity,
  auditIntegrityDetails,
  base64ToBytes,
  buildScramblePlan,
  bytesToBase64,
  captureEarlyIntegritySnapshot,
  comparePerceptualFingerprints,
  cyrb128,
  decodeBmpImage,
  decodeContainer,
  decryptPayload,
  index_default as default,
  detectAutomation,
  detectStegoFingerprint,
  embedStegoFingerprint,
  encodeContainer,
  encryptPayload,
  forensicBlockSigns,
  forensicScore,
  generateKeyBase64,
  hashSeed,
  hmacSha256Bytes,
  isArchxContainer,
  legacyStegoFingerprint,
  listPlugins,
  mulberry32,
  normalizePerceptualFingerprint,
  normalizeTemporalInterlace,
  offClientEvent,
  onClientEvent,
  paddedSize,
  perceptualFingerprint,
  perceptualFingerprintDistance,
  preloadAssets,
  preset,
  scramblePixels,
  scramblePixelsPadded,
  sfc32,
  sha256Bytes,
  sha256SeededPrng,
  sniffImageFormat,
  sniffImageInfo,
  stegoFingerprint,
  tileRect,
  useJsonParser,
  usePlugin,
  useSyncCrypto,
  useWebCrypto,
  validateArchxHeader,
  verifyEarlyIntegritySnapshot
};
//# sourceMappingURL=archx.esm.js.map
