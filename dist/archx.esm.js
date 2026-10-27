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

// src/scramble.js
var ARCHX_MAGIC = "ARCHX1";
var DEFAULT_GRID = 8;
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
function buildScramblePlan(grid = DEFAULT_GRID, key = "") {
  const g = Math.max(2, Math.min(32, grid | 0));
  const count = g * g;
  const rand = mulberry32(hashSeed(String(key) + "::archx-grid-" + g));
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
  return { grid: g, count, order, inverse, flips };
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
function asBytes(bytes) {
  if (bytes instanceof Uint8Array) return bytes;
  if (bytes instanceof ArrayBuffer) return new Uint8Array(bytes);
  if (ArrayBuffer.isView(bytes)) return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return new Uint8Array(bytes || []);
}
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
  const head = new TextDecoder("utf-8", { fatal: false }).decode(u8.subarray(0, Math.min(1024, u8.length))).trimStart().toLowerCase();
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
function bytesToBase64(bytes) {
  const u8 = asBytes(bytes);
  if (typeof Buffer !== "undefined") return Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength).toString("base64");
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
  const bin = atob(normalized);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
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
  "sg"
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
  const headerBytes = new TextEncoder().encode(JSON.stringify(header));
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
function decodeContainer(bytes) {
  const u8 = asBytes(bytes);
  if (!isArchxContainer(u8)) throw new Error("Archx: not an .archx container");
  const headerLen = new DataView(u8.buffer, u8.byteOffset, u8.byteLength).getUint32(6, false);
  if (!Number.isSafeInteger(headerLen) || headerLen < 2 || headerLen > MAX_ARCHX_HEADER_BYTES || 10 + headerLen >= u8.length) {
    throw new Error("Archx: invalid .archx header length");
  }
  let header;
  try {
    header = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(u8.subarray(10, 10 + headerLen)));
  } catch {
    throw new Error("Archx: invalid .archx header encoding");
  }
  validateArchxHeader(header);
  const payload = u8.subarray(10 + headerLen);
  if (!payload.length) throw new Error("Archx: invalid .archx payload");
  return { header, payload };
}
var keyCache = /* @__PURE__ */ new Map();
var AES_KEY_CACHE_MAX = 16;
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
    if (![16, 24, 32].includes(raw.length)) {
      throw new Error("Archx: AES key must be 16/24/32 bytes (base64)");
    }
    return globalThis.crypto.subtle.importKey(
      "raw",
      raw,
      { name: "AES-GCM", length: raw.length * 8 },
      false,
      ["encrypt", "decrypt"]
    );
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
  globalThis.crypto.getRandomValues(raw);
  return bytesToBase64(raw);
}
async function encryptPayload(plainBytes, keyBase64) {
  const key = await importAesKey(keyBase64);
  const iv = new Uint8Array(12);
  globalThis.crypto.getRandomValues(iv);
  const cipher = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    asBytes(plainBytes)
  );
  return { cipher: new Uint8Array(cipher), iv: bytesToBase64(iv) };
}
async function decryptPayload(cipherBytes, keyBase64, ivBase64) {
  const cipher = asBytes(cipherBytes);
  const iv = base64ToBytes(ivBase64);
  if (iv.length !== 12) throw new Error("Archx: AES-GCM IV must be 12 bytes");
  if (cipher.length < 17) throw new Error("Archx: AES-GCM payload is too short");
  const key = await importAesKey(keyBase64);
  const plain = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    key,
    cipher
  );
  return new Uint8Array(plain);
}
function forensicBlockSigns(seed, count) {
  const rand = mulberry32(hashSeed(String(seed) + "::archx-forensic"));
  return Array.from({ length: count }, () => rand() < 0.5 ? -1 : 1);
}
function applyForensicBlocks(rgba, w, h, seed, { blockSize = 32, delta = 2 } = {}) {
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
function forensicScore(candidate, reference, w, h, seed, { blockSize = 32 } = {}) {
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
          diff += (candidate[i] + candidate[i + 1] + candidate[i + 2] - (reference[i] + reference[i + 1] + reference[i + 2])) / 3;
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
function stegoFingerprint(value) {
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
function stegoBytesToBits(bytes) {
  const bits = new Uint8Array(bytes.length * 8);
  bytes.forEach((byte, i) => {
    for (let b = 0; b < 8; b++) bits[i * 8 + b] = byte >> 7 - b & 1;
  });
  return bits;
}
function robustStegoCodeBits(fingerprint, key) {
  const payload = new Uint8Array(6);
  for (let i = 0; i < 6; i++) payload[i] = parseInt(fingerprint.slice(i * 2, i * 2 + 2), 16);
  const crc = stegoCrc16(payload);
  const first = [...payload, crc >> 8 & 255, crc & 255];
  const keyByte = Math.floor(hashSeed("archx-stego-robust:" + String(key ?? ""), 20907) % 256);
  const keyed = new Uint8Array(first.length + 1);
  keyed.set(first, 0);
  keyed[keyed.length - 1] = keyByte;
  const check = stegoCrc16(keyed);
  return stegoBytesToBits(new Uint8Array([
    ...first,
    check >> 8 & 255,
    check & 255,
    165,
    90
  ]));
}
function robustStegoBytesValid(bytes, key) {
  if (!bytes || bytes.length !== 12) return false;
  if (stegoCrc16(bytes.subarray(0, 6)) !== (bytes[6] << 8 | bytes[7])) return false;
  if (bytes[10] !== 165 || bytes[11] !== 90) return false;
  const keyByte = Math.floor(hashSeed("archx-stego-robust:" + String(key ?? ""), 20907) % 256);
  const keyed = new Uint8Array(9);
  keyed.set(bytes.subarray(0, 8), 0);
  keyed[8] = keyByte;
  return stegoCrc16(keyed) === (bytes[8] << 8 | bytes[9]);
}
function robustStegoBitsValid(bits, key) {
  if (!bits || bits.length !== 96) return false;
  const bytes = new Uint8Array(12);
  for (let i = 0; i < 12; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = byte << 1 | bits[i * 8 + b];
    bytes[i] = byte;
  }
  return robustStegoBytesValid(bytes, key);
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
function repairRobustViaFirstCrc(scores, hard, key) {
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
    const fingerprint = robustStegoFingerprintFromBits(correctedFirst);
    const canonical = robustStegoCodeBits(fingerprint, key);
    let flips = 0;
    let softCost = 0;
    for (let i = 0; i < 96; i++) {
      if (canonical[i] === hard[i]) continue;
      flips++;
      softCost += Math.abs(scores[i] || 0);
    }
    return flips <= 8 ? { bits: canonical, flips, softCost } : null;
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
function repairRobustStegoBits(scores, hard, key, maxFlips = 5) {
  const bits = Uint8Array.from(hard);
  const bytes = new Uint8Array(12);
  for (let i = 0; i < 12; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = byte << 1 | bits[i * 8 + b];
    bytes[i] = byte;
  }
  if (robustStegoBytesValid(bytes, key)) return { bits, flips: 0 };
  const syndromeRepair = repairRobustViaFirstCrc(scores, bits, key);
  if (syndromeRepair) return syndromeRepair;
  const candidates = Array.from({ length: bits.length }, (_, index) => index).sort((a, b) => Math.abs(scores[a]) - Math.abs(scores[b])).slice(0, 24);
  const flip = (index) => {
    bits[index] ^= 1;
    bytes[index >> 3] ^= 1 << 7 - (index & 7);
  };
  const search = (start, depth, targetDepth) => {
    if (depth === targetDepth) return robustStegoBytesValid(bytes, key);
    for (let i = start; i <= candidates.length - (targetDepth - depth); i++) {
      flip(candidates[i]);
      if (search(i + 1, depth + 1, targetDepth)) return true;
      flip(candidates[i]);
    }
    return false;
  };
  for (let flips = 1; flips <= maxFlips; flips++) {
    if (search(0, 0, flips)) return { bits: Uint8Array.from(bits), flips };
  }
  return null;
}
function stegoCodeBits(fingerprint) {
  const bytes = new Uint8Array(6);
  for (let i = 0; i < 6; i++) bytes[i] = parseInt(fingerprint.slice(i * 2, i * 2 + 2), 16);
  const crc = stegoCrc16(bytes);
  const all = [...bytes, crc >> 8 & 255, crc & 255];
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
function correctStegoBits(bits, reliability) {
  if (stegoCrcValid(bits)) return { bits, corrections: 0 };
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
var STEGO_ROW_SEGMENTS = 4;
function stegoLayout(cellCount, key) {
  const rand = mulberry32(hashSeed(String(key) + "::archx-stego-layout"));
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
function robustStegoLayout(cellCount, key) {
  const order = Array.from({ length: cellCount }, (_, i) => i);
  const polarity = new Int8Array(cellCount);
  const segmentPolarity = new Int8Array(cellCount * STEGO_ROW_SEGMENTS);
  const rand = mulberry32(hashSeed("archx-stego-robust-layout:" + String(key ?? ""), 20907));
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
function embedStegoFingerprint(rgba, w, h, payload, {
  key = "",
  strength = 6,
  gridX,
  gridY,
  profile = "standard",
  inPlace = false
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
  const bits = robust ? robustStegoCodeBits(fingerprint, key) : stegoCodeBits(fingerprint);
  const { gx, gy } = stegoGrid(w, h, effectiveGridX, effectiveGridY);
  const cellCount = gx * gy;
  const { order, polarity, segmentPolarity } = robust ? robustStegoLayout(cellCount, key) : stegoLayout(cellCount, key);
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
      const cellAmp = amp * Math.max(0.35, Math.min(1, 0.35 + std / 55));
      const cellW = x1 - x0;
      const cellH = y1 - y0;
      for (let y = y0; y < y1; y++) {
        const segment = Math.min(
          rowSegments - 1,
          Math.floor((y - y0) * rowSegments / cellH)
        );
        const segmentSign = segmentPolarity[cell * rowSegments + segment];
        let i = (y * w + x0) * 4;
        for (let x = x0; x < x1; x++, i += 4) {
          const band = Math.min(columnBands - 1, Math.floor((x - x0) * columnBands / cellW));
          const pattern = (band % 2 === 0 ? 1 : -1) * (bit ? 1 : -1) * pol * segmentSign;
          const delta = cellAmp * pattern;
          out[i] = Math.max(0, Math.min(255, src[i] + delta));
          out[i + 1] = Math.max(0, Math.min(255, src[i + 1] + delta));
          out[i + 2] = Math.max(0, Math.min(255, src[i + 2] + delta));
        }
      }
    }
  }
  return out;
}
function detectStegoFingerprint(rgba, w, h, {
  key = "",
  gridX,
  gridY,
  profile = "standard",
  searchOffsets = false,
  searchGeometry = false
} = {}) {
  if (profile === "auto") {
    const standard = detectStegoFingerprint(rgba, w, h, {
      key,
      gridX,
      gridY,
      profile: "standard",
      searchOffsets,
      searchGeometry: false
    });
    if (standard?.found && standard.confidence >= 0.9 && !searchGeometry) return standard;
    const robust2 = detectStegoFingerprint(rgba, w, h, {
      key,
      gridX,
      gridY,
      profile: "robust",
      searchOffsets,
      searchGeometry: false
    });
    const initial = robust2?.found && !standard?.found ? robust2 : standard?.found && !robust2?.found ? standard : (robust2?.confidence ?? 0) > (standard?.confidence ?? 0) ? robust2 : standard;
    if (!searchGeometry || initial?.found) return initial;
    const standardGeometry = detectStegoFingerprint(rgba, w, h, {
      key,
      gridX,
      gridY,
      profile: "standard",
      searchOffsets,
      searchGeometry: true
    });
    if (standardGeometry?.found) return standardGeometry;
    const robustGeometry = detectStegoFingerprint(rgba, w, h, {
      key,
      gridX,
      gridY,
      profile: "robust",
      searchOffsets,
      searchGeometry: true
    });
    return robustGeometry?.found || (robustGeometry?.confidence ?? 0) > (standardGeometry?.confidence ?? 0) ? robustGeometry : standardGeometry;
  }
  const src = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  if (src.length < w * h * 4) throw new Error("Archx stego: pixel buffer is smaller than w\xD7h\xD74");
  const robust = profile === "robust";
  const effectiveProfile = robust ? "robust" : "standard";
  const codeLength = robust ? 96 : 64;
  const rowSegments = STEGO_ROW_SEGMENTS;
  const columnBands = 4;
  const effectiveGridX = gridX ?? (robust ? 20 : 24);
  const effectiveGridY = gridY ?? (robust ? 14 : 16);
  const { gx, gy } = stegoGrid(w, h, effectiveGridX, effectiveGridY);
  const cellCount = gx * gy;
  const { order, polarity, segmentPolarity } = robust ? robustStegoLayout(cellCount, key) : stegoLayout(cellCount, key);
  const cw = w / gx, ch = h / gy;
  const fractions = searchOffsets ? [-0.25, -0.125, 0, 0.125, 0.25] : [0];
  const evaluate = ({ fx = 0, fy = 0, scale = 1, scaleX = scale, scaleY = scale, originX = null, originY = null } = {}) => {
    const cellW0 = cw * scaleX;
    const cellH0 = ch * scaleY;
    const ox = originX ?? fx * cw;
    const oy = originY ?? fy * ch;
    const bitScores = new Float64Array(codeLength);
    const bitCounts = new Uint16Array(codeLength);
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
        const sums = new Float64Array(rowSegments * columnBands);
        const counts = new Uint32Array(rowSegments * columnBands);
        const cellW = x1 - x0;
        const cellH = y1 - y0;
        const step = Math.max(1, Math.floor(Math.min(cellW, cellH) / 12));
        for (let y = y0; y < y1; y += step) {
          const segment = Math.max(0, Math.min(
            rowSegments - 1,
            Math.floor((y - rawY0) * rowSegments / cellH0)
          ));
          let i = (y * w + x0) * 4;
          for (let x = x0; x < x1; x += step, i += step * 4) {
            const band = Math.max(0, Math.min(columnBands - 1, Math.floor((x - rawX0) * columnBands / cellW0)));
            const idx = segment * columnBands + band;
            sums[idx] += src[i] * 77 + src[i + 1] * 150 + src[i + 2] * 29 >> 8;
            counts[idx]++;
          }
        }
        let segmentScoreSum = 0;
        let segmentWeightSum = 0;
        let validSegments = 0;
        const robustSegmentResponses = robust ? [] : null;
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
        cellScores.push({ bitIndex, score });
      }
    }
    const votedBits = new Uint8Array(codeLength);
    const reliability = new Float64Array(codeLength);
    const voteScores = new Float64Array(codeLength);
    if (robust) {
      const groups = Array.from({ length: codeLength }, () => []);
      for (const { bitIndex, score } of cellScores) groups[bitIndex].push(score);
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
    const corrected = robust ? (() => {
      const repaired = repairRobustStegoBits(reliability, votedBits, key, 5);
      return repaired ? { bits: repaired.bits, corrections: repaired.flips } : { bits: votedBits, corrections: -1 };
    })() : correctStegoBits(votedBits, reliability);
    const bits = corrected.bits;
    const fingerprint = robust ? robustStegoFingerprintFromBits(bits) : [...stegoBitsToBytes(bits).subarray(0, 6)].map((b) => b.toString(16).padStart(2, "0")).join("");
    const crcValid = robust ? robustStegoBitsValid(bits, key) : stegoCrcValid(bits);
    const agreeing = cellScores.filter(({ bitIndex, score }) => score >= 0 === !!bits[bitIndex]).length;
    const agreement = cellScores.length ? agreeing / cellScores.length : 0;
    const meanAbs = voteScores.reduce((s, v) => s + Math.abs(v), 0) / codeLength;
    const evidence = Math.max(0, agreement - 0.64) * 2.4 + Math.min(0.55, Math.max(0, meanAbs - 1.4) / 8) - Math.max(0, corrected.corrections) * 0.04;
    const confidence = crcValid ? Math.max(0, Math.min(0.99, 0.42 + evidence)) : Math.max(0, Math.min(0.49, evidence));
    const minBitCount = Math.min(...bitCounts);
    const observedBits = bitCounts.reduce((count, value) => count + (value > 0 ? 1 : 0), 0);
    const bitCoverageOk = robust ? observedBits >= 88 && cellScores.length >= 128 : minBitCount >= 1;
    const correctionCount = Math.max(0, corrected.corrections);
    const robustCorrectionOk = !robust || correctionCount <= 3 || correctionCount <= 5 && meanAbs >= 3.5 && agreement >= 0.95;
    return {
      found: crcValid && agreement >= 0.72 && meanAbs >= 1.2 && cellScores.length >= 96 && bitCoverageOk && robustCorrectionOk,
      fingerprint,
      profile: effectiveProfile,
      observedBits,
      crcValid,
      corrections: Math.max(0, corrected.corrections),
      confidence: Math.round(confidence * 1e3) / 1e3,
      agreement: Math.round(agreement * 1e3) / 1e3,
      meanSignal: Math.round(meanAbs * 100) / 100,
      cells: cellScores.length,
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
  };
  let best = null;
  const consider = (candidate) => {
    const better = !best || candidate.found && !best.found || candidate.found === best.found && candidate._evidence > best._evidence || candidate.found === best.found && candidate._evidence === best._evidence && candidate.confidence > best.confidence;
    if (better) best = candidate;
    return candidate;
  };
  for (const fx of fractions) for (const fy of fractions) {
    consider(evaluate({ fx, fy }));
    if (best.found && best.confidence >= 0.92 && fx === 0 && fy === 0) break;
  }
  if (searchGeometry && !best?.found) {
    const scaleValues = [0.8, 0.85, 0.9, 0.95, 1, 1.05, 1 / 0.9, 1 / 0.85, 1.25];
    const unique = (values) => [...new Set(values.map((v) => Math.round(v * 10) / 10))];
    const originRange = (span, extent) => {
      const min = Math.min(0, extent - span);
      const max = Math.max(0, extent - span);
      return { min, max, center: (min + max) / 2 };
    };
    const scaleCandidates = [];
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
    const originCandidates = [];
    const seenPairs = /* @__PURE__ */ new Set();
    for (const candidate of scaleCandidates.sort((a, b) => b._evidence - a._evidence)) {
      const key2 = `${Math.round(candidate._scaleX * 1e3)}:${Math.round(candidate._scaleY * 1e3)}`;
      if (seenPairs.has(key2)) continue;
      seenPairs.add(key2);
      const rangeX = originRange(gx * cw * candidate._scaleX, w);
      const rangeY = originRange(gy * ch * candidate._scaleY, h);
      for (const originX of unique([rangeX.min, rangeX.center, rangeX.max])) {
        for (const originY of unique([rangeY.min, rangeY.center, rangeY.max])) {
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
        for (let x = 0; x < tw; x++) out32[dstRow + x] = src32[srcRow + (tw - 1 - x)];
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
  const weights = new Float64Array(SIZE * SIZE);
  for (let y = 0; y < h; y++) {
    const y0 = y * SIZE / h;
    const y1 = (y + 1) * SIZE / h;
    const oyStart = Math.floor(y0);
    const oyEnd = Math.min(SIZE - 1, Math.ceil(y1) - 1);
    const rowOffset = y * w * 4;
    for (let x = 0; x < w; x++) {
      const i = rowOffset + x * 4;
      const alpha = src[i + 3] / 255;
      const gray = (src[i] * 54 + src[i + 1] * 183 + src[i + 2] * 19) / 256 * alpha;
      const x0 = x * SIZE / w;
      const x1 = (x + 1) * SIZE / w;
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
  const cosines = Array.from({ length: SIZE }, (_, x) => Array.from({ length: 8 }, (_2, u) => Math.cos((2 * x + 1) * u * Math.PI / (2 * SIZE))));
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

// src/archx.js
var VERSION = "1.7.0";
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
    useProgram: grab(gl2Proto, "useProgram") || grab(gl1Proto, "useProgram")
  };
  return Object.freeze({
    fnToString: Function.prototype.toString,
    fetch: grab(g, "fetch"),
    createImageBitmap: grab(g, "createImageBitmap"),
    ImageCtor: typeof Image !== "undefined" ? Image : null,
    createObjectURL: typeof URL !== "undefined" ? grab(URL, "createObjectURL") : null,
    revokeObjectURL: typeof URL !== "undefined" ? grab(URL, "revokeObjectURL") : null,
    canvasGetContext: grab(canvasProto, "getContext"),
    canvasToDataURL: grab(canvasProto, "toDataURL"),
    canvasToBlob: grab(canvasProto, "toBlob"),
    ctxDrawImage: grab(ctx2dProto, "drawImage"),
    ctxGetImageData: grab(ctx2dProto, "getImageData"),
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
function isNativeFn(fn) {
  if (typeof fn !== "function") return false;
  try {
    return /\[native code\]/.test(NATIVES.fnToString.call(fn));
  } catch {
    return false;
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
    ["Document.prototype.createElement", typeof Document !== "undefined" ? Document.prototype.createElement : null, NATIVES.docCreateElement]
  ];
  const webglMethodNames = [
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
    "useProgram"
  ];
  for (const [label, ctor, capturedMap] of [
    ["WebGLRenderingContext", typeof WebGLRenderingContext !== "undefined" ? WebGLRenderingContext : null, NATIVES.webgl1],
    ["WebGL2RenderingContext", typeof WebGL2RenderingContext !== "undefined" ? WebGL2RenderingContext : null, NATIVES.webgl2]
  ]) {
    for (const method of webglMethodNames) {
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
    ["Document.prototype.createElement", NATIVES.docCreateElement]
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
    ["WebGL2RenderingContext.prototype.readPixels", typeof WebGL2RenderingContext !== "undefined" ? WebGL2RenderingContext.prototype.readPixels : null, snapshot.webgl2ReadPixels]
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
function nativeFetch(url, options) {
  return NATIVES.fetch ? NATIVES.fetch.call(globalThis, url, options) : fetch(url, options);
}
function nativeCreateImageBitmap(source, opts) {
  return NATIVES.createImageBitmap ? NATIVES.createImageBitmap.call(globalThis, source, opts) : createImageBitmap(source, opts);
}
function makeCanvas(ownerDocument) {
  const doc = ownerDocument || document;
  return NATIVES.docCreateElement ? NATIVES.docCreateElement.call(doc, "canvas") : doc.createElement("canvas");
}
function getNativeContext(canvas, type, attrs) {
  return NATIVES.canvasGetContext ? NATIVES.canvasGetContext.call(canvas, type, attrs) : canvas.getContext(type, attrs);
}
function nativeDrawImage(ctx, ...args) {
  return NATIVES.ctxDrawImage ? NATIVES.ctxDrawImage.call(ctx, ...args) : ctx.drawImage(...args);
}
function nativeGlDrawArrays(gl, mode, first, count) {
  return NATIVES.glDrawArrays ? NATIVES.glDrawArrays.call(gl, mode, first, count) : gl.drawArrays(mode, first, count);
}
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
  onLoad: null,
  onError: null,
  onClick: null,
  onEvent: null,
  // (sanitizedEvent, instance) => void — generic monitoring/plugin hook; never receives tokens/keys/pixels
  alt: ""
};
var globalConfig = structuredCloneSafe(DEFAULTS);
var instances = /* @__PURE__ */ new Set();
var hostToInstance = /* @__PURE__ */ new WeakMap();
var pageSessionId = null;
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
function structuredCloneSafe(obj) {
  return JSON.parse(JSON.stringify(obj, (k, v) => typeof v === "function" ? void 0 : v));
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
  merged.renderer = rendererValue === "canvas" || rendererValue === "webgl" ? rendererValue : "auto";
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
    "assetmanifest"
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
    noiseStrength: clampTemporalNumber(merged.noiseStrength ?? merged.strength, 0.16, 0, 0.45),
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
var bitmapCache = /* @__PURE__ */ new Map();
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
var visibilityObservers = /* @__PURE__ */ new Map();
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
function normalizedHttpCache(value, fallback = "no-store") {
  const mode = String(value ?? fallback).toLowerCase();
  return ["default", "no-store", "reload", "no-cache", "force-cache", "only-if-cached"].includes(mode) ? mode : fallback;
}
function fetchPriorityInit(options = {}) {
  const priority = String(options.fetchPriority || "").toLowerCase();
  return ["high", "low", "auto"].includes(priority) ? { priority } : {};
}
var ASSET_MANIFEST_CACHE_MAX = 8;
var assetManifestCache = /* @__PURE__ */ new Map();
var assetManifestObjectCache = /* @__PURE__ */ new WeakMap();
async function sha256Hex(bytes) {
  try {
    if (typeof crypto === "undefined" || !crypto.subtle?.digest) return null;
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const digest = await crypto.subtle.digest("SHA-256", view);
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
var tokenBatchQueues = /* @__PURE__ */ new Map();
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
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (; ; ) {
      const { done, value } = await reader.read();
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
function parseBoundedJson(bytes) {
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
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
      const pair = await subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign", "verify"]
      );
      const exported = await subtle.exportKey("jwk", pair.publicKey);
      if (!exported || exported.kty !== "EC" || exported.crv !== "P-256" || typeof exported.x !== "string" || typeof exported.y !== "string") {
        throw new Error("unsupported proof public key");
      }
      const jwk = { kty: "EC", crv: "P-256", x: exported.x, y: exported.y };
      const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
      const thumbprint = bytesToBase64Url(await subtle.digest("SHA-256", new TextEncoder().encode(canonical)));
      return Object.freeze({
        privateKey: pair.privateKey,
        jwk: Object.freeze(jwk),
        jkt: thumbprint,
        header: bytesToBase64Url(new TextEncoder().encode(JSON.stringify(jwk)))
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
    ath: bytesToBase64Url(await subtle.digest("SHA-256", new TextEncoder().encode(accessToken)))
  };
  const payloadPart = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(proof)));
  const signingInput = `v1.${payloadPart}`;
  const signature = await subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    proofKey.privateKey,
    new TextEncoder().encode(signingInput)
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
  intermediate.width = Math.max(1, Math.ceil(dw * 2));
  intermediate.height = Math.max(1, Math.ceil(dh * 2));
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
  intermediate.width = 0;
  intermediate.height = 0;
}
function unscrambleToCanvas(bitmap, meta, targetW, targetH) {
  const canvas = makeCanvas();
  canvas.width = Math.max(1, targetW);
  canvas.height = Math.max(1, targetH);
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
  padded.width = tileW * plan.grid;
  padded.height = tileH * plan.grid;
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
    pctx.save();
    pctx.translate(dx + (fx ? tileW : 0), dy + (fy ? tileH : 0));
    pctx.scale(fx ? -1 : 1, fy ? -1 : 1);
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
    pctx.restore();
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
  padded.width = 0;
  padded.height = 0;
  return canvas;
}
function scrambleCanvasLocally(source, grid, key) {
  const w = source.width, h = source.height;
  const { tw, th, pw, ph } = paddedSize(w, h, grid);
  const plan = buildScramblePlan(grid, key);
  const cleanPadded = makeCanvas();
  cleanPadded.width = pw;
  cleanPadded.height = ph;
  const cctx = getNativeContext(cleanPadded, "2d");
  setSmoothing(cctx, false);
  cctx.fillStyle = "#000";
  cctx.fillRect(0, 0, pw, ph);
  nativeDrawImage(cctx, source, 0, 0);
  const scrambled = makeCanvas();
  scrambled.width = pw;
  scrambled.height = ph;
  const ctx = getNativeContext(scrambled, "2d");
  setSmoothing(ctx, false);
  ctx.fillStyle = "#000";
  ctx.fillRect(0, 0, pw, ph);
  for (let dest = 0; dest < plan.count; dest++) {
    const orig = plan.order[dest];
    const s = tileRect(orig, plan.grid, tw, th);
    const d = tileRect(dest, plan.grid, tw, th);
    const { fx, fy } = plan.flips[dest];
    ctx.save();
    ctx.translate(d.x + (fx ? tw : 0), d.y + (fy ? th : 0));
    ctx.scale(fx ? -1 : 1, fy ? -1 : 1);
    nativeDrawImage(ctx, cleanPadded, s.x, s.y, tw, th, 0, 0, tw, th);
    ctx.restore();
  }
  cleanPadded.width = 0;
  cleanPadded.height = 0;
  return { canvas: scrambled, meta: { plan, origW: w, origH: h, padW: pw, padH: ph } };
}
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
var _options, _host, _root, _wrap, _canvas, _tilesEl, _shieldEl, _source, _bitmap, _meta, _abort, _decoy, _gl, _raf, _loaded, _destroyed, _risk, _blackoutTimer, _resizeTimer, _visibilityObs, _realCtx, _attemptHandler, _loading, _visible, _unloaded, _glProg, _glLoc, _glTex, _glMap, _glWm, _glWmOn, _glSource, _glMeta, _frameCanvas, _lensBase, _lensPoint, _lensRaf, _lensCells, _traceEl, _traceTimer, _strikes, _lockedUntil, _lockTimer, _integrityIssues, _bitmapReleased, _loadedOnce, _cachedBytes, _cachedExtra, _bitmapCacheEntry, _prefetchedTokenMint, _renderedW, _renderedH, _deviceBox, _glFrameBudget, _glFrames, _temporalSign, _temporalPhase, _temporalRaf, _temporalFrames, _temporalIndex, _temporalEngineActual, _temporalInterlaceCache, _ProtectedImage_instances, registerStrike_fn, trackLensTravel_fn, requestLensFrame_fn, isTokenSource_fn, isAssetSource_fn, shouldUpgradeDerivative_fn, temporalConfig_fn, waitForStableSize_fn, tokenMintContext_fn, prefetchTokenBatchMint_fn, securityGate_fn, releaseSourceBitmap_fn, setupTemporalFrames_fn, paintTemporal2d_fn, startTemporal2d_fn, stopTemporal2d_fn, paintLens2d_fn, fresh2dCanvas_fn, prepareGlSource_fn, glContinuous_fn;
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
    __privateAdd(this, _gl, null);
    __privateAdd(this, _raf, 0);
    __privateAdd(this, _loaded, false);
    __privateAdd(this, _destroyed, false);
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
        root = __privateGet(this, _host).attachShadow({ mode: o.shadow === "open" ? "open" : "closed" });
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
    if (src && typeof src === "object" && !(src instanceof Blob) && !(src instanceof ArrayBuffer) && !ArrayBuffer.isView(src) && src.id) {
      if (typeof src.id !== "string" || !src.id || src.id.length > 256 || /[\u0000-\u001f\u007f]/.test(src.id)) {
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
                id: src.id,
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
        const mint = await fetchBounded(mintUrl.href, {
          method: tokenMethod,
          credentials: controls.credentials,
          cache: "no-store",
          redirect: "error",
          headers: mintHeaders,
          signal: __privateGet(this, _abort).signal,
          ...fetchPriorityInit(o)
        }, {
          retries: controls.retries,
          maxBytes: 65536,
          timeoutMs: controls.fetchTimeoutMs,
          validateResponse: (res) => assertResponseFinalOrigin(res, /* @__PURE__ */ new Set([endpointUrl.origin]))
        });
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
      meta = { plan: buildScramblePlan(grid, key), origW, origH, padW, padH };
    } else {
      meta = { plan: null, origW: bitmapW, origH: bitmapH, padW: bitmapW, padH: bitmapH };
    }
    return { bitmap, meta, header };
  }
  _bitmapViaImage(blob, timeoutMs = DEFAULTS.fetchTimeoutMs) {
    return new Promise((resolve, reject) => {
      const url = NATIVES.createObjectURL ? NATIVES.createObjectURL.call(URL, blob) : URL.createObjectURL(blob);
      const img = new (NATIVES.ImageCtor || Image)();
      let settled = false;
      const finish = (fn, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        img.onload = null;
        img.onerror = null;
        NATIVES.revokeObjectURL ? NATIVES.revokeObjectURL.call(URL, url) : URL.revokeObjectURL(url);
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
      if (!__privateGet(this, _options).aspectRatio && !__privateGet(this, _options).height) {
        __privateGet(this, _host).style.aspectRatio = meta.origW + " / " + meta.origH;
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
      __privateSet(this, _decoy, this._makeDecoy(full, w, h));
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
      __privateSet(this, _decoy, this._makeDecoy(full, w, h));
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
    __privateSet(this, _decoy, this._makeDecoy(full, w, h));
    full.width = 0;
    full.height = 0;
    this._poison(canvas, ctx);
    __privateMethod(this, _ProtectedImage_instances, releaseSourceBitmap_fn).call(this);
  }
  _renderSplit() {
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
      nativeDrawImage(tctx, composed, i % g * tw, Math.floor(i / g) * th, tw, th, 0, 0, tw, th);
      __privateGet(this, _tilesEl).appendChild(c);
      __privateSet(this, _decoy, __privateGet(this, _decoy) || this._makeDecoy(full, w, h));
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
          const diag = Math.hypot(w, h);
          for (let y = -diag / 2; y < diag / 2; y += stepY) {
            ctx.fillText(text, 0, y);
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
      const plan = buildScramblePlan(g, "decoy-" + sessionId());
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
  /**
   * Poison read-back APIs on ONE canvas instance (prototypes untouched, so
   * the rest of the host page's canvases keep working). Naïve grabbers and
   * extensions calling canvas.toDataURL() etc. receive the decoy.
   * Note: HTMLCanvasElement.prototype.toDataURL.call(canvas) bypasses any
   * instance patch on a 2D canvas — vault/WebGL mode exists for that threat.
   */
  _poison(canvas, ctx) {
    const decoy = () => __privateGet(this, _decoy);
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
      return d ? realToDataURL.call(d, type, quality) : "data:,";
    });
    define("toBlob", function(cb, type, quality) {
      var _a;
      __privateGet(_a = self, _attemptHandler).call(_a, "extract-blob");
      const d = decoy();
      if (d) realToBlob.call(d, cb, type, quality);
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
    if (glContextsInUse >= GL_CONTEXT_BUDGET && !__privateGet(this, _gl)) return false;
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
      __privateSet(this, _gl, gl);
      glContextsInUse++;
      canvas.addEventListener("webglcontextlost", (e) => {
        e.preventDefault();
        __privateSet(this, _gl, null);
        glContextsInUse = Math.max(0, glContextsInUse - 1);
        __privateSet(this, _glSource, null);
        __privateSet(this, _glMeta, null);
        __privateMethod(this, _ProtectedImage_instances, fresh2dCanvas_fn).call(this);
        if (__privateGet(this, _bitmap)) this._render2d();
        else {
          __privateSet(this, _loaded, false);
          this._load();
        }
      }, { signal: __privateGet(this, _abort).signal });
      if (!this._initGl(gl)) {
        __privateSet(this, _gl, null);
        glContextsInUse--;
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
    if (!__privateGet(this, _decoy) && __privateGet(this, _bitmap)) {
      const { full } = this._workingCanvas(320, Math.max(1, Math.round(320 * __privateGet(this, _meta).origH / __privateGet(this, _meta).origW)));
      __privateSet(this, _decoy, this._makeDecoy(full, full.width, full.height));
      full.width = 0;
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
      uniform float uInterlaceOn; uniform float uInterlacePhase;
      uniform float uInterlacePhases; uniform float uInterlaceLayout;
      uniform float uInterlaceCell; uniform float uInterlaceAxis;
      uniform float uInterlaceFill; uniform float uInterlaceFillBlock;
      uniform float uInterlaceFillStrength; uniform float uInterlaceHiddenScale;
      uniform float uInterlaceActiveGain; uniform float uInterlaceNoiseStrength;
      in vec2 vUv; out vec4 frag;
      float hash(vec2 q){ return fract(sin(dot(q, vec2(127.1,311.7))+uSeed)*43758.5453); }
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
          if(abs(assigned-uInterlacePhase)<0.5){
            c.rgb *= uInterlaceActiveGain;
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
              fillColor = c.rgb + delta * uInterlaceNoiseStrength * uTemporalSign;
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
        }
        frag = vec4(c.rgb, 1.0);
      }`;
    const compile = (type, srcText) => {
      const s = gl.createShader(type);
      gl.shaderSource(s, srcText);
      gl.compileShader(s);
      if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) return null;
      return s;
    };
    const v = compile(gl.VERTEX_SHADER, vs);
    const f = compile(gl.FRAGMENT_SHADER, fs);
    if (!v || !f) return false;
    const prog = gl.createProgram();
    gl.attachShader(prog, v);
    gl.attachShader(prog, f);
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return false;
    gl.useProgram(prog);
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
      "uInterlaceNoiseStrength"
    ].forEach((n) => {
      __privateGet(this, _glLoc)[n] = gl.getUniformLocation(prog, n);
    });
    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
    gl.enableVertexAttribArray(0);
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
    __privateSet(this, _glTex, gl.createTexture());
    __privateSet(this, _glMap, gl.createTexture());
    __privateSet(this, _glWm, gl.createTexture());
    return true;
  }
  _uploadGlTexture(gl) {
    const meta = __privateGet(this, _glMeta) || __privateGet(this, _meta);
    const source = __privateGet(this, _glSource) || __privateGet(this, _bitmap);
    const texImage = (...args) => NATIVES.glTexImage2D ? NATIVES.glTexImage2D.call(gl, ...args) : gl.texImage2D(...args);
    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, __privateGet(this, _glTex));
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, false);
    texImage(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, source);
    if (!meta.plan) {
      try {
        gl.generateMipmap(gl.TEXTURE_2D);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR_MIPMAP_LINEAR);
      } catch {
      }
    }
    gl.activeTexture(gl.TEXTURE1);
    gl.bindTexture(gl.TEXTURE_2D, __privateGet(this, _glMap));
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
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
    gl.activeTexture(gl.TEXTURE2);
    gl.bindTexture(gl.TEXTURE_2D, __privateGet(this, _glWm));
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    const wm = __privateGet(this, _options).watermark;
    __privateSet(this, _glWmOn, 0);
    if (wm) {
      const cfg = typeof wm === "string" ? { text: wm } : wm;
      const text = String(cfg.text || "").replace("{session}", sessionId().slice(0, 6));
      if (text) {
        const c = makeCanvas();
        c.width = 1024;
        c.height = Math.max(64, Math.round(1024 * meta.origH / meta.origW));
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
          for (let y = -diag / 2; y < diag / 2; y += fs * 4.2) ctx.fillText(text, 0, y);
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
    if (__privateMethod(this, _ProtectedImage_instances, glContinuous_fn).call(this)) __privateSet(this, _glFrameBudget, Infinity);
    else __privateSet(this, _glFrameBudget, Math.max(__privateGet(this, _glFrameBudget), Math.max(1, frames | 0)));
    if (__privateGet(this, _raf)) return;
    const gl = __privateGet(this, _gl);
    const draw = () => {
      __privateSet(this, _raf, 0);
      if (__privateGet(this, _destroyed) || !__privateGet(this, _gl)) return;
      const { w, h } = this._backingSize();
      if (__privateGet(this, _canvas).width !== w || __privateGet(this, _canvas).height !== h) {
        __privateGet(this, _canvas).width = w;
        __privateGet(this, _canvas).height = h;
      }
      __privateSet(this, _renderedW, w);
      __privateSet(this, _renderedH, h);
      gl.viewport(0, 0, w, h);
      gl.useProgram(__privateGet(this, _glProg));
      const L = __privateGet(this, _glLoc);
      const meta = __privateGet(this, _glMeta) || __privateGet(this, _meta);
      gl.uniform1i(L.uTex, 0);
      gl.uniform1i(L.uMap, 1);
      gl.uniform1i(L.uWm, 2);
      gl.uniform1f(L.uGrid, meta.plan ? meta.plan.grid : 1);
      gl.uniform2f(L.uCrop, meta.origW / meta.padW, meta.origH / meta.padH);
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
          sy = srcRatio / dstRatio;
          oy = -(sy - 1) / 2;
          sy = 1 / sy;
          oy = (1 - sy) / 2;
        }
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
      gl.uniform2f(L.uFitScale, sx, sy);
      gl.uniform2f(L.uFitOffset, ox, oy);
      gl.uniform1f(L.uScrambled, meta.plan ? 1 : 0);
      gl.uniform1f(L.uSeed, hashSeed(sessionId()) % 1e3 / 37);
      gl.uniform1f(L.uWmOn, __privateGet(this, _glWmOn) || 0);
      const lensCfg = typeof __privateGet(this, _options).lens === "object" && __privateGet(this, _options).lens ? __privateGet(this, _options).lens : {};
      gl.uniform1f(L.uLensOn, __privateGet(this, _options).lens ? 1 : 0);
      gl.uniform1f(L.uLensActive, __privateGet(this, _lensPoint) ? 1 : 0);
      gl.uniform2f(L.uLensCenter, __privateGet(this, _lensPoint)?.x ?? -10, __privateGet(this, _lensPoint)?.y ?? -10);
      gl.uniform1f(L.uLensRadius, Math.max(24, Math.min(w, h) * (lensCfg.radius ?? 0.3)));
      gl.uniform2f(L.uResolution, w, h);
      gl.uniform1f(L.uLocked, Date.now() < __privateGet(this, _lockedUntil) ? 1 : 0);
      const temporal = __privateMethod(this, _ProtectedImage_instances, temporalConfig_fn).call(this);
      const interlace = temporal?.interlace || null;
      const interlacePhases = interlace?.phases || 2;
      const interlacePhase = (__privateGet(this, _temporalPhase) % interlacePhases + interlacePhases) % interlacePhases;
      gl.uniform1f(L.uTemporalOn, temporal?.noise ? 1 : 0);
      gl.uniform1f(L.uTemporalSign, __privateGet(this, _temporalSign));
      gl.uniform1f(L.uTemporalStrength, temporal ? temporal.strength : 0);
      gl.uniform1f(L.uTemporalBlock, temporal ? temporal.block : 1);
      gl.uniform1f(L.uTemporalPattern, temporal ? temporal.patternCode : 0);
      gl.uniform1f(L.uTemporalChroma, temporal?.chroma ? 1 : 0);
      gl.uniform1f(L.uInterlaceOn, interlace ? 1 : 0);
      gl.uniform1f(L.uInterlacePhase, interlacePhase);
      gl.uniform1f(L.uInterlacePhases, interlacePhases);
      gl.uniform1f(
        L.uInterlaceLayout,
        interlace?.layout === "pixels" ? 0 : interlace?.layout === "strips" ? 1 : interlace?.layout === "blocks" ? 2 : 3
      );
      gl.uniform1f(L.uInterlaceCell, interlace?.cellSize || 1);
      gl.uniform1f(L.uInterlaceAxis, interlace?.axis === "columns" ? 1 : 0);
      gl.uniform1f(
        L.uInterlaceFill,
        interlace?.fill === "dim" ? 1 : interlace?.fill === "black" ? 2 : interlace?.fill === "noise" ? 3 : 0
      );
      gl.uniform1f(L.uInterlaceFillBlock, interlace?.fillBlock || 12);
      gl.uniform1f(L.uInterlaceFillStrength, interlace?.fillStrength ?? 1);
      gl.uniform1f(L.uInterlaceHiddenScale, interlace?.hiddenScale ?? 0.3);
      gl.uniform1f(L.uInterlaceActiveGain, interlace?.activeGain ?? 1);
      gl.uniform1f(L.uInterlaceNoiseStrength, interlace?.noiseStrength ?? 0.16);
      nativeGlDrawArrays(gl, gl.TRIANGLE_STRIP, 0, 4);
      __privateWrapper(this, _glFrames)._++;
      if (temporal) {
        __privateSet(this, _temporalSign, -__privateGet(this, _temporalSign));
        __privateWrapper(this, _temporalIndex)._++;
        __privateSet(this, _temporalPhase, interlace ? (interlacePhase + 1) % interlacePhases : (__privateGet(this, _temporalPhase) + 1) % 2);
      }
      if (__privateGet(this, _glFrameBudget) !== Infinity && __privateGet(this, _glFrameBudget) > 0) __privateWrapper(this, _glFrameBudget)._--;
      const keepGoing = __privateMethod(this, _ProtectedImage_instances, glContinuous_fn).call(this) || __privateGet(this, _glFrameBudget) > 0;
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
        __privateGet(this, _gl).getExtension("WEBGL_lose_context")?.loseContext();
      } catch {
      }
      glContextsInUse = Math.max(0, glContextsInUse - 1);
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
_gl = new WeakMap();
_raf = new WeakMap();
_loaded = new WeakMap();
_destroyed = new WeakMap();
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
/** Heuristic: a lens swept rapidly across many cells == stitching attempt. */
trackLensTravel_fn = function(point) {
  const now = performance.now();
  const cell = Math.floor(point.y * 6) * 6 + Math.floor(point.x * 6);
  __privateGet(this, _lensCells).push({ cell, now });
  __privateSet(this, _lensCells, __privateGet(this, _lensCells).filter((c) => now - c.now < 8e3));
  const distinct = new Set(__privateGet(this, _lensCells).map((c) => c.cell)).size;
  const cfg = typeof __privateGet(this, _options).lens === "object" && __privateGet(this, _options).lens ? __privateGet(this, _options).lens : {};
  const threshold = cfg.scanCells ?? 26;
  if (distinct >= threshold) {
    __privateSet(this, _lensCells, []);
    if (__privateGet(this, _attemptHandler)) __privateGet(this, _attemptHandler).call(this, "lens-scan");
  }
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
isTokenSource_fn = function() {
  const src = __privateGet(this, _source);
  return !!(src && typeof src === "object" && !(src instanceof Blob) && !(src instanceof ArrayBuffer) && !ArrayBuffer.isView(src) && src.id);
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
  const src = __privateGet(this, _source);
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
  mintUrl.pathname = `${mintUrl.pathname.replace(/\/?$/, "/")}${encodeURIComponent(src.id)}`;
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
    src.id,
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
  const src = __privateGet(this, _source);
  if (o.tokenBatch !== true || __privateGet(this, _prefetchedTokenMint) || __privateGet(this, _destroyed)) return;
  if (!force && __privateGet(this, _cachedBytes)) return;
  if (!src || typeof src !== "object" || src instanceof Blob || src instanceof ArrayBuffer || ArrayBuffer.isView(src) || !src.id) return;
  if (typeof src.id !== "string" || !src.id || src.id.length > 256 || /[\u0000-\u001f\u007f]/.test(src.id)) return;
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
      id: src.id,
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
    src = fctx.getImageData(0, 0, w, h);
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
      lowData = lowCtx.getImageData(0, 0, lowW, lowH).data;
      low.width = 0;
      low.height = 0;
    } catch {
      lowData = null;
    }
  }
  const mk = (phase) => {
    const sign = phase % 2 ? -1 : 1;
    const c = makeCanvas(__privateGet(this, _host).ownerDocument);
    c.width = w;
    c.height = h;
    const cctx = getNativeContext(c, "2d");
    const out = cctx.createImageData(w, h);
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
      cctx.putImageData(out, 0, 0);
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
          for (let x = x0; x < x1; x++, p += 4) {
            const sr = s[p], sg = s[p + 1], sb = s[p + 2];
            let r, g, b;
            if (active) {
              r = sr * gain;
              g = sg * gain;
              b = sb * gain;
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
                const nbx = Math.min(nbw - 1, Math.floor(x / noiseBlock));
                const nby = Math.min(nbh - 1, Math.floor(y / noiseBlock));
                const oi = (nby * nbw + nbx) * 3;
                fr = sr + sign * offsets[oi];
                fg = sg + sign * offsets[oi + 1];
                fb = sb + sign * offsets[oi + 2];
              }
              r = sr + (fr - sr) * fillMix;
              g = sg + (fg - sg) * fillMix;
              b = sb + (fb - sb) * fillMix;
            }
            if (cfg.noise && offsets) {
              const nbx = Math.min(nbw - 1, Math.floor(x / noiseBlock));
              const nby = Math.min(nbh - 1, Math.floor(y / noiseBlock));
              const oi = (nby * nbw + nbx) * 3;
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
    cctx.putImageData(out, 0, 0);
    return c;
  };
  __privateSet(this, _temporalFrames, Array.from({ length: phases }, (_, phase) => mk(phase)));
  __privateSet(this, _temporalIndex, 0);
  __privateSet(this, _temporalPhase, 0);
  __privateSet(this, _temporalSign, 1);
  __privateMethod(this, _ProtectedImage_instances, paintTemporal2d_fn).call(this);
  if (__privateGet(this, _visible)) __privateMethod(this, _ProtectedImage_instances, startTemporal2d_fn).call(this);
};
paintTemporal2d_fn = function() {
  const ctx = __privateGet(this, _realCtx);
  const frames = __privateGet(this, _temporalFrames);
  if (!ctx || !frames?.length || __privateGet(this, _destroyed) || !__privateGet(this, _canvas)) return;
  const phase = (__privateGet(this, _temporalIndex) % frames.length + frames.length) % frames.length;
  __privateSet(this, _temporalPhase, phase);
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
    const radius = Math.max(24, Math.min(w, h) * (cfg.radius ?? 0.3));
    const cx = point.x * w, cy = point.y * h;
    ctx.save();
    ctx.beginPath();
    ctx.arc(cx, cy, radius, 0, Math.PI * 2);
    ctx.clip();
    const phaseFrames = __privateGet(this, _temporalFrames);
    const sharpSource = phaseFrames?.length ? phaseFrames[(__privateGet(this, _temporalIndex) % phaseFrames.length + phaseFrames.length) % phaseFrames.length] : frame;
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
    if (!__privateGet(this, _decoy)) __privateSet(this, _decoy, this._makeDecoy(full, full.width, full.height));
    full.width = 0;
    full.height = 0;
    __privateSet(this, _glSource, local.canvas);
    __privateSet(this, _glMeta, local.meta);
    return;
  }
  __privateSet(this, _glSource, __privateGet(this, _bitmap));
  __privateSet(this, _glMeta, __privateGet(this, _meta));
};
glContinuous_fn = function() {
  const loop = __privateGet(this, _options).renderLoop;
  if (loop === "continuous") return true;
  if (loop === "static") return false;
  return !!__privateMethod(this, _ProtectedImage_instances, temporalConfig_fn).call(this);
};
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
  class ArchxImage extends HTMLElement {
    static get observedAttributes() {
      return ["src", "image-id", "asset-id", "asset-manifest", "mode", "renderer", "preset", "quality-profile", "watermark", "alt", "fit", "grid", "key", "scrambled", "lens", "capture-shield", "temporal-shield", "camera-shield", "temporal-interlace", "temporal-interlace-engine", "temporal-interlace-layout", "temporal-interlace-phases", "temporal-interlace-cell-size", "temporal-interlace-fill", "temporal-interlace-refresh-hz", "render-loop", "reload-on-resize", "on-extract", "token-endpoint", "token-method", "token-transport", "token-batch", "fetch-priority", "proof-of-possession", "cache-scope"];
    }
    connectedCallback() {
      if (elementInstances.has(this)) return;
      this.style.display = this.style.display || "block";
      const inner = document.createElement("div");
      inner.style.width = "100%";
      inner.style.height = "100%";
      this.appendChild(inner);
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
        scrambled: this.hasAttribute("scrambled"),
        lens: this.hasAttribute("lens") ? true : presetOptions.lens,
        captureShield: this.hasAttribute("capture-shield") ? true : presetOptions.captureShield,
        temporalShield: this.hasAttribute("temporal-shield") ? true : presetOptions.temporalShield,
        cameraShield: this.hasAttribute("camera-shield") ? { pattern: "checker", chroma: true } : presetOptions.cameraShield,
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
      }
    }
    attributeChangedCallback(name, oldV, newV) {
      const inst = elementInstances.get(this);
      if (!inst || oldV === newV) return;
      if (name === "src" && newV) inst.reload(newV);
    }
  }
  customElements.define("archx-image", ArchxImage);
}
var Archx = {
  version: VERSION,
  ProtectedImage,
  presets: PRESETS,
  preset,
  sourceWidthBuckets: DEFAULT_SOURCE_WIDTH_BUCKETS,
  temporalInterlaceProfiles: TEMPORAL_INTERLACE_PROFILES,
  normalizeTemporalInterlace,
  config(partial = {}) {
    const clean = {};
    for (const [k, v] of Object.entries(partial)) if (v !== void 0) clean[k] = v;
    globalConfig = { ...globalConfig, ...clean, guards: { ...globalConfig.guards, ...partial.guards || {} } };
    return sanitizeOptionsView(globalConfig);
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
    pageSessionId = null;
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
  VERSION,
  applyForensicBlocks,
  auditIntegrity,
  auditIntegrityDetails,
  base64ToBytes,
  buildScramblePlan,
  bytesToBase64,
  captureEarlyIntegritySnapshot,
  comparePerceptualFingerprints,
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
  isArchxContainer,
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
  sniffImageFormat,
  sniffImageInfo,
  stegoFingerprint,
  tileRect,
  usePlugin,
  validateArchxHeader,
  verifyEarlyIntegritySnapshot
};
//# sourceMappingURL=archx.esm.js.map
