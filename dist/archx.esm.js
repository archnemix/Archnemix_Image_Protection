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
  const tw = Math.ceil(w / grid);
  const th = Math.ceil(h / grid);
  return { tw, th, pw: tw * grid, ph: th * grid };
}
function bytesToBase64(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (typeof Buffer !== "undefined") return Buffer.from(u8).toString("base64");
  let bin = "";
  const CHUNK = 32768;
  for (let i = 0; i < u8.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}
function base64ToBytes(b64) {
  if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(String(b64), "base64"));
  const bin = atob(String(b64));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function encodeContainer(header, payload) {
  const headerBytes = new TextEncoder().encode(JSON.stringify(header));
  const body = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
  const out = new Uint8Array(6 + 4 + headerBytes.length + body.length);
  out.set(new TextEncoder().encode(ARCHX_MAGIC), 0);
  new DataView(out.buffer).setUint32(6, headerBytes.length, false);
  out.set(headerBytes, 10);
  out.set(body, 10 + headerBytes.length);
  return out;
}
function isArchxContainer(bytes) {
  if (!bytes || bytes.length < 10) return false;
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return ARCHX_MAGIC.split("").every((c, i) => u8[i] === c.charCodeAt(0));
}
function decodeContainer(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (!isArchxContainer(u8)) throw new Error("Archx: not an .archx container");
  const headerLen = new DataView(u8.buffer, u8.byteOffset).getUint32(6, false);
  const header = JSON.parse(new TextDecoder().decode(u8.subarray(10, 10 + headerLen)));
  const payload = u8.subarray(10 + headerLen);
  return { header, payload };
}
var keyCache = /* @__PURE__ */ new Map();
async function importAesKey(keyBase64) {
  if (keyCache.has(keyBase64)) return keyCache.get(keyBase64);
  const raw = base64ToBytes(keyBase64);
  if (![16, 24, 32].includes(raw.length)) {
    throw new Error("Archx: AES key must be 16/24/32 bytes (base64)");
  }
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    raw,
    { name: "AES-GCM", length: raw.length * 8 },
    false,
    ["encrypt", "decrypt"]
  );
  keyCache.set(keyBase64, key);
  return key;
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
    plainBytes instanceof Uint8Array ? plainBytes : new Uint8Array(plainBytes)
  );
  return { cipher: new Uint8Array(cipher), iv: bytesToBase64(iv) };
}
async function decryptPayload(cipherBytes, keyBase64, ivBase64) {
  const key = await importAesKey(keyBase64);
  const plain = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(ivBase64) },
    key,
    cipherBytes instanceof Uint8Array ? cipherBytes : new Uint8Array(cipherBytes)
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
function scramblePixels(rgba, pw, ph, plan, direction = "scramble") {
  const { grid, count } = plan;
  const tw = pw / grid;
  const th = ph / grid;
  const src = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  const out = new Uint8Array(src.length);
  for (let dest = 0; dest < count; dest++) {
    const source = direction === "scramble" ? plan.order[dest] : plan.inverse[dest];
    const flipPos = direction === "scramble" ? dest : source;
    const { fx, fy } = plan.flips[flipPos];
    const sx = source % grid * tw;
    const sy = Math.floor(source / grid) * th;
    const dx = dest % grid * tw;
    const dy = Math.floor(dest / grid) * th;
    for (let y = 0; y < th; y++) {
      const yy = fy ? th - 1 - y : y;
      for (let x = 0; x < tw; x++) {
        const xx = fx ? tw - 1 - x : x;
        const si = ((sy + yy) * pw + (sx + xx)) * 4;
        const di = ((dy + y) * pw + (dx + x)) * 4;
        out[di] = src[si];
        out[di + 1] = src[si + 1];
        out[di + 2] = src[si + 2];
        out[di + 3] = src[si + 3];
      }
    }
  }
  return out;
}

// src/archx.js
var VERSION = "1.1.0";
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
  const gl2Proto = typeof WebGL2RenderingContext !== "undefined" ? WebGL2RenderingContext.prototype : null;
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
    glTexImage2D: grab(gl2Proto, "texImage2D"),
    glReadPixels: grab(gl2Proto, "readPixels")
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
    ["Document.prototype.createElement", typeof Document !== "undefined" ? Document.prototype.createElement : null, NATIVES.docCreateElement],
    ["WebGL2RenderingContext.prototype.texImage2D", typeof WebGL2RenderingContext !== "undefined" ? WebGL2RenderingContext.prototype.texImage2D : null, NATIVES.glTexImage2D],
    ["WebGL2RenderingContext.prototype.readPixels", typeof WebGL2RenderingContext !== "undefined" ? WebGL2RenderingContext.prototype.readPixels : null, NATIVES.glReadPixels]
  ];
  const issues = [];
  for (const [name, now, captured] of current) {
    if (!captured && !now) continue;
    if (now !== captured || captured && !isNativeFn(captured)) issues.push(name);
  }
  return issues;
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
var DEFAULTS = {
  mode: "shield",
  // 'lite' | 'shield' | 'vault' | 'fortress'
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
  onExtract: "black",
  // 'black' | 'lowres' | 'scrambled'
  splitCanvases: false,
  // shield+: one canvas per tile (hero images)
  splitGrid: 3,
  maxBackingWidth: 1920,
  // never paint a wider backing store than this
  dprCap: 2,
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
  alt: ""
};
var globalConfig = structuredCloneSafe(DEFAULTS);
var instances = /* @__PURE__ */ new Set();
var hostToInstance = /* @__PURE__ */ new WeakMap();
var pageSessionId = null;
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
  if (merged.mode === "fortress") {
    merged.requestedMode = "fortress";
    merged.mode = "vault";
    if (clean.onExtract === void 0) merged.onExtract = "black";
    if (clean.integrity === void 0) merged.integrity = "lock";
    if (clean.memory === void 0) merged.memory = "strict";
    if (clean.localScramble === void 0) merged.localScramble = true;
    if (clean.forensic === void 0) merged.forensic = true;
    if (clean.strikes === void 0) merged.strikes = { blurAt: 3, lockAt: 6, lockMs: 3e4 };
    if (!opts.guards || opts.guards.devtools === void 0) merged.guards.devtools = true;
  }
  return merged;
}
function sanitizeOptionsView(opts) {
  if (!opts) return opts;
  const { key, aesKey, ...rest } = opts;
  return { ...rest, guards: { ...opts.guards || {} }, key: key ? "[redacted]" : key, aesKey: aesKey ? "[redacted]" : aesKey };
}
var limiter = {
  max: 6,
  active: 0,
  queue: [],
  run(fn) {
    return new Promise((resolve, reject) => {
      const job = () => {
        this.active++;
        Promise.resolve().then(fn).then(resolve, reject).finally(() => {
          this.active--;
          const next = this.queue.shift();
          if (next) next();
        });
      };
      if (this.active < this.max) job();
      else this.queue.push(job);
    });
  }
};
var bitmapCache = /* @__PURE__ */ new Map();
var BITMAP_CACHE_MAX = 40;
function cachePut(key, promise) {
  if (bitmapCache.has(key)) bitmapCache.delete(key);
  bitmapCache.set(key, promise);
  while (bitmapCache.size > BITMAP_CACHE_MAX) {
    const oldest = bitmapCache.keys().next().value;
    bitmapCache.delete(oldest);
  }
}
var visibilityObserver = null;
function getVisibilityObserver() {
  if (!visibilityObserver) {
    visibilityObserver = new IntersectionObserver((entries) => {
      for (const e of entries) {
        const inst = hostToInstance.get(e.target);
        if (inst) inst._onVisibility(e.isIntersecting);
      }
    }, { rootMargin: "500px" });
  }
  return visibilityObserver;
}
var globalGuardsInstalled = false;
function installGlobalGuards() {
  if (globalGuardsInstalled || typeof window === "undefined") return;
  globalGuardsInstalled = true;
  const blackoutAll = (ms, kind) => instances.forEach((i) => i._momentaryBlackout(ms, kind));
  window.addEventListener("keydown", (e) => {
    const shotKey = e.key === "PrintScreen" || e.code === "PrintScreen";
    const macShot = e.metaKey && e.shiftKey && ["3", "4", "5"].includes(e.key);
    const winSnip = e.metaKey && e.shiftKey && (e.key === "S" || e.key === "s");
    if (shotKey || macShot || winSnip) {
      blackoutAll(900, "screenshot-key");
      if (shotKey && navigator.clipboard?.writeText) {
        navigator.clipboard.writeText("").catch(() => {
        });
      }
    }
  }, true);
  window.addEventListener("blur", () => instances.forEach((i) => i._setRisk("blur", true)));
  window.addEventListener("focus", () => instances.forEach((i) => i._setRisk("blur", false)));
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
  devtoolsTimer = setInterval(() => {
    const open = window.outerWidth - window.innerWidth > 170 || window.outerHeight - window.innerHeight > 200;
    instances.forEach((i) => {
      if (i.options.guards.devtools) i._setRisk("devtools", open);
    });
  }, 1e3);
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
async function fetchWithRetries(url, options, retries) {
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await nativeFetch(url, options);
      if (!res.ok) throw new Error("Archx fetch failed: HTTP " + res.status);
      return res;
    } catch (err) {
      lastErr = err;
      if (attempt < retries) await new Promise((r) => setTimeout(r, 250 * (attempt + 1)));
    }
  }
  throw lastErr;
}
function unscrambleToCanvas(bitmap, meta, targetW, targetH) {
  const canvas = makeCanvas();
  canvas.width = Math.max(1, targetW);
  canvas.height = Math.max(1, targetH);
  const ctx = getNativeContext(canvas, "2d");
  if (!meta.plan) {
    nativeDrawImage(ctx, bitmap, 0, 0, targetW, targetH);
    return canvas;
  }
  const { plan, origW, origH, padW, padH } = meta;
  const twSrc = bitmap.width / plan.grid;
  const thSrc = bitmap.height / plan.grid;
  const tileW = Math.max(1, Math.round(targetW * (padW / origW) / plan.grid));
  const tileH = Math.max(1, Math.round(targetH * (padH / origH) / plan.grid));
  const padded = makeCanvas();
  padded.width = tileW * plan.grid;
  padded.height = tileH * plan.grid;
  const pctx = getNativeContext(padded, "2d");
  const exactScale = Math.abs(tileW - twSrc) < 0.01 && Math.abs(tileH - thSrc) < 0.01;
  pctx.imageSmoothingEnabled = !exactScale;
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
  ctx.imageSmoothingEnabled = true;
  ctx.imageSmoothingQuality = "high";
  nativeDrawImage(
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
  cctx.fillStyle = "#000";
  cctx.fillRect(0, 0, pw, ph);
  nativeDrawImage(cctx, source, 0, 0);
  const scrambled = makeCanvas();
  scrambled.width = pw;
  scrambled.height = ph;
  const ctx = getNativeContext(scrambled, "2d");
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
var _options, _host, _root, _wrap, _canvas, _tilesEl, _shieldEl, _source, _bitmap, _meta, _abort, _decoy, _gl, _raf, _loaded, _destroyed, _risk, _blackoutTimer, _resizeObs, _realCtx, _attemptHandler, _loading, _visible, _unloaded, _glProg, _glLoc, _glTex, _glMap, _glWm, _glWmOn, _glSource, _glMeta, _frameCanvas, _lensBase, _lensPoint, _lensRaf, _lensCells, _strikes, _lockedUntil, _lockTimer, _integrityIssues, _bitmapReleased, _ProtectedImage_instances, registerStrike_fn, trackLensTravel_fn, requestLensFrame_fn, securityGate_fn, releaseSourceBitmap_fn, paintLens2d_fn, fresh2dCanvas_fn, prepareGlSource_fn;
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
    __privateAdd(this, _resizeObs, null);
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
    __privateAdd(this, _strikes, 0);
    __privateAdd(this, _lockedUntil, 0);
    __privateAdd(this, _lockTimer, 0);
    __privateAdd(this, _integrityIssues, []);
    __privateAdd(this, _bitmapReleased, false);
    __privateSet(this, _options, mergeOptions(options));
    __privateSet(this, _source, source);
    const host = $(target);
    if (!host) throw new Error("Archx: target element not found: " + target);
    __privateSet(this, _host, host);
    host.classList.add("archx-host");
    hostToInstance.set(host, this);
    if (__privateGet(this, _options).alt) {
      host.setAttribute("role", "img");
      host.setAttribute("aria-label", __privateGet(this, _options).alt);
    }
    this._buildDom();
    this._attachGuards();
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
        root = __privateGet(this, _host);
      }
    }
    __privateSet(this, _root, root);
    const doc = __privateGet(this, _host).ownerDocument;
    const style = doc.createElement("style");
    style.textContent = SHADOW_CSS;
    const wrap = doc.createElement("div");
    wrap.className = "wrap loading" + (o.showBadge ? " show-badge" : "");
    wrap.innerHTML = `
      <div class="tiles" hidden></div>
      <canvas class="main" aria-hidden="true"></canvas>
      <div class="badge">ARCHX&nbsp;PROTECTED</div>
      <div class="shield"></div>
      <div class="risk"></div>
      <div class="err"><span>\u26A0<br>Protected image unavailable</span></div>`;
    root.append(style, wrap);
    __privateSet(this, _wrap, wrap);
    __privateSet(this, _canvas, wrap.querySelector("canvas.main"));
    __privateSet(this, _tilesEl, wrap.querySelector(".tiles"));
    __privateSet(this, _shieldEl, wrap.querySelector(".shield"));
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
  _onVisibility(visible) {
    __privateSet(this, _visible, visible);
    if (visible && !__privateGet(this, _loaded) && !__privateGet(this, _loading)) this._load();
    if (visible && __privateGet(this, _loaded) && __privateGet(this, _unloaded)) this._load();
    if (!visible && __privateGet(this, _options).unloadOnExit && __privateGet(this, _loaded)) this._unloadPixels();
    if (__privateGet(this, _gl)) visible ? this._startGlLoop() : this._stopGlLoop();
  }
  async _init() {
    let resizeTimer = 0;
    __privateSet(this, _resizeObs, new ResizeObserver(() => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        if (__privateGet(this, _gl)) return;
        if (__privateGet(this, _bitmap)) this._render();
        else if (__privateGet(this, _loaded) && __privateGet(this, _bitmapReleased) && __privateGet(this, _visible)) this._load();
      }, 90);
    }));
    __privateGet(this, _resizeObs).observe(__privateGet(this, _host));
    if (__privateGet(this, _options).lazy && "IntersectionObserver" in window) {
      getVisibilityObserver().observe(__privateGet(this, _host));
      const r = __privateGet(this, _host).getBoundingClientRect();
      if (r.bottom > -500 && r.top < innerHeight + 500) this._load();
    } else {
      __privateSet(this, _visible, true);
      await this._load();
    }
    return this;
  }
  /* ---------------- source resolution ---------------- */
  async _resolveBytes() {
    const o = __privateGet(this, _options);
    let src = __privateGet(this, _source);
    let extra = {};
    const strict = o.memory === "strict";
    if (src && typeof src === "object" && !(src instanceof Blob) && !(src instanceof ArrayBuffer) && !ArrayBuffer.isView(src) && src.id) {
      const endpoint = src.tokenEndpoint || o.tokenEndpoint;
      if (!endpoint) throw new Error("Archx: tokenEndpoint required for {id} sources");
      const w = Math.min(o.maxBackingWidth, Math.ceil((__privateGet(this, _host).clientWidth || 800) * Math.min(devicePixelRatio || 1, o.dprCap)));
      let lastErr;
      for (let tokenAttempt = 0; tokenAttempt <= 1; tokenAttempt++) {
        try {
          const res = await fetchWithRetries(
            endpoint + encodeURIComponent(src.id) + "?w=" + w,
            { credentials: o.credentials, signal: __privateGet(this, _abort).signal },
            o.retries
          );
          const token = await res.json();
          const imgRes = await nativeFetch(token.url, {
            credentials: o.credentials,
            cache: "no-store",
            signal: __privateGet(this, _abort).signal
          });
          if ((imgRes.status === 401 || imgRes.status === 403) && tokenAttempt === 0) continue;
          if (!imgRes.ok) throw new Error("Archx fetch failed: HTTP " + imgRes.status);
          const buf = new Uint8Array(await imgRes.arrayBuffer());
          return { ...await this._bytesToBitmap(buf, token), extra: token };
        } catch (err) {
          lastErr = err;
          if (tokenAttempt === 1) throw err;
        }
      }
      throw lastErr;
    }
    if (typeof src === "string") {
      const cacheKey = src + "|" + (extra.key || o.key || "");
      if (!strict && bitmapCache.has(cacheKey)) return { ...await bitmapCache.get(cacheKey), extra };
      const promise = (async () => {
        const res = await fetchWithRetries(
          src,
          { credentials: o.credentials, cache: "no-store", signal: __privateGet(this, _abort).signal },
          o.retries
        );
        const buf = new Uint8Array(await res.arrayBuffer());
        return this._bytesToBitmap(buf, extra);
      })();
      if (!strict) cachePut(cacheKey, promise);
      return { ...await promise, extra };
    }
    if (src instanceof Blob) return { ...await this._bytesToBitmap(new Uint8Array(await src.arrayBuffer()), extra), extra };
    if (src instanceof ArrayBuffer || ArrayBuffer.isView(src)) {
      const bytes = ArrayBuffer.isView(src) ? new Uint8Array(src.buffer, src.byteOffset, src.byteLength) : new Uint8Array(src);
      return { ...await this._bytesToBitmap(bytes, extra), extra };
    }
    throw new Error("Archx: unsupported source type");
  }
  async _bytesToBitmap(buf, extra = {}) {
    const o = __privateGet(this, _options);
    let header = null;
    let payload = buf;
    if (isArchxContainer(buf)) {
      const decoded = decodeContainer(buf);
      header = decoded.header;
      payload = decoded.payload;
      if (header.encrypted) {
        const aesKey = extra.aesKey || o.aesKey;
        if (!aesKey) throw new Error("Archx: encrypted .archx payload needs aesKey");
        payload = await decryptPayload(payload, aesKey, header.iv);
      }
    }
    const scrambled = header ? !!header.scrambled : !!o.scrambled;
    const grid = header?.grid || extra.grid || o.grid;
    const key = extra.key || o.key || "";
    const blob = new Blob([payload], { type: header?.mime || "image/webp" });
    let bitmap;
    try {
      bitmap = await nativeCreateImageBitmap(blob);
    } catch {
      bitmap = await this._bitmapViaImage(blob);
    }
    let meta;
    if (scrambled) {
      const origW = header?.w || bitmap.width;
      const origH = header?.h || bitmap.height;
      const { pw, ph } = header?.pw ? { pw: header.pw, ph: header.ph } : paddedSize(origW, origH, grid);
      meta = { plan: buildScramblePlan(grid, key), origW, origH, padW: pw, padH: ph };
    } else {
      meta = { plan: null, origW: bitmap.width, origH: bitmap.height, padW: bitmap.width, padH: bitmap.height };
    }
    return { bitmap, meta, header };
  }
  _bitmapViaImage(blob) {
    return new Promise((resolve, reject) => {
      const url = NATIVES.createObjectURL ? NATIVES.createObjectURL.call(URL, blob) : URL.createObjectURL(blob);
      const img = new (NATIVES.ImageCtor || Image)();
      img.onload = () => {
        NATIVES.revokeObjectURL ? NATIVES.revokeObjectURL.call(URL, url) : URL.revokeObjectURL(url);
        resolve(img);
      };
      img.onerror = (e) => {
        NATIVES.revokeObjectURL ? NATIVES.revokeObjectURL.call(URL, url) : URL.revokeObjectURL(url);
        reject(e);
      };
      img.src = url;
    });
  }
  async _load() {
    if (__privateGet(this, _loading) || __privateGet(this, _destroyed)) return;
    if (!__privateMethod(this, _ProtectedImage_instances, securityGate_fn).call(this)) {
      __privateGet(this, _wrap).classList.remove("loading");
      __privateGet(this, _wrap).classList.add("error");
      __privateGet(this, _host).dispatchEvent(new CustomEvent("archx-error", {
        detail: { error: new Error("Archx: blocked by integrity/automation/lockout policy") },
        bubbles: true
      }));
      return;
    }
    __privateSet(this, _loading, true);
    try {
      const { bitmap, meta } = await limiter.run(() => this._resolveBytes());
      if (__privateGet(this, _destroyed)) return;
      __privateSet(this, _bitmap, bitmap);
      __privateSet(this, _meta, meta);
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
      try {
        __privateGet(this, _options).onLoad && __privateGet(this, _options).onLoad(this);
      } catch {
      }
    } catch (err) {
      if (__privateGet(this, _destroyed)) return;
      __privateGet(this, _wrap).classList.remove("loading");
      __privateGet(this, _wrap).classList.add("error");
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
    __privateSet(this, _unloaded, true);
  }
  /* ---------------- rendering ---------------- */
  _backingSize() {
    const o = __privateGet(this, _options);
    const rect = __privateGet(this, _host).getBoundingClientRect();
    const cssW = Math.max(1, Math.round(rect.width || __privateGet(this, _host).clientWidth || 320));
    const cssH = Math.max(1, Math.round(rect.height || __privateGet(this, _host).clientHeight || Math.round(cssW * (__privateGet(this, _meta).origH / __privateGet(this, _meta).origW)) || 240));
    let scale = Math.min(window.devicePixelRatio || 1, o.dprCap);
    if (cssW * scale > o.maxBackingWidth) scale = o.maxBackingWidth / cssW;
    const maxScaleBySource = __privateGet(this, _meta).origW * 1 / cssW;
    const w = Math.max(1, Math.round(cssW * Math.min(scale, Math.max(maxScaleBySource, 0.25))));
    const h = Math.max(1, Math.round(cssH * (w / cssW)));
    return { w, h, cssW, cssH };
  }
  _render() {
    if (!__privateGet(this, _bitmap) || __privateGet(this, _destroyed)) return;
    const mode = __privateGet(this, _options).mode;
    if (mode === "vault") {
      if (this._tryRenderWebGL()) return;
    }
    if (__privateGet(this, _options).splitCanvases && mode !== "lite" && !__privateGet(this, _options).lens) this._renderSplit();
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
    const ctx = getNativeContext(canvas, "2d", { alpha: false });
    __privateSet(this, _realCtx, ctx);
    const { full, fit } = this._workingCanvas(w, h);
    if (__privateGet(this, _options).lens) {
      const frame = makeCanvas(__privateGet(this, _host).ownerDocument);
      frame.width = w;
      frame.height = h;
      const fctx = getNativeContext(frame, "2d");
      fctx.fillStyle = "#000";
      fctx.fillRect(0, 0, w, h);
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
    const g = Math.max(2, Math.min(6, __privateGet(this, _options).splitGrid | 0));
    const { full, fit } = this._workingCanvas(w, h);
    const composed = makeCanvas();
    composed.width = w;
    composed.height = h;
    const cctx = getNativeContext(composed, "2d");
    cctx.fillStyle = "#000";
    cctx.fillRect(0, 0, w, h);
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
    if (o.forensic && o.mode !== "lite") {
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
      ctx.globalAlpha = 0.5;
      ctx.fillStyle = "#fff";
      ctx.font = `700 ${Math.max(14, w / 18)}px system-ui,sans-serif`;
      ctx.textAlign = "center";
      ctx.translate(w / 2, h / 2);
      ctx.rotate(-Math.PI / 8);
      ctx.fillText(String((typeof o.watermark === "string" ? o.watermark : o.watermark?.text) || o.brand), 0, 0);
      ctx.restore();
      return decoy;
    }
    if (kind === "scrambled") {
      decoy.width = w;
      decoy.height = h;
      const g = 8;
      const plan = buildScramblePlan(g, "decoy-" + sessionId());
      const tw = cleanCanvas.width / g, th = cleanCanvas.height / g;
      const dw = w / g, dh = h / g;
      for (let dest = 0; dest < plan.count; dest++) {
        const source = plan.order[dest];
        nativeDrawImage(
          ctx,
          cleanCanvas,
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
      gl = getNativeContext(canvas, "webgl2", { preserveDrawingBuffer: false, antialias: false, alpha: false, powerPreference: "low-power" });
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
      in vec2 vUv; out vec4 frag;
      float hash(vec2 q){ return fract(sin(dot(q, vec2(127.1,311.7))+uSeed)*43758.5453); }
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
        vec2 srcUv = effUv;
        if(uScrambled>0.5){
          vec2 paddedUv = effUv * uCrop; // orig->padded space
          vec2 tile = floor(paddedUv*uGrid);
          vec2 local = fract(paddedUv*uGrid);
          vec4 m = texelFetch(uMap, ivec2(tile), 0);
          vec2 srcTile = m.rg*255.0;
          if(m.b>0.5) local.x = 1.0-local.x;
          if(m.a>0.5) local.y = 1.0-local.y;
          srcUv = (srcTile+local)/uGrid;
          // Clamp inside the source tile (half-texel inset) so LINEAR
          // filtering never blends across scrambled-tile boundaries -> no seams.
          vec2 texel = 1.0 / vec2(textureSize(uTex, 0));
          srcUv = clamp(srcUv, srcTile/uGrid + texel*0.75, (srcTile+1.0)/uGrid - texel*0.75);
        }
        vec4 c = texture(uTex, srcUv);
        c.rgb += (hash(gl_FragCoord.xy)-0.5)*(2.0/255.0); // forensic grain
        if(lensOutside>0.5) c.rgb *= 0.82;
        if(uWmOn>0.5){
          vec4 wm = texture(uWm, vUv);
          c.rgb = mix(c.rgb, wm.rgb, wm.a);
        }
        if(uLensOn>0.5 && uLensActive>0.5 && abs(lensDistPx-uLensRadius)<1.5){
          c.rgb = mix(c.rgb, vec3(1.0), 0.35);
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
      "uLocked"
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
  _startGlLoop() {
    if (__privateGet(this, _raf) || !__privateGet(this, _gl)) return;
    const gl = __privateGet(this, _gl);
    const draw = () => {
      __privateSet(this, _raf, requestAnimationFrame(draw));
      if (__privateGet(this, _destroyed) || !__privateGet(this, _gl)) return;
      const { w, h } = this._backingSize();
      if (__privateGet(this, _canvas).width !== w || __privateGet(this, _canvas).height !== h) {
        __privateGet(this, _canvas).width = w;
        __privateGet(this, _canvas).height = h;
      }
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
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    };
    __privateSet(this, _raf, requestAnimationFrame(draw));
  }
  _stopGlLoop() {
    if (__privateGet(this, _raf)) cancelAnimationFrame(__privateGet(this, _raf));
    __privateSet(this, _raf, 0);
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
      glScrambledTexture: !!(__privateGet(this, _glMeta) && __privateGet(this, _glMeta).plan)
    };
  }
  async reload(newSource) {
    if (newSource !== void 0) __privateSet(this, _source, newSource);
    __privateSet(this, _loaded, false);
    __privateGet(this, _wrap).classList.add("loading");
    await this._load();
    return this;
  }
  destroy() {
    __privateSet(this, _destroyed, true);
    instances.delete(this);
    __privateGet(this, _abort).abort();
    this._stopGlLoop();
    if (__privateGet(this, _gl)) {
      try {
        __privateGet(this, _gl).getExtension("WEBGL_lose_context")?.loseContext();
      } catch {
      }
      glContextsInUse = Math.max(0, glContextsInUse - 1);
      __privateSet(this, _gl, null);
    }
    if (__privateGet(this, _resizeObs)) __privateGet(this, _resizeObs).disconnect();
    if (visibilityObserver) visibilityObserver.unobserve(__privateGet(this, _host));
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
    clearTimeout(__privateGet(this, _lockTimer));
    if (__privateGet(this, _options).memory === "strict") {
      try {
        __privateGet(this, _bitmap)?.close && __privateGet(this, _bitmap).close();
      } catch {
      }
    }
    __privateSet(this, _bitmap, null);
    __privateGet(this, _root).replaceChildren?.();
    hostToInstance.delete(__privateGet(this, _host));
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
_resizeObs = new WeakMap();
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
_strikes = new WeakMap();
_lockedUntil = new WeakMap();
_lockTimer = new WeakMap();
_integrityIssues = new WeakMap();
_bitmapReleased = new WeakMap();
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
  if (__privateGet(this, _gl)) return;
  if (__privateGet(this, _lensRaf) || !__privateGet(this, _frameCanvas)) return;
  __privateSet(this, _lensRaf, requestAnimationFrame(() => {
    __privateSet(this, _lensRaf, 0);
    __privateMethod(this, _ProtectedImage_instances, paintLens2d_fn).call(this);
  }));
};
/** Hook/automation gate. Returns true if loading may proceed. */
securityGate_fn = function() {
  const o = __privateGet(this, _options);
  if (Date.now() < __privateGet(this, _lockedUntil)) return false;
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
  try {
    __privateGet(this, _bitmap).close && __privateGet(this, _bitmap).close();
  } catch {
  }
  __privateSet(this, _bitmap, null);
  __privateSet(this, _bitmapReleased, true);
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
    ctx.imageSmoothingEnabled = true;
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
    nativeDrawImage(ctx, frame, 0, 0);
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
function loadImage(target, source, options) {
  const inst = new ProtectedImage(target, source, options);
  return inst;
}
function loadGallery(container, items, options = {}) {
  const host = $(container);
  if (!host) throw new Error("Archx: gallery container not found");
  const galleryDefaults = { mode: "lite", unloadOnExit: true };
  const made = items.map((item) => {
    const cell = document.createElement("div");
    cell.className = options.itemClass || "archx-gallery-item";
    host.appendChild(cell);
    const isObj = item && typeof item === "object" && ("src" in item || "id" in item);
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
      return ["src", "image-id", "mode", "watermark", "alt", "fit", "grid", "key", "on-extract"];
    }
    connectedCallback() {
      if (elementInstances.has(this)) return;
      this.style.display = this.style.display || "block";
      const inner = document.createElement("div");
      inner.style.width = "100%";
      inner.style.height = "100%";
      this.appendChild(inner);
      const id = this.getAttribute("image-id");
      const src = id ? { id } : this.getAttribute("src");
      const inst = new ProtectedImage(inner, src, {
        mode: this.getAttribute("mode") || void 0,
        watermark: this.getAttribute("watermark") || void 0,
        alt: this.getAttribute("alt") || "",
        fit: this.getAttribute("fit") || void 0,
        grid: this.getAttribute("grid") ? Number(this.getAttribute("grid")) : void 0,
        key: this.getAttribute("key") || void 0,
        scrambled: this.hasAttribute("scrambled"),
        lens: this.hasAttribute("lens") ? true : void 0,
        onExtract: this.getAttribute("on-extract") || void 0,
        tokenEndpoint: this.getAttribute("token-endpoint") || void 0
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
  defineElement,
  /** Number of live protected images (the registry itself stays private). */
  get instanceCount() {
    return instances.size;
  },
  /** Names of browser APIs that currently look monkey-patched. */
  auditIntegrity,
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
  ProtectedImage,
  VERSION,
  applyForensicBlocks,
  auditIntegrity,
  base64ToBytes,
  buildScramblePlan,
  bytesToBase64,
  decodeContainer,
  decryptPayload,
  index_default as default,
  detectAutomation,
  encodeContainer,
  encryptPayload,
  forensicBlockSigns,
  forensicScore,
  generateKeyBase64,
  hashSeed,
  isArchxContainer,
  mulberry32,
  paddedSize,
  scramblePixels,
  tileRect
};
//# sourceMappingURL=archx.esm.js.map
