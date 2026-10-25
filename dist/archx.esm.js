var __typeError = (msg) => {
  throw TypeError(msg);
};
var __accessCheck = (obj, member, msg) => member.has(obj) || __typeError("Cannot " + msg);
var __privateGet = (obj, member, getter) => (__accessCheck(obj, member, "read from private field"), getter ? getter.call(obj) : member.get(obj));
var __privateAdd = (obj, member, value) => member.has(obj) ? __typeError("Cannot add the same private member more than once") : member instanceof WeakSet ? member.add(obj) : member.set(obj, value);
var __privateSet = (obj, member, value, setter) => (__accessCheck(obj, member, "write to private field"), setter ? setter.call(obj, value) : member.set(obj, value), value);

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
var VERSION = "1.0.0";
var DEFAULTS = {
  mode: "shield",
  // 'lite' | 'shield' | 'vault'
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
  // invisible per-session pixel noise (shield/vault)
  sessionId: null,
  // defaults to a random per-page-view id
  brand: "\xA9 Protected \xB7 Archnemix",
  retries: 2,
  credentials: "same-origin",
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
  return merged;
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
        const inst = e.target.__archx;
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
      const res = await fetch(url, options);
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
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, targetW);
  canvas.height = Math.max(1, targetH);
  const ctx = canvas.getContext("2d");
  if (!meta.plan) {
    ctx.drawImage(bitmap, 0, 0, targetW, targetH);
    return canvas;
  }
  const { plan, origW, origH, padW, padH } = meta;
  const twSrc = bitmap.width / plan.grid;
  const thSrc = bitmap.height / plan.grid;
  const tileW = Math.max(1, Math.round(targetW * (padW / origW) / plan.grid));
  const tileH = Math.max(1, Math.round(targetH * (padH / origH) / plan.grid));
  const padded = document.createElement("canvas");
  padded.width = tileW * plan.grid;
  padded.height = tileH * plan.grid;
  const pctx = padded.getContext("2d");
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
    pctx.drawImage(
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
  ctx.drawImage(
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
var _source, _bitmap, _meta, _abort, _decoy, _gl, _raf, _loaded, _destroyed, _risk, _blackoutTimer, _resizeObs, _realCtx;
var ProtectedImage = class {
  constructor(target, source, options = {}) {
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
    this.options = mergeOptions(options);
    __privateSet(this, _source, source);
    const host = $(target);
    if (!host) throw new Error("Archx: target element not found: " + target);
    this.host = host;
    host.classList.add("archx-host");
    host.__archx = this;
    if (this.options.alt) {
      host.setAttribute("role", "img");
      host.setAttribute("aria-label", this.options.alt);
    }
    this._buildDom();
    this._attachGuards();
    instances.add(this);
    installGlobalGuards();
    if (this.options.guards.devtools) ensureDevtoolsWatcher();
    this.ready = this._init();
  }
  /* ---------------- DOM ---------------- */
  _buildDom() {
    const o = this.options;
    let root;
    if (o.shadow === "none") {
      root = this.host;
    } else {
      try {
        root = this.host.attachShadow({ mode: o.shadow === "open" ? "open" : "closed" });
      } catch {
        root = this.host;
      }
    }
    this.root = root;
    const doc = this.host.ownerDocument;
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
    this.wrap = wrap;
    this.canvas = wrap.querySelector("canvas.main");
    this.tilesEl = wrap.querySelector(".tiles");
    this.shieldEl = wrap.querySelector(".shield");
    if (o.aspectRatio) this.host.style.aspectRatio = String(o.aspectRatio);
    if (o.width) this.host.style.width = typeof o.width === "number" ? o.width + "px" : o.width;
    if (o.height) this.host.style.height = typeof o.height === "number" ? o.height + "px" : o.height;
  }
  _attachGuards() {
    const o = this.options;
    const sig = { signal: __privateGet(this, _abort).signal };
    const attempt = (kind) => {
      try {
        o.onAttempt && o.onAttempt(kind, this);
      } catch {
      }
      this.host.dispatchEvent(new CustomEvent("archx-attempt", { detail: { kind }, bubbles: true }));
    };
    this._attempt = attempt;
    if (o.guards.contextMenu) {
      this.wrap.addEventListener("contextmenu", (e) => {
        e.preventDefault();
        e.stopPropagation();
        attempt("contextmenu");
      }, sig);
    }
    if (o.guards.drag) {
      this.wrap.addEventListener("dragstart", (e) => {
        e.preventDefault();
        attempt("drag");
      }, sig);
    }
    if (o.guards.copy) {
      this.wrap.addEventListener("copy", (e) => {
        e.preventDefault();
        attempt("copy");
      }, sig);
      this.wrap.addEventListener("selectstart", (e) => e.preventDefault(), sig);
    }
    if (o.guards.longPress) {
      let timer = 0;
      this.wrap.addEventListener("pointerdown", (e) => {
        if (e.pointerType !== "touch") return;
        timer = setTimeout(() => {
          attempt("longpress");
          this._momentaryBlackout(700, "longpress");
        }, 450);
      }, sig);
      const clear = () => clearTimeout(timer);
      this.wrap.addEventListener("pointerup", clear, sig);
      this.wrap.addEventListener("pointercancel", clear, sig);
      this.wrap.addEventListener("pointermove", clear, sig);
    }
    this.shieldEl.addEventListener("click", (e) => {
      if (o.onClick) {
        try {
          o.onClick(e, this);
        } catch {
        }
      }
      if (!o.swallowClick) {
        this.host.dispatchEvent(new MouseEvent("click", { bubbles: true, clientX: e.clientX, clientY: e.clientY }));
      }
    }, sig);
  }
  _onVisibility(visible) {
    this._visible = visible;
    if (visible && !__privateGet(this, _loaded) && !this._loading) this._load();
    if (visible && __privateGet(this, _loaded) && this._unloaded) this._load();
    if (!visible && this.options.unloadOnExit && __privateGet(this, _loaded)) this._unloadPixels();
    if (__privateGet(this, _gl)) visible ? this._startGlLoop() : this._stopGlLoop();
  }
  async _init() {
    let resizeTimer = 0;
    __privateSet(this, _resizeObs, new ResizeObserver(() => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        if (__privateGet(this, _bitmap)) this._render();
      }, 90);
    }));
    __privateGet(this, _resizeObs).observe(this.host);
    if (this.options.lazy && "IntersectionObserver" in window) {
      getVisibilityObserver().observe(this.host);
      const r = this.host.getBoundingClientRect();
      if (r.bottom > -500 && r.top < innerHeight + 500) this._load();
    } else {
      this._visible = true;
      await this._load();
    }
    return this;
  }
  /* ---------------- source resolution ---------------- */
  async _resolveBytes() {
    const o = this.options;
    let src = __privateGet(this, _source);
    let extra = {};
    if (src && typeof src === "object" && !(src instanceof Blob) && !(src instanceof ArrayBuffer) && !ArrayBuffer.isView(src) && src.id) {
      const endpoint = src.tokenEndpoint || o.tokenEndpoint;
      if (!endpoint) throw new Error("Archx: tokenEndpoint required for {id} sources");
      const w = Math.min(o.maxBackingWidth, Math.ceil((this.host.clientWidth || 800) * Math.min(devicePixelRatio || 1, o.dprCap)));
      const res = await fetchWithRetries(
        endpoint + encodeURIComponent(src.id) + "?w=" + w,
        { credentials: o.credentials, signal: __privateGet(this, _abort).signal },
        o.retries
      );
      const token = await res.json();
      extra = token;
      src = token.url;
    }
    if (typeof src === "string") {
      const cacheKey = src + "|" + (extra.key || o.key || "");
      if (bitmapCache.has(cacheKey)) return { ...await bitmapCache.get(cacheKey), extra };
      const promise = (async () => {
        const res = await fetchWithRetries(
          src,
          { credentials: o.credentials, cache: "no-store", signal: __privateGet(this, _abort).signal },
          o.retries
        );
        const buf = new Uint8Array(await res.arrayBuffer());
        return this._bytesToBitmap(buf, extra);
      })();
      cachePut(cacheKey, promise);
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
    const o = this.options;
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
      bitmap = await createImageBitmap(blob);
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
      const url = URL.createObjectURL(blob);
      const img = new Image();
      img.onload = () => {
        URL.revokeObjectURL(url);
        resolve(img);
      };
      img.onerror = (e) => {
        URL.revokeObjectURL(url);
        reject(e);
      };
      img.src = url;
    });
  }
  async _load() {
    if (this._loading || __privateGet(this, _destroyed)) return;
    this._loading = true;
    try {
      const { bitmap, meta } = await limiter.run(() => this._resolveBytes());
      if (__privateGet(this, _destroyed)) return;
      __privateSet(this, _bitmap, bitmap);
      __privateSet(this, _meta, meta);
      __privateSet(this, _decoy, null);
      if (!this.options.aspectRatio && !this.options.height) {
        this.host.style.aspectRatio = meta.origW + " / " + meta.origH;
      }
      this._render();
      __privateSet(this, _loaded, true);
      this._unloaded = false;
      this.wrap.classList.remove("loading", "error");
      this.host.dispatchEvent(new CustomEvent("archx-load", { bubbles: true }));
      try {
        this.options.onLoad && this.options.onLoad(this);
      } catch {
      }
    } catch (err) {
      if (__privateGet(this, _destroyed)) return;
      this.wrap.classList.remove("loading");
      this.wrap.classList.add("error");
      this.host.dispatchEvent(new CustomEvent("archx-error", { detail: { error: err }, bubbles: true }));
      try {
        this.options.onError && this.options.onError(err, this);
      } catch {
      }
    } finally {
      this._loading = false;
    }
  }
  _unloadPixels() {
    if (this.canvas) {
      this.canvas.width = 0;
      this.canvas.height = 0;
    }
    this._unloaded = true;
  }
  /* ---------------- rendering ---------------- */
  _backingSize() {
    const o = this.options;
    const rect = this.host.getBoundingClientRect();
    const cssW = Math.max(1, Math.round(rect.width || this.host.clientWidth || 320));
    const cssH = Math.max(1, Math.round(rect.height || this.host.clientHeight || Math.round(cssW * (__privateGet(this, _meta).origH / __privateGet(this, _meta).origW)) || 240));
    let scale = Math.min(window.devicePixelRatio || 1, o.dprCap);
    if (cssW * scale > o.maxBackingWidth) scale = o.maxBackingWidth / cssW;
    const maxScaleBySource = __privateGet(this, _meta).origW * 1 / cssW;
    const w = Math.max(1, Math.round(cssW * Math.min(scale, Math.max(maxScaleBySource, 0.25))));
    const h = Math.max(1, Math.round(cssH * (w / cssW)));
    return { w, h, cssW, cssH };
  }
  _render() {
    if (!__privateGet(this, _bitmap) || __privateGet(this, _destroyed)) return;
    const mode = this.options.mode;
    if (mode === "vault") {
      if (this._tryRenderWebGL()) return;
    }
    if (this.options.splitCanvases && mode !== "lite") this._renderSplit();
    else this._render2d();
  }
  /** Private, capped, un-scrambled working canvas (wiped after use). */
  _workingCanvas(w, h) {
    const meta = __privateGet(this, _meta);
    const fit = fitRects(meta.origW, meta.origH, w, h, this.options.fit);
    const fullW = Math.max(1, Math.round(meta.origW / fit.sw * fit.dw));
    const fullH = Math.max(1, Math.round(meta.origH / fit.sh * fit.dh));
    return { full: unscrambleToCanvas(__privateGet(this, _bitmap), meta, fullW, fullH), fit, fullW, fullH };
  }
  _render2d() {
    const { w, h } = this._backingSize();
    const canvas = this.canvas;
    this.tilesEl.hidden = true;
    canvas.hidden = false;
    canvas.width = w;
    canvas.height = h;
    const ctx = canvas.getContext("2d", { alpha: false });
    __privateSet(this, _realCtx, ctx);
    const { full, fit } = this._workingCanvas(w, h);
    ctx.fillStyle = "#000";
    ctx.fillRect(0, 0, w, h);
    ctx.drawImage(
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
  }
  _renderSplit() {
    const { w, h } = this._backingSize();
    const g = Math.max(2, Math.min(6, this.options.splitGrid | 0));
    const { full, fit } = this._workingCanvas(w, h);
    const composed = document.createElement("canvas");
    composed.width = w;
    composed.height = h;
    const cctx = composed.getContext("2d");
    cctx.fillStyle = "#000";
    cctx.fillRect(0, 0, w, h);
    cctx.drawImage(
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
    this.canvas.hidden = true;
    this.tilesEl.hidden = false;
    this.tilesEl.style.gridTemplateColumns = `repeat(${g},1fr)`;
    this.tilesEl.style.gridTemplateRows = `repeat(${g},1fr)`;
    this.tilesEl.replaceChildren();
    const tw = Math.ceil(w / g), th = Math.ceil(h / g);
    for (let i = 0; i < g * g; i++) {
      const c = document.createElement("canvas");
      c.width = tw;
      c.height = th;
      const tctx = c.getContext("2d", { alpha: false });
      tctx.drawImage(composed, i % g * tw, Math.floor(i / g) * th, tw, th, 0, 0, tw, th);
      this.tilesEl.appendChild(c);
      __privateSet(this, _decoy, __privateGet(this, _decoy) || this._makeDecoy(full, w, h));
      this._poison(c, tctx);
    }
    composed.width = 0;
    full.width = 0;
    full.height = 0;
  }
  _bakeOverlays(ctx, w, h) {
    const o = this.options;
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
      const rand = mulberry32(hashSeed(sessionId() + "|" + (typeof __privateGet(this, _source) === "string" ? __privateGet(this, _source) : "blob")));
      ctx.save();
      for (let i = 0; i < 240; i++) {
        const v = Math.floor(rand() * 255);
        ctx.fillStyle = `rgba(${v},${v},${v},0.035)`;
        ctx.fillRect(Math.floor(rand() * w), Math.floor(rand() * h), 1, 1);
      }
      ctx.restore();
    }
  }
  _makeDecoy(cleanCanvas, w, h) {
    const o = this.options;
    const kind = o.onExtract;
    const decoy = document.createElement("canvas");
    const ctx = decoy.getContext("2d");
    if (kind === "lowres") {
      const tinyW = 72;
      const tinyH = Math.max(1, Math.round(h / w * tinyW));
      const tiny = document.createElement("canvas");
      tiny.width = tinyW;
      tiny.height = tinyH;
      tiny.getContext("2d").drawImage(cleanCanvas, 0, 0, tinyW, tinyH);
      decoy.width = w;
      decoy.height = h;
      ctx.imageSmoothingEnabled = false;
      ctx.drawImage(tiny, 0, 0, w, h);
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
        ctx.drawImage(
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
    const realToDataURL = HTMLCanvasElement.prototype.toDataURL;
    const realToBlob = HTMLCanvasElement.prototype.toBlob;
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
      self._attempt && self._attempt("extract-dataurl");
      const d = decoy();
      return d ? realToDataURL.call(d, type, quality) : "data:,";
    });
    define("toBlob", function(cb, type, quality) {
      self._attempt && self._attempt("extract-blob");
      const d = decoy();
      if (d) realToBlob.call(d, cb, type, quality);
      else if (cb) cb(new Blob([], { type: type || "image/png" }));
    });
    if ("captureStream" in canvas) {
      define("captureStream", function() {
        self._attempt && self._attempt("extract-stream");
        const d = decoy();
        if (d && d.captureStream) return d.captureStream(1);
        throw new DOMException("Protected canvas", "SecurityError");
      });
    }
    if (ctx && ctx.getImageData) {
      const poisonedGet = function(sx, sy, sw, sh) {
        self._attempt && self._attempt("extract-pixels");
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
  /* ---------------- WebGL vault ---------------- */
  _tryRenderWebGL() {
    if (glContextsInUse >= GL_CONTEXT_BUDGET && !__privateGet(this, _gl)) return false;
    const canvas = this.canvas;
    this.tilesEl.hidden = true;
    canvas.hidden = false;
    let gl = __privateGet(this, _gl);
    if (!gl) {
      gl = canvas.getContext("webgl2", { preserveDrawingBuffer: false, antialias: false, alpha: false, powerPreference: "low-power" });
      if (!gl) return false;
      __privateSet(this, _gl, gl);
      glContextsInUse++;
      canvas.addEventListener("webglcontextlost", (e) => {
        e.preventDefault();
        __privateSet(this, _gl, null);
        glContextsInUse = Math.max(0, glContextsInUse - 1);
        this._render2d();
      }, { signal: __privateGet(this, _abort).signal });
      if (!this._initGl(gl)) {
        __privateSet(this, _gl, null);
        glContextsInUse--;
        return false;
      }
    }
    this._uploadGlTexture(gl);
    this._startGlLoop();
    if (!__privateGet(this, _decoy)) {
      const { full } = this._workingCanvas(320, Math.max(1, Math.round(320 * __privateGet(this, _meta).origH / __privateGet(this, _meta).origW)));
      __privateSet(this, _decoy, this._makeDecoy(full, full.width, full.height));
      full.width = 0;
    }
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
      in vec2 vUv; out vec4 frag;
      float hash(vec2 q){ return fract(sin(dot(q, vec2(127.1,311.7))+uSeed)*43758.5453); }
      void main(){
        vec2 uv = vUv*uFitScale + uFitOffset;
        if(uv.x<0.0||uv.x>1.0||uv.y<0.0||uv.y>1.0){ frag=vec4(0.,0.,0.,1.); return; }
        vec2 srcUv = uv;
        if(uScrambled>0.5){
          vec2 paddedUv = uv * uCrop; // orig->padded space
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
        if(uWmOn>0.5){
          vec4 wm = texture(uWm, vUv);
          c.rgb = mix(c.rgb, wm.rgb, wm.a);
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
    this._glProg = prog;
    this._glLoc = {};
    ["uTex", "uMap", "uWm", "uGrid", "uCrop", "uFitScale", "uFitOffset", "uScrambled", "uSeed", "uWmOn"].forEach((n) => {
      this._glLoc[n] = gl.getUniformLocation(prog, n);
    });
    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 1, -1, -1, 1, 1, 1]), gl.STATIC_DRAW);
    gl.enableVertexAttribArray(0);
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
    this._glTex = gl.createTexture();
    this._glMap = gl.createTexture();
    this._glWm = gl.createTexture();
    return true;
  }
  _uploadGlTexture(gl) {
    const meta = __privateGet(this, _meta);
    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, this._glTex);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, false);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, __privateGet(this, _bitmap));
    gl.activeTexture(gl.TEXTURE1);
    gl.bindTexture(gl.TEXTURE_2D, this._glMap);
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
      gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, g, g, 0, gl.RGBA, gl.UNSIGNED_BYTE, data);
    }
    gl.activeTexture(gl.TEXTURE2);
    gl.bindTexture(gl.TEXTURE_2D, this._glWm);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    const wm = this.options.watermark;
    this._glWmOn = 0;
    if (wm) {
      const text = String((typeof wm === "string" ? wm : wm.text) || "").replace("{session}", sessionId().slice(0, 6));
      if (text) {
        const c = document.createElement("canvas");
        c.width = 1024;
        c.height = Math.max(64, Math.round(1024 * meta.origH / meta.origW));
        const ctx = c.getContext("2d");
        ctx.clearRect(0, 0, c.width, c.height);
        ctx.fillStyle = "#ffffff";
        ctx.globalAlpha = (typeof wm === "object" ? wm.opacity : void 0) ?? 0.16;
        const fs = Math.max(18, Math.round(Math.min(c.width, c.height) / 12));
        ctx.font = `700 ${fs}px system-ui,sans-serif`;
        ctx.textAlign = "center";
        ctx.translate(c.width / 2, c.height / 2);
        ctx.rotate(-Math.PI / 7);
        const diag = Math.hypot(c.width, c.height);
        for (let y = -diag / 2; y < diag / 2; y += fs * 4.2) ctx.fillText(text, 0, y);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, c);
        this._glWmOn = 1;
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
      if (this.canvas.width !== w || this.canvas.height !== h) {
        this.canvas.width = w;
        this.canvas.height = h;
      }
      gl.viewport(0, 0, w, h);
      gl.useProgram(this._glProg);
      const L = this._glLoc;
      const meta = __privateGet(this, _meta);
      gl.uniform1i(L.uTex, 0);
      gl.uniform1i(L.uMap, 1);
      gl.uniform1i(L.uWm, 2);
      gl.uniform1f(L.uGrid, meta.plan ? meta.plan.grid : 1);
      gl.uniform2f(L.uCrop, meta.origW / meta.padW, meta.origH / meta.padH);
      const srcRatio = meta.origW / meta.origH;
      const dstRatio = w / h;
      let sx = 1, sy = 1, ox = 0, oy = 0;
      if (this.options.fit === "cover") {
        if (srcRatio > dstRatio) {
          sx = dstRatio / srcRatio;
          ox = (1 - sx) / 2;
        } else {
          sy = srcRatio / dstRatio;
          oy = (1 - sy) / 2;
        }
      } else if (this.options.fit === "contain") {
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
      gl.uniform1f(L.uWmOn, this._glWmOn || 0);
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
    const g = this.options.guards;
    const relevant = kind === "blur" && g.blurOnBlur || kind === "hidden" && g.blurOnBlur || kind === "print" && g.print || kind === "devtools" && g.devtools;
    if (!relevant) return;
    if (on) __privateGet(this, _risk).add(kind);
    else __privateGet(this, _risk).delete(kind);
    this.wrap.classList.toggle("risk-on", __privateGet(this, _risk).size > 0);
  }
  _momentaryBlackout(ms, kind) {
    if (kind === "screenshot-key" && !this.options.guards.screenshotKeys) return;
    this.wrap.classList.add("blackout");
    if (this._attempt) this._attempt(kind);
    clearTimeout(__privateGet(this, _blackoutTimer));
    __privateSet(this, _blackoutTimer, setTimeout(() => this.wrap.classList.remove("blackout"), ms));
  }
  /* ---------------- public per-instance API ---------------- */
  get loaded() {
    return __privateGet(this, _loaded);
  }
  get element() {
    return this.host;
  }
  /** Test/debug hook — returns internals. Never enable in production pages. */
  _debug() {
    return { canvas: this.canvas, tiles: [...this.tilesEl.querySelectorAll("canvas")], wrap: this.wrap, meta: __privateGet(this, _meta) };
  }
  async reload(newSource) {
    if (newSource !== void 0) __privateSet(this, _source, newSource);
    __privateSet(this, _loaded, false);
    this.wrap.classList.add("loading");
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
    if (visibilityObserver) visibilityObserver.unobserve(this.host);
    if (this.canvas) {
      this.canvas.width = 0;
      this.canvas.height = 0;
    }
    if (__privateGet(this, _decoy)) {
      __privateGet(this, _decoy).width = 0;
      __privateSet(this, _decoy, null);
    }
    this.root.replaceChildren?.();
    delete this.host.__archx;
  }
};
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
  class ArchxImage extends HTMLElement {
    static get observedAttributes() {
      return ["src", "image-id", "mode", "watermark", "alt", "fit", "grid", "key", "on-extract"];
    }
    connectedCallback() {
      if (this._inst) return;
      this.style.display = this.style.display || "block";
      const inner = document.createElement("div");
      inner.style.width = "100%";
      inner.style.height = "100%";
      this.appendChild(inner);
      const id = this.getAttribute("image-id");
      const src = id ? { id } : this.getAttribute("src");
      this._inst = new ProtectedImage(inner, src, {
        mode: this.getAttribute("mode") || void 0,
        watermark: this.getAttribute("watermark") || void 0,
        alt: this.getAttribute("alt") || "",
        fit: this.getAttribute("fit") || void 0,
        grid: this.getAttribute("grid") ? Number(this.getAttribute("grid")) : void 0,
        key: this.getAttribute("key") || void 0,
        scrambled: this.hasAttribute("scrambled"),
        onExtract: this.getAttribute("on-extract") || void 0,
        tokenEndpoint: this.getAttribute("token-endpoint") || void 0
      });
      this.ready = this._inst.ready;
    }
    disconnectedCallback() {
      if (this._inst) {
        this._inst.destroy();
        this._inst = null;
      }
    }
    attributeChangedCallback(name, oldV, newV) {
      if (!this._inst || oldV === newV) return;
      if (name === "src" && newV) this._inst.reload(newV);
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
    return { ...globalConfig };
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
  _instances: instances,
  _sessionId: sessionId
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
  base64ToBytes,
  buildScramblePlan,
  bytesToBase64,
  decodeContainer,
  decryptPayload,
  index_default as default,
  encodeContainer,
  encryptPayload,
  generateKeyBase64,
  hashSeed,
  isArchxContainer,
  mulberry32,
  paddedSize,
  scramblePixels,
  tileRect
};
//# sourceMappingURL=archx.esm.js.map
