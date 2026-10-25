/**
 * Archnemix Image Protection ("Archx") — browser library.
 *
 *   Archx.load.image('#hero', 'https://cdn.example.com/photo.jpg', { mode: 'shield' })
 *   Archx.load.image(el, fileOrBlob)
 *   Archx.load.gallery('#grid', [...urls])
 *   <archx-image image-id="hero-1" mode="vault"></archx-image>
 *
 * Defence layers (combined, cheapest first):
 *  1. No <img> is ever created in the page — the picture is painted on a
 *     <canvas> inside a CLOSED shadow root. "Save image as", "Open image in
 *     new tab", drag-to-desktop, bulk-downloader extensions and DOM scrapers
 *     find nothing: no src URL exists anywhere in the DOM.
 *  2. Bytes arrive via fetch() + createImageBitmap(), never via an image
 *     load, so DevTools' Network "Img" filter stays empty and the URL is
 *     held only in JS closures / private fields.
 *  3. Poisoned read-back: canvas.toDataURL()/toBlob()/getImageData()/
 *     captureStream() on our canvases return a decoy — a black card, a
 *     heavily pixelated thumbnail, or a re-scrambled mosaic — instead of
 *     the picture. (Extensions that grab canvases get the decoy.)
 *  4. Vault mode renders with WebGL (preserveDrawingBuffer:false): even a
 *     prototype-bypass call HTMLCanvasElement.prototype.toDataURL.call(c)
 *     returns black, because the browser clears the drawing buffer after
 *     compositing. Tile un-scrambling happens in the fragment shader.
 *  5. Optional scrambled / AES-GCM-encrypted ".archx" delivery: what crosses
 *     the network is a shuffled mosaic or ciphertext, useless if captured.
 *  6. Resolution capping: the canvas backing store is only as large as the
 *     display box (×DPR, hard-capped). Even a perfect extraction can never
 *     yield more than the on-screen, watermarked, web-resolution copy.
 *  7. Baked-in visible + forensic watermarking, interaction guards
 *     (context-menu / drag / long-press / copy), blur-on-window-blur,
 *     print black-out, optional DevTools-open blur.
 *
 * Honest limit: pixels shown on a screen can always be photographed or
 * screenshotted at screen resolution. Archx makes bulk / one-click /
 * full-quality theft impractical and makes leaked copies traceable — it
 * cannot repeal the "analog hole". See docs/RESEARCH.md.
 */
import {
  buildScramblePlan, tileRect, paddedSize,
  isArchxContainer, decodeContainer, decryptPayload,
  hashSeed, mulberry32, DEFAULT_GRID,
} from './scramble.js';

export const VERSION = '1.0.0';

/* ================================================================== */
/* Global config + registries                                          */
/* ================================================================== */

const DEFAULTS = {
  mode: 'shield',               // 'lite' | 'shield' | 'vault'
  fit: 'cover',                 // 'cover' | 'contain' | 'fill'
  lazy: true,
  rootMargin: '500px',
  unloadOnExit: false,          // gallery mode turns this on for huge grids
  shadow: 'closed',             // 'closed' | 'open' | 'none'
  grid: DEFAULT_GRID,
  scrambled: false,             // source pixels are tile-scrambled
  key: null,                    // scramble seed and/or AES key (see docs)
  aesKey: null,                 // base64 AES key for encrypted .archx payloads
  tokenEndpoint: null,          // e.g. '/archx/token/'  (+ image id)
  onExtract: 'black',           // 'black' | 'lowres' | 'scrambled'
  splitCanvases: false,         // shield+: one canvas per tile (hero images)
  splitGrid: 3,
  maxBackingWidth: 1920,        // never paint a wider backing store than this
  dprCap: 2,
  watermark: null,              // string | { text, opacity, tile, corner }
  forensic: true,               // invisible per-session pixel noise (shield/vault)
  sessionId: null,              // defaults to a random per-page-view id
  brand: '© Protected · Archnemix',
  retries: 2,
  credentials: 'same-origin',
  guards: {
    contextMenu: true,
    drag: true,
    copy: true,
    longPress: true,
    print: true,
    blurOnBlur: true,           // blur while window unfocused (snipping tools)
    screenshotKeys: true,       // best-effort PrintScreen reaction
    devtools: false,            // opt-in: blur while DevTools appears open
  },
  onAttempt: null,              // (kind, instance) => void  — hook your logging
  onLoad: null,
  onError: null,
  onClick: null,
  alt: '',
};

let globalConfig = structuredCloneSafe(DEFAULTS);
const instances = new Set();
let pageSessionId = null;

function structuredCloneSafe(obj) {
  return JSON.parse(JSON.stringify(obj, (k, v) => (typeof v === 'function' ? undefined : v)));
}
function sessionId() {
  if (globalConfig.sessionId) return globalConfig.sessionId;
  if (!pageSessionId) {
    const a = new Uint8Array(8);
    crypto.getRandomValues(a);
    pageSessionId = [...a].map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  return pageSessionId;
}
function mergeOptions(opts = {}) {
  // Strip `undefined` values so e.g. an absent HTML attribute on
  // <archx-image> never clobbers a global config value with undefined.
  const clean = {};
  for (const [k, v] of Object.entries(opts)) if (v !== undefined) clean[k] = v;
  const merged = { ...globalConfig, ...clean };
  merged.guards = { ...globalConfig.guards };
  if (opts.guards) {
    for (const [k, v] of Object.entries(opts.guards)) if (v !== undefined) merged.guards[k] = v;
  }
  return merged;
}

/* ---------- shared concurrency limiter (hundreds of images, no jank) */
const limiter = {
  max: 6, active: 0, queue: [],
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
      if (this.active < this.max) job(); else this.queue.push(job);
    });
  },
};

/* ---------- decoded-bitmap LRU (scrambled pixels only, never clean DOM) */
const bitmapCache = new Map(); // cacheKey -> Promise<{bitmap,meta}>
const BITMAP_CACHE_MAX = 40;
function cachePut(key, promise) {
  if (bitmapCache.has(key)) bitmapCache.delete(key);
  bitmapCache.set(key, promise);
  while (bitmapCache.size > BITMAP_CACHE_MAX) {
    const oldest = bitmapCache.keys().next().value;
    bitmapCache.delete(oldest); // bitmap itself is closed by owners' refcount-lite
  }
}

/* ---------- shared observers */
let visibilityObserver = null;
function getVisibilityObserver() {
  if (!visibilityObserver) {
    visibilityObserver = new IntersectionObserver((entries) => {
      for (const e of entries) {
        const inst = e.target.__archx;
        if (inst) inst._onVisibility(e.isIntersecting);
      }
    }, { rootMargin: '500px' });
  }
  return visibilityObserver;
}

/* ---------- one-time global guards (screenshot keys, print, focus) */
let globalGuardsInstalled = false;
function installGlobalGuards() {
  if (globalGuardsInstalled || typeof window === 'undefined') return;
  globalGuardsInstalled = true;

  const blackoutAll = (ms, kind) => instances.forEach((i) => i._momentaryBlackout(ms, kind));

  window.addEventListener('keydown', (e) => {
    const shotKey = e.key === 'PrintScreen' || e.code === 'PrintScreen';
    const macShot = e.metaKey && e.shiftKey && ['3', '4', '5'].includes(e.key);
    const winSnip = e.metaKey && e.shiftKey && (e.key === 'S' || e.key === 's');
    if (shotKey || macShot || winSnip) {
      blackoutAll(900, 'screenshot-key');
      if (shotKey && navigator.clipboard?.writeText) {
        navigator.clipboard.writeText('').catch(() => {});
      }
    }
  }, true);

  window.addEventListener('blur', () => instances.forEach((i) => i._setRisk('blur', true)));
  window.addEventListener('focus', () => instances.forEach((i) => i._setRisk('blur', false)));
  document.addEventListener('visibilitychange', () => {
    instances.forEach((i) => i._setRisk('hidden', document.hidden));
  });
  if (window.matchMedia) {
    const mq = window.matchMedia('print');
    const onPrint = (m) => instances.forEach((i) => i._setRisk('print', m.matches));
    if (mq.addEventListener) mq.addEventListener('change', onPrint);
  }
  window.addEventListener('beforeprint', () => instances.forEach((i) => i._setRisk('print', true)));
  window.addEventListener('afterprint', () => instances.forEach((i) => i._setRisk('print', false)));
}

/* opt-in DevTools detector (size heuristic — see docs for caveats) */
let devtoolsTimer = null;
function ensureDevtoolsWatcher() {
  if (devtoolsTimer) return;
  devtoolsTimer = setInterval(() => {
    const open = (window.outerWidth - window.innerWidth > 170) ||
                 (window.outerHeight - window.innerHeight > 200);
    instances.forEach((i) => { if (i.options.guards.devtools) i._setRisk('devtools', open); });
  }, 1000);
}

/* WebGL context budget (browsers allow ~8–16; stay conservative) */
let glContextsInUse = 0;
const GL_CONTEXT_BUDGET = 8;

/* ================================================================== */
/* Small helpers                                                       */
/* ================================================================== */

const $ = (t) => (typeof t === 'string' ? document.querySelector(t) : t);

function fitRects(srcW, srcH, dstW, dstH, fit) {
  if (fit === 'fill') return { sx: 0, sy: 0, sw: srcW, sh: srcH, dx: 0, dy: 0, dw: dstW, dh: dstH };
  const srcRatio = srcW / srcH;
  const dstRatio = dstW / dstH;
  if (fit === 'contain') {
    let dw = dstW, dh = dstW / srcRatio;
    if (dh > dstH) { dh = dstH; dw = dstH * srcRatio; }
    return { sx: 0, sy: 0, sw: srcW, sh: srcH, dx: (dstW - dw) / 2, dy: (dstH - dh) / 2, dw, dh };
  }
  // cover: crop source
  let sw = srcW, sh = srcH;
  if (srcRatio > dstRatio) sw = srcH * dstRatio; else sh = srcW / dstRatio;
  return { sx: (srcW - sw) / 2, sy: (srcH - sh) / 2, sw, sh, dx: 0, dy: 0, dw: dstW, dh: dstH };
}

async function fetchWithRetries(url, options, retries) {
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, options);
      if (!res.ok) throw new Error('Archx fetch failed: HTTP ' + res.status);
      return res;
    } catch (err) {
      lastErr = err;
      if (attempt < retries) await new Promise((r) => setTimeout(r, 250 * (attempt + 1)));
    }
  }
  throw lastErr;
}

/** Un-scramble a bitmap onto a private offscreen canvas (capped size). */
function unscrambleToCanvas(bitmap, meta, targetW, targetH) {
  const canvas = document.createElement('canvas');
  canvas.width = Math.max(1, targetW);
  canvas.height = Math.max(1, targetH);
  const ctx = canvas.getContext('2d');
  if (!meta.plan) { // not scrambled — single draw
    ctx.drawImage(bitmap, 0, 0, targetW, targetH);
    return canvas;
  }
  const { plan, origW, origH, padW, padH } = meta;
  const twSrc = bitmap.width / plan.grid;
  const thSrc = bitmap.height / plan.grid;
  // Reassemble on an intermediate canvas whose tile size is an INTEGER number
  // of pixels. Fractional tile origins make browsers paint semi-transparent
  // edge coverage and blend pixels from neighbouring *scrambled* tiles,
  // which shows up as a visible grid of seams. Integer tiles + a final clean
  // smoothing pass (where neighbours are once again true neighbours) avoid it.
  const tileW = Math.max(1, Math.round((targetW * (padW / origW)) / plan.grid));
  const tileH = Math.max(1, Math.round((targetH * (padH / origH)) / plan.grid));
  const padded = document.createElement('canvas');
  padded.width = tileW * plan.grid;
  padded.height = tileH * plan.grid;
  const pctx = padded.getContext('2d');
  const exactScale = Math.abs(tileW - twSrc) < 0.01 && Math.abs(tileH - thSrc) < 0.01;
  pctx.imageSmoothingEnabled = !exactScale;
  // Half-pixel source inset when scaling: prevents smoothing from sampling
  // the unrelated tile next door in the scrambled bitmap. At exact scale we
  // copy pixels 1:1, so no inset (and no geometric shift) is needed.
  const insetX = exactScale ? 0 : Math.min(0.5, twSrc * 0.01);
  const insetY = exactScale ? 0 : Math.min(0.5, thSrc * 0.01);
  for (let orig = 0; orig < plan.count; orig++) {
    const scrambledPos = plan.inverse[orig];
    const s = tileRect(scrambledPos, plan.grid, twSrc, thSrc);
    const dx = (orig % plan.grid) * tileW;
    const dy = Math.floor(orig / plan.grid) * tileH;
    const { fx, fy } = plan.flips[scrambledPos];
    pctx.save();
    pctx.translate(dx + (fx ? tileW : 0), dy + (fy ? tileH : 0));
    pctx.scale(fx ? -1 : 1, fy ? -1 : 1);
    pctx.drawImage(bitmap,
      s.x + insetX, s.y + insetY, s.w - insetX * 2, s.h - insetY * 2,
      0, 0, tileW, tileH);
    pctx.restore();
  }
  // Crop away the padding strip and scale to the exact requested size.
  ctx.imageSmoothingEnabled = true;
  ctx.imageSmoothingQuality = 'high';
  ctx.drawImage(padded,
    0, 0, padded.width * (origW / padW), padded.height * (origH / padH),
    0, 0, targetW, targetH);
  padded.width = 0; padded.height = 0;
  return canvas;
}

const SHADOW_CSS = `
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

/* ================================================================== */
/* ProtectedImage                                                      */
/* ================================================================== */

export class ProtectedImage {
  #source; #bitmap = null; #meta = null; #abort = new AbortController();
  #decoy = null; #gl = null; #raf = 0; #loaded = false; #destroyed = false;
  #risk = new Set(); #blackoutTimer = 0; #resizeObs = null; #realCtx = null;

  constructor(target, source, options = {}) {
    this.options = mergeOptions(options);
    this.#source = source;
    const host = $(target);
    if (!host) throw new Error('Archx: target element not found: ' + target);
    this.host = host;
    host.classList.add('archx-host');
    host.__archx = this;
    if (this.options.alt) {
      host.setAttribute('role', 'img');
      host.setAttribute('aria-label', this.options.alt);
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
    if (o.shadow === 'none') {
      root = this.host;
    } else {
      try {
        root = this.host.attachShadow({ mode: o.shadow === 'open' ? 'open' : 'closed' });
      } catch { root = this.host; }
    }
    this.root = root;
    const doc = this.host.ownerDocument;
    const style = doc.createElement('style');
    style.textContent = SHADOW_CSS;
    const wrap = doc.createElement('div');
    wrap.className = 'wrap loading' + (o.showBadge ? ' show-badge' : '');
    wrap.innerHTML = `
      <div class="tiles" hidden></div>
      <canvas class="main" aria-hidden="true"></canvas>
      <div class="badge">ARCHX&nbsp;PROTECTED</div>
      <div class="shield"></div>
      <div class="risk"></div>
      <div class="err"><span>⚠<br>Protected image unavailable</span></div>`;
    root.append(style, wrap);
    this.wrap = wrap;
    this.canvas = wrap.querySelector('canvas.main');
    this.tilesEl = wrap.querySelector('.tiles');
    this.shieldEl = wrap.querySelector('.shield');
    if (o.aspectRatio) this.host.style.aspectRatio = String(o.aspectRatio);
    if (o.width) this.host.style.width = typeof o.width === 'number' ? o.width + 'px' : o.width;
    if (o.height) this.host.style.height = typeof o.height === 'number' ? o.height + 'px' : o.height;
  }

  _attachGuards() {
    const o = this.options;
    const sig = { signal: this.#abort.signal };
    const attempt = (kind) => {
      try { o.onAttempt && o.onAttempt(kind, this); } catch {}
      this.host.dispatchEvent(new CustomEvent('archx-attempt', { detail: { kind }, bubbles: true }));
    };
    this._attempt = attempt;

    if (o.guards.contextMenu) {
      this.wrap.addEventListener('contextmenu', (e) => { e.preventDefault(); e.stopPropagation(); attempt('contextmenu'); }, sig);
    }
    if (o.guards.drag) {
      this.wrap.addEventListener('dragstart', (e) => { e.preventDefault(); attempt('drag'); }, sig);
    }
    if (o.guards.copy) {
      this.wrap.addEventListener('copy', (e) => { e.preventDefault(); attempt('copy'); }, sig);
      this.wrap.addEventListener('selectstart', (e) => e.preventDefault(), sig);
    }
    if (o.guards.longPress) {
      let timer = 0;
      this.wrap.addEventListener('pointerdown', (e) => {
        if (e.pointerType !== 'touch') return;
        timer = setTimeout(() => { attempt('longpress'); this._momentaryBlackout(700, 'longpress'); }, 450);
      }, sig);
      const clear = () => clearTimeout(timer);
      this.wrap.addEventListener('pointerup', clear, sig);
      this.wrap.addEventListener('pointercancel', clear, sig);
      this.wrap.addEventListener('pointermove', clear, sig);
    }
    // Forward genuine clicks so galleries/lightboxes keep working.
    this.shieldEl.addEventListener('click', (e) => {
      if (o.onClick) { try { o.onClick(e, this); } catch {} }
      if (!o.swallowClick) {
        this.host.dispatchEvent(new MouseEvent('click', { bubbles: true, clientX: e.clientX, clientY: e.clientY }));
      }
    }, sig);
  }

  _onVisibility(visible) {
    this._visible = visible;
    if (visible && !this.#loaded && !this._loading) this._load();
    if (visible && this.#loaded && this._unloaded) this._load();
    if (!visible && this.options.unloadOnExit && this.#loaded) this._unloadPixels();
    if (this.#gl) visible ? this._startGlLoop() : this._stopGlLoop();
  }

  async _init() {
    // Resize handling (debounced redraw from cached bitmap — no refetch)
    let resizeTimer = 0;
    this.#resizeObs = new ResizeObserver(() => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => { if (this.#bitmap) this._render(); }, 90);
    });
    this.#resizeObs.observe(this.host);

    if (this.options.lazy && 'IntersectionObserver' in window) {
      getVisibilityObserver().observe(this.host);
      // _load fires from observer; also kick if already on screen pre-observe
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
    let src = this.#source;
    let extra = {};
    // Token flow: {id} or string id with tokenEndpoint
    if (src && typeof src === 'object' && !(src instanceof Blob) &&
        !(src instanceof ArrayBuffer) && !ArrayBuffer.isView(src) && src.id) {
      const endpoint = src.tokenEndpoint || o.tokenEndpoint;
      if (!endpoint) throw new Error('Archx: tokenEndpoint required for {id} sources');
      const w = Math.min(o.maxBackingWidth, Math.ceil((this.host.clientWidth || 800) * Math.min(devicePixelRatio || 1, o.dprCap)));
      const res = await fetchWithRetries(endpoint + encodeURIComponent(src.id) + '?w=' + w,
        { credentials: o.credentials, signal: this.#abort.signal }, o.retries);
      const token = await res.json();
      extra = token; // {url, key?, aesKey?, grid?}
      src = token.url;
    }
    if (typeof src === 'string') {
      const cacheKey = src + '|' + (extra.key || o.key || '');
      if (bitmapCache.has(cacheKey)) return { ...(await bitmapCache.get(cacheKey)), extra };
      const promise = (async () => {
        const res = await fetchWithRetries(src,
          { credentials: o.credentials, cache: 'no-store', signal: this.#abort.signal }, o.retries);
        const buf = new Uint8Array(await res.arrayBuffer());
        return this._bytesToBitmap(buf, extra);
      })();
      cachePut(cacheKey, promise);
      return { ...(await promise), extra };
    }
    if (src instanceof Blob) return { ...(await this._bytesToBitmap(new Uint8Array(await src.arrayBuffer()), extra)), extra };
    if (src instanceof ArrayBuffer || ArrayBuffer.isView(src)) {
      const bytes = ArrayBuffer.isView(src)
        ? new Uint8Array(src.buffer, src.byteOffset, src.byteLength)
        : new Uint8Array(src);
      return { ...(await this._bytesToBitmap(bytes, extra)), extra };
    }
    throw new Error('Archx: unsupported source type');
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
        if (!aesKey) throw new Error('Archx: encrypted .archx payload needs aesKey');
        payload = await decryptPayload(payload, aesKey, header.iv);
      }
    }
    const scrambled = header ? !!header.scrambled : !!o.scrambled;
    const grid = header?.grid || extra.grid || o.grid;
    const key = extra.key || o.key || '';
    const blob = new Blob([payload], { type: header?.mime || 'image/webp' });
    let bitmap;
    try {
      bitmap = await createImageBitmap(blob);
    } catch {
      bitmap = await this._bitmapViaImage(blob); // Safari-older fallback
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
      const img = new Image(); // detached, never inserted into the document
      img.onload = () => { URL.revokeObjectURL(url); resolve(img); };
      img.onerror = (e) => { URL.revokeObjectURL(url); reject(e); };
      img.src = url;
    });
  }

  async _load() {
    if (this._loading || this.#destroyed) return;
    this._loading = true;
    try {
      const { bitmap, meta } = await limiter.run(() => this._resolveBytes());
      if (this.#destroyed) return;
      this.#bitmap = bitmap;
      this.#meta = meta;
      this.#decoy = null; // regenerate poison for the (possibly new) source
      if (!this.options.aspectRatio && !this.options.height) {
        this.host.style.aspectRatio = meta.origW + ' / ' + meta.origH;
      }
      this._render();
      this.#loaded = true;
      this._unloaded = false;
      this.wrap.classList.remove('loading', 'error');
      this.host.dispatchEvent(new CustomEvent('archx-load', { bubbles: true }));
      try { this.options.onLoad && this.options.onLoad(this); } catch {}
    } catch (err) {
      if (this.#destroyed) return;
      this.wrap.classList.remove('loading');
      this.wrap.classList.add('error');
      this.host.dispatchEvent(new CustomEvent('archx-error', { detail: { error: err }, bubbles: true }));
      try { this.options.onError && this.options.onError(err, this); } catch {}
    } finally {
      this._loading = false;
    }
  }

  _unloadPixels() {
    // Free backing stores for off-screen gallery items; bytes stay cached.
    if (this.canvas) { this.canvas.width = 0; this.canvas.height = 0; }
    this._unloaded = true;
  }

  /* ---------------- rendering ---------------- */
  _backingSize() {
    const o = this.options;
    const rect = this.host.getBoundingClientRect();
    const cssW = Math.max(1, Math.round(rect.width || this.host.clientWidth || 320));
    const cssH = Math.max(1, Math.round(rect.height || this.host.clientHeight || Math.round(cssW * (this.#meta.origH / this.#meta.origW)) || 240));
    let scale = Math.min(window.devicePixelRatio || 1, o.dprCap);
    if (cssW * scale > o.maxBackingWidth) scale = o.maxBackingWidth / cssW;
    // Never upscale beyond the (already web-resolution) source by much.
    const maxScaleBySource = (this.#meta.origW * 1.0) / cssW;
    const w = Math.max(1, Math.round(cssW * Math.min(scale, Math.max(maxScaleBySource, 0.25))));
    const h = Math.max(1, Math.round(cssH * (w / cssW)));
    return { w, h, cssW, cssH };
  }

  _render() {
    if (!this.#bitmap || this.#destroyed) return;
    const mode = this.options.mode;
    if (mode === 'vault') {
      if (this._tryRenderWebGL()) return;
      // fall through to shield rendering on any GL problem / budget hit
    }
    if (this.options.splitCanvases && mode !== 'lite') this._renderSplit();
    else this._render2d();
  }

  /** Private, capped, un-scrambled working canvas (wiped after use). */
  _workingCanvas(w, h) {
    // Un-scramble at source aspect, capped to backing size, then fit-crop.
    const meta = this.#meta;
    const fit = fitRects(meta.origW, meta.origH, w, h, this.options.fit);
    const fullW = Math.max(1, Math.round((meta.origW / fit.sw) * fit.dw));
    const fullH = Math.max(1, Math.round((meta.origH / fit.sh) * fit.dh));
    return { full: unscrambleToCanvas(this.#bitmap, meta, fullW, fullH), fit, fullW, fullH };
  }

  _render2d() {
    const { w, h } = this._backingSize();
    const canvas = this.canvas;
    this.tilesEl.hidden = true;
    canvas.hidden = false;
    canvas.width = w; canvas.height = h;
    const ctx = canvas.getContext('2d', { alpha: false });
    this.#realCtx = ctx;
    const { full, fit } = this._workingCanvas(w, h);
    ctx.fillStyle = '#000';
    ctx.fillRect(0, 0, w, h);
    ctx.drawImage(full, fit.sx * (full.width / this.#meta.origW), fit.sy * (full.height / this.#meta.origH),
      fit.sw * (full.width / this.#meta.origW), fit.sh * (full.height / this.#meta.origH),
      fit.dx, fit.dy, fit.dw, fit.dh);
    this._bakeOverlays(ctx, w, h);
    this.#decoy = this._makeDecoy(full, w, h);
    full.width = 0; full.height = 0; // wipe the clean working copy immediately
    this._poison(canvas, ctx);
  }

  _renderSplit() {
    const { w, h } = this._backingSize();
    const g = Math.max(2, Math.min(6, this.options.splitGrid | 0));
    const { full, fit } = this._workingCanvas(w, h);
    // Compose final image privately once (with watermark), then slice it.
    const composed = document.createElement('canvas');
    composed.width = w; composed.height = h;
    const cctx = composed.getContext('2d');
    cctx.fillStyle = '#000'; cctx.fillRect(0, 0, w, h);
    cctx.drawImage(full, fit.sx * (full.width / this.#meta.origW), fit.sy * (full.height / this.#meta.origH),
      fit.sw * (full.width / this.#meta.origW), fit.sh * (full.height / this.#meta.origH),
      fit.dx, fit.dy, fit.dw, fit.dh);
    this._bakeOverlays(cctx, w, h);
    this.canvas.hidden = true;
    this.tilesEl.hidden = false;
    this.tilesEl.style.gridTemplateColumns = `repeat(${g},1fr)`;
    this.tilesEl.style.gridTemplateRows = `repeat(${g},1fr)`;
    this.tilesEl.replaceChildren();
    const tw = Math.ceil(w / g), th = Math.ceil(h / g);
    for (let i = 0; i < g * g; i++) {
      const c = document.createElement('canvas');
      c.width = tw; c.height = th;
      const tctx = c.getContext('2d', { alpha: false });
      tctx.drawImage(composed, (i % g) * tw, Math.floor(i / g) * th, tw, th, 0, 0, tw, th);
      this.tilesEl.appendChild(c);
      this.#decoy = this.#decoy || this._makeDecoy(full, w, h);
      this._poison(c, tctx);
    }
    composed.width = 0;
    full.width = 0; full.height = 0;
  }

  _bakeOverlays(ctx, w, h) {
    const o = this.options;
    const wm = o.watermark;
    if (wm) {
      const cfg = typeof wm === 'string' ? { text: wm } : wm;
      const text = String(cfg.text || '').replace('{session}', sessionId().slice(0, 6));
      if (text) {
        ctx.save();
        ctx.fillStyle = cfg.color || '#ffffff';
        if (cfg.tile !== false) {
          ctx.globalAlpha = cfg.opacity ?? 0.16;
          const fs = Math.max(12, Math.round(Math.min(w, h) / 14));
          ctx.font = `700 ${fs}px system-ui, sans-serif`;
          ctx.translate(w / 2, h / 2);
          ctx.rotate(-Math.PI / 7);
          ctx.textAlign = 'center';
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
          ctx.textAlign = 'right';
          ctx.shadowColor = 'rgba(0,0,0,.8)'; ctx.shadowBlur = 4;
          ctx.fillText(text, w - 10, h - 10);
        }
        ctx.restore();
      }
    }
    if (o.forensic && o.mode !== 'lite') {
      // Deterministic sub-visible noise: screenshots carry a session trace.
      const rand = mulberry32(hashSeed(sessionId() + '|' + (typeof this.#source === 'string' ? this.#source : 'blob')));
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
    const decoy = document.createElement('canvas');
    const ctx = decoy.getContext('2d');
    if (kind === 'lowres') {
      const tinyW = 72;
      const tinyH = Math.max(1, Math.round((h / w) * tinyW));
      const tiny = document.createElement('canvas');
      tiny.width = tinyW; tiny.height = tinyH;
      tiny.getContext('2d').drawImage(cleanCanvas, 0, 0, tinyW, tinyH);
      decoy.width = w; decoy.height = h;
      ctx.imageSmoothingEnabled = false;
      ctx.drawImage(tiny, 0, 0, w, h); // blocky pixelated upscale
      tiny.width = 0;
      ctx.save();
      ctx.globalAlpha = 0.5; ctx.fillStyle = '#fff';
      ctx.font = `700 ${Math.max(14, w / 18)}px system-ui,sans-serif`;
      ctx.textAlign = 'center'; ctx.translate(w / 2, h / 2); ctx.rotate(-Math.PI / 8);
      ctx.fillText(String((typeof o.watermark === 'string' ? o.watermark : o.watermark?.text) || o.brand), 0, 0);
      ctx.restore();
      return decoy;
    }
    if (kind === 'scrambled') {
      decoy.width = w; decoy.height = h;
      const g = 8;
      const plan = buildScramblePlan(g, 'decoy-' + sessionId());
      const tw = cleanCanvas.width / g, th = cleanCanvas.height / g;
      const dw = w / g, dh = h / g;
      for (let dest = 0; dest < plan.count; dest++) {
        const source = plan.order[dest];
        ctx.drawImage(cleanCanvas, (source % g) * tw, Math.floor(source / g) * th, tw, th,
          (dest % g) * dw, Math.floor(dest / g) * dh, dw + 1, dh + 1);
      }
      return decoy;
    }
    // black (default)
    decoy.width = Math.max(320, Math.min(w, 800));
    decoy.height = Math.max(200, Math.round(decoy.width * (h / Math.max(w, 1))));
    ctx.fillStyle = '#05070c'; ctx.fillRect(0, 0, decoy.width, decoy.height);
    ctx.fillStyle = '#e8ecf4'; ctx.textAlign = 'center';
    ctx.font = `700 ${Math.max(16, decoy.width / 16)}px system-ui,sans-serif`;
    ctx.fillText('PROTECTED IMAGE', decoy.width / 2, decoy.height / 2 - 8);
    ctx.font = `500 ${Math.max(11, decoy.width / 34)}px system-ui,sans-serif`;
    ctx.fillStyle = '#8b94a7';
    ctx.fillText(String((typeof o.watermark === 'string' ? o.watermark : o.watermark?.text) || o.brand),
      decoy.width / 2, decoy.height / 2 + Math.max(20, decoy.width / 22));
    ctx.fillText('This image is displayed with Archnemix Image Protection.', decoy.width / 2, decoy.height / 2 + Math.max(42, decoy.width / 13));
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
    const decoy = () => this.#decoy;
    const realToDataURL = HTMLCanvasElement.prototype.toDataURL;
    const realToBlob = HTMLCanvasElement.prototype.toBlob;
    const self = this;
    const define = (name, fn) => {
      try {
        Object.defineProperty(canvas, name, { value: fn, writable: false, configurable: false });
      } catch { try { canvas[name] = fn; } catch {} }
    };
    define('toDataURL', function (type, quality) {
      self._attempt && self._attempt('extract-dataurl');
      const d = decoy();
      return d ? realToDataURL.call(d, type, quality) : 'data:,';
    });
    define('toBlob', function (cb, type, quality) {
      self._attempt && self._attempt('extract-blob');
      const d = decoy();
      if (d) realToBlob.call(d, cb, type, quality);
      else if (cb) cb(new Blob([], { type: type || 'image/png' }));
    });
    if ('captureStream' in canvas) {
      define('captureStream', function () {
        self._attempt && self._attempt('extract-stream');
        const d = decoy();
        if (d && d.captureStream) return d.captureStream(1);
        throw new DOMException('Protected canvas', 'SecurityError');
      });
    }
    if (ctx && ctx.getImageData) {
      const poisonedGet = function (sx, sy, sw, sh) {
        self._attempt && self._attempt('extract-pixels');
        const w = Math.max(1, Math.abs(sw | 0)), h = Math.max(1, Math.abs(sh | 0));
        const data = new Uint8ClampedArray(w * h * 4);
        for (let i = 3; i < data.length; i += 4) data[i] = 255; // opaque black
        return new ImageData(data, w, h);
      };
      try { Object.defineProperty(ctx, 'getImageData', { value: poisonedGet, writable: false, configurable: false }); }
      catch { try { ctx.getImageData = poisonedGet; } catch {} }
    }
  }

  /* ---------------- WebGL vault ---------------- */
  _tryRenderWebGL() {
    if (glContextsInUse >= GL_CONTEXT_BUDGET && !this.#gl) return false;
    const canvas = this.canvas;
    this.tilesEl.hidden = true;
    canvas.hidden = false;
    let gl = this.#gl;
    if (!gl) {
      gl = canvas.getContext('webgl2', { preserveDrawingBuffer: false, antialias: false, alpha: false, powerPreference: 'low-power' });
      if (!gl) return false;
      this.#gl = gl;
      glContextsInUse++;
      canvas.addEventListener('webglcontextlost', (e) => {
        e.preventDefault();
        this.#gl = null; glContextsInUse = Math.max(0, glContextsInUse - 1);
        this._render2d();
      }, { signal: this.#abort.signal });
      if (!this._initGl(gl)) { this.#gl = null; glContextsInUse--; return false; }
    }
    this._uploadGlTexture(gl);
    this._startGlLoop();
    // Decoy for any instance-level grabbers (prototype calls return black anyway)
    if (!this.#decoy) {
      const { full } = this._workingCanvas(320, Math.max(1, Math.round(320 * this.#meta.origH / this.#meta.origW)));
      this.#decoy = this._makeDecoy(full, full.width, full.height);
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
      gl.shaderSource(s, srcText); gl.compileShader(s);
      if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) return null;
      return s;
    };
    const v = compile(gl.VERTEX_SHADER, vs);
    const f = compile(gl.FRAGMENT_SHADER, fs);
    if (!v || !f) return false;
    const prog = gl.createProgram();
    gl.attachShader(prog, v); gl.attachShader(prog, f); gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) return false;
    gl.useProgram(prog);
    this._glProg = prog;
    this._glLoc = {};
    ['uTex','uMap','uWm','uGrid','uCrop','uFitScale','uFitOffset','uScrambled','uSeed','uWmOn']
      .forEach((n) => { this._glLoc[n] = gl.getUniformLocation(prog, n); });
    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1,-1, 1,-1, -1,1, 1,1]), gl.STATIC_DRAW);
    gl.enableVertexAttribArray(0);
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
    this._glTex = gl.createTexture();
    this._glMap = gl.createTexture();
    this._glWm = gl.createTexture();
    return true;
  }

  _uploadGlTexture(gl) {
    const meta = this.#meta;
    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, this._glTex);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, false);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, this.#bitmap);
    // Tile map: for each ORIGINAL tile -> scrambled source tile + flips
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
    // Watermark texture rendered once on a 2D canvas
    gl.activeTexture(gl.TEXTURE2);
    gl.bindTexture(gl.TEXTURE_2D, this._glWm);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    const wm = this.options.watermark;
    this._glWmOn = 0;
    if (wm) {
      const text = String((typeof wm === 'string' ? wm : wm.text) || '').replace('{session}', sessionId().slice(0, 6));
      if (text) {
        const c = document.createElement('canvas');
        c.width = 1024; c.height = Math.max(64, Math.round(1024 * meta.origH / meta.origW));
        const ctx = c.getContext('2d');
        ctx.clearRect(0, 0, c.width, c.height);
        ctx.fillStyle = '#ffffff';
        ctx.globalAlpha = (typeof wm === 'object' ? wm.opacity : undefined) ?? 0.16;
        const fs = Math.max(18, Math.round(Math.min(c.width, c.height) / 12));
        ctx.font = `700 ${fs}px system-ui,sans-serif`;
        ctx.textAlign = 'center';
        ctx.translate(c.width / 2, c.height / 2); ctx.rotate(-Math.PI / 7);
        const diag = Math.hypot(c.width, c.height);
        for (let y = -diag / 2; y < diag / 2; y += fs * 4.2) ctx.fillText(text, 0, y);
        gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, c);
        this._glWmOn = 1;
      }
    }
  }

  _startGlLoop() {
    if (this.#raf || !this.#gl) return;
    const gl = this.#gl;
    const draw = () => {
      this.#raf = requestAnimationFrame(draw);
      if (this.#destroyed || !this.#gl) return;
      const { w, h } = this._backingSize();
      if (this.canvas.width !== w || this.canvas.height !== h) {
        this.canvas.width = w; this.canvas.height = h;
      }
      gl.viewport(0, 0, w, h);
      gl.useProgram(this._glProg);
      const L = this._glLoc;
      const meta = this.#meta;
      gl.uniform1i(L.uTex, 0); gl.uniform1i(L.uMap, 1); gl.uniform1i(L.uWm, 2);
      gl.uniform1f(L.uGrid, meta.plan ? meta.plan.grid : 1);
      gl.uniform2f(L.uCrop, meta.origW / meta.padW, meta.origH / meta.padH);
      // fit
      const srcRatio = meta.origW / meta.origH;
      const dstRatio = w / h;
      let sx = 1, sy = 1, ox = 0, oy = 0;
      if (this.options.fit === 'cover') {
        if (srcRatio > dstRatio) { sx = dstRatio / srcRatio; ox = (1 - sx) / 2; }
        else { sy = srcRatio / dstRatio; oy = (1 - sy) / 2; }
      } else if (this.options.fit === 'contain') {
        if (srcRatio > dstRatio) { sy = srcRatio / dstRatio; oy = -(sy - 1) / 2; sy = 1 / sy; oy = (1 - sy) / 2; /* letterbox via scale>range guarded in shader */ }
        // For contain, invert: scale uv beyond [0,1] and let shader black-bar it
        if (srcRatio > dstRatio) { const s = srcRatio / dstRatio; sy = s; oy = -(s - 1) / 2; sx = 1; ox = 0; }
        else { const s = dstRatio / srcRatio; sx = s; ox = -(s - 1) / 2; }
      }
      gl.uniform2f(L.uFitScale, sx, sy);
      gl.uniform2f(L.uFitOffset, ox, oy);
      gl.uniform1f(L.uScrambled, meta.plan ? 1 : 0);
      gl.uniform1f(L.uSeed, (hashSeed(sessionId()) % 1000) / 37.0);
      gl.uniform1f(L.uWmOn, this._glWmOn || 0);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
    };
    this.#raf = requestAnimationFrame(draw);
  }
  _stopGlLoop() {
    if (this.#raf) cancelAnimationFrame(this.#raf);
    this.#raf = 0;
  }

  /* ---------------- risk reactions ---------------- */
  _setRisk(kind, on) {
    const g = this.options.guards;
    const relevant = (kind === 'blur' && g.blurOnBlur) || (kind === 'hidden' && g.blurOnBlur) ||
      (kind === 'print' && g.print) || (kind === 'devtools' && g.devtools);
    if (!relevant) return;
    if (on) this.#risk.add(kind); else this.#risk.delete(kind);
    this.wrap.classList.toggle('risk-on', this.#risk.size > 0);
  }
  _momentaryBlackout(ms, kind) {
    if (kind === 'screenshot-key' && !this.options.guards.screenshotKeys) return;
    this.wrap.classList.add('blackout');
    if (this._attempt) this._attempt(kind);
    clearTimeout(this.#blackoutTimer);
    this.#blackoutTimer = setTimeout(() => this.wrap.classList.remove('blackout'), ms);
  }

  /* ---------------- public per-instance API ---------------- */
  get loaded() { return this.#loaded; }
  get element() { return this.host; }
  /** Test/debug hook — returns internals. Never enable in production pages. */
  _debug() {
    return { canvas: this.canvas, tiles: [...this.tilesEl.querySelectorAll('canvas')], wrap: this.wrap, meta: this.#meta };
  }
  async reload(newSource) {
    if (newSource !== undefined) this.#source = newSource;
    this.#loaded = false;
    this.wrap.classList.add('loading');
    await this._load();
    return this;
  }
  destroy() {
    this.#destroyed = true;
    instances.delete(this);
    this.#abort.abort();
    this._stopGlLoop();
    if (this.#gl) {
      try { this.#gl.getExtension('WEBGL_lose_context')?.loseContext(); } catch {}
      glContextsInUse = Math.max(0, glContextsInUse - 1);
      this.#gl = null;
    }
    if (this.#resizeObs) this.#resizeObs.disconnect();
    if (visibilityObserver) visibilityObserver.unobserve(this.host);
    if (this.canvas) { this.canvas.width = 0; this.canvas.height = 0; }
    if (this.#decoy) { this.#decoy.width = 0; this.#decoy = null; }
    this.root.replaceChildren?.();
    delete this.host.__archx;
  }
}

/* ================================================================== */
/* Public API: Archx.load.image(...)                                   */
/* ================================================================== */

function loadImage(target, source, options) {
  const inst = new ProtectedImage(target, source, options);
  // Return the instance immediately (sync handle) AND make it awaitable
  // via inst.ready. Most callers can fire-and-forget.
  return inst;
}

function loadGallery(container, items, options = {}) {
  const host = $(container);
  if (!host) throw new Error('Archx: gallery container not found');
  const galleryDefaults = { mode: 'lite', unloadOnExit: true };
  const made = items.map((item) => {
    const cell = document.createElement('div');
    cell.className = options.itemClass || 'archx-gallery-item';
    host.appendChild(cell);
    const isObj = item && typeof item === 'object' && ('src' in item || 'id' in item);
    const src = isObj && 'src' in item ? item.src : item;
    const per = isObj ? { alt: item.alt || '', ...(item.options || {}) } : {};
    return new ProtectedImage(cell, src, { ...galleryDefaults, ...options, ...per });
  });
  return { instances: made, ready: Promise.allSettled(made.map((i) => i.ready)) };
}

/** Replace existing <img data-protect> (or a selector) with protected views. */
function protectAll(selectorOrNodes = 'img[data-protect], [data-archx-src]', options = {}) {
  const nodes = typeof selectorOrNodes === 'string'
    ? [...document.querySelectorAll(selectorOrNodes)]
    : [...selectorOrNodes];
  return nodes.map((node) => {
    const src = node.dataset.archxSrc || node.currentSrc || node.getAttribute('src');
    const host = document.createElement('div');
    host.className = node.className || '';
    if (node.getAttribute('style')) host.setAttribute('style', node.getAttribute('style'));
    const w = node.getAttribute('width'), h = node.getAttribute('height');
    if (w && h) host.style.aspectRatio = w + ' / ' + h;
    node.replaceWith(host);
    return new ProtectedImage(host, src, { alt: node.getAttribute('alt') || '', ...options });
  });
}

/* Custom element: <archx-image src=... | image-id=... mode=... > */
function defineElement() {
  if (typeof customElements === 'undefined' || customElements.get('archx-image')) return;
  class ArchxImage extends HTMLElement {
    static get observedAttributes() { return ['src', 'image-id', 'mode', 'watermark', 'alt', 'fit', 'grid', 'key', 'on-extract']; }
    connectedCallback() {
      if (this._inst) return;
      this.style.display = this.style.display || 'block';
      const inner = document.createElement('div');
      inner.style.width = '100%'; inner.style.height = '100%';
      this.appendChild(inner);
      const id = this.getAttribute('image-id');
      const src = id ? { id } : this.getAttribute('src');
      this._inst = new ProtectedImage(inner, src, {
        mode: this.getAttribute('mode') || undefined,
        watermark: this.getAttribute('watermark') || undefined,
        alt: this.getAttribute('alt') || '',
        fit: this.getAttribute('fit') || undefined,
        grid: this.getAttribute('grid') ? Number(this.getAttribute('grid')) : undefined,
        key: this.getAttribute('key') || undefined,
        scrambled: this.hasAttribute('scrambled'),
        onExtract: this.getAttribute('on-extract') || undefined,
        tokenEndpoint: this.getAttribute('token-endpoint') || undefined,
      });
      this.ready = this._inst.ready;
    }
    disconnectedCallback() {
      if (this._inst) { this._inst.destroy(); this._inst = null; }
    }
    attributeChangedCallback(name, oldV, newV) {
      if (!this._inst || oldV === newV) return;
      if (name === 'src' && newV) this._inst.reload(newV);
    }
  }
  customElements.define('archx-image', ArchxImage);
}

const Archx = {
  version: VERSION,
  ProtectedImage,
  config(partial = {}) {
    const clean = {};
    for (const [k, v] of Object.entries(partial)) if (v !== undefined) clean[k] = v;
    globalConfig = { ...globalConfig, ...clean, guards: { ...globalConfig.guards, ...(partial.guards || {}) } };
    return { ...globalConfig };
  },
  load: {
    image: loadImage,
    gallery: loadGallery,
  },
  // Friendly aliases
  image: loadImage,
  gallery: loadGallery,
  protectAll,
  defineElement,
  _instances: instances,
  _sessionId: sessionId,
};

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', defineElement, { once: true });
  } else defineElement();
}

export default Archx;
