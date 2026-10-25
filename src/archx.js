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

export const VERSION = '1.2.0';

/* ================================================================== */
/* Pristine native references (captured before any page script runs)    */
/* ================================================================== */
/*
 * A determined attacker doesn't use the console — they inject a script that
 * monkey-patches fetch / createImageBitmap / drawImage BEFORE the library
 * loads, then simply records the bytes as they flow past. We capture the
 * native functions at module-evaluation time and call *those* (so hooks
 * installed later are bypassed), and we audit for hooks that were already
 * in place (non-native function bodies) so fortress mode can fail closed.
 * A pre-installed hook that also forges Function.prototype.toString can
 * still evade detection — nothing in-page can fully solve that — but the
 * cheap 95% of hooking (userscripts, naive extensions) is caught.
 */
const NATIVES = (() => {
  const g = globalThis;
  const grab = (obj, name) => {
    try { return obj && typeof obj[name] === 'function' ? obj[name] : null; } catch { return null; }
  };
  const canvasProto = typeof HTMLCanvasElement !== 'undefined' ? HTMLCanvasElement.prototype : null;
  const ctx2dProto = typeof CanvasRenderingContext2D !== 'undefined' ? CanvasRenderingContext2D.prototype : null;
  const docProto = typeof Document !== 'undefined' ? Document.prototype : null;
  const gl2Proto = typeof WebGL2RenderingContext !== 'undefined' ? WebGL2RenderingContext.prototype : null;
  return Object.freeze({
    fnToString: Function.prototype.toString,
    fetch: grab(g, 'fetch'),
    createImageBitmap: grab(g, 'createImageBitmap'),
    ImageCtor: typeof Image !== 'undefined' ? Image : null,
    createObjectURL: typeof URL !== 'undefined' ? grab(URL, 'createObjectURL') : null,
    revokeObjectURL: typeof URL !== 'undefined' ? grab(URL, 'revokeObjectURL') : null,
    canvasGetContext: grab(canvasProto, 'getContext'),
    canvasToDataURL: grab(canvasProto, 'toDataURL'),
    canvasToBlob: grab(canvasProto, 'toBlob'),
    ctxDrawImage: grab(ctx2dProto, 'drawImage'),
    ctxGetImageData: grab(ctx2dProto, 'getImageData'),
    docCreateElement: grab(docProto, 'createElement'),
    glTexImage2D: grab(gl2Proto, 'texImage2D'),
    glReadPixels: grab(gl2Proto, 'readPixels'),
  });
})();

function isNativeFn(fn) {
  if (typeof fn !== 'function') return false;
  try { return /\[native code\]/.test(NATIVES.fnToString.call(fn)); } catch { return false; }
}

/** Names of sensitive APIs that look hooked (replaced or non-native). */
export function auditIntegrity() {
  const g = globalThis;
  const current = [
    ['fetch', g.fetch, NATIVES.fetch],
    ['createImageBitmap', g.createImageBitmap, NATIVES.createImageBitmap],
    ['URL.createObjectURL', typeof URL !== 'undefined' ? URL.createObjectURL : null, NATIVES.createObjectURL],
    ['HTMLCanvasElement.prototype.getContext', typeof HTMLCanvasElement !== 'undefined' ? HTMLCanvasElement.prototype.getContext : null, NATIVES.canvasGetContext],
    ['HTMLCanvasElement.prototype.toDataURL', typeof HTMLCanvasElement !== 'undefined' ? HTMLCanvasElement.prototype.toDataURL : null, NATIVES.canvasToDataURL],
    ['HTMLCanvasElement.prototype.toBlob', typeof HTMLCanvasElement !== 'undefined' ? HTMLCanvasElement.prototype.toBlob : null, NATIVES.canvasToBlob],
    ['CanvasRenderingContext2D.prototype.drawImage', typeof CanvasRenderingContext2D !== 'undefined' ? CanvasRenderingContext2D.prototype.drawImage : null, NATIVES.ctxDrawImage],
    ['CanvasRenderingContext2D.prototype.getImageData', typeof CanvasRenderingContext2D !== 'undefined' ? CanvasRenderingContext2D.prototype.getImageData : null, NATIVES.ctxGetImageData],
    ['Document.prototype.createElement', typeof Document !== 'undefined' ? Document.prototype.createElement : null, NATIVES.docCreateElement],
    ['WebGL2RenderingContext.prototype.texImage2D', typeof WebGL2RenderingContext !== 'undefined' ? WebGL2RenderingContext.prototype.texImage2D : null, NATIVES.glTexImage2D],
    ['WebGL2RenderingContext.prototype.readPixels', typeof WebGL2RenderingContext !== 'undefined' ? WebGL2RenderingContext.prototype.readPixels : null, NATIVES.glReadPixels],
  ];
  const issues = [];
  for (const [name, now, captured] of current) {
    if (!captured && !now) continue; // API absent in this environment
    if (now !== captured || (captured && !isNativeFn(captured))) issues.push(name);
  }
  return issues;
}

/** Cheap automation signals (headless/bot browsers). Spoofable — a tripwire. */
export function detectAutomation() {
  const signals = [];
  try {
    if (typeof navigator !== 'undefined') {
      if (navigator.webdriver) signals.push('webdriver');
      if (/HeadlessChrome|PhantomJS|Headless/i.test(navigator.userAgent || '')) signals.push('headless-ua');
      if (navigator.languages && navigator.languages.length === 0) signals.push('no-languages');
    }
    if (typeof window !== 'undefined' && window.outerWidth === 0 && window.outerHeight === 0) signals.push('zero-outer-size');
  } catch {}
  return signals;
}

function nativeFetch(url, options) {
  return NATIVES.fetch ? NATIVES.fetch.call(globalThis, url, options) : fetch(url, options);
}
function nativeCreateImageBitmap(source, opts) {
  return NATIVES.createImageBitmap
    ? NATIVES.createImageBitmap.call(globalThis, source, opts)
    : createImageBitmap(source, opts);
}
function makeCanvas(ownerDocument) {
  const doc = ownerDocument || document;
  return NATIVES.docCreateElement
    ? NATIVES.docCreateElement.call(doc, 'canvas')
    : doc.createElement('canvas');
}
function getNativeContext(canvas, type, attrs) {
  return NATIVES.canvasGetContext
    ? NATIVES.canvasGetContext.call(canvas, type, attrs)
    : canvas.getContext(type, attrs);
}
function nativeDrawImage(ctx, ...args) {
  return NATIVES.ctxDrawImage ? NATIVES.ctxDrawImage.call(ctx, ...args) : ctx.drawImage(...args);
}

/* ================================================================== */
/* Global config + registries                                          */
/* ================================================================== */

const DEFAULTS = {
  mode: 'shield',               // 'lite' | 'shield' | 'vault' | 'fortress'
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
  dprCap: 3,                    // match modern retina/mobile displays instead of upscaling a 2x canvas
  sourceOversample: 2,          // fetch a 2x derivative then supersample down (server entitlement still caps the signed width)
  maxSourceWidth: 2560,         // client-side ceiling before the server's own entitlement cap
  watermark: null,              // string | { text, opacity, tile, corner }
  forensic: true,               // invisible per-session block pattern (shield/vault/fortress)
  sessionId: null,              // defaults to a random per-page-view id
  brand: '© Protected · Archnemix',
  retries: 2,
  credentials: 'same-origin',
  integrity: 'monitor',         // 'off' | 'monitor' | 'lock' — hooked-API policy
  automation: 'monitor',        // 'off' | 'monitor' | 'lock' — headless/bot policy
  memory: 'standard',           // 'standard' | 'strict' — strict wipes decoded bitmaps ASAP
  localScramble: false,         // fortress: GPU texture holds scrambled pixels even for plain sources
  lens: null,                   // anti-screenshot pointer lens: true | { radius, idlePixelate }
  captureShield: null,          // true | { dynamicTrace, temporalPattern, text, opacity } (fortress enables)
  strikes: null,                // attempt lockout: { blurAt, lockAt, lockMs } (fortress enables)
  debug: false,                 // enables _debug() internals hook — NEVER in production
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
/* Host -> instance lookup WITHOUT stamping an expando on a public DOM node:
 * `element.__archx` would hand any page script/extension a direct handle to
 * our internals. A module-private WeakMap gives no such handle. */
const hostToInstance = new WeakMap();
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
  // Fortress: maximum-paranoia preset (explicit options still win).
  if (merged.mode === 'fortress') {
    merged.requestedMode = 'fortress';
    merged.mode = 'vault';
    if (clean.onExtract === undefined) merged.onExtract = 'black';
    if (clean.integrity === undefined) merged.integrity = 'lock';
    if (clean.memory === undefined) merged.memory = 'strict';
    if (clean.localScramble === undefined) merged.localScramble = true;
    if (clean.forensic === undefined) merged.forensic = true;
    if (clean.captureShield === undefined) merged.captureShield = true;
    if (clean.strikes === undefined) merged.strikes = { blurAt: 3, lockAt: 6, lockMs: 30000 };
    if (!opts.guards || opts.guards.devtools === undefined) merged.guards.devtools = true;
  }
  return merged;
}

function sanitizeOptionsView(opts) {
  if (!opts) return opts;
  const { key, aesKey, ...rest } = opts;
  return { ...rest, guards: { ...(opts.guards || {}) }, key: key ? '[redacted]' : key, aesKey: aesKey ? '[redacted]' : aesKey };
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
        const inst = hostToInstance.get(e.target);
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

  let lastCaptureKeyAt = 0;
  const onCaptureKey = (e) => {
    const key = String(e.key || '');
    const shotKey = key === 'PrintScreen' || e.code === 'PrintScreen';
    const macShot = e.metaKey && e.shiftKey && ['3', '4', '5'].includes(key);
    // Windows Snipping Tool (Win+Shift+S), Firefox Screenshots and several
    // extension defaults (Ctrl/Cmd+Shift+S). Many OS/browser shortcuts never
    // reach the page at all; when one does, react before/while capture UI opens.
    const snipShortcut = (e.metaKey || e.ctrlKey) && e.shiftKey && key.toLowerCase() === 's';
    if (!shotKey && !macShot && !snipShortcut) return;
    if (shotKey && navigator.clipboard?.writeText) {
      // Best effort only: the OS may already own the clipboard, and browsers
      // can deny clipboard writes without a user gesture/permission.
      navigator.clipboard.writeText('').catch(() => {});
    }
    const now = Date.now();
    if (now - lastCaptureKeyAt < 250) return; // keydown+keyup are one gesture
    lastCaptureKeyAt = now;
    blackoutAll(1200, 'screenshot-key');
  };
  window.addEventListener('keydown', onCaptureKey, true);
  window.addEventListener('keyup', onCaptureKey, true);
  // Some capture/tab-freeze paths freeze JS before a normal blur is useful.
  document.addEventListener('freeze', () => blackoutAll(1500, 'screenshot-key'), true);

  window.addEventListener('blur', () => instances.forEach((i) => i._setRisk('blur', true)), true);
  window.addEventListener('focus', () => instances.forEach((i) => i._setRisk('blur', false)), true);
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
  const check = () => {
    // Docked DevTools changes the viewport/outer-size relationship. Undocked
    // DevTools and remote/CDP capture cannot be detected by page JavaScript.
    const open = (window.outerWidth - window.innerWidth > 170) ||
                 (window.outerHeight - window.innerHeight > 200);
    instances.forEach((i) => { if (i.options.guards.devtools) i._setRisk('devtools', open); });
  };
  check();
  window.addEventListener('resize', check, true);
  devtoolsTimer = setInterval(check, 400);
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
      const res = await nativeFetch(url, options);
      if (!res.ok) throw new Error('Archx fetch failed: HTTP ' + res.status);
      return res;
    } catch (err) {
      lastErr = err;
      if (attempt < retries) await new Promise((r) => setTimeout(r, 250 * (attempt + 1)));
    }
  }
  throw lastErr;
}

function setSmoothing(ctx, enabled) {
  ctx.imageSmoothingEnabled = enabled;
  if (enabled) {
    try { ctx.imageSmoothingQuality = 'high'; } catch {}
  }
}

/**
 * Draw with browser-native high-quality resampling. Large reductions are
 * halved progressively instead of asking one drawImage call to jump, say,
 * 2400px -> 340px; that preserves edges/text much better in canvas engines.
 */
function drawImageHighQuality(ctx, source, sx, sy, sw, sh, dx, dy, dw, dh) {
  if (sw <= 0 || sh <= 0 || dw <= 0 || dh <= 0) return;
  const scaleX = dw / sw;
  const scaleY = dh / sh;
  const exact = Math.abs(scaleX - 1) < 0.01 && Math.abs(scaleY - 1) < 0.01;
  if (scaleX >= 0.5 || scaleY >= 0.5) {
    setSmoothing(ctx, !exact);
    nativeDrawImage(ctx, source, sx, sy, sw, sh, dx, dy, dw, dh);
    return;
  }

  let current = makeCanvas();
  current.width = Math.max(1, Math.ceil(sw));
  current.height = Math.max(1, Math.ceil(sh));
  let currentCtx = getNativeContext(current, '2d');
  setSmoothing(currentCtx, true);
  nativeDrawImage(currentCtx, source, sx, sy, sw, sh, 0, 0, current.width, current.height);

  while (current.width > dw * 2 || current.height > dh * 2) {
    const next = makeCanvas();
    next.width = Math.max(Math.ceil(dw), Math.ceil(current.width / 2));
    next.height = Math.max(Math.ceil(dh), Math.ceil(current.height / 2));
    const nextCtx = getNativeContext(next, '2d');
    setSmoothing(nextCtx, true);
    nativeDrawImage(nextCtx, current, 0, 0, current.width, current.height, 0, 0, next.width, next.height);
    current.width = 0; current.height = 0;
    current = next;
  }
  setSmoothing(ctx, true);
  nativeDrawImage(ctx, current, 0, 0, current.width, current.height, dx, dy, dw, dh);
  current.width = 0; current.height = 0;
}

/** Un-scramble a bitmap onto a private offscreen canvas (capped size). */
function unscrambleToCanvas(bitmap, meta, targetW, targetH) {
  const canvas = makeCanvas();
  canvas.width = Math.max(1, targetW);
  canvas.height = Math.max(1, targetH);
  const ctx = getNativeContext(canvas, '2d');
  if (!meta.plan) { // not scrambled — single high-quality draw
    drawImageHighQuality(ctx, bitmap, 0, 0, bitmap.width, bitmap.height, 0, 0, targetW, targetH);
    return canvas;
  }
  const { plan, origW, origH, padW, padH } = meta;
  const twSrc = bitmap.width / plan.grid;
  const thSrc = bitmap.height / plan.grid;
  // Reassemble on an intermediate canvas whose tile size is an INTEGER number
  // of pixels. Fractional tile origins make browsers paint semi-transparent
  // edge coverage and blend pixels from neighbouring *scrambled* tiles,
  // which shows up as a visible grid of seams.
  //
  // Quality matters here: scaling every shuffled tile straight to its final
  // size throws away detail 64 separate times and looks slurry. Prefer the
  // decoded bitmap's native resolution (or at most 2x the final size for a
  // very large source), reassemble there, then perform ONE high-quality
  // downscale after neighbouring pixels are true neighbours again.
  const targetPadW = targetW * (padW / origW);
  const targetPadH = targetH * (padH / origH);
  const intermediateScale = Math.max(0.05, Math.min(
    2,
    bitmap.width / Math.max(1, targetPadW),
    bitmap.height / Math.max(1, targetPadH),
  ));
  const tileW = Math.max(1, Math.round((targetPadW * intermediateScale) / plan.grid));
  const tileH = Math.max(1, Math.round((targetPadH * intermediateScale) / plan.grid));
  const padded = makeCanvas();
  padded.width = tileW * plan.grid;
  padded.height = tileH * plan.grid;
  const pctx = getNativeContext(padded, '2d');
  const exactScale = Math.abs(tileW - twSrc) < 0.01 && Math.abs(tileH - thSrc) < 0.01;
  setSmoothing(pctx, !exactScale);
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
    nativeDrawImage(pctx, bitmap,
      s.x + insetX, s.y + insetY, s.w - insetX * 2, s.h - insetY * 2,
      0, 0, tileW, tileH);
    pctx.restore();
  }
  // Crop away the padding strip and scale once to the exact requested size.
  drawImageHighQuality(ctx, padded,
    0, 0, padded.width * (origW / padW), padded.height * (origH / padH),
    0, 0, targetW, targetH);
  padded.width = 0; padded.height = 0;
  return canvas;
}

/**
 * Locally scramble a clean canvas (Fortress/plain-source Vault): the GPU
 * texture then holds shuffled pixels, so texture/framebuffer snooping sees
 * a mosaic even when the network source itself was a plain image.
 */
function scrambleCanvasLocally(source, grid, key) {
  const w = source.width, h = source.height;
  const { tw, th, pw, ph } = paddedSize(w, h, grid);
  const plan = buildScramblePlan(grid, key);
  const cleanPadded = makeCanvas();
  cleanPadded.width = pw; cleanPadded.height = ph;
  const cctx = getNativeContext(cleanPadded, '2d');
  setSmoothing(cctx, false); // exact 1:1 copy into the padded frame
  cctx.fillStyle = '#000'; cctx.fillRect(0, 0, pw, ph);
  nativeDrawImage(cctx, source, 0, 0);
  const scrambled = makeCanvas();
  scrambled.width = pw; scrambled.height = ph;
  const ctx = getNativeContext(scrambled, '2d');
  setSmoothing(ctx, false); // tiles are copied 1:1; never resample them here
  ctx.fillStyle = '#000'; ctx.fillRect(0, 0, pw, ph);
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
  cleanPadded.width = 0; cleanPadded.height = 0;
  return { canvas: scrambled, meta: { plan, origW: w, origH: h, padW: pw, padH: ph } };
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

/* ================================================================== */
/* ProtectedImage                                                      */
/* ================================================================== */

export class ProtectedImage {
  /* Everything sensitive is a #private field: page scripts and extension
   * content scripts that obtain an instance (or its host element) get no
   * handle to the canvas, bitmap, options/secrets, or shadow internals. */
  #options; #host; #root; #wrap; #canvas; #tilesEl; #shieldEl;
  #source; #bitmap = null; #meta = null; #abort = new AbortController();
  #decoy = null; #gl = null; #raf = 0; #loaded = false; #destroyed = false;
  #risk = new Set(); #blackoutTimer = 0; #resizeObs = null; #realCtx = null;
  #attemptHandler = null; #loading = false; #visible = false; #unloaded = false;
  #glProg = null; #glLoc = null; #glTex = null; #glMap = null; #glWm = null; #glWmOn = 0;
  #glSource = null; #glMeta = null; #frameCanvas = null; #lensBase = null;
  #lensPoint = null; #lensRaf = 0; #lensCells = [];
  #traceEl = null; #traceTimer = 0;
  #strikes = 0; #lockedUntil = 0; #lockTimer = 0; #integrityIssues = [];
  #bitmapReleased = false;

  /** Sanitised, secret-free view of the effective options. */
  get options() { return sanitizeOptionsView(this.#options); }

  constructor(target, source, options = {}) {
    this.#options = mergeOptions(options);
    this.#source = source;
    const host = $(target);
    if (!host) throw new Error('Archx: target element not found: ' + target);
    this.#host = host;
    host.classList.add('archx-host');
    hostToInstance.set(host, this);
    if (this.#options.alt) {
      host.setAttribute('role', 'img');
      host.setAttribute('aria-label', this.#options.alt);
    }
    this._buildDom();
    this._attachGuards();
    this._startCaptureTrace();
    instances.add(this);
    installGlobalGuards();
    if (this.#options.guards.devtools) ensureDevtoolsWatcher();

    this.ready = this._init();
  }

  /* ---------------- DOM ---------------- */
  _buildDom() {
    const o = this.#options;
    let root;
    if (o.shadow === 'none') {
      root = this.#host;
    } else {
      try {
        root = this.#host.attachShadow({ mode: o.shadow === 'open' ? 'open' : 'closed' });
      } catch { root = this.#host; }
    }
    this.#root = root;
    const doc = this.#host.ownerDocument;
    const style = doc.createElement('style');
    style.textContent = SHADOW_CSS;
    const wrap = doc.createElement('div');
    wrap.className = 'wrap loading' + (o.showBadge ? ' show-badge' : '');
    wrap.innerHTML = `
      <div class="tiles" hidden></div>
      <canvas class="main" aria-hidden="true"></canvas>
      <div class="badge">ARCHX&nbsp;PROTECTED</div>
      <div class="trace" aria-hidden="true"><div class="trace-inner"><span></span><span></span><span></span><span></span><span></span></div></div>
      <div class="shield"></div>
      <div class="risk"></div>
      <div class="err"><span>⚠<br>Protected image unavailable</span></div>`;
    root.append(style, wrap);
    this.#wrap = wrap;
    this.#canvas = wrap.querySelector('canvas.main');
    this.#tilesEl = wrap.querySelector('.tiles');
    this.#shieldEl = wrap.querySelector('.shield');
    this.#traceEl = wrap.querySelector('.trace');
    if (o.aspectRatio) this.#host.style.aspectRatio = String(o.aspectRatio);
    if (o.width) this.#host.style.width = typeof o.width === 'number' ? o.width + 'px' : o.width;
    if (o.height) this.#host.style.height = typeof o.height === 'number' ? o.height + 'px' : o.height;
  }

  _attachGuards() {
    const o = this.#options;
    const sig = { signal: this.#abort.signal };
    const attempt = (kind) => {
      try { o.onAttempt && o.onAttempt(kind, this); } catch {}
      this.#host.dispatchEvent(new CustomEvent('archx-attempt', { detail: { kind }, bubbles: true }));
      this.#registerStrike(kind);
    };
    this.#attemptHandler = attempt;

    if (o.guards.contextMenu) {
      this.#wrap.addEventListener('contextmenu', (e) => { e.preventDefault(); e.stopPropagation(); attempt('contextmenu'); }, sig);
    }
    if (o.guards.drag) {
      this.#wrap.addEventListener('dragstart', (e) => { e.preventDefault(); attempt('drag'); }, sig);
    }
    if (o.guards.copy) {
      this.#wrap.addEventListener('copy', (e) => { e.preventDefault(); attempt('copy'); }, sig);
      this.#wrap.addEventListener('selectstart', (e) => e.preventDefault(), sig);
    }
    if (o.guards.longPress) {
      let timer = 0;
      this.#wrap.addEventListener('pointerdown', (e) => {
        if (e.pointerType !== 'touch') return;
        timer = setTimeout(() => { attempt('longpress'); this._momentaryBlackout(700, 'longpress'); }, 450);
      }, sig);
      const clear = () => clearTimeout(timer);
      this.#wrap.addEventListener('pointerup', clear, sig);
      this.#wrap.addEventListener('pointercancel', clear, sig);
      this.#wrap.addEventListener('pointermove', clear, sig);
    }
    // Forward genuine clicks so galleries/lightboxes keep working.
    this.#shieldEl.addEventListener('click', (e) => {
      if (o.onClick) { try { o.onClick(e, this); } catch {} }
      if (!o.swallowClick) {
        this.#host.dispatchEvent(new MouseEvent('click', { bubbles: true, clientX: e.clientX, clientY: e.clientY }));
      }
    }, sig);

    // Pointer lens: only *trusted* pointer input may move the sharp region.
    // Script-dispatched synthetic events (isTrusted === false) are ignored,
    // so a scraping script can't sweep the lens across the image and stitch
    // the sharp patches together without real input hardware / CDP control.
    if (o.lens) {
      const updateLens = (e) => {
        if (!e.isTrusted) return;
        const r = this.#wrap.getBoundingClientRect();
        if (r.width <= 0 || r.height <= 0) return;
        this.#lensPoint = {
          x: Math.max(0, Math.min(1, (e.clientX - r.left) / r.width)),
          y: Math.max(0, Math.min(1, (e.clientY - r.top) / r.height)),
        };
        this.#trackLensTravel(this.#lensPoint);
        this.#requestLensFrame();
      };
      this.#shieldEl.addEventListener('pointermove', updateLens, sig);
      this.#shieldEl.addEventListener('pointerdown', updateLens, sig);
      this.#shieldEl.addEventListener('pointerleave', () => {
        this.#lensPoint = null;
        this.#requestLensFrame();
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
    const raw = this.#options.captureShield;
    if (!raw || !this.#traceEl || this.#traceTimer) return;
    const cfg = raw === true ? {} : raw;
    if (!cfg || cfg.dynamicTrace === false) return;
    this.#wrap.classList.add('trace-on');
    this.#traceEl.classList.toggle('temporal', !!cfg.temporalPattern);
    this.#traceEl.style.setProperty('--trace-opacity', String(cfg.opacity ?? 0.08));
    const update = () => {
      if (this.#destroyed || !this.#traceEl) return;
      const wm = this.#options.watermark;
      const wmText = typeof wm === 'string' ? wm : wm?.text;
      let template = cfg.text || wmText || `${this.#options.brand} · {session} · {time}`;
      if (!template.includes('{time}')) template += ' · {time}';
      const text = String(template)
        .replaceAll('{session}', sessionId().slice(0, 6))
        .replaceAll('{time}', new Date().toISOString().slice(11, 19));
      const inner = this.#traceEl.querySelector('.trace-inner');
      if (inner) {
        const width = this.#wrap.clientWidth || this.#host.clientWidth || 320;
        inner.style.fontSize = `${Math.max(10, Math.min(24, Math.round(width / 18)))}px`;
        inner.querySelectorAll('span').forEach((span) => { span.textContent = text; });
      }
    };
    update();
    this.#traceTimer = setInterval(update, Math.max(1000, cfg.updateMs ?? 4000));
  }

  /** Strike accounting: repeated extraction attempts escalate to lockout. */
  #registerStrike(kind) {
    const serious = /^(extract-|contextmenu|drag|copy|longpress|integrity|automation|lens-scan)/.test(kind);
    if (!serious) return;
    this.#strikes++;
    const policy = this.#options.strikes;
    if (!policy) return;
    const blurAt = policy.blurAt ?? 3;
    const lockAt = policy.lockAt ?? 6;
    const lockMs = policy.lockMs ?? 30000;
    if (this.#strikes >= lockAt) {
      this.#lockedUntil = Date.now() + lockMs;
      this.#wrap.classList.add('blackout');
      this._stopGlLoop();
      clearTimeout(this.#lockTimer);
      this.#lockTimer = setTimeout(() => {
        this.#lockedUntil = 0;
        this.#strikes = 0;
        this.#wrap.classList.remove('blackout');
        if (this.#gl && this.#visible) this._startGlLoop();
        else if (this.#frameCanvas) this.#paintLens2d();
      }, lockMs);
    } else if (this.#strikes >= blurAt) {
      this.#wrap.classList.add('risk-on');
      setTimeout(() => {
        if (!this.#risk.size && Date.now() >= this.#lockedUntil) this.#wrap.classList.remove('risk-on');
      }, 4000);
    }
  }

  /** Heuristic: a lens swept rapidly across many cells == stitching attempt. */
  #trackLensTravel(point) {
    const now = performance.now();
    const cell = Math.floor(point.y * 6) * 6 + Math.floor(point.x * 6);
    this.#lensCells.push({ cell, now });
    this.#lensCells = this.#lensCells.filter((c) => now - c.now < 8000);
    const distinct = new Set(this.#lensCells.map((c) => c.cell)).size;
    const cfg = typeof this.#options.lens === 'object' && this.#options.lens ? this.#options.lens : {};
    const threshold = cfg.scanCells ?? 26;
    if (distinct >= threshold) {
      this.#lensCells = [];
      if (this.#attemptHandler) this.#attemptHandler('lens-scan');
    }
  }

  #requestLensFrame() {
    if (this.#gl) return; // GL loop reads #lensPoint every frame
    if (this.#lensRaf || !this.#frameCanvas) return;
    this.#lensRaf = requestAnimationFrame(() => {
      this.#lensRaf = 0;
      this.#paintLens2d();
    });
  }

  _onVisibility(visible) {
    this.#visible = visible;
    if (visible && !this.#loaded && !this.#loading) this._load();
    if (visible && this.#loaded && this.#unloaded) this._load();
    if (!visible && this.#options.unloadOnExit && this.#loaded) this._unloadPixels();
    if (this.#gl) visible ? this._startGlLoop() : this._stopGlLoop();
  }

  async _init() {
    // Resize handling (debounced redraw from cached bitmap — no refetch)
    let resizeTimer = 0;
    this.#resizeObs = new ResizeObserver(() => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        if (this.#gl) return; // GL loop tracks size itself, texture stays uploaded
        if (this.#bitmap) this._render();
        // Strict-memory mode released the bitmap after first paint: a size
        // change that needs fresh pixels re-resolves the source (fresh token).
        else if (this.#loaded && this.#bitmapReleased && this.#visible) this._load();
      }, 90);
    });
    this.#resizeObs.observe(this.#host);

    if (this.#options.lazy && 'IntersectionObserver' in window) {
      getVisibilityObserver().observe(this.#host);
      // _load fires from observer; also kick if already on screen pre-observe
      const r = this.#host.getBoundingClientRect();
      if (r.bottom > -500 && r.top < innerHeight + 500) this._load();
    } else {
      this.#visible = true;
      await this._load();
    }
    return this;
  }

  /* ---------------- source resolution ---------------- */
  async _resolveBytes() {
    const o = this.#options;
    let src = this.#source;
    let extra = {};
    const strict = o.memory === 'strict';
    // Token flow: { id } against the signing server. Kept separate from the
    // generic URL path so a 403 (expired / one-time-consumed / binding
    // mismatch after a network hiccup) re-mints a FRESH token instead of
    // blindly retrying a dead signed URL.
    if (src && typeof src === 'object' && !(src instanceof Blob) &&
        !(src instanceof ArrayBuffer) && !ArrayBuffer.isView(src) && src.id) {
      const endpoint = src.tokenEndpoint || o.tokenEndpoint;
      if (!endpoint) throw new Error('Archx: tokenEndpoint required for {id} sources');
      const rect = this.#host.getBoundingClientRect?.();
      const cssWidth = rect?.width || this.#host.clientWidth || 800;
      const cssHeight = rect?.height || this.#host.clientHeight || cssWidth * 0.75;
      const pixelScale = Math.min(devicePixelRatio || 1, o.dprCap) * Math.max(1, o.sourceOversample || 1);
      const maxSourceWidth = o.maxSourceWidth || 2560;
      const boxW = Math.min(maxSourceWidth, Math.ceil(cssWidth * pixelScale));
      const boxH = Math.min(maxSourceWidth, Math.ceil(cssHeight * pixelScale));
      // Send the display box, not just a width: for cover-fit, the server must
      // account for the source aspect or a landscape image in a squarer box
      // gets cropped and then upscaled (a major source of slurry detail).
      const tokenQuery = `?w=${boxW}&bw=${boxW}&bh=${boxH}&fit=${encodeURIComponent(o.fit || 'cover')}`;
      let lastErr;
      for (let tokenAttempt = 0; tokenAttempt <= 1; tokenAttempt++) {
        try {
          const res = await fetchWithRetries(endpoint + encodeURIComponent(src.id) + tokenQuery,
            { credentials: o.credentials, signal: this.#abort.signal }, o.retries);
          const token = await res.json();
          const imgRes = await nativeFetch(token.url, {
            credentials: o.credentials, cache: 'no-store', signal: this.#abort.signal,
          });
          if ((imgRes.status === 401 || imgRes.status === 403) && tokenAttempt === 0) continue;
          if (!imgRes.ok) throw new Error('Archx fetch failed: HTTP ' + imgRes.status);
          const buf = new Uint8Array(await imgRes.arrayBuffer());
          return { ...(await this._bytesToBitmap(buf, token)), extra: token };
        } catch (err) {
          lastErr = err;
          if (tokenAttempt === 1) throw err;
        }
      }
      throw lastErr;
    }
    if (typeof src === 'string') {
      const cacheKey = src + '|' + (extra.key || o.key || '');
      if (!strict && bitmapCache.has(cacheKey)) return { ...(await bitmapCache.get(cacheKey)), extra };
      const promise = (async () => {
        const res = await fetchWithRetries(src,
          { credentials: o.credentials, cache: 'no-store', signal: this.#abort.signal }, o.retries);
        const buf = new Uint8Array(await res.arrayBuffer());
        return this._bytesToBitmap(buf, extra);
      })();
      if (!strict) cachePut(cacheKey, promise);
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
    const o = this.#options;
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
      bitmap = await nativeCreateImageBitmap(blob);
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
      const url = NATIVES.createObjectURL ? NATIVES.createObjectURL.call(URL, blob) : URL.createObjectURL(blob);
      const img = new (NATIVES.ImageCtor || Image)(); // detached, never inserted into the document
      img.onload = () => { (NATIVES.revokeObjectURL ? NATIVES.revokeObjectURL.call(URL, url) : URL.revokeObjectURL(url)); resolve(img); };
      img.onerror = (e) => { (NATIVES.revokeObjectURL ? NATIVES.revokeObjectURL.call(URL, url) : URL.revokeObjectURL(url)); reject(e); };
      img.src = url;
    });
  }

  /** Hook/automation gate. Returns true if loading may proceed. */
  #securityGate() {
    const o = this.#options;
    if (Date.now() < this.#lockedUntil) return false;
    if (o.integrity !== 'off') {
      this.#integrityIssues = auditIntegrity();
      if (this.#integrityIssues.length) {
        if (this.#attemptHandler) this.#attemptHandler('integrity:' + this.#integrityIssues.join(','));
        if (o.integrity === 'lock') return false;
      }
    }
    if (o.automation !== 'off') {
      const signals = detectAutomation();
      if (signals.length) {
        if (this.#attemptHandler) this.#attemptHandler('automation:' + signals.join(','));
        if (o.automation === 'lock') return false;
      }
    }
    return true;
  }

  async _load() {
    if (this.#loading || this.#destroyed) return;
    if (!this.#securityGate()) {
      this.#wrap.classList.remove('loading');
      this.#wrap.classList.add('error');
      this.#host.dispatchEvent(new CustomEvent('archx-error', {
        detail: { error: new Error('Archx: blocked by integrity/automation/lockout policy') }, bubbles: true,
      }));
      return;
    }
    this.#loading = true;
    try {
      const { bitmap, meta } = await limiter.run(() => this._resolveBytes());
      if (this.#destroyed) return;
      this.#bitmap = bitmap;
      this.#meta = meta;
      this.#bitmapReleased = false;
      this.#glSource = null;
      this.#glMeta = null;
      this.#decoy = null; // regenerate poison for the (possibly new) source
      if (!this.#options.aspectRatio && !this.#options.height) {
        this.#host.style.aspectRatio = meta.origW + ' / ' + meta.origH;
      }
      this._render();
      this.#loaded = true;
      this.#unloaded = false;
      this.#wrap.classList.remove('loading', 'error');
      this.#host.dispatchEvent(new CustomEvent('archx-load', { bubbles: true }));
      try { this.#options.onLoad && this.#options.onLoad(this); } catch {}
    } catch (err) {
      if (this.#destroyed) return;
      this.#wrap.classList.remove('loading');
      this.#wrap.classList.add('error');
      this.#host.dispatchEvent(new CustomEvent('archx-error', { detail: { error: err }, bubbles: true }));
      try { this.#options.onError && this.#options.onError(err, this); } catch {}
    } finally {
      this.#loading = false;
    }
  }

  _unloadPixels() {
    // Free backing stores for off-screen gallery items; bytes stay cached.
    if (this.#canvas) { this.#canvas.width = 0; this.#canvas.height = 0; }
    this.#unloaded = true;
  }

  /** Strict-memory mode: drop the decoded source as soon as pixels are painted. */
  #releaseSourceBitmap() {
    if (this.#options.memory !== 'strict' || !this.#bitmap) return;
    try { this.#bitmap.close && this.#bitmap.close(); } catch {}
    this.#bitmap = null;
    this.#bitmapReleased = true;
  }

  /* ---------------- rendering ---------------- */
  _backingSize() {
    const o = this.#options;
    const rect = this.#host.getBoundingClientRect();
    const cssW = Math.max(1, Math.round(rect.width || this.#host.clientWidth || 320));
    const cssH = Math.max(1, Math.round(rect.height || this.#host.clientHeight || Math.round(cssW * (this.#meta.origH / this.#meta.origW)) || 240));
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
    const mode = this.#options.mode;
    if (mode === 'vault') {
      if (this._tryRenderWebGL()) return;
      // fall through to shield rendering on any GL problem / budget hit
    }
    if (this.#options.splitCanvases && mode !== 'lite' && !this.#options.lens) this._renderSplit();
    else this._render2d();
  }

  /** Private, capped, un-scrambled working canvas (wiped after use). */
  _workingCanvas(w, h) {
    // Un-scramble at source aspect, capped to backing size, then fit-crop.
    const meta = this.#meta;
    const fit = fitRects(meta.origW, meta.origH, w, h, this.#options.fit);
    const fullW = Math.max(1, Math.round((meta.origW / fit.sw) * fit.dw));
    const fullH = Math.max(1, Math.round((meta.origH / fit.sh) * fit.dh));
    return { full: unscrambleToCanvas(this.#bitmap, meta, fullW, fullH), fit, fullW, fullH };
  }

  _render2d() {
    const { w, h } = this._backingSize();
    const canvas = this.#canvas;
    this.#tilesEl.hidden = true;
    canvas.hidden = false;
    canvas.width = w; canvas.height = h;
    const ctx = getNativeContext(canvas, '2d', { alpha: false });
    this.#realCtx = ctx;
    const { full, fit } = this._workingCanvas(w, h);
    if (this.#options.lens) {
      // Compose the sharp frame privately (never in the DOM), bake overlays
      // into it, then show only a pixelated base + a sharp circle that
      // follows trusted pointer input. Any single screenshot / canvas grab
      // therefore captures mostly mush with one small sharp patch.
      const frame = makeCanvas(this.#host.ownerDocument);
      frame.width = w; frame.height = h;
      const fctx = getNativeContext(frame, '2d');
      fctx.fillStyle = '#000'; fctx.fillRect(0, 0, w, h);
      setSmoothing(fctx, true);
      nativeDrawImage(fctx, full, fit.sx * (full.width / this.#meta.origW), fit.sy * (full.height / this.#meta.origH),
        fit.sw * (full.width / this.#meta.origW), fit.sh * (full.height / this.#meta.origH),
        fit.dx, fit.dy, fit.dw, fit.dh);
      this._bakeOverlays(fctx, w, h);
      this.#decoy = this._makeDecoy(full, w, h);
      full.width = 0; full.height = 0;
      if (this.#frameCanvas) { this.#frameCanvas.width = 0; this.#frameCanvas.height = 0; }
      this.#frameCanvas = frame;
      // Pre-render the pixelated base once.
      const cfg = typeof this.#options.lens === 'object' ? this.#options.lens : {};
      const factor = cfg.idlePixelate ?? 18;
      const base = makeCanvas(this.#host.ownerDocument);
      base.width = Math.max(8, Math.round(w / factor));
      base.height = Math.max(8, Math.round(h / factor));
      nativeDrawImage(getNativeContext(base, '2d'), frame, 0, 0, base.width, base.height);
      this.#lensBase = base;
      this.#paintLens2d();
      this._poison(canvas, ctx);
      this.#releaseSourceBitmap();
      return;
    }
    ctx.fillStyle = '#000';
    ctx.fillRect(0, 0, w, h);
    setSmoothing(ctx, true);
    nativeDrawImage(ctx, full, fit.sx * (full.width / this.#meta.origW), fit.sy * (full.height / this.#meta.origH),
      fit.sw * (full.width / this.#meta.origW), fit.sh * (full.height / this.#meta.origH),
      fit.dx, fit.dy, fit.dw, fit.dh);
    this._bakeOverlays(ctx, w, h);
    this.#decoy = this._makeDecoy(full, w, h);
    full.width = 0; full.height = 0; // wipe the clean working copy immediately
    this._poison(canvas, ctx);
    this.#releaseSourceBitmap();
  }

  #paintLens2d() {
    const ctx = this.#realCtx;
    const frame = this.#frameCanvas;
    if (!ctx || !frame || this.#destroyed) return;
    const w = frame.width, h = frame.height;
    if (Date.now() < this.#lockedUntil) {
      ctx.fillStyle = '#000'; ctx.fillRect(0, 0, w, h);
      return;
    }
    // Pixelated base everywhere…
    ctx.fillStyle = '#000'; ctx.fillRect(0, 0, w, h);
    if (this.#lensBase) {
      ctx.imageSmoothingEnabled = false; // deliberately blocky outside the lens
      nativeDrawImage(ctx, this.#lensBase, 0, 0, w, h);
      ctx.fillStyle = 'rgba(4,6,12,0.18)';
      ctx.fillRect(0, 0, w, h);
    }
    // …plus one sharp disc under the pointer.
    const point = this.#lensPoint;
    if (point) {
      const cfg = typeof this.#options.lens === 'object' ? this.#options.lens : {};
      const radius = Math.max(24, Math.min(w, h) * (cfg.radius ?? 0.30));
      const cx = point.x * w, cy = point.y * h;
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.clip();
      nativeDrawImage(ctx, frame, 0, 0);
      ctx.restore();
      ctx.save();
      ctx.strokeStyle = 'rgba(255,255,255,0.35)';
      ctx.lineWidth = 1.5;
      ctx.beginPath(); ctx.arc(cx, cy, radius, 0, Math.PI * 2); ctx.stroke();
      ctx.restore();
    }
  }

  _renderSplit() {
    const { w, h } = this._backingSize();
    const g = Math.max(2, Math.min(6, this.#options.splitGrid | 0));
    const { full, fit } = this._workingCanvas(w, h);
    // Compose final image privately once (with watermark), then slice it.
    const composed = makeCanvas();
    composed.width = w; composed.height = h;
    const cctx = getNativeContext(composed, '2d');
    cctx.fillStyle = '#000'; cctx.fillRect(0, 0, w, h);
    setSmoothing(cctx, true);
    nativeDrawImage(cctx, full, fit.sx * (full.width / this.#meta.origW), fit.sy * (full.height / this.#meta.origH),
      fit.sw * (full.width / this.#meta.origW), fit.sh * (full.height / this.#meta.origH),
      fit.dx, fit.dy, fit.dw, fit.dh);
    this._bakeOverlays(cctx, w, h);
    this.#canvas.hidden = true;
    this.#tilesEl.hidden = false;
    this.#tilesEl.style.gridTemplateColumns = `repeat(${g},1fr)`;
    this.#tilesEl.style.gridTemplateRows = `repeat(${g},1fr)`;
    this.#tilesEl.replaceChildren();
    const tw = Math.ceil(w / g), th = Math.ceil(h / g);
    for (let i = 0; i < g * g; i++) {
      const c = makeCanvas();
      c.width = tw; c.height = th;
      const tctx = getNativeContext(c, '2d', { alpha: false });
      nativeDrawImage(tctx, composed, (i % g) * tw, Math.floor(i / g) * th, tw, th, 0, 0, tw, th);
      this.#tilesEl.appendChild(c);
      this.#decoy = this.#decoy || this._makeDecoy(full, w, h);
      this._poison(c, tctx);
    }
    composed.width = 0;
    full.width = 0; full.height = 0;
    this.#releaseSourceBitmap();
  }

  _bakeOverlays(ctx, w, h) {
    const o = this.#options;
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
      // Block-level forensic pattern (survives re-encoding/scaling far better
      // than 1px noise): a seeded ± luminance checker at macro-block scale.
      // Server mode additionally bakes an equivalent mark pre-scramble.
      const rand = mulberry32(hashSeed(sessionId() + '|' + (typeof this.#source === 'string' ? this.#source : 'blob') + '|fx'));
      ctx.save();
      const bs = Math.max(16, Math.round(Math.min(w, h) / 18));
      for (let y = 0; y < h; y += bs) {
        for (let x = 0; x < w; x += bs) {
          ctx.fillStyle = rand() < 0.5 ? 'rgba(0,0,0,0.016)' : 'rgba(255,255,255,0.016)';
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
    const o = this.#options;
    const kind = o.onExtract;
    const decoy = makeCanvas();
    const ctx = getNativeContext(decoy, '2d');
    if (kind === 'lowres') {
      const tinyW = 72;
      const tinyH = Math.max(1, Math.round((h / w) * tinyW));
      const tiny = makeCanvas();
      tiny.width = tinyW; tiny.height = tinyH;
      nativeDrawImage(getNativeContext(tiny, '2d'), cleanCanvas, 0, 0, tinyW, tinyH);
      decoy.width = w; decoy.height = h;
      ctx.imageSmoothingEnabled = false;
      nativeDrawImage(ctx, tiny, 0, 0, w, h); // blocky pixelated upscale
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
        nativeDrawImage(ctx, cleanCanvas, (source % g) * tw, Math.floor(source / g) * th, tw, th,
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
    // Captured at module load — a hook installed afterwards cannot hijack
    // the decoy-generation path by replacing the prototypes now.
    const realToDataURL = NATIVES.canvasToDataURL || HTMLCanvasElement.prototype.toDataURL;
    const realToBlob = NATIVES.canvasToBlob || HTMLCanvasElement.prototype.toBlob;
    const self = this;
    const define = (name, fn) => {
      try {
        Object.defineProperty(canvas, name, { value: fn, writable: false, configurable: false });
      } catch { try { canvas[name] = fn; } catch {} }
    };
    define('toDataURL', function (type, quality) {
      self.#attemptHandler('extract-dataurl');
      const d = decoy();
      return d ? realToDataURL.call(d, type, quality) : 'data:,';
    });
    define('toBlob', function (cb, type, quality) {
      self.#attemptHandler('extract-blob');
      const d = decoy();
      if (d) realToBlob.call(d, cb, type, quality);
      else if (cb) cb(new Blob([], { type: type || 'image/png' }));
    });
    if ('captureStream' in canvas) {
      define('captureStream', function () {
        self.#attemptHandler('extract-stream');
        const d = decoy();
        if (d && d.captureStream) return d.captureStream(1);
        throw new DOMException('Protected canvas', 'SecurityError');
      });
    }
    if (ctx && ctx.getImageData) {
      const poisonedGet = function (sx, sy, sw, sh) {
        self.#attemptHandler('extract-pixels');
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
  /** A canvas that already owns a WebGL context can never become a 2D
   * canvas — fallback therefore swaps in a fresh element inside the shadow. */
  #fresh2dCanvas() {
    const fresh = makeCanvas(this.#host.ownerDocument);
    fresh.className = 'main';
    fresh.setAttribute('aria-hidden', 'true');
    this.#canvas.replaceWith(fresh);
    this.#canvas = fresh;
    this.#realCtx = null;
    return fresh;
  }

  /** Decide what the GPU texture will hold (scrambled whenever possible). */
  #prepareGlSource() {
    if (this.#glMeta) return;
    const o = this.#options;
    if (!this.#meta.plan && o.localScramble) {
      const { w, h } = this._backingSize();
      const { full } = this._workingCanvas(w, h);
      const local = scrambleCanvasLocally(full, o.grid, 'local:' + sessionId());
      if (!this.#decoy) this.#decoy = this._makeDecoy(full, full.width, full.height);
      full.width = 0; full.height = 0;
      this.#glSource = local.canvas;
      this.#glMeta = local.meta;
      return;
    }
    this.#glSource = this.#bitmap;
    this.#glMeta = this.#meta;
  }

  _tryRenderWebGL() {
    if (glContextsInUse >= GL_CONTEXT_BUDGET && !this.#gl) return false;
    const canvas = this.#canvas;
    this.#tilesEl.hidden = true;
    canvas.hidden = false;
    let gl = this.#gl;
    if (!gl) {
      gl = getNativeContext(canvas, 'webgl2', { preserveDrawingBuffer: false, antialias: false, alpha: false, powerPreference: 'low-power' });
      if (!gl) return false;
      this.#gl = gl;
      glContextsInUse++;
      canvas.addEventListener('webglcontextlost', (e) => {
        e.preventDefault();
        this.#gl = null; glContextsInUse = Math.max(0, glContextsInUse - 1);
        this.#glSource = null; this.#glMeta = null;
        this.#fresh2dCanvas();
        if (this.#bitmap) this._render2d();
        else { this.#loaded = false; this._load(); }
      }, { signal: this.#abort.signal });
      if (!this._initGl(gl)) {
        this.#gl = null; glContextsInUse--;
        this.#fresh2dCanvas();
        return false;
      }
    }
    this.#prepareGlSource();
    this._uploadGlTexture(gl);
    // Texture now lives on the GPU; the CPU-side upload source can go.
    if (this.#glSource && this.#glSource !== this.#bitmap) {
      try { this.#glSource.width = 0; this.#glSource.height = 0; } catch {}
    }
    this.#glSource = null;
    // Decoy for any instance-level grabbers (prototype calls return black anyway).
    // Generated BEFORE strict release, while the decoded bitmap still exists.
    if (!this.#decoy && this.#bitmap) {
      const { full } = this._workingCanvas(320, Math.max(1, Math.round(320 * this.#meta.origH / this.#meta.origW)));
      this.#decoy = this._makeDecoy(full, full.width, full.height);
      full.width = 0;
    }
    this._startGlLoop();
    this.#releaseSourceBitmap();
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
    this.#glProg = prog;
    this.#glLoc = {};
    ['uTex','uMap','uWm','uGrid','uCrop','uFitScale','uFitOffset','uScrambled','uSeed','uWmOn',
     'uLensOn','uLensActive','uLensCenter','uLensRadius','uResolution','uLocked']
      .forEach((n) => { this.#glLoc[n] = gl.getUniformLocation(prog, n); });
    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1,-1, 1,-1, -1,1, 1,1]), gl.STATIC_DRAW);
    gl.enableVertexAttribArray(0);
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
    this.#glTex = gl.createTexture();
    this.#glMap = gl.createTexture();
    this.#glWm = gl.createTexture();
    return true;
  }

  _uploadGlTexture(gl) {
    const meta = this.#glMeta || this.#meta;
    const source = this.#glSource || this.#bitmap;
    const texImage = (...args) => (NATIVES.glTexImage2D
      ? NATIVES.glTexImage2D.call(gl, ...args)
      : gl.texImage2D(...args));
    gl.activeTexture(gl.TEXTURE0);
    gl.bindTexture(gl.TEXTURE_2D, this.#glTex);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    gl.pixelStorei(gl.UNPACK_FLIP_Y_WEBGL, false);
    texImage(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, source);
    if (!meta.plan) {
      // A clean (unscrambled) texture can use real trilinear mipmaps. A
      // scrambled texture deliberately cannot: mip levels would blend across
      // neighbouring shuffled tiles; sampleImage() supersamples instead.
      try {
        gl.generateMipmap(gl.TEXTURE_2D);
        gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR_MIPMAP_LINEAR);
      } catch {}
    }
    // Tile map: for each ORIGINAL tile -> scrambled source tile + flips
    gl.activeTexture(gl.TEXTURE1);
    gl.bindTexture(gl.TEXTURE_2D, this.#glMap);
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
    // Watermark texture rendered once on a 2D canvas
    gl.activeTexture(gl.TEXTURE2);
    gl.bindTexture(gl.TEXTURE_2D, this.#glWm);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    const wm = this.#options.watermark;
    this.#glWmOn = 0;
    if (wm) {
      const cfg = typeof wm === 'string' ? { text: wm } : wm;
      const text = String(cfg.text || '').replace('{session}', sessionId().slice(0, 6));
      if (text) {
        const c = makeCanvas();
        c.width = 1024; c.height = Math.max(64, Math.round(1024 * meta.origH / meta.origW));
        const ctx = getNativeContext(c, '2d');
        ctx.clearRect(0, 0, c.width, c.height);
        ctx.fillStyle = cfg.color || '#ffffff';
        if (cfg.tile !== false) {
          ctx.save();
          ctx.globalAlpha = cfg.opacity ?? 0.16;
          const fs = Math.max(18, Math.round(Math.min(c.width, c.height) / 12));
          ctx.font = `700 ${fs}px system-ui,sans-serif`;
          ctx.textAlign = 'center';
          ctx.translate(c.width / 2, c.height / 2); ctx.rotate(-Math.PI / 7);
          const diag = Math.hypot(c.width, c.height);
          for (let y = -diag / 2; y < diag / 2; y += fs * 4.2) ctx.fillText(text, 0, y);
          ctx.restore();
        }
        if (cfg.corner !== false) {
          ctx.save();
          ctx.globalAlpha = cfg.cornerOpacity ?? 0.9;
          const fs = Math.max(14, Math.round(Math.min(c.width, c.height) / 30));
          ctx.font = `600 ${fs}px system-ui,sans-serif`;
          ctx.textAlign = 'right';
          ctx.shadowColor = 'rgba(0,0,0,.85)'; ctx.shadowBlur = 5;
          ctx.fillText(text, c.width - 14, c.height - 14);
          ctx.restore();
        }
        texImage(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, c);
        c.width = 0; c.height = 0;
        this.#glWmOn = 1;
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
      if (this.#canvas.width !== w || this.#canvas.height !== h) {
        this.#canvas.width = w; this.#canvas.height = h;
      }
      gl.viewport(0, 0, w, h);
      gl.useProgram(this.#glProg);
      const L = this.#glLoc;
      const meta = this.#glMeta || this.#meta;
      gl.uniform1i(L.uTex, 0); gl.uniform1i(L.uMap, 1); gl.uniform1i(L.uWm, 2);
      gl.uniform1f(L.uGrid, meta.plan ? meta.plan.grid : 1);
      gl.uniform2f(L.uCrop, meta.origW / meta.padW, meta.origH / meta.padH);
      // fit
      const srcRatio = meta.origW / meta.origH;
      const dstRatio = w / h;
      let sx = 1, sy = 1, ox = 0, oy = 0;
      if (this.#options.fit === 'cover') {
        if (srcRatio > dstRatio) { sx = dstRatio / srcRatio; ox = (1 - sx) / 2; }
        else { sy = srcRatio / dstRatio; oy = (1 - sy) / 2; }
      } else if (this.#options.fit === 'contain') {
        if (srcRatio > dstRatio) { sy = srcRatio / dstRatio; oy = -(sy - 1) / 2; sy = 1 / sy; oy = (1 - sy) / 2; /* letterbox via scale>range guarded in shader */ }
        // For contain, invert: scale uv beyond [0,1] and let shader black-bar it
        if (srcRatio > dstRatio) { const s = srcRatio / dstRatio; sy = s; oy = -(s - 1) / 2; sx = 1; ox = 0; }
        else { const s = dstRatio / srcRatio; sx = s; ox = -(s - 1) / 2; }
      }
      gl.uniform2f(L.uFitScale, sx, sy);
      gl.uniform2f(L.uFitOffset, ox, oy);
      gl.uniform1f(L.uScrambled, meta.plan ? 1 : 0);
      gl.uniform1f(L.uSeed, (hashSeed(sessionId()) % 1000) / 37.0);
      gl.uniform1f(L.uWmOn, this.#glWmOn || 0);
      const lensCfg = typeof this.#options.lens === 'object' && this.#options.lens ? this.#options.lens : {};
      gl.uniform1f(L.uLensOn, this.#options.lens ? 1 : 0);
      gl.uniform1f(L.uLensActive, this.#lensPoint ? 1 : 0);
      gl.uniform2f(L.uLensCenter, this.#lensPoint?.x ?? -10, this.#lensPoint?.y ?? -10);
      gl.uniform1f(L.uLensRadius, Math.max(24, Math.min(w, h) * (lensCfg.radius ?? 0.30)));
      gl.uniform2f(L.uResolution, w, h);
      gl.uniform1f(L.uLocked, Date.now() < this.#lockedUntil ? 1 : 0);
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
    const g = this.#options.guards;
    const relevant = (kind === 'blur' && g.blurOnBlur) || (kind === 'hidden' && g.blurOnBlur) ||
      (kind === 'print' && g.print) || (kind === 'devtools' && g.devtools);
    if (!relevant) return;
    if (on) this.#risk.add(kind); else this.#risk.delete(kind);
    this.#wrap.classList.toggle('risk-on', this.#risk.size > 0);
  }
  _momentaryBlackout(ms, kind) {
    if (kind === 'screenshot-key' && !this.#options.guards.screenshotKeys) return;
    this.#wrap.classList.add('blackout');
    if (this.#attemptHandler) this.#attemptHandler(kind);
    clearTimeout(this.#blackoutTimer);
    this.#blackoutTimer = setTimeout(() => this.#wrap.classList.remove('blackout'), ms);
  }

  /* ---------------- public per-instance API ---------------- */
  get loaded() { return this.#loaded; }
  get element() { return this.#host; }
  /**
   * Test/debug hook — returns internals ONLY when this instance was created
   * with `debug: true`. There is deliberately no way to switch this on for
   * an existing instance from outside (options are private + sanitised).
   * Never enable in production pages.
   */
  _debug() {
    if (this.#options.debug !== true) return null;
    return {
      canvas: this.#canvas,
      tiles: [...this.#tilesEl.querySelectorAll('canvas')],
      wrap: this.#wrap,
      meta: this.#meta,
      integrityIssues: [...this.#integrityIssues],
      strikes: this.#strikes,
      locked: Date.now() < this.#lockedUntil,
      lens: this.#lensPoint ? { ...this.#lensPoint } : null,
      bitmapReleased: this.#bitmapReleased,
      glScrambledTexture: !!(this.#glMeta && this.#glMeta.plan),
      captureTraceOn: this.#wrap.classList.contains('trace-on'),
      traceText: this.#traceEl?.textContent?.trim() || '',
    };
  }
  async reload(newSource) {
    if (newSource !== undefined) this.#source = newSource;
    this.#loaded = false;
    this.#wrap.classList.add('loading');
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
    if (visibilityObserver) visibilityObserver.unobserve(this.#host);
    if (this.#canvas) { this.#canvas.width = 0; this.#canvas.height = 0; }
    if (this.#decoy) { this.#decoy.width = 0; this.#decoy = null; }
    if (this.#frameCanvas) { this.#frameCanvas.width = 0; this.#frameCanvas.height = 0; this.#frameCanvas = null; }
    if (this.#lensBase) { this.#lensBase.width = 0; this.#lensBase.height = 0; this.#lensBase = null; }
    if (this.#lensRaf) cancelAnimationFrame(this.#lensRaf);
    if (this.#traceTimer) clearInterval(this.#traceTimer);
    this.#traceTimer = 0;
    clearTimeout(this.#lockTimer);
    // Only strict (uncached) bitmaps are exclusively ours to close; a
    // standard-mode bitmap may be shared from the LRU by other instances.
    if (this.#options.memory === 'strict') {
      try { this.#bitmap?.close && this.#bitmap.close(); } catch {}
    }
    this.#bitmap = null;
    this.#root.replaceChildren?.();
    hostToInstance.delete(this.#host);
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
  const galleryDefaults = { mode: 'lite', unloadOnExit: true, sourceOversample: 1.5 };
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
  // Element -> instance in a WeakMap: no public `_inst` handle on the DOM node.
  const elementInstances = new WeakMap();
  class ArchxImage extends HTMLElement {
    static get observedAttributes() { return ['src', 'image-id', 'mode', 'watermark', 'alt', 'fit', 'grid', 'key', 'scrambled', 'lens', 'capture-shield', 'on-extract', 'token-endpoint']; }
    connectedCallback() {
      if (elementInstances.has(this)) return;
      this.style.display = this.style.display || 'block';
      const inner = document.createElement('div');
      inner.style.width = '100%'; inner.style.height = '100%';
      this.appendChild(inner);
      const id = this.getAttribute('image-id');
      const src = id ? { id } : this.getAttribute('src');
      const inst = new ProtectedImage(inner, src, {
        mode: this.getAttribute('mode') || undefined,
        watermark: this.getAttribute('watermark') || undefined,
        alt: this.getAttribute('alt') || '',
        fit: this.getAttribute('fit') || undefined,
        grid: this.getAttribute('grid') ? Number(this.getAttribute('grid')) : undefined,
        key: this.getAttribute('key') || undefined,
        scrambled: this.hasAttribute('scrambled'),
        lens: this.hasAttribute('lens') ? true : undefined,
        captureShield: this.hasAttribute('capture-shield') ? true : undefined,
        onExtract: this.getAttribute('on-extract') || undefined,
        tokenEndpoint: this.getAttribute('token-endpoint') || undefined,
      });
      elementInstances.set(this, inst);
      this.ready = inst.ready;
    }
    disconnectedCallback() {
      const inst = elementInstances.get(this);
      if (inst) { inst.destroy(); elementInstances.delete(this); }
    }
    attributeChangedCallback(name, oldV, newV) {
      const inst = elementInstances.get(this);
      if (!inst || oldV === newV) return;
      if (name === 'src' && newV) inst.reload(newV);
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
    // Never echo secrets back: any page script may call config() with no args.
    return sanitizeOptionsView(globalConfig);
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
  /** Number of live protected images (the registry itself stays private). */
  get instanceCount() { return instances.size; },
  /** Names of browser APIs that currently look monkey-patched. */
  auditIntegrity,
  /** Cheap headless/automation signals present in this browser. */
  detectAutomation,
};

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', defineElement, { once: true });
  } else defineElement();
}

export default Archx;
