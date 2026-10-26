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
  hashSeed, mulberry32, DEFAULT_GRID, sniffImageInfo,
} from './scramble.js';

export const VERSION = '1.5.0';

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
  mode: 'shield',               // 'lite' | 'shield' | 'vault' | 'fortress' | 'custom'
  renderer: 'auto',             // 'auto' | 'canvas' | 'webgl' — direct renderer flag (lets custom setups skip preset modes)
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
  tokenMethod: 'POST',          // token mint method; POST + X-Archx-Request avoids simple cross-site GET minting
  tokenTransport: 'header',     // 'header' | 'query' | 'auto' — header keeps bearer tokens out of image URLs/logs
  proofOfPossession: 'auto',    // 'auto' | 'required' | 'off' — bind tokens to a non-extractable page key when WebCrypto allows
  allowedTokenOrigins: null,    // exact extra origins allowed for token-returned payload URLs (endpoint origin is always allowed)
  fetchTimeoutMs: 20000,        // per-request network deadline (mint, payload, and direct sources)
  maxResponseBytes: 64 * 1024 * 1024,
  maxDecodedPixels: 40000000,   // pre-decode header budget + post-decode bitmap budget
  maxDecodedDimension: 16384,
  onExtract: 'black',           // 'black' | 'lowres' | 'scrambled'
  splitCanvases: false,         // shield+: one canvas per tile (hero images)
  splitGrid: 3,
  maxBackingWidth: 1920,        // never paint a wider backing store than this
  dprCap: 3,                    // match modern retina/mobile displays instead of upscaling a 2x canvas
  sourceOversample: 2,          // fetch a 2x derivative then supersample down (server entitlement still caps the signed width)
  maxSourceWidth: 2560,         // client-side ceiling before the server's own entitlement cap
  qualityProfile: 'high',       // 'original' | 'high' | 'balanced' | 'fast' (sets requestQuality + sampling unless overridden)
  requestQuality: null,         // 1..100 | 'lossless' — honoured only when the server opts in with allowClientQuality
  cacheBitmap: true,            // reuse a decoded bitmap for the same source in this page session
  bitmapCacheMaxEntries: 40,
  bitmapCacheMaxBytes: 256 * 1024 * 1024, // approximate decoded RGBA bytes in the shared LRU
  cachePayload: true,           // retain the scrambled bytes privately so repaint/strict-memory recovery needs NO network reload
  cacheScope: null,             // set per authenticated viewer/tenant so SPA account switches cannot reuse another viewer's bitmap
  reloadOnResize: 'upscale',    // 'never' | 'upscale' | 'always' — ordinary resizes repaint locally, never remint tokens
  resizeUpscaleFactor: 1.75,    // only a much larger box may justify a fresh derivative under 'upscale'
  renderLoop: 'auto',           // 'auto' (static images draw on demand; temporal shield animates) | 'static' | 'continuous'
  temporalShield: null,         // true | { strength, block, pattern, chroma, respectReducedMotion } — complementary frames a single screenshot cannot average
  temporalInterlace: null,      // true | 'balanced60'|'pixels60'|'strips60'|'blocks60' | { profile, engine, layout, phases, cellSize, fill, refreshHz, ... }
  cameraShield: null,           // experimental alias/profile for temporalShield aimed at rolling-shutter/Bayer cameras
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
  // Quality profiles are shortcuts, not black boxes: every value below can
  // still be overridden directly (sourceOversample / dprCap / requestQuality).
  const qualityProfiles = {
    original: { requestQuality: 'lossless', sourceOversample: 2, dprCap: 3 },
    high: { requestQuality: 95, sourceOversample: 2, dprCap: 3 },
    balanced: { requestQuality: 90, sourceOversample: 1.5, dprCap: 2.5 },
    fast: { requestQuality: 82, sourceOversample: 1.25, dprCap: 2 },
  };
  const qp = qualityProfiles[merged.qualityProfile];
  if (qp) {
    if (clean.requestQuality === undefined && merged.requestQuality == null) merged.requestQuality = qp.requestQuality;
    if (clean.sourceOversample === undefined && clean.qualityProfile !== undefined) merged.sourceOversample = qp.sourceOversample;
    if (clean.dprCap === undefined && clean.qualityProfile !== undefined) merged.dprCap = qp.dprCap;
  }
  // Direct-flag mode: `mode: 'custom'` (or simply omitting `mode` while
  // passing `renderer`) applies NO preset bundle. The caller chooses the
  // renderer plus every protection flag explicitly; internally we only map
  // that renderer choice onto the existing canvas/WebGL pipelines.
  const rendererValue = String(merged.renderer || 'auto').toLowerCase();
  merged.renderer = (rendererValue === 'canvas' || rendererValue === 'webgl') ? rendererValue : 'auto';
  const customRequested = merged.mode === 'custom' ||
    (clean.mode === undefined && clean.renderer !== undefined);
  if (customRequested) {
    merged.requestedMode = 'custom';
    merged.mode = merged.renderer === 'webgl' ? 'vault' : 'shield';
  }
  // Lite is the one preset that historically skipped client forensic marks.
  // Preserve that default, but let an explicit `forensic: true` flag win.
  if (merged.mode === 'lite' && clean.forensic === undefined) merged.forensic = false;

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
    if (clean.temporalShield === undefined
      && clean.cameraShield === undefined
      && !normalizeTemporalInterlace(merged.temporalInterlace)) {
      merged.temporalShield = { strength: 0.16, block: 2, pattern: 'checker', chroma: true };
    }
    if (clean.strikes === undefined) merged.strikes = { blurAt: 3, lockAt: 6, lockMs: 30000 };
    if (!opts.guards || opts.guards.devtools === undefined) merged.guards.devtools = true;
  }
  return merged;
}

function sanitizeOptionsView(opts) {
  if (!opts) return opts;
  const sensitive = new Set([
    'key', 'aeskey', 'cachescope', 'sessionid', 'token', 'accesstoken', 'refreshtoken',
    'secret', 'password', 'authorization', 'cookie',
  ]);
  const seen = new WeakMap();
  const clone = (value, keyName = '') => {
    if (sensitive.has(String(keyName).toLowerCase())) return value ? '[redacted]' : value;
    if (!value || typeof value !== 'object') return value; // functions stay host-owned callbacks
    if (seen.has(value)) return '[circular]';
    if (Array.isArray(value)) {
      const out = [];
      seen.set(value, out);
      for (const item of value) out.push(clone(item));
      return out;
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

/** Named, inspectable parameter bundles. Spread one, then override any key:
 *  Archx.load.image(el, src, { ...Archx.preset('commerce'), temporalShield: false }) */
export const PRESETS = Object.freeze({
  gallery: Object.freeze({
    mode: 'lite', qualityProfile: 'balanced', sourceOversample: 1.5, lazy: true,
    unloadOnExit: false, cacheBitmap: true, cachePayload: true, renderLoop: 'static',
    reloadOnResize: 'never', guards: Object.freeze({ blurOnBlur: false }),
  }),
  editorial: Object.freeze({
    mode: 'shield', qualityProfile: 'original', cacheBitmap: true, cachePayload: true,
    renderLoop: 'static', reloadOnResize: 'upscale', forensic: true,
  }),
  commerce: Object.freeze({
    mode: 'vault', qualityProfile: 'original', onExtract: 'black', cacheBitmap: true,
    cachePayload: true, renderLoop: 'static', reloadOnResize: 'upscale', forensic: true,
    captureShield: Object.freeze({ dynamicTrace: true, temporalPattern: true }),
  }),
  screenshotResistant: Object.freeze({
    mode: 'fortress', qualityProfile: 'original', lens: true,
    temporalShield: Object.freeze({ strength: 0.16, block: 2, pattern: 'checker', chroma: true }),
    captureShield: Object.freeze({ dynamicTrace: true, temporalPattern: true }),
    cacheBitmap: true, cachePayload: true, renderLoop: 'auto',
    strikes: Object.freeze({ blurAt: 3, lockAt: 6, lockMs: 30000 }),
  }),
});

export function preset(name = 'editorial', overrides = {}) {
  const base = PRESETS[name];
  if (!base) throw new Error(`Archx: unknown preset "${name}" (known: ${Object.keys(PRESETS).join(', ')})`);
  return {
    ...base,
    ...overrides,
    guards: { ...(base.guards || {}), ...(overrides.guards || {}) },
  };
}

/**
 * 60 Hz-first temporal-interlace profiles. These are deliberately NOT
 * Fortress defaults: at 60 Hz a two-phase subset updates at only 30 Hz, so
 * the safer default partition is fine-grained and its hidden cells retain
 * locally averaged colour instead of dropping to black.
 */
export const TEMPORAL_INTERLACE_PROFILES = Object.freeze({
  balanced60: Object.freeze({
    engine: 'auto', layout: 'checker', cellSize: 2, phases: 2,
    fill: 'lowres', fillBlock: 12, fillStrength: 1,
    refreshHz: 60, minPhaseHz: 30, optimizeRefresh: true,
    respectReducedMotion: true, chroma: true,
  }),
  pixels60: Object.freeze({
    engine: 'auto', layout: 'pixels', cellSize: 1, phases: 2,
    fill: 'lowres', fillBlock: 8, fillStrength: 1,
    refreshHz: 60, minPhaseHz: 30, optimizeRefresh: true,
    respectReducedMotion: true, chroma: true,
  }),
  strips60: Object.freeze({
    engine: 'auto', layout: 'strips', axis: 'rows', cellSize: 2, phases: 2,
    fill: 'lowres', fillBlock: 12, fillStrength: 1,
    refreshHz: 60, minPhaseHz: 30, optimizeRefresh: true,
    respectReducedMotion: true, chroma: true,
  }),
  blocks60: Object.freeze({
    engine: 'auto', layout: 'blocks', cellSize: 8, phases: 2,
    fill: 'lowres', fillBlock: 16, fillStrength: 1,
    refreshHz: 60, minPhaseHz: 30, optimizeRefresh: true,
    respectReducedMotion: true, chroma: true,
  }),
});

function clampTemporalNumber(value, fallback, min, max) {
  const n = Number(value);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback;
}

/** Normalize and bound one temporalInterlace option. Returns null when off. */
export function normalizeTemporalInterlace(raw) {
  if (raw == null || raw === false) return null;
  let input = {};
  let profileName = 'balanced60';
  if (raw === true) {
    input = {};
  } else if (typeof raw === 'string') {
    if (['false', 'off', 'none', 'disabled'].includes(raw.toLowerCase())) return null;
    profileName = TEMPORAL_INTERLACE_PROFILES[raw] ? raw : 'balanced60';
  } else if (isPlainClientObject(raw)) {
    input = raw;
    if (input.enabled === false || input.profile === false) return null;
    if (typeof input.profile === 'string'
      && ['false', 'off', 'none', 'disabled'].includes(input.profile.toLowerCase())) return null;
    // An explicit on:false in the enclosing option object also turns the
    // feature off, which makes page-level overrides easy.
    if (input.enabled === undefined && input.on === false) return null;
    if (typeof input.profile === 'string' && TEMPORAL_INTERLACE_PROFILES[input.profile]) {
      profileName = input.profile;
    }
  } else {
    return null;
  }

  const merged = { ...TEMPORAL_INTERLACE_PROFILES[profileName] };
  for (const [key, value] of Object.entries(input)) {
    if (value !== undefined) merged[key] = value;
  }

  const engineRaw = String(merged.engine || merged.drawingMode || merged.renderMode || 'auto').toLowerCase();
  const engine = ['shader', 'gpu', 'webgl', 'fragment-shader'].includes(engineRaw)
    ? 'shader'
    : ['frames', 'frame', 'pre-rendered', 'prerendered', 'canvas', 'canvas2d', '2d'].includes(engineRaw)
      ? 'frames'
      : 'auto';

  const layoutRaw = String(merged.layout || merged.pattern || 'checker').toLowerCase();
  const layout = layoutRaw === 'bands' || layoutRaw === 'stripes'
    ? 'strips'
    : layoutRaw === 'pixel' || layoutRaw === 'pixel-level'
      ? 'pixels'
      : layoutRaw === 'squares' || layoutRaw === 'checkerboard'
        ? 'checker'
        : layoutRaw === 'random-blocks' || layoutRaw === 'random'
          ? 'blocks'
          : ['pixels', 'strips', 'blocks', 'checker'].includes(layoutRaw) ? layoutRaw : 'checker';

  const requestedPhases = Math.round(clampTemporalNumber(merged.phases, 2, 2, 4));
  const refreshHz = clampTemporalNumber(merged.refreshHz ?? merged.displayHz, 60, 24, 480);
  const minPhaseHz = clampTemporalNumber(merged.minPhaseHz ?? merged.minimumPhaseHz, 30, 1, 240);
  const optimizeRefresh = merged.optimizeRefresh !== false && merged.optimizeForRefresh !== false;
  const maxPhasesAtRefresh = Math.max(2, Math.floor(refreshHz / minPhaseHz));
  const phases = optimizeRefresh
    ? Math.min(requestedPhases, maxPhasesAtRefresh)
    : requestedPhases;

  const hasCellInput = input.cellSize !== undefined
    || input.stripSize !== undefined
    || input.block !== undefined;
  const layoutDefaultCell = layout === 'pixels' ? 1
    : layout === 'blocks' ? 8
      : 2;
  const cellSize = Math.round(clampTemporalNumber(
    merged.cellSize ?? merged.stripSize ?? merged.block,
    hasCellInput ? layoutDefaultCell : (TEMPORAL_INTERLACE_PROFILES[profileName].cellSize || layoutDefaultCell),
    1,
    64,
  ));
  let effectiveCellSize = cellSize;
  if (!hasCellInput && input.layout !== undefined) effectiveCellSize = layoutDefaultCell;

  const fillRaw = String(merged.fill || merged.hiddenFill || 'lowres').toLowerCase();
  const fill = ['blur', 'pixelate', 'pixelated', 'local-average'].includes(fillRaw)
    ? 'lowres'
    : fillRaw === 'complementary' || fillRaw === 'complement'
      ? 'noise'
      : ['lowres', 'dim', 'black', 'noise'].includes(fillRaw) ? fillRaw : 'lowres';
  const fillStrength = clampTemporalNumber(merged.fillStrength, 1, 0, 1);
  const hiddenScale = clampTemporalNumber(merged.hiddenScale ?? merged.hiddenBrightness, 0.3, 0, 1);
  const hiddenEffectiveScale = fill === 'black'
    ? 1 - fillStrength
    : fill === 'dim'
      ? 1 - fillStrength + fillStrength * hiddenScale
      : 1;
  const compensation = clampTemporalNumber(
    merged.compensation ?? merged.brightnessCompensation,
    0.5,
    0,
    1,
  );
  const exactGain = phases - (phases - 1) * hiddenEffectiveScale;
  const computedGain = fill === 'black' || fill === 'dim'
    ? 1 + compensation * (exactGain - 1)
    : 1;
  const activeGain = clampTemporalNumber(merged.activeGain, computedGain, 0.25, 4);

  return Object.freeze({
    profile: profileName,
    engine,
    layout,
    axis: merged.axis === 'columns' || merged.axis === 'vertical' ? 'columns' : 'rows',
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
    respectReducedMotion: merged.respectReducedMotion !== false,
  });
}

/* ---------- shared concurrency limiter (hundreds of images, no jank) */
const limiter = {
  max: 6, active: 0, queue: [], queueHead: 0,
  run(fn) {
    return new Promise((resolve, reject) => {
      const job = () => {
        this.active++;
        Promise.resolve().then(fn).then(resolve, reject).finally(() => {
          this.active--;
          const next = this.queueHead < this.queue.length ? this.queue[this.queueHead++] : null;
          if (this.queueHead >= this.queue.length) { this.queue.length = 0; this.queueHead = 0; }
          else if (this.queueHead > 1024 && this.queueHead * 2 >= this.queue.length) {
            this.queue.splice(0, this.queueHead); this.queueHead = 0;
          }
          if (next) next();
        });
      };
      if (this.active < this.max) job(); else this.queue.push(job);
    });
  },
};

/* ---------- decoded-bitmap LRU (scrambled pixels only, never clean DOM) */
const bitmapCache = new Map(); // digest -> { promise, result, refs, bytes, settled }
let bitmapCacheBytes = 0;

function bitmapEstimatedBytes(result) {
  const bitmap = result?.bitmap;
  const w = bitmap?.width || bitmap?.naturalWidth || result?.meta?.padW || 0;
  const h = bitmap?.height || bitmap?.naturalHeight || result?.meta?.padH || 0;
  const bytes = w * h * 4;
  return Number.isFinite(bytes) && bytes > 0 ? Math.ceil(bytes) : 0;
}

function closeBitmapQuietly(bitmap) {
  try { bitmap?.close?.(); } catch {}
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
  while (bitmapCache.size > entryLimit || (byteLimit > 0 && bitmapCacheBytes > byteLimit)) {
    const oldest = bitmapCache.keys().next().value;
    if (oldest === undefined) break;
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
  bitmapCache.delete(key); bitmapCache.set(key, entry);
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

/* ---------- shared observers */
const visibilityObservers = new Map(); // rootMargin -> IntersectionObserver
function getVisibilityObserver(rootMargin = '500px') {
  const margin = typeof rootMargin === 'string' && rootMargin.length <= 64 ? rootMargin : '500px';
  let observer = visibilityObservers.get(margin);
  if (!observer) {
    const callback = (entries) => {
      for (const e of entries) {
        const inst = hostToInstance.get(e.target);
        if (inst) inst._onVisibility(e.isIntersecting);
      }
    };
    try { observer = new IntersectionObserver(callback, { rootMargin: margin }); }
    catch { observer = new IntersectionObserver(callback, { rootMargin: '500px' }); }
    visibilityObservers.set(margin, observer);
  }
  return observer;
}

let sharedResizeObserver = null;
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

function cyrb53(str, seed = 0) {
  let h1 = 0xdeadbeef ^ seed;
  let h2 = 0x41c6ce57 ^ seed;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return 4294967296 * (2097151 & h2) + (h1 >>> 0);
}

/* Cache keys are digests, not a second long-lived copy of raw URLs, tenant
 * scopes, scramble keys, or AES material. Two independent 53-bit hashes make
 * accidental cross-image collisions negligible for an in-memory page cache. */
function cacheDigest(parts) {
  const raw = JSON.stringify(parts);
  return `v1:${raw.length}:${cyrb53(raw, 1).toString(36)}:${cyrb53(raw, 2).toString(36)}`;
}

function boundedInteger(value, fallback, min, max) {
  return Number.isInteger(value) && value >= min && value <= max ? value : fallback;
}

function fetchControls(o = {}) {
  return {
    maxResponseBytes: boundedInteger(o.maxResponseBytes, DEFAULTS.maxResponseBytes, 1024, 512 * 1024 * 1024),
    fetchTimeoutMs: boundedInteger(o.fetchTimeoutMs, DEFAULTS.fetchTimeoutMs, 100, 120000),
    maxDecodedPixels: boundedInteger(o.maxDecodedPixels, DEFAULTS.maxDecodedPixels, 10000, 268402689),
    maxDecodedDimension: boundedInteger(o.maxDecodedDimension, DEFAULTS.maxDecodedDimension, 64, 65536),
    retries: boundedInteger(o.retries, 2, 0, 5),
    credentials: ['omit', 'same-origin', 'include'].includes(o.credentials) ? o.credentials : 'same-origin',
  };
}

function nonRetryableError(message, code = 'ARCHX_INVALID_RESPONSE') {
  const err = new Error(message);
  err.code = code;
  err.nonRetryable = true;
  return err;
}

function signalWithTimeout(parentSignal, timeoutMs) {
  const ms = Math.max(0, Math.floor(Number(timeoutMs) || 0));
  try {
    if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function' &&
        typeof AbortSignal.any === 'function') {
      const signals = [];
      if (parentSignal) signals.push(parentSignal);
      if (ms > 0) signals.push(AbortSignal.timeout(ms));
      return {
        signal: signals.length === 1 ? signals[0] : AbortSignal.any(signals),
        cleanup() {},
      };
    }
  } catch { /* fall through to the manual controller */ }
  const controller = new AbortController();
  let timer = 0;
  const onParentAbort = () => {
    try { controller.abort(parentSignal?.reason); } catch { controller.abort(); }
  };
  if (parentSignal?.aborted) onParentAbort();
  else parentSignal?.addEventListener?.('abort', onParentAbort, { once: true });
  if (ms > 0) {
    timer = setTimeout(() => {
      let reason;
      try { reason = new DOMException('Archx fetch timed out', 'TimeoutError'); } catch {}
      try { controller.abort(reason); } catch { controller.abort(); }
    }, ms);
  }
  return {
    signal: controller.signal,
    cleanup() {
      if (timer) clearTimeout(timer);
      parentSignal?.removeEventListener?.('abort', onParentAbort);
    },
  };
}

async function readResponseBytes(response, maxBytes) {
  const limit = Math.max(1, Math.floor(Number(maxBytes) || 1));
  const lengthRaw = response.headers?.get?.('content-length');
  if (lengthRaw != null) {
    const declared = Number(lengthRaw);
    if (!Number.isSafeInteger(declared) || declared < 0 || declared > limit) {
      try { await response.body?.cancel?.(); } catch {}
      throw nonRetryableError('Archx: response exceeds the configured byte limit', 'ARCHX_RESPONSE_TOO_LARGE');
    }
  }
  if (!response.body?.getReader) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length > limit) {
      throw nonRetryableError('Archx: response exceeds the configured byte limit', 'ARCHX_RESPONSE_TOO_LARGE');
    }
    return bytes;
  }
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value || []);
      total += chunk.length;
      if (total > limit) {
        try { await reader.cancel(); } catch {}
        throw nonRetryableError('Archx: response exceeds the configured byte limit', 'ARCHX_RESPONSE_TOO_LARGE');
      }
      if (chunk.length) chunks.push(chunk);
    }
  } finally {
    try { reader.releaseLock(); } catch {}
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.length; }
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
        try { await response.body?.cancel?.(); } catch {}
        return { response, bytes: null };
      }
      if (!response.ok) {
        try { await response.body?.cancel?.(); } catch {}
        const err = new Error('Archx fetch failed: HTTP ' + response.status);
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
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function parseBoundedJson(bytes) {
  let value;
  try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { throw nonRetryableError('Archx: token endpoint returned invalid JSON'); }
  if (!isPlainClientObject(value)) throw nonRetryableError('Archx: token endpoint returned an invalid response');
  return value;
}

function resolveHttpUrl(raw, { base, label = 'URL', protocols = ['http:', 'https:'] } = {}) {
  if (typeof raw !== 'string' || !raw || raw.length > 16384 || /[\u0000-\u0020\u007f]/.test(raw)) {
    throw nonRetryableError(`Archx: invalid ${label}`);
  }
  let url;
  try {
    const fallbackBase = typeof document !== 'undefined' ? document.baseURI : undefined;
    url = new URL(raw, base || fallbackBase);
  } catch { throw nonRetryableError(`Archx: invalid ${label}`); }
  if (!protocols.includes(url.protocol) || url.username || url.password) {
    throw nonRetryableError(`Archx: disallowed ${label}`);
  }
  return url;
}

function exactOriginSet(values, endpointUrl) {
  const origins = new Set();
  if (endpointUrl?.origin) origins.add(endpointUrl.origin);
  const list = values == null ? [] : (Array.isArray(values) ? values : [values]);
  for (const value of list) {
    if (typeof value !== 'string' || !value || value.length > 512) {
      throw nonRetryableError('Archx: allowedTokenOrigins must contain exact origins');
    }
    let parsed;
    try { parsed = new URL(value); } catch { throw nonRetryableError('Archx: allowedTokenOrigins must contain exact origins'); }
    const trimmed = value.endsWith('/') ? value.slice(0, -1) : value;
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.origin !== trimmed) {
      throw nonRetryableError('Archx: allowedTokenOrigins must contain exact origins');
    }
    origins.add(parsed.origin);
  }
  return origins;
}

function assertResponseFinalOrigin(response, origins) {
  if (!response?.url) return;
  let finalUrl;
  try { finalUrl = new URL(response.url); }
  catch { throw nonRetryableError('Archx: response redirected to an invalid URL'); }
  if (!['http:', 'https:'].includes(finalUrl.protocol) || !origins.has(finalUrl.origin)) {
    throw nonRetryableError('Archx: response came from an untrusted origin');
  }
}

function validTokenString(value, { min = 1, max = 512, pattern = null } = {}) {
  return typeof value === 'string' && value.length >= min && value.length <= max &&
    !/[\u0000-\u001f\u007f]/.test(value) && (!pattern || pattern.test(value));
}

function bytesToBase64Url(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
  let binary = '';
  const chunkSize = 32768;
  for (let i = 0; i < view.length; i += chunkSize) {
    binary += String.fromCharCode(...view.subarray(i, Math.min(view.length, i + chunkSize)));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

let proofKeyPromise = null;

/**
 * One ephemeral ECDSA P-256 key pair per page. The private key is created
 * non-extractable, so ordinary page tooling cannot export it and replay a
 * copied image token in another browser. This is a token-theft control, not
 * DRM: script already running in this page, a malicious extension, or the
 * browser operator can still ask the page to load/display an authorized image.
 */
function getProofKey(required = false) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle?.generateKey || !subtle?.exportKey || !subtle?.sign || !subtle?.digest ||
      !globalThis.crypto?.getRandomValues) {
    if (required) return Promise.reject(nonRetryableError('Archx: proof-of-possession requires WebCrypto'));
    return Promise.resolve(null);
  }
  if (!proofKeyPromise) {
    proofKeyPromise = (async () => {
      const pair = await subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify'],
      );
      const exported = await subtle.exportKey('jwk', pair.publicKey);
      if (!exported || exported.kty !== 'EC' || exported.crv !== 'P-256' ||
          typeof exported.x !== 'string' || typeof exported.y !== 'string') {
        throw new Error('unsupported proof public key');
      }
      const jwk = { kty: 'EC', crv: 'P-256', x: exported.x, y: exported.y };
      const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
      const thumbprint = bytesToBase64Url(await subtle.digest('SHA-256', new TextEncoder().encode(canonical)));
      return Object.freeze({
        privateKey: pair.privateKey,
        jwk: Object.freeze(jwk),
        jkt: thumbprint,
        header: bytesToBase64Url(new TextEncoder().encode(JSON.stringify(jwk))),
      });
    })().catch((err) => {
      proofKeyPromise = null;
      throw err;
    });
  }
  return proofKeyPromise.catch((err) => {
    if (required) throw nonRetryableError('Archx: proof-of-possession key generation failed');
    return null;
  });
}

async function createProofHeader(proofKey, accessToken, payloadUrl) {
  if (!proofKey || !accessToken) return null;
  const subtle = globalThis.crypto?.subtle;
  if (!subtle?.sign || !subtle?.digest) throw nonRetryableError('Archx: proof-of-possession signing is unavailable');
  const now = Date.now();
  const random = new Uint8Array(18);
  globalThis.crypto.getRandomValues(random);
  const proof = {
    jwk: proofKey.jwk,
    jti: bytesToBase64Url(random),
    iat: now,
    exp: now + 60000,
    htm: 'GET',
    htu: payloadUrl.pathname,
    ath: bytesToBase64Url(await subtle.digest('SHA-256', new TextEncoder().encode(accessToken))),
  };
  const payloadPart = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(proof)));
  const signingInput = `v1.${payloadPart}`;
  const signature = await subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    proofKey.privateKey,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${bytesToBase64Url(signature)}`;
}

function parseTokenResponse(raw, options, endpointUrl) {
  if (!isPlainClientObject(raw)) throw nonRetryableError('Archx: token endpoint returned an invalid response');
  if (!validTokenString(raw.key, { min: 1, max: 512 })) throw nonRetryableError('Archx: token response has an invalid key');
  if (!Number.isInteger(raw.grid) || raw.grid < 2 || raw.grid > 32) throw nonRetryableError('Archx: token response has an invalid grid');
  if (raw.aesKey !== undefined && !validTokenString(raw.aesKey, { min: 16, max: 256 })) {
    throw nonRetryableError('Archx: token response has an invalid AES key');
  }
  if (raw.exp !== undefined && (!Number.isSafeInteger(raw.exp) || raw.exp <= Date.now() - 300000)) {
    throw nonRetryableError('Archx: token response is expired');
  }
  const separateToken = raw.token;
  if (separateToken !== undefined &&
      !validTokenString(separateToken, { min: 16, max: 8192, pattern: /^[A-Za-z0-9._~-]+$/ })) {
    throw nonRetryableError('Archx: token response has an invalid token');
  }
  const rawUrl = raw.cleanUrl ?? raw.url;
  const candidate = resolveHttpUrl(rawUrl, { base: endpointUrl.href, label: 'token payload URL' });
  const allowedOrigins = exactOriginSet(options.allowedTokenOrigins, endpointUrl);
  if (!allowedOrigins.has(candidate.origin)) {
    throw nonRetryableError('Archx: token payload URL points to an untrusted origin');
  }
  const payloadUrl = new URL(candidate.href);
  const queryTokens = payloadUrl.searchParams.getAll('t');
  if (queryTokens.length > 1) throw nonRetryableError('Archx: token payload URL is ambiguous');
  const requestedTransport = String(options.tokenTransport || 'header').toLowerCase();
  const transport = ['header', 'query', 'auto'].includes(requestedTransport) ? requestedTransport : 'header';
  let headerToken = null;
  let accessToken = separateToken || queryTokens[0] || null;
  if (transport === 'header' || (transport === 'auto' && separateToken)) {
    headerToken = separateToken || null;
    if (queryTokens.length === 1) {
      if (headerToken && headerToken !== queryTokens[0]) throw nonRetryableError('Archx: token response is ambiguous');
      headerToken = queryTokens[0];
      payloadUrl.searchParams.delete('t');
    }
    if (!validTokenString(headerToken, { min: 16, max: 8192, pattern: /^[A-Za-z0-9._~-]+$/ })) {
      throw nonRetryableError('Archx: token response did not include a header token');
    }
    accessToken = headerToken;
  } else {
    if (separateToken && queryTokens.length === 1 && separateToken !== queryTokens[0]) {
      throw nonRetryableError('Archx: token response is ambiguous');
    }
    if (queryTokens.length === 0) {
      if (!separateToken) throw nonRetryableError('Archx: token response did not include a payload token');
      payloadUrl.searchParams.set('t', separateToken);
    }
  }
  const extra = { key: raw.key, grid: raw.grid };
  if (raw.aesKey !== undefined) extra.aesKey = raw.aesKey;
  return Object.freeze({ extra: Object.freeze(extra), payloadUrl, headerToken, accessToken, allowedOrigins });
}

function asByteArray(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  throw nonRetryableError('Archx: image source must be bytes');
}

function setSmoothing(ctx, enabled) {
  ctx.imageSmoothingEnabled = enabled;
  if (enabled) {
    try { ctx.imageSmoothingQuality = 'high'; } catch {}
  }
}

/**
 * Draw with browser-native high-quality resampling. Large reductions go via
 * a destination-anchored 2× intermediate (recursively for very large jumps)
 * instead of repeatedly halving the full source frame. In Chromium this
 * measured materially closer to an ordinary <img> downscale than either one
 * huge drawImage jump or full-frame progressive halving, both of which can
 * make fine photo detail look slurry.
 */
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
  const ictx = getNativeContext(intermediate, '2d');
  drawImageHighQuality(
    ictx, source, sx, sy, sw, sh,
    0, 0, intermediate.width, intermediate.height,
  );
  setSmoothing(ctx, true);
  nativeDrawImage(ctx, intermediate, 0, 0, intermediate.width, intermediate.height, dx, dy, dw, dh);
  intermediate.width = 0; intermediate.height = 0;
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
  #risk = new Set(); #blackoutTimer = 0; #resizeTimer = 0; #visibilityObs = null; #realCtx = null;
  #attemptHandler = null; #loading = false; #visible = false; #unloaded = false;
  #glProg = null; #glLoc = null; #glTex = null; #glMap = null; #glWm = null; #glWmOn = 0;
  #glSource = null; #glMeta = null; #frameCanvas = null; #lensBase = null;
  #lensPoint = null; #lensRaf = 0; #lensCells = [];
  #traceEl = null; #traceTimer = 0;
  #strikes = 0; #lockedUntil = 0; #lockTimer = 0; #integrityIssues = [];
  #bitmapReleased = false;
  #loadedOnce = false; #cachedBytes = null; #cachedExtra = null; #bitmapCacheEntry = null;
  #renderedW = 0; #renderedH = 0; #deviceBox = null;
  #glFrameBudget = 0; #glFrames = 0; #temporalSign = 1; #temporalPhase = 0;
  #temporalRaf = 0; #temporalFrames = null; #temporalIndex = 0; #temporalEngineActual = null;
  #temporalInterlaceCache = undefined;

  /** Sanitised, secret-free view of the effective options. */
  get options() { return sanitizeOptionsView(this.#options); }

  constructor(target, source, options = {}) {
    this.#options = mergeOptions(options);
    this.#source = source;
    const host = $(target);
    if (!host) throw new Error('Archx: target element not found: ' + target);
    if (hostToInstance.has(host)) {
      throw new Error('Archx: target element already hosts a live protected image; destroy it or use a fresh host');
    }
    this.#host = host;
    host.classList.add('archx-host');
    if (this.#options.alt) {
      host.setAttribute('role', 'img');
      host.setAttribute('aria-label', this.#options.alt);
    }
    this._buildDom();
    this._attachGuards();
    this._startCaptureTrace();
    hostToInstance.set(host, this);
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
      } catch {
        // Never silently downgrade a requested closed/open shadow root to
        // light DOM: that would expose exactly the canvases this library is
        // meant to keep out of the page tree. `shadow:'none'` remains the
        // explicit opt-out for hosts that truly want light DOM.
        throw new Error('Archx: unable to attach the requested shadow root; use a fresh host element or shadow:"none" explicitly');
      }
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
    if (this.#gl) { this._startGlLoop(2); return; }
    if (this.#lensRaf || !this.#frameCanvas) return;
    this.#lensRaf = requestAnimationFrame(() => {
      this.#lensRaf = 0;
      this.#paintLens2d();
    });
  }

  #isTokenSource() {
    const src = this.#source;
    return !!(src && typeof src === 'object' && !(src instanceof Blob) &&
      !(src instanceof ArrayBuffer) && !ArrayBuffer.isView(src) && src.id);
  }

  /**
   * Only a token source can produce a *different, larger* derivative. For it,
   * a large host growth (or explicit reloadOnResize:'always') may justify one
   * fresh mint; every ordinary resize remains a local repaint.
   */
  #shouldUpgradeDerivative(previousW, previousH) {
    if (!this.#loadedOnce || !this.#meta || !this.#visible || !this.#isTokenSource()) return false;
    const policy = this.#options.reloadOnResize;
    if (policy === 'never') return false;
    let size;
    try { size = this._backingSize(); } catch { return false; }
    if (policy === 'always') return size.w !== previousW || size.h !== previousH;
    if (policy !== 'upscale') return false;
    const factor = Math.max(1, this.#options.resizeUpscaleFactor || 1.75);
    return !!((previousW && size.w > previousW * factor) ||
      (previousH && size.h > previousH * factor));
  }

  _onVisibility(visible) {
    this.#visible = visible;
    if (visible && !this.#loaded && !this.#loading) this._load();
    if (visible && this.#loaded && this.#unloaded) {
      // A once-loaded image must not phone home just because it scrolled:
      // repaint from the retained bitmap / GL texture when we still have one,
      // and only fall back to resolving bytes (which itself prefers the
      // privately cached scrambled payload) when nothing displayable remains.
      this.#unloaded = false;
      if (this.#gl) this._startGlLoop(2);
      else if (this.#bitmap) this._render();
      else this._load();
    }
    if (!visible && this.#options.unloadOnExit && this.#loaded) this._unloadPixels();
    if (!visible) this.#stopTemporal2d();
    else if (this.#temporalFrames) this.#startTemporal2d();
    if (this.#gl) visible ? this._startGlLoop(2) : this._stopGlLoop();
  }

  _onResize(entry) {
    const box = entry?.devicePixelContentBoxSize?.[0];
    if (box && box.inlineSize > 0 && box.blockSize > 0) {
      this.#deviceBox = { w: box.inlineSize, h: box.blockSize };
    }
    clearTimeout(this.#resizeTimer);
    this.#resizeTimer = setTimeout(() => {
      if (this.#destroyed) return;
      const previousW = this.#renderedW;
      const previousH = this.#renderedH;
      const upgrade = this.#shouldUpgradeDerivative(previousW, previousH);
      if (this.#gl) {
        this._startGlLoop(2);
        if (upgrade) void this._load({ force: true });
        return;
      }
      if (this.#bitmap) {
        this._render();
        if (upgrade) void this._load({ force: true });
      } else if (this.#loaded && this.#bitmapReleased && this.#visible) {
        // Strict memory: ordinary resizes keep the already-painted canvas
        // (the browser scales it) instead of reminting a one-time token.
        // A configurable large upscale is the one exception. Token sources
        // force a fresh, adequately sized derivative; other sources simply
        // decode the privately cached payload locally.
        const policy = this.#options.reloadOnResize;
        if (policy === 'always') void this._load({ force: this.#isTokenSource() });
        else if (policy === 'upscale' && this.#meta) {
          const { w, h } = this._backingSize();
          const f = Math.max(1, this.#options.resizeUpscaleFactor || 1.75);
          if (w > previousW * f || h > previousH * f) {
            void this._load({ force: this.#isTokenSource() });
          }
        }
      }
    }, 90);
  }

  async _init() {
    const resizeObserver = getResizeObserver();
    try { resizeObserver.observe(this.#host, { box: 'device-pixel-content-box' }); }
    catch { resizeObserver.observe(this.#host); }

    if (this.#options.lazy && 'IntersectionObserver' in window) {
      this.#visibilityObs = getVisibilityObserver(this.#options.rootMargin);
      this.#visibilityObs.observe(this.#host);
      // _load fires from observer; also kick if already on screen pre-observe.
      const r = this.#host.getBoundingClientRect();
      if (r.bottom > 0 && r.top < innerHeight) this._load();
    } else {
      this.#visible = true;
      await this._load();
    }
    return this;
  }

  /* ---------------- source resolution ---------------- */
  /**
   * Effective temporal config, or null when disabled / reduced-motion.
   * Legacy temporalShield/cameraShield complementary noise and the newer
   * literal temporalInterlace can be used independently or combined.
   */
  #temporalConfig() {
    const o = this.#options;
    const reducedMotion = typeof matchMedia === 'function'
      && matchMedia('(prefers-reduced-motion: reduce)').matches;

    // A truthy cameraShield is the more specific direct flag, so it wins
    // over a preset's generic temporalShield. `cameraShield:false` merely
    // means "no camera-specific override" and leaves temporalShield alone.
    let raw = o.cameraShield || o.temporalShield;
    if (raw == null && o.captureShield && typeof o.captureShield === 'object') {
      raw = o.captureShield.temporalDither;
    }
    let noise = null;
    if (raw) {
      const cfg = raw === true ? {} : raw;
      const respected = !cfg || cfg.respectReducedMotion === false || !reducedMotion;
      if (cfg && cfg.enabled !== false && respected) {
        const pattern = ['blocks', 'checker', 'bands'].includes(cfg.pattern) ? cfg.pattern : 'blocks';
        const engineRaw = String(cfg.engine || cfg.drawingMode || 'auto').toLowerCase();
        noise = {
          strength: Math.max(0, Math.min(0.45, Number(cfg.strength ?? 0.16))),
          block: Math.max(1, Math.min(16, Math.round(Number(cfg.block ?? 2)))),
          pattern,
          chroma: cfg.chroma === true,
          engine: ['shader', 'gpu', 'webgl'].includes(engineRaw)
            ? 'shader'
            : ['frames', 'canvas', 'canvas2d', '2d'].includes(engineRaw)
              ? 'frames'
              : 'auto',
        };
      }
    }

    if (this.#temporalInterlaceCache === undefined) {
      this.#temporalInterlaceCache = normalizeTemporalInterlace(o.temporalInterlace);
    }
    let interlace = this.#temporalInterlaceCache;
    if (interlace && interlace.respectReducedMotion && reducedMotion) interlace = null;
    if (!noise && !interlace) return null;

    const legacyPattern = interlace?.layout === 'strips'
      ? 'bands'
      : interlace?.layout === 'checker' || interlace?.layout === 'pixels'
        ? 'checker'
        : 'blocks';
    const pattern = noise?.pattern || legacyPattern;
    return {
      strength: noise?.strength ?? 0,
      block: noise?.block ?? interlace?.cellSize ?? 2,
      pattern,
      patternCode: pattern === 'checker' ? 1 : pattern === 'bands' ? 2 : 0,
      chroma: noise?.chroma ?? interlace?.chroma ?? false,
      noise: !!noise,
      interlace,
      engine: interlace?.engine || noise?.engine || 'auto',
      phases: interlace?.phases || 2,
    };
  }

  /**
   * Wait (briefly) for the host box to settle before the FIRST token request.
   * A token minted against a layout that is still mid-reflow (fonts, CSS grid,
   * aspect-ratio not applied yet) asks for the wrong derivative size and the
   * image then sits upscaled/blurry forever. Two identical frames = stable.
   */
  async #waitForStableSize() {
    if (typeof requestAnimationFrame !== 'function') return;
    let last = '';
    let stable = 0;
    for (let i = 0; i < 14 && !this.#destroyed; i++) {
      const r = this.#host.getBoundingClientRect?.();
      const key = `${Math.round(r?.width || 0)}x${Math.round(r?.height || 0)}`;
      if (r && r.width > 2 && r.height > 2 && key === last) {
        if (++stable >= 2) break;
      } else stable = 0;
      last = key;
      await new Promise((res) => requestAnimationFrame(res));
    }
  }

  async _resolveBytes(force = false) {
    const o = this.#options;
    const src = this.#source;
    const extra = {};
    const controls = fetchControls(o);
    const strict = o.memory === 'strict';
    const cacheBitmap = o.cacheBitmap !== false && !strict;
    // Already-loaded images never reload implicitly: decode the privately
    // retained scrambled payload locally instead of minting/fetching again.
    if (!force && this.#cachedBytes) {
      return { ...(await this._bytesToBitmap(this.#cachedBytes, this.#cachedExtra || {})), extra: this.#cachedExtra || {} };
    }

    // Token flow: { id } against the signing server. The token JSON is an
    // untrusted upstream response: it is byte-bounded, schema-checked, and
    // only the key/grid/AES fields needed for decoding are retained. Payload
    // URLs must stay on the endpoint origin (or an exact allowlisted origin),
    // redirects are refused, and only a payload 401/403 triggers one remint.
    if (src && typeof src === 'object' && !(src instanceof Blob) &&
        !(src instanceof ArrayBuffer) && !ArrayBuffer.isView(src) && src.id) {
      if (typeof src.id !== 'string' || !src.id || src.id.length > 256 || /[\u0000-\u001f\u007f]/.test(src.id)) {
        throw nonRetryableError('Archx: token image id is invalid');
      }
      const endpointRaw = src.tokenEndpoint || o.tokenEndpoint;
      if (!endpointRaw) throw new Error('Archx: tokenEndpoint required for {id} sources');
      const endpointUrl = resolveHttpUrl(endpointRaw, { label: 'token endpoint' });
      if (endpointUrl.search || endpointUrl.hash) throw nonRetryableError('Archx: token endpoint must not contain a query or fragment');
      const rect = this.#host.getBoundingClientRect?.();
      const cssWidth = rect?.width || this.#host.clientWidth || 800;
      const cssHeight = rect?.height || this.#host.clientHeight || cssWidth * 0.75;
      const dprCap = Number.isFinite(Number(o.dprCap)) && Number(o.dprCap) > 0 ? Number(o.dprCap) : DEFAULTS.dprCap;
      const oversample = Number.isFinite(Number(o.sourceOversample)) && Number(o.sourceOversample) > 0 ? Number(o.sourceOversample) : 1;
      const pixelScale = Math.min(devicePixelRatio || 1, dprCap) * Math.max(1, oversample);
      const maxSourceWidth = boundedInteger(o.maxSourceWidth, DEFAULTS.maxSourceWidth, 64, 16384);
      const boxW = Math.min(maxSourceWidth, Math.ceil(cssWidth * pixelScale));
      const boxH = Math.min(maxSourceWidth, Math.ceil(cssHeight * pixelScale));
      const fit = ['cover', 'contain', 'fill'].includes(o.fit) ? o.fit : 'cover';
      const requestQuality = o.requestQuality === 'lossless' ||
        (Number.isInteger(o.requestQuality) && o.requestQuality >= 1 && o.requestQuality <= 100)
        ? o.requestQuality : null;
      const tokenMethod = String(o.tokenMethod || 'POST').toUpperCase() === 'GET' ? 'GET' : 'POST';
      const tokenTransport = ['header', 'query', 'auto'].includes(String(o.tokenTransport || 'header').toLowerCase())
        ? String(o.tokenTransport || 'header').toLowerCase() : 'header';
      const proofSetting = o.proofOfPossession;
      const proofMode = proofSetting === false || proofSetting === 'off' ? 'off'
        : proofSetting === true || proofSetting === 'required' ? 'required' : 'auto';
      const proofKey = proofMode === 'off' ? null : await getProofKey(proofMode === 'required');
      const mintUrl = new URL(endpointUrl.href);
      mintUrl.pathname = `${mintUrl.pathname.replace(/\/?$/, '/')}${encodeURIComponent(src.id)}`;
      mintUrl.searchParams.set('w', String(boxW));
      mintUrl.searchParams.set('bw', String(boxW));
      mintUrl.searchParams.set('bh', String(boxH));
      mintUrl.searchParams.set('fit', fit);
      if (requestQuality != null) mintUrl.searchParams.set('q', String(requestQuality));

      const tokenCacheKey = cacheDigest([
        'token', 1, o.cacheScope || '', endpointUrl.origin, endpointUrl.pathname, src.id,
        boxW, boxH, fit, requestQuality, tokenMethod, tokenTransport, proofKey?.jkt || proofMode, controls.credentials,
        o.allowedTokenOrigins || null, o.grid, o.scrambled === true, o.key || '', o.aesKey || '',
        controls.maxResponseBytes, controls.maxDecodedPixels, controls.maxDecodedDimension,
      ]);
      if (!force && cacheBitmap) {
        const hitEntry = cacheGetEntry(tokenCacheKey, { acquire: true });
        if (hitEntry) {
          const hit = await hitEntry.promise;
          return { ...hit, extra: hit.extra || {}, cacheEntry: hitEntry };
        }
      }

      const tokenPromise = (async () => {
        for (let tokenAttempt = 0; tokenAttempt <= 1; tokenAttempt++) {
          const mint = await fetchBounded(mintUrl.href, {
            method: tokenMethod,
            credentials: controls.credentials,
            cache: 'no-store',
            redirect: 'error',
            headers: proofKey
              ? { 'X-Archx-Request': 'token', 'X-Archx-Proof-Key': proofKey.header }
              : { 'X-Archx-Request': 'token' },
            signal: this.#abort.signal,
          }, {
            retries: controls.retries,
            maxBytes: 65536,
            timeoutMs: controls.fetchTimeoutMs,
            validateResponse: (res) => assertResponseFinalOrigin(res, new Set([endpointUrl.origin])),
          });
          const parsed = parseTokenResponse(parseBoundedJson(mint.bytes), o, mintUrl);
          const payloadHeaders = parsed.headerToken ? { 'X-Archx-Token': parsed.headerToken } : {};
          if (proofKey) {
            const proof = await createProofHeader(proofKey, parsed.accessToken, parsed.payloadUrl);
            if (!proof) throw nonRetryableError('Archx: proof-of-possession could not be created');
            payloadHeaders['X-Archx-Proof'] = proof;
          }
          const payload = await fetchBounded(parsed.payloadUrl.href, {
            method: 'GET',
            credentials: controls.credentials,
            cache: 'no-store',
            redirect: 'error',
            headers: payloadHeaders,
            signal: this.#abort.signal,
          }, {
            retries: 0,
            maxBytes: controls.maxResponseBytes,
            timeoutMs: controls.fetchTimeoutMs,
            allowedStatuses: new Set([401, 403]),
            validateResponse: (res) => assertResponseFinalOrigin(res, parsed.allowedOrigins),
          });
          if (payload.bytes == null) {
            if (tokenAttempt === 0) continue; // exactly one fresh mint for a rejected payload token
            const err = new Error('Archx fetch failed: HTTP ' + payload.response.status);
            err.status = payload.response.status;
            throw err;
          }
          const buf = payload.bytes;
          if (o.cachePayload !== false) { this.#cachedBytes = buf; this.#cachedExtra = parsed.extra; }
          return { ...(await this._bytesToBitmap(buf, parsed.extra)), extra: parsed.extra };
        }
        throw new Error('Archx: token request failed');
      })();
      const cacheEntry = cacheBitmap ? cachePut(tokenCacheKey, tokenPromise, o) : null;
      const result = await tokenPromise;
      return { ...result, cacheEntry };
    }

    if (typeof src === 'string') {
      let sourceUrl;
      try {
        if (!src || /[\u0000-\u001f\u007f]/.test(src) ||
            (!src.startsWith('data:') && src.length > 16384) ||
            (src.startsWith('data:') && src.length > controls.maxResponseBytes * 2 + 1024)) {
          throw new Error('invalid source URL');
        }
        sourceUrl = new URL(src, typeof document !== 'undefined' ? document.baseURI : undefined);
        if (!['http:', 'https:', 'blob:', 'data:'].includes(sourceUrl.protocol) || sourceUrl.username || sourceUrl.password) {
          throw new Error('disallowed source URL');
        }
      } catch { throw nonRetryableError('Archx: image source URL is invalid'); }
      const cacheKey = cacheDigest([
        'url', 1, o.cacheScope || '', sourceUrl.href, controls.credentials,
        o.grid, o.scrambled === true, o.key || '', o.aesKey || '',
        controls.maxResponseBytes, controls.maxDecodedPixels, controls.maxDecodedDimension,
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
          cache: 'no-store',
          signal: this.#abort.signal,
        }, {
          retries: controls.retries,
          maxBytes: controls.maxResponseBytes,
          timeoutMs: controls.fetchTimeoutMs,
          validateResponse: (res) => {
            if (!res.url) return;
            let finalUrl;
            try { finalUrl = new URL(res.url); } catch { throw nonRetryableError('Archx: image response URL is invalid'); }
            if (!['http:', 'https:', 'blob:', 'data:'].includes(finalUrl.protocol)) {
              throw nonRetryableError('Archx: image response URL is disallowed');
            }
          },
        });
        if (o.cachePayload !== false) { this.#cachedBytes = buf; this.#cachedExtra = extra; }
        return this._bytesToBitmap(buf, extra);
      })();
      const cacheEntry = cacheBitmap ? cachePut(cacheKey, promise, o) : null;
      const result = await promise;
      return { ...result, extra, cacheEntry };
    }

    if (src instanceof Blob) {
      if (!Number.isSafeInteger(src.size) || src.size < 1 || src.size > controls.maxResponseBytes) {
        throw nonRetryableError('Archx: Blob source exceeds the configured byte limit', 'ARCHX_RESPONSE_TOO_LARGE');
      }
      const buf = asByteArray(await src.arrayBuffer());
      if (buf.length > controls.maxResponseBytes) throw nonRetryableError('Archx: Blob source exceeds the configured byte limit', 'ARCHX_RESPONSE_TOO_LARGE');
      if (o.cachePayload !== false) { this.#cachedBytes = buf; this.#cachedExtra = extra; }
      return { ...(await this._bytesToBitmap(buf, extra)), extra };
    }
    if (src instanceof ArrayBuffer || ArrayBuffer.isView(src)) {
      const bytes = asByteArray(src);
      if (!bytes.length || bytes.length > controls.maxResponseBytes) {
        throw nonRetryableError('Archx: byte source exceeds the configured byte limit', 'ARCHX_RESPONSE_TOO_LARGE');
      }
      if (o.cachePayload !== false) { this.#cachedBytes = bytes; this.#cachedExtra = extra; }
      return { ...(await this._bytesToBitmap(bytes, extra)), extra };
    }
    throw new Error('Archx: unsupported source type');
  }

  async _bytesToBitmap(buf, extra = {}) {
    const o = this.#options;
    const controls = fetchControls(o);
    const bytes = asByteArray(buf);
    if (!bytes.length || bytes.length > controls.maxResponseBytes) {
      throw nonRetryableError('Archx: image payload exceeds the configured byte limit', 'ARCHX_RESPONSE_TOO_LARGE');
    }
    let header = null;
    let payload = bytes;
    if (isArchxContainer(bytes)) {
      const decoded = decodeContainer(bytes); // strict v1 schema and padded geometry
      header = decoded.header;
      if (header.pw > controls.maxDecodedDimension || header.ph > controls.maxDecodedDimension ||
          header.pw * header.ph > controls.maxDecodedPixels) {
        throw nonRetryableError('Archx: image dimensions exceed the configured decode budget', 'ARCHX_RESPONSE_TOO_LARGE');
      }
      payload = decoded.payload;
      if (header.encrypted) {
        const aesKey = extra.aesKey || o.aesKey;
        if (typeof aesKey !== 'string' || !aesKey) throw new Error('Archx: encrypted .archx payload needs aesKey');
        payload = asByteArray(await decryptPayload(payload, aesKey, header.iv));
        if (!payload.length || payload.length > controls.maxResponseBytes) {
          throw nonRetryableError('Archx: decrypted image exceeds the configured byte limit', 'ARCHX_RESPONSE_TOO_LARGE');
        }
      }
    }

    // Format/dimension sniffing happens BEFORE the browser decoder is asked
    // to allocate a bitmap. Decompression-bomb headers and MIME/container
    // mismatches fail here; the decoded bitmap is checked again below.
    const sniffed = sniffImageInfo(payload);
    const browserRasterFormats = new Set(['png', 'jpeg', 'webp', 'avif', 'gif', 'bmp']);
    if (!sniffed || !browserRasterFormats.has(sniffed.format)) {
      throw nonRetryableError('Archx: unsupported or unrecognized image payload');
    }
    if (header && sniffed.mime !== header.mime) {
      throw nonRetryableError('Archx: .archx payload format does not match its header');
    }
    if (sniffed.width && sniffed.height) {
      if (sniffed.width > controls.maxDecodedDimension || sniffed.height > controls.maxDecodedDimension ||
          sniffed.width * sniffed.height > controls.maxDecodedPixels) {
        throw nonRetryableError('Archx: image dimensions exceed the configured decode budget', 'ARCHX_RESPONSE_TOO_LARGE');
      }
      if (header && !((sniffed.width === header.pw && sniffed.height === header.ph) ||
          (sniffed.width === header.ph && sniffed.height === header.pw))) {
        throw nonRetryableError('Archx: .archx payload dimensions do not match its header');
      }
    }

    const scrambled = header ? header.scrambled : o.scrambled === true;
    const grid = header?.grid ?? extra.grid ?? o.grid;
    if (!Number.isInteger(grid) || grid < 2 || grid > 32) throw nonRetryableError('Archx: invalid scramble grid');
    const keyValue = extra.key ?? o.key ?? '';
    if (!['string', 'number', 'bigint'].includes(typeof keyValue)) throw nonRetryableError('Archx: invalid scramble key');
    const key = String(keyValue);
    const blob = new Blob([payload], { type: header?.mime || sniffed.mime });
    let bitmap;
    try {
      bitmap = await nativeCreateImageBitmap(blob);
    } catch (err) {
      if (this.#destroyed || this.#abort.signal.aborted) throw err;
      bitmap = await this._bitmapViaImage(blob, controls.fetchTimeoutMs); // Safari-older fallback
    }
    const bitmapW = bitmap?.width || bitmap?.naturalWidth || 0;
    const bitmapH = bitmap?.height || bitmap?.naturalHeight || 0;
    if (!Number.isSafeInteger(bitmapW) || !Number.isSafeInteger(bitmapH) || bitmapW < 1 || bitmapH < 1 ||
        bitmapW > controls.maxDecodedDimension || bitmapH > controls.maxDecodedDimension ||
        bitmapW * bitmapH > controls.maxDecodedPixels) {
      closeBitmapQuietly(bitmap);
      throw nonRetryableError('Archx: decoded image exceeds the configured dimension budget', 'ARCHX_RESPONSE_TOO_LARGE');
    }

    let meta;
    if (scrambled) {
      let origW; let origH; let padW; let padH;
      if (header) {
        if (bitmapW === header.pw && bitmapH === header.ph) {
          ({ w: origW, h: origH, pw: padW, ph: padH } = header);
        } else if (bitmapW === header.ph && bitmapH === header.pw && header.pw !== header.ph) {
          // Tolerate a decoder-applied quarter-turn orientation swap without
          // accepting arbitrary geometry.
          origW = header.h; origH = header.w; padW = bitmapW; padH = bitmapH;
        } else {
          closeBitmapQuietly(bitmap);
          throw nonRetryableError('Archx: decoded image dimensions do not match its .archx header');
        }
      } else {
        if (bitmapW % grid !== 0 || bitmapH % grid !== 0) {
          closeBitmapQuietly(bitmap);
          throw nonRetryableError('Archx: scrambled image dimensions are not divisible by the grid');
        }
        origW = bitmapW; origH = bitmapH; padW = bitmapW; padH = bitmapH;
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
      const img = new (NATIVES.ImageCtor || Image)(); // detached, never inserted into the document
      let settled = false;
      const finish = (fn, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        img.onload = null;
        img.onerror = null;
        (NATIVES.revokeObjectURL ? NATIVES.revokeObjectURL.call(URL, url) : URL.revokeObjectURL(url));
        fn(value);
      };
      const timer = setTimeout(() => {
        try { img.src = ''; } catch {}
        finish(reject, new Error('Archx: image decode timed out'));
      }, Math.max(100, Math.floor(Number(timeoutMs) || DEFAULTS.fetchTimeoutMs)));
      img.onload = () => finish(resolve, img);
      img.onerror = () => finish(reject, new Error('Archx: image decode failed'));
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

  async _load({ force = false } = {}) {
    if (this.#loading || this.#destroyed) return;
    // Loaded once = loaded. Repaint from what we already hold; only an
    // explicit reload() / source change may touch the network again.
    if (!force && this.#loadedOnce && this.#bitmap && this.#meta) {
      this._render();
      this.#loaded = true;
      this.#unloaded = false;
      this.#wrap.classList.remove('loading', 'error');
      return;
    }
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
      if (!this.#loadedOnce) await this.#waitForStableSize();
      if (this.#destroyed) return;
      const result = await limiter.run(() => this._resolveBytes(force));
      if (this.#destroyed) {
        if (result?.cacheEntry) cacheReleaseEntry(result.cacheEntry);
        else closeBitmapQuietly(result?.bitmap);
        return;
      }
      const { bitmap, meta, cacheEntry = null } = result;
      const previousEntry = this.#bitmapCacheEntry;
      const previousBitmap = this.#bitmap;
      if (cacheEntry && cacheEntry === previousEntry) {
        // A cache hit acquired one ref for this load; the instance already
        // owned one for the same entry, so drop only the duplicate.
        cacheReleaseEntry(cacheEntry);
      } else {
        this.#bitmapCacheEntry = cacheEntry;
        if (previousEntry) cacheReleaseEntry(previousEntry);
        else if (previousBitmap && previousBitmap !== bitmap) closeBitmapQuietly(previousBitmap);
      }
      this.#bitmap = bitmap;
      this.#meta = meta;
      this.#loadedOnce = true;
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
    // Free backing stores for off-screen gallery items. When this instance
    // retained the compressed/scrambled payload, also release the decoded
    // bitmap: repaint can decode locally with no network/token reload. If
    // there is no local recovery path, keep the shared bitmap rather than
    // turning an ordinary scroll into a fresh one-time-token mint.
    if (this.#canvas) { this.#canvas.width = 0; this.#canvas.height = 0; }
    if (this.#bitmap && this.#cachedBytes) {
      if (this.#bitmapCacheEntry) cacheReleaseEntry(this.#bitmapCacheEntry);
      else closeBitmapQuietly(this.#bitmap);
      this.#bitmapCacheEntry = null;
      this.#bitmap = null;
      this.#bitmapReleased = true;
    }
    this.#unloaded = true;
  }

  /** Strict-memory mode: drop the decoded source as soon as pixels are painted. */
  #releaseSourceBitmap() {
    if (this.#options.memory !== 'strict' || !this.#bitmap) return;
    if (this.#bitmapCacheEntry) cacheReleaseEntry(this.#bitmapCacheEntry);
    else closeBitmapQuietly(this.#bitmap);
    this.#bitmapCacheEntry = null;
    this.#bitmap = null;
    this.#bitmapReleased = true;
  }

  /* ---------------- rendering ---------------- */
  _backingSize() {
    const o = this.#options;
    const rect = this.#host.getBoundingClientRect();
    const cssW = Math.max(1, Math.round(rect.width || this.#host.clientWidth || 320));
    const cssH = Math.max(1, Math.round(rect.height || this.#host.clientHeight || Math.round(cssW * (this.#meta.origH / this.#meta.origW)) || 240));
    // Prefer the browser's exact device-pixel content box when the
    // ResizeObserver provided one: cssWidth × DPR can be off by a pixel on
    // fractional layouts and forces a needless resample of the whole image.
    const deviceW = this.#deviceBox && this.#deviceBox.w > 0 ? this.#deviceBox.w : 0;
    let scale = Math.min(window.devicePixelRatio || 1, o.dprCap);
    if (deviceW) scale = Math.min(scale, deviceW / cssW);
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
    const temporal = this.#temporalConfig();
    let wantsWebGL = this.#options.renderer === 'webgl' ||
      (this.#options.renderer !== 'canvas' && mode === 'vault');
    if (temporal?.engine === 'shader') wantsWebGL = true;
    else if (temporal?.engine === 'frames') wantsWebGL = false;
    this.#temporalEngineActual = null;
    if (wantsWebGL) {
      if (this._tryRenderWebGL()) {
        if (temporal) this.#temporalEngineActual = 'shader';
        return;
      }
      // fall through to canvas rendering on any GL problem / budget hit
    }
    if (temporal) this.#temporalEngineActual = 'frames';
    if (this.#options.splitCanvases && !this.#options.lens && !temporal) this._renderSplit();
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
    this.#renderedW = w; this.#renderedH = h;
    const ctx = getNativeContext(canvas, '2d', { alpha: false });
    this.#realCtx = ctx;
    const { full, fit } = this._workingCanvas(w, h);
    const temporalCfg = this.#temporalConfig();
    this.#temporalEngineActual = temporalCfg ? 'frames' : null;
    if (temporalCfg) {
      // Temporal dithering/interlace: phase frames alternate at display
      // refresh. Human temporal integration averages them toward the image;
      // a single OS/extension/DevTools screenshot receives only one altered
      // phase. Recordings and multiple captures can recombine phases, so
      // this is a capture-cost layer, not screenshot-proofing.
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
      if (this.#options.lens) {
        if (this.#frameCanvas) { this.#frameCanvas.width = 0; this.#frameCanvas.height = 0; }
        this.#frameCanvas = frame;
        const cfg = typeof this.#options.lens === 'object' ? this.#options.lens : {};
        const factor = cfg.idlePixelate ?? 18;
        const base = makeCanvas(this.#host.ownerDocument);
        base.width = Math.max(8, Math.round(w / factor));
        base.height = Math.max(8, Math.round(h / factor));
        nativeDrawImage(getNativeContext(base, '2d'), frame, 0, 0, base.width, base.height);
        this.#lensBase = base;
        this.#setupTemporalFrames(frame, temporalCfg);
      } else {
        this.#setupTemporalFrames(frame, temporalCfg);
        frame.width = 0; frame.height = 0;
      }
      this._poison(canvas, ctx);
      this.#releaseSourceBitmap();
      return;
    }
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

  /**
   * Build pre-rendered phase frames for Canvas2D. Legacy temporalShield
   * keeps its original two complementary-noise frames. temporalInterlace
   * instead assigns each spatial cell to exactly one phase; cells outside
   * the current phase receive the configured low-detail/dim/black/noise fill.
   */
  #setupTemporalFrames(frame, cfg) {
    this.#stopTemporal2d(true);
    const w = frame.width, h = frame.height;
    const fctx = getNativeContext(frame, '2d');
    let src;
    try { src = fctx.getImageData(0, 0, w, h); } catch { return; }

    const interlace = cfg.interlace;
    const phases = Math.max(2, Math.min(4, cfg.phases || 2));
    const needNoise = !!cfg.noise || interlace?.fill === 'noise';
    const noiseBlock = Math.max(1, cfg.block || 1);
    const nbw = Math.ceil(w / noiseBlock), nbh = Math.ceil(h / noiseBlock);
    const offsets = needNoise ? new Float32Array(nbw * nbh * 3) : null;
    const amp = (cfg.noise ? cfg.strength : (interlace?.noiseStrength || 0)) * 255;
    if (offsets) {
      for (let by = 0; by < nbh; by++) {
        for (let bx = 0; bx < nbw; bx++) {
          const oi = (by * nbw + bx) * 3;
          if (cfg.pattern === 'bands' && bx > 0) {
            offsets[oi] = offsets[oi - 3];
            offsets[oi + 1] = offsets[oi - 2];
            offsets[oi + 2] = offsets[oi - 1];
            continue;
          }
          const parity = cfg.pattern === 'checker' ? (((bx + by) & 1) ? 1 : -1) : 1;
          if (cfg.chroma) {
            // Opponent-colour modulation: human chroma sensitivity is lower
            // than luma sensitivity, while Bayer sensors sample RGB unevenly.
            const scalar = cfg.pattern === 'checker'
              ? (0.35 + Math.random() * 0.65) * amp * parity
              : (Math.random() * 2 - 1) * amp;
            offsets[oi] = scalar;
            offsets[oi + 1] = -0.62 * scalar;
            offsets[oi + 2] = 0.78 * scalar;
          } else if (cfg.pattern === 'checker') {
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
          if (interlace.layout === 'strips') {
            phase = (interlace.axis === 'columns' ? bx : by) % phases;
          } else if (interlace.layout === 'blocks') {
            phase = (Math.random() * phases) | 0;
          } else if (interlace.layout === 'pixels') {
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
    if (interlace?.fill === 'lowres') {
      lowBlock = Math.max(1, interlace.fillBlock || 12);
      lowW = Math.max(1, Math.ceil(w / lowBlock));
      lowH = Math.max(1, Math.ceil(h / lowBlock));
      try {
        const low = makeCanvas(this.#host.ownerDocument);
        low.width = lowW; low.height = lowH;
        const lowCtx = getNativeContext(low, '2d');
        setSmoothing(lowCtx, true);
        nativeDrawImage(lowCtx, frame, 0, 0, lowW, lowH);
        lowData = lowCtx.getImageData(0, 0, lowW, lowH).data;
        low.width = 0; low.height = 0;
      } catch {
        lowData = null;
      }
    }

    const mk = (phase) => {
      const sign = phase % 2 ? -1 : 1;
      const c = makeCanvas(this.#host.ownerDocument);
      c.width = w; c.height = h;
      const cctx = getNativeContext(c, '2d');
      const out = cctx.createImageData(w, h);
      const s = src.data, d = out.data; // Uint8ClampedArray clamps assignments

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
                r = sr * gain; g = sg * gain; b = sb * gain;
              } else {
                let fr = sr, fg = sg, fb = sb;
                if (interlace.fill === 'lowres' && lowData) {
                  const lowX = Math.min(lowW - 1, Math.floor(x / lowBlock));
                  const li = (lowY * lowW + lowX) * 4;
                  fr = lowData[li]; fg = lowData[li + 1]; fb = lowData[li + 2];
                } else if (interlace.fill === 'dim') {
                  fr = sr * interlace.hiddenScale;
                  fg = sg * interlace.hiddenScale;
                  fb = sb * interlace.hiddenScale;
                } else if (interlace.fill === 'black') {
                  fr = 0; fg = 0; fb = 0;
                } else if (interlace.fill === 'noise' && offsets) {
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

    this.#temporalFrames = Array.from({ length: phases }, (_, phase) => mk(phase));
    this.#temporalIndex = 0;
    this.#temporalPhase = 0;
    this.#temporalSign = 1;
    this.#paintTemporal2d();
    if (this.#visible) this.#startTemporal2d();
  }

  #paintTemporal2d() {
    const ctx = this.#realCtx;
    const frames = this.#temporalFrames;
    if (!ctx || !frames?.length || this.#destroyed || !this.#canvas) return;
    const phase = ((this.#temporalIndex % frames.length) + frames.length) % frames.length;
    this.#temporalPhase = phase;
    if (this.#options.lens && this.#frameCanvas) {
      this.#paintLens2d();
      return;
    }
    if (Date.now() < this.#lockedUntil) {
      ctx.fillStyle = '#000';
      ctx.fillRect(0, 0, this.#canvas.width, this.#canvas.height);
      return;
    }
    nativeDrawImage(ctx, frames[phase], 0, 0);
  }

  #startTemporal2d() {
    if (this.#temporalRaf || !this.#temporalFrames || this.#destroyed) return;
    const step = () => {
      this.#temporalRaf = 0;
      if (this.#destroyed || !this.#temporalFrames || !this.#visible) return;
      this.#temporalIndex++;
      this.#paintTemporal2d();
      this.#temporalRaf = requestAnimationFrame(step);
    };
    this.#temporalRaf = requestAnimationFrame(step);
  }

  #stopTemporal2d(wipe = false) {
    if (this.#temporalRaf) cancelAnimationFrame(this.#temporalRaf);
    this.#temporalRaf = 0;
    if (wipe && this.#temporalFrames) {
      for (const f of this.#temporalFrames) { f.width = 0; f.height = 0; }
      this.#temporalFrames = null;
    }
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
      const phaseFrames = this.#temporalFrames;
      const sharpSource = phaseFrames?.length
        ? phaseFrames[((this.#temporalIndex % phaseFrames.length) + phaseFrames.length) % phaseFrames.length]
        : frame;
      nativeDrawImage(ctx, sharpSource, 0, 0);
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
    this.#renderedW = w; this.#renderedH = h;
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
    if (o.forensic) {
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
      gl = getNativeContext(canvas, 'webgl2', {
        preserveDrawingBuffer: false,
        antialias: false,
        alpha: false,
        depth: false,
        stencil: false,
        powerPreference: 'low-power',
      });
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
     'uLensOn','uLensActive','uLensCenter','uLensRadius','uResolution','uLocked',
     'uTemporalOn','uTemporalSign','uTemporalStrength','uTemporalBlock','uTemporalPattern','uTemporalChroma',
     'uInterlaceOn','uInterlacePhase','uInterlacePhases','uInterlaceLayout','uInterlaceCell','uInterlaceAxis',
     'uInterlaceFill','uInterlaceFillBlock','uInterlaceFillStrength','uInterlaceHiddenScale','uInterlaceActiveGain','uInterlaceNoiseStrength']
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

  #glContinuous() {
    const loop = this.#options.renderLoop;
    if (loop === 'continuous') return true;
    if (loop === 'static') return false;
    return !!this.#temporalConfig();
  }

  /**
   * Draw-on-demand WebGL. A static protected photograph does not need a
   * 60fps GPU loop: we present a couple of frames (so the first composite is
   * never blank) and then stop. Continuous presentation is reserved for the
   * temporal shield (or explicit renderLoop:'continuous').
   */
  _startGlLoop(frames = 2) {
    if (!this.#gl) return;
    if (this.#glContinuous()) this.#glFrameBudget = Infinity;
    else this.#glFrameBudget = Math.max(this.#glFrameBudget, Math.max(1, frames | 0));
    if (this.#raf) return;
    const gl = this.#gl;
    const draw = () => {
      this.#raf = 0;
      if (this.#destroyed || !this.#gl) return;
      const { w, h } = this._backingSize();
      if (this.#canvas.width !== w || this.#canvas.height !== h) {
        this.#canvas.width = w; this.#canvas.height = h;
      }
      this.#renderedW = w; this.#renderedH = h;
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
      const temporal = this.#temporalConfig();
      const interlace = temporal?.interlace || null;
      const interlacePhases = interlace?.phases || 2;
      const interlacePhase = ((this.#temporalPhase % interlacePhases) + interlacePhases) % interlacePhases;
      gl.uniform1f(L.uTemporalOn, temporal?.noise ? 1 : 0);
      gl.uniform1f(L.uTemporalSign, this.#temporalSign);
      gl.uniform1f(L.uTemporalStrength, temporal ? temporal.strength : 0);
      gl.uniform1f(L.uTemporalBlock, temporal ? temporal.block : 1);
      gl.uniform1f(L.uTemporalPattern, temporal ? temporal.patternCode : 0);
      gl.uniform1f(L.uTemporalChroma, temporal?.chroma ? 1 : 0);
      gl.uniform1f(L.uInterlaceOn, interlace ? 1 : 0);
      gl.uniform1f(L.uInterlacePhase, interlacePhase);
      gl.uniform1f(L.uInterlacePhases, interlacePhases);
      gl.uniform1f(L.uInterlaceLayout,
        interlace?.layout === 'pixels' ? 0
          : interlace?.layout === 'strips' ? 1
            : interlace?.layout === 'blocks' ? 2
              : 3);
      gl.uniform1f(L.uInterlaceCell, interlace?.cellSize || 1);
      gl.uniform1f(L.uInterlaceAxis, interlace?.axis === 'columns' ? 1 : 0);
      gl.uniform1f(L.uInterlaceFill,
        interlace?.fill === 'dim' ? 1
          : interlace?.fill === 'black' ? 2
            : interlace?.fill === 'noise' ? 3
              : 0);
      gl.uniform1f(L.uInterlaceFillBlock, interlace?.fillBlock || 12);
      gl.uniform1f(L.uInterlaceFillStrength, interlace?.fillStrength ?? 1);
      gl.uniform1f(L.uInterlaceHiddenScale, interlace?.hiddenScale ?? 0.3);
      gl.uniform1f(L.uInterlaceActiveGain, interlace?.activeGain ?? 1);
      gl.uniform1f(L.uInterlaceNoiseStrength, interlace?.noiseStrength ?? 0.16);
      gl.drawArrays(gl.TRIANGLE_STRIP, 0, 4);
      this.#glFrames++;
      if (temporal) {
        this.#temporalSign = -this.#temporalSign;
        this.#temporalIndex++;
        this.#temporalPhase = interlace
          ? (interlacePhase + 1) % interlacePhases
          : (this.#temporalPhase + 1) % 2;
      }
      if (this.#glFrameBudget !== Infinity && this.#glFrameBudget > 0) this.#glFrameBudget--;
      const keepGoing = this.#glContinuous() || this.#glFrameBudget > 0;
      if (keepGoing && this.#visible && !this.#destroyed && !this.#unloaded) {
        this.#raf = requestAnimationFrame(draw);
      }
    };
    this.#raf = requestAnimationFrame(draw);
  }
  _stopGlLoop() {
    if (this.#raf) cancelAnimationFrame(this.#raf);
    this.#raf = 0;
    this.#glFrameBudget = 0;
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
    const temporal = this.#temporalConfig();
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
      loadedOnce: this.#loadedOnce,
      cachedPayload: !!this.#cachedBytes,
      renderedSize: { w: this.#renderedW, h: this.#renderedH },
      glFrames: this.#glFrames,
      glContinuous: this.#gl ? this.#glContinuous() : false,
      temporalOn: !!temporal,
      temporalPattern: temporal?.pattern || null,
      temporalChroma: !!temporal?.chroma,
      temporalFrames2d: !!this.#temporalFrames,
      temporalNoise: !!temporal?.noise,
      temporalEngineRequested: temporal?.engine || null,
      temporalEngineActual: this.#temporalEngineActual,
      temporalPhase: this.#temporalPhase,
      temporalIndex: this.#temporalIndex,
      temporalFrameCount: this.#temporalFrames?.length || 0,
      temporalInterlace: temporal?.interlace ? { ...temporal.interlace } : null,
      tokenMethod: this.#options.tokenMethod,
      tokenTransport: this.#options.tokenTransport,
      proofOfPossession: this.#options.proofOfPossession,
      cacheScopeSet: !!this.#options.cacheScope,
    };
  }
  async reload(newSource) {
    if (newSource !== undefined) {
      this.#source = newSource;
      this.#cachedBytes = null;
      this.#cachedExtra = null;
      this.#loadedOnce = false;
    }
    this.#loaded = false;
    this.#wrap.classList.add('loading');
    // Explicit reload is the ONLY implicit-reload escape hatch: it bypasses
    // both the bitmap cache and the privately retained payload.
    await this._load({ force: true });
    return this;
  }
  destroy() {
    this.#destroyed = true;
    instances.delete(this);
    this.#abort.abort();
    this.#stopTemporal2d(true);
    this.#cachedBytes = null;
    this.#cachedExtra = null;
    this._stopGlLoop();
    if (this.#gl) {
      try { this.#gl.getExtension('WEBGL_lose_context')?.loseContext(); } catch {}
      glContextsInUse = Math.max(0, glContextsInUse - 1);
      this.#gl = null;
    }
    clearTimeout(this.#resizeTimer);
    this.#resizeTimer = 0;
    try { sharedResizeObserver?.unobserve(this.#host); } catch {}
    try { this.#visibilityObs?.unobserve(this.#host); } catch {}
    this.#visibilityObs = null;
    if (this.#canvas) { this.#canvas.width = 0; this.#canvas.height = 0; }
    if (this.#decoy) { this.#decoy.width = 0; this.#decoy = null; }
    if (this.#frameCanvas) { this.#frameCanvas.width = 0; this.#frameCanvas.height = 0; this.#frameCanvas = null; }
    if (this.#lensBase) { this.#lensBase.width = 0; this.#lensBase.height = 0; this.#lensBase = null; }
    if (this.#lensRaf) cancelAnimationFrame(this.#lensRaf);
    if (this.#traceTimer) clearInterval(this.#traceTimer);
    this.#traceTimer = 0;
    clearTimeout(this.#lockTimer);
    // Refcounted LRU bitmaps stay alive for other owners / later reuse;
    // an uncached bitmap is exclusively ours and is closed immediately.
    if (this.#bitmapCacheEntry) cacheReleaseEntry(this.#bitmapCacheEntry);
    else closeBitmapQuietly(this.#bitmap);
    this.#bitmapCacheEntry = null;
    this.#bitmap = null;
    this.#root.replaceChildren?.();
    if (hostToInstance.get(this.#host) === this) hostToInstance.delete(this.#host);
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
  const galleryDefaults = { mode: 'lite', unloadOnExit: false, sourceOversample: 1.5, cachePayload: true, reloadOnResize: 'never' };
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
    static get observedAttributes() { return ['src', 'image-id', 'mode', 'renderer', 'preset', 'quality-profile', 'watermark', 'alt', 'fit', 'grid', 'key', 'scrambled', 'lens', 'capture-shield', 'temporal-shield', 'camera-shield', 'temporal-interlace', 'temporal-interlace-engine', 'temporal-interlace-layout', 'temporal-interlace-phases', 'temporal-interlace-cell-size', 'temporal-interlace-fill', 'temporal-interlace-refresh-hz', 'render-loop', 'reload-on-resize', 'on-extract', 'token-endpoint', 'token-method', 'token-transport', 'proof-of-possession', 'cache-scope']; }
    connectedCallback() {
      if (elementInstances.has(this)) return;
      this.style.display = this.style.display || 'block';
      const inner = document.createElement('div');
      inner.style.width = '100%'; inner.style.height = '100%';
      this.appendChild(inner);
      const id = this.getAttribute('image-id');
      const src = id ? { id } : this.getAttribute('src');
      let presetOptions = {};
      const presetName = this.getAttribute('preset');
      if (presetName) { try { presetOptions = preset(presetName); } catch {} }
      let temporalInterlace = presetOptions.temporalInterlace;
      const interlaceAttr = this.getAttribute('temporal-interlace');
      const hasInterlaceDetails = ['temporal-interlace-engine', 'temporal-interlace-layout',
        'temporal-interlace-phases', 'temporal-interlace-cell-size',
        'temporal-interlace-fill', 'temporal-interlace-refresh-hz']
        .some((name) => this.hasAttribute(name));
      if (interlaceAttr != null || hasInterlaceDetails) {
        if (interlaceAttr === 'false' || interlaceAttr === 'off' || interlaceAttr === 'none') {
          temporalInterlace = false;
        } else {
          const details = {};
          if (interlaceAttr && interlaceAttr !== 'true') details.profile = interlaceAttr;
          const engine = this.getAttribute('temporal-interlace-engine');
          const layout = this.getAttribute('temporal-interlace-layout');
          const phases = this.getAttribute('temporal-interlace-phases');
          const cellSize = this.getAttribute('temporal-interlace-cell-size');
          const fill = this.getAttribute('temporal-interlace-fill');
          const refreshHz = this.getAttribute('temporal-interlace-refresh-hz');
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
        mode: this.getAttribute('mode') || presetOptions.mode,
        renderer: this.getAttribute('renderer') || presetOptions.renderer,
        qualityProfile: this.getAttribute('quality-profile') || presetOptions.qualityProfile,
        watermark: this.getAttribute('watermark') || undefined,
        alt: this.getAttribute('alt') || '',
        fit: this.getAttribute('fit') || undefined,
        grid: this.getAttribute('grid') ? Number(this.getAttribute('grid')) : undefined,
        key: this.getAttribute('key') || undefined,
        scrambled: this.hasAttribute('scrambled'),
        lens: this.hasAttribute('lens') ? true : presetOptions.lens,
        captureShield: this.hasAttribute('capture-shield') ? true : presetOptions.captureShield,
        temporalShield: this.hasAttribute('temporal-shield') ? true : presetOptions.temporalShield,
        cameraShield: this.hasAttribute('camera-shield')
          ? { pattern: 'checker', chroma: true }
          : presetOptions.cameraShield,
        temporalInterlace,
        renderLoop: this.getAttribute('render-loop') || presetOptions.renderLoop,
        reloadOnResize: this.getAttribute('reload-on-resize') || presetOptions.reloadOnResize,
        onExtract: this.getAttribute('on-extract') || presetOptions.onExtract,
        tokenEndpoint: this.getAttribute('token-endpoint') || undefined,
        tokenMethod: this.getAttribute('token-method') || undefined,
        tokenTransport: this.getAttribute('token-transport') || undefined,
        proofOfPossession: this.getAttribute('proof-of-possession') || undefined,
        cacheScope: this.getAttribute('cache-scope') || undefined,
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
  presets: PRESETS,
  preset,
  temporalInterlaceProfiles: TEMPORAL_INTERLACE_PROFILES,
  normalizeTemporalInterlace,
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
  /** Prevent future reuse of shared decoded bitmaps (call on logout/account switch). */
  clearCaches() { clearBitmapCache(); pageSessionId = null; },
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
