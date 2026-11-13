/**
 * Viewer option surface: DEFAULTS, global config state, merge/preset logic, sanitized option views. Single source of truth for option semantics.
 */
import { DEFAULT_GRID } from '../scramble.js';
import { normalizeTemporalInterlace } from './temporal.js';

export const DEFAULT_SOURCE_WIDTH_BUCKETS = Object.freeze([
  160, 240, 320, 480, 640, 800, 960, 1200, 1440, 1600, 1920, 2240, 2560,
]);

export const DEFAULTS = {
  mode: 'shield',               // 'lite' | 'shield' | 'vault' | 'fortress' | 'custom' | 'performance' (=shield pipeline) | 'elite' (=fortress + PoP required)
  profile: null,                // 1.28: null | 'lite' | 'performance' | 'elite' — applies the canonical bundle UNDER explicit options (explicit keys win); unknown values throw
  renderer: 'auto',             // 'auto' | 'canvas' | 'webgl' — direct renderer flag (lets custom setups skip preset modes)
  fit: 'cover',                 // 'cover' | 'contain' | 'fill'
  lazy: true,
  rootMargin: '500px',
  unloadOnExit: false,          // gallery mode turns this on for huge grids
  shadow: 'closed',             // 'closed' | 'open' | 'none'
  grid: DEFAULT_GRID,
  scrambled: false,             // source pixels are tile-scrambled
  planVersion: 1,               // scramble plan derivation for container-less scrambled sources (1 = legacy 32-bit seed, 2 = 128-bit seed); .archx headers carry their own `pv` and win
  key: null,                    // scramble seed and/or AES key (see docs)
  aesKey: null,                 // base64 AES key for encrypted .archx payloads
  tokenEndpoint: null,          // e.g. '/archx/token/'  (+ image id)
  tokenMethod: 'POST',          // token mint method; POST + X-Archx-Request avoids simple cross-site GET minting
  tokenTransport: 'header',     // 'header' | 'query' | 'auto' — header keeps bearer tokens out of image URLs/logs
  tokenBatch: false,            // coalesce simultaneous POST mints into {basePath}/tokens (catalog/gallery presets enable it)
  tokenBatchEndpoint: null,     // explicit batch endpoint; otherwise derived by replacing a trailing /token segment
  tokenBatchSize: 50,           // maximum mints per batch HTTP request
  tokenBatchDelayMs: 8,         // quiet-period coalescing window for gallery/page bursts
  tokenBatchMaxDelayMs: 50,     // hard cap so a continuous trickle cannot starve the first mint
  assetManifest: null,          // archx-build manifest URL or object for { assetId } sources
  assetManifestMaxBytes: 8 * 1024 * 1024,
  assetHttpCache: 'default',    // manifest/variant fetches may use browser/CDN HTTP caching
  assetIntegrity: 'auto',       // 'auto' | 'require' | 'off' — verify per-variant SHA-256 digests from the manifest
  assetManifestIntegrity: null, // optional 'sha256-<hex>' pin for a fetched manifest (archx-build prints it)
  httpCache: 'no-store',        // direct URL sources; token mint/payload requests always remain no-store
  fetchPriority: null,          // null | 'high' | 'low' | 'auto' (hero images may use high; leave auto for galleries)
  proofOfPossession: 'auto',    // 'auto' | 'required' | 'off' — bind tokens to a non-extractable page key when WebCrypto allows
  allowedTokenOrigins: null,    // exact extra origins allowed for token-returned payload URLs (endpoint origin is always allowed)
  fetchTimeoutMs: 20000,        // per-request network deadline (mint, payload, and direct sources)
  maxResponseBytes: 64 * 1024 * 1024,
  maxDecodedPixels: 40000000,   // pre-decode header budget + post-decode bitmap budget
  maxDecodedDimension: 16384,
  onExtract: 'black',           // 'black' | 'lowres' | 'scrambled'
  taintReadback: 'auto',        // 'auto' | 'off' — origin-taint 2D display canvases so even prototype-call readbacks throw
  taintUrl: null,               // explicit cross-origin 1x1 image URL for tainting; auto-derived from a cross-origin token endpoint when null
  taintFallback: 'warn',        // 'warn' | 'webgl' | 'off' — when no cross-origin taint pixel is available in a 2D mode: surface it (telemetry + one console warning), promote this instance to the WebGL renderer, or stay silent
  splitCanvases: false,         // shield+: one canvas per tile (hero images)
  splitGrid: 3,
  maxBackingWidth: 1920,        // never paint a wider backing store than this
  dprCap: 3,                    // match modern retina/mobile displays instead of upscaling a 2x canvas
  sourceOversample: 2,          // fetch a 2x derivative then supersample down (server entitlement still caps the signed width)
  maxSourceWidth: 2560,         // client-side ceiling before the server's own entitlement cap
  sourceWidthBuckets: null,     // canonical requested widths (catalog/gallery presets supply a ladder)
  qualityProfile: 'high',       // 'original' | 'high' | 'balanced' | 'catalog' | 'fast' (sets requestQuality + sampling unless overridden)
  requestQuality: null,         // 1..100 | 'lossless' — honoured only when the server opts in with allowClientQuality
  networkAware: false,          // honour Save-Data / slow effectiveType with a smaller derivative (Network Information API)
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
  onChallenge: null,            // async ({id, reason}) => proofToken — server step-up (Turnstile/WebAuthn) integration
  onLoad: null,
  onError: null,
  onClick: null,
  onEvent: null,                // (sanitizedEvent, instance) => void — generic monitoring/plugin hook; never receives tokens/keys/pixels
  alt: '',
};

const KNOWN_OPTION_KEYS = new Set([
  ...Object.keys(DEFAULTS),
  // Public, optional presentation/click options consumed by ProtectedImage
  // but intentionally omitted from the shared global defaults.
  'aspectRatio', 'height', 'showBadge', 'swallowClick', 'width',
]);

/** Warn about misspelled client options without changing the supplied values. */
export function warnUnknownOptionKeys(options, additionalKeys = []) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) return;
  const known = additionalKeys.length
    ? new Set([...KNOWN_OPTION_KEYS, ...additionalKeys])
    : KNOWN_OPTION_KEYS;
  for (const key of Object.keys(options)) {
    if (!known.has(key)) {
      console.warn(`[Archx] Unknown option key: "${key}" — check spelling. See the README for valid options.`);
    }
  }
}

let globalConfig = structuredCloneSafe(DEFAULTS);

export function structuredCloneSafe(obj) {
  return JSON.parse(JSON.stringify(obj, (k, v) => (typeof v === 'function' ? undefined : v)));
}

export function mergeOptions(opts = {}) {
  // Strip `undefined` values so e.g. an absent HTML attribute on
  // <archx-image> never clobbers a global config value with undefined.
  const clean = {};
  for (const [k, v] of Object.entries(opts)) if (v !== undefined) clean[k] = v;
  const merged = { ...globalConfig, ...clean };
  merged.guards = { ...globalConfig.guards };
  if (opts.guards) {
    for (const [k, v] of Object.entries(opts.guards)) if (v !== undefined) merged.guards[k] = v;
  }
  // 1.28 canonical profiles: lite (CPU/RAM/speed first), performance
  // (balanced security + speed), elite (security first). A profile is a
  // bundle applied UNDER explicit options: it only fills keys the caller
  // did not set, so it is a default a deployment refines — never a
  // lock-in. Users can always build their own default with
  // Archx.config() or mode:'custom' + explicit flags.
  if (clean.profile !== undefined && clean.profile !== null) {
    const bundleName = String(clean.profile).toLowerCase();
    if (!['lite', 'performance', 'elite'].includes(bundleName)) {
      throw new TypeError(`Archx: unknown profile "${clean.profile}" (known: lite, performance, elite). For a fully custom setup use mode:'custom' with explicit flags.`);
    }
    const bundle = structuredCloneSafe(PRESETS[bundleName]);
    for (const [k, v] of Object.entries(bundle)) {
      if (k === 'guards') continue;
      if (clean[k] === undefined) {
        merged[k] = v;
        // Count as caller-set so later fill-ins (e.g. the fortress
        // block's captureShield default) cannot overwrite the bundle.
        clean[k] = v;
      }
    }
    if (bundle.guards) {
      for (const [k, v] of Object.entries(bundle.guards)) {
        if (!opts.guards || opts.guards[k] === undefined) merged.guards[k] = v;
      }
    }
    merged.profile = bundleName;
    // Treat the bundle's quality shorthand as caller-set so its
    // oversample/dprCap shortcuts engage below; explicit values win.
    if (clean.qualityProfile === undefined && bundle.qualityProfile !== undefined) clean.qualityProfile = bundle.qualityProfile;
  }
  // Quality profiles are shortcuts, not black boxes: every value below can
  // still be overridden directly (sourceOversample / dprCap / requestQuality).
  const qualityProfiles = {
    original: { requestQuality: 'lossless', sourceOversample: 2, dprCap: 3 },
    high: { requestQuality: 95, sourceOversample: 2, dprCap: 3 },
    balanced: { requestQuality: 90, sourceOversample: 1.5, dprCap: 2.5 },
    catalog: { requestQuality: 88, sourceOversample: 1, dprCap: 2 },
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
  merged.renderer = rendererValue === 'canvas2d' ? 'canvas'
    : (rendererValue === 'canvas' || rendererValue === 'webgl') ? rendererValue : 'auto';
  // Automation policy: canonical values are 'off' | 'monitor' | 'lock'.
  // The published TypeScript union once said 'allow'|'degrade'|'block',
  // which silently failed to engage 'lock'. Map those legacy aliases
  // (and close synonyms) onto the canonical policy so existing callers
  // get the strictness they configured; unknown values fall back to
  // 'monitor' (report-only) rather than disabling the tripwire.
  const AUTOMATION_ALIASES = {
    allow: 'off', ignore: 'off', off: 'off', none: 'off',
    warn: 'monitor', report: 'monitor', degrade: 'monitor', monitor: 'monitor',
    block: 'lock', deny: 'lock', lock: 'lock',
  };
  merged.automation = AUTOMATION_ALIASES[String(merged.automation ?? 'monitor').toLowerCase()] ?? 'monitor';
  const customRequested = merged.mode === 'custom' ||
    (clean.mode === undefined && clean.renderer !== undefined);
  if (customRequested) {
    merged.requestedMode = 'custom';
    merged.mode = merged.renderer === 'webgl' ? 'vault' : 'shield';
  }
  // Lite is the one preset that historically skipped client forensic marks.
  // Preserve that default, but let an explicit `forensic: true` flag win.
  if (merged.mode === 'lite' && clean.forensic === undefined) merged.forensic = false;

  // 1.28 profile-mode names, layered on the legacy pipelines so existing
  // deployments' names keep their exact 1.x meaning and pixels:
  // 'performance' runs the balanced shield pipeline; 'elite' runs the
  // fortress bundle below plus sender-constrained delivery required and
  // WebGL fallback when the taint layer is unavailable.
  if (merged.mode === 'performance') {
    merged.requestedMode = 'performance';
    merged.mode = 'shield';
  } else if (merged.mode === 'elite') {
    merged.requestedMode = 'elite';
    merged.mode = 'fortress';
    if (clean.proofOfPossession === undefined) merged.proofOfPossession = 'required';
    if (clean.taintFallback === undefined) merged.taintFallback = 'webgl';
  } else if (merged.mode === 'fortress') {
    merged.requestedMode = 'fortress';
  }

  // Fortress: maximum-paranoia preset (explicit options still win).
  if (merged.mode === 'fortress') {
    if (!merged.requestedMode) merged.requestedMode = 'fortress';
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

export function sanitizeOptionsView(opts) {
  if (!opts) return opts;
  const sensitive = new Set([
    'key', 'aeskey', 'cachescope', 'sessionid', 'token', 'accesstoken', 'refreshtoken',
    'secret', 'password', 'authorization', 'cookie', 'assetmanifest', 'tainturl',
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
    mode: 'lite', qualityProfile: 'catalog', sourceOversample: 1, dprCap: 2, lazy: true,
    unloadOnExit: true, cacheBitmap: true, cachePayload: true, renderLoop: 'static',
    reloadOnResize: 'never', tokenBatch: true, tokenBatchDelayMs: 20, tokenBatchMaxDelayMs: 150,
    sourceWidthBuckets: DEFAULT_SOURCE_WIDTH_BUCKETS, httpCache: 'default', networkAware: true,
    bitmapCacheMaxEntries: 24, bitmapCacheMaxBytes: 128 * 1024 * 1024,
    guards: Object.freeze({ blurOnBlur: false }),
  }),
  catalog: Object.freeze({
    mode: 'lite', qualityProfile: 'catalog', sourceOversample: 1, dprCap: 2, lazy: true,
    unloadOnExit: true, cacheBitmap: true, cachePayload: true, renderLoop: 'static',
    reloadOnResize: 'never', tokenBatch: true, tokenBatchDelayMs: 20, tokenBatchMaxDelayMs: 150,
    sourceWidthBuckets: DEFAULT_SOURCE_WIDTH_BUCKETS, httpCache: 'default', networkAware: true,
    assetHttpCache: 'default', bitmapCacheMaxEntries: 24,
    bitmapCacheMaxBytes: 128 * 1024 * 1024,
    guards: Object.freeze({ blurOnBlur: false }),
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
  marketplace: Object.freeze({
    mode: 'vault', qualityProfile: 'high', onExtract: 'black', tokenBatch: true,
    cacheBitmap: true, cachePayload: true, renderLoop: 'static',
    reloadOnResize: 'upscale', forensic: true,
    captureShield: Object.freeze({ dynamicTrace: true, temporalPattern: true }),
  }),
  // === The three canonical profiles (v1.28) ===
  // lite: CPU/RAM/speed first. The 2D pipeline, catalog sampling,
  // smallest caches, batched mints, static loop — every layer that costs
  // nothing stays on (guards, taint, closed shadow DOM); the paid
  // extras (GL, forensic blocks, temporal) stay off.
  // Server counterpart: withLiteDefaults().
  lite: Object.freeze({
    mode: 'lite', renderer: 'canvas', qualityProfile: 'catalog', sourceOversample: 1,
    dprCap: 2, lazy: true, unloadOnExit: true, cacheBitmap: true, cachePayload: true,
    renderLoop: 'static', reloadOnResize: 'never', tokenBatch: true,
    tokenBatchDelayMs: 20, tokenBatchMaxDelayMs: 150,
    sourceWidthBuckets: DEFAULT_SOURCE_WIDTH_BUCKETS, networkAware: true,
    httpCache: 'default', assetHttpCache: 'default',
    bitmapCacheMaxEntries: 16, bitmapCacheMaxBytes: 96 * 1024 * 1024,
    taintFallback: 'warn',
    guards: Object.freeze({ blurOnBlur: false }),
  }),
  // performance: the balanced default (rebalanced in v1.28; the v1.23
  // CPU-first composition moved to 'lite'). Shield pipeline with the
  // taint layer, balanced sampling, forensic blocks, moderate caches,
  // batched mints. Server counterpart: withPerformanceDefaults().
  performance: Object.freeze({
    mode: 'performance', renderer: 'canvas', qualityProfile: 'balanced',
    sourceOversample: 1.5, dprCap: 2.5, lazy: true, cacheBitmap: true,
    cachePayload: true, renderLoop: 'static', reloadOnResize: 'upscale',
    tokenBatch: true, tokenBatchDelayMs: 20, tokenBatchMaxDelayMs: 150,
    sourceWidthBuckets: DEFAULT_SOURCE_WIDTH_BUCKETS, networkAware: true,
    bitmapCacheMaxEntries: 24, bitmapCacheMaxBytes: 128 * 1024 * 1024,
    taintFallback: 'warn', forensic: true,
    guards: Object.freeze({ blurOnBlur: false }),
  }),
  // elite: security first — everything that can harden, on. WebGL
  // pipeline (black readback), fortress extras (integrity lock, strict
  // memory, local scramble, strikes, devtools guard), sender-constrained
  // tokens required, 60 Hz temporal interlace, dynamic trace. Budgets
  // are spent on protection, not removed.
  // Server counterpart: withEliteDefaults().
  elite: Object.freeze({
    mode: 'elite', renderer: 'webgl', qualityProfile: 'original', onExtract: 'black',
    taintFallback: 'webgl', proofOfPossession: 'required', forensic: true,
    temporalInterlace: 'balanced60',
    captureShield: Object.freeze({ dynamicTrace: true, temporalPattern: true }),
    cacheBitmap: true, cachePayload: true, renderLoop: 'auto', reloadOnResize: 'upscale',
  }),
  maxProtection: Object.freeze({
    // Legacy (v1.23) alias, kept working unchanged: vault + WebGL +
    // PoP required + temporal, without the fortress extras elite adds.
    // Server counterpart: withMaxProtectionDefaults().
    mode: 'vault', renderer: 'webgl', qualityProfile: 'original', onExtract: 'black',
    taintFallback: 'webgl', proofOfPossession: 'required', forensic: true,
    temporalInterlace: 'balanced60',
    captureShield: Object.freeze({ dynamicTrace: true, temporalPattern: true }),
    cacheBitmap: true, cachePayload: true, renderLoop: 'auto', reloadOnResize: 'upscale',
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

let pageSessionId = null;
/** Reset the anonymous page-session id (Archx.clearCaches, e.g. on logout). */
export function resetPageSession() { pageSessionId = null; }

export function sessionId() {
  if (globalConfig.sessionId) return globalConfig.sessionId;
  if (!pageSessionId) {
    const a = new Uint8Array(8);
    crypto.getRandomValues(a);
    pageSessionId = [...a].map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  return pageSessionId;
}

/** Global-config accessors (the binding itself stays module-private). */
export function getGlobalConfig() { return globalConfig; }
export function setGlobalConfig(next) { globalConfig = next; }
