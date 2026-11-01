/**
 * ProtectedImage: the viewer state machine (load, render via Canvas2D/WebGL, guards, lens, temporal presentation, lifecycle).
 */
import { chooseAssetVariant, loadAssetManifest, normalizeAssetIntegrityMode, verifyAssetVariantIntegrity } from './assets.js';
import { cacheGetEntry, cachePut, cacheReleaseEntry, closeBitmapQuietly } from './bitmap-cache.js';
import { asByteArray, scrambleCanvasLocally, setSmoothing, unscrambleToCanvas } from './draw.js';
import { emitClientEvent } from './events.js';
import { auditIntegrity, detectAutomation } from './integrity.js';
import { NATIVES, getNativeContext, glNative, makeCanvas, nativeCall, nativeCreateImageBitmap, nativeDrawImage, nativeGetImageData, nativeGlDrawArrays, nativePutImageData } from './native.js';
import { assertResponseFinalOrigin, createProofHeader, deriveTokenBatchEndpoint, fetchBounded, fetchControls, getProofKey, nonRetryableError, parseBoundedJson, parseTokenResponse, queueTokenBatchRequest, resolveHttpUrl } from './network.js';
import { $, GL_CONTEXT_BUDGET, acquireGlSlot, ensureDevtoolsWatcher, getResizeObserver, getVisibilityObserver, glSlotsInUse, installGlobalGuards, releaseGlSlot, sharedResizeObserver } from './observers.js';
import { DEFAULTS, mergeOptions, preset, sanitizeOptionsView, sessionId } from './options.js';
import { hostToInstance, instances } from './registry.js';
import { boundedInteger, cacheDigest, canonicalSourceWidth, effectiveSampling, ensureTaintImage, fetchPriorityInit, fitRects, normalizedHttpCache, resolveTaintUrl } from './sampling.js';
import { buildScramblePlan, decodeContainer, decryptPayload, hashSeed, isArchxContainer, mulberry32, sniffImageInfo } from '../scramble.js';
import { SHADOW_CSS } from './styles.js';
import { limiter, normalizeTemporalInterlace } from './temporal.js';

// One console warning per page for the same-origin taint degradation
// (audit D1): telemetry carries the machine-readable signal; this is for
// the human reading DevTools while integrating.
let taintConsoleWarned = false;

export class ProtectedImage {
  /* Everything sensitive is a #private field: page scripts and extension
   * content scripts that obtain an instance (or its host element) get no
   * handle to the canvas, bitmap, options/secrets, or shadow internals. */
  #options; #host; #root; #wrap; #canvas; #tilesEl; #shieldEl;
  #source; #bitmap = null; #meta = null; #abort = new AbortController();
  #decoy = null; #decoySize = null; #gl = null; #raf = 0; #loaded = false; #destroyed = false;
  #glBudgetWarned = false; #taintWarned = false; #taintPromotedWebGL = false;
  #canaryDone = false; #canaryPause = false; #canaryProbe = null; #canaryWait = 0; #canaryNextTry = 1;
  #preserveFlagged = false; #integrityHardLock = false; #glReleasing = false;
  #taintImage = null;
  #risk = new Set(); #blackoutTimer = 0; #resizeTimer = 0; #visibilityObs = null; #realCtx = null;
  #attemptHandler = null; #loading = false; #visible = false; #unloaded = false;
  #glProg = null; #glLoc = null; #glTex = null; #glMap = null; #glWm = null; #glWmOn = 0;
  #glSource = null; #glMeta = null; #frameCanvas = null; #lensBase = null;
  #lensPoint = null; #lensRaf = 0; #lensCells = [];
  #lensCoverage = new Float64Array(64).fill(-1e15);
  #lensRadiusScale = 1; #lensRadiusAt = 0;
  #traceEl = null; #traceTimer = 0;
  #strikes = 0; #lockedUntil = 0; #lockTimer = 0; #integrityIssues = [];
  #bitmapReleased = false;
  #loadedOnce = false; #cachedBytes = null; #cachedExtra = null; #bitmapCacheEntry = null; #prefetchedTokenMint = null;
  #renderedW = 0; #renderedH = 0; #deviceBox = null;
  #glFrameBudget = 0; #glFrames = 0; #temporalSign = 1; #temporalPhase = 0;
  #temporalRaf = 0; #temporalFrames = null; #temporalIndex = 0; #temporalEngineActual = null;
  #phaseBag = []; #signBalance = 0;
  #dutyIndex = 0; #biasSeed = Math.random() * 100; #biasFrames = 0;
  #lastInteractAt = 0; #idleSkip = 0;
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
        // Use the captured native so a hooked attachShadow cannot silently
        // downgrade the closed root to an open one.
        const attachInit = { mode: o.shadow === 'open' ? 'open' : 'closed' };
        root = NATIVES.attachShadow
          ? nativeCall(NATIVES.attachShadow, this.#host, [attachInit])
          : this.#host.attachShadow(attachInit);
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
    // Prefer a constructable stylesheet inside shadow DOM. That avoids a
    // dynamically inserted <style> element in modern browsers and is the
    // cleanest path under strict style-src policies. Older browsers and
    // shadow:'none' still need the <style> fallback documented in the CSP
    // guide; Archx does not pretend one policy fits every browser.
    let style = null;
    let adoptedStyles = false;
    if (root !== this.#host && typeof CSSStyleSheet !== 'undefined' && 'adoptedStyleSheets' in root) {
      try {
        const sheet = new CSSStyleSheet();
        sheet.replaceSync(SHADOW_CSS);
        root.adoptedStyleSheets = [...root.adoptedStyleSheets, sheet];
        adoptedStyles = true;
      } catch { /* fall back to a style element */ }
    }
    if (!adoptedStyles) {
      style = doc.createElement('style');
      style.textContent = SHADOW_CSS;
    }
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
    if (style) root.append(style, wrap);
    else root.append(wrap);
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
      emitClientEvent('archx.attempt', { kind, outcome: 'detected' }, this);
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
    // Interaction clock for the temporal idle throttle (passive, cheap).
    const interact = () => { this.#lastInteractAt = performance.now(); };
    this.#wrap.addEventListener('pointermove', interact, { ...sig, passive: true });
    this.#wrap.addEventListener('pointerdown', interact, { ...sig, passive: true });
    this.#wrap.addEventListener('touchmove', interact, { ...sig, passive: true });
    this.#wrap.addEventListener('wheel', interact, { ...sig, passive: true });
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
      // Hidden tab or scrolled off-screen: this instance cannot be
      // captured right now; skip the text repaint (the next tick after
      // it becomes visible refreshes within updateMs).
      if (this.#host.ownerDocument?.hidden) return;
      if (this.#loadedOnce && !this.#visible) return;
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

  /** Heuristic: a lens swept rapidly across many cells == stitching attempt.
   * Accounting uses every cell the revealed DISC touches, not just the cell
   * under its center: with a ~30%-radius lens one park position exposes
   * ~28% of the frame, so center-only counting let a stitcher harvest the
   * whole image in 3-4 parks without ever tripping the threshold. */
  #trackLensTravel(point) {
    const now = performance.now();
    const cfg = typeof this.#options.lens === 'object' && this.#options.lens ? this.#options.lens : {};
    const cells = 8;
    const bw = this.#canvas?.width || 1;
    const bh = this.#canvas?.height || 1;
    const radiusPx = Math.max(24, Math.min(bw, bh) * (cfg.radius ?? 0.30));
    const rx = radiusPx / bw, ry = radiusPx / bh;
    const reachX = rx + 0.75 / cells, reachY = ry + 0.75 / cells;
    for (let cy = 0; cy < cells; cy++) {
      for (let cx = 0; cx < cells; cx++) {
        const ccx = (cx + 0.5) / cells, ccy = (cy + 0.5) / cells;
        const dx = (ccx - point.x) / Math.max(reachX, 1e-6);
        const dy = (ccy - point.y) / Math.max(reachY, 1e-6);
        if (dx * dx + dy * dy <= 1) this.#lensCells.push({ cell: cy * cells + cx, now });
      }
    }
    this.#lensCells = this.#lensCells.filter((c) => now - c.now < 8000);
    const distinct = new Set(this.#lensCells.map((c) => c.cell)).size;
    const threshold = cfg.scanCells ?? 46;
    if (distinct >= threshold) {
      this.#lensCells = [];
      if (this.#attemptHandler) this.#attemptHandler('lens-scan');
      return;
    }
    // Paced stitching defeats the 8 s burst window by parking, waiting
    // out the window, and parking elsewhere. A slow cumulative ledger
    // (last-visit timestamp per cell, 120 s horizon) catches systematic
    // whole-frame coverage across pauses: a human inspects 1-3 regions,
    // a stitcher eventually visits almost every cell.
    const visited = new Set(this.#lensCells.map((c) => c.cell));
    for (const cell of visited) this.#lensCoverage[cell] = now;
    let covered = 0;
    for (let i = 0; i < 64; i++) if (now - this.#lensCoverage[i] < 120000) covered++;
    const cumulativeThreshold = cfg.scanCellsCumulative ?? 56;
    if (covered >= cumulativeThreshold) {
      this.#lensCoverage = new Float64Array(64).fill(-1e15);
      this.#lensCells = [];
      if (this.#attemptHandler) this.#attemptHandler('lens-scan');
    }
  }

  // Lens radius with a slow +-6% jitter (re-rolled at most 4x/second):
  // stitched captures of overlapping parks get inconsistent disc rims,
  // so seams ghost instead of aligning pixel-exactly.
  #lensRadiusPx(w, h, frac) {
    const now = performance.now();
    if (now - this.#lensRadiusAt > 250) {
      this.#lensRadiusAt = now;
      this.#lensRadiusScale = 0.94 + Math.random() * 0.12;
    }
    return Math.max(24, Math.min(w, h) * frac * this.#lensRadiusScale);
  }

  #requestLensFrame() {
    if (this.#gl) { this._startGlLoop(2); return; }
    if (this.#lensRaf || !this.#frameCanvas) return;
    this.#lensRaf = requestAnimationFrame(() => {
      this.#lensRaf = 0;
      this.#paintLens2d();
    });
  }

  // Token sources are { id }; { imageId } is accepted as an alias so the
  // shape the TypeScript surface long documented keeps working.
  #tokenSourceId() {
    const src = this.#source;
    if (!src || typeof src !== 'object' || src instanceof Blob ||
        src instanceof ArrayBuffer || ArrayBuffer.isView(src)) return null;
    return src.id ?? src.imageId ?? null;
  }

  #isTokenSource() {
    return !!this.#tokenSourceId();
  }

  #isAssetSource() {
    const src = this.#source;
    return !!(src && typeof src === 'object' && !(src instanceof Blob) &&
      !(src instanceof ArrayBuffer) && !ArrayBuffer.isView(src) &&
      (src.assetId || src.asset));
  }

  /**
   * Only a token source can produce a *different, larger* derivative. For it,
   * a large host growth (or explicit reloadOnResize:'always') may justify one
   * fresh mint; every ordinary resize remains a local repaint.
   */
  #shouldUpgradeDerivative(previousW, previousH) {
    if (!this.#loadedOnce || !this.#meta || !this.#visible ||
        (!this.#isTokenSource() && !this.#isAssetSource())) return false;
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
        if (policy === 'always') void this._load({ force: this.#isTokenSource() || this.#isAssetSource() });
        else if (policy === 'upscale' && this.#meta) {
          const { w, h } = this._backingSize();
          const f = Math.max(1, this.#options.resizeUpscaleFactor || 1.75);
          if (w > previousW * f || h > previousH * f) {
            void this._load({ force: this.#isTokenSource() || this.#isAssetSource() });
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

  async #tokenMintContext(controls) {
    const o = this.#options;
    const src = this.#source || {};
    const tokenId = this.#tokenSourceId();
    const endpointRaw = src.tokenEndpoint || o.tokenEndpoint;
    if (!endpointRaw) throw new Error('Archx: tokenEndpoint required for {id} sources');
    const endpointUrl = resolveHttpUrl(endpointRaw, { label: 'token endpoint' });
    if (endpointUrl.search || endpointUrl.hash) throw nonRetryableError('Archx: token endpoint must not contain a query or fragment');
    const rect = this.#host.getBoundingClientRect?.();
    const cssWidth = rect?.width || this.#host.clientWidth || 800;
    const cssHeight = rect?.height || this.#host.clientHeight || cssWidth * 0.75;
    const { dprCap, oversample, requestQuality } = effectiveSampling(o);
    const pixelScale = Math.min(devicePixelRatio || 1, dprCap) * Math.max(1, oversample);
    const maxSourceWidth = boundedInteger(o.maxSourceWidth, DEFAULTS.maxSourceWidth, 64, 16384);
    const boxW = canonicalSourceWidth(cssWidth * pixelScale, o.sourceWidthBuckets, maxSourceWidth);
    const boxH = canonicalSourceWidth(cssHeight * pixelScale, o.sourceWidthBuckets, maxSourceWidth);
    const fit = ['cover', 'contain', 'fill'].includes(o.fit) ? o.fit : 'cover';
    const tokenMethod = String(o.tokenMethod || 'POST').toUpperCase() === 'GET' ? 'GET' : 'POST';
    const tokenTransport = ['header', 'query', 'auto'].includes(String(o.tokenTransport || 'header').toLowerCase())
      ? String(o.tokenTransport || 'header').toLowerCase() : 'header';
    const proofSetting = o.proofOfPossession;
    const proofMode = proofSetting === false || proofSetting === 'off' ? 'off'
      : proofSetting === true || proofSetting === 'required' ? 'required' : 'auto';
    const proofKey = proofMode === 'off' ? null : await getProofKey(proofMode === 'required');
    const mintUrl = new URL(endpointUrl.href);
    mintUrl.pathname = `${mintUrl.pathname.replace(/\/?$/, '/')}${encodeURIComponent(tokenId)}`;
    mintUrl.searchParams.set('w', String(boxW));
    mintUrl.searchParams.set('bw', String(boxW));
    mintUrl.searchParams.set('bh', String(boxH));
    mintUrl.searchParams.set('fit', fit);
    if (requestQuality != null) mintUrl.searchParams.set('q', String(requestQuality));

    const tokenCacheKey = cacheDigest([
      'token', 1, o.cacheScope || '', endpointUrl.origin, endpointUrl.pathname, tokenId,
      boxW, boxH, fit, requestQuality, tokenMethod, tokenTransport, proofKey?.jkt || proofMode, controls.credentials,
      o.allowedTokenOrigins || null, o.grid, o.scrambled === true, o.key || '', o.aesKey || '',
      controls.maxResponseBytes, controls.maxDecodedPixels, controls.maxDecodedDimension,
    ]);
    return {
      endpointUrl, boxW, boxH, fit, requestQuality, tokenMethod, tokenTransport,
      proofMode, proofKey, mintUrl, tokenCacheKey,
    };
  }

  async #prefetchTokenBatchMint(force = false) {
    const o = this.#options;
    if (o.tokenBatch !== true || this.#prefetchedTokenMint || this.#destroyed) return;
    if (!force && this.#cachedBytes) return;
    const tokenId = this.#tokenSourceId();
    if (!tokenId || typeof tokenId !== 'string' || tokenId.length > 256 || /[\u0000-\u001f\u007f]/.test(tokenId)) return;
    const controls = fetchControls(o);
    let context;
    try { context = await this.#tokenMintContext(controls); }
    catch { return; } // _resolveBytes reports the authoritative error in-order.
    if (this.#destroyed || this.#prefetchedTokenMint || context.tokenMethod !== 'POST') return;
    const batchUrl = deriveTokenBatchEndpoint(context.endpointUrl, o);
    if (!batchUrl) return;
    const cacheBitmap = o.cacheBitmap !== false && o.memory !== 'strict';
    if (!force && cacheBitmap && cacheGetEntry(context.tokenCacheKey)) return;
    const headers = context.proofKey
      ? { 'X-Archx-Request': 'token', 'X-Archx-Proof-Key': context.proofKey.header }
      : { 'X-Archx-Request': 'token' };
    const promise = queueTokenBatchRequest({
      batchUrl,
      item: {
        id: tokenId,
        w: context.boxW,
        bw: context.boxW,
        bh: context.boxH,
        fit: context.fit,
        ...(context.requestQuality != null ? { q: context.requestQuality } : {}),
      },
      headers,
      credentials: controls.credentials,
      controls,
      signal: this.#abort.signal,
      options: o,
    });
    // The authoritative await happens inside _resolveBytes. Attach a benign
    // handler now so a destroyed/unused prefetch cannot surface as an
    // unhandled rejection while other gallery items are still being queued.
    promise.catch(() => {});
    this.#prefetchedTokenMint = { key: context.tokenCacheKey, promise };
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

    // Precomputed asset flow: { assetId } + an archx-build manifest. Variant
    // payloads are immutable scrambled derivatives on static/CDN hosting, so
    // this path deliberately uses the browser HTTP cache by default and does
    // not mint, authorize, or run Sharp per view. The manifest is the trust
    // boundary: serve/sign it appropriately for private catalogs.
    if (src && typeof src === 'object' && !(src instanceof Blob) &&
        !(src instanceof ArrayBuffer) && !ArrayBuffer.isView(src) &&
        (src.assetId || src.asset)) {
      const assetId = src.assetId || src.asset;
      if (typeof assetId !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(assetId)) {
        throw nonRetryableError('Archx: asset id is invalid');
      }
      const manifestSource = src.manifest || o.assetManifest;
      if (!manifestSource) throw new Error('Archx: assetManifest required for {assetId} sources');
      const manifest = await loadAssetManifest(manifestSource, o, controls);
      const asset = manifest.assets.get(assetId);
      if (!asset) throw nonRetryableError('Archx: asset id is not present in the manifest');
      const rect = this.#host.getBoundingClientRect?.();
      const cssWidth = rect?.width || this.#host.clientWidth || 800;
      const cssHeight = rect?.height || this.#host.clientHeight || cssWidth * 0.75;
      const { dprCap, oversample } = effectiveSampling(o);
      const pixelScale = Math.min(devicePixelRatio || 1, dprCap) * Math.max(1, oversample);
      const maxSourceWidth = boundedInteger(o.maxSourceWidth, DEFAULTS.maxSourceWidth, 64, 16384);
      const boxW = canonicalSourceWidth(cssWidth * pixelScale, o.sourceWidthBuckets, maxSourceWidth);
      const boxH = canonicalSourceWidth(cssHeight * pixelScale, o.sourceWidthBuckets, maxSourceWidth);
      const fit = ['cover', 'contain', 'fill'].includes(o.fit) ? o.fit : 'cover';
      const aspect = asset.width / asset.height;
      const neededWidth = fit === 'contain'
        ? Math.min(boxW, boxH * aspect)
        : fit === 'fill'
          ? boxW
          : Math.max(boxW, boxH * aspect);
      const variant = chooseAssetVariant(asset, neededWidth);
      const assetExtra = {
        key: asset.key,
        grid: asset.grid,
        ...(asset.planVersion !== undefined ? { planVersion: asset.planVersion } : {}),
        ...(asset.aesKey !== undefined ? { aesKey: asset.aesKey } : {}),
      };
      const assetCacheMode = normalizedHttpCache(o.assetHttpCache, 'default');
      const assetCacheKey = cacheDigest([
        'asset', 2, o.cacheScope || '', assetId, variant.url.href, variant.width,
        variant.sha256 || '', normalizeAssetIntegrityMode(o.assetIntegrity),
        asset.key, asset.grid, asset.aesKey || '', controls.credentials, assetCacheMode,
        controls.maxResponseBytes, controls.maxDecodedPixels, controls.maxDecodedDimension,
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
          method: 'GET',
          credentials: controls.credentials,
          cache: assetCacheMode,
          signal: this.#abort.signal,
          ...fetchPriorityInit(o),
        }, {
          retries: controls.retries,
          maxBytes: controls.maxResponseBytes,
          timeoutMs: controls.fetchTimeoutMs,
          validateResponse: (res) => {
            if (!res.url) return;
            let finalUrl;
            try { finalUrl = new URL(res.url); }
            catch { throw nonRetryableError('Archx: asset response URL is invalid'); }
            if (!['http:', 'https:'].includes(finalUrl.protocol) || finalUrl.username || finalUrl.password) {
              throw nonRetryableError('Archx: asset response URL is disallowed');
            }
          },
        });
        await verifyAssetVariantIntegrity(variant, buf, o);
        if (o.cachePayload !== false) { this.#cachedBytes = buf; this.#cachedExtra = assetExtra; }
        return { ...(await this._bytesToBitmap(buf, assetExtra)), extra: assetExtra };
      })();
      const cacheEntry = cacheBitmap ? cachePut(assetCacheKey, assetPromise, o) : null;
      const result = await assetPromise;
      return { ...result, cacheEntry };
    }

    // Token flow: { id } against the signing server. The token JSON is an
    // untrusted upstream response: it is byte-bounded, schema-checked, and
    // only the key/grid/AES fields needed for decoding are retained. Payload
    // URLs must stay on the endpoint origin (or an exact allowlisted origin),
    // redirects are refused, and only a payload 401/403 triggers one remint.
    const tokenId = this.#tokenSourceId();
    if (tokenId != null) {
      if (typeof tokenId !== 'string' || !tokenId || tokenId.length > 256 || /[\u0000-\u001f\u007f]/.test(tokenId)) {
        throw nonRetryableError('Archx: token image id is invalid');
      }
      const {
        endpointUrl, boxW, boxH, fit, requestQuality, tokenMethod, tokenTransport,
        proofMode, proofKey, mintUrl, tokenCacheKey,
      } = await this.#tokenMintContext(controls);
      if (!force && cacheBitmap) {
        const hitEntry = cacheGetEntry(tokenCacheKey, { acquire: true });
        if (hitEntry) {
          this.#prefetchedTokenMint = null;
          const hit = await hitEntry.promise;
          return { ...hit, extra: hit.extra || {}, cacheEntry: hitEntry };
        }
      }

      const mintHeaders = proofKey
        ? { 'X-Archx-Request': 'token', 'X-Archx-Proof-Key': proofKey.header }
        : { 'X-Archx-Request': 'token' };
      const batchUrl = o.tokenBatch === true && tokenMethod === 'POST'
        ? deriveTokenBatchEndpoint(endpointUrl, o)
        : null;
      const requestMint = async (tokenAttempt) => {
        if (batchUrl && tokenAttempt === 0) {
          try {
            const prefetched = this.#prefetchedTokenMint?.key === tokenCacheKey
              ? this.#prefetchedTokenMint.promise : null;
            this.#prefetchedTokenMint = null;
            return await (prefetched || queueTokenBatchRequest({
              batchUrl,
              item: {
                id: tokenId,
                w: boxW,
                bw: boxW,
                bh: boxH,
                fit,
                ...(requestQuality != null ? { q: requestQuality } : {}),
              },
              headers: mintHeaders,
              credentials: controls.credentials,
              controls,
              signal: this.#abort.signal,
              options: o,
            }));
          } catch (err) {
            // A batch endpoint is an optimization, not a new hard dependency:
            // an older/partial server deployment can still serve the ordinary
            // single-token route. Per-item authorization/rate decisions are
            // not retried through the fallback.
            const endpointUnsupported = !err?.archxBatchItem &&
              [404, 405, 501].includes(err?.status);
            if (this.#abort.signal.aborted || !endpointUnsupported) throw err;
          }
        }
        const doMintFetch = (headers) => fetchBounded(mintUrl.href, {
          method: tokenMethod,
          credentials: controls.credentials,
          cache: 'no-store',
          redirect: 'error',
          headers,
          signal: this.#abort.signal,
          ...fetchPriorityInit(o),
        }, {
          retries: controls.retries,
          maxBytes: 65536,
          timeoutMs: controls.fetchTimeoutMs,
          validateResponse: (res) => assertResponseFinalOrigin(res, new Set([endpointUrl.origin])),
        });
        let mint;
        try {
          mint = await doMintFetch(mintHeaders);
        } catch (err) {
          // Step-up challenge: the server flagged this session as
          // suspicious and will accept a host-verified proof (e.g. a
          // Turnstile token) instead of a blunt block. Only when the
          // host wired onChallenge; otherwise the 403 stands.
          if (!err?.challengeRequired || typeof o.onChallenge !== 'function' || this.#destroyed) throw err;
          const proof = await o.onChallenge({ id: tokenId, reason: 'suspicious-scraping' });
          if (typeof proof !== 'string' || !proof || proof.length > 8192) throw err;
          mint = await doMintFetch({ ...mintHeaders, 'X-Archx-Challenge': proof });
        }
        return parseBoundedJson(mint.bytes);
      };

      const tokenPromise = (async () => {
        for (let tokenAttempt = 0; tokenAttempt <= 1; tokenAttempt++) {
          const parsed = parseTokenResponse(await requestMint(tokenAttempt), o, mintUrl);
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
            ...fetchPriorityInit(o),
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
        normalizedHttpCache(o.httpCache, 'no-store'),
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
          cache: normalizedHttpCache(o.httpCache, 'no-store'),
          signal: this.#abort.signal,
          ...fetchPriorityInit(o),
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
    const planVersion = header?.pv ?? o.planVersion ?? 1;
    if (planVersion !== 1 && planVersion !== 2) throw nonRetryableError('Archx: invalid scramble plan version');
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
      meta = { plan: buildScramblePlan(grid, key, planVersion), origW, origH, padW, padH };
    } else {
      meta = { plan: null, origW: bitmapW, origH: bitmapH, padW: bitmapW, padH: bitmapH };
    }
    return { bitmap, meta, header };
  }

  _bitmapViaImage(blob, timeoutMs = DEFAULTS.fetchTimeoutMs) {
    return new Promise((resolve, reject) => {
      const url = NATIVES.createObjectURL ? nativeCall(NATIVES.createObjectURL, URL, [blob]) : URL.createObjectURL(blob);
      const img = new (NATIVES.ImageCtor || Image)(); // detached, never inserted into the document
      let settled = false;
      const finish = (fn, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        img.onload = null;
        img.onerror = null;
        (NATIVES.revokeObjectURL ? nativeCall(NATIVES.revokeObjectURL, URL, [url]) : URL.revokeObjectURL(url));
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
    if (!['off', 'monitor', 'lock'].includes(o.integrity)) {
      if (this.#attemptHandler) this.#attemptHandler('integrity:invalid-mode');
      return false;
    }
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
      emitClientEvent('archx.blocked', {
        reason: 'integrity-automation-or-lockout-policy',
        outcome: 'blocked',
        issues: this.#integrityIssues,
      }, this);
      this.#host.dispatchEvent(new CustomEvent('archx-error', {
        detail: { error: new Error('Archx: blocked by integrity/automation/lockout policy') }, bubbles: true,
      }));
      return;
    }
    this.#loading = true;
    try {
      if (!this.#loadedOnce) await this.#waitForStableSize();
      if (this.#destroyed) return;
      await this.#prefetchTokenBatchMint(force);
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
      this.#decoy = null; this.#decoySize = null; // regenerate poison for the (possibly new) source
      if (!this.#options.aspectRatio && !this.#options.height) {
        this.#host.style.aspectRatio = meta.origW + ' / ' + meta.origH;
      }
      // Resolve the optional origin-taint pixel before first paint (2D
      // paths only; WebGL canvases never expose a readable bitmap).
      if (this.#options.mode !== 'vault') {
        this.#taintImage = await ensureTaintImage(this.#options, this.#source);
        if (this.#destroyed) return;
        // Browser-enforced readback denial needs a CROSS-ORIGIN taint pixel;
        // same-origin deployments can't get one automatically. Surface that
        // state once so operators can see shield/lite is relying on the
        // (weaker, hookable) instance-poisoning layer alone.
        if (!this.#taintImage && !this.#taintWarned &&
            this.#options.taintReadback !== 'off' && this.#options.taintReadback !== false) {
          this.#taintWarned = true;
          const fallback = this.#options.taintFallback;
          // taintFallback 'webgl': promote this instance to the WebGL
          // renderer, whose readback is black by construction
          // (preserveDrawingBuffer:false + shadowed readPixels), instead
          // of silently accepting the weaker 2D layer. The frame-based
          // temporal engine cannot run on GL, so promotion skips there.
          let promoted = false;
          if (fallback === 'webgl' && this.#temporalConfig()?.engine !== 'frames') {
            this.#taintPromotedWebGL = true;
            promoted = true;
          }
          const reason = resolveTaintUrl(this.#options, this.#source)
            ? 'taint-load-failed' : 'no-cross-origin-taint-source';
          this.#host.dispatchEvent(new CustomEvent('archx-taint-unavailable', {
            detail: { mode: this.#options.mode, reason, promoted }, bubbles: true,
          }));
          emitClientEvent('archx.taint_unavailable', {
            reason, outcome: promoted ? 'webgl-promoted' : 'instance-poisoning-only',
          }, this);
          if (!promoted && fallback !== 'off' && !taintConsoleWarned) {
            taintConsoleWarned = true;
            try {
              console.warn('[archx] origin-taint readback protection is unavailable (same-origin deployment or the taint pixel failed to load): 2D modes are relying on instance poisoning only, which prototype-call readbacks bypass. Serve the Archx API or taintUrl from a different origin, use vault/WebGL mode, or set taintFallback:"webgl". Machine-readable signal: the archx.taint_unavailable telemetry event.');
            } catch { /* console unavailable */ }
          }
        }
      }
      this._render();
      this.#loaded = true;
      this.#unloaded = false;
      this.#wrap.classList.remove('loading', 'error');
      this.#host.dispatchEvent(new CustomEvent('archx-load', { bubbles: true }));
      emitClientEvent('archx.loaded', { outcome: 'loaded' }, this);
      try { this.#options.onLoad && this.#options.onLoad(this); } catch {}
    } catch (err) {
      if (this.#destroyed) return;
      this.#wrap.classList.remove('loading');
      this.#wrap.classList.add('error');
      emitClientEvent('archx.error', { reason: 'load-failed', outcome: 'error' }, this);
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
    // Release the WebGL context too: otherwise the first GL_CONTEXT_BUDGET
    // vault images in a long gallery hold contexts forever and everything
    // below the fold degrades to 2D. The context-lost handler (flagged
    // intentional) returns the budget slot; visibility re-render creates
    // a fresh context on return.
    if (this.#gl) {
      this._stopGlLoop();
      try {
        const lose = this.#gl.getExtension && glNative(this.#gl, 'getExtension', 'WEBGL_lose_context');
        if (lose?.loseContext) { this.#glReleasing = true; lose.loseContext(); }
      } catch { /* context stays; budget slot returns on natural loss */ }
    }
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
      (this.#options.renderer !== 'canvas' && mode === 'vault') ||
      (this.#options.renderer !== 'canvas' && this.#taintPromotedWebGL);
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
    if (this.#integrityHardLock) { this.#paintBlackout(); return; }
    const { w, h } = this._backingSize();
    const canvas = this.#canvas;
    this.#tilesEl.hidden = true;
    canvas.hidden = false;
    canvas.width = w; canvas.height = h;
    this.#renderedW = w; this.#renderedH = h;
    const ctx = getNativeContext(canvas, '2d', { alpha: false });
    this.#realCtx = ctx;
    this.#taintContext(ctx); // covered by every paint below; flag is sticky
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
      this.#prepareDecoy(full, w, h);
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
      this.#prepareDecoy(full, w, h);
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
    this.#prepareDecoy(full, w, h);
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
    try { src = nativeGetImageData(fctx, 0, 0, w, h); } catch { return; }

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
        lowData = nativeGetImageData(lowCtx, 0, 0, lowW, lowH).data;
        low.width = 0; low.height = 0;
      } catch {
        lowData = null;
      }
    }

    // Cycle-zero-mean block bias (noise fill only): with static frames
    // the per-pixel cycle multiset is {c, c+d1, c+d2} and the temporal
    // MEDIAN is exactly c whenever the hidden deltas straddle it. A
    // fixed per-block offset b applied +b*(P-1)/P on the active phase
    // and -b/P on hidden phases keeps the cycle mean exact (no visible
    // brightness flicker) while moving every cycle statistic off c —
    // the same construction as the shader path and the duty bias.
    const biasBlock = 24;
    const bbw = Math.ceil(w / biasBlock), bbh = Math.ceil(h / biasBlock);
    const biasAmp = (interlace?.noiseStrength || 0) * 255 * 0.55;
    const biases = (interlace && interlace.fill === 'noise' && biasAmp > 0)
      ? new Float32Array(bbw * bbh) : null;
    if (biases) for (let i = 0; i < biases.length; i++) biases[i] = (Math.random() * 2 - 1) * biasAmp;
    const colBias = biases ? new Int32Array(w) : null;
    if (colBias) for (let x = 0; x < w; x++) colBias[x] = Math.min(bbw - 1, Math.floor(x / biasBlock));
    // Column lookup tables replace two Math.floor divisions per pixel
    // in the frame builder (~6M divisions per 4-phase 1600px build).
    const colNoiseOi = offsets ? new Int32Array(w) : null;
    if (colNoiseOi) for (let x = 0; x < w; x++) colNoiseOi[x] = Math.min(nbw - 1, Math.floor(x / noiseBlock)) * 3;
    // One scratch ImageData for all phases (putImageData copies sync).
    const scratch = fctx.createImageData(w, h);

    const mk = (phase) => {
      // Per-phase amplitude diversity: with identical |delta| every phase,
      // a short capture's per-pixel multiset is {c+d, c-d, ...} and its
      // median/mean lands exactly on c. Varied amplitudes make short-window
      // statistics land off-target; the eye still integrates the cycle.
      const sign = (phase % 2 ? -1 : 1) * [1, 0.6, 1.3, 0.85][phase % 4];
      const c = makeCanvas(this.#host.ownerDocument);
      c.width = w; c.height = h;
      const cctx = getNativeContext(c, '2d');
      const out = scratch;
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
                r = sr * gain + ab; g = sg * gain + ab; b = sb * gain + ab;
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

    this.#temporalFrames = Array.from({ length: phases }, (_, phase) => mk(phase));
    this.#temporalIndex = 0;
    this.#temporalPhase = 0;
    this.#temporalSign = 1;
    this.#paintTemporal2d();
    if (this.#visible) this.#startTemporal2d();
  }

  // Next temporal phase from a shuffled bag: every phase appears once per
  // cycle (so the eye still integrates the full set at the same rate) but
  // the ORDER is unpredictable, so fixed-cadence capture cannot parity-lock
  // onto a stable subsequence.
  #nextPhase(phases) {
    if (!this.#phaseBag.length || this.#phaseBag[0] >= phases) {
      this.#phaseBag = Array.from({ length: phases }, (_, i) => i);
      for (let i = phases - 1; i > 0; i--) {
        const j = (Math.random() * (i + 1)) | 0;
        [this.#phaseBag[i], this.#phaseBag[j]] = [this.#phaseBag[j], this.#phaseBag[i]];
      }
    }
    return this.#phaseBag.pop();
  }

  #paintTemporal2d() {
    const ctx = this.#realCtx;
    const frames = this.#temporalFrames;
    if (!ctx || !frames?.length || this.#destroyed || !this.#canvas) return;
    const phase = this.#temporalPhase % frames.length;
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
      this.#temporalPhase = this.#nextPhase(this.#temporalFrames.length);
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
      const radius = this.#lensRadiusPx(w, h, cfg.radius ?? 0.30);
      const cx = point.x * w, cy = point.y * h;
      ctx.save();
      ctx.beginPath();
      ctx.arc(cx, cy, radius, 0, Math.PI * 2);
      ctx.clip();
      const phaseFrames = this.#temporalFrames;
      const sharpSource = phaseFrames?.length
        ? phaseFrames[this.#temporalPhase % phaseFrames.length]
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
    if (this.#integrityHardLock) { this.#paintBlackout(); return; }
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
      this.#taintContext(tctx); // each tile canvas is tainted before its slice covers the pixel
      nativeDrawImage(tctx, composed, (i % g) * tw, Math.floor(i / g) * th, tw, th, 0, 0, tw, th);
      this.#tilesEl.appendChild(c);
      this.#prepareDecoy(full, w, h);
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
          // Tile on BOTH axes (measured-width step, alternating row
          // offset): one stamp per row left most of the frame's width
          // clean, so cropping the band edges erased attribution.
          const stepY = fs * 4.2;
          const stepX = Math.max(fs * 3, ctx.measureText(text).width + fs * 2.2);
          const diag = Math.hypot(w, h);
          let row = 0;
          for (let y = -diag / 2; y < diag / 2; y += stepY, row++) {
            const x0 = (row % 2) * (stepX / 2) - diag / 2;
            for (let x = x0; x < diag / 2 + stepX; x += stepX) ctx.fillText(text, x, y);
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

  // Record the decoy size and build REAL decoys (lowres/scrambled)
  // eagerly while clean pixels exist; the default black policy defers
  // to #getDecoy() on first intercepted readback (most sessions never
  // have one, saving a full-size placeholder canvas per instance).
  #prepareDecoy(cleanCanvas, w, h) {
    this.#decoySize = { w, h };
    if (this.#decoy || !cleanCanvas) return;
    const kind = this.#options.onExtract;
    if (kind === 'lowres' || kind === 'scrambled') {
      this.#decoy = this._makeDecoy(cleanCanvas, w, h);
    }
  }

  #getDecoy() {
    if (this.#decoy) return this.#decoy;
    let size = this.#decoySize;
    if (!size) {
      try { const { w, h } = this._backingSize(); size = { w, h }; }
      catch { size = { w: 320, h: 200 }; }
    }
    try {
      this.#decoy = this._makeDecoy(null, Math.max(1, size.w), Math.max(1, size.h));
    } catch {
      const c = makeCanvas(this.#host.ownerDocument);
      c.width = 1; c.height = 1;
      this.#decoy = c;
    }
    return this.#decoy;
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
      const markSize = Math.max(14, w / 18);
      ctx.font = `700 ${markSize}px system-ui,sans-serif`;
      ctx.textAlign = 'center'; ctx.translate(w / 2, h / 2); ctx.rotate(-Math.PI / 8);
      ctx.fillStyle = 'rgba(0,0,0,0.58)';
      ctx.fillRect(-w * 0.75, -markSize * 0.92, w * 1.5, markSize * 1.45);
      ctx.globalAlpha = 0.96; ctx.fillStyle = '#fff';
      ctx.fillText(String((typeof o.watermark === 'string' ? o.watermark : o.watermark?.text) || o.brand), 0, 0);
      ctx.restore();
      return decoy;
    }
    if (kind === 'scrambled') {
      decoy.width = w; decoy.height = h;
      // Never scramble the clean full-resolution working canvas directly:
      // first destroy detail at 144px wide, then upscale without smoothing,
      // scramble that already-degraded staging image, and visibly mark it.
      // Even a perfect unscramble therefore recovers only a coarse, branded
      // preview rather than the displayed derivative's detail.
      const tinyW = 144;
      const tinyH = Math.max(1, Math.round((h / Math.max(1, w)) * tinyW));
      const tiny = makeCanvas();
      tiny.width = tinyW; tiny.height = tinyH;
      nativeDrawImage(getNativeContext(tiny, '2d'), cleanCanvas, 0, 0, tinyW, tinyH);
      const staging = makeCanvas();
      staging.width = w; staging.height = h;
      const stagingCtx = getNativeContext(staging, '2d');
      stagingCtx.imageSmoothingEnabled = false;
      nativeDrawImage(stagingCtx, tiny, 0, 0, w, h);
      tiny.width = 0; tiny.height = 0;

      const g = 8;
      const plan = buildScramblePlan(g, 'decoy-' + sessionId(), 2);
      const tw = staging.width / g, th = staging.height / g;
      const dw = w / g, dh = h / g;
      for (let dest = 0; dest < plan.count; dest++) {
        const source = plan.order[dest];
        nativeDrawImage(ctx, staging, (source % g) * tw, Math.floor(source / g) * th, tw, th,
          (dest % g) * dw, Math.floor(dest / g) * dh, dw + 1, dh + 1);
      }
      staging.width = 0; staging.height = 0;
      ctx.save();
      const markSize = Math.max(14, w / 18);
      ctx.font = `700 ${markSize}px system-ui,sans-serif`;
      ctx.textAlign = 'center'; ctx.translate(w / 2, h / 2); ctx.rotate(-Math.PI / 8);
      ctx.fillStyle = 'rgba(0,0,0,0.58)';
      ctx.fillRect(-w * 0.75, -markSize * 0.92, w * 1.5, markSize * 1.45);
      ctx.globalAlpha = 0.96; ctx.fillStyle = '#fff';
      ctx.fillText(String((typeof o.watermark === 'string' ? o.watermark : o.watermark?.text) || o.brand), 0, 0);
      ctx.restore();
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
  /**
   * Draw the cross-origin 1x1 taint pixel into a fresh 2D bitmap BEFORE
   * any image pixels cover it. The pixel itself is invisible in the final
   * composition; its only effect is flipping origin-clean to false so the
   * browser itself rejects every readback (see resolveTaintUrl). Must be
   * re-applied after any canvas resize, which resets the flag.
   */
  #taintContext(ctx) {
    const img = this.#taintImage;
    if (!img || !ctx) return;
    try { nativeDrawImage(ctx, img, 0, 0, 1, 1); } catch {}
  }

  _poison(canvas, ctx) {
    const decoy = () => this.#getDecoy();
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
      return d ? nativeCall(realToDataURL, d, [type, quality]) : 'data:,';
    });
    define('toBlob', function (cb, type, quality) {
      self.#attemptHandler('extract-blob');
      const d = decoy();
      if (d) nativeCall(realToBlob, d, [cb, type, quality]);
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
      this.#prepareDecoy(full, full.width, full.height);
      full.width = 0; full.height = 0;
      this.#glSource = local.canvas;
      this.#glMeta = local.meta;
      return;
    }
    this.#glSource = this.#bitmap;
    this.#glMeta = this.#meta;
  }

  // A rewritten/preserved drawing buffer breaks the vault's core
  // readback guarantee. Under integrity:'lock' (fortress default) that is
  // fatal for this instance — blackout instead of silently gifting an
  // untainted 2D fallback; under 'monitor' it is a strike + event.
  #flagPreserveRewrite(source) {
    if (this.#preserveFlagged) return;
    this.#preserveFlagged = true;
    this.#host.dispatchEvent(new CustomEvent('archx-integrity', {
      detail: { issue: 'preserveDrawingBuffer-rewritten', source }, bubbles: true,
    }));
    if (this.#attemptHandler) this.#attemptHandler('integrity:preserve-drawing-buffer');
    if (this.#options.integrity === 'lock') {
      this.#integrityHardLock = true;
      this._stopGlLoop();
      if (this.#gl) {
        try {
          const lose = this.#gl.getExtension && glNative(this.#gl, 'getExtension', 'WEBGL_lose_context');
          if (lose?.loseContext) { this.#glReleasing = true; lose.loseContext(); }
        } catch { /* best-effort */ }
      }
      this.#paintBlackout();
    }
  }

  #paintBlackout() {
    try {
      this.#wrap.classList.add('blackout');
      if (!this.#canvas || this.#destroyed) return;
      const { w, h } = this._backingSize();
      this.#tilesEl.hidden = true;
      this.#canvas.hidden = false;
      if (this.#canvas.width !== w || this.#canvas.height !== h) {
        this.#canvas.width = w; this.#canvas.height = h;
      }
      const ctx = getNativeContext(this.#canvas, '2d', { alpha: false });
      if (ctx) { ctx.fillStyle = '#000'; ctx.fillRect(0, 0, w, h); }
    } catch { /* blackout is best-effort; the wrap class still applies */ }
  }

  // The clear-at-composite only happens for a canvas that was actually
  // presented. A below-fold canvas (our visibility observer uses a 500px
  // rootMargin, so the loop runs before the element is on screen) keeps
  // its drawing buffer indefinitely — indistinguishable from a forced
  // preserve. The canary therefore only runs when the canvas is provably
  // inside the layout viewport, and defers (never flags) otherwise.
  #canaryPresentable() {
    try {
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return false;
      const el = this.#canvas || this.#wrap;
      if (!el?.getBoundingClientRect) return false;
      const r = el.getBoundingClientRect();
      if (!(r.width > 0 && r.height > 0)) return false;
      const vw = window.innerWidth || document.documentElement?.clientWidth || 0;
      const vh = window.innerHeight || document.documentElement?.clientHeight || 0;
      if (!(vw > 0 && vh > 0)) return false;
      const overlapX = Math.min(r.right, vw) - Math.max(r.left, 0);
      const overlapY = Math.min(r.bottom, vh) - Math.max(r.top, 0);
      return overlapX >= 8 && overlapY >= 8;
    } catch { return false; }
  }

  // One-time behavioral probe (per GL context): on a genuine
  // preserveDrawingBuffer:false swapchain, the drawing buffer is cleared
  // at composite time, so a readPixels two frames later (before drawing)
  // returns clear color. If our painted pixels are still there, a
  // getContext proxy preserved the buffer even if getContextAttributes
  // was spoofed to deny it.
  #captureCanaryProbe(gl, w, h) {
    try {
      if (!NATIVES.glReadPixels || w < 8 || h < 8) { this.#canaryDone = true; return; }
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
        this.#canaryProbe = probe;
        this.#canaryPause = true;
        // Chromium clears the drawing buffer only after the SECOND
        // following rAF (verified empirically); checking one frame after
        // capture reads the not-yet-composited buffer and false-positives.
        this.#canaryWait = 2;
      } else this.#canaryDone = true;
    } catch { this.#canaryDone = true; }
  }

  #checkCanaryProbe(gl) {
    const probe = this.#canaryProbe;
    this.#canaryProbe = null;
    this.#canaryPause = false;
    if (!probe?.length || !NATIVES.glReadPixels) { this.#canaryDone = true; return; }
    // Scrolled out of the viewport between capture and check: the frame
    // may never have been composited, so surviving pixels prove nothing.
    // Defer — recapture on a later presented frame, never flag.
    if (!this.#canaryPresentable()) return;
    this.#canaryDone = true;
    try {
      const px = new Uint8Array(4);
      let preserved = true;
      for (const p of probe) {
        nativeCall(NATIVES.glReadPixels, gl, [p.x, p.y, 1, 1, gl.RGBA, gl.UNSIGNED_BYTE, px]);
        if (px[0] !== p.r || px[1] !== p.g || px[2] !== p.b) { preserved = false; break; }
      }
      if (preserved) this.#flagPreserveRewrite('canary');
    } catch { /* inconclusive: never lock on a failed probe */ }
  }

  _tryRenderWebGL() {
    if (this.#integrityHardLock) return false;
    if (glSlotsInUse() >= GL_CONTEXT_BUDGET && !this.#gl) {
      if (!this.#glBudgetWarned) {
        this.#glBudgetWarned = true;
        this.#host.dispatchEvent(new CustomEvent('archx-webgl-budget', {
          detail: { inUse: glSlotsInUse(), budget: GL_CONTEXT_BUDGET }, bubbles: true,
        }));
        emitClientEvent('archx.webgl_budget', { outcome: 'canvas2d-fallback' }, this);
      }
      return false;
    }
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
      // A getContext proxy can honor our call but rewrite the attributes:
      // verify the actual context configuration (via the captured native
      // getter — the method itself can be proxied, which is what the
      // post-composite readPixels canary below catches behaviorally).
      try {
        const attrs = NATIVES.glGetContextAttributes
          ? nativeCall(NATIVES.glGetContextAttributes, gl, [])
          : glNative(gl, 'getContextAttributes', );
        if (attrs && attrs.preserveDrawingBuffer === true) {
          const lose = gl.getExtension && glNative(gl, 'getExtension', 'WEBGL_lose_context');
          try { lose && lose.loseContext && lose.loseContext(); } catch { /* best-effort */ }
          this.#flagPreserveRewrite('attributes');
          this.#fresh2dCanvas();
          return false;
        }
      } catch { /* attributes unreadable: proceed, other layers still apply */ }
      this.#gl = gl;
      acquireGlSlot();
      // Prototype readbacks already return black (drawing buffer is not
      // preserved), but captureStream() could record frames WHILE temporal
      // animation draws them; shadow the instance APIs here too.
      this._poison(canvas, null);
      // Defence in depth (audit D8): shadow instance readPixels too.
      // Prototype-call readbacks still return the cleared (black) buffer
      // because preserveDrawingBuffer stays false; this ensures a direct
      // gl.readPixels() instance call can never observe a live frame even
      // if a future path or browser retained the drawing buffer. The
      // internal preserve-rewrite canary uses the captured native
      // function and is unaffected.
      try {
        Object.defineProperty(gl, 'readPixels', {
          value: function (x, y, width, height, format, type, pixels) {
            try { if (pixels && typeof pixels.fill === 'function') pixels.fill(0); } catch { /* stay silent */ }
          },
          writable: false, configurable: false,
        });
      } catch { /* platform object refused the shadow; buffer policy still applies */ }
      canvas.addEventListener('webglcontextlost', (e) => {
        e.preventDefault();
        this.#gl = null; releaseGlSlot();
        this.#glSource = null; this.#glMeta = null;
        this.#canaryDone = false; // re-probe if a fresh context is created
        if (this.#glReleasing) {
          // Intentional release (viewport unload / hard lock): stay
          // unloaded; the visibility lifecycle re-renders on return.
          this.#glReleasing = false;
          this.#fresh2dCanvas();
          return;
        }
        this.#fresh2dCanvas();
        if (this.#bitmap) this._render2d();
        else { this.#loaded = false; this._load(); }
      }, { signal: this.#abort.signal });
      if (!this._initGl(gl)) {
        this.#gl = null; releaseGlSlot();
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
    // Decoy for any instance-level grabbers (prototype calls return black
    // anyway). REAL decoys are generated BEFORE strict release, while the
    // decoded bitmap still exists; the default black policy defers to
    // #getDecoy() (saving this 320px unscramble per GL instance too).
    const decoyH = Math.max(1, Math.round(320 * this.#meta.origH / this.#meta.origW));
    const wantRealDecoy = this.#options.onExtract === 'lowres' || this.#options.onExtract === 'scrambled';
    if (!this.#decoy && this.#bitmap && wantRealDecoy) {
      const { full } = this._workingCanvas(320, decoyH);
      this.#prepareDecoy(full, full.width, full.height);
      full.width = 0;
    } else if (!this.#decoySize) {
      this.#decoySize = { w: 320, h: decoyH };
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
          // MEDIAN of any short capture converges to c - b/3, not c —
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
      const s = glNative(gl, 'createShader', type);
      glNative(gl, 'shaderSource', s, srcText); glNative(gl, 'compileShader', s);
      if (!glNative(gl, 'getShaderParameter', s, gl.COMPILE_STATUS)) return null;
      return s;
    };
    const v = compile(gl.VERTEX_SHADER, vs);
    const f = compile(gl.FRAGMENT_SHADER, fs);
    if (!v || !f) return false;
    const prog = glNative(gl, 'createProgram', );
    glNative(gl, 'attachShader', prog, v); glNative(gl, 'attachShader', prog, f); glNative(gl, 'linkProgram', prog);
    if (!glNative(gl, 'getProgramParameter', prog, gl.LINK_STATUS)) return false;
    glNative(gl, 'useProgram', prog);
    this.#glProg = prog;
    this.#glLoc = {};
    ['uTex','uMap','uWm','uGrid','uCrop','uFitScale','uFitOffset','uScrambled','uSeed','uWmOn',
     'uLensOn','uLensActive','uLensCenter','uLensRadius','uResolution','uLocked',
     'uTemporalOn','uTemporalSign','uTemporalStrength','uTemporalBlock','uTemporalPattern','uTemporalChroma',
     'uTemporalDuty','uTemporalBias','uBiasSeed',
     'uInterlaceOn','uInterlacePhase','uInterlacePhases','uInterlaceLayout','uInterlaceCell','uInterlaceAxis',
     'uInterlaceFill','uInterlaceFillBlock','uInterlaceFillStrength','uInterlaceHiddenScale','uInterlaceActiveGain','uInterlaceNoiseStrength','uInterlaceBias']
      .forEach((n) => { this.#glLoc[n] = glNative(gl, 'getUniformLocation', prog, n); });
    const buf = glNative(gl, 'createBuffer', );
    glNative(gl, 'bindBuffer', gl.ARRAY_BUFFER, buf);
    glNative(gl, 'bufferData', gl.ARRAY_BUFFER, new Float32Array([-1,-1, 1,-1, -1,1, 1,1]), gl.STATIC_DRAW);
    glNative(gl, 'enableVertexAttribArray', 0);
    glNative(gl, 'vertexAttribPointer', 0, 2, gl.FLOAT, false, 0, 0);
    this.#glTex = glNative(gl, 'createTexture', );
    this.#glMap = glNative(gl, 'createTexture', );
    this.#glWm = glNative(gl, 'createTexture', );
    return true;
  }

  _uploadGlTexture(gl) {
    const meta = this.#glMeta || this.#meta;
    const source = this.#glSource || this.#bitmap;
    const texImage = (...args) => (NATIVES.glTexImage2D
      ? nativeCall(NATIVES.glTexImage2D, gl, args)
      : glNative(gl, 'texImage2D', ...args));
    glNative(gl, 'activeTexture', gl.TEXTURE0);
    glNative(gl, 'bindTexture', gl.TEXTURE_2D, this.#glTex);
    glNative(gl, 'texParameteri', gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    glNative(gl, 'texParameteri', gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    glNative(gl, 'texParameteri', gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    glNative(gl, 'texParameteri', gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    glNative(gl, 'pixelStorei', gl.UNPACK_FLIP_Y_WEBGL, false);
    texImage(gl.TEXTURE_2D, 0, gl.RGBA, gl.RGBA, gl.UNSIGNED_BYTE, source);
    if (!meta.plan) {
      // A clean (unscrambled) texture can use real trilinear mipmaps. A
      // scrambled texture deliberately cannot: mip levels would blend across
      // neighbouring shuffled tiles; sampleImage() supersamples instead.
      try {
        glNative(gl, 'generateMipmap', gl.TEXTURE_2D);
        glNative(gl, 'texParameteri', gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR_MIPMAP_LINEAR);
      } catch {}
    }
    // Tile map: for each ORIGINAL tile -> scrambled source tile + flips
    glNative(gl, 'activeTexture', gl.TEXTURE1);
    glNative(gl, 'bindTexture', gl.TEXTURE_2D, this.#glMap);
    glNative(gl, 'texParameteri', gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
    glNative(gl, 'texParameteri', gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.NEAREST);
    glNative(gl, 'texParameteri', gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    glNative(gl, 'texParameteri', gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
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
    glNative(gl, 'activeTexture', gl.TEXTURE2);
    glNative(gl, 'bindTexture', gl.TEXTURE_2D, this.#glWm);
    glNative(gl, 'texParameteri', gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    glNative(gl, 'texParameteri', gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    glNative(gl, 'texParameteri', gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    glNative(gl, 'texParameteri', gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    const wm = this.#options.watermark;
    this.#glWmOn = 0;
    if (wm) {
      const cfg = typeof wm === 'string' ? { text: wm } : wm;
      const text = String(cfg.text || '').replace('{session}', sessionId().slice(0, 6));
      if (text) {
        const c = makeCanvas();
        // Right-size the watermark texture to the current backing store
        // (this re-runs on resize re-uploads): a fixed 1024px texture
        // wasted raster time + VRAM on the small tiles that dominate
        // galleries, for zero visible gain.
        const texW = Math.max(256, Math.min(1024, this.#canvas?.width || 1024));
        c.width = texW; c.height = Math.max(64, Math.round(texW * meta.origH / meta.origW));
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
          const stepX = Math.max(fs * 3, ctx.measureText(text).width + fs * 2.2);
          let row = 0;
          for (let y = -diag / 2; y < diag / 2; y += fs * 4.2, row++) {
            const x0 = (row % 2) * (stepX / 2) - diag / 2;
            for (let x = x0; x < diag / 2 + stepX; x += stepX) ctx.fillText(text, x, y);
          }
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
    if (!this.#lastInteractAt) this.#lastInteractAt = performance.now();
    if (this.#glContinuous()) this.#glFrameBudget = Infinity;
    else this.#glFrameBudget = Math.max(this.#glFrameBudget, Math.max(1, frames | 0));
    if (this.#raf) return;
    const gl = this.#gl;
    const draw = () => {
      this.#raf = 0;
      if (this.#destroyed || !this.#gl) return;
      // Post-composite canary: hold drawing for two frames so the captured
      // frame is definitely composited (and, if honest, cleared), then
      // check before this frame draws anything.
      if (this.#canaryPause && this.#canaryProbe) {
        if (this.#canaryWait > 0) {
          this.#canaryWait--;
          this.#raf = requestAnimationFrame(draw);
          return;
        }
        this.#checkCanaryProbe(gl);
      }
      if (this.#integrityHardLock) return;
      const { w, h } = this._backingSize();
      if (this.#canvas.width !== w || this.#canvas.height !== h) {
        this.#canvas.width = w; this.#canvas.height = h;
      }
      this.#renderedW = w; this.#renderedH = h;
      glNative(gl, 'viewport', 0, 0, w, h);
      glNative(gl, 'useProgram', this.#glProg);
      const L = this.#glLoc;
      const meta = this.#glMeta || this.#meta;
      glNative(gl, 'uniform1i', L.uTex, 0); glNative(gl, 'uniform1i', L.uMap, 1); glNative(gl, 'uniform1i', L.uWm, 2);
      glNative(gl, 'uniform1f', L.uGrid, meta.plan ? meta.plan.grid : 1);
      glNative(gl, 'uniform2f', L.uCrop, meta.origW / meta.padW, meta.origH / meta.padH);
      // fit
      const srcRatio = meta.origW / meta.origH;
      const dstRatio = w / h;
      let sx = 1, sy = 1, ox = 0, oy = 0;
      if (this.#options.fit === 'cover') {
        if (srcRatio > dstRatio) { sx = dstRatio / srcRatio; ox = (1 - sx) / 2; }
        else { sy = srcRatio / dstRatio; oy = (1 - sy) / 2; }
      } else if (this.#options.fit === 'contain') {
        // For contain, invert: scale uv beyond [0,1] and let shader black-bar it
        if (srcRatio > dstRatio) { const s = srcRatio / dstRatio; sy = s; oy = -(s - 1) / 2; sx = 1; ox = 0; }
        else { const s = dstRatio / srcRatio; sx = s; ox = -(s - 1) / 2; }
      }
      glNative(gl, 'uniform2f', L.uFitScale, sx, sy);
      glNative(gl, 'uniform2f', L.uFitOffset, ox, oy);
      glNative(gl, 'uniform1f', L.uScrambled, meta.plan ? 1 : 0);
      // Per-frame noise seed: with a session-constant seed the temporal
      // delta for a block is the same value every cycle, so a 6-frame
      // capture's multiset is {c, c+d, c-d}x2 and the median IS c exactly.
      // Re-seeding every presented frame makes deltas independent draws —
      // short-window medians land off-target and recovery needs long
      // averaging (which remains possible; this raises cost, not a wall).
      glNative(gl, 'uniform1f', L.uSeed, (hashSeed(sessionId()) % 1000) / 37.0 + Math.random() * 997.0);
      glNative(gl, 'uniform1f', L.uWmOn, this.#glWmOn || 0);
      const lensCfg = typeof this.#options.lens === 'object' && this.#options.lens ? this.#options.lens : {};
      glNative(gl, 'uniform1f', L.uLensOn, this.#options.lens ? 1 : 0);
      glNative(gl, 'uniform1f', L.uLensActive, this.#lensPoint ? 1 : 0);
      glNative(gl, 'uniform2f', L.uLensCenter, this.#lensPoint?.x ?? -10, this.#lensPoint?.y ?? -10);
      glNative(gl, 'uniform1f', L.uLensRadius, this.#lensRadiusPx(w, h, lensCfg.radius ?? 0.30));
      glNative(gl, 'uniform2f', L.uResolution, w, h);
      glNative(gl, 'uniform1f', L.uLocked, Date.now() < this.#lockedUntil ? 1 : 0);
      const temporal = this.#temporalConfig();
      // Idle throttle: after 5 s without pointer activity over this
      // instance, a continuous temporal loop draws 1 frame in 3 (~20 Hz).
      // Modulation — and its capture friction — continues; it just stops
      // burning full-rate GPU/battery (and blocking panel self-refresh)
      // for an unwatched still. Any interaction restores full rate.
      if (temporal && performance.now() - this.#lastInteractAt > 5000) {
        if ((this.#idleSkip++ % 3) !== 0) {
          this.#raf = requestAnimationFrame(draw);
          return;
        }
      } else {
        this.#idleSkip = 0;
      }
      const interlace = temporal?.interlace || null;
      const interlacePhases = interlace?.phases || 2;
      const interlacePhase = ((this.#temporalPhase % interlacePhases) + interlacePhases) % interlacePhases;
      glNative(gl, 'uniform1f', L.uTemporalOn, temporal?.noise ? 1 : 0);
      glNative(gl, 'uniform1f', L.uTemporalSign, this.#temporalSign);
      glNative(gl, 'uniform1f', L.uTemporalStrength, temporal ? temporal.strength * (0.75 + Math.random() * 0.5) : 0);
      glNative(gl, 'uniform1f', L.uTemporalDuty, [2 / 3, -1 / 3, -1 / 3][this.#dutyIndex % 3]);
      glNative(gl, 'uniform1f', L.uTemporalBias, temporal ? temporal.strength * 0.55 : 0);
      glNative(gl, 'uniform1f', L.uBiasSeed, this.#biasSeed);
      glNative(gl, 'uniform1f', L.uTemporalBlock, temporal ? temporal.block : 1);
      glNative(gl, 'uniform1f', L.uTemporalPattern, temporal ? temporal.patternCode : 0);
      glNative(gl, 'uniform1f', L.uTemporalChroma, temporal?.chroma ? 1 : 0);
      glNative(gl, 'uniform1f', L.uInterlaceOn, interlace ? 1 : 0);
      glNative(gl, 'uniform1f', L.uInterlacePhase, interlacePhase);
      glNative(gl, 'uniform1f', L.uInterlacePhases, interlacePhases);
      glNative(gl, 'uniform1f', L.uInterlaceLayout,
        interlace?.layout === 'pixels' ? 0
          : interlace?.layout === 'strips' ? 1
            : interlace?.layout === 'blocks' ? 2
              : 3);
      glNative(gl, 'uniform1f', L.uInterlaceCell, interlace?.cellSize || 1);
      glNative(gl, 'uniform1f', L.uInterlaceAxis, interlace?.axis === 'columns' ? 1 : 0);
      glNative(gl, 'uniform1f', L.uInterlaceFill,
        interlace?.fill === 'dim' ? 1
          : interlace?.fill === 'black' ? 2
            : interlace?.fill === 'noise' ? 3
              : 0);
      glNative(gl, 'uniform1f', L.uInterlaceFillBlock, interlace?.fillBlock || 12);
      glNative(gl, 'uniform1f', L.uInterlaceFillStrength, interlace?.fillStrength ?? 1);
      glNative(gl, 'uniform1f', L.uInterlaceHiddenScale, interlace?.hiddenScale ?? 0.3);
      glNative(gl, 'uniform1f', L.uInterlaceActiveGain, interlace?.activeGain ?? 1);
      glNative(gl, 'uniform1f', L.uInterlaceNoiseStrength, interlace?.noiseStrength ?? 0.16);
      glNative(gl, 'uniform1f', L.uInterlaceBias, interlace ? (interlace.noiseStrength ?? 0.16) * 0.55 : 0);
      nativeGlDrawArrays(gl, gl.TRIANGLE_STRIP, 0, 4);
      this.#glFrames++;
      if (!this.#canaryDone && !this.#canaryPause && this.#glFrames >= this.#canaryNextTry) {
        // Retry at most every 30 drawn frames until the canvas has been
        // presented on screen at least once (see #canaryPresentable).
        this.#canaryNextTry = this.#glFrames + 30;
        if (this.#canaryPresentable()) this.#captureCanaryProbe(gl, w, h);
      }
      if (temporal) {
        // Randomized sign (balance-corrected so long-run brightness stays
        // neutral) and shuffled phase order: fixed +- alternation let a
        // 60 fps recorder split frames by parity and separate the subsets
        // exactly.
        let nextSign = Math.random() < 0.5 ? 1 : -1;
        if (Math.abs(this.#signBalance + nextSign) > 2) nextSign = -nextSign;
        this.#temporalSign = nextSign;
        this.#signBalance += nextSign;
        this.#dutyIndex++;
        if (++this.#biasFrames >= 90) {
          this.#biasFrames = 0;
          this.#biasSeed = Math.random() * 100;
        }
        this.#temporalIndex++;
        this.#temporalPhase = this.#nextPhase(interlace ? interlacePhases : 2);
      }
      if (this.#glFrameBudget !== Infinity && this.#glFrameBudget > 0) this.#glFrameBudget--;
      const keepGoing = this.#glContinuous() || this.#glFrameBudget > 0 || this.#canaryPause;
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
      canary: {
        done: this.#canaryDone, pause: this.#canaryPause, wait: this.#canaryWait,
        presentable: this.#gl ? this.#canaryPresentable() : false,
        preserveFlagged: this.#preserveFlagged, hardLock: this.#integrityHardLock,
      },
      idleMs: this.#lastInteractAt ? Math.round(performance.now() - this.#lastInteractAt) : -1,
      glBudget: this.#glFrameBudget === Infinity ? 'inf' : this.#glFrameBudget,
      rafPending: !!this.#raf, visible: this.#visible, unloaded: this.#unloaded,
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
      try { glNative(this.#gl, 'getExtension', 'WEBGL_lose_context')?.loseContext(); } catch {}
      releaseGlSlot();
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
