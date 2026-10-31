/**
 * Public loading helpers: loadImage, galleries, <img> protection sweep, asset preloading, and the <archx-image> element.
 */
import { chooseAssetVariant, loadAssetManifest, verifyAssetVariantIntegrity } from './assets.js';
import { instances } from './registry.js';
import { $ } from './observers.js';
import { fetchBounded, fetchControls, nonRetryableError } from './network.js';
import { DEFAULTS, DEFAULT_SOURCE_WIDTH_BUCKETS, mergeOptions, preset } from './options.js';
import { boundedInteger, canonicalSourceWidth, effectiveSampling, fetchPriorityInit, networkConnectionInfo, normalizedHttpCache } from './sampling.js';
import { ProtectedImage } from './viewer.js';

export function loadImage(target, source, options) {
  const inst = new ProtectedImage(target, source, options);
  // Return the instance immediately (sync handle) AND make it awaitable
  // via inst.ready. Most callers can fire-and-forget.
  return inst;
}

/**
 * Warm the manifest + browser HTTP caches for precomputed assets (a hero
 * image, the next carousel slide, likely detail views) without mounting a
 * viewer. Variant bytes are integrity-checked exactly like a real load and
 * then left in the HTTP cache, so the eventual `load.image(el, {assetId})`
 * skips the network entirely. With `networkAware`, Save-Data users are
 * never charged for speculative preloads.
 * Returns `{ preloaded: [id…], failed: [{ id, error }…] }` (plus
 * `skipped: 'save-data'` when data-saver short-circuits the call).
 */
export async function preloadAssets(assetIds, options = {}) {
  if (!Array.isArray(assetIds)) throw new Error('Archx: preloadAssets requires an array of asset ids');
  const ids = [...new Set(assetIds.filter(
    (id) => typeof id === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(id),
  ))].slice(0, 500);
  const o = mergeOptions(options);
  const controls = fetchControls(o);
  if (o.networkAware === true && networkConnectionInfo()?.saveData) {
    return Object.freeze({
      preloaded: Object.freeze([]),
      failed: Object.freeze([]),
      skipped: 'save-data',
    });
  }
  const manifestSource = options.assetManifest || o.assetManifest;
  if (!manifestSource) throw new Error('Archx: assetManifest required for preloadAssets');
  const manifest = await loadAssetManifest(manifestSource, o, controls);
  const { dprCap } = effectiveSampling(o);
  const viewportWidth = typeof window !== 'undefined' ? window.innerWidth || 1280 : 1280;
  const deviceRatio = typeof devicePixelRatio !== 'undefined' ? devicePixelRatio || 1 : 1;
  const defaultWidth = Math.ceil(Math.min(viewportWidth * Math.min(deviceRatio, dprCap), 2560));
  const wantedWidth = canonicalSourceWidth(
    boundedInteger(options.width, defaultWidth, 1, 16384),
    o.sourceWidthBuckets,
    boundedInteger(o.maxSourceWidth, DEFAULTS.maxSourceWidth, 64, 16384),
  );
  const cacheMode = normalizedHttpCache(o.assetHttpCache, 'default');
  const preloaded = [];
  const failed = [];
  let cursor = 0;
  const workers = Array.from({ length: Math.min(4, ids.length) }, async () => {
    while (cursor < ids.length) {
      const id = ids[cursor++];
      try {
        const asset = manifest.assets.get(id);
        if (!asset) throw new Error('asset id is not present in the manifest');
        const variant = chooseAssetVariant(asset, wantedWidth);
        const { bytes } = await fetchBounded(variant.url.href, {
          method: 'GET',
          credentials: controls.credentials,
          cache: cacheMode,
          ...fetchPriorityInit({ ...o, fetchPriority: o.fetchPriority || 'low' }),
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
    failed: Object.freeze(failed),
  });
}

export function loadGallery(container, items, options = {}) {
  const host = $(container);
  if (!host) throw new Error('Archx: gallery container not found');
  const galleryDefaults = {
    mode: 'lite',
    qualityProfile: 'catalog',
    unloadOnExit: true,
    sourceOversample: 1,
    dprCap: 2,
    cachePayload: true,
    reloadOnResize: 'never',
    tokenBatch: true,
    tokenBatchDelayMs: 20,
    tokenBatchMaxDelayMs: 150,
    sourceWidthBuckets: DEFAULT_SOURCE_WIDTH_BUCKETS,
    networkAware: true,
    httpCache: 'default',
    bitmapCacheMaxEntries: 24,
    bitmapCacheMaxBytes: 128 * 1024 * 1024,
  };
  const made = items.map((item) => {
    const cell = document.createElement('div');
    cell.className = options.itemClass || 'archx-gallery-item';
    host.appendChild(cell);
    const isObj = item && typeof item === 'object' &&
      ('src' in item || 'id' in item || 'assetId' in item || 'asset' in item);
    const src = isObj && 'src' in item ? item.src : item;
    const per = isObj ? { alt: item.alt || '', ...(item.options || {}) } : {};
    return new ProtectedImage(cell, src, { ...galleryDefaults, ...options, ...per });
  });
  return { instances: made, ready: Promise.allSettled(made.map((i) => i.ready)) };
}

/** Replace existing <img data-protect> (or a selector) with protected views. */
export function protectAll(selectorOrNodes = 'img[data-protect], [data-archx-src]', options = {}) {
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
export function defineElement() {
  if (typeof customElements === 'undefined' || customElements.get('archx-image')) return;
  // Element -> instance in a WeakMap: no public `_inst` handle on the DOM node.
  const elementInstances = new WeakMap();
  const elementInners = new WeakMap();
  // Boolean-ish attributes parse VALUES, not mere presence, so markup
  // generated by frameworks (scrambled="false") cannot silently ENABLE
  // a protection (or a cost) the author turned off. Absent = undefined,
  // letting preset/global defaults apply.
  const boolAttr = (el, name) => {
    if (!el.hasAttribute(name)) return undefined;
    const v = String(el.getAttribute(name) ?? '').trim().toLowerCase();
    return !(v === 'false' || v === '0' || v === 'off' || v === 'no');
  };
  class ArchxImage extends HTMLElement {
    static get observedAttributes() { return ['src', 'image-id', 'asset-id', 'asset-manifest', 'mode', 'renderer', 'preset', 'quality-profile', 'watermark', 'alt', 'fit', 'grid', 'key', 'scrambled', 'lens', 'capture-shield', 'temporal-shield', 'camera-shield', 'temporal-interlace', 'temporal-interlace-engine', 'temporal-interlace-layout', 'temporal-interlace-phases', 'temporal-interlace-cell-size', 'temporal-interlace-fill', 'temporal-interlace-refresh-hz', 'render-loop', 'reload-on-resize', 'on-extract', 'token-endpoint', 'token-method', 'token-transport', 'token-batch', 'fetch-priority', 'proof-of-possession', 'cache-scope', 'taint-readback', 'taint-url', 'plan-version']; }
    connectedCallback() {
      if (elementInstances.has(this)) return;
      this.style.display = this.style.display || 'block';
      const inner = document.createElement('div');
      inner.style.width = '100%'; inner.style.height = '100%';
      this.appendChild(inner);
      elementInners.set(this, inner);
      const id = this.getAttribute('image-id');
      const assetId = this.getAttribute('asset-id');
      const src = assetId ? { assetId } : id ? { id } : this.getAttribute('src');
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
      const cameraAttr = boolAttr(this, 'camera-shield');
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
        scrambled: boolAttr(this, 'scrambled'),
        lens: boolAttr(this, 'lens') ?? presetOptions.lens,
        captureShield: boolAttr(this, 'capture-shield') ?? presetOptions.captureShield,
        temporalShield: boolAttr(this, 'temporal-shield') ?? presetOptions.temporalShield,
        cameraShield: cameraAttr === true
          ? { pattern: 'checker', chroma: true }
          : cameraAttr === false ? false : presetOptions.cameraShield,
        temporalInterlace,
        renderLoop: this.getAttribute('render-loop') || presetOptions.renderLoop,
        reloadOnResize: this.getAttribute('reload-on-resize') || presetOptions.reloadOnResize,
        onExtract: this.getAttribute('on-extract') || presetOptions.onExtract,
        tokenEndpoint: this.getAttribute('token-endpoint') || undefined,
        tokenMethod: this.getAttribute('token-method') || undefined,
        tokenTransport: this.getAttribute('token-transport') || undefined,
        tokenBatch: this.hasAttribute('token-batch')
          ? this.getAttribute('token-batch') !== 'false'
          : presetOptions.tokenBatch,
        assetManifest: this.getAttribute('asset-manifest') || presetOptions.assetManifest,
        assetIntegrity: this.getAttribute('asset-integrity') || presetOptions.assetIntegrity,
        assetManifestIntegrity: this.getAttribute('asset-manifest-integrity') || presetOptions.assetManifestIntegrity,
        networkAware: this.hasAttribute('network-aware')
          ? this.getAttribute('network-aware') !== 'false'
          : presetOptions.networkAware,
        taintReadback: this.getAttribute('taint-readback') || presetOptions.taintReadback,
        taintUrl: this.getAttribute('taint-url') || presetOptions.taintUrl,
        planVersion: this.hasAttribute('plan-version')
          ? Number(this.getAttribute('plan-version'))
          : presetOptions.planVersion,
        fetchPriority: this.getAttribute('fetch-priority') || presetOptions.fetchPriority,
        proofOfPossession: this.getAttribute('proof-of-possession') || undefined,
        cacheScope: this.getAttribute('cache-scope') || undefined,
      });
      elementInstances.set(this, inst);
      this.ready = inst.ready;
    }
    disconnectedCallback() {
      const inst = elementInstances.get(this);
      if (inst) { inst.destroy(); elementInstances.delete(this); elementInners.delete(this); }
    }
    attributeChangedCallback(name, oldV, newV) {
      const inst = elementInstances.get(this);
      if (!inst || oldV === newV) return;
      // Source attributes hot-swap through the instance's reload path...
      if (name === 'src') { if (newV) inst.reload(newV); return; }
      if (name === 'image-id') { if (newV) inst.reload({ id: newV }); return; }
      if (name === 'asset-id') { if (newV) inst.reload({ assetId: newV }); return; }
      // ...every other observed attribute re-mounts the instance so the
      // change actually takes effect (previously all were silently
      // ignored despite being listed in observedAttributes).
      try { inst.destroy(); } catch { /* remount best effort */ }
      elementInstances.delete(this);
      const inner = elementInners.get(this);
      if (inner) inner.remove();
      elementInners.delete(this);
      this.connectedCallback();
    }
  }
  customElements.define('archx-image', ArchxImage);
}
