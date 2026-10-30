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
 *
 * Implementation lives in src/client/ (one responsibility per module);
 * this file is the stable public assembly — see docs/ARCHITECTURE.md.
 */
import { ProtectedImage } from './client/viewer.js';
import {
  DEFAULT_SOURCE_WIDTH_BUCKETS, PRESETS, preset,
  getGlobalConfig, setGlobalConfig, sanitizeOptionsView, resetPageSession,
} from './client/options.js';
import { TEMPORAL_INTERLACE_PROFILES, normalizeTemporalInterlace } from './client/temporal.js';
import { instances } from './client/registry.js';
import { clearBitmapCache } from './client/bitmap-cache.js';
import { assetManifestCache } from './client/assets.js';
import {
  auditIntegrity, auditIntegrityDetails, captureEarlyIntegritySnapshot,
  verifyEarlyIntegritySnapshot, detectAutomation,
} from './client/integrity.js';
import { onClientEvent, offClientEvent, usePlugin, listPlugins } from './client/events.js';
import { loadImage, loadGallery, protectAll, preloadAssets, defineElement } from './client/loaders.js';

export const VERSION = '1.20.0';

const Archx = {
  version: VERSION,
  ProtectedImage,
  presets: PRESETS,
  preset,
  sourceWidthBuckets: DEFAULT_SOURCE_WIDTH_BUCKETS,
  temporalInterlaceProfiles: TEMPORAL_INTERLACE_PROFILES,
  normalizeTemporalInterlace,
  config(partial = {}) {
    const clean = {};
    for (const [k, v] of Object.entries(partial)) if (v !== undefined) clean[k] = v;
    const current = getGlobalConfig();
    setGlobalConfig({ ...current, ...clean, guards: { ...current.guards, ...(partial.guards || {}) } });
    // Never echo secrets back: any page script may call config() with no args.
    return sanitizeOptionsView(getGlobalConfig());
  },
  load: {
    image: loadImage,
    gallery: loadGallery,
  },
  // Friendly aliases
  image: loadImage,
  gallery: loadGallery,
  protectAll,
  /** Warm manifest + HTTP caches for {assetId} sources without mounting viewers. */
  preloadAssets,
  defineElement,
  /** Number of live protected images (the registry itself stays private). */
  get instanceCount() { return instances.size; },
  /** Prevent future reuse of shared decoded bitmaps (call on logout/account switch). */
  clearCaches() { clearBitmapCache(); assetManifestCache.clear(); resetPageSession(); },
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
  detectAutomation,
};

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', defineElement, { once: true });
  } else defineElement();
}

export {
  ProtectedImage, PRESETS, preset, DEFAULT_SOURCE_WIDTH_BUCKETS,
  TEMPORAL_INTERLACE_PROFILES, normalizeTemporalInterlace,
  auditIntegrity, auditIntegrityDetails, captureEarlyIntegritySnapshot,
  verifyEarlyIntegritySnapshot, detectAutomation,
  onClientEvent, offClientEvent, usePlugin, listPlugins, preloadAssets,
};
export default Archx;
