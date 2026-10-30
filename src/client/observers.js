/**
 * Shared Intersection/Resize observers, global interaction guards, DevTools watcher, and the WebGL context budget.
 */
import { hostToInstance, instances } from './registry.js';

export function getVisibilityObserver(rootMargin = '500px') {
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

export let sharedResizeObserver = null;
export function getResizeObserver() {
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
export let globalGuardsInstalled = false;
export function installGlobalGuards() {
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
export let devtoolsTimer = null;
export function ensureDevtoolsWatcher() {
  if (devtoolsTimer) return;
  const check = () => {
    // Hidden tabs need no DevTools polling (and rAF-driven temporal
    // loops already stop with the tab); skip the layout reads.
    if (typeof document !== 'undefined' && document.hidden) return;
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
export const GL_CONTEXT_BUDGET = 8;

/* ================================================================== */
/* Small helpers                                                       */
/* ================================================================== */

export const $ = (t) => (typeof t === 'string' ? document.querySelector(t) : t);
export const visibilityObservers = new Map(); // rootMargin -> IntersectionObserver

/** WebGL context-budget accounting (see GL_CONTEXT_BUDGET). */
export function glSlotsInUse() { return glContextsInUse; }
export function acquireGlSlot() { glContextsInUse++; }
export function releaseGlSlot() { glContextsInUse = Math.max(0, glContextsInUse - 1); }
