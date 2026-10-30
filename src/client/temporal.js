/**
 * Temporal interlace/shield configuration: profiles, normalization, 60 Hz-safe phase rules, reduced-motion handling inputs.
 */
import { isPlainClientObject } from './network.js';

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
  // Higher-cost capture-resistant profile: three phases mean each spatial
  // subset is fully present only once per three display frames (about 20 Hz
  // per subset on a 60 Hz display), hidden cells use keyed noise instead of a
  // locally useful average, and the active subset is not gain-compensated.
  // This is visibly harsher and still cannot stop multi-frame/video capture;
  // it is an explicit quality/security trade-off, not a new guarantee.
  fortress60: Object.freeze({
    engine: 'auto', layout: 'blocks', cellSize: 6, phases: 3,
    fill: 'noise', fillBlock: 10, fillStrength: 1, noiseStrength: 0.55,
    hiddenScale: 0, activeGain: 1,
    refreshHz: 60, minPhaseHz: 20, optimizeRefresh: true,
    respectReducedMotion: true, chroma: true,
  }),
});

export function clampTemporalNumber(value, fallback, min, max) {
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
    noiseStrength: clampTemporalNumber(merged.noiseStrength ?? merged.strength, 0.16, 0, 0.65),
    chroma: merged.chroma !== false,
    respectReducedMotion: merged.respectReducedMotion !== false,
  });
}

/* ---------- shared concurrency limiter (hundreds of images, no jank) */
export const limiter = {
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
