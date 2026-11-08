import { resampleRgba, rotateRgba } from './pixels.js';

const clampByteSize = (value) => Math.max(64, Math.round(value));

function centerCrop(rgba, width, height, fraction) {
  if (fraction >= 1) return { rgba, width, height };
  const cropWidth = clampByteSize(width * fraction);
  const cropHeight = clampByteSize(height * fraction);
  const left = Math.round((width - cropWidth) / 2);
  const top = Math.round((height - cropHeight) / 2);
  const out = new Uint8Array(cropWidth * cropHeight * 4);
  for (let y = 0; y < cropHeight; y++) {
    const start = ((top + y) * width + left) * 4;
    out.set(rgba.subarray(start, start + cropWidth * 4), y * cropWidth * 4);
  }
  return { rgba: out, width: cropWidth, height: cropHeight };
}

function signalScore(hit) {
  const sync = hit?.syncRegistration;
  const signal = Number.isFinite(sync?.meanSignal) ? sync.meanSignal : hit?.meanSignal;
  const agreement = Number.isFinite(sync?.agreement) ? sync.agreement : hit?.agreement;
  if (!Number.isFinite(signal)) return 0;
  return signal * (Number.isFinite(agreement) ? Math.max(0, agreement) : 1);
}

/**
 * Pilot-feature affine deskew for offline forensic scans.
 *
 * The v5 sync pilot is a keyed, spatial feature set. Its correlation score
 * supplies a rotation estimate without OCR, EXIF orientation, or an image
 * origin prior. We screen a low-resolution proxy in coarse 5-degree steps,
 * refine the strongest two basins at 1-degree steps, and let the caller
 * confirm candidates at full resolution (optionally with geometry and
 * keystone correction). This is intentionally not used on request paths.
 */
export function searchStegoDeskew(rgba, width, height, probe, {
  maxProxyEdge = 640,
  maxCandidates = 3,
  shouldStop = () => false,
} = {}) {
  if (!(rgba instanceof Uint8Array) || rgba.length < width * height * 4 ||
      !Number.isSafeInteger(width * height * 4) || typeof probe !== 'function') return [];

  const scale = Math.min(1, maxProxyEdge / Math.max(width, height));
  const proxyWidth = clampByteSize(width * scale);
  const proxyHeight = clampByteSize(height * scale);
  const proxy = scale < 1 ? resampleRgba(rgba, width, height, proxyWidth, proxyHeight) : rgba;
  const samples = new Map();
  const scan = (degrees) => {
    const angle = Math.round(degrees * 10) / 10;
    if (Math.abs(angle) < 0.01 || samples.has(angle) || shouldStop()) return;
    const corrected = rotateRgba(proxy, proxyWidth, proxyHeight, (-angle * Math.PI) / 180);
    let best = null;
    for (const fraction of [1, 0.96, 0.92]) {
      const view = centerCrop(corrected, proxyWidth, proxyHeight, fraction);
      const hit = probe(view.rgba, view.width, view.height, angle);
      if (hit?.found) {
        samples.set(angle, { angle, score: signalScore(hit), hit });
        return;
      }
      const score = signalScore(hit);
      if (!best || score > best.score) best = { angle, score, hit };
      if (shouldStop()) break;
    }
    if (best) samples.set(angle, best);
  };

  // Expand symmetrically so either camera rotation direction gets the same
  // early-search budget. Five-degree steps cover the routine 10–30° range.
  for (let magnitude = 5; magnitude <= 30; magnitude += 5) {
    scan(magnitude);
    if (samples.get(magnitude)?.hit?.found) break;
    scan(-magnitude);
    if (samples.get(-magnitude)?.hit?.found || shouldStop()) break;
  }

  if (![...samples.values()].some((sample) => sample.hit?.found) && !shouldStop()) {
    const leaders = [...samples.values()].sort((a, b) => b.score - a.score).slice(0, 2);
    for (const leader of leaders) {
      for (let delta = -2; delta <= 2.001; delta += 1) {
        if (delta !== 0) scan(leader.angle + delta);
        if (shouldStop() || [...samples.values()].some((sample) => sample.hit?.found)) break;
      }
      if (shouldStop() || [...samples.values()].some((sample) => sample.hit?.found)) break;
    }
  }

  return [...samples.values()]
    .sort((a, b) => (b.hit?.found ? 1 : 0) - (a.hit?.found ? 1 : 0) || b.score - a.score)
    .slice(0, maxCandidates);
}
