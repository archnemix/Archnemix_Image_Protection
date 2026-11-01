/**
 * Perceptual fingerprint (64-bit DCT pHash): the soft-binding layer
 * for ownership claims and near-duplicate matching. Bit format is
 * frozen — issued registries depend on it.
 */
import { asBytes } from './bytes.js';
import { flipPixels, rotatePixels90, transposePixels, resampleRgba } from './pixels.js';


// Module-static DCT basis (same Math.cos values, computed once instead
// of 256 transcendental calls per fingerprint).
const DCT_COSINES_32x8 = (() => {
  const table = new Float64Array(32 * 8);
  for (let x = 0; x < 32; x++) {
    for (let u = 0; u < 8; u++) table[x * 8 + u] = Math.cos(((2 * x + 1) * u * Math.PI) / (2 * 32));
  }
  return table;
})();

// The per-output-cell WEIGHT sums depend only on (w, h) — not on pixel
// data — and are accumulated in a fixed order, so caching the finished
// table per size is bit-identical to recomputing it. Bounded to the
// last few sizes (8 KB each); same-size streams (derivative pipelines)
// are the hit case that matters.
const _weightsCache = new Map();
function cachedWeights(w, h, SIZE, colSpans, rowSpans) {
  const key = w + 'x' + h;
  let table = _weightsCache.get(key);
  if (table) return table;
  const { starts: colStart, offsets: colOff, wts: colWts } = colSpans;
  const { starts: rowStart, offsets: rowOff, wts: rowWts } = rowSpans;
  table = new Float64Array(SIZE * SIZE);
  for (let y = 0; y < h; y++) {
    const oyBase = rowOff[y], oyCount = rowOff[y + 1] - oyBase;
    const oRow = rowStart[y];
    for (let x = 0; x < w; x++) {
      const oxBase = colOff[x], oxCount = colOff[x + 1] - oxBase;
      const oCol = colStart[x];
      for (let oyi = 0; oyi < oyCount; oyi++) {
        const wy = rowWts[oyBase + oyi];
        if (wy <= 0) continue;
        const rowBase = (oRow + oyi) * SIZE + oCol;
        for (let oxi = 0; oxi < oxCount; oxi++) {
          const wx = colWts[oxBase + oxi];
          if (wx <= 0) continue;
          table[rowBase + oxi] += wx * wy;
        }
      }
    }
  }
  _weightsCache.set(key, table);
  if (_weightsCache.size > 4) _weightsCache.delete(_weightsCache.keys().next().value);
  return table;
}

export function perceptualFingerprint(rgba, w, h) {
  if (!Number.isSafeInteger(w) || !Number.isSafeInteger(h) || w < 1 || h < 1) {
    throw new RangeError('Archx: invalid image dimensions for perceptual fingerprint');
  }
  const src = asBytes(rgba);
  const expected = w * h * 4;
  if (!Number.isSafeInteger(expected) || src.length < expected) {
    throw new RangeError('Archx: RGBA buffer is smaller than the image');
  }
  const SIZE = 32;
  const small = new Float64Array(SIZE * SIZE);

  // Area-average to 32×32. Area weighting is slower than nearest-neighbour
  // sampling but makes the fingerprint materially steadier across the exact
  // resampling choices of browsers, Sharp, and social-media transcoders.
  // The per-column/per-row overlap spans are precomputed once (they depend
  // only on x / y); the accumulation order — and therefore every float —
  // is unchanged, so fingerprints stay bit-identical to the direct form.
  // Spans flattened into typed arrays (offset+count+weights): the
  // accumulation below then touches no per-pixel objects, but visits
  // exactly the same (pixel, output) pairs in exactly the same order
  // with the same float arithmetic — fingerprints stay bit-identical.
  const spansFor = (n) => {
    const starts = new Int32Array(n);
    const offsets = new Int32Array(n + 1);
    const flat = [];
    for (let s = 0; s < n; s++) {
      const s0 = (s * SIZE) / n;
      const s1 = ((s + 1) * SIZE) / n;
      const start = Math.floor(s0);
      const end = Math.min(SIZE - 1, Math.ceil(s1) - 1);
      starts[s] = start;
      offsets[s] = flat.length;
      for (let o = start; o <= end; o++) flat.push(Math.min(s1, o + 1) - Math.max(s0, o));
    }
    offsets[n] = flat.length;
    return { starts, offsets, wts: Float64Array.from(flat) };
  };
  const colSpans = spansFor(w);
  const rowSpans = spansFor(h);
  const weights = cachedWeights(w, h, SIZE, colSpans, rowSpans);
  const { starts: colStart, offsets: colOff, wts: colWts } = colSpans;
  const { starts: rowStart, offsets: rowOff, wts: rowWts } = rowSpans;
  for (let y = 0; y < h; y++) {
    const rowOffset = y * w * 4;
    const oyBase = rowOff[y], oyCount = rowOff[y + 1] - oyBase;
    const oRow = rowStart[y];
    for (let x = 0; x < w; x++) {
      const i = rowOffset + x * 4;
      // Opaque fast path: alpha = 255/255 = 1 exactly, so gray is the
      // same float with the multiply skipped (x * 1 === x in IEEE 754).
      const gray = src[i + 3] === 255
        ? (src[i] * 54 + src[i + 1] * 183 + src[i + 2] * 19) / 256
        : ((src[i] * 54 + src[i + 1] * 183 + src[i + 2] * 19) / 256) * (src[i + 3] / 255);
      const oxBase = colOff[x], oxCount = colOff[x + 1] - oxBase;
      const oCol = colStart[x];
      for (let oyi = 0; oyi < oyCount; oyi++) {
        const wy = rowWts[oyBase + oyi];
        if (wy <= 0) continue;
        const rowBase = (oRow + oyi) * SIZE + oCol;
        for (let oxi = 0; oxi < oxCount; oxi++) {
          const wx = colWts[oxBase + oxi];
          if (wx <= 0) continue;
          const idx = rowBase + oxi;
          small[idx] += gray * (wx * wy);
        }
      }
    }
  }
  for (let i = 0; i < small.length; i++) {
    small[i] = weights[i] > 0 ? small[i] / weights[i] : 0;
  }

  const cosines = DCT_COSINES_32x8;
  const rowDct = new Float64Array(SIZE * 8);
  for (let y = 0; y < SIZE; y++) {
    for (let u = 0; u < 8; u++) {
      let sum = 0;
      for (let x = 0; x < SIZE; x++) sum += small[y * SIZE + x] * cosines[x * 8 + u];
      rowDct[y * 8 + u] = sum;
    }
  }
  const coefficients = new Float64Array(64);
  for (let v = 0; v < 8; v++) {
    for (let u = 0; u < 8; u++) {
      let sum = 0;
      for (let y = 0; y < SIZE; y++) sum += rowDct[y * 8 + u] * cosines[y * 8 + v];
      coefficients[v * 8 + u] = sum;
    }
  }
  // Median over AC terms only (DC excluded). The DC coefficient itself
  // is then always > median, so the top hash bit is a constant 1 —
  // 63 effective bits, the long-standing fingerprint format. Changing
  // it would orphan every stored registry print for one bit of dedup
  // entropy; documented instead (thresholds were calibrated with it).
  const sorted = [...coefficients.slice(1)].sort((a, b) => a - b);
  const median = sorted[Math.floor(sorted.length / 2)];
  let bits = 0n;
  for (let i = 0; i < 64; i++) {
    if (coefficients[i] > median) bits |= 1n << BigInt(63 - i);
  }
  return bits.toString(16).padStart(16, '0');
}

export function normalizePerceptualFingerprint(value) {
  if (typeof value !== 'string') return null;
  const normalized = value.trim().toLowerCase();
  return /^[0-9a-f]{16}$/.test(normalized) ? normalized : null;
}

export function perceptualFingerprintDistance(a, b) {
  const left = normalizePerceptualFingerprint(a);
  const right = normalizePerceptualFingerprint(b);
  if (!left || !right) throw new TypeError('Archx: perceptual fingerprint must be 16 hex characters');
  let xor = BigInt('0x' + left) ^ BigInt('0x' + right);
  let distance = 0;
  while (xor > 0n) {
    distance += Number(xor & 1n);
    xor >>= 1n;
  }
  return distance;
}

export function comparePerceptualFingerprints(a, b, { maxDistance = 10 } = {}) {
  if (!Number.isInteger(maxDistance) || maxDistance < 0 || maxDistance > 64) {
    throw new RangeError('Archx: perceptual fingerprint maxDistance must be an integer from 0 to 64');
  }
  const distance = perceptualFingerprintDistance(a, b);
  return Object.freeze({
    distance,
    similarity: 1 - distance / 64,
    match: distance <= maxDistance,
  });
}

// Orientation-tolerant soft-binding match. The shipped 64-bit
// fingerprint is (deliberately) orientation-sensitive: a leaked copy
// that was flipped, rotated 90°, or transposed — all one-click
// editor operations and all EXIF-orientation values — produces a
// completely different fingerprint even though it is pixel-identical
// up to a rectangle symmetry. This matcher closes that gap on the
// VERIFICATION side only (registered fingerprints and the bit format
// are untouched): the identity view is fingerprinted at full
// resolution exactly as before; only when it misses are the other
// seven dihedral symmetries probed, on a bounded ≤256 px proxy so a
// 24 MP suspect costs eight small fingerprints instead of eight
// full-frame ones (and never allocates eight full-frame copies).
// `orientation` names the correction applied to the suspect that
// produced the best distance ('identity' when none was needed).
const _ORIENTATION_PROBES = [
  ['flip-x', (src, w, h) => ({ data: flipPixels(src, w, h, true, false), w, h })],
  ['flip-y', (src, w, h) => ({ data: flipPixels(src, w, h, false, true), w, h })],
  ['rotate-180', (src, w, h) => ({ data: flipPixels(src, w, h, true, true), w, h })],
  ['rotate-90-ccw', (src, w, h) => ({ data: rotatePixels90(src, w, h, false), w: h, h: w })],
  ['rotate-90-cw', (src, w, h) => ({ data: rotatePixels90(src, w, h, true), w: h, h: w })],
  ['transpose', (src, w, h) => ({ data: transposePixels(src, w, h, false), w: h, h: w })],
  ['transpose-anti', (src, w, h) => ({ data: transposePixels(src, w, h, true), w: h, h: w })],
];

export function matchPerceptualFingerprint(rgba, w, h, expected, {
  maxDistance = 10, orientations = true,
} = {}) {
  if (!Number.isInteger(maxDistance) || maxDistance < 0 || maxDistance > 64) {
    throw new RangeError('Archx: perceptual fingerprint maxDistance must be an integer from 0 to 64');
  }
  const expectedNorm = normalizePerceptualFingerprint(expected);
  if (!expectedNorm) throw new TypeError('Archx: perceptual fingerprint must be 16 hex characters');
  const src = asBytes(rgba);
  const identityFingerprint = perceptualFingerprint(src, w, h);
  let best = {
    orientation: 'identity',
    fingerprint: identityFingerprint,
    distance: perceptualFingerprintDistance(identityFingerprint, expectedNorm),
  };
  let orientationsChecked = 1;
  if (best.distance > maxDistance && orientations) {
    let probe = src, pw = w, ph = h;
    const longest = Math.max(w, h);
    if (longest > 256) {
      const scale = 256 / longest;
      pw = Math.max(1, Math.round(w * scale));
      ph = Math.max(1, Math.round(h * scale));
      probe = resampleRgba(src, w, h, pw, ph);
    }
    for (const [label, applyOrientation] of _ORIENTATION_PROBES) {
      const view = applyOrientation(probe, pw, ph);
      const fingerprint = perceptualFingerprint(view.data, view.w, view.h);
      const distance = perceptualFingerprintDistance(fingerprint, expectedNorm);
      orientationsChecked += 1;
      if (distance < best.distance) best = { orientation: label, fingerprint, distance };
      if (best.distance === 0) break;
    }
  }
  return Object.freeze({
    match: best.distance <= maxDistance,
    distance: best.distance,
    similarity: 1 - best.distance / 64,
    orientation: best.orientation,
    fingerprint: best.fingerprint,
    orientationsChecked,
  });
}
