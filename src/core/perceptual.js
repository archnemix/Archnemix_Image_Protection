/**
 * Perceptual fingerprint (64-bit DCT pHash): the soft-binding layer
 * for ownership claims and near-duplicate matching. Bit format is
 * frozen — issued registries depend on it.
 */
import { asBytes } from './bytes.js';


// Module-static DCT basis (same Math.cos values, computed once instead
// of 256 transcendental calls per fingerprint).
const DCT_COSINES_32x8 = (() => {
  const table = new Float64Array(32 * 8);
  for (let x = 0; x < 32; x++) {
    for (let u = 0; u < 8; u++) table[x * 8 + u] = Math.cos(((2 * x + 1) * u * Math.PI) / (2 * 32));
  }
  return table;
})();

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
  const weights = new Float64Array(SIZE * SIZE);

  // Area-average to 32×32. Area weighting is slower than nearest-neighbour
  // sampling but makes the fingerprint materially steadier across the exact
  // resampling choices of browsers, Sharp, and social-media transcoders.
  // The per-column/per-row overlap spans are precomputed once (they depend
  // only on x / y); the accumulation order — and therefore every float —
  // is unchanged, so fingerprints stay bit-identical to the direct form.
  const spansFor = (n) => {
    const spans = new Array(n);
    for (let s = 0; s < n; s++) {
      const s0 = (s * SIZE) / n;
      const s1 = ((s + 1) * SIZE) / n;
      const start = Math.floor(s0);
      const end = Math.min(SIZE - 1, Math.ceil(s1) - 1);
      const wts = new Float64Array(end - start + 1);
      for (let o = start; o <= end; o++) wts[o - start] = Math.min(s1, o + 1) - Math.max(s0, o);
      spans[s] = { start, wts };
    }
    return spans;
  };
  const colSpans = spansFor(w);
  const rowSpans = spansFor(h);
  for (let y = 0; y < h; y++) {
    const rowSpan = rowSpans[y];
    const rowOffset = y * w * 4;
    for (let x = 0; x < w; x++) {
      const i = rowOffset + x * 4;
      const alpha = src[i + 3] / 255;
      const gray = ((src[i] * 54 + src[i + 1] * 183 + src[i + 2] * 19) / 256) * alpha;
      const colSpan = colSpans[x];
      for (let oyi = 0; oyi < rowSpan.wts.length; oyi++) {
        const wy = rowSpan.wts[oyi];
        if (wy <= 0) continue;
        const rowBase = (rowSpan.start + oyi) * SIZE + colSpan.start;
        for (let oxi = 0; oxi < colSpan.wts.length; oxi++) {
          const wx = colSpan.wts[oxi];
          if (wx <= 0) continue;
          const idx = rowBase + oxi;
          const weight = wx * wy;
          small[idx] += gray * weight;
          weights[idx] += weight;
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
