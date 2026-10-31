/**
 * Forensic block marks: keyed per-block luminance signs used to
 * score a suspect against a reference (weak, removal-prone layer —
 * corroboration only, never standalone attribution).
 */
import { hashSeed, mulberry32, cyrb128, sfc32, sha256SeededPrng } from './crypto.js';

/**
 * A seeded ±delta luminance pattern applied per macro-block. Unlike 1px
 * noise, block-level shifts have a chance of surviving WebP/JPEG
 * re-encoding and screen-resolution screenshots well enough to be
 * *correlated* later: given a suspect image and a candidate viewing
 * session, resize/align the suspect to the payload geometry and compare
 * its block means against the unwatermarked reference (or a flat-field
 * estimate) — the seeded sign pattern either matches or it doesn't.
 * This is a tracing aid, not magic: cropping, heavy filtering or a camera
 * photo will weaken or destroy it. The visible watermark remains the
 * primary deterrent; this is the quiet second witness.
 */
// Sign derivations: v3 (default since 1.14) seeds sfc32 from SHA-256
// with warm-up; v2 (1.13) seeds through cyrb128+sfc32 (128-bit state);
// v1 reproduces the pre-1.13 mulberry32(hashSeed(...)) sequence whose
// 32-bit state truncated any seed's entropy. Verifiers (forensicScore)
// score against all three derivations, so older marks keep verifying.
export function forensicBlockSigns(seed, count, version = 3) {
  const rand = version === 1
    ? mulberry32(hashSeed(String(seed) + '::archx-forensic'))
    : version === 2
      ? sfc32(...cyrb128(String(seed) + '::archx-forensic'))
      : sha256SeededPrng(String(seed) + '::archx-forensic-v3');
  return Array.from({ length: count }, () => (rand() < 0.5 ? -1 : 1));
}

export function applyForensicBlocks(rgba, w, h, seed, { blockSize = 32, delta = 2, signsVersion = 3 } = {}) {
  const bs = Math.max(8, blockSize | 0);
  const bx = Math.ceil(w / bs);
  const by = Math.ceil(h / bs);
  const signs = forensicBlockSigns(seed, bx * by, signsVersion === 1 ? 1 : signsVersion === 2 ? 2 : 3);
  const out = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  // Every block applies one of exactly two deltas (+/-delta): clamped-add
  // tables built through the same Uint8 conversion as the direct form
  // keep output bytes identical while dropping the per-channel clamps.
  const lutPos = new Uint8Array(256);
  const lutNeg = new Uint8Array(256);
  for (let v = 0; v < 256; v++) {
    lutPos[v] = Math.max(0, Math.min(255, v + delta));
    lutNeg[v] = Math.max(0, Math.min(255, v - delta));
  }
  for (let byi = 0; byi < by; byi++) {
    for (let bxi = 0; bxi < bx; bxi++) {
      const sign = signs[byi * bx + bxi];
      const d = sign * delta;
      if (!d) continue;
      const lut = sign > 0 ? lutPos : lutNeg;
      const x0 = bxi * bs, y0 = byi * bs;
      const x1 = Math.min(w, x0 + bs), y1 = Math.min(h, y0 + bs);
      for (let y = y0; y < y1; y++) {
        let i = (y * w + x0) * 4;
        for (let x = x0; x < x1; x++, i += 4) {
          out[i] = lut[out[i]];
          out[i + 1] = lut[out[i + 1]];
          out[i + 2] = lut[out[i + 2]];
        }
      }
    }
  }
  return out;
}

/**
 * Score how well `candidate` matches the forensic pattern for `seed`,
 * using `reference` (same geometry, unmarked) as the baseline.
 * Returns { score: -1..1, matched, total } — a genuine marked copy
 * typically scores > 0.7 even after lossy re-encoding at the same size.
 */
export function forensicScore(candidate, reference, w, h, seed, { blockSize = 32 } = {}) {
  const bs = Math.max(8, blockSize | 0);
  const bx = Math.ceil(w / bs);
  const by = Math.ceil(h / bs);
  // Per-block mean signs are computed once and scored against both sign
  // derivations (v2 default since 1.13, v1 for pre-1.13 marks); the
  // stronger correlation wins and reports which derivation matched.
  const blockSigns = new Int8Array(bx * by); // sign+2 encoding; 0 = not computed
  let total = 0;
  for (let byi = 0; byi < by; byi++) {
    for (let bxi = 0; bxi < bx; bxi++) {
      const x0 = bxi * bs, y0 = byi * bs;
      const x1 = Math.min(w, x0 + bs), y1 = Math.min(h, y0 + bs);
      let diff = 0, n = 0;
      for (let y = y0; y < y1; y += 2) {
        let i = (y * w + x0) * 4;
        for (let x = x0; x < x1; x += 2, i += 8) {
          diff += ((candidate[i] + candidate[i + 1] + candidate[i + 2]) -
                   (reference[i] + reference[i + 1] + reference[i + 2])) / 3;
          n++;
        }
      }
      if (!n) continue;
      blockSigns[byi * bx + bxi] = Math.sign(diff / n) + 2;
      total++;
    }
  }
  let best = { score: 0, matched: 0, total, signsVersion: 3 };
  for (const version of [3, 2, 1]) {
    const signs = forensicBlockSigns(seed, bx * by, version);
    let matched = 0, signedSum = 0;
    for (let i = 0; i < blockSigns.length; i++) {
      if (!blockSigns[i]) continue;
      const hit = blockSigns[i] - 2 === signs[i];
      signedSum += hit ? 1 : -1;
      if (hit) matched++;
    }
    const score = total ? signedSum / total : 0;
    if (version === 3 || score > best.score) best = { score, matched, total, signsVersion: version };
  }
  return best;
}

/* ------------------------------------------------------------------ */
/* Blind steganographic ownership fingerprint                          */
/* ------------------------------------------------------------------ */
