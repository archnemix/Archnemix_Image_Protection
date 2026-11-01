/**
 * StegoMark detector: native screen, offset/geometry/D4-variant
 * search, erasure decoding, bit repair, optional tilt deskew, and
 * the multi-recipient collusion assay. Bounded by maxTimeMs.
 */

import { STEGO_ROW_SEGMENTS, robustStegoCodeBits, bchStegoDecode, bchStegoSolveObserved, STEGO_V4_CODE_BITS, stegoLayout, robustStegoLayout, stegoGrid, robustStegoBytesValid, robustStegoFingerprintFromBits, stegoBitsToBytes, correctStegoBits, stegoCrc16, stegoMac16, ROBUST_MARKER_BITS } from './stego-code.js';
import { buildLumaIntegral, mirroredVariant, rotatedVariant, transposedVariant, resampleRgba, rotateRgba, MIRROR_AXES } from './pixels.js';

function repairRobustViaFirstCrc(scores, hard, key, tag = 'mac') {
  const first = Uint8Array.from(hard.subarray(0, 64));
  const syndromeOf = (bits) => {
    const bytes = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
      let byte = 0;
      for (let b = 0; b < 8; b++) byte = (byte << 1) | bits[i * 8 + b];
      bytes[i] = byte;
    }
    return stegoCrc16(bytes.subarray(0, 6)) ^ ((bytes[6] << 8) | bytes[7]);
  };
  const target = syndromeOf(first);
  const buildCanonical = (correctedFirst) => {
    // Prefilter before paying for the acceptance MAC: the canonical
    // codeword's first 64 bits ARE correctedFirst (syndrome-zero), and
    // the trailing marker is a constant — so most junk syndrome
    // candidates can be rejected on marker disagreement alone, without
    // an HMAC each (tens of thousands on unmarked geometry searches).
    let flips = 0;
    let markerFlips = 0;
    let softCost = 0;
    for (let i = 0; i < 64; i++) {
      if (correctedFirst[i] === hard[i]) continue;
      flips++;
      softCost += Math.abs(scores[i] || 0);
    }
    for (let j = 0; j < 16; j++) {
      if (ROBUST_MARKER_BITS[j] === hard[80 + j]) continue;
      markerFlips++;
      flips++;
      softCost += Math.abs(scores[80 + j] || 0);
    }
    if (markerFlips > 2 || flips > 8) return null;
    const fingerprint = robustStegoFingerprintFromBits(correctedFirst);
    const canonical = robustStegoCodeBits(fingerprint, key, tag);
    let tagFlips = markerFlips;
    for (let i = 64; i < 80; i++) {
      if (canonical[i] === hard[i]) continue;
      flips++;
      tagFlips++;
      softCost += Math.abs(scores[i] || 0);
    }
    // The acceptance tag must be OBSERVED, not synthesized: bits 64..95
    // (tag + marker) may carry a couple of vote errors, but regenerating
    // them wholesale would let a LEGACY (CRC2) mark be claimed by the
    // 'mac' pass — its CRC2 differs from the synthesized MAC in ~8 bits,
    // which the old flips<=8 budget cheerfully paid, mislabeling the
    // scheme and short-circuiting the CRC fallback. Candidates whose
    // tag needs >2 flips fall through to the exhaustive search, which
    // pays for every flipped tag bit out of the gate-capped budget.
    return flips <= 8 && tagFlips <= 2 ? { bits: canonical, flips, softCost } : null;
  };
  if (target === 0) return buildCanonical(first);

  const columns = new Uint16Array(64);
  for (let i = 0; i < 64; i++) {
    first[i] ^= 1;
    columns[i] = syndromeOf(first) ^ target;
    first[i] ^= 1;
  }
  const weakest = Array.from({ length: 64 }, (_, index) => index)
    .sort((a, b) => Math.abs(scores[a]) - Math.abs(scores[b]))
    .slice(0, 32);
  // Interleave the weakest candidates between halves so a meet-in-the-middle
  // search can represent up to three likely errors on each side.
  const leftCandidates = weakest.filter((_, index) => index % 2 === 0);
  const rightCandidates = weakest.filter((_, index) => index % 2 === 1);
  const subsetMaps = (candidates) => {
    const byWeight = Array.from({ length: 4 }, () => new Map());
    const visit = (start, chosen, syndrome, cost) => {
      const map = byWeight[chosen.length];
      const previous = map.get(syndrome);
      if (!previous || cost < previous.cost) map.set(syndrome, { indices: [...chosen], cost });
      if (chosen.length >= 3) return;
      for (let i = start; i < candidates.length; i++) {
        const bit = candidates[i];
        chosen.push(bit);
        visit(i + 1, chosen, syndrome ^ columns[bit], cost + Math.abs(scores[bit] || 0));
        chosen.pop();
      }
    };
    visit(0, [], 0, 0);
    return byWeight;
  };
  const leftMaps = subsetMaps(leftCandidates);
  const rightMaps = subsetMaps(rightCandidates);
  // Rank every first-CRC syndrome solution by the soft cost of the complete
  // canonical 96-bit codeword. Accepting the first low-weight CRC collision
  // would be unsafe: the second CRC and marker observations must also be
  // close to the candidate before it can become an attribution.
  let bestCanonical = null;
  for (let total = 1; total <= 6; total++) {
    for (let leftWeight = 0; leftWeight <= Math.min(3, total); leftWeight++) {
      const rightWeight = total - leftWeight;
      if (rightWeight < 0 || rightWeight > 3) continue;
      for (const [syndrome, left] of leftMaps[leftWeight]) {
        const right = rightMaps[rightWeight].get(target ^ syndrome);
        if (!right) continue;
        const corrected = Uint8Array.from(first);
        for (const bit of [...left.indices, ...right.indices]) corrected[bit] ^= 1;
        if (syndromeOf(corrected) !== 0) continue;
        const candidate = buildCanonical(corrected);
        if (!candidate) continue;
        if (!bestCanonical || candidate.softCost < bestCanonical.softCost ||
            (candidate.softCost === bestCanonical.softCost && candidate.flips < bestCanonical.flips)) {
          bestCanonical = candidate;
        }
      }
    }
  }
  return bestCanonical ? { bits: bestCanonical.bits, flips: bestCanonical.flips } : null;
}

function repairRobustStegoBits(scores, hard, key, maxFlips = 5, tag = 'mac') {
  const bits = Uint8Array.from(hard);
  const bytes = new Uint8Array(12);
  for (let i = 0; i < 12; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = (byte << 1) | bits[i * 8 + b];
    bytes[i] = byte;
  }
  if (robustStegoBytesValid(bytes, key, tag)) return { bits, flips: 0, tagScheme: tag };
  const syndromeRepair = repairRobustViaFirstCrc(scores, bits, key, tag);
  if (syndromeRepair) return { ...syndromeRepair, tagScheme: tag };
  // Byte-level flips plus the table CRC keep an exhaustive search of the
  // 24 weakest bits to five flips practical during offline geometry search.
  const candidates = Array.from({ length: bits.length }, (_, index) => index)
    .sort((a, b) => Math.abs(scores[a]) - Math.abs(scores[b]))
    .slice(0, 24);
  const flip = (index) => {
    bits[index] ^= 1;
    bytes[index >> 3] ^= 1 << (7 - (index & 7));
  };
  const search = (start, depth, targetDepth) => {
    if (depth === targetDepth) return robustStegoBytesValid(bytes, key, tag);
    for (let i = start; i <= candidates.length - (targetDepth - depth); i++) {
      flip(candidates[i]);
      if (search(i + 1, depth + 1, targetDepth)) return true;
      flip(candidates[i]);
    }
    return false;
  };
  for (let flips = 1; flips <= maxFlips; flips++) {
    if (search(0, 0, flips)) return { bits: Uint8Array.from(bits), flips, tagScheme: tag };
  }
  return null;
}

const STEGO_TIMEOUT = Symbol('archx-stego-timeout');

export function detectStegoFingerprint(rgba, w, h, {
  key = '', gridX, gridY, profile = 'standard', searchOffsets = false, searchGeometry = false,
  // Mirrored-suspect recovery is on by default for every profile (one
  // extra bounded pass on flipped pixels, only when the forward pass
  // found nothing); set false to disable.
  searchMirror = true,
  searchRotation = true,
  // Small-angle deskew search (offline forensic opt-in): sweeps
  // ±6° on a downscaled proxy, refines by raw signal, then confirms
  // at full resolution. Off by default (cost); the CLI exposes --tilt.
  searchTilt = false,
  // Optional wall-clock budget for the WHOLE search (all layouts,
  // profiles, and probes share one deadline). On expiry the best
  // candidate so far is returned with `timedOut: true` instead of
  // running unbounded forensic stages. 0 (default) = unlimited.
  maxTimeMs = 0,
  // Layout space: 'auto' (default) screens v3 (SHA-256-seeded),
  // v4 (v1.20 BCH code over the v3 layout), then v2/v1 legacy
  // seeds — native screens for all layouts first, then geometry
  // searches with the deadline sliced fairly across layouts;
  // pass 1-4 to pin one space (full budget to that one search,
  // roughly proportionally lower worst-case cost).
  layoutVersion = 'auto',
  _mirrorProbe = false,
  _tiltProbe = false,
  _layoutVersion = 0,
  _planes = null,
  _deadline = 0,
} = {}) {
  const deadline = _deadline > 0 ? _deadline
    : (Number.isFinite(maxTimeMs) && maxTimeMs > 0 ? Date.now() + maxTimeMs : 0);
  const deadlineHit = () => deadline > 0 && Date.now() > deadline;
  const concreteLayout = (_layoutVersion === 1 || _layoutVersion === 2 || _layoutVersion === 3 || _layoutVersion === 4)
    ? _layoutVersion
    : (layoutVersion === 1 || layoutVersion === 2 || layoutVersion === 3 || layoutVersion === 4 ? layoutVersion : 0);
  // Shared read-only pixel planes for every recursive probe of this
  // top-level call: layout/profile/geometry/mirror fan-out used to
  // rebuild the luma plane + summed-area table (and the flipped copy)
  // up to a dozen times per suspect — hundreds of MB of typed-array
  // churn at 1080p. Entries are keyed by the exact source buffer and
  // never mutated, so every probe reads bit-identical values.
  const planesCache = _planes || new Map();
  const srcTop = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  const planesEntry = (buf) => {
    let entry = planesCache.get(buf);
    if (!entry) { entry = { flipped: null, luma: null, integral: null }; planesCache.set(buf, entry); }
    return entry;
  };
  if (!concreteLayout) {
    // Two-phase auto-detection. Phase 1 screens every layout
    // natively (no geometry/tilt sweep): identity, re-encode,
    // resize, brightness and mirror suspects resolve in well
    // under a second per layout. Phase 2 runs the exhaustive
    // geometry searches. The split exists because of budget
    // starvation, measured on the v1.20 bench: a single-phase
    // loop let the FIRST layout's hopeless 20 s crop search
    // consume the entire shared deadline, so suspects belonging
    // to later layouts timed out even at identity. Phase 2 also
    // slices the remaining budget fairly (remaining / layouts
    // left): successful crop searches resolve in 0.4-3.6 s
    // (bench p90), so a fair slice rarely costs a real recovery
    // but guarantees every layout is reached. Pinning a layout
    // still restores the full budget to that one search.
    const order = [3, 4, 2, 1];
    const shared = { key, gridX, gridY, profile, searchOffsets, searchMirror, searchRotation, _mirrorProbe, _tiltProbe, _planes: planesCache };
    let best = null;
    const consider = (attempt) => {
      if (attempt && (!best || (attempt.confidence ?? 0) > (best.confidence ?? 0))) best = attempt;
    };
    for (const version of order) {
      const attempt = detectStegoFingerprint(srcTop, w, h, {
        ...shared, searchGeometry: false, searchTilt: false, _layoutVersion: version, _deadline: deadline,
      });
      if (attempt?.found) return attempt;
      consider(attempt);
      if (attempt?.timedOut || deadlineHit()) {
        if (best && !best.timedOut) best = { ...best, timedOut: true };
        return best;
      }
    }
    if (searchGeometry || searchTilt) {
      for (let i = 0; i < order.length; i++) {
        let slice = deadline;
        if (deadline > 0) {
          const remainingMs = deadline - Date.now();
          if (remainingMs <= 0) break;
          slice = Math.min(deadline, Date.now() + Math.max(1500, Math.ceil(remainingMs / (order.length - i))));
        }
        const attempt = detectStegoFingerprint(srcTop, w, h, {
          ...shared, searchGeometry, searchTilt, _layoutVersion: order[i], _deadline: slice,
        });
        if (attempt?.found) return attempt;
        consider(attempt);
        if (deadlineHit()) break;
      }
      if (best && deadlineHit() && !best.timedOut) best = { ...best, timedOut: true };
    }
    return best;
  }
  if (profile === 'auto') {
    const standard = detectStegoFingerprint(srcTop, w, h, {
      key, gridX, gridY, profile: 'standard', searchOffsets, searchGeometry: false, searchMirror: false, searchRotation: false, searchTilt: false, _mirrorProbe: true, _tiltProbe: true, _layoutVersion: concreteLayout, _planes: planesCache, _deadline: deadline,
    });
    if (standard?.found && standard.confidence >= 0.9 && !searchGeometry) return standard;
    const robust = detectStegoFingerprint(srcTop, w, h, {
      key, gridX, gridY, profile: 'robust', searchOffsets, searchGeometry: false, searchMirror: false, searchRotation: false, searchTilt: false, _mirrorProbe: true, _tiltProbe: true, _layoutVersion: concreteLayout, _planes: planesCache, _deadline: deadline,
    });
    const initial = robust?.found && !standard?.found
      ? robust
      : standard?.found && !robust?.found
        ? standard
        : (robust?.confidence ?? 0) > (standard?.confidence ?? 0) ? robust : standard;
    if (!searchGeometry || initial?.found) return initial;
    if (deadlineHit()) return initial?.timedOut ? initial : { ...initial, timedOut: true };
    const standardGeometry = detectStegoFingerprint(srcTop, w, h, {
      key, gridX, gridY, profile: 'standard', searchOffsets, searchGeometry: true, searchMirror: false, searchRotation: false, searchTilt, _mirrorProbe: true, _layoutVersion: concreteLayout, _planes: planesCache, _deadline: deadline,
    });
    if (standardGeometry?.found) return standardGeometry;
    const robustGeometry = detectStegoFingerprint(srcTop, w, h, {
      key, gridX, gridY, profile: 'robust', searchOffsets, searchGeometry: true, searchMirror: false, searchRotation: false, searchTilt, _mirrorProbe: true, _layoutVersion: concreteLayout, _planes: planesCache, _deadline: deadline,
    });
    if (robustGeometry?.found) return robustGeometry;
    // Last bounded candidate: a horizontally mirrored suspect (a common
    // zero-cost evasion). The probe inherits the geometry search so
    // compound flip+crop/resize suspects recover too; it only runs after
    // the full forward geometry search failed (offline forensic mode).
    if ((searchMirror || searchRotation) && !_mirrorProbe) try {
      if (srcTop.length >= w * h * 4 && Number.isSafeInteger(w * h * 4)) {
        const entry = planesEntry(srcTop);
        // Fast (offset-only) probes across every mirror axis are cheap;
        // geometry probes for the y/xy axes are gated on the caller's
        // searchGeometry so unmarked auto-detects stay bounded.
        for (const [axis, fx, fy] of searchMirror ? MIRROR_AXES : []) {
          const variant = mirroredVariant(entry, srcTop, w, h, axis, fx, fy);
          for (const candidateProfile of ['standard', 'robust']) {
            const fast = detectStegoFingerprint(variant, w, h, {
              key, gridX, gridY, profile: candidateProfile, searchOffsets,
              searchGeometry: false, searchMirror: false, searchRotation: false, searchTilt: false, _mirrorProbe: true, _tiltProbe: true, _layoutVersion: concreteLayout, _planes: planesCache, _deadline: deadline,
            });
            if (fast?.found) return { ...fast, mirrored: true, mirrorAxis: axis };
          }
        }
        if (searchRotation) for (const clockwise of [false, true]) {
          const variant = rotatedVariant(entry, srcTop, w, h, clockwise);
          for (const candidateProfile of ['standard', 'robust']) {
            const fast = detectStegoFingerprint(variant, h, w, {
              key, gridX, gridY, profile: candidateProfile, searchOffsets,
              searchGeometry: false, searchMirror: false, searchRotation: false, searchTilt: false, _mirrorProbe: true, _tiltProbe: true, _layoutVersion: concreteLayout, _planes: planesCache, _deadline: deadline,
            });
            if (fast?.found) return { ...fast, rotated: clockwise ? 270 : 90 };
          }
        }
        if (searchRotation) for (const anti of [false, true]) {
          const variant = transposedVariant(entry, srcTop, w, h, anti);
          for (const candidateProfile of ['standard', 'robust']) {
            const fast = detectStegoFingerprint(variant, h, w, {
              key, gridX, gridY, profile: candidateProfile, searchOffsets,
              searchGeometry: false, searchMirror: false, searchRotation: false, searchTilt: false, _mirrorProbe: true, _tiltProbe: true, _layoutVersion: concreteLayout, _planes: planesCache, _deadline: deadline,
            });
            if (fast?.found) return { ...fast, transposed: anti ? 'anti' : 'main' };
          }
        }
        for (const [axis, fx, fy] of searchMirror ? MIRROR_AXES : []) {
          if (axis !== 'x' && !searchGeometry) continue;
          const variant = mirroredVariant(entry, srcTop, w, h, axis, fx, fy);
          for (const candidateProfile of ['standard', 'robust']) {
            const mirrored = detectStegoFingerprint(variant, w, h, {
              key, gridX, gridY, profile: candidateProfile, searchOffsets,
              searchGeometry: true, searchMirror: false, searchRotation: false, searchTilt: false, _mirrorProbe: true, _tiltProbe: true, _layoutVersion: concreteLayout, _planes: planesCache, _deadline: deadline,
            });
            if (mirrored?.found) return { ...mirrored, mirrored: true, mirrorAxis: axis };
          }
        }
        // Rotation+geometry compounds probe robust only in auto mode:
        // two more full geometry searches per profile made the
        // unmarked auto worst case ~30s, and robust is the forensic
        // carrier. Explicit profile:'standard' calls still probe
        // rotated geometry via the single-profile path.
        if (searchRotation && searchGeometry) for (const clockwise of [false, true]) {
          const variant = rotatedVariant(entry, srcTop, w, h, clockwise);
          for (const candidateProfile of ['robust']) {
            const rotated = detectStegoFingerprint(variant, h, w, {
              key, gridX, gridY, profile: candidateProfile, searchOffsets,
              searchGeometry: true, searchMirror: false, searchRotation: false, searchTilt: false, _mirrorProbe: true, _tiltProbe: true, _layoutVersion: concreteLayout, _planes: planesCache, _deadline: deadline,
            });
            if (rotated?.found) return { ...rotated, rotated: clockwise ? 270 : 90 };
          }
        }
        if (searchRotation && searchGeometry) for (const anti of [false, true]) {
          const variant = transposedVariant(entry, srcTop, w, h, anti);
          for (const candidateProfile of ['robust']) {
            const transposed = detectStegoFingerprint(variant, h, w, {
              key, gridX, gridY, profile: candidateProfile, searchOffsets,
              searchGeometry: true, searchMirror: false, searchRotation: false, searchTilt: false, _mirrorProbe: true, _tiltProbe: true, _layoutVersion: concreteLayout, _planes: planesCache, _deadline: deadline,
            });
            if (transposed?.found) return { ...transposed, transposed: anti ? 'anti' : 'main' };
          }
        }
      }
    } catch { /* mirror probe is best-effort */ }
    return (robustGeometry?.confidence ?? 0) > (standardGeometry?.confidence ?? 0)
      ? robustGeometry
      : standardGeometry;
  }
  const src = srcTop;
  if (src.length < w * h * 4) throw new Error('Archx stego: pixel buffer is smaller than w×h×4');
  const robust = profile === 'robust';
  const effectiveProfile = robust ? 'robust' : 'standard';
  // Layout v4: same cells/statistic, BCH(188,64) codeword instead of
  // the 96/64-bit repetition codes. Everything downstream that is
  // parameterized by codeLength follows automatically; the repair
  // and coverage gates branch explicitly below.
  const isV4 = concreteLayout === 4;
  const codeLength = isV4 ? STEGO_V4_CODE_BITS : robust ? 96 : 64;
  const rowSegments = STEGO_ROW_SEGMENTS;
  const columnBands = 4;
  const effectiveGridX = gridX ?? (robust ? 20 : 24);
  const effectiveGridY = gridY ?? (robust ? 14 : 16);
  const { gx, gy } = stegoGrid(w, h, effectiveGridX, effectiveGridY);
  const cellCount = gx * gy;
  const { order, polarity, segmentPolarity } = robust
    ? robustStegoLayout(cellCount, key, isV4 ? 3 : concreteLayout)
    : stegoLayout(cellCount, key, isV4 ? 3 : concreteLayout);
  const cw = w / gx, ch = h / gy;
  // One luma plane + summed-area table per source buffer, shared by
  // every recursive probe of this top-level call (see planesCache):
  // geometry search evaluates thousands of candidates over the same
  // pixels, and recomputing (r*77+g*150+b*29)>>8 per sample was ~30%
  // of detector wall time. Every cell band/segment mean becomes four
  // array reads over the table — full-population means, same gates.
  const planes = planesEntry(src);
  if (!planes.luma) {
    const built = buildLumaIntegral(src, w, h);
    planes.luma = built.luma;
    planes.integral = built.integral;
  }
  const integral = planes.integral;
  const integralStride = w + 1;
  const rectSum = (rx0, ry0, rx1, ry1) =>
    integral[ry1 * integralStride + rx1] - integral[ry0 * integralStride + rx1] -
    integral[ry1 * integralStride + rx0] + integral[ry0 * integralStride + rx0];
  const fractions = searchOffsets ? [-0.25, -0.125, 0, 0.125, 0.25] : [0];

  // Reused scratch across this call's (synchronous) evaluate() probes:
  // geometry search runs thousands of candidates, and allocating the
  // vote/sum typed arrays per cell/evaluate was pure GC churn.
  const _sums = new Float64Array(rowSegments * columnBands);
  const _counts = new Uint32Array(rowSegments * columnBands);
  const _bitScores = new Float64Array(codeLength);
  const _bitCounts = new Uint16Array(codeLength);
  const _votedBits = new Uint8Array(codeLength);
  const _reliability = new Float64Array(codeLength);
  const _voteScores = new Float64Array(codeLength);
  const _groups = Array.from({ length: codeLength }, () => []);
  const _cellBitIdx = new Uint16Array(gx * gy);
  const _cellScore = new Float32Array(gx * gy);
  const _disagreeByBit = new Uint16Array(codeLength);
  const _segmentResponses = [];
  // Per-call geometry scratch for evaluate(): row/column bounds and
  // segment/band split points depend only on (cy, segment) and
  // (cx, band), so they are computed once per probe instead of once
  // per cell per segment. The stored integers come from the exact
  // same Math.round/clamp expressions the inline code used, so every
  // rectSum argument — and therefore every score — is bit-identical.
  const _rowY0 = new Int32Array(gy);
  const _rowY1 = new Int32Array(gy);
  const _rowOk = new Uint8Array(gy);
  const _segYB = new Int32Array(gy * (rowSegments + 1));
  const _segY0 = new Int32Array(gy * rowSegments);
  const _segH = new Int32Array(gy * rowSegments);
  const _colX0 = new Int32Array(gx);
  const _colX1 = new Int32Array(gx);
  const _colOk = new Uint8Array(gx);
  const _bandXB = new Int32Array(gx * (columnBands + 1));
  const _bandX0 = new Int32Array(gx * columnBands);
  const _bandW = new Int32Array(gx * columnBands);
  const _colAllBands = new Uint8Array(gx);
  const _gains = new Uint16Array(codeLength);
  // Layout-derived per-cell constants: code-bit index and the signed
  // (polarity x segmentPolarity) product. Both are exact integer
  // facts about the fixed layout; folding the +/-1 product into one
  // Int8 keeps the floating-point score identical (multiplication
  // by +/-1 is an exact sign flip, and sign flips compose exactly).
  const _cellBitAll = new Uint16Array(cellCount);
  const _signPol = new Int8Array(cellCount * rowSegments);
  for (let i = 0; i < cellCount; i++) {
    _cellBitAll[i] = order[i] % codeLength;
    const pol = polarity[i];
    const base = i * rowSegments;
    for (let segment = 0; segment < rowSegments; segment++) {
      _signPol[base + segment] = pol * segmentPolarity[base + segment];
    }
  }
  let _evalTick = 0;
  // OSD reprocessing budget for this detect call: the ML fallback
  // may run inside thousands of geometry probes, so escalations
  // (each up to ~70 solves) are capped per top-level search.
  let osdEscalations = 0;
  let isdEscalations = 0;
  // Forensic stash: votes+cell evidence of the strongest FAILED
  // v4 candidates (up to 3, distinct geometries), kept for deep
  // end-of-search decodes. Inline escalation budgets are spent in
  // encounter order, but geometry refinement produces its best
  // candidates late (measured: true candidate at probe ~1500 of
  // 16000, budgets long gone); and evidence ranking alone is an
  // imperfect decodability proxy (the max-evidence candidate
  // measured 15 bit errors with one inside the trusted top-24
  // reliability ranks — the worst case for biased ISD — while a
  // sibling geometry had 13 errors, none in the top 27). Three
  // distinct geometries decoded deeply beat one anointed winner.
  const forensicStash = [];
  // One deep decode attempt on a stashed candidate: full ladder
  // (OSD + ISD) with acceptance recomputed exactly as evaluate()
  // computes it — agreement against the corrected bits over the
  // stashed cell readings, mismatch-rate tiers, evidence and
  // confidence formulas. Returns a finished result or null.
  const deepForensicTry = (s, trials, salt) => {
    const cap = Math.max(4, Math.floor((s.order.length - 64) * 0.30));
    const hit = bchStegoSolveObserved(s.votes, s.order, key, {
      maxMismatches: cap, osd: true, isdTrials: trials, seedSalt: salt,
    });
    if (!hit) return null;
    let agreeing = 0;
    for (let ci = 0; ci < s.cellLen; ci++) {
      if ((s.cellScore[ci] >= 0) === !!hit.bits[s.cellBitIdx[ci]]) agreeing++;
    }
    const agreement = s.cellLen ? agreeing / s.cellLen : 0;
    const mismRate = hit.mismatches / Math.max(1, s.order.length - 64);
    const tierOk = mismRate <= 0.10 ||
      (mismRate <= 0.20 && s.meanAbs >= 2.0 && agreement >= 0.82) ||
      (s.meanAbs >= 2.5 && agreement >= 0.82);
    if (!(agreement >= 0.72 && s.meanAbs >= 1.2 && tierOk)) return null;
    const bchBudget = Math.round(120 * mismRate);
    const evidence2 = Math.max(0, agreement - 0.64) * 2.4 +
      Math.min(0.55, Math.max(0, s.meanAbs - 1.4) / 8) - (bchBudget / 6) * 0.04;
    const deep = {
      ...s.result, found: true, fingerprint: hit.fingerprint,
      tagScheme: 'mac', erasureDecoded: true, crcValid: true,
      corrections: hit.mismatches,
      agreement: Math.round(agreement * 1000) / 1000,
      confidence: Math.round(Math.max(0, Math.min(0.99, 0.42 + evidence2)) * 1000) / 1000,
    };
    delete deep._evidence; delete deep._originX; delete deep._originY;
    delete deep._scaleX; delete deep._scaleY;
    return deep;
  };
  // Deep decodes are evidence-gated (genuine best candidates
  // measured 0.94-1.16; failed searches over unmarked content
  // stash self-agreement artifacts around <=0.55) so screening
  // unmarked suspects does not pay seconds of ISD per layout.
  const STASH_DEEP_MIN_EVIDENCE = 0.6;
  const evaluate = ({ fx = 0, fy = 0, scale = 1, scaleX = scale, scaleY = scale, originX = null, originY = null, erasure = false } = {}) => {
    // Every search stage funnels through evaluate(); checking the
    // shared deadline here (amortized) bounds total forensic time
    // without threading flags through dozens of loops. The sentinel
    // is caught around the search body below.
    if (deadline && (++_evalTick & 15) === 0 && Date.now() > deadline) throw STEGO_TIMEOUT;
    const cellW0 = cw * scaleX;
    const cellH0 = ch * scaleY;
    const ox = originX ?? fx * cw;
    const oy = originY ?? fy * ch;
    const bitScores = _bitScores.fill(0);
    const bitCounts = _bitCounts.fill(0);
    let cellLen = 0;
    // Hoisted row/column geometry (see scratch note above): identical
    // rounding and skip predicates, evaluated gy+gx times per probe
    // instead of per cell.
    for (let cy = 0; cy < gy; cy++) {
      const rawY0 = oy + cy * cellH0;
      const rawY1 = rawY0 + cellH0;
      const y0 = Math.max(0, Math.round(rawY0));
      const y1 = Math.min(h, Math.round(rawY1));
      _rowY0[cy] = y0;
      _rowY1[cy] = y1;
      _rowOk[cy] = (y1 - y0 < 2 || (y1 - y0) / cellH0 < 0.45) ? 0 : 1;
      const segBase = cy * (rowSegments + 1);
      for (let s2 = 0; s2 <= rowSegments; s2++) {
        _segYB[segBase + s2] = Math.round(rawY0 + (s2 * cellH0) / rowSegments);
      }
      const segClampBase = cy * rowSegments;
      for (let s2 = 0; s2 < rowSegments; s2++) {
        const ry0 = Math.max(y0, _segYB[segBase + s2]);
        const ry1 = Math.min(y1, _segYB[segBase + s2 + 1]);
        _segY0[segClampBase + s2] = ry0;
        _segH[segClampBase + s2] = ry1 - ry0;
      }
    }
    for (let cx = 0; cx < gx; cx++) {
      const rawX0 = ox + cx * cellW0;
      const rawX1 = rawX0 + cellW0;
      const x0 = Math.max(0, Math.round(rawX0));
      const x1 = Math.min(w, Math.round(rawX1));
      _colX0[cx] = x0;
      _colX1[cx] = x1;
      _colOk[cx] = (x1 - x0 < 4 || (x1 - x0) / cellW0 < 0.45) ? 0 : 1;
      const bandBase = cx * (columnBands + 1);
      for (let b2 = 0; b2 <= columnBands; b2++) {
        _bandXB[bandBase + b2] = Math.round(rawX0 + (b2 * cellW0) / columnBands);
      }
      const bandClampBase = cx * columnBands;
      let allBands = 1;
      for (let b2 = 0; b2 < columnBands; b2++) {
        const rx0 = Math.max(x0, _bandXB[bandBase + b2]);
        const rx1 = Math.min(x1, _bandXB[bandBase + b2 + 1]);
        _bandX0[bandClampBase + b2] = rx0;
        _bandW[bandClampBase + b2] = rx1 - rx0;
        if (rx1 - rx0 <= 0) allBands = 0;
      }
      _colAllBands[cx] = allBands;
    }
    for (let cy = 0; cy < gy; cy++) {
      if (!_rowOk[cy]) continue;
      const y0 = _rowY0[cy];
      const y1 = _rowY1[cy];
      const segClampBase = cy * rowSegments;
      for (let cx = 0; cx < gx; cx++) {
        if (!_colOk[cx]) continue;
        const bandClampBase = cx * columnBands;
        const sums = _sums.fill(0);
        const counts = _counts.fill(0);
        for (let segment = 0; segment < rowSegments; segment++) {
          const segH = _segH[segClampBase + segment];
          if (segH <= 0) continue;
          const ry0 = _segY0[segClampBase + segment];
          const ry1 = ry0 + segH;
          for (let band = 0; band < columnBands; band++) {
            const bandW = _bandW[bandClampBase + band];
            if (bandW <= 0) continue;
            const rx0 = _bandX0[bandClampBase + band];
            const idx = segment * columnBands + band;
            sums[idx] = rectSum(rx0, ry0, rx0 + bandW, ry1);
            counts[idx] = bandW * segH;
          }
        }
        // Third-difference responds to +−+− alternation and cancels linear /
        // quadratic image content. Evaluate each short row segment under its
        // keyed sign, then average. Positive result means code bit = 1.
        let segmentScoreSum = 0;
        let segmentWeightSum = 0;
        let validSegments = 0;
        const robustSegmentResponses = robust ? (_segmentResponses.length = 0, _segmentResponses) : null;
        const cellIndex = cy * gx + cx;
        for (let segment = 0; segment < rowSegments; segment++) {
          const base = segment * columnBands;
          // A segment is complete iff every band of this cell got a
          // nonzero pixel count, which is exactly
          // segH > 0 && all band widths > 0 for this column.
          if (!_colAllBands[cx] || _segH[segClampBase + segment] <= 0) continue;
          validSegments++;
          const m0 = sums[base] / counts[base];
          const m1 = sums[base + 1] / counts[base + 1];
          const weight = Math.min(counts[base], counts[base + 1], counts[base + 2], counts[base + 3]);
          // Both profiles use the third-difference response: it cancels smooth
          // image gradients that otherwise swamp a two-band difference. The
          // robust profile gains low-frequency resilience from its larger
          // macro-cells/bands, redundant 96-bit codeword, and higher amplitude.
          const response = (-(-m0 + 3 * m1 - 3 * (sums[base + 2] / counts[base + 2]) + (sums[base + 3] / counts[base + 3])) / 8);
          const signedResponse = response * _signPol[cellIndex * rowSegments + segment];
          if (robust) robustSegmentResponses.push(signedResponse);
          segmentScoreSum += signedResponse * weight;
          segmentWeightSum += weight;
        }
        if (!segmentWeightSum || validSegments < 2) continue;
        let rawScore = segmentScoreSum / segmentWeightSum;
        if (robust) {
          // Median across row segments: one segment crossed by a hard image
          // edge should not dominate the whole macro-cell in the robust path.
          const values = robustSegmentResponses.sort((a, b) => a - b);
          const middle = Math.floor(values.length / 2);
          rawScore = values.length % 2
            ? values[middle]
            : (values[middle - 1] + values[middle]) / 2;
        }
        // Clip outliers: one hard image edge crossing a cell can otherwise
        // outvote five correctly-marked repetitions of the same code bit.
        const score = Math.max(-12, Math.min(12, rawScore));
        const bitIndex = _cellBitAll[cellIndex];
        bitScores[bitIndex] += score;
        bitCounts[bitIndex]++;
        _cellBitIdx[cellLen] = bitIndex;
        _cellScore[cellLen] = score;
        cellLen++;
      }
    }
    const votedBits = _votedBits.fill(0);
    const reliability = _reliability.fill(0);
    const voteScores = _voteScores.fill(0);
    if (robust) {
      // Robust repetitions are fewer than in the standard 64-bit layout.
      // Median voting prevents one hard image edge (already clipped to ±12)
      // from outvoting the other repetitions of the same code bit; the
      // standard profile retains its original summed-vote decoder exactly.
      const groups = _groups;
      for (const group of groups) group.length = 0;
      for (let ci = 0; ci < cellLen; ci++) groups[_cellBitIdx[ci]].push(_cellScore[ci]);
      for (let i = 0; i < codeLength; i++) {
        const values = groups[i].sort((a, b) => a - b);
        if (!values.length) continue;
        const middle = Math.floor(values.length / 2);
        voteScores[i] = values.length % 2
          ? values[middle]
          : (values[middle - 1] + values[middle]) / 2;
        votedBits[i] = voteScores[i] >= 0 ? 1 : 0;
        reliability[i] = Math.abs(voteScores[i]);
      }
    } else {
      for (let i = 0; i < codeLength; i++) {
        voteScores[i] = bitScores[i] / Math.max(1, bitCounts[i]);
        votedBits[i] = bitScores[i] >= 0 ? 1 : 0;
        reliability[i] = Math.abs(voteScores[i]);
      }
    }
    // Search-budget hint (outcome-preserving): the standard gates only
    // accept 2-3 corrections when raw signal is clearly genuine, so on
    // weak candidates a deep MAC search would manufacture rejects at
    // full HMAC cost across every geometry probe.
    let voteAbsSum = 0;
    for (let i = 0; i < codeLength; i++) voteAbsSum += Math.abs(voteScores[i]);
    const meanAbsPre = voteAbsSum / codeLength;
    // Agreement and per-bit disagreement are complementary views of
    // the same comparison; one fused pass computes both (the counts
    // feed the repair pre-gate's agreement bound below).
    let preAgreeing = 0;
    const disagreeByBit = _disagreeByBit.fill(0);
    for (let ci = 0; ci < cellLen; ci++) {
      if ((_cellScore[ci] >= 0) === !!votedBits[_cellBitIdx[ci]]) preAgreeing++;
      else disagreeByBit[_cellBitIdx[ci]]++;
    }
    const preAgreement = cellLen ? preAgreeing / cellLen : 0;
    const standardDepth = meanAbsPre >= 2.0 && preAgreement >= 0.82 ? 3 : 1;
    // Repair pre-gate: the flip search (CRC syndrome / MAC verification)
    // is most of detector wall time on hopeless probes, and several
    // acceptance inputs cannot change under repair — meanAbs and bit
    // coverage are vote-level facts, and flipping at most K bits can
    // raise agreement by at most the K largest per-bit disagree counts.
    // When even that bound misses the found-gates, the candidate is
    // rejected without running the search (tag fields then report
    // "not evaluated": corrections -1, tagScheme null).
    let minBitCountPre = Infinity;
    let observedBitsPre = 0;
    for (let i = 0; i < codeLength; i++) {
      const c = bitCounts[i];
      if (c < minBitCountPre) minBitCountPre = c;
      if (c > 0) observedBitsPre++;
    }
    const coverageOkPre = isV4
      ? observedBitsPre >= 88 && cellLen >= 96
      : robust
      ? observedBitsPre >= 88 && cellLen >= 128
      : minBitCountPre >= 2 && cellLen >= codeLength * 3;
    let agreementBound = preAgreement;
    if (cellLen) {
      // Sum of the largest maxFlips disagreement counts, via bounded
      // selection on a scratch copy (maxFlips <= 5): identical integer
      // sum to sorting descending, without allocating + sorting an
      // Array view of the typed array on every probe.
      const maxFlips = robust ? 5 : standardDepth;
      _gains.set(disagreeByBit);
      let gainSum = 0;
      const kMax = Math.min(maxFlips, codeLength);
      for (let k = 0; k < kMax; k++) {
        let bestIdx = -1;
        let bestVal = 0;
        for (let i = 0; i < codeLength; i++) {
          if (_gains[i] > bestVal) { bestVal = _gains[i]; bestIdx = i; }
        }
        if (bestIdx < 0) break;
        gainSum += bestVal;
        _gains[bestIdx] = 0;
      }
      agreementBound = (preAgreeing + gainSum) / cellLen;
    }
    // v4's BCH attempt is cheap (0.1 ms algebraic decode vs the
    // combinatorial flip searches) and its pre-gate lives in
    // bchAttempt below; the agreement-bound logic above models the
    // <=5-flip correctors and does not apply.
    const repairable = isV4
      ? meanAbsPre >= 1.2 && cellLen >= 96 && coverageOkPre
      : meanAbsPre >= 1.2 && cellLen >= 96 && coverageOkPre && agreementBound >= 0.72;
    // Erasure decoding (robust, MAC only): bits with zero cell votes
    // are UNKNOWN, not wrong — flipping <=5 of them cannot recover a
    // crop that erased 10-20. But only the erased PAYLOAD bits are
    // free variables: the CRC/MAC check bytes are recomputed from the
    // candidate payload and compared against whichever check bits WERE
    // observed, and the marker is constant. Enumeration is therefore
    // 2^(erased payload bits) x (small flip sets on weak observed
    // payload bits), gated on strong signal so noise candidates never
    // reach the search: an unmarked suspect measures ~0.6-0.68
    // self-agreement and mean signal well under 1.4.
    const erasureDecode = () => {
      const erasedPayload = [];
      let erasedTotal = 0;
      for (let i = 0; i < codeLength; i++) {
        if (bitCounts[i] === 0) { erasedTotal++; if (i < 48) erasedPayload.push(i); }
      }
      if (!erasedTotal || erasedTotal > 32 || erasedPayload.length > 20) return null;
      // As the surviving evidence thins, demand cleaner evidence: past
      // 24 erasures (a <=60%-retained crop) the repetition consensus
      // must be near-unanimous and the recomputed check bytes may
      // disagree with at most 2 observed bits.
      const deep = erasedTotal > 24;
      if (meanAbsPre < 2.0 || preAgreement < (deep ? 0.9 : 0.8) || cellLen < 96) return null;
      // Extremely clean deep candidates (near-unanimous consensus at
      // high amplitude — the real-photo 60% crop profile) may spend
      // the full budget of 3; noisier deep candidates stay at 2.
      const budget = deep && !(preAgreement >= 0.95 && meanAbsPre >= 4) ? 2 : 3;
      const weak = [];
      for (let i = 0; i < 48; i++) if (bitCounts[i] > 0) weak.push(i);
      weak.sort((a, b) => reliability[a] - reliability[b]);
      const weakPool = weak.slice(0, 16);
      const bits = Uint8Array.from(votedBits);
      const payload = new Uint8Array(6);
      const tryCandidate = (flips) => {
        for (let i = 0; i < 6; i++) {
          let byte = 0;
          for (let b = 0; b < 8; b++) byte = (byte << 1) | bits[i * 8 + b];
          payload[i] = byte;
        }
        // Cheap-first ordering mirrors robustStegoBytesValid: the
        // table CRC rejects ~all enumerated payloads before any MAC
        // (SHA-256) work runs — matters at 2^20 worst-case erasures.
        const crc = stegoCrc16(payload);
        let mismatches = 0;
        for (let i = 48; i < 64 && mismatches + flips <= budget; i++) {
          if (!bitCounts[i]) continue;
          const byte = i < 56 ? (crc >> 8) & 255 : crc & 255;
          if (((byte >> (7 - (i & 7))) & 1) !== votedBits[i]) mismatches++;
        }
        if (flips + mismatches > budget) return null;
        const mac = stegoMac16(key, payload);
        const checkBytes = [(crc >> 8) & 255, crc & 255, (mac >> 8) & 255, mac & 255];
        for (let i = 64; i < 80 && mismatches + flips <= budget; i++) {
          if (!bitCounts[i]) continue;
          const expected = (checkBytes[(i - 48) >> 3] >> (7 - (i & 7))) & 1;
          if (expected !== votedBits[i]) mismatches++;
        }
        for (let i = 80; i < 96 && mismatches + flips <= budget; i++) {
          if (bitCounts[i] && ROBUST_MARKER_BITS[i - 80] !== votedBits[i]) mismatches++;
        }
        if (flips + mismatches > budget) return null;
        const decoded = new Uint8Array(96);
        decoded.set(bits.subarray(0, 48), 0);
        for (let i = 48; i < 80; i++) decoded[i] = (checkBytes[(i - 48) >> 3] >> (7 - (i & 7))) & 1;
        for (let i = 80; i < 96; i++) decoded[i] = ROBUST_MARKER_BITS[i - 80];
        return { bits: decoded, corrections: flips + mismatches, tagScheme: 'mac', erasureDecoded: true, erasedBits: erasedTotal };
      };
      const enumerate = (flipSet) => {
        for (const i of flipSet) bits[i] ^= 1;
        const combos = 1 << erasedPayload.length;
        for (let mask = 0; mask < combos; mask++) {
          for (let j = 0; j < erasedPayload.length; j++) {
            bits[erasedPayload[j]] = (mask >> j) & 1;
          }
          const hit = tryCandidate(flipSet.length);
          if (hit) return hit;
        }
        for (const i of flipSet) bits[i] ^= 1;
        return null;
      };
      let hit = enumerate([]);
      if (!hit && erasedPayload.length <= 17) {
        for (const i of weakPool) { hit = enumerate([i]); if (hit) break; }
      }
      if (!hit && erasedPayload.length <= 14) {
        outer: for (let a = 0; a < weakPool.length; a++) {
          for (let b = a + 1; b < weakPool.length; b++) {
            hit = enumerate([weakPool[a], weakPool[b]]);
            if (hit) break outer;
          }
        }
      }
      return hit;
    };
    // Standard-profile erasure assist: the coverage pre-gate refuses
    // to run the flip corrector at all when a bit has zero votes
    // (minBitCount < 2), so a perfectly registered deep crop with ONE
    // erased bit failed while its corrector sat idle. With <= 4
    // erasures the erased bits are exactly the corrector's weakest
    // (reliability 0) flip candidates; acceptance is MAC-only since
    // the 16-bit tag is the standard codeword's only redundancy.
    const standardErasureAssist = () => {
      // The pre-gate's actual blocker is sparsity (bits with < 2
      // votes), which includes minRep=1 with zero true erasures.
      let sparse = 0;
      for (let i = 0; i < codeLength; i++) if (bitCounts[i] < 2) sparse++;
      const erased = codeLength - observedBitsPre;
      if (sparse < 1 || sparse > 6 || observedBitsPre < 60) return null;
      if (meanAbsPre < 2.0 || preAgreement < 0.85 || cellLen < codeLength * 3) return null;
      const fixed = correctStegoBits(votedBits, reliability, key, 3);
      if (fixed.corrections < 0 || fixed.tagScheme !== 'mac') return null;
      return { ...fixed, erasureDecoded: true, erasedBits: erased };
    };
    // v4 decode: BCH corrects errors AND erasures algebraically, so
    // the flip-search correctors and erasure enumeration above are
    // v1-v3 machinery. Erasure candidates are the zero-vote bits,
    // widened to the weakest-reliability bits on retry — each costs
    // one syndrome decode, so at most three bounded attempts.
    const bchAttempt = () => {
      if (!repairable) return null;
      const zeroVote = [];
      const byReliability = [];
      for (let i = 0; i < codeLength; i++) {
        if (bitCounts[i] === 0) zeroVote.push(i);
        else byReliability.push(i);
      }
      byReliability.sort((a, b) => reliability[a] - reliability[b]);
      // Bounded-distance passes first (exact error counts, cheapest
      // acceptance story), erasure sets widened by unreliability.
      if (zeroVote.length <= 36) {
        const erasureSets = [zeroVote];
        if (zeroVote.length <= 28) erasureSets.push([...zeroVote, ...byReliability.slice(0, 8)]);
        if (zeroVote.length <= 20) erasureSets.push([...zeroVote, ...byReliability.slice(0, 16)]);
        for (const set of erasureSets) {
          const hit = bchStegoDecode(votedBits, set, key);
          if (hit) {
            return {
              bits: hit.bits,
              corrections: hit.errors,
              tagScheme: 'mac',
              erasureDecoded: hit.erasures > 0,
              _bchBudget: 2 * hit.errors + hit.erasures,
              _fingerprint: hit.fingerprint,
            };
          }
        }
      }
      // ML erasure fallback (deep crops): solve the 64 data bits
      // from the most reliable observed bits; acceptance needs the
      // solved codeword to agree with (nearly) every OTHER observed
      // bit plus the MAC — noise solves to ~50% disagreement, far
      // outside the mismatch cap, long before the MAC matters.
      // Gated to erasure-shaped damage (several zero-vote bits) or
      // already-coherent candidates: during geometry search this
      // runs inside thousands of probes, and pure-error rescue is
      // the bounded-distance pass's job, not the solver's.
      const observedOrder = [...byReliability].reverse(); // reliability DESC
      if (observedOrder.length >= 72 && (zeroVote.length >= 4 || preAgreement >= 0.8)) {
        // Mismatch cap at 30% of the check equations (observed-64):
        // a noise solve disagrees with ~50% (7+ sigma beyond the
        // cap at these lengths), while genuine post-resampling
        // error counts measured 15-25% — a 15% cap rejected TRUE
        // codewords (v1.20 bench: watch crops and a standard-mode
        // identity suspect, all MAC-correct, all over the cap).
        // The MAC is verified inside the solve either way; the
        // rate tiers below scale evidence demands with the
        // mismatch rate actually consumed. OSD reprocessing
        // escalates only for already-coherent candidates and is
        // budgeted per search (see osdEscalations).
        const mismCap = Math.max(4, Math.floor((observedOrder.length - 64) * 0.30));
        // Escalation budgets were retuned after measuring budget
        // starvation on small-grid suspects: at ~1.5 cells/bit
        // (640px graphics) preAgreement inflates for nearly every
        // probe, so a 24-deep OSD budget evaporated on sweep junk
        // before the true candidate (1-3 bit errors!) arrived.
        // OSD itself is ~2 ms worst-case; 48 escalations bound
        // the added worst case to ~0.1 s per search while still
        // covering the late-arriving true candidates.
        const allowOsd = preAgreement >= 0.85 && osdEscalations < 48;
        if (allowOsd) osdEscalations++;
        // ISD escalation (randomized information sets) is the last
        // rung: measured crop damage put ~5 errors inside the
        // most-reliable basis — beyond OSD's 2 flips, trivial for
        // resampling. The gate is deliberately strict, calibrated
        // on a full 16,490-candidate geometry sweep of the failing
        // bench case: preAgreement>=0.95 && meanAbs>=3.5 admitted
        // just 28 candidates, 16 of them decodable, the FIRST of
        // them already the true geometry — while the looser
        // 0.92/2.5 gate admitted 1,117 and would burn any budget
        // on near-misses. The salt varies per escalation so
        // repeated refinement encounters explore fresh
        // information sets instead of replaying failures.
        // The signal floor is 2.0, not the 3.5 calibrated on 800px
        // photos: genuine graphic-class candidates measure
        // meanAbs 2.0-2.9 (their votes average fewer, larger
        // cells), and preAgreement>=0.95 remains the strict axis.
        const allowIsd = preAgreement >= 0.95 && meanAbsPre >= 2.0 &&
          observedOrder.length >= 100 && isdEscalations < 8;
        if (allowIsd) isdEscalations++;
        const ml = bchStegoSolveObserved(votedBits, observedOrder, key, {
          maxMismatches: mismCap, osd: allowOsd,
          isdTrials: allowIsd ? 600 : 0, seedSalt: isdEscalations,
        });
        if (ml && ml.mismatches <= mismCap) {
          const mismRate = ml.mismatches / Math.max(1, observedOrder.length - 64);
          return {
            bits: ml.bits,
            corrections: ml.mismatches,
            tagScheme: 'mac',
            erasureDecoded: true,
            _mismRate: mismRate,
            _bchBudget: Math.round(120 * mismRate),
            _fingerprint: ml.fingerprint,
          };
        }
      }
      return null;
    };
    let corrected = isV4 ? bchAttempt() : erasure ? (robust ? erasureDecode() : standardErasureAssist()) : null;
    if (!corrected) corrected = isV4
      ? { bits: votedBits, corrections: -1, tagScheme: null }
      : !repairable
      ? { bits: votedBits, corrections: -1, tagScheme: null }
      : robust
      ? (() => {
          // Depth caps that cannot change outcomes: 4-5 corrections are
          // only acceptable for MAC candidates with meanAbs>=3.5 and
          // agreement>=0.95 (robustCorrectionOk below), and never for
          // legacy CRC candidates — searching deeper in other regimes
          // only manufactures rejects at full combinatorial cost.
          // MAC depth tier relaxed in 1.17: the agreementBound >= 0.95
          // condition was CRC-era phantom logic. A <=5-flip candidate
          // must still satisfy marker+CRC+MAC (48 redundancy bits), so
          // at genuine signal levels (meanAbs >= 3.5) a depth-5 search
          // cannot manufacture an attribution — but gating it out made
          // real photos with 4-5 content-damaged bits undetectable.
          const macDepth = meanAbsPre >= 3.5 ? 5 : 3;
          const repaired = repairRobustStegoBits(reliability, votedBits, key, macDepth, 'mac') ||
            repairRobustStegoBits(reliability, votedBits, key, 3, 'crc');
          return repaired
            ? { bits: repaired.bits, corrections: repaired.flips, tagScheme: repaired.tagScheme }
            : { bits: votedBits, corrections: -1, tagScheme: null };
        })()
      : correctStegoBits(votedBits, reliability, key, standardDepth);
    const bits = corrected.bits;
    const fingerprint = isV4
      ? (corrected._fingerprint || '')
      : robust
      ? robustStegoFingerprintFromBits(bits)
      : [...stegoBitsToBytes(bits).subarray(0, 6)].map((b) => b.toString(16).padStart(2, '0')).join('');
    // The correctors only return corrections >= 0 for a candidate that
    // passed its acceptance predicate (MAC tag, or legacy CRC fallback).
    const crcValid = corrected.corrections >= 0;
    let agreeing = 0;
    for (let ci = 0; ci < cellLen; ci++) {
      if ((_cellScore[ci] >= 0) === !!bits[_cellBitIdx[ci]]) agreeing++;
    }
    const agreement = cellLen ? agreeing / cellLen : 0;
    const meanAbs = meanAbsPre;
    // Unmarked photos naturally show ~0.60–0.68 self-agreement (majority
    // vote bias) and weak mean signal; genuine marks sit far above both.
    const evidence = Math.max(0, agreement - 0.64) * 2.4 +
      Math.min(0.55, Math.max(0, meanAbs - 1.4) / 8) -
      (isV4 ? (corrected._bchBudget || 0) / 6 : Math.max(0, corrected.corrections)) * 0.04;
    const confidence = crcValid
      ? Math.max(0, Math.min(0.99, 0.42 + evidence))
      : Math.max(0, Math.min(0.49, evidence));
    const minBitCount = Math.min(...bitCounts);
    const observedBits = bitCounts.reduce((count, value) => count + (value > 0 ? 1 : 0), 0);
    // A center crop can remove every repetition of a few robust code bits.
    // Accept that bounded case only when at least 88/96 bits were observed
    // and the dual-CRC/marker codeword plus signal thresholds all validate.
    // The standard profile requires dense evidence — >=3 cells per bit on
    // average and >=2 for every bit: with ~1-2 cells per bit, majority
    // "agreement" is near-tautological and the CRC corrector can flip
    // low-reliability bits into a false positive on unmarked noise (found
    // by fuzzing; genuine marks measure ~6 cells/bit, agreement >= 0.84).
    const bitCoverageOk = isV4
      ? (observedBits >= 150 && cellLen >= 128) ||
        (corrected.erasureDecoded === true && observedBits >= 96 && cellLen >= 110)
      : robust
      ? (observedBits >= 88 && cellLen >= 128) ||
        // Erasure decodes trade coverage for cryptographic certainty:
        // the payload + recomputed CRC/MAC/marker must agree with every
        // observed check bit (<=3 disagreements), which noise cannot
        // manufacture — but a floor of 76 observed bits stays.
        (corrected.erasureDecoded === true && observedBits >= 64)
      : (minBitCount >= 2 && cellLen >= codeLength * 3) ||
        (corrected.erasureDecoded === true && observedBits >= 60 && cellLen >= codeLength * 3);
    // The robust syndrome decoder can search farther than the standard
    // decoder. To prefer "not found" over a wrong attribution, candidates
    // needing four or five corrections must also show strong raw signal and
    // cell agreement; a weak, heavily repaired candidate is not evidence.
    const correctionCount = Math.max(0, corrected.corrections);
    // Legacy (pre-v1.12, CRC-tagged) candidates are held to stricter gates:
    // their linear tag is exactly what collusion-phantom repair exploits,
    // so a legacy standard decode must be nearly repair-free with very
    // high agreement, and a legacy robust decode loses the 4-5 tier.
    const legacyScheme = corrected.tagScheme === 'crc';
    const robustCorrectionOk = isV4 || !robust || correctionCount <= 3 ||
      (!legacyScheme && correctionCount <= 5 && meanAbs >= 3.5 && agreement >= 0.85);
    // Same principle for the standard decoder: a candidate needing 2+
    // repaired bits must carry clearly genuine raw signal, or the repair
    // search itself manufactures the CRC match (false attribution).
    const standardCorrectionOk = isV4 || robust || (legacyScheme
      ? correctionCount <= 1 && agreement >= 0.95
      : correctionCount <= 1 || (meanAbs >= 2.0 && agreement >= 0.85));
    // v4 correction tiers mirror the v1-v3 philosophy (heavy repair
    // needs strong raw signal), scaled to the BCH budget 2e+s<=36:
    // the MAC inside the payload already rejects miscorrections,
    // these gates keep confidence honest on marginal decodes.
    const bchBudget = corrected._bchBudget || 0;
    // Bounded-distance decodes keep the 2e+s budget tiers. ML/OSD
    // decodes are tiered by mismatch RATE over the check
    // equations instead: an absolute budget double-counts
    // erasures (deep crops shrink the denominator), and vote
    // magnitudes in the standard profile (1-2 cells/bit at 188
    // bits) never reach the robust-profile thresholds even for
    // genuine identity suspects (measured meanAbs 2.1, MAC-valid,
    // rejected by the old top tier). The MAC + 30% cap carry
    // attribution safety (~7 sigma from the noise-solve rate);
    // these tiers keep confidence honest on marginal decodes.
    // Top ML tier agreement is 0.82, not 0.88: agreement is scored
    // against the CORRECTED bits, so the cells that manufactured
    // each wrong vote flip to "disagreeing" after correction —
    // at ~1.2 cells/bit after a deep crop, a genuine 13-mismatch
    // MAC-verified decode lands at ~0.87 and an 0.88 tier rejects
    // the recovery for the very damage the code just repaired
    // (measured, bench watch center0.7). Attribution safety at
    // this rung is the MAC plus the 30% mismatch cap; agreement
    // remains a corroborating floor, not a second wall.
    const v4CorrectionOk = !isV4 || (corrected._mismRate != null
      ? corrected._mismRate <= 0.10 ||
        (corrected._mismRate <= 0.20 && meanAbs >= 2.0 && agreement >= 0.82) ||
        (meanAbs >= 2.5 && agreement >= 0.82)
      : bchBudget <= 12 ||
        (bchBudget <= 24 && meanAbs >= 2.5 && agreement >= 0.82) ||
        (meanAbs >= 3.5 && agreement >= 0.88));
    const found = crcValid && agreement >= 0.72 && meanAbs >= 1.2 &&
      cellLen >= 96 && bitCoverageOk && robustCorrectionOk && standardCorrectionOk && v4CorrectionOk;
    const _result = {
      found,
      fingerprint,
      profile: effectiveProfile,
      tagScheme: corrected.tagScheme ?? null,
      layoutVersion: concreteLayout,
      erasureDecoded: corrected.erasureDecoded === true,
      erasedBits: codeLength - observedBits,
      observedBits,
      minBitRepetitions: minBitCount,
      crcValid,
      corrections: Math.max(0, corrected.corrections),
      // Confidence describes the ACCEPTED verdict: a candidate the gates
      // rejected must never report near-certain confidence, or downstream
      // tooling will treat a manufactured CRC match as an attribution.
      confidence: Math.round((found ? confidence : Math.min(0.49, confidence)) * 1000) / 1000,
      agreement: Math.round(agreement * 1000) / 1000,
      meanSignal: Math.round(meanAbs * 100) / 100,
      cells: cellLen,
      offset: {
        x: Math.round((ox / cellW0) * 1000) / 1000,
        y: Math.round((oy / cellH0) * 1000) / 1000,
      },
      geometry: {
        scaleX: Math.round(scaleX * 1000) / 1000,
        scaleY: Math.round(scaleY * 1000) / 1000,
        originX: Math.round(ox * 10) / 10,
        originY: Math.round(oy * 10) / 10,
      },
      grid: { x: gx, y: gy },
      _evidence: evidence,
      _originX: ox,
      _originY: oy,
      _scaleX: scaleX,
      _scaleY: scaleY,
    };
    if (isV4 && !found && observedBits >= 96 && cellLen >= 110 && meanAbs >= 1.2 &&
        (forensicStash.length < 3 || evidence > forensicStash[forensicStash.length - 1].evidence)) {
      const geoKey = `${_result.geometry.scaleX}|${_result.geometry.scaleY}|${Math.round(_result.geometry.originX / 4)}|${Math.round(_result.geometry.originY / 4)}`;
      const dup = forensicStash.findIndex((e) => e.geoKey === geoKey);
      if (dup < 0 || evidence > forensicStash[dup].evidence) {
        const ord = [];
        for (let i = 0; i < codeLength; i++) if (bitCounts[i] > 0) ord.push(i);
        ord.sort((a, b) => reliability[b] - reliability[a]);
        const entry = {
          result: _result, evidence, meanAbs, cellLen, geoKey,
          votes: Uint8Array.from(votedBits), order: ord,
          cellScore: _cellScore.slice(0, cellLen),
          cellBitIdx: _cellBitIdx.slice(0, cellLen),
        };
        if (dup >= 0) forensicStash[dup] = entry; else forensicStash.push(entry);
        forensicStash.sort((a, b) => b.evidence - a.evidence);
        if (forensicStash.length > 3) forensicStash.length = 3;
      }
    }
    return _result;
  };

  let best = null;
  const consider = (candidate) => {
    const better = !best ||
      (candidate.found && !best.found) ||
      (candidate.found === best.found && candidate._evidence > best._evidence) ||
      (candidate.found === best.found && candidate._evidence === best._evidence && candidate.confidence > best.confidence);
    if (better) best = candidate;
    return candidate;
  };

  try {
  for (const fx of fractions) for (const fy of fractions) {
    consider(evaluate({ fx, fy }));
    if (best.found && best.confidence >= 0.92 && fx === 0 && fy === 0) break;
  }

  // Fast dihedral screens BEFORE the exhaustive geometry sweep:
  // mirrored / rotated / transposed suspects resolve natively in
  // a few hundred ms, but sequenced after the geometry search
  // they cost 5-14 s of hopeless forward sweeping first (bench:
  // transposeMain successes at 9.9-13.9 s). Compound suspects
  // (flip AND crop) still reach the geometry-inheriting probes
  // at the end of the search; these early probes are pure
  // latency work and run only when geometry was requested (when
  // it is off, the end probes already run natively).
  if (searchGeometry && !best?.found && (searchMirror || searchRotation) && !_mirrorProbe) {
    try {
      if (srcTop.length >= w * h * 4 && Number.isSafeInteger(w * h * 4)) {
        const entry = planesEntry(srcTop);
        for (const [axis, fx, fy] of searchMirror ? MIRROR_AXES : []) {
          const variant = mirroredVariant(entry, srcTop, w, h, axis, fx, fy);
          const mirrored = detectStegoFingerprint(variant, w, h, {
            key, gridX, gridY, profile, searchOffsets, searchGeometry: false,
            searchMirror: false, searchRotation: false, searchTilt: false, _mirrorProbe: true, _tiltProbe: true, _layoutVersion: concreteLayout, _planes: planesCache, _deadline: deadline,
          });
          if (mirrored?.found) return { ...mirrored, mirrored: true, mirrorAxis: axis };
        }
        for (const clockwise of searchRotation ? [false, true] : []) {
          const variant = rotatedVariant(entry, srcTop, w, h, clockwise);
          const rotated = detectStegoFingerprint(variant, h, w, {
            key, gridX, gridY, profile, searchOffsets, searchGeometry: false,
            searchMirror: false, searchRotation: false, searchTilt: false, _mirrorProbe: true, _tiltProbe: true, _layoutVersion: concreteLayout, _planes: planesCache, _deadline: deadline,
          });
          if (rotated?.found) return { ...rotated, rotated: clockwise ? 270 : 90 };
        }
        for (const anti of searchRotation ? [false, true] : []) {
          const variant = transposedVariant(entry, srcTop, w, h, anti);
          const transposed = detectStegoFingerprint(variant, h, w, {
            key, gridX, gridY, profile, searchOffsets, searchGeometry: false,
            searchMirror: false, searchRotation: false, searchTilt: false, _mirrorProbe: true, _tiltProbe: true, _layoutVersion: concreteLayout, _planes: planesCache, _deadline: deadline,
          });
          if (transposed?.found) return { ...transposed, transposed: anti ? 'anti' : 'main' };
        }
      }
    } catch (probeErr) { if (probeErr === STEGO_TIMEOUT) throw probeErr; /* fast variant screens are best-effort */ }
  }

  // Uniform crop+resize changes the suspect-pixel size and origin of the
  // original macro-cell grid. Search a bounded set of retained-area scales
  // (80–125%) at left/center/right and top/center/bottom origins, then refine
  // the strongest geometries by sub-cell offsets. This intentionally does
  // NOT claim perspective/rotation recovery: a phone photo usually needs
  // manual deskew/crop to the displayed rectangle before detection.
  if (searchGeometry && !best?.found) {
    const scaleValues = [0.8, 0.85, 0.9, 0.95, 1, 1.05, 1 / 0.9, 1 / 0.85, 1.2, 1.25];
    // 3-decimal precision: rounding to 1 decimal (pre-1.13) silently
    // rewrote half the table (0.85->0.9, 1/0.9->1.1, ...), and at
    // 1.1 vs the true 1.111 for an unresized 90% center crop the cell
    // grid drifts ~10px across the frame — enough to lose the mark.
    const unique = (values) => [...new Set(values.map((v) => Math.round(v * 1000) / 1000))];
    const originRange = (span, extent) => {
      const min = Math.min(0, extent - span);
      const max = Math.max(0, extent - span);
      return { min, max, center: (min + max) / 2 };
    };

    // First rank independent X/Y retained-area scales at edge/center origins.
    // This catches one-axis crops (e.g. only the left edge was removed) as
    // well as symmetric crops. Geometry search is an offline forensic mode,
    // so a few hundred bounded candidates are acceptable.
    const scaleCandidates = [];
    // Native-resolution crops (no resize): the signal is pristine but the
    // grid is offset by whole cells — searchOffsets only covers ±1 cell.
    // Roam ±4 cells at scale 1; the sub-cell refinement below polishes.
    for (let cellX = -4; cellX <= 4; cellX++) {
      for (let cellY = -4; cellY <= 4; cellY++) {
        if (cellX === 0 && cellY === 0) continue;
        scaleCandidates.push(consider(evaluate({
          scaleX: 1, scaleY: 1, originX: cellX * cw, originY: cellY * ch,
        })));
      }
    }
    for (const scaleX of scaleValues) {
      const rangeX = originRange(gx * cw * scaleX, w);
      for (const scaleY of scaleValues) {
        const rangeY = originRange(gy * ch * scaleY, h);
        for (const originX of unique([rangeX.min, rangeX.center, rangeX.max])) {
          for (const originY of unique([rangeY.min, rangeY.center, rangeY.max])) {
            scaleCandidates.push(consider(evaluate({
              scaleX, scaleY, originX, originY,
            })));
          }
        }
      }
    }
    // Stage 2 (only when stage 1 found nothing): deeper retained-area
    // scales for aggressive crops — 65–75% kept, or equivalently an
    // 88% corner crop whose scale (~1.14) fell between table entries
    // often enough that grid drift killed every candidate. Independent
    // X/Y values keep aspect-changing crops reachable; the origin
    // refinement below polishes whichever pair leads.
    if (!best?.found) {
      const deepScales = [0.65, 0.7, 0.75, 1 / 0.88, 1 / 0.75, 1.38, 1 / 0.7, 1 / 0.65];
      for (const scaleX of deepScales) {
        const rangeX = originRange(gx * cw * scaleX, w);
        for (const scaleY of deepScales) {
          const rangeY = originRange(gy * ch * scaleY, h);
          for (const originX of unique([rangeX.min, rangeX.center, rangeX.max])) {
            for (const originY of unique([rangeY.min, rangeY.center, rangeY.max])) {
              scaleCandidates.push(consider(evaluate({
                scaleX, scaleY, originX, originY,
              })));
            }
          }
        }
      }
    }

    // Stage 3 (still nothing): reframe-shaped seeds the two cross
    // tables never generate — stage 1 caps at 1.25 and stage 2 crosses
    // deep scales only with each other, so (1.5, 1.0) for a 3:2 -> 1:1
    // reframe and the (s, 1)/(1, s) one-axis-crop pairs were never
    // evaluated at all, and ±3.5% fine steps cannot reach 1.5 from
    // 1.538's diagonal basin. Diagonals cover uniform crops to 55%.
    if (!best?.found) {
      const seedPairs = [];
      for (const s of [0.55, 0.6, 2 / 3, 1.5, 1 / 0.6, 16 / 9, 1 / 0.55]) seedPairs.push([s, s]);
      for (const s of [1 / 0.75, 1 / 0.7, 1.5, 1 / 0.65, 1 / 0.6, 16 / 9]) {
        seedPairs.push([s, 1], [1, s]);
      }
      for (const s of [0.65, 0.7, 0.75]) seedPairs.push([s, 1], [1, s]);
      for (const [scaleX, scaleY] of seedPairs) {
        const rangeX = originRange(gx * cw * scaleX, w);
        const rangeY = originRange(gy * ch * scaleY, h);
        for (const originX of unique([rangeX.min, rangeX.center, rangeX.max])) {
          for (const originY of unique([rangeY.min, rangeY.center, rangeY.max])) {
            scaleCandidates.push(consider(evaluate({ scaleX, scaleY, originX, originY })));
          }
        }
        if (best?.found) break;
      }
    }

    // Then try edge/center origins for the strongest scale pairs.
    const originCandidates = [];
    const seenPairs = new Set();
    for (const candidate of scaleCandidates.sort((a, b) => b._evidence - a._evidence)) {
      const key = `${Math.round(candidate._scaleX * 1000)}:${Math.round(candidate._scaleY * 1000)}`;
      if (seenPairs.has(key)) continue;
      seenPairs.add(key);
      const rangeX = originRange(gx * cw * candidate._scaleX, w);
      const rangeY = originRange(gy * ch * candidate._scaleY, h);
      // Quarter points as well as edges/center: an asymmetric crop (e.g.
      // 14% off the left, 4% off the right) lands between center and edge
      // and previously desynchronized every candidate.
      const quarter = (range) => unique([
        range.min,
        range.min + (range.max - range.min) * 0.25,
        range.center,
        range.min + (range.max - range.min) * 0.75,
        range.max,
      ]);
      for (const originX of quarter(rangeX)) {
        for (const originY of quarter(rangeY)) {
          originCandidates.push(consider(evaluate({
            scaleX: candidate._scaleX,
            scaleY: candidate._scaleY,
            originX,
            originY,
          })));
        }
      }
      if (seenPairs.size >= 4) break;
    }

    // Finally refine the best three geometries by sub-cell offsets.
    const refinements = [];
    const seenGeometries = new Set();
    for (const candidate of originCandidates.sort((a, b) => b._evidence - a._evidence)) {
      const key = `${Math.round(candidate._scaleX * 1000)}:${Math.round(candidate._scaleY * 1000)}:` +
        `${Math.round(candidate._originX)}:${Math.round(candidate._originY)}`;
      if (seenGeometries.has(key)) continue;
      seenGeometries.add(key);
      refinements.push(candidate);
      if (refinements.length >= 3) break;
    }
    for (const coarseCandidate of refinements) {
      for (const fx of fractions) for (const fy of fractions) {
        consider(evaluate({
          scaleX: coarseCandidate._scaleX,
          scaleY: coarseCandidate._scaleY,
          originX: coarseCandidate._originX + fx * cw * coarseCandidate._scaleX,
          originY: coarseCandidate._originY + fy * ch * coarseCandidate._scaleY,
        }));
      }
    }

    // Fine scale refinement around the leaders. The coarse scale grid is
    // 5%-stepped; an 82%-retained crop sits between 0.80 and 0.85, and a
    // 2–3% scale error drifts the macro-cell grid by up to ~0.7 cell at
    // the far edge — enough to desync voting even at the right origin.
    // Walk ±3.5% in ~1.2% steps on each axis around the best geometries,
    // re-centering the origin so the grid center stays anchored.
    if (!best?.found) {
      const fineFactors = [0.965, 0.977, 0.988, 1.012, 1.023, 1.035];
      const leaders = refinements.slice(0, 2);
      for (const leader of leaders) {
        for (const fxScale of [1, ...fineFactors]) {
          for (const fyScale of [1, ...fineFactors]) {
            if (fxScale === 1 && fyScale === 1) continue;
            const scaleX = leader._scaleX * fxScale;
            const scaleY = leader._scaleY * fyScale;
            consider(evaluate({
              scaleX,
              scaleY,
              originX: leader._originX + (gx * cw * (leader._scaleX - scaleX)) / 2,
              originY: leader._originY + (gy * ch * (leader._scaleY - scaleY)) / 2,
            }));
            if (best?.found) break;
          }
          if (best?.found) break;
        }
      }
    }
    // Coordinate-descent scale escape. Aspect-changing crops (3:2 → 1:1
    // needs scaleX 1.5, scaleY 1.0) pull the coarse search into a
    // diagonal "average" basin (1.43, 1.33) that the ±3.5% fine walk
    // cannot leave. Moving ONE axis at a time with larger steps walks
    // out of the basin along the improving coordinate; two rounds from
    // the updated best converge for the common reframe ratios.
    if (!best?.found) {
      const descendFrom = (seed) => {
        let cur = seed;
        for (let round = 0; round < 2 && cur && !best?.found; round++) {
          const beforeScaleX = cur._scaleX, beforeScaleY = cur._scaleY;
          for (const f of [0.9, 0.94, 0.97, 1.03, 1.06, 1.11]) {
            const sx = cur._scaleX * f;
            consider(evaluate({
              scaleX: sx, scaleY: cur._scaleY,
              originX: cur._originX + (gx * cw * (cur._scaleX - sx)) / 2,
              originY: cur._originY,
            }));
            const sy = cur._scaleY * f;
            consider(evaluate({
              scaleX: cur._scaleX, scaleY: sy,
              originX: cur._originX,
              originY: cur._originY + (gy * ch * (cur._scaleY - sy)) / 2,
            }));
            if (best?.found) return;
          }
          cur = best;
          if (cur._scaleX === beforeScaleX && cur._scaleY === beforeScaleY) break;
        }
      };
      // Seed the descent from the strongest DIVERSE scale pairs, not
      // only the origin-refined leaders: a reframe seed like (1.78, 1)
      // can carry real signal yet lose the origin-refinement cut to a
      // spurious diagonal basin, and one 6% axis step from its true
      // basin is all it needs.
      const descentSeeds = [];
      const descentSeen = new Set();
      // Ranked by raw signal (meanSignal), NOT evidence: partial grid
      // alignment raises per-bit median amplitudes long before
      // agreement/tag gates move, while best-of-thousands noise
      // basins win evidence via majority-vote self-agreement.
      for (const cand of [best, ...originCandidates, ...scaleCandidates]
        .filter(Boolean).sort((a, b) => (b.meanSignal - a.meanSignal) || (b._evidence - a._evidence))) {
        const k = `${Math.round(cand._scaleX * 100)}:${Math.round(cand._scaleY * 100)}`;
        if (descentSeen.has(k)) continue;
        descentSeen.add(k);
        descentSeeds.push(cand);
        if (descentSeeds.length >= 6) break;
      }
      for (const leader of descentSeeds) {
        descendFrom(leader);
        if (best?.found) break;
      }
      // Origin re-roam at the descended scales: centre-anchored
      // recentering can land 1-2 cells off when the seed basin aligned
      // a different sub-region, which sub-cell steps cannot fix.
      if (!best?.found && best) {
        const rangeX = originRange(gx * cw * best._scaleX, w);
        const rangeY = originRange(gy * ch * best._scaleY, h);
        const roam = (r) => unique([r.min, r.min + (r.max - r.min) * 0.25, r.center, r.min + (r.max - r.min) * 0.75, r.max]);
        for (const originX of roam(rangeX)) {
          for (const originY of roam(rangeY)) {
            consider(evaluate({ scaleX: best._scaleX, scaleY: best._scaleY, originX, originY }));
          }
        }
      }
      // Sub-cell polish around wherever the descent landed.
      if (!best?.found && best) {
        const landed = best;
        for (const fx of fractions) for (const fy of fractions) {
          consider(evaluate({
            scaleX: landed._scaleX, scaleY: landed._scaleY,
            originX: landed._originX + fx * cw * landed._scaleX,
            originY: landed._originY + fy * ch * landed._scaleY,
          }));
          if (best?.found) break;
        }
      }
    }
  }

  // Erasure-decode stage (robust profile): the geometry search often
  // registers a deep crop exactly (agreement ~1.0, strong signal) yet
  // the tag cannot verify because the crop removed EVERY repetition
  // of 10-20 code bits — far beyond the <=5-flip repair. Those bits
  // are erasures at known positions, and the robust codeword carries
  // CRC-16 + MAC-16 + a constant marker, so enumerating only the
  // erased PAYLOAD bits (check bytes are recomputed, not searched)
  // recovers them exactly. Runs once, on the leading candidate, and
  // only behind strong independent signal gates (see evaluate()).
  if (best && !best.found && best.cells >= 96 &&
    ((robust && best.meanSignal >= 2.0 && best.agreement >= 0.8) ||
     (!robust && best.meanSignal >= 2.0 && best.agreement >= 0.85 && best.observedBits >= 60))) {
    consider(evaluate({
      scaleX: best._scaleX, scaleY: best._scaleY,
      originX: best._originX, originY: best._originY, erasure: true,
    }));
  }

  if (best) {
    delete best._evidence;
    delete best._originX;
    delete best._originY;
    delete best._scaleX;
    delete best._scaleY;
  }
  // Explicit-profile mirror recovery (compound flip+geometry included,
  // since the probe inherits this call's search options).
  // Tilt (small-angle) deskew stage: a few degrees of rotation smear
  // the macro-cell grid beyond every axis-aligned candidate, so no
  // amount of scale/origin search registers it. Sweep candidate
  // angles on a <=960px proxy with cheap native detects (center-
  // cropped, since rotating editors expand the canvas and leave the
  // grid at ~0.94-0.99x frame scale), estimate the angle as the
  // signal-weighted CENTROID of the resulting broad bump (argmax is
  // unstable: residual scale mismatch flattens the peak over ~±1.5
  // degrees), then confirm a handful of candidate angles at full
  // resolution with the complete detector. Forensic opt-in.
  if (!best?.found && searchTilt && !_tiltProbe) {
    try {
      if (srcTop.length >= w * h * 4 && Number.isSafeInteger(w * h * 4)) {
        const entry = planesEntry(srcTop);
        // Confirmation detects run WITHOUT variant probes per angle
        // (each would fan out into full mirror/rotation geometry
        // searches on failure); one final variants-on confirmation at
        // the leading candidate covers tilt+flip compounds.
        const confirmAt = (degreesCw, variants = false) => {
          const warpedFull = rotateRgba(srcTop, w, h, (-degreesCw * Math.PI) / 180);
          return detectStegoFingerprint(warpedFull, w, h, {
            key, gridX, gridY, profile, searchOffsets: true, searchGeometry,
            searchMirror: variants && searchMirror, searchRotation: variants && searchRotation,
            searchTilt: false,
            _tiltProbe: true, _layoutVersion: concreteLayout, _planes: planesCache, _deadline: deadline,
          });
        };
        let tiltCandidates = entry.tiltCandidates || null;
        let tiltScreenHit = null;
        if (!tiltCandidates) {
          const proxyScale = Math.min(1, 960 / w);
          const pw = Math.max(64, Math.round(w * proxyScale));
          const ph = Math.max(64, Math.round(h * proxyScale));
          const proxy = proxyScale < 1 ? resampleRgba(srcTop, w, h, pw, ph) : srcTop;
          const cropCenter = (buf, bw, bh, frac) => {
            if (frac >= 1) return { buf, w: bw, h: bh };
            const cw2 = Math.max(64, Math.round(bw * frac));
            const ch2 = Math.max(64, Math.round(bh * frac));
            const ox = Math.round((bw - cw2) / 2), oy = Math.round((bh - ch2) / 2);
            const out = new Uint8Array(cw2 * ch2 * 4);
            for (let y = 0; y < ch2; y++) {
              out.set(buf.subarray(((oy + y) * bw + ox) * 4, ((oy + y) * bw + ox + cw2) * 4), y * cw2 * 4);
            }
            return { buf: out, w: cw2, h: ch2 };
          };
          const quickDetect = (degreesCw) => {
            const warped = rotateRgba(proxy, pw, ph, (-degreesCw * Math.PI) / 180);
            let bestHit = null;
            for (const frac of [1, 0.96, 0.92]) {
              const view = cropCenter(warped, pw, ph, frac);
              const hit = detectStegoFingerprint(view.buf, view.w, view.h, {
                key, gridX, gridY, profile, searchOffsets: true,
                searchGeometry: false, searchMirror: false, searchRotation: false, searchTilt: false,
                _mirrorProbe: true, _tiltProbe: true, _layoutVersion: concreteLayout, _planes: planesCache, _deadline: deadline,
              });
              if (hit?.found) return hit;
              if (!bestHit || (hit?.meanSignal ?? 0) > (bestHit.meanSignal ?? 0)) bestHit = hit;
            }
            return bestHit;
          };
          const samples = [];
          for (let angle = -6; angle <= 6.001; angle += 0.5) {
            if (deadlineHit()) throw STEGO_TIMEOUT;
            if (Math.abs(angle) < 1e-9) continue;
            const hit = quickDetect(angle);
            if (hit?.found) { tiltScreenHit = { hit, angle }; break; }
            samples.push([angle, hit?.meanSignal ?? 0]);
          }
          if (tiltScreenHit) {
            tiltCandidates = [tiltScreenHit.angle];
          } else if (samples.length >= 5) {
            const signals = samples.map((s) => s[1]);
            const sorted = [...signals].sort((a, b) => a - b);
            const baseline = sorted[Math.floor(sorted.length / 2)] ?? 0;
            let maxIdx = 0;
            for (let i = 1; i < signals.length; i++) if (signals[i] > signals[maxIdx]) maxIdx = i;
            const peak = signals[maxIdx];
            if (peak >= 1.2 && peak > baseline + 0.15) {
              const thresh = baseline + 0.25 * (peak - baseline);
              let lo = maxIdx, hi = maxIdx;
              while (lo > 0 && signals[lo - 1] > thresh) lo--;
              while (hi < signals.length - 1 && signals[hi + 1] > thresh) hi++;
              let wSum = 0, aSum = 0;
              for (let i = lo; i <= hi; i++) {
                const weight = (signals[i] - baseline) ** 2;
                wSum += weight;
                aSum += weight * samples[i][0];
              }
              const centroid = wSum > 0 ? aSum / wSum : samples[maxIdx][0];
              tiltCandidates = [...new Set([
                centroid, samples[maxIdx][0], centroid - 0.3, centroid + 0.3,
              ].map((a) => Math.round(a * 100) / 100))];
            }
          }
          entry.tiltCandidates = tiltCandidates;
        }
        if (tiltCandidates) {
          for (const angle of tiltCandidates) {
            const full = confirmAt(angle);
            if (full?.found) return { ...full, deskewed: Math.round(angle * 100) / 100 };
          }
          if (searchMirror || searchRotation) {
            const full = confirmAt(tiltCandidates[0], true);
            if (full?.found) return { ...full, deskewed: Math.round(tiltCandidates[0] * 100) / 100 };
          }
          if (tiltScreenHit) return { ...tiltScreenHit.hit, deskewed: Math.round(tiltScreenHit.angle * 100) / 100 };
        }
      }
    } catch (tiltErr) { if (tiltErr === STEGO_TIMEOUT) throw tiltErr; /* tilt search is best-effort */ }
  }
  if (!best?.found && (searchMirror || searchRotation) && !_mirrorProbe) {
    try {
      if (srcTop.length >= w * h * 4 && Number.isSafeInteger(w * h * 4)) {
        const entry = planesEntry(srcTop);
        for (const [axis, fx, fy] of searchMirror ? MIRROR_AXES : []) {
          const variant = mirroredVariant(entry, srcTop, w, h, axis, fx, fy);
          const mirrored = detectStegoFingerprint(variant, w, h, {
            key, gridX, gridY, profile, searchOffsets, searchGeometry,
            searchMirror: false, searchRotation: false, searchTilt: false, _mirrorProbe: true, _tiltProbe: true, _layoutVersion: concreteLayout, _planes: planesCache, _deadline: deadline,
          });
          if (mirrored?.found) return { ...mirrored, mirrored: true, mirrorAxis: axis };
        }
        for (const clockwise of searchRotation ? [false, true] : []) {
          const variant = rotatedVariant(entry, srcTop, w, h, clockwise);
          const rotated = detectStegoFingerprint(variant, h, w, {
            key, gridX, gridY, profile, searchOffsets, searchGeometry,
            searchMirror: false, searchRotation: false, searchTilt: false, _mirrorProbe: true, _tiltProbe: true, _layoutVersion: concreteLayout, _planes: planesCache, _deadline: deadline,
          });
          if (rotated?.found) return { ...rotated, rotated: clockwise ? 270 : 90 };
        }
        for (const anti of searchRotation ? [false, true] : []) {
          const variant = transposedVariant(entry, srcTop, w, h, anti);
          const transposed = detectStegoFingerprint(variant, h, w, {
            key, gridX, gridY, profile, searchOffsets, searchGeometry,
            searchMirror: false, searchRotation: false, searchTilt: false, _mirrorProbe: true, _tiltProbe: true, _layoutVersion: concreteLayout, _planes: planesCache, _deadline: deadline,
          });
          if (transposed?.found) return { ...transposed, transposed: anti ? 'anti' : 'main' };
        }
      }
    } catch (probeErr) { if (probeErr === STEGO_TIMEOUT) throw probeErr; /* variant probes are best-effort */ }
  }
  } catch (err) {
    if (err !== STEGO_TIMEOUT) throw err;
    if (!best) {
      return {
        found: false, fingerprint: '', profile: effectiveProfile, tagScheme: null,
        layoutVersion: concreteLayout, erasureDecoded: false, erasedBits: 0, observedBits: 0,
        minBitRepetitions: 0, crcValid: false, corrections: 0, confidence: 0, agreement: 0,
        meanSignal: 0, cells: 0, offset: { x: 0, y: 0 },
        geometry: { scaleX: 1, scaleY: 1, originX: 0, originY: 0 }, grid: { x: gx, y: gy },
        timedOut: true,
      };
    }
    // One bounded deep decode even past the deadline: a search
    // that timed out during geometry refinement is exactly where
    // the best candidate already exists but never received decode
    // budget. Top stash only, evidence-gated, ~100 ms overrun.
    if (isV4 && !best?.found && forensicStash.length && !_mirrorProbe && !_tiltProbe &&
        forensicStash[0].evidence >= STASH_DEEP_MIN_EVIDENCE) {
      try {
        const deep = deepForensicTry(forensicStash[0], 2500, 97);
        if (deep) return deep;
      } catch { /* forensic escalation is best-effort */ }
    }
    delete best._evidence;
    delete best._originX;
    delete best._originY;
    delete best._scaleX;
    delete best._scaleY;
    best.timedOut = true;
    return best;
  }
  // Deep forensic decodes on the stashed candidates, strongest
  // first, while deadline headroom remains.
  if (!best?.found && isV4 && !_mirrorProbe && !_tiltProbe) {
    for (let si = 0; si < forensicStash.length; si++) {
      if (deadlineHit()) break;
      const s = forensicStash[si];
      if (s.evidence < STASH_DEEP_MIN_EVIDENCE) continue;
      try {
        const deep = deepForensicTry(s, 4000, 77 + si);
        if (deep) return deep;
      } catch { /* forensic escalation is best-effort */ }
    }
  }
  return best;
}
