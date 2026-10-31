/**
 * StegoMark assays (measurement aids, not verdicts): the embed
 * pre-flight assay (real embed + optional self-detect: PSNR, content
 * class, minimum self-verifying strength) and the collusion assay
 * (soft per-cell ranking of candidate recipients against a suspect
 * copy). Detection/attribution itself lives in stego-detect.js.
 */
import { STEGO_ROW_SEGMENTS, bchStegoCodeBits, robustStegoCodeBits, robustStegoLayout, stegoCodeBits, stegoFingerprint, stegoGrid, stegoLayout } from './stego-code.js';
import { buildLumaIntegral } from './pixels.js';
import { embedStegoFingerprint } from './stego-embed.js';
import { detectStegoFingerprint } from './stego-detect.js';

/**
 * Pre-flight assay for a planned embed (v1.19): measures the ACTUAL
 * distortion the current embedder will cause (it runs the real
 * embedder on a copy — no model drift), classifies the content, and
 * optionally self-verifies that the detector recovers the mark at
 * the chosen strength, walking up the strength ladder until it
 * does. Operators protecting slides/UI/documents should run this
 * per catalog: near-binary periodic graphics are a documented weak
 * class (see RESEARCH 2.26/2.27), and "imperceptible" is a number
 * (PSNR at YOUR settings on YOUR images), not an adjective.
 */
export function assayStegoEmbed(rgba, w, h, {
  key = '', profile = 'robust', strength = 6, gridX, gridY, verify = false, layoutVersion = 3,
} = {}) {
  const src = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  const robust = profile === 'robust';
  const effectiveGridX = gridX ?? (robust ? 20 : 24);
  const effectiveGridY = gridY ?? (robust ? 14 : 16);
  const { gx, gy } = stegoGrid(w, h, effectiveGridX, effectiveGridY);
  const { luma, integral } = buildLumaIntegral(src, w, h);
  const rectSum = (x0, y0, x1, y1) => integral[y1 * (w + 1) + x1] - integral[y0 * (w + 1) + x1]
    - integral[y1 * (w + 1) + x0] + integral[y0 * (w + 1) + x0];
  let smoothCells = 0;
  let binaryCells = 0;
  let cells = 0;
  for (let cy = 0; cy < gy; cy++) {
    const y0 = Math.floor((cy * h) / gy), y1 = Math.floor(((cy + 1) * h) / gy);
    for (let cx = 0; cx < gx; cx++) {
      const x0 = Math.floor((cx * w) / gx), x1 = Math.floor(((cx + 1) * w) / gx);
      const n = (x1 - x0) * (y1 - y0);
      if (n < 16) continue;
      cells++;
      const mean = rectSum(x0, y0, x1, y1) / n;
      let extreme = 0;
      let sq = 0;
      const step = Math.max(1, Math.floor(n / 256));
      let sampled = 0;
      for (let y = y0; y < y1; y += 2) {
        for (let x = x0; x < x1; x += 2 * step) {
          const v = luma[y * w + x];
          sq += (v - mean) * (v - mean);
          if (v < 64 || v > 191) extreme++;
          sampled++;
        }
      }
      const std = sampled ? Math.sqrt(sq / sampled) : 0;
      if (std < 8) smoothCells++;
      if (sampled && extreme / sampled > 0.85 && std > 40) binaryCells++;
    }
  }
  const smoothFraction = cells ? smoothCells / cells : 0;
  const binaryFraction = cells ? binaryCells / cells : 0;
  const measure = (atStrength) => {
    const marked = embedStegoFingerprint(src, w, h, 'archx-assay', {
      key, profile, strength: atStrength, gridX, gridY, layoutVersion,
    });
    let mse = 0, maxDelta = 0;
    for (let i = 0; i < src.length; i += 4) {
      for (let c = 0; c < 3; c++) {
        const d = marked[i + c] - src[i + c];
        mse += d * d;
        if (Math.abs(d) > maxDelta) maxDelta = Math.abs(d);
      }
    }
    mse /= (src.length / 4) * 3;
    const psnr = mse === 0 ? Infinity : Math.round(10 * Math.log10((255 * 255) / mse) * 10) / 10;
    return { marked, psnr, maxDelta };
  };
  const base = measure(strength);
  const result = {
    profile, strength, layoutVersion,
    grid: { x: gx, y: gy },
    psnr: base.psnr,
    maxChannelDelta: base.maxDelta,
    smoothFraction: Math.round(smoothFraction * 1000) / 1000,
    binaryFraction: Math.round(binaryFraction * 1000) / 1000,
    contentClass: binaryFraction > 0.35 ? 'binary-graphic'
      : smoothFraction > 0.7 ? 'flat-minimal' : 'photo-textured',
    verifiedAtStrength: null,
    recommendedStrength: strength,
    warnings: [],
  };
  const codeBits = layoutVersion === 4 ? 188 : robust ? 96 : 64;
  if (gx * gy < codeBits) {
    result.warnings.push(`grid has only ${gx * gy} cells for a ${codeBits}-bit codeword: some bits get no cell at this size — use a larger delivery size`);
  }
  if (result.contentClass === 'binary-graphic') {
    result.warnings.push('near-binary high-contrast content (UI/text/periodic graphics) is StegoMark\'s documented weak class; expect poor recovery without much higher strength');
  }
  if (result.psnr < 32) {
    result.warnings.push(`predicted PSNR ${result.psnr} dB at strength ${strength}: macro-cell shading may be visible on smooth gradients — judge on your own catalog, not on the word "invisible"`);
  }
  if (verify) {
    for (const candidate of [strength, strength + 2, strength + 4, 16]) {
      if (candidate > 16) break;
      const trial = candidate === strength ? base : measure(candidate);
      const hit = detectStegoFingerprint(trial.marked, w, h, { key, profile, gridX, gridY, layoutVersion });
      if (hit.found) {
        result.verifiedAtStrength = candidate;
        result.recommendedStrength = candidate;
        if (candidate !== strength) result.psnr = trial.psnr;
        break;
      }
    }
    if (result.verifiedAtStrength === null) {
      result.warnings.push('detector did NOT recover a fresh mark even at maximum strength: this content class is outside the embedder envelope — rely on visible marks/metadata, not StegoMark');
    }
  }
  return Object.freeze(result);
}

/**
 * Collusion assay (investigative ranking aid, NOT a Tardos code):
 * when k recipients average their differently-marked copies, each
 * participant's per-cell pattern survives at ~1/k amplitude while
 * bit-level decoding fails. This scores candidate payloads against
 * the suspect's soft per-cell readings: E[reading * expectedSign]
 * is ~amplitude/k for participants and ~0 for everyone else, so the
 * z-scored ranking surfaces likely colluders for manual review. It
 * ranks suspicion; it never proves participation on its own.
 *
 * candidates: [{ id, payload, key? }] — key defaults to options.key
 * (pass per-candidate keys when marks were embedded viewer-scoped).
 * Run detectStegoFingerprint first on single-recipient leaks; pass
 * its result.geometry here so the assay reads at the registered
 * grid when the suspect was cropped/rescaled.
 */
export function assayStegoCollusion(rgba, w, h, candidates, {
  key = '', profile = 'robust', gridX, gridY, layoutVersion = 3, geometry = null,
} = {}) {
  const src = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  if (!Number.isSafeInteger(w * h * 4) || src.length < w * h * 4) {
    throw new Error('Archx stego assay: pixel buffer is smaller than w×h×4');
  }
  if (w < 64 || h < 64) throw new Error('Archx stego assay: image too small (minimum 64×64)');
  if (!Array.isArray(candidates) || candidates.length === 0 || candidates.length > 4096) {
    throw new Error('Archx stego assay: candidates must be an array of 1..4096 entries');
  }
  const robust = profile === 'robust';
  const v4 = layoutVersion === 4;
  const layout = layoutVersion === 1 ? 1 : layoutVersion === 2 ? 2 : 3; // v4 reuses v3 seeds
  const rowSegments = STEGO_ROW_SEGMENTS;
  const columnBands = 4;
  const effectiveGridX = gridX ?? (robust ? 20 : 24);
  const effectiveGridY = gridY ?? (robust ? 14 : 16);
  const { gx, gy } = stegoGrid(w, h, effectiveGridX, effectiveGridY);
  const cellCount = gx * gy;
  const cw = w / gx, ch = h / gy;
  const scaleX = geometry?.scaleX > 0 ? geometry.scaleX : 1;
  const scaleY = geometry?.scaleY > 0 ? geometry.scaleY : 1;
  const originX = geometry?.originX ?? 0;
  const originY = geometry?.originY ?? 0;
  const { integral } = buildLumaIntegral(src, w, h);
  const rectSum = (rx0, ry0, rx1, ry1) =>
    integral[ry1 * (w + 1) + rx1] - integral[ry0 * (w + 1) + rx1] -
    integral[ry1 * (w + 1) + rx0] + integral[ry0 * (w + 1) + rx0];

  // Soft per-cell readings, grouped by effective key (the polarity
  // correction that makes "positive means bit 1" is key-dependent).
  // Estimator mirrors detect's evaluate(): keep the two in sync.
  const readingsByKey = new Map();
  const readCells = (readKey) => {
    const { order, polarity, segmentPolarity } = robust
      ? robustStegoLayout(cellCount, readKey, layout)
      : stegoLayout(cellCount, readKey, layout);
    const readings = new Float64Array(cellCount);
    readings.fill(NaN);
    const cellW0 = cw * scaleX, cellH0 = ch * scaleY;
    for (let cy = 0; cy < gy; cy++) {
      const rawY0 = originY + cy * cellH0;
      const y0 = Math.max(0, Math.round(rawY0));
      const y1 = Math.min(h, Math.round(rawY0 + cellH0));
      if (y1 - y0 < 2 || (y1 - y0) / cellH0 < 0.45) continue;
      for (let cx = 0; cx < gx; cx++) {
        const rawX0 = originX + cx * cellW0;
        const x0 = Math.max(0, Math.round(rawX0));
        const x1 = Math.min(w, Math.round(rawX0 + cellW0));
        if (x1 - x0 < 4 || (x1 - x0) / cellW0 < 0.45) continue;
        const cellIndex = cy * gx + cx;
        const responses = [];
        let scoreSum = 0, weightSum = 0, validSegments = 0;
        for (let segment = 0; segment < rowSegments; segment++) {
          const ry0 = Math.max(y0, Math.round(rawY0 + (segment * cellH0) / rowSegments));
          const ry1 = Math.min(y1, Math.round(rawY0 + ((segment + 1) * cellH0) / rowSegments));
          if (ry1 <= ry0) continue;
          const means = [];
          let weight = Infinity, complete = true;
          for (let band = 0; band < columnBands; band++) {
            const rx0 = Math.max(x0, Math.round(rawX0 + (band * cellW0) / columnBands));
            const rx1 = Math.min(x1, Math.round(rawX0 + ((band + 1) * cellW0) / columnBands));
            if (rx1 <= rx0) { complete = false; break; }
            means[band] = rectSum(rx0, ry0, rx1, ry1) / ((rx1 - rx0) * (ry1 - ry0));
            weight = Math.min(weight, (rx1 - rx0) * (ry1 - ry0));
          }
          if (!complete) continue;
          validSegments++;
          const response = -(-means[0] + 3 * means[1] - 3 * means[2] + means[3]) / 8;
          const signed = response * polarity[cellIndex]
            * segmentPolarity[cellIndex * rowSegments + segment];
          responses.push(signed);
          scoreSum += signed * weight;
          weightSum += weight;
        }
        if (!weightSum || validSegments < 2) continue;
        if (robust && responses.length >= 3) {
          const sorted = [...responses].sort((a, b) => a - b);
          readings[cellIndex] = sorted[Math.floor(sorted.length / 2)];
        } else {
          readings[cellIndex] = scoreSum / weightSum;
        }
      }
    }
    return { readings, order };
  };

  // Score per CODEWORD BIT, not per cell: cells repeat each bit
  // ~cellCount/codeLength times, so a per-cell z would overstate
  // significance ~sqrt(repeats). Bits identical across every
  // candidate in a key group (the constant sync tail) carry no
  // ranking information and are excluded.
  const prepared = candidates.map((candidate) => {
    const candKey = candidate?.key ?? key;
    if (!readingsByKey.has(candKey)) readingsByKey.set(candKey, readCells(candKey));
    const fingerprint = stegoFingerprint(candidate?.payload ?? '');
    const bits = v4
      ? bchStegoCodeBits(fingerprint, candKey)
      : robust
      ? robustStegoCodeBits(fingerprint, candKey, 'mac')
      : stegoCodeBits(fingerprint, candKey, 'mac');
    return { candidate, candKey, fingerprint, bits };
  });
  const constantBitsByKey = new Map();
  for (const p of prepared) {
    if (!constantBitsByKey.has(p.candKey)) {
      const group = prepared.filter((q) => q.candKey === p.candKey);
      const constants = new Uint8Array(p.bits.length);
      if (group.length > 1) {
        for (let b = 0; b < constants.length; b++) {
          constants[b] = group.every((q) => q.bits[b] === group[0].bits[b]) ? 1 : 0;
        }
      }
      constantBitsByKey.set(p.candKey, constants);
    }
  }
  const results = prepared.map(({ candidate, candKey, fingerprint, bits }) => {
    const { readings, order } = readingsByKey.get(candKey);
    const constants = constantBitsByKey.get(candKey);
    const bitSum = new Float64Array(bits.length);
    const bitCount = new Uint16Array(bits.length);
    let cells = 0, agree = 0;
    for (let cell = 0; cell < cellCount; cell++) {
      const reading = readings[cell];
      if (!Number.isFinite(reading)) continue;
      const bitIndex = order[cell] % bits.length;
      bitSum[bitIndex] += reading;
      bitCount[bitIndex]++;
      if ((reading >= 0) === (bits[bitIndex] === 1)) agree++;
      cells++;
    }
    let usedBits = 0, signedSum = 0, absSum = 0;
    for (let b = 0; b < bits.length; b++) {
      if (constants[b] || bitCount[b] === 0) continue;
      const soft = bitSum[b] / bitCount[b];
      signedSum += soft * (bits[b] ? 1 : -1);
      absSum += soft * soft;
      usedBits++;
    }
    const score = usedBits ? signedSum / usedBits : 0;
    const sigma = usedBits ? Math.sqrt(absSum / usedBits) : 0;
    const zScore = sigma > 0 ? (score * Math.sqrt(usedBits)) / sigma : 0;
    return {
      id: candidate?.id ?? null,
      fingerprint,
      score: Math.round(score * 1000) / 1000,
      zScore: Math.round(zScore * 100) / 100,
      cellAgreement: cells ? Math.round((agree / cells) * 1000) / 1000 : 0,
      cells,
      bits: usedBits,
    };
  });
  results.sort((a, b) => b.zScore - a.zScore);
  return {
    results,
    cells: results[0]?.cells ?? 0,
    geometry: { scaleX, scaleY, originX, originY },
    profile: robust ? 'robust' : 'standard',
  };
}
