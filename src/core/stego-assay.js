/**
 * Embed pre-flight assay: runs the real embedder (+ optionally the
 * detector) to report measured PSNR, content class, and the minimum
 * self-verifying strength for a given image.
 */
import { stegoGrid } from './stego-code.js';
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
