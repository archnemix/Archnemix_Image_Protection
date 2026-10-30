/**
 * StegoMark embedder: keyed spread-spectrum cell marking with
 * texture-adaptive amplitude masking. Embed-side only — detectors
 * for shipped marks must keep reading them (see stego-code.js).
 */
import { stegoFingerprint, stegoCodeBits, robustStegoCodeBits, stegoLayout, robustStegoLayout, stegoGrid, STEGO_ROW_SEGMENTS } from './stego-code.js';


export function embedStegoFingerprint(rgba, w, h, payload, {
  key = '', strength = 6, gridX, gridY, profile = 'standard', inPlace = false,
  // Codeword v2 (keyed MAC acceptance tag) is the default; legacyCode
  // reproduces pre-v1.12 CRC-tagged codewords for compatibility testing.
  legacyCode = false,
  // Layout seed space: 2 = 128-bit (default since 1.13); 1 reproduces
  // the pre-1.13 32-bit-truncated layout for compatibility testing.
  layoutVersion = 3,
} = {}) {
  const src = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
  if (src.length < w * h * 4) throw new Error('Archx stego: pixel buffer is smaller than w×h×4');
  if (w < 64 || h < 64) throw new Error('Archx stego: image too small (minimum 64×64)');
  const robust = profile === 'robust';
  const effectiveGridX = gridX ?? (robust ? 20 : 24);
  const effectiveGridY = gridY ?? (robust ? 14 : 16);
  const rowSegments = STEGO_ROW_SEGMENTS;
  const columnBands = 4;
  const fingerprint = stegoFingerprint(payload);
  const tag = legacyCode ? 'crc' : 'mac';
  const bits = robust ? robustStegoCodeBits(fingerprint, key, tag) : stegoCodeBits(fingerprint, key, tag);
  const { gx, gy } = stegoGrid(w, h, effectiveGridX, effectiveGridY);
  const cellCount = gx * gy;
  const { order, polarity, segmentPolarity } = robust
    ? robustStegoLayout(cellCount, key, layoutVersion === 1 ? 1 : layoutVersion === 2 ? 2 : 3)
    : stegoLayout(cellCount, key, layoutVersion === 1 ? 1 : layoutVersion === 2 ? 2 : 3);
  // The server pipeline owns a disposable Sharp buffer, so it may opt out of
  // this full-frame copy. Cell statistics are computed before that cell is
  // written, which makes the in-place path byte-for-byte equivalent.
  const out = inPlace ? src : new Uint8Array(src);
  const baseAmp = Math.max(1, Math.min(16, Number(strength) || 6));
  const amp = robust ? Math.min(16, baseAmp * 1.35) : baseAmp;

  for (let cy = 0; cy < gy; cy++) {
    const y0 = Math.floor((cy * h) / gy);
    const y1 = Math.floor(((cy + 1) * h) / gy);
    for (let cx = 0; cx < gx; cx++) {
      const x0 = Math.floor((cx * w) / gx);
      const x1 = Math.floor(((cx + 1) * w) / gx);
      if (x1 - x0 < 4 || y1 - y0 < 2) continue;
      const cell = cy * gx + cx;
      const bit = bits[order[cell] % bits.length];
      const pol = polarity[cell];

      // Perceptual masking: textured cells can hide a stronger mark than
      // flat sky/skin. Sample local luminance spread to scale amplitude.
      let sum = 0, sum2 = 0, n = 0;
      for (let y = y0; y < y1; y += 2) {
        let i = (y * w + x0) * 4;
        for (let x = x0; x < x1; x += 2, i += 8) {
          const lum = (src[i] * 77 + src[i + 1] * 150 + src[i + 2] * 29) >> 8;
          sum += lum; sum2 += lum * lum; n++;
        }
      }
      const mean = n ? sum / n : 0;
      const std = n ? Math.sqrt(Math.max(0, sum2 / n - mean * mean)) : 0;
      // Texture-boosted masking (1.17): the previous curve only ever
      // REDUCED amplitude below nominal (cap 1.0), so the cells where
      // image content fights the estimator hardest — textured/edge
      // cells — got the same or less energy than flat sky. Flat cells
      // stay gentle (they need little help and show banding first);
      // textured cells may now exceed nominal amplitude, where the
      // energy is perceptually hidden. Sign pattern is unchanged, so
      // older detectors still read marks embedded with the new curve.
      const cellAmp = Math.min(16, amp * Math.max(0.4, Math.min(1.4, 0.4 + std / 36)));
      const cellW = x1 - x0;
      const cellH = y1 - y0;

      for (let y = y0; y < y1; y++) {
        const segment = Math.min(
          rowSegments - 1,
          Math.floor(((y - y0) * rowSegments) / cellH),
        );
        const segmentSign = segmentPolarity[cell * rowSegments + segment];
        let i = (y * w + x0) * 4;
        for (let x = x0; x < x1; x++, i += 4) {
          const band = Math.min(columnBands - 1, Math.floor(((x - x0) * columnBands) / cellW));
          const pattern = (band % 2 === 0 ? 1 : -1) * (bit ? 1 : -1) * pol * segmentSign;
          const delta = cellAmp * pattern;
          // Clamp per channel: a saturated red channel must not suppress the
          // mark in green/blue, or flat synthetic/saturated areas decode with
          // a systematic one-direction bias.
          out[i] = Math.max(0, Math.min(255, src[i] + delta));
          out[i + 1] = Math.max(0, Math.min(255, src[i + 1] + delta));
          out[i + 2] = Math.max(0, Math.min(255, src[i + 2] + delta));
        }
      }
    }
  }
  return out;
}
