/**
 * StegoMark embedder: keyed spread-spectrum cell marking with
 * texture-adaptive amplitude masking. Embed-side only — detectors
 * for shipped marks must keep reading them (see stego-code.js).
 */
import { stegoFingerprint, stegoCodeBits, robustStegoCodeBits, bchStegoCodeBits, stegoLayout, robustStegoLayout, stegoGrid, STEGO_ROW_SEGMENTS } from './stego-code.js';


export function embedStegoFingerprint(rgba, w, h, payload, {
  key = '', strength = 6, gridX, gridY, profile = 'standard', inPlace = false,
  // Codeword v2 (keyed MAC acceptance tag) is the default; legacyCode
  // reproduces pre-v1.12 CRC-tagged codewords for compatibility testing.
  legacyCode = false,
  // Layout space: 3 = SHA-256-seeded repetition code (default),
  // 2 = 128-bit cyrb128, 1 = pre-1.13 32-bit-truncated (both kept
  // for compatibility testing), 4 = v1.20 BCH(188,64) code over the
  // v3 cell layout (corrects 2e+s <= 36; needs a v1.20+ detector).
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
  const v4 = layoutVersion === 4;
  if (v4 && legacyCode) throw new Error('Archx stego: layoutVersion 4 always uses the keyed MAC payload (legacyCode is v1-v3 only)');
  const tag = legacyCode ? 'crc' : 'mac';
  const bits = v4
    ? bchStegoCodeBits(fingerprint, key)
    : robust ? robustStegoCodeBits(fingerprint, key, tag) : stegoCodeBits(fingerprint, key, tag);
  const { gx, gy } = stegoGrid(w, h, effectiveGridX, effectiveGridY);
  const cellCount = gx * gy;
  // v4 reuses the v3 layout seed space verbatim; only the codeword
  // assigned to the cells changes (see bchStegoCodeBits).
  const seedVersion = v4 || layoutVersion === 3 ? 3 : layoutVersion === 2 ? 2 : 1;
  const { order, polarity, segmentPolarity } = robust
    ? robustStegoLayout(cellCount, key, seedVersion)
    : stegoLayout(cellCount, key, seedVersion);
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
      // v4 curve (1.20): BCH headroom pays for a gentler texture cap
      // (1.2 vs 1.4), where most of the v1-v3 distortion energy sat.
      // The flat-cell floor stays at the shipped 0.4: a 0.3 floor
      // measured fine at identity but flat hosts lost every crop
      // case (resampling attenuates what little signal flat cells
      // carry). v1-v3 embeds keep the shipped curve byte-for-byte;
      // byte-for-byte.
      const cellAmp = v4
        ? Math.min(16, amp * Math.max(0.4, Math.min(1.2, 0.4 + std / 40)))
        : Math.min(16, amp * Math.max(0.4, Math.min(1.4, 0.4 + std / 36)));
      const cellW = x1 - x0;
      const cellH = y1 - y0;
      // The per-pixel delta takes exactly two values per cell
      // (+/- cellAmp: polarity, band parity, segment sign and the bit
      // are all ±1), and the band changes only at four fixed x
      // offsets. Precompute clamped-add lookup tables for both
      // deltas and the band ranges once per cell instead of a
      // divide/floor, sign product and double clamp per pixel. The
      // tables are built through the same Uint8 conversion the
      // direct assignments used, so embedded bytes are identical.
      // Clamping stays per channel: a saturated red channel must not
      // suppress the mark in green/blue, or flat synthetic/saturated
      // areas decode with a systematic one-direction bias.
      const lutPos = new Uint8Array(256);
      const lutNeg = new Uint8Array(256);
      for (let v = 0; v < 256; v++) {
        lutPos[v] = Math.max(0, Math.min(255, v + cellAmp));
        lutNeg[v] = Math.max(0, Math.min(255, v - cellAmp));
      }
      // band b covers x-x0 in [ceil(b*cellW/4), ceil((b+1)*cellW/4)):
      // the same partition the old per-pixel floor computed.
      const bandStart = [0, 0, 0, 0];
      for (let b = 1; b < columnBands; b++) bandStart[b] = Math.ceil((b * cellW) / columnBands);
      const cellSign = (bit ? 1 : -1) * pol;

      for (let y = y0; y < y1; y++) {
        const segment = Math.min(
          rowSegments - 1,
          Math.floor(((y - y0) * rowSegments) / cellH),
        );
        const segmentSign = segmentPolarity[cell * rowSegments + segment];
        const rowPositive = cellSign * segmentSign > 0; // even-band sign
        let i = (y * w + x0) * 4;
        for (let b = 0; b < columnBands; b++) {
          const xs = x0 + bandStart[b];
          const xe = x0 + (b + 1 < columnBands ? bandStart[b + 1] : cellW);
          const lut = (b % 2 === 0) === rowPositive ? lutPos : lutNeg;
          for (let x = xs; x < xe; x++, i += 4) {
            out[i] = lut[src[i]];
            out[i + 1] = lut[src[i + 1]];
            out[i + 2] = lut[src[i + 2]];
          }
        }
      }
    }
  }
  return out;
}
