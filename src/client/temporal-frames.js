/** Build the CPU-backed temporal presentation frames from clean pixels. */
import { getNativeContext, makeCanvas, nativeDrawImage, nativeGetImageData, nativePutImageData } from './native.js';
import { setSmoothing } from './draw.js';

export function buildTemporalFrames(frame, cfg, document) {
  const w = frame.width, h = frame.height;
  const fctx = getNativeContext(frame, '2d');
  let src;
  try { src = nativeGetImageData(fctx, 0, 0, w, h); } catch { return null; }

  const interlace = cfg.interlace;
  const phases = Math.max(2, Math.min(4, cfg.phases || 2));
  const needNoise = !!cfg.noise || interlace?.fill === 'noise';
  const noiseBlock = Math.max(1, cfg.block || 1);
  const nbw = Math.ceil(w / noiseBlock), nbh = Math.ceil(h / noiseBlock);
  const offsets = needNoise ? new Float32Array(nbw * nbh * 3) : null;
  const amp = (cfg.noise ? cfg.strength : (interlace?.noiseStrength || 0)) * 255;
  if (offsets) {
    for (let by = 0; by < nbh; by++) {
      for (let bx = 0; bx < nbw; bx++) {
        const oi = (by * nbw + bx) * 3;
        if (cfg.pattern === 'bands' && bx > 0) {
          offsets[oi] = offsets[oi - 3];
          offsets[oi + 1] = offsets[oi - 2];
          offsets[oi + 2] = offsets[oi - 1];
          continue;
        }
        const parity = cfg.pattern === 'checker' ? (((bx + by) & 1) ? 1 : -1) : 1;
        if (cfg.chroma) {
          // Opponent-colour modulation: human chroma sensitivity is lower
          // than luma sensitivity, while Bayer sensors sample RGB unevenly.
          const scalar = cfg.pattern === 'checker'
            ? (0.35 + Math.random() * 0.65) * amp * parity
            : (Math.random() * 2 - 1) * amp;
          offsets[oi] = scalar;
          offsets[oi + 1] = -0.62 * scalar;
          offsets[oi + 2] = 0.78 * scalar;
        } else if (cfg.pattern === 'checker') {
          offsets[oi] = (0.35 + Math.random() * 0.65) * amp * parity;
          offsets[oi + 1] = (0.35 + Math.random() * 0.65) * amp * parity;
          offsets[oi + 2] = (0.35 + Math.random() * 0.65) * amp * parity;
        } else {
          offsets[oi] = (Math.random() * 2 - 1) * amp;
          offsets[oi + 1] = (Math.random() * 2 - 1) * amp;
          offsets[oi + 2] = (Math.random() * 2 - 1) * amp;
        }
      }
    }
  }

  const cell = Math.max(1, interlace?.cellSize || noiseBlock);
  const bw = Math.ceil(w / cell), bh = Math.ceil(h / cell);
  let assignments = null;
  if (interlace) {
    assignments = new Uint8Array(bw * bh);
    for (let by = 0; by < bh; by++) {
      for (let bx = 0; bx < bw; bx++) {
        let phase = 0;
        if (interlace.layout === 'strips') {
          phase = (interlace.axis === 'columns' ? bx : by) % phases;
        } else if (interlace.layout === 'blocks') {
          phase = (Math.random() * phases) | 0;
        } else if (interlace.layout === 'pixels') {
          phase = (bx + (phases === 2 ? by : 2 * by)) % phases;
        } else {
          phase = (bx + by) % phases;
        }
        assignments[by * bw + bx] = phase;
      }
    }
  }

  let lowData = null;
  let lowW = 0;
  let lowH = 0;
  let lowBlock = 1;
  if (interlace?.fill === 'lowres') {
    lowBlock = Math.max(1, interlace.fillBlock || 12);
    lowW = Math.max(1, Math.ceil(w / lowBlock));
    lowH = Math.max(1, Math.ceil(h / lowBlock));
    try {
      const low = makeCanvas(document);
      low.width = lowW; low.height = lowH;
      const lowCtx = getNativeContext(low, '2d');
      setSmoothing(lowCtx, true);
      nativeDrawImage(lowCtx, frame, 0, 0, lowW, lowH);
      lowData = nativeGetImageData(lowCtx, 0, 0, lowW, lowH).data;
      low.width = 0; low.height = 0;
    } catch {
      lowData = null;
    }
  }

  // Cycle-zero-mean block bias (noise fill only): with static frames
  // the per-pixel cycle multiset is {c, c+d1, c+d2} and the temporal
  // MEDIAN is exactly c whenever the hidden deltas straddle it. A
  // fixed per-block offset b applied +b*(P-1)/P on the active phase
  // and -b/P on hidden phases keeps the cycle mean exact (no visible
  // brightness flicker) while moving every cycle statistic off c —
  // the same construction as the shader path and the duty bias.
  const biasBlock = 24;
  const bbw = Math.ceil(w / biasBlock), bbh = Math.ceil(h / biasBlock);
  const biasAmp = (interlace?.noiseStrength || 0) * 255 * 0.55;
  const biases = (interlace && interlace.fill === 'noise' && biasAmp > 0)
    ? new Float32Array(bbw * bbh) : null;
  if (biases) for (let i = 0; i < biases.length; i++) biases[i] = (Math.random() * 2 - 1) * biasAmp;
  const colBias = biases ? new Int32Array(w) : null;
  if (colBias) for (let x = 0; x < w; x++) colBias[x] = Math.min(bbw - 1, Math.floor(x / biasBlock));
  // Column lookup tables replace two Math.floor divisions per pixel
  // in the frame builder (~6M divisions per 4-phase 1600px build).
  const colNoiseOi = offsets ? new Int32Array(w) : null;
  if (colNoiseOi) for (let x = 0; x < w; x++) colNoiseOi[x] = Math.min(nbw - 1, Math.floor(x / noiseBlock)) * 3;
  // One scratch ImageData for all phases (putImageData copies sync).
  const scratch = fctx.createImageData(w, h);

  const mk = (phase) => {
    // Per-phase amplitude diversity: with identical |delta| every phase,
    // a short capture's per-pixel multiset is {c+d, c-d, ...} and its
    // median/mean lands exactly on c. Varied amplitudes make short-window
    // statistics land off-target; the eye still integrates the cycle.
    const sign = (phase % 2 ? -1 : 1) * [1, 0.6, 1.3, 0.85][phase % 4];
    const c = makeCanvas(document);
    c.width = w; c.height = h;
    const cctx = getNativeContext(c, '2d');
    const out = scratch;
    const s = src.data, d = out.data; // Uint8ClampedArray clamps assignments

    if (!interlace) {
      for (let by = 0; by < nbh; by++) {
        const y0 = by * noiseBlock;
        const y1 = Math.min(h, y0 + noiseBlock);
        for (let y = y0; y < y1; y++) {
          let p = y * w * 4;
          for (let bx = 0; bx < nbw; bx++) {
            const oi = (by * nbw + bx) * 3;
            const x1 = Math.min(w, (bx + 1) * noiseBlock);
            for (let x = bx * noiseBlock; x < x1; x++, p += 4) {
              d[p] = s[p] + sign * offsets[oi];
              d[p + 1] = s[p + 1] + sign * offsets[oi + 1];
              d[p + 2] = s[p + 2] + sign * offsets[oi + 2];
              d[p + 3] = 255;
            }
          }
        }
      }
      nativePutImageData(cctx, out, 0, 0);
      return c;
    }

    const gain = interlace.activeGain || 1;
    const fillMix = interlace.fillStrength;
    for (let by = 0; by < bh; by++) {
      const y0 = by * cell;
      const y1 = Math.min(h, y0 + cell);
      for (let bx = 0; bx < bw; bx++) {
        const active = assignments[by * bw + bx] === phase;
        const x0 = bx * cell;
        const x1 = Math.min(w, x0 + cell);
        for (let y = y0; y < y1; y++) {
          let p = (y * w + x0) * 4;
          const lowY = lowData ? Math.min(lowH - 1, Math.floor(y / lowBlock)) : 0;
          const rowNoiseOi = offsets ? Math.min(nbh - 1, Math.floor(y / noiseBlock)) * nbw * 3 : 0;
          const rowBiasOff = biases ? Math.min(bbh - 1, Math.floor(y / biasBlock)) * bbw : 0;
          for (let x = x0; x < x1; x++, p += 4) {
            const sr = s[p], sg = s[p + 1], sb = s[p + 2];
            const bv = biases ? biases[rowBiasOff + colBias[x]] : 0;
            let r, g, b;
            if (active) {
              const ab = bv * fillMix * (phases - 1) / phases;
              r = sr * gain + ab; g = sg * gain + ab; b = sb * gain + ab;
            } else {
              let fr = sr, fg = sg, fb = sb;
              if (interlace.fill === 'lowres' && lowData) {
                const lowX = Math.min(lowW - 1, Math.floor(x / lowBlock));
                const li = (lowY * lowW + lowX) * 4;
                fr = lowData[li]; fg = lowData[li + 1]; fb = lowData[li + 2];
              } else if (interlace.fill === 'dim') {
                fr = sr * interlace.hiddenScale;
                fg = sg * interlace.hiddenScale;
                fb = sb * interlace.hiddenScale;
              } else if (interlace.fill === 'black') {
                fr = 0; fg = 0; fb = 0;
              } else if (interlace.fill === 'noise' && offsets) {
                const oi = rowNoiseOi + colNoiseOi[x];
                const hb = bv / phases;
                fr = sr - hb + sign * offsets[oi];
                fg = sg - hb + sign * offsets[oi + 1];
                fb = sb - hb + sign * offsets[oi + 2];
              }
              r = sr + (fr - sr) * fillMix;
              g = sg + (fg - sg) * fillMix;
              b = sb + (fb - sb) * fillMix;
            }
            if (cfg.noise && offsets) {
              const oi = rowNoiseOi + colNoiseOi[x];
              r += sign * offsets[oi];
              g += sign * offsets[oi + 1];
              b += sign * offsets[oi + 2];
            }
            d[p] = r;
            d[p + 1] = g;
            d[p + 2] = b;
            d[p + 3] = 255;
          }
        }
      }
    }
    nativePutImageData(cctx, out, 0, 0);
    return c;
  };

  return Array.from({ length: phases }, (_, phase) => mk(phase));
}
