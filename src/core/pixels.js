/**
 * Pixel-plane helpers for detection: luma + integral image, flips,
 * right-angle rotations, transposes, resampling, small-angle warp.
 */


export function buildLumaIntegral(src, w, h) {
  const luma = new Uint8Array(w * h);
  // Integral sums are integers bounded by 255*w*h: below 2^32 a
  // Uint32Array is EXACT (and halves the table's memory bandwidth)
  // where Float64 was pure waste; huge frames keep Float64 headroom.
  const integral = w * h <= 16_000_000
    ? new Uint32Array((w + 1) * (h + 1))
    : new Float64Array((w + 1) * (h + 1));
  // Luma and its integral are built in one pass: the row running sum
  // consumes each luma value as it is produced (same integers, same
  // accumulation order as the two-pass form — one full-frame read of
  // the luma plane saved, worth ~40% at 24 MP).
  for (let y = 0; y < h; y++) {
    let rowSum = 0;
    let i = y * w * 4;
    const lumaRow = y * w;
    const outRow = (y + 1) * (w + 1);
    const prevRow = y * (w + 1);
    for (let x = 0; x < w; x++, i += 4) {
      const v = (src[i] * 77 + src[i + 1] * 150 + src[i + 2] * 29) >> 8;
      luma[lumaRow + x] = v;
      rowSum += v;
      integral[outRow + x + 1] = integral[prevRow + x + 1] + rowSum;
    }
  }
  return { luma, integral };
}

const wordView = (u8, words) =>
  (u8.byteOffset % 4 === 0 && u8.byteLength >= words * 4)
    ? new Uint32Array(u8.buffer, u8.byteOffset, words)
    : null;

export function flipPixels(src, w, h, flipX, flipY) {
  const flipped = new Uint8Array(w * h * 4);
  // Word-level fast paths (pure permutations — byte-identical):
  // flipXY is a whole-buffer reversal; flipX is copy+reverse per row;
  // flipY is row-order copying. Unaligned sources keep the scalar loop.
  const src32 = wordView(src, w * h);
  if (src32) {
    const out32 = new Uint32Array(flipped.buffer);
    if (flipX && flipY) {
      out32.set(src32);
      out32.reverse();
      return flipped;
    }
    for (let y = 0; y < h; y++) {
      const sy = flipY ? h - 1 - y : y;
      out32.set(src32.subarray(sy * w, sy * w + w), y * w);
      if (flipX) out32.subarray(y * w, y * w + w).reverse();
    }
    return flipped;
  }
  for (let y = 0; y < h; y++) {
    const sy = flipY ? h - 1 - y : y;
    const srow = sy * w * 4;
    const drow = y * w * 4;
    for (let x = 0; x < w; x++) {
      const sx = flipX ? w - 1 - x : x;
      const si = srow + sx * 4;
      const di = drow + x * 4;
      flipped[di] = src[si]; flipped[di + 1] = src[si + 1];
      flipped[di + 2] = src[si + 2]; flipped[di + 3] = src[si + 3];
    }
  }
  return flipped;
}

// Lazily materialized mirror variants of a source buffer, cached on the
// shared planes entry: 'x' (horizontal mirror), 'y' (vertical flip),
// 'xy' (both = 180° rotation). Red-team testing showed fy-only suspects
// (a one-click editor operation) evaded detection completely when only
// the horizontal mirror was probed.
export const MIRROR_AXES = [['x', true, false], ['y', false, true], ['xy', true, true]];
export function mirroredVariant(entry, srcTop, w, h, axis, flipX, flipY) {
  const slot = axis === 'x' ? 'flipped' : axis === 'y' ? 'flippedY' : 'flippedXY';
  if (!entry[slot]) entry[slot] = flipPixels(srcTop, w, h, flipX, flipY);
  return entry[slot];
}

// 90° rotations: a sideways phone photo is among the most common real
// suspect transforms, and (like the mirror probes) needs no embed-side
// change — every already-shipped mark benefits. rotCcw restores a
// suspect that was rotated 90° clockwise (result reports rotated: 90).
export function rotatePixels90(src, w, h, clockwise) {
  const out = new Uint8Array(w * h * 4);
  const nw = h;
  const src32 = wordView(src, w * h);
  if (src32) {
    // Cache-tiled word scatter (pure permutation): 32x32 tiles keep
    // both the strided reads and the writes inside L1/L2 instead of
    // streaming the whole frame per column (~3x at 24 MP).
    const out32 = new Uint32Array(out.buffer);
    const T = 32;
    for (let ty = 0; ty < h; ty += T) {
      const yEnd = Math.min(h, ty + T);
      for (let tx = 0; tx < w; tx += T) {
        const xEnd = Math.min(w, tx + T);
        for (let y = ty; y < yEnd; y++) {
          const sRow = y * w;
          const dx = clockwise ? h - 1 - y : y;
          for (let x = tx; x < xEnd; x++) {
            const dy = clockwise ? x : w - 1 - x;
            out32[dy * nw + dx] = src32[sRow + x];
          }
        }
      }
    }
    return out;
  }
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const si = (y * w + x) * 4;
      const dx = clockwise ? h - 1 - y : y;
      const dy = clockwise ? x : w - 1 - x;
      const di = (dy * nw + dx) * 4;
      out[di] = src[si]; out[di + 1] = src[si + 1];
      out[di + 2] = src[si + 2]; out[di + 3] = src[si + 3];
    }
  }
  return out;
}
export function rotatedVariant(entry, srcTop, w, h, clockwise) {
  const slot = clockwise ? 'rotCw' : 'rotCcw';
  if (!entry[slot]) entry[slot] = rotatePixels90(srcTop, w, h, clockwise);
  return entry[slot];
}

// The last two dihedral symmetries (EXIF orientations 5 and 7):
// reflections across the main / anti diagonal. Both are involutions,
// so probing applies the same transform that produced the suspect.
// With these, all 8 rectangle symmetries are covered.
export function transposePixels(src, w, h, anti) {
  const out = new Uint8Array(w * h * 4);
  const src32 = wordView(src, w * h);
  if (src32) {
    // Cache-tiled word scatter, as in rotatePixels90.
    const out32 = new Uint32Array(out.buffer);
    const T = 32;
    for (let ty = 0; ty < h; ty += T) {
      const yEnd = Math.min(h, ty + T);
      for (let tx = 0; tx < w; tx += T) {
        const xEnd = Math.min(w, tx + T);
        for (let y = ty; y < yEnd; y++) {
          const sRow = y * w;
          for (let x = tx; x < xEnd; x++) {
            const di = anti ? (w - 1 - x) * h + (h - 1 - y) : x * h + y;
            out32[di] = src32[sRow + x];
          }
        }
      }
    }
    return out;
  }
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const si = (y * w + x) * 4;
      const di = anti
        ? ((w - 1 - x) * h + (h - 1 - y)) * 4
        : (x * h + y) * 4;
      out[di] = src[si]; out[di + 1] = src[si + 1];
      out[di + 2] = src[si + 2]; out[di + 3] = src[si + 3];
    }
  }
  return out;
}
export function transposedVariant(entry, srcTop, w, h, anti) {
  const slot = anti ? 'trAnti' : 'trMain';
  if (!entry[slot]) entry[slot] = transposePixels(srcTop, w, h, anti);
  return entry[slot];
}

// Bilinear resample / rotate for the tilt (small-angle deskew) search.
// rotateRgba rotates image CONTENT clockwise by angleRad in screen
// coordinates (matching sharp.rotate(+deg)); out-of-frame samples
// replicate edge pixels so no artificial black wedges bias the
// third-difference estimator.
export function resampleRgba(src, w, h, nw, nh) {
  const out = new Uint8Array(nw * nh * 4);
  const sx = w / nw, sy = h / nh;
  // Column sample positions do not depend on y: compute them once
  // (same expressions, same floats) instead of per pixel. Weight
  // complements are likewise hoisted per pixel; the blend arithmetic
  // and its evaluation order are untouched, so output is identical.
  const colX0 = new Int32Array(nw), colX1 = new Int32Array(nw);
  const colWx = new Float64Array(nw), colInvWx = new Float64Array(nw);
  for (let x = 0; x < nw; x++) {
    const fx = Math.min(w - 1, Math.max(0, (x + 0.5) * sx - 0.5));
    const x0 = Math.floor(fx);
    colX0[x] = x0;
    colX1[x] = Math.min(w - 1, x0 + 1);
    colWx[x] = fx - x0;
    colInvWx[x] = 1 - colWx[x];
  }
  for (let y = 0; y < nh; y++) {
    const fy = Math.min(h - 1, Math.max(0, (y + 0.5) * sy - 0.5));
    const y0 = Math.floor(fy), y1 = Math.min(h - 1, y0 + 1), wy = fy - y0;
    const invWy = 1 - wy;
    const row0 = y0 * w, row1 = y1 * w;
    let di = y * nw * 4;
    for (let x = 0; x < nw; x++, di += 4) {
      const wx = colWx[x], invWx = colInvWx[x];
      const i00 = (row0 + colX0[x]) * 4, i10 = (row0 + colX1[x]) * 4;
      const i01 = (row1 + colX0[x]) * 4, i11 = (row1 + colX1[x]) * 4;
      for (let c = 0; c < 4; c++) {
        out[di + c] = (src[i00 + c] * invWx + src[i10 + c] * wx) * invWy +
          (src[i01 + c] * invWx + src[i11 + c] * wx) * wy;
      }
    }
  }
  return out;
}
export function rotateRgba(src, w, h, angleRad) {
  // Always a FRESH buffer: callers key plane caches by buffer
  // identity (planesEntry), so reusing a scratch buffer across
  // angles served the previous angle's luma/integral (v1.19 bug).
  const out = new Uint8Array(w * h * 4);
  const cx = (w - 1) / 2, cy = (h - 1) / 2;
  const cos = Math.cos(angleRad), sin = Math.sin(angleRad);
  for (let y = 0; y < h; y++) {
    const dy = y - cy;
    // Per-row products hoisted (identical values); per-pixel terms and
    // addition order unchanged, so every sampled float is identical.
    const dySin = dy * sin, dyCos = dy * cos;
    let di = y * w * 4;
    for (let x = 0; x < w; x++, di += 4) {
      const dx = x - cx;
      // Inverse map for a clockwise content rotation (y down).
      const fx = cx + dx * cos + dySin;
      const fy = cy - dx * sin + dyCos;
      const sx = Math.min(w - 1, Math.max(0, fx));
      const sy = Math.min(h - 1, Math.max(0, fy));
      const x0 = Math.floor(sx), y0 = Math.floor(sy);
      const x1 = Math.min(w - 1, x0 + 1), y1 = Math.min(h - 1, y0 + 1);
      const wx = sx - x0, wy = sy - y0;
      const invWx = 1 - wx, invWy = 1 - wy;
      const i00 = (y0 * w + x0) * 4, i10 = (y0 * w + x1) * 4;
      const i01 = (y1 * w + x0) * 4, i11 = (y1 * w + x1) * 4;
      for (let c = 0; c < 4; c++) {
        out[di + c] = (src[i00 + c] * invWx + src[i10 + c] * wx) * invWy +
          (src[i01 + c] * invWx + src[i11 + c] * wx) * wy;
      }
    }
  }
  return out;
}
