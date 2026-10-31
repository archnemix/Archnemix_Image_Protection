/**
 * Scramble plans: key-seeded tile permutation + mirror flags, and
 * application of a plan to pixel buffers (with keyed padding).
 * The plan is obfuscation; AES-256-GCM in crypto.js is the secrecy.
 */
import { asBytes } from './bytes.js';
import { hashSeed, mulberry32, cyrb128, sfc32 } from './crypto.js';

export const DEFAULT_GRID = 8;

/**
 * Build the deterministic scramble plan for a key.
 * @param {number} grid tiles per side (2..32)
 * @param {string} key  secret seed material
 * @param {number} [version=1] plan derivation version. **1** is the legacy
 *   32-bit-seed plan (kept for payload compatibility). **2** derives the
 *   permutation from a 128-bit seed (cyrb128 + sfc32), so recovering the
 *   permutation by seed brute force is infeasible; the tile permutation is
 *   still obfuscation, not encryption — use the AES-GCM layer for secrecy.
 * @returns {{grid:number,count:number,version:number,order:number[],inverse:number[],flips:{fx:boolean,fy:boolean}[]}}
 *   order[scrambledPos]   = originalPos
 *   inverse[originalPos]  = scrambledPos
 */
export function buildScramblePlan(grid = DEFAULT_GRID, key = '', version = 2) {
  // Default is the 128-bit-seeded plan (v2) since 1.17, matching the
  // server/builder/CLI defaults flipped in 1.15: no public entry point
  // emits the brute-forceable 32-bit-seed permutation unless a caller
  // explicitly passes version 1 for legacy payloads.
  if (version !== 1 && version !== 2) throw new TypeError('Archx: scramble plan version must be 1 or 2');
  const g = Math.max(2, Math.min(32, grid | 0));
  const count = g * g;
  let rand;
  if (version === 2) {
    rand = sfc32(...cyrb128(String(key) + '::archx-grid2-' + g));
    for (let i = 0; i < 8; i++) rand(); // diffuse the state before shuffling
  } else {
    rand = mulberry32(hashSeed(String(key) + '::archx-grid-' + g));
  }
  const order = Array.from({ length: count }, (_, i) => i);
  for (let i = count - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }
  const flips = Array.from({ length: count }, () => ({
    fx: rand() < 0.5,
    fy: rand() < 0.5,
  }));
  const inverse = new Array(count);
  order.forEach((orig, scrambledPos) => { inverse[orig] = scrambledPos; });
  return { grid: g, count, version, order, inverse, flips };
}

/** Pixel rect of tile `index` in a padded image of tile size tw×th. */
export function tileRect(index, grid, tw, th) {
  return { x: (index % grid) * tw, y: Math.floor(index / grid) * th, w: tw, h: th };
}

/** Padded dimensions so both sides divide exactly by `grid`. */
export function paddedSize(w, h, grid) {
  if (!Number.isInteger(w) || !Number.isInteger(h) || w < 1 || h < 1 ||
      !Number.isInteger(grid) || grid < 2 || grid > 32) {
    throw new RangeError('Archx: invalid image/grid dimensions');
  }
  const tw = Math.ceil(w / grid);
  const th = Math.ceil(h / grid);
  return { tw, th, pw: tw * grid, ph: th * grid };
}

export function scramblePixels(rgba, pw, ph, plan, direction = 'scramble') {
  if (direction !== 'scramble' && direction !== 'unscramble') {
    throw new TypeError('Archx: scramble direction is invalid');
  }
  const grid = plan?.grid;
  const count = plan?.count;
  if (!Number.isSafeInteger(pw) || !Number.isSafeInteger(ph) || pw < 1 || ph < 1 ||
      !Number.isInteger(grid) || grid < 2 || grid > 32 || count !== grid * grid ||
      pw % grid !== 0 || ph % grid !== 0 || !Array.isArray(plan.order) ||
      !Array.isArray(plan.inverse) || !Array.isArray(plan.flips) ||
      plan.order.length !== count || plan.inverse.length !== count || plan.flips.length !== count) {
    throw new RangeError('Archx: invalid scramble geometry');
  }
  const tw = pw / grid;
  const th = ph / grid;
  const src = asBytes(rgba);
  const expected = pw * ph * 4;
  if (!Number.isSafeInteger(expected) || src.length < expected) {
    throw new RangeError('Archx: RGBA buffer is smaller than the padded image');
  }
  const out = new Uint8Array(expected);
  const useWords = src.byteOffset % 4 === 0 && src.byteLength % 4 === 0;
  const src32 = useWords ? new Uint32Array(src.buffer, src.byteOffset, src.byteLength / 4) : null;
  const out32 = useWords ? new Uint32Array(out.buffer) : null;
  for (let dest = 0; dest < count; dest++) {
    // scramble: dest is scrambled pos, source = order[dest]
    // unscramble: dest is original pos, source = inverse[dest]
    const source = direction === 'scramble' ? plan.order[dest] : plan.inverse[dest];
    if (!Number.isInteger(source) || source < 0 || source >= count) {
      throw new RangeError('Archx: invalid scramble plan');
    }
    const flipPos = direction === 'scramble' ? dest : source;
    const flip = plan.flips[flipPos];
    if (!flip || typeof flip !== 'object') throw new RangeError('Archx: invalid scramble plan');
    const { fx, fy } = flip;
    const sx = (source % grid) * tw;
    const sy = Math.floor(source / grid) * th;
    const dx = (dest % grid) * tw;
    const dy = Math.floor(dest / grid) * th;
    for (let y = 0; y < th; y++) {
      const yy = fy ? th - 1 - y : y;
      const srcRow = (sy + yy) * pw + sx;
      const dstRow = (dy + y) * pw + dx;
      if (useWords && !fx) {
        out32.set(src32.subarray(srcRow, srcRow + tw), dstRow);
      } else if (useWords) {
        // Mirror rows: copy then reverse natively (two engine-level
        // passes beat one scalar JS pass; byte-identical result).
        out32.set(src32.subarray(srcRow, srcRow + tw), dstRow);
        out32.subarray(dstRow, dstRow + tw).reverse();
      } else {
        for (let x = 0; x < tw; x++) {
          const xx = fx ? tw - 1 - x : x;
          const si = (srcRow + xx) * 4;
          const di = (dstRow + x) * 4;
          out[di] = src[si]; out[di + 1] = src[si + 1];
          out[di + 2] = src[si + 2]; out[di + 3] = src[si + 3];
        }
      }
    }
  }
  return out;
}

/**
 * Fused pad + scramble: read a raw RGBA buffer of w×h (NOT pre-padded) and
 * write the scrambled pw×ph result, treating out-of-bounds source pixels as
 * opaque black (the same padding `padRaw` + `scramblePixels` produced).
 * One output allocation and one pass replace the pad copy, the scramble
 * copy, and the caller's Buffer.from copy. `out`, when given, must hold at
 * least pw*ph*4 bytes and is fully overwritten; the written bytes are
 * identical to `scramblePixels(pad(rgba), pw, ph, plan, 'scramble')`.
 * @param {Uint8Array|Buffer} rgba w*h*4 bytes (unpadded)
 * @param {Uint8Array|Buffer} [out] optional destination buffer
 * @returns {Uint8Array|Buffer} the destination buffer
 */
export function scramblePixelsPadded(rgba, w, h, plan, out = null) {
  const grid = plan?.grid;
  const count = plan?.count;
  if (!Number.isSafeInteger(w) || !Number.isSafeInteger(h) || w < 1 || h < 1 ||
      !Number.isInteger(grid) || grid < 2 || grid > 32 || count !== grid * grid ||
      !Array.isArray(plan.order) || !Array.isArray(plan.flips) ||
      plan.order.length !== count || plan.flips.length !== count) {
    throw new RangeError('Archx: invalid scramble geometry');
  }
  const tw = Math.ceil(w / grid);
  const th = Math.ceil(h / grid);
  const pw = tw * grid;
  const ph = th * grid;
  const src = asBytes(rgba);
  if (!Number.isSafeInteger(w * h * 4) || src.length < w * h * 4) {
    throw new RangeError('Archx: RGBA buffer is smaller than the image');
  }
  const expected = pw * ph * 4;
  const target = out ? asBytes(out) : new Uint8Array(expected);
  if (!Number.isSafeInteger(expected) || target.length < expected) {
    throw new RangeError('Archx: scramble output buffer is too small');
  }
  const useWords = src.byteOffset % 4 === 0 && src.byteLength % 4 === 0 &&
    target.byteOffset % 4 === 0 && target.byteLength % 4 === 0;
  const src32 = useWords ? new Uint32Array(src.buffer, src.byteOffset, src.byteLength / 4) : null;
  const out32 = useWords ? new Uint32Array(target.buffer, target.byteOffset, target.byteLength / 4) : null;
  // Padding = KEYED COHERENT WRAP, DC-anchored + block-coherent noise.
  // History of this strip: black (pre-1.11) identified every edge tile
  // + flip; edge replication (1.11) duplicated rows exactly; interior
  // reflection (1.12) left a palindromic seam (MAD ~0.6 vs ~17 real);
  // the 1.13 shifted wrap killed the palindrome but re-phased every
  // pad row horizontally and left a luminance cliff at the seam —
  // row-to-row MAD inside strips measured 3-9x interior on smooth
  // content, naming boundary tiles (and fy by seam position) again.
  // Now: ONE keyed 2D toroidal offset for the whole strip (consecutive
  // pad rows/cols are consecutive interior rows/cols, so strip texture
  // coheres exactly like real texture), each pad pixel DC-shifted by
  // the ±16px local box-mean delta between the true edge and its
  // source (no seam cliff), plus keyed noise that is constant over
  // 8x8 blocks and never zero (decorrelates exact matching without
  // raising strip row-diff statistics). Display unaffected.
  // A solver without the scramble key cannot predict the fill; a
  // solver WITH the key never needed the oracle. The padded region is
  // cropped before presentation, and unscrambling never regenerates it.
  let padSeedState = 0x9e3779b9;
  for (let i = 0; i < count; i++) {
    padSeedState = Math.imul(padSeedState ^ (plan.order[i] * 2654435761), 2246822519);
    padSeedState = Math.imul(padSeedState ^ ((plan.flips[i].fx ? 2 : 0) + (plan.flips[i].fy ? 1 : 0) + 1), 3266489917);
  }
  const padRand = mulberry32(padSeedState >>> 0);
  let padShiftY = h > 3 ? 1 + Math.floor(padRand() * (h - 2)) : 0;
  let padShiftX = w > 3 ? 1 + Math.floor(padRand() * (w - 2)) : 0;
  // Refine each shift by keyed best-match search: among 24 keyed
  // candidate source rows/cols, keep the one whose (mean-removed,
  // subsampled) texture is closest to the true edge. The seam then
  // looks like an ordinary texture continuation instead of a jump to
  // an unrelated row — without containing any mirrored (palindromic)
  // content. Candidates come from the keyed pad PRNG, so the chosen
  // shift is not predictable without the scramble key.
  if (h > 8 && w > 4) {
    let best = padShiftY, bestScore = Infinity;
    for (let c = 0; c < 24; c++) {
      const cand = 1 + Math.floor(padRand() * (h - 2));
      let ma0 = 0, ma1 = 0, ma2 = 0, mb0 = 0, mb1 = 0, mb2 = 0, n = 0;
      for (let x = 0; x < w; x += 3) {
        const a = ((h - 1) * w + x) * 4, b = (cand * w + x) * 4;
        ma0 += src[a]; ma1 += src[a + 1]; ma2 += src[a + 2];
        mb0 += src[b]; mb1 += src[b + 1]; mb2 += src[b + 2];
        n++;
      }
      ma0 /= n; ma1 /= n; ma2 /= n; mb0 /= n; mb1 /= n; mb2 /= n;
      let s = 0;
      for (let x = 0; x < w; x += 3) {
        const a = ((h - 1) * w + x) * 4, b = (cand * w + x) * 4;
        s += Math.abs((src[a] - ma0) - (src[b] - mb0)) +
             Math.abs((src[a + 1] - ma1) - (src[b + 1] - mb1)) +
             Math.abs((src[a + 2] - ma2) - (src[b + 2] - mb2));
      }
      const score = s / (3 * n);
      if (score < bestScore) { bestScore = score; best = cand; }
    }
    padShiftY = best;
  }
  if (w > 8 && h > 4) {
    let best = padShiftX, bestScore = Infinity;
    for (let c = 0; c < 24; c++) {
      const cand = 1 + Math.floor(padRand() * (w - 2));
      let ma0 = 0, ma1 = 0, ma2 = 0, mb0 = 0, mb1 = 0, mb2 = 0, n = 0;
      for (let y = 0; y < h; y += 3) {
        const a = (y * w + w - 1) * 4, b = (y * w + cand) * 4;
        ma0 += src[a]; ma1 += src[a + 1]; ma2 += src[a + 2];
        mb0 += src[b]; mb1 += src[b + 1]; mb2 += src[b + 2];
        n++;
      }
      ma0 /= n; ma1 /= n; ma2 /= n; mb0 /= n; mb1 /= n; mb2 /= n;
      let s = 0;
      for (let y = 0; y < h; y += 3) {
        const a = (y * w + w - 1) * 4, b = (y * w + cand) * 4;
        s += Math.abs((src[a] - ma0) - (src[b] - mb0)) +
             Math.abs((src[a + 1] - ma1) - (src[b + 1] - mb1)) +
             Math.abs((src[a + 2] - ma2) - (src[b + 2] - mb2));
      }
      const score = s / (3 * n);
      if (score < bestScore) { bestScore = score; best = cand; }
    }
    padShiftX = best;
  }
  const padPhaseSeed = Math.floor(padRand() * 0xffffffff) | 0;
  const wrapPos = (c, n) => ((c % n) + n) % n;
  const PAD_NOISE_LUT = [-3, -2, -1, 1, 2, 3]; // never 0: pad != edge on flats
  const padNoise = (gx, gy, channel) => {
    let hash = (padPhaseSeed ^ Math.imul((gx >> 3) + 1, 374761393) ^ Math.imul((gy >> 3) + 1, 668265263) ^ Math.imul(channel + 1, 2246822519)) | 0;
    hash = Math.imul(hash ^ (hash >>> 13), 1274126177);
    return PAD_NOISE_LUT[(hash >>> 16) % 6];
  };
  // DC anchoring: per-channel prefix sums along the true edge row/col
  // and each referenced source row/col, built lazily (distinct strip
  // rows/cols only). A pad pixel is shifted by the difference of
  // ±16px box means so its local baseline continues the real edge.
  const ANCHOR_R = 16;
  const rowPrefixCache = new Map();
  const colPrefixCache = new Map();
  const rowPrefix = (y) => {
    let p = rowPrefixCache.get(y);
    if (!p) {
      p = new Float64Array(3 * (w + 1));
      const base = y * w * 4;
      for (let x = 0; x < w; x++) {
        const si = base + x * 4;
        p[x + 1] = p[x] + src[si];
        p[w + 1 + x + 1] = p[w + 1 + x] + src[si + 1];
        p[2 * (w + 1) + x + 1] = p[2 * (w + 1) + x] + src[si + 2];
      }
      rowPrefixCache.set(y, p);
    }
    return p;
  };
  const colPrefix = (x) => {
    let p = colPrefixCache.get(x);
    if (!p) {
      p = new Float64Array(3 * (h + 1));
      for (let y = 0; y < h; y++) {
        const si = (y * w + x) * 4;
        p[y + 1] = p[y] + src[si];
        p[h + 1 + y + 1] = p[h + 1 + y] + src[si + 1];
        p[2 * (h + 1) + y + 1] = p[2 * (h + 1) + y] + src[si + 2];
      }
      colPrefixCache.set(x, p);
    }
    return p;
  };
  const _boxA = [0, 0, 0];
  const _boxB = [0, 0, 0];
  const rowBox = (y, cx, out) => {
    const p = rowPrefix(y);
    const x0 = Math.max(0, cx - ANCHOR_R), x1 = Math.min(w, cx + ANCHOR_R + 1);
    const n = Math.max(1, x1 - x0);
    out[0] = (p[x1] - p[x0]) / n;
    out[1] = (p[w + 1 + x1] - p[w + 1 + x0]) / n;
    out[2] = (p[2 * (w + 1) + x1] - p[2 * (w + 1) + x0]) / n;
  };
  const colBox = (x, cy, out) => {
    const p = colPrefix(x);
    const y0 = Math.max(0, cy - ANCHOR_R), y1 = Math.min(h, cy + ANCHOR_R + 1);
    const n = Math.max(1, y1 - y0);
    out[0] = (p[y1] - p[y0]) / n;
    out[1] = (p[h + 1 + y1] - p[h + 1 + y0]) / n;
    out[2] = (p[2 * (h + 1) + y1] - p[2 * (h + 1) + y0]) / n;
  };
  const writePixel = (di, si) => {
    target[di] = src[si]; target[di + 1] = src[si + 1];
    target[di + 2] = src[si + 2]; target[di + 3] = src[si + 3];
  };
  const PAD_FEATHER = [0.45, 0.3, 0.15];
  const writePadPixel = (di, srcX, srcY, rawX, rawY) => {
    const si = (srcY * w + srcX) * 4;
    let fade = 0, edgeSi = -1;
    if (rawY >= h) {
      rowBox(h - 1, srcX, _boxA); rowBox(srcY, srcX, _boxB);
      const d = rawY - h;
      // Feather the first pad rows toward the true edge row: natural
      // continuation rows correlate strongly with the previous row, so
      // a partial blend hides the residual seam without ever
      // duplicating or mirroring edge content.
      if (d < 3) { fade = PAD_FEATHER[d]; edgeSi = ((h - 1) * w + srcX) * 4; }
    } else {
      colBox(w - 1, rawY, _boxA); colBox(srcX, rawY, _boxB);
      const d = rawX - w;
      if (d < 3) { fade = PAD_FEATHER[d]; edgeSi = (rawY * w + w - 1) * 4; }
    }
    for (let c = 0; c < 3; c++) {
      let v = src[si + c] + Math.round(_boxA[c] - _boxB[c]);
      if (fade) v = v * (1 - fade) + src[edgeSi + c] * fade;
      target[di + c] = Math.max(0, Math.min(255, Math.round(v) + padNoise(rawX, rawY, c)));
    }
    target[di + 3] = src[si + 3];
  };
  for (let dest = 0; dest < count; dest++) {
    const source = plan.order[dest];
    if (!Number.isInteger(source) || source < 0 || source >= count) {
      throw new RangeError('Archx: invalid scramble plan');
    }
    const flip = plan.flips[dest];
    if (!flip || typeof flip !== 'object') throw new RangeError('Archx: invalid scramble plan');
    const { fx, fy } = flip;
    const sx = (source % grid) * tw;
    const sy = Math.floor(source / grid) * th;
    const dx = (dest % grid) * tw;
    const dy = Math.floor(dest / grid) * th;
    for (let y = 0; y < th; y++) {
      const rawY = sy + (fy ? th - 1 - y : y);
      const rowIsPad = rawY >= h;
      const srcY = rowIsPad ? wrapPos(padShiftY + (rawY - h), h) : rawY;
      const dstRow = (dy + y) * pw + dx;
      if (useWords && !fx && !rowIsPad) {
        const avail = Math.max(0, Math.min(tw, w - sx));
        if (avail > 0) out32.set(src32.subarray(srcY * w + sx, srcY * w + sx + avail), dstRow);
        for (let x = avail; x < tw; x++) {
          const rawX = sx + x;
          const srcX = wrapPos(padShiftX + (rawX - w), w);
          writePadPixel((dstRow + x) * 4, srcX, srcY, rawX, rawY);
        }
      } else if (useWords && !rowIsPad && !((sx + tw) > w)) {
        // fx mirror of a full interior row: native copy + reverse.
        out32.set(src32.subarray(srcY * w + sx, srcY * w + sx + tw), dstRow);
        out32.subarray(dstRow, dstRow + tw).reverse();
      } else {
        for (let x = 0; x < tw; x++) {
          const rawX = sx + (fx ? tw - 1 - x : x);
          const colIsPad = rawX >= w;
          const srcX = colIsPad ? wrapPos(padShiftX + (rawX - w), w) : rawX;
          if (rowIsPad || colIsPad) {
            writePadPixel((dstRow + x) * 4, srcX, srcY, rawX, rawY);
          } else {
            writePixel((dstRow + x) * 4, (srcY * w + srcX) * 4);
          }
        }
      }
    }
  }
  return target;
}
