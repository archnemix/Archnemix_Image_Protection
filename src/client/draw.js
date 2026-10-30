/**
 * Canvas composition helpers: high-quality resampling, tile unscramble to canvas, local scramble for plain sources.
 */
import { ctxNative, getNativeContext, makeCanvas, nativeDrawImage, setCanvasSize } from './native.js';
import { nonRetryableError } from './network.js';
import { buildScramblePlan, paddedSize, tileRect } from '../scramble.js';

export function asByteArray(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  throw nonRetryableError('Archx: image source must be bytes');
}

export function setSmoothing(ctx, enabled) {
  ctx.imageSmoothingEnabled = enabled;
  if (enabled) {
    try { ctx.imageSmoothingQuality = 'high'; } catch {}
  }
}

/**
 * Draw with browser-native high-quality resampling. Large reductions go via
 * a destination-anchored 2× intermediate (recursively for very large jumps)
 * instead of repeatedly halving the full source frame. In Chromium this
 * measured materially closer to an ordinary <img> downscale than either one
 * huge drawImage jump or full-frame progressive halving, both of which can
 * make fine photo detail look slurry.
 */
export function drawImageHighQuality(ctx, source, sx, sy, sw, sh, dx, dy, dw, dh) {
  if (sw <= 0 || sh <= 0 || dw <= 0 || dh <= 0) return;
  const scaleX = dw / sw;
  const scaleY = dh / sh;
  const exact = Math.abs(scaleX - 1) < 0.01 && Math.abs(scaleY - 1) < 0.01;
  if (Math.min(scaleX, scaleY) >= 0.5) {
    setSmoothing(ctx, !exact);
    nativeDrawImage(ctx, source, sx, sy, sw, sh, dx, dy, dw, dh);
    return;
  }

  const intermediate = makeCanvas();
  setCanvasSize(intermediate, Math.max(1, Math.ceil(dw * 2)), Math.max(1, Math.ceil(dh * 2)));
  const ictx = getNativeContext(intermediate, '2d');
  drawImageHighQuality(
    ictx, source, sx, sy, sw, sh,
    0, 0, intermediate.width, intermediate.height,
  );
  setSmoothing(ctx, true);
  nativeDrawImage(ctx, intermediate, 0, 0, intermediate.width, intermediate.height, dx, dy, dw, dh);
  setCanvasSize(intermediate, 0, 0);
}

/** Un-scramble a bitmap onto a private offscreen canvas (capped size). */
export function unscrambleToCanvas(bitmap, meta, targetW, targetH) {
  const canvas = makeCanvas();
  setCanvasSize(canvas, Math.max(1, targetW), Math.max(1, targetH));
  const ctx = getNativeContext(canvas, '2d');
  if (!meta.plan) { // not scrambled — single high-quality draw
    drawImageHighQuality(ctx, bitmap, 0, 0, bitmap.width, bitmap.height, 0, 0, targetW, targetH);
    return canvas;
  }
  const { plan, origW, origH, padW, padH } = meta;
  const twSrc = bitmap.width / plan.grid;
  const thSrc = bitmap.height / plan.grid;
  // Reassemble on an intermediate canvas whose tile size is an INTEGER number
  // of pixels. Fractional tile origins make browsers paint semi-transparent
  // edge coverage and blend pixels from neighbouring *scrambled* tiles,
  // which shows up as a visible grid of seams.
  //
  // Quality matters here: scaling every shuffled tile straight to its final
  // size throws away detail 64 separate times and looks slurry. Prefer the
  // decoded bitmap's native resolution (or at most 2x the final size for a
  // very large source), reassemble there, then perform ONE high-quality
  // downscale after neighbouring pixels are true neighbours again.
  const targetPadW = targetW * (padW / origW);
  const targetPadH = targetH * (padH / origH);
  const intermediateScale = Math.max(0.05, Math.min(
    2,
    bitmap.width / Math.max(1, targetPadW),
    bitmap.height / Math.max(1, targetPadH),
  ));
  const tileW = Math.max(1, Math.round((targetPadW * intermediateScale) / plan.grid));
  const tileH = Math.max(1, Math.round((targetPadH * intermediateScale) / plan.grid));
  const padded = makeCanvas();
  setCanvasSize(padded, tileW * plan.grid, tileH * plan.grid);
  const pctx = getNativeContext(padded, '2d');
  const exactScale = Math.abs(tileW - twSrc) < 0.01 && Math.abs(tileH - thSrc) < 0.01;
  setSmoothing(pctx, !exactScale);
  // Half-pixel source inset when scaling: prevents smoothing from sampling
  // the unrelated tile next door in the scrambled bitmap. At exact scale we
  // copy pixels 1:1, so no inset (and no geometric shift) is needed.
  const insetX = exactScale ? 0 : Math.min(0.5, twSrc * 0.01);
  const insetY = exactScale ? 0 : Math.min(0.5, thSrc * 0.01);
  for (let orig = 0; orig < plan.count; orig++) {
    const scrambledPos = plan.inverse[orig];
    const s = tileRect(scrambledPos, plan.grid, twSrc, thSrc);
    const dx = (orig % plan.grid) * tileW;
    const dy = Math.floor(orig / plan.grid) * tileH;
    const { fx, fy } = plan.flips[scrambledPos];
    ctxNative(pctx, 'save', );
    ctxNative(pctx, 'translate', dx + (fx ? tileW : 0), dy + (fy ? tileH : 0));
    ctxNative(pctx, 'scale', fx ? -1 : 1, fy ? -1 : 1);
    nativeDrawImage(pctx, bitmap,
      s.x + insetX, s.y + insetY, s.w - insetX * 2, s.h - insetY * 2,
      0, 0, tileW, tileH);
    ctxNative(pctx, 'restore', );
  }
  // Crop away the padding strip and scale once to the exact requested size.
  drawImageHighQuality(ctx, padded,
    0, 0, padded.width * (origW / padW), padded.height * (origH / padH),
    0, 0, targetW, targetH);
  setCanvasSize(padded, 0, 0);
  return canvas;
}

/**
 * Locally scramble a clean canvas (Fortress/plain-source Vault): the GPU
 * texture then holds shuffled pixels, so texture/framebuffer snooping sees
 * a mosaic even when the network source itself was a plain image.
 */
export function scrambleCanvasLocally(source, grid, key) {
  const w = source.width, h = source.height;
  const { tw, th, pw, ph } = paddedSize(w, h, grid);
  const plan = buildScramblePlan(grid, key, 2); // ephemeral in-page plan: strongest seed is free here
  const cleanPadded = makeCanvas();
  setCanvasSize(cleanPadded, pw, ph);
  const cctx = getNativeContext(cleanPadded, '2d');
  setSmoothing(cctx, false); // exact 1:1 copy into the padded frame
  nativeDrawImage(cctx, source, 0, 0);
  // Keyed DOUBLE shifted toroidal wrap into the padding (the 2D analog
  // of the core scramblePixelsPadded scheme): black/edge-duplicated
  // padding identifies boundary tiles, and mirror reflection leaves a
  // palindrome seam a keyless solver can lock onto. Two wraps from
  // different plan-keyed offsets composited at partial alpha produce a
  // blend that is a near-copy of NEITHER source region, so exact/NCC
  // duplicate-hunting finds no anchor; a low-alpha true-edge taper over
  // the first 3 px pulls the pad->image seam toward texture scale.
  const shiftFor = (orderIdx, len) => (len > 1
    ? (len >> 1) + (plan.order[((orderIdx % plan.count) + plan.count) % plan.count] % Math.max(1, len >> 1))
    : 0);
  const wrapCols = (shiftX) => {
    let dx = w;
    let sx = shiftX % Math.max(1, w);
    while (dx < pw) {
      const seg = Math.min(w - sx, pw - dx);
      nativeDrawImage(cctx, source, sx, 0, seg, h, dx, 0, seg, h);
      dx += seg; sx = 0;
    }
  };
  const wrapRows = (shiftY) => {
    // Rows are drawn from the padded frame itself (self-draw uses a
    // snapshot, per canvas spec) so the corner inherits wrapped columns.
    let dy = h;
    let sy = shiftY % Math.max(1, h);
    while (dy < ph) {
      const seg = Math.min(h - sy, ph - dy);
      nativeDrawImage(cctx, cleanPadded, 0, sy, pw, seg, 0, dy, pw, seg);
      dy += seg; sy = 0;
    }
  };
  if (pw > w && w > 0) {
    ctxNative(cctx, 'save', );
    cctx.fillStyle = '#000'; cctx.fillRect(w, 0, pw - w, h);
    cctx.globalAlpha = 0.96; wrapCols(shiftFor(0, w));
    cctx.globalAlpha = 0.45; wrapCols(shiftFor(1, w));
    cctx.globalAlpha = 0.35;
    nativeDrawImage(cctx, source, w - 1, 0, 1, h, w, 0, Math.min(3, pw - w), h);
    ctxNative(cctx, 'restore', );
  }
  if (ph > h && h > 0) {
    ctxNative(cctx, 'save', );
    cctx.fillStyle = '#000'; cctx.fillRect(0, h, pw, ph - h);
    cctx.globalAlpha = 0.96; wrapRows(shiftFor(plan.count - 1, h));
    cctx.globalAlpha = 0.45; wrapRows(shiftFor(plan.count - 2, h));
    cctx.globalAlpha = 0.35;
    nativeDrawImage(cctx, cleanPadded, 0, h - 1, pw, 1, 0, h, pw, Math.min(3, ph - h));
    ctxNative(cctx, 'restore', );
  }
  const scrambled = makeCanvas();
  setCanvasSize(scrambled, pw, ph);
  const ctx = getNativeContext(scrambled, '2d');
  setSmoothing(ctx, false); // tiles are copied 1:1; never resample them here
  ctx.fillStyle = '#000'; ctx.fillRect(0, 0, pw, ph);
  for (let dest = 0; dest < plan.count; dest++) {
    const orig = plan.order[dest];
    const s = tileRect(orig, plan.grid, tw, th);
    const d = tileRect(dest, plan.grid, tw, th);
    const { fx, fy } = plan.flips[dest];
    ctxNative(ctx, 'save', );
    ctxNative(ctx, 'translate', d.x + (fx ? tw : 0), d.y + (fy ? th : 0));
    ctxNative(ctx, 'scale', fx ? -1 : 1, fy ? -1 : 1);
    nativeDrawImage(ctx, cleanPadded, s.x, s.y, tw, th, 0, 0, tw, th);
    ctxNative(ctx, 'restore', );
  }
  setCanvasSize(cleanPadded, 0, 0);
  return { canvas: scrambled, meta: { plan, origW: w, origH: h, padW: pw, padH: ph } };
}
