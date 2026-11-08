export function makeTexturedRgba(width, height, seed = 0x12345678) {
  const rgba = new Uint8Array(width * height * 4);
  let state = seed >>> 0;
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
      const grain = (state >>> 24) & 0xff;
      const i = (y * width + x) * 4;
      rgba[i] = Math.min(255, 50 + grain * 0.55 + (x / width) * 40);
      rgba[i + 1] = Math.min(255, 60 + grain * 0.45 + (y / height) * 30);
      rgba[i + 2] = Math.min(255, 70 + grain * 0.5);
      rgba[i + 3] = 255;
    }
  }
  return rgba;
}

export function cropRgba(rgba, sourceWidth, { left, top, width, height }) {
  const crop = new Uint8Array(width * height * 4);
  for (let y = 0; y < height; y++) {
    const from = ((top + y) * sourceWidth + left) * 4;
    crop.set(rgba.subarray(from, from + width * 4), y * width * 4);
  }
  return crop;
}
