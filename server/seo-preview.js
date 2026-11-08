import { prepareDerivativeBase } from './scramble-image.js';

/** Build the visible, repeated preview-only mark used for verified crawler derivatives. */
export function createSeoWatermarkSvg(width, height, label) {
  const escape = (value) => String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
  const text = escape(`PREVIEW ONLY · ${label}`);
  const fontSize = Math.max(12, Math.round(Math.min(width, height) / 8));
  const tileWidth = Math.max(120, fontSize * 6);
  const tileHeight = Math.max(56, fontSize * 3);
  return Buffer.from(
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">` +
    `<defs><pattern id="p" width="${tileWidth}" height="${tileHeight}" patternUnits="userSpaceOnUse" patternTransform="rotate(-28)">` +
    `<text x="8" y="${Math.ceil(tileHeight * 0.68)}" font-family="Arial,sans-serif" font-size="${fontSize}" font-weight="900" letter-spacing="1.5" fill="#fff" fill-opacity=".72" stroke="#111" stroke-opacity=".8" stroke-width="2.5" paint-order="stroke">${text}</text>` +
    `</pattern></defs><rect width="100%" height="100%" fill="url(#p)"/>` +
    `<rect x="2" y="2" width="${Math.max(1, width - 4)}" height="${Math.max(1, height - 4)}" fill="none" stroke="#fff" stroke-opacity=".9" stroke-width="${Math.max(2, Math.round(fontSize / 7))}"/>` +
    `<rect x="0" y="0" width="${width}" height="${Math.max(22, fontSize + 12)}" fill="#111" fill-opacity=".65"/>` +
    `<text x="8" y="${Math.max(18, fontSize + 2)}" font-family="Arial,sans-serif" font-size="${Math.max(12, Math.round(fontSize * .72))}" font-weight="900" fill="#fff" stroke="#111" stroke-width="1.5" paint-order="stroke">${text}</text></svg>`,
  );
}

/**
 * Render a low-resolution, watermarked crawler preview. Authorization,
 * verification, cache policy, and source-file race checks remain owned by
 * the middleware; this module owns only the image transformation.
 */
export async function renderSeoPreview(sourceBytes, {
  maxWidth, processing, watermark, quality, format,
}) {
  const base = await prepareDerivativeBase(sourceBytes, {
    grid: 8,
    maxWidth,
    processing,
  });
  const sharpModule = await import('sharp');
  const sharp = sharpModule.default || sharpModule;
  let pipeline = sharp(Buffer.from(base.data), {
    raw: { width: base.w, height: base.h, channels: 4 },
  }).timeout({ seconds: processing.timeoutSec });
  pipeline = pipeline.composite([{ input: createSeoWatermarkSvg(base.w, base.h, watermark) }]);
  if (format === 'jpeg') {
    pipeline = pipeline.flatten({ background: '#fff' }).jpeg({
      quality,
      chromaSubsampling: '4:2:0',
      mozjpeg: false,
    });
  } else {
    pipeline = pipeline.webp({
      quality,
      alphaQuality: 80,
      effort: Math.min(processing.webpEffort, 2),
      smartSubsample: false,
    });
  }
  return pipeline.toBuffer();
}
