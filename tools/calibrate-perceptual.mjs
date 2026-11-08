#!/usr/bin/env node
/**
 * Measure pHash distance distributions on an operator-supplied image corpus.
 * This is calibration evidence, not an automatic production threshold change.
 *
 *   node tools/calibrate-perceptual.mjs ./copyrighted-image-sample
 */
import fs from 'node:fs/promises';
import path from 'node:path';
import sharp from 'sharp';
import { perceptualFingerprint, perceptualFingerprintDistance } from '../src/scramble.js';

const inputDir = process.argv[2];
if (!inputDir || process.argv.includes('--help')) {
  console.log('Usage: node tools/calibrate-perceptual.mjs <directory> [--json <file>]');
  process.exit(inputDir ? 0 : 2);
}
const jsonIndex = process.argv.indexOf('--json');
const outputFile = jsonIndex >= 0 ? process.argv[jsonIndex + 1] : null;
if (jsonIndex >= 0 && (!outputFile || outputFile.startsWith('--'))) {
  throw new Error('--json requires an output file path');
}
const supported = /\.(?:avif|gif|heic|heif|jpeg|jpg|png|tif|tiff|webp)$/i;
const files = (await fs.readdir(inputDir, { withFileTypes: true }))
  .filter((entry) => entry.isFile() && supported.test(entry.name))
  .map((entry) => path.join(inputDir, entry.name)).sort();
if (files.length < 2) throw new Error('Calibration needs at least two supported image files in the input directory');

async function pixels(source, variant = 'baseline') {
  let pipeline = sharp(source, { failOn: 'error', limitInputPixels: 25_000_000 }).rotate();
  if (variant === 'jpeg-70') pipeline = pipeline.resize(512, 512, { fit: 'inside', withoutEnlargement: true }).jpeg({ quality: 70 });
  else if (variant === 'webp-75') pipeline = pipeline.resize(512, 512, { fit: 'inside', withoutEnlargement: true }).webp({ quality: 75 });
  else if (variant === 'half-resize') pipeline = pipeline.resize(256, 256, { fit: 'inside', withoutEnlargement: true }).resize(512, 512, { fit: 'inside', withoutEnlargement: true });
  else if (variant === 'center-crop-85') {
    const base = await sharp(source, { failOn: 'error', limitInputPixels: 25_000_000 }).rotate()
      .resize(512, 512, { fit: 'inside', withoutEnlargement: true }).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
    const width = Math.max(1, Math.round(base.info.width * 0.85));
    const height = Math.max(1, Math.round(base.info.height * 0.85));
    const left = Math.floor((base.info.width - width) / 2);
    const top = Math.floor((base.info.height - height) / 2);
    const cropped = await sharp(base.data, { raw: { width: base.info.width, height: base.info.height, channels: base.info.channels } }).extract({ left, top, width, height })
      .resize(512, 512, { fit: 'inside', withoutEnlargement: true }).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
    return { data: new Uint8Array(cropped.data), width: cropped.info.width, height: cropped.info.height };
  }
  const decoded = await pipeline.resize(512, 512, { fit: 'inside', withoutEnlargement: true })
    .ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  return { data: new Uint8Array(decoded.data), width: decoded.info.width, height: decoded.info.height };
}

const positives = [];
const negatives = [];
const records = [];
const baseHashes = [];
for (const file of files) {
  const base = await pixels(file);
  const baseHash = perceptualFingerprint(base.data, base.width, base.height);
  baseHashes.push(baseHash);
  const variants = {};
  for (const variant of ['jpeg-70', 'webp-75', 'half-resize', 'center-crop-85']) {
    const altered = await pixels(file, variant);
    const distance = perceptualFingerprintDistance(baseHash,
      perceptualFingerprint(altered.data, altered.width, altered.height));
    positives.push(distance);
    variants[variant] = distance;
  }
  records.push({ file: path.basename(file), variants });
  for (let i = 0; i < records.length - 1; i++) {
    negatives.push(perceptualFingerprintDistance(baseHash, baseHashes[i]));
  }
}

function percentile(values, p) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor((sorted.length - 1) * p))] : null;
}
let best = null;
for (let threshold = 0; threshold <= 64; threshold++) {
  const tp = positives.filter((distance) => distance <= threshold).length;
  const fp = negatives.filter((distance) => distance <= threshold).length;
  const fn = positives.length - tp;
  const tn = negatives.length - fp;
  const balancedError = ((fp / negatives.length) + (fn / positives.length)) / 2;
  if (!best || balancedError < best.balancedError ||
      (balancedError === best.balancedError && threshold < best.threshold)) {
    best = { threshold, balancedError, tp, fp, fn, tn };
  }
}
const report = {
  tool: 'archx-perceptual-fingerprint-calibration',
  fingerprintBits: 63,
  images: files.length,
  positiveComparisons: positives.length,
  negativeComparisons: negatives.length,
  positiveDistance: { min: Math.min(...positives), median: percentile(positives, 0.5), p95: percentile(positives, 0.95), max: Math.max(...positives) },
  negativeDistance: { min: Math.min(...negatives), median: percentile(negatives, 0.5), p05: percentile(negatives, 0.05), max: Math.max(...negatives) },
  bestBalancedThreshold: best,
  perImage: records,
  caveat: 'Threshold is corpus-specific calibration evidence. Validate with independent positive/negative sets and never treat pHash as cryptographic proof or access control.',
};
if (outputFile) await fs.writeFile(outputFile, `${JSON.stringify(report, null, 2)}\n`);
console.log(JSON.stringify(report, null, 2));
