/**
 * Ingest/build-time protected-asset generation for image-heavy sites.
 *
 * The online middleware is the right boundary for paid, revocable, per-viewer
 * deliveries. It is not the cheapest way to serve a large public catalog:
 * even with caching, every cold derivative pays Sharp decode/encode work on a
 * request path. This builder moves that work to upload/CI time, emits a small
 * set of canonical scrambled variants per master, and writes a manifest the
 * browser client can use to fetch immutable `.archx` payloads from any static
 * host or CDN.
 *
 * Security model: generated payloads are down-scaled scrambled derivatives,
 * never masters. The manifest necessarily contains the browser scramble key
 * (and AES key when encryption is enabled), so anyone allowed to read a
 * manifest + payload can reconstruct that derivative. Serve a public manifest
 * only for an intentionally public catalog; for private catalogs, serve/sign
 * the manifest (or its URLs) through your normal authorization layer.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  DEFAULT_WIDTH_BUCKETS,
  validateImageId,
} from './middleware.js';
import { isPathInside, pathsOverlap } from './config.js';
import {
  configureSharpPerformance,
  inspectImageMetadata,
  scrambleImage,
} from './scramble-image.js';

export const DEFAULT_ASSET_WIDTHS = DEFAULT_WIDTH_BUCKETS;

const SUPPORTED_EXTENSIONS = new Set(['.jpg', '.jpeg', '.png', '.webp', '.avif']);

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function stableValue(value) {
  if (value === undefined) return null;
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return value;
  if (typeof value === 'function') return `function:${sha256(String(value))}`;
  if (Array.isArray(value)) return value.map(stableValue);
  if (isPlainObject(value)) {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = stableValue(value[key]);
    return out;
  }
  return String(value);
}

async function writeJsonAtomic(filePath, value, { mode = 0o600 } = {}) {
  await fs.promises.mkdir(path.dirname(filePath), { recursive: true });
  const tmp = `${filePath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  await fs.promises.writeFile(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode });
  await fs.promises.rename(tmp, filePath);
}

async function readJsonIfPresent(filePath) {
  try {
    const parsed = JSON.parse(await fs.promises.readFile(filePath, 'utf8'));
    return isPlainObject(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

function normalizeWidths(widths, maxWidth) {
  const raw = widths ?? DEFAULT_ASSET_WIDTHS;
  if (!Array.isArray(raw) || raw.length > 32 ||
      raw.some((value) => !Number.isInteger(value) || value < 64 || value > 8192)) {
    throw new TypeError('Archx asset build: widths must be an array of up to 32 integers from 64 to 8192');
  }
  const cap = maxWidth === 0 ? 8192 : maxWidth;
  return [...new Set(raw.filter((value) => value <= cap))].sort((a, b) => a - b);
}

function collectInputs(options) {
  const inputs = new Map();
  const add = (id, filePath) => {
    if (!validateImageId(id)) {
      throw new TypeError(`Archx asset build: invalid image id "${String(id)}"`);
    }
    if (inputs.has(id)) {
      throw new TypeError(`Archx asset build: duplicate image id "${id}"`);
    }
    let real;
    try { real = fs.realpathSync(path.resolve(String(filePath))); }
    catch { throw new TypeError(`Archx asset build: master does not exist for id "${id}"`); }
    if (!fs.statSync(real).isFile()) {
      throw new TypeError(`Archx asset build: master is not a file for id "${id}"`);
    }
    inputs.set(id, real);
  };

  if (options.images !== undefined) {
    const entries = options.images instanceof Map
      ? [...options.images.entries()]
      : isPlainObject(options.images)
        ? Object.entries(options.images)
        : null;
    if (!entries) {
      throw new TypeError('Archx asset build: images must be an object or Map of id to file path');
    }
    for (const [id, filePath] of entries) add(id, filePath);
  }
  if (options.inputDir !== undefined) {
    if (typeof options.inputDir !== 'string' || !options.inputDir) {
      throw new TypeError('Archx asset build: inputDir must be a non-empty string');
    }
    let root;
    try { root = fs.realpathSync(path.resolve(options.inputDir)); }
    catch { throw new TypeError('Archx asset build: inputDir does not exist'); }
    if (!fs.statSync(root).isDirectory()) {
      throw new TypeError('Archx asset build: inputDir is not a directory');
    }
    const names = fs.readdirSync(root).sort((a, b) => a.localeCompare(b));
    for (const name of names) {
      const ext = path.extname(name).toLowerCase();
      if (!SUPPORTED_EXTENSIONS.has(ext)) continue;
      add(path.basename(name, ext), path.join(root, name));
    }
  }
  if (!inputs.size) {
    throw new TypeError('Archx asset build: inputDir or images must contain at least one supported master');
  }
  return inputs;
}

async function resolveDynamic(value, context) {
  return typeof value === 'function' ? await value(context) : value;
}

/**
 * Build canonical scrambled variants + a browser manifest.
 *
 * @param {object} options
 * @param {string} [options.inputDir] Directory of masters (non-recursive).
 * @param {object|Map} [options.images] Explicit id -> master path map.
 * @param {string} options.outputDir Directory for generated `.archx` files.
 * @param {string} [options.manifestPath] Defaults to outputDir/archx-manifest.json.
 * @param {string} [options.statePath] Incremental state file (do not deploy).
 * @param {string} [options.baseUrl] URL prefix for variant files in the manifest.
 * @param {number[]} [options.widths] Canonical widths; source width is never enlarged.
 * @param {number} [options.jobs] Parallel masters to process.
 * @param {boolean} [options.force] Regenerate even when state matches.
 * @param {boolean} [options.clean] Remove stale files recorded in prior state.
 */
export async function buildArchxAssets(options = {}) {
  if (!isPlainObject(options)) throw new TypeError('Archx asset build: options must be an object');
  if (typeof options.outputDir !== 'string' || !options.outputDir) {
    throw new TypeError('Archx asset build: outputDir is required');
  }
  const outputDir = path.resolve(options.outputDir);
  const manifestPath = path.resolve(options.manifestPath || path.join(outputDir, 'archx-manifest.json'));
  const statePath = path.resolve(options.statePath || path.join(outputDir, '.archx-build-state.json'));
  const inputs = collectInputs(options);
  for (const masterPath of inputs.values()) {
    if (pathsOverlap(outputDir, path.dirname(masterPath))) {
      throw new TypeError('Archx asset build: outputDir must not overlap a master directory');
    }
  }
  await fs.promises.mkdir(outputDir, { recursive: true });
  const outputRealDir = fs.realpathSync(outputDir);
  for (const masterPath of inputs.values()) {
    if (pathsOverlap(outputRealDir, path.dirname(masterPath))) {
      throw new TypeError('Archx asset build: outputDir must not overlap a master directory');
    }
  }

  const grid = options.grid ?? 8;
  if (!Number.isInteger(grid) || grid < 2 || grid > 32) {
    throw new TypeError('Archx asset build: grid must be an integer from 2 to 32');
  }
  const planVersion = options.planVersion ?? 2; // 128-bit seed; containers carry pv for clients
  if (planVersion !== 1 && planVersion !== 2) {
    throw new TypeError('Archx asset build: planVersion must be 1 or 2');
  }
  const key = options.key ?? '';
  if (typeof key !== 'string' || !key || key.length > 512 || /[\u0000-\u001f\u007f]/.test(key)) {
    throw new TypeError('Archx asset build: key must be a non-empty string of at most 512 characters (set ARCHX_SCRAMBLE_KEY for the CLI)');
  }
  const aesKey = options.aesKey ?? null;
  if (aesKey !== null && (typeof aesKey !== 'string' || aesKey.length < 16 || aesKey.length > 256 || /[\u0000-\u001f\u007f]/.test(aesKey))) {
    throw new TypeError('Archx asset build: aesKey must be a base64 string');
  }
  // The manifest publishes `key` in plaintext so browsers can unscramble.
  // Defaulting the forensic StegoMark layout key to it would hand every
  // visitor the watermark secret (removal + forgery). Refuse loudly.
  const wantsStego = options.stegoPayload != null && options.stegoPayload !== '';
  const effectiveStegoKey = options.stegoKey ?? null;
  if (wantsStego && (typeof effectiveStegoKey !== 'string' || !effectiveStegoKey || effectiveStegoKey === key)) {
    throw new TypeError('Archx asset build: stegoKey must be an explicit dedicated secret when stegoPayload is set (never the scramble key — it is published in the manifest)');
  }
  if (effectiveStegoKey !== null && (typeof effectiveStegoKey !== 'string' || effectiveStegoKey.length > 512 || /[\u0000-\u001f\u007f]/.test(effectiveStegoKey))) {
    throw new TypeError('Archx asset build: stegoKey must be a string of at most 512 characters');
  }
  const maxWidth = options.maxWidth ?? 1920;
  if (maxWidth !== 0 && (!Number.isInteger(maxWidth) || maxWidth < 64 || maxWidth > 8192)) {
    throw new TypeError('Archx asset build: maxWidth must be 0 or an integer from 64 to 8192');
  }
  const widths = normalizeWidths(options.widths, maxWidth);
  const quality = options.quality ?? 88;
  if (quality !== 'lossless' && (!Number.isInteger(quality) || quality < 1 || quality > 100)) {
    throw new TypeError('Archx asset build: quality must be lossless or an integer from 1 to 100');
  }
  const format = options.format ?? 'webp';
  if (!['webp', 'png', 'jpeg', 'avif'].includes(format)) {
    throw new TypeError("Archx asset build: format must be 'webp', 'png', 'jpeg', or 'avif'");
  }
  const jobs = options.jobs ?? Math.max(1, Math.min(4,
    typeof os.availableParallelism === 'function' ? os.availableParallelism() : (os.cpus()?.length || 2)));
  if (!Number.isInteger(jobs) || jobs < 1 || jobs > 32) {
    throw new TypeError('Archx asset build: jobs must be an integer from 1 to 32');
  }
  const processing = {
    webpEffort: 2,
    webpSmartSubsample: false,
    resizeKernel: 'lanczos2',
    pngCompressionLevel: 6,
    jpegChromaSubsampling: '4:2:0',
    sharpConcurrency: 1,
    ...(isPlainObject(options.processing) ? options.processing : {}),
  };
  if (processing.sharpConcurrency > 0 || processing.sharpCache !== undefined) {
    configureSharpPerformance({
      ...(processing.sharpConcurrency > 0 ? { concurrency: processing.sharpConcurrency } : {}),
      ...(processing.sharpCache !== undefined ? { cache: processing.sharpCache } : {}),
    });
  }

  const optionsMaterial = stableValue({
    // Derivative byte-format vintage (mirrors the middleware output
    // cache namespace): pad generation, stego/forensic seed layouts
    // and watermark rasterization all change output bytes without
    // changing any user option, so incremental builds must count a
    // vintage bump as an options change and regenerate.
    derivativeFormatVersion: 'v6',
    grid,
    planVersion,
    keyHash: sha256(key),
    aesKeyHash: aesKey ? sha256(aesKey) : null,
    maxWidth,
    widths,
    quality,
    lossless: options.lossless === true,
    format,
    watermark: options.watermark ?? null,
    forensicSeed: options.forensicSeed ?? null,
    forensic: options.forensic ?? null,
    stegoPayload: options.stegoPayload ?? null,
    stegoKeyHash: sha256(String(effectiveStegoKey ?? '')),
    stegoStrength: options.stegoStrength ?? 6,
    stegoProfile: options.stegoProfile ?? 'standard',
    steganography: options.steganography ?? null,
    contentFingerprint: options.contentFingerprint === true,
    processing,
  });
  const optionsHash = sha256(JSON.stringify(optionsMaterial));
  const previousState = await readJsonIfPresent(statePath);
  const previousVariants = isPlainObject(previousState?.variants) ? previousState.variants : {};
  const baseUrl = typeof options.baseUrl === 'string' ? options.baseUrl : '';
  const assetUrl = (file) => baseUrl ? `${baseUrl.replace(/\/?$/, '/')}${encodeURIComponent(file)}` : file;
  const progress = typeof options.onProgress === 'function' ? options.onProgress : null;
  const notify = async (event) => {
    if (!progress) return;
    try { await progress(Object.freeze(event)); } catch { /* logging must not fail a build */ }
  };

  const buildOne = async (id, masterPath) => {
    const sourceBytes = await fs.promises.readFile(masterPath);
    const sourceSha256 = sha256(sourceBytes);
    const metadata = await inspectImageMetadata(sourceBytes, { processing });
    const targetCap = maxWidth === 0 ? metadata.width : Math.min(metadata.width, maxWidth);
    const selected = [...new Set([
      ...widths.filter((width) => width < targetCap),
      targetCap,
    ])].sort((a, b) => a - b);
    const variants = [];
    const stateEntries = [];
    let generated = 0;
    let skipped = 0;
    let bytesTotal = 0;

    for (const requestedWidth of selected) {
      const version = sha256(`${sourceSha256}:${optionsHash}:${requestedWidth}`).slice(0, 12);
      const file = `${id}-${requestedWidth}w-${version}.archx`;
      const outputPath = path.join(outputDir, file);
      const stateKey = `${id}:${requestedWidth}`;
      const previous = previousVariants[stateKey];
      let record = null;
      if (!options.force && isPlainObject(previous) &&
          previous.sourceSha256 === sourceSha256 &&
          previous.optionsHash === optionsHash &&
          previous.file === file &&
          Number.isSafeInteger(previous.width) && Number.isSafeInteger(previous.height) &&
          Number.isSafeInteger(previous.bytes)) {
        try {
          const existing = await fs.promises.readFile(outputPath);
          if (existing.length === previous.bytes &&
              (!previous.outputSha256 || sha256(existing) === previous.outputSha256)) {
            record = previous;
          }
        } catch { /* regenerate below */ }
      }
      if (!record) {
        const context = Object.freeze({ id, width: requestedWidth, sourceWidth: metadata.width, sourceHeight: metadata.height });
        const watermark = await resolveDynamic(options.watermark ?? null, context);
        const forensicSeed = await resolveDynamic(options.forensicSeed ?? null, context);
        const stegoPayload = await resolveDynamic(options.stegoPayload ?? null, context);
        const result = await scrambleImage(sourceBytes, {
          grid,
          planVersion,
          key,
          maxWidth: requestedWidth >= 64 ? requestedWidth : 0,
          quality,
          lossless: options.lossless === true,
          format,
          aesKey,
          watermark,
          forensicSeed,
          forensic: options.forensic,
          stegoPayload,
          stegoKey: effectiveStegoKey,
          stegoStrength: options.stegoStrength ?? 6,
          stegoProfile: options.stegoProfile ?? 'standard',
          steganography: options.steganography,
          contentFingerprint: options.contentFingerprint === true,
          processing,
        });
        const tmp = `${outputPath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
        await fs.promises.writeFile(tmp, result.bytes, { mode: 0o644 });
        await fs.promises.rename(tmp, outputPath);
        record = {
          sourceSha256,
          optionsHash,
          file,
          width: result.header.w,
          height: result.header.h,
          bytes: result.bytes.length,
          outputSha256: sha256(result.bytes),
          mime: result.header.mime,
          stegoFingerprint: result.stegoFingerprint || null,
          perceptualFingerprint: result.perceptualFingerprint || null,
        };
        generated++;
        await notify({ type: 'variant-generated', id, width: requestedWidth, bytes: record.bytes });
      } else {
        skipped++;
        await notify({ type: 'variant-skipped', id, width: requestedWidth, bytes: record.bytes });
      }
      bytesTotal += record.bytes;
      variants.push({
        width: record.width,
        height: record.height,
        file: record.file,
        url: assetUrl(record.file),
        bytes: record.bytes,
        sha256: record.outputSha256 || null,
        mime: record.mime || null,
      });
      stateEntries.push([stateKey, record]);
    }

    const asset = {
      id,
      width: metadata.width,
      height: metadata.height,
      key,
      grid,
      ...(planVersion === 2 ? { planVersion: 2 } : {}),
      ...(aesKey ? { aesKey } : {}),
      variants,
    };
    const fingerprint = stateEntries.find(([, record]) => record.perceptualFingerprint)?.[1]?.perceptualFingerprint;
    if (fingerprint) asset.perceptualFingerprint = fingerprint;
    return { id, asset, stateEntries, generated, skipped, bytesTotal };
  };

  const entries = [...inputs.entries()];
  const results = new Array(entries.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(jobs, entries.length) }, async () => {
    for (;;) {
      const index = cursor++;
      if (index >= entries.length) return;
      try {
        results[index] = { ok: true, value: await buildOne(...entries[index]) };
      } catch (err) {
        results[index] = { ok: false, id: entries[index][0], error: err };
      }
    }
  });
  await Promise.all(workers);
  const failures = results.filter((result) => !result.ok);
  if (failures.length) {
    const detail = failures.map((failure) => `${failure.id}: ${failure.error?.message || 'build failed'}`).join('; ');
    throw new Error(`Archx asset build failed for ${failures.length} master(s): ${detail}`);
  }

  const assets = {};
  const variantsState = {};
  let generated = 0;
  let skipped = 0;
  let totalBytes = 0;
  let variantCount = 0;
  for (const result of results) {
    const value = result.value;
    assets[value.id] = value.asset;
    for (const [stateKey, record] of value.stateEntries) variantsState[stateKey] = record;
    generated += value.generated;
    skipped += value.skipped;
    totalBytes += value.bytesTotal;
    variantCount += value.stateEntries.length;
  }

  let removed = 0;
  if (options.clean !== false) {
    const currentFiles = new Set(Object.values(variantsState).map((record) => record.file));
    for (const previous of Object.values(previousVariants)) {
      const file = previous?.file;
      if (typeof file !== 'string' || currentFiles.has(file) || path.basename(file) !== file ||
          !file.endsWith('.archx')) continue;
      const stalePath = path.join(outputDir, file);
      if (!isPathInside(outputDir, stalePath)) continue;
      try {
        await fs.promises.unlink(stalePath);
        removed++;
      } catch { /* already gone */ }
    }
  }

  const manifest = Object.freeze({
    version: 1,
    assets,
  });
  // The manifest is a PUBLIC web asset (its keys are delivered to every
  // browser by design); 0600 would make it unreadable by the web-server
  // user on typical nginx/Caddy deployments. Build state stays 0600.
  await writeJsonAtomic(manifestPath, manifest, { mode: 0o644 });
  // Hash the exact manifest bytes on disk so hosts can pin them in the
  // browser (`assetManifestIntegrity`) and detect CDN/object-store tampering
  // or stale-manifest mix-ups before any key or variant URL is trusted.
  const manifestSha256 = sha256(await fs.promises.readFile(manifestPath));
  await writeJsonAtomic(statePath, { version: 1, variants: variantsState });

  return Object.freeze({
    manifest,
    manifestSha256,
    manifestPath,
    statePath,
    assets: entries.length,
    variants: variantCount,
    generated,
    skipped,
    removed,
    bytes: totalBytes,
    totalBytes,
  });
}

export default buildArchxAssets;
