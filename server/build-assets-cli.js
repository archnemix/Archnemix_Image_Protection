#!/usr/bin/env node
/**
 * Build responsive, CDN-ready Archx assets at ingest/CI time.
 *
 *   ARCHX_SCRAMBLE_KEY="<long random>" npx archx-build ./masters ./public/protected \
 *     --base-url /protected/ --widths 320,640,960,1200,1600 --quality 88 --jobs 4
 *
 * The generated manifest contains the browser scramble key (and AES key when
 * --encrypt is used). Treat it as authorized derivative-delivery metadata:
 * publish it only for public catalogs, or serve/sign it through your app for
 * private ones. Do not deploy the masters or `.archx-build-state.json`.
 */
import fs from 'node:fs';
import path from 'node:path';
import { buildArchxAssets } from './build-assets.js';
import { generateKeyBase64 } from './scramble-image.js';

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith('--')) {
      const name = arg.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) { out[name] = next; i++; }
      else out[name] = true;
    } else out._.push(arg);
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
const [inputDir, outputDir] = args._;
if (!inputDir || !outputDir || args.help) {
  console.log(`Usage: archx-build <masters folder> <output folder> [options]
  --key <secret>          scramble key (prefer ARCHX_SCRAMBLE_KEY)
  --manifest <path>       manifest path (default <output>/archx-manifest.json)
  --state <path>          incremental state path (default <output>/.archx-build-state.json)
  --base-url <url>        public URL prefix for generated files (default: relative filenames)
  --widths <list>         canonical widths, comma-separated (default responsive ladder)
  --max-width <px>        largest derivative width (default 1920; never enlarges)
  --grid <n>              scramble tiles per side (default 8)
  --quality <1-100>       WebP/JPEG quality (default 88; use --lossless for exact pixels)
  --lossless              lossless WebP/PNG at delivered sizes
  --format <fmt>          webp (default), png, or jpeg
  --encrypt               AES-GCM encrypt payloads (ARCHX_AES_KEY, else reuse/generate the manifest key)
  --watermark <text>      bake visible watermark text before scrambling
  --forensic-seed <s>     shared forensic seed (prefer ARCHX_FORENSIC_SEED)
  --stego <payload>       StegoMark payload; {id} is replaced per image
  --stego-key <s>         StegoMark key (prefer ARCHX_STEGO_KEY; default scramble key)
  --stego-profile <p>     standard (default) or robust
  --jobs <n>              parallel masters (default up to 4)
  --force                 regenerate all variants
  --no-clean              keep stale generated files recorded in prior state
  --webp-effort <0-6>     WebP effort (default 2 for catalog builds)
  --smart-subsample       enable WebP smart chroma subsampling (slower; default off here)
  --resize-kernel <name>  lanczos2 (default), lanczos3, mitchell, cubic, nearest, mks2013, mks2021
  --sharp-concurrency <n> libvips threads per image job (default 1)`);
  process.exit(inputDir ? 0 : 1);
}

const key = process.env.ARCHX_SCRAMBLE_KEY || args.key || '';
if (!key) {
  console.error('Archx build failed: set ARCHX_SCRAMBLE_KEY to a long random scramble key');
  process.exit(1);
}
if (args.key || args['stego-key'] || args['forensic-seed']) {
  console.warn('⚠  Secret-bearing CLI arguments can leak via shell history/process lists; prefer ARCHX_* environment variables.');
}
const widths = args.widths
  ? String(args.widths).split(',').map((value) => Number(value.trim()))
  : undefined;
let aesKey = null;
if (args.encrypt) {
  aesKey = process.env.ARCHX_AES_KEY || null;
  if (!aesKey) {
    // Reuse the key already published in an existing manifest so repeat CI
    // builds stay incremental instead of rotating every encrypted variant.
    const existingManifestPath = path.resolve(args.manifest || path.join(outputDir, 'archx-manifest.json'));
    try {
      const existing = JSON.parse(fs.readFileSync(existingManifestPath, 'utf8'));
      const keys = [...new Set(Object.values(existing?.assets || {})
        .map((asset) => asset?.aesKey)
        .filter((value) => typeof value === 'string' && value))];
      if (keys.length > 1) throw new Error('existing manifest contains multiple AES keys; set ARCHX_AES_KEY explicitly');
      aesKey = keys[0] || null;
    } catch (err) {
      if (err?.code !== 'ENOENT' && !/multiple AES keys/.test(String(err?.message || ''))) {
        console.warn('⚠  Existing manifest could not be reused for its AES key; a new key will be generated.');
      } else if (/multiple AES keys/.test(String(err?.message || ''))) {
        console.error(`Archx build failed: ${err.message}`);
        process.exit(1);
      }
    }
    if (!aesKey) aesKey = generateKeyBase64();
  }
}

try {
  const summary = await buildArchxAssets({
    inputDir,
    outputDir,
    manifestPath: args.manifest || undefined,
    statePath: args.state || undefined,
    baseUrl: args['base-url'] || '',
    widths,
    maxWidth: args['max-width'] ? Number(args['max-width']) : undefined,
    grid: args.grid ? Number(args.grid) : undefined,
    key,
    quality: args.quality === 'lossless' ? 'lossless' : (args.quality ? Number(args.quality) : 88),
    lossless: !!args.lossless,
    format: args.format || 'webp',
    aesKey,
    watermark: args.watermark || null,
    forensicSeed: process.env.ARCHX_FORENSIC_SEED || args['forensic-seed'] || null,
    stegoPayload: args.stego
      ? ({ id }) => String(args.stego).replaceAll('{id}', id)
      : null,
    stegoKey: process.env.ARCHX_STEGO_KEY || args['stego-key'] || key,
    stegoProfile: args['stego-profile'] || 'standard',
    jobs: args.jobs ? Number(args.jobs) : undefined,
    force: !!args.force,
    clean: !args['no-clean'],
    processing: {
      webpEffort: args['webp-effort'] ? Number(args['webp-effort']) : 2,
      webpSmartSubsample: !!args['smart-subsample'],
      resizeKernel: args['resize-kernel'] || 'lanczos2',
      sharpConcurrency: args['sharp-concurrency'] ? Number(args['sharp-concurrency']) : 1,
    },
    onProgress(event) {
      if (event.type === 'variant-generated') {
        console.log(`✔ ${event.id} ${event.width}w (${(event.bytes / 1024).toFixed(0)} KiB)`);
      }
    },
  });
  console.log(`\nBuilt ${summary.assets} asset(s), ${summary.variants} variant(s): ` +
    `${summary.generated} generated, ${summary.skipped} reused, ${summary.removed} stale removed.`);
  console.log(`Manifest: ${summary.manifestPath}`);
  console.log('Browser: Archx.config({ assetManifest: "/protected/archx-manifest.json" }); ' +
    'Archx.load.image(el, { assetId: "<id>" }, Archx.preset("catalog"));');
  if (aesKey) console.log('Note: the manifest contains the AES key needed by authorized browsers; protect/sign it according to your catalog policy.');
} catch (err) {
  console.error(`Archx build failed: ${err?.message || err}`);
  process.exit(1);
}
