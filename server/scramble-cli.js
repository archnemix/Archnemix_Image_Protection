#!/usr/bin/env node
/**
 * Offline protector CLI: turn a master image into a scrambled .archx asset
 * you can host on any static CDN. The output is useless without the key.
 *
 *   ARCHX_SCRAMBLE_KEY="<long random>" npx archx-protect photo.jpg photo.archx --max-width 1400
 *   npx archx-protect photo.jpg photo.archx --encrypt        (generates an AES key)
 *   ARCHX_SCRAMBLE_KEY="<long random>" npx archx-protect ./masters ./protected
 *
 * Prefer ARCHX_SCRAMBLE_KEY / ARCHX_STEGO_KEY / ARCHX_FORENSIC_SEED /
 * ARCHX_AES_KEY over secret-bearing argv values, which can leak through
 * shell history and process listings.
 */
import fs from 'node:fs';
import path from 'node:path';
import { scrambleImage, generateKeyBase64 } from './scramble-image.js';

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const name = a.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('--')) { out[name] = next; i++; }
      else out[name] = true;
    } else out._.push(a);
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
const [input, output] = args._;
if (!input || !output || args.help) {
  console.log(`Usage: archx-protect <input image|folder> <output .archx|folder> [options]
  --key <secret>       scramble key (prefer ARCHX_SCRAMBLE_KEY; argv secrets can leak)
  --grid <n>           tiles per side (default 8)
  --plan-version <1|2> scramble plan seed strength (1 = legacy, 2 = 128-bit; default 1)
  --max-width <px>     down-scale master to this width first (default 1600)
  --quality <1-100>    WebP/JPEG quality (default 95; use --lossless for exact pixels)
  --lossless           lossless WebP/PNG at the delivered size (larger payload)
  --format <fmt>       webp (default), png, or jpeg
  --encrypt            AES-GCM-encrypt (ARCHX_AES_KEY if set; otherwise prints one generated key once)
  --watermark <text>   bake a visible watermark in before scrambling
  --forensic-seed <s>  forensic seed (prefer ARCHX_FORENSIC_SEED)
  --stego <payload>    bake a blind StegoMark ownership fingerprint (detect later with archx-detect)
  --stego-key <s>      StegoMark key (prefer ARCHX_STEGO_KEY; default: scramble key)
  --stego-strength <n> StegoMark strength 1–16 (default 6; higher = tougher, slightly more visible)
  --stego-profile <p> standard (default) or robust low-frequency forensic profile
  --stego-grid-x <n>  StegoMark grid columns 4–64 (profile default)
  --stego-grid-y <n>  StegoMark grid rows 4–64 (profile default)
  --max-input-bytes <n> reject masters above this size (default 52428800)
  --max-input-pixels <n> reject masters above this pixel budget (default 40000000)
  --timeout-sec <n> Sharp processing timeout per image (default 10)`);
  process.exit(input ? 0 : 1);
}

const key = process.env.ARCHX_SCRAMBLE_KEY || args.key || '';
if (!key) console.warn('⚠  No scramble key given: anyone can un-scramble with the default key. Set ARCHX_SCRAMBLE_KEY.');
if (args.key || args['stego-key'] || args['forensic-seed']) {
  console.warn('⚠  Secret-bearing CLI arguments can leak via shell history/process lists; prefer the ARCHX_* environment variables.');
}
const aesKey = args.encrypt ? (process.env.ARCHX_AES_KEY || generateKeyBase64()) : null;
const generatedAesKey = !!args.encrypt && !process.env.ARCHX_AES_KEY;
const stegoProfile = args['stego-profile'] || 'standard';
const stegoGridX = args['stego-grid-x'] ? Number(args['stego-grid-x']) : undefined;
const stegoGridY = args['stego-grid-y'] ? Number(args['stego-grid-y']) : undefined;
if (!['standard', 'robust'].includes(stegoProfile) ||
    (stegoGridX !== undefined && (!Number.isInteger(stegoGridX) || stegoGridX < 4 || stegoGridX > 64)) ||
    (stegoGridY !== undefined && (!Number.isInteger(stegoGridY) || stegoGridY < 4 || stegoGridY > 64))) {
  console.error('Archx protect: --stego-profile must be standard or robust; StegoMark grid values must be integers from 4 to 64');
  process.exit(1);
}
const opts = {
  key,
  grid: args.grid ? Number(args.grid) : 8,
  planVersion: args['plan-version'] ? Number(args['plan-version']) : 1,
  maxWidth: args['max-width'] ? Number(args['max-width']) : 1600,
  quality: args.quality === 'lossless' ? 'lossless' : (args.quality ? Number(args.quality) : 95),
  lossless: !!args.lossless,
  format: args.format || 'webp',
  aesKey,
  watermark: args.watermark || null,
  forensicSeed: process.env.ARCHX_FORENSIC_SEED || args['forensic-seed'] || null,
  stegoPayload: args.stego || null,
  stegoKey: process.env.ARCHX_STEGO_KEY || args['stego-key'] || key,
  stegoStrength: args['stego-strength'] ? Number(args['stego-strength']) : 6,
  stegoProfile,
  steganography: {
    profile: stegoProfile,
    ...(stegoGridX !== undefined ? { gridX: stegoGridX } : {}),
    ...(stegoGridY !== undefined ? { gridY: stegoGridY } : {}),
  },
  contentFingerprint: true,
  maxInputBytes: args['max-input-bytes'] ? Number(args['max-input-bytes']) : undefined,
  maxInputPixels: args['max-input-pixels'] ? Number(args['max-input-pixels']) : undefined,
  processingTimeoutSec: args['timeout-sec'] ? Number(args['timeout-sec']) : undefined,
};

async function protectOne(inPath, outPath) {
  const maxInputBytes = Number.isInteger(opts.maxInputBytes) ? opts.maxInputBytes : 50 * 1024 * 1024;
  // fstat + read through one descriptor so the checked size describes the
  // bytes actually processed (no stat/read race).
  const inputFd = fs.openSync(inPath, 'r');
  let inputBytes;
  try {
    const inputStat = fs.fstatSync(inputFd);
    if (!inputStat.isFile() || inputStat.size > maxInputBytes) {
      throw new Error(`Archx protect: input is not a regular file within the ${maxInputBytes}-byte limit`);
    }
    inputBytes = fs.readFileSync(inputFd);
  } finally { fs.closeSync(inputFd); }
  const { bytes, header, stegoFingerprint, perceptualFingerprint } = await scrambleImage(inputBytes, opts);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, bytes);
  console.log(`✔ ${inPath} -> ${outPath}  (${header.w}×${header.h}, grid ${header.grid}, ${(bytes.length / 1024).toFixed(0)} kB${stegoFingerprint ? `, StegoMark ${stegoFingerprint} (${stegoProfile})` : ''}${perceptualFingerprint ? `, soft-binding ${perceptualFingerprint}` : ''})`);
}

const stat = fs.statSync(input);
let exampleOutput = output;
if (stat.isDirectory()) {
  const files = fs.readdirSync(input).filter((f) => /\.(jpe?g|png|webp|avif)$/i.test(f));
  for (const f of files) {
    const outPath = path.join(output, f.replace(/\.[^.]+$/, '') + '.archx');
    if (exampleOutput === output) exampleOutput = outPath;
    await protectOne(path.join(input, f), outPath);
  }
} else {
  await protectOne(input, output);
}

console.log('\nUse it in the browser:');
console.log(`  Archx.load.image('#hero', '/protected/${path.basename(exampleOutput)}', {`);
console.log(`    key: '<ARCHX_SCRAMBLE_KEY>'${aesKey ? `,\n    aesKey: '<ARCHX_AES_KEY>'  // deliver server-side/token-gated in production` : ''}`);
console.log('  });');
console.log('  // Keys are intentionally not echoed here. Inject them from your server-side secret store.');
if (generatedAesKey) console.log('\n🔑 Generated AES key (shown once; store it like a password):', aesKey);
