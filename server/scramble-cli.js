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
import { assayStegoEmbed } from '../src/scramble.js';
import { generateOwnershipKeyPair } from './ownership.js';

function parseArgs(argv, booleanFlags = new Set()) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith('--')) { out._.push(a); continue; }
    const eq = a.indexOf('=');
    if (eq !== -1) {
      const name = a.slice(2, eq); const value = a.slice(eq + 1);
      out[name] = booleanFlags.has(name) && (value === 'true' || value === 'false') ? value === 'true' : value;
      continue;
    }
    const name = a.slice(2);
    const next = argv[i + 1];
    if (booleanFlags.has(name)) {
      // Boolean flags never swallow the next positional (the file path);
      // an explicit 'true'/'false' literal is honoured as the value.
      if (next === 'true' || next === 'false') { out[name] = next === 'true'; i++; }
      else out[name] = true;
    } else if (next !== undefined && !next.startsWith('--')) { out[name] = next; i++; }
    else out[name] = true;
  }
  return out;
}

const args = parseArgs(process.argv.slice(2), new Set(['encrypt', 'lossless', 'help', 'assay', 'assay-no-verify', 'json']));
const [input, output] = args._;
if (args['gen-ownership-key']) {
  const pair = generateOwnershipKeyPair();
  console.log('# Archx ownership key pair — store the PRIVATE key like a signing secret.');
  console.log('# ARCHX_OWNERSHIP_PRIVATE_KEY (server/CLI only, never ship to browsers):');
  console.log(pair.privateKey);
  console.log('# ARCHX_OWNERSHIP_PUBLIC_KEY (publish freely; used by archx-detect --verify-ownership):');
  console.log(pair.publicKey);
  process.exit(0);
}
if (args.assay) {
  // Pre-flight embed assay (v1.19): measure the REAL distortion of the
  // current embedder on THIS image and optionally self-verify detector
  // recovery, before committing a catalog to StegoMark settings. Exit 0 =
  // verified (or --assay-no-verify), 2 = no self-verifying strength found.
  if (!input) { console.error('Usage: archx-protect <input image> --assay [--stego-profile robust] [--stego-strength 6] [--json]'); process.exit(1); }
  const assayProfile = args['stego-profile'] || 'robust';
  const assayStrength = args['stego-strength'] ? Number(args['stego-strength']) : 6;
  const assayGridX = args['stego-grid-x'] ? Number(args['stego-grid-x']) : undefined;
  const assayGridY = args['stego-grid-y'] ? Number(args['stego-grid-y']) : undefined;
  if (!['standard', 'robust'].includes(assayProfile) ||
      !Number.isInteger(assayStrength) || assayStrength < 1 || assayStrength > 16 ||
      (assayGridX !== undefined && (!Number.isInteger(assayGridX) || assayGridX < 4 || assayGridX > 64)) ||
      (assayGridY !== undefined && (!Number.isInteger(assayGridY) || assayGridY < 4 || assayGridY > 64))) {
    console.error('Archx assay: --stego-profile must be standard or robust; --stego-strength 1-16; grids 4-64');
    process.exit(1);
  }
  const maxInputBytes = args['max-input-bytes'] ? Number(args['max-input-bytes']) : 50 * 1024 * 1024;
  const fd = fs.openSync(input, 'r');
  let bytes;
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > maxInputBytes) throw new Error(`input is not a regular file within the ${maxInputBytes}-byte limit`);
    bytes = fs.readFileSync(fd);
  } finally { fs.closeSync(fd); }
  const sharpModule = await import('sharp');
  const sharp = sharpModule.default || sharpModule;
  let pipe = sharp(bytes, { failOn: 'error', limitInputPixels: 40_000_000 }).rotate();
  if (args['max-width']) pipe = pipe.resize({ width: Number(args['max-width']), withoutEnlargement: true });
  const { data, info } = await pipe.ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const report = assayStegoEmbed(new Uint8Array(data), info.width, info.height, {
    key: process.env.ARCHX_STEGO_KEY || args['stego-key'] || 'archx-assay-probe',
    profile: assayProfile, strength: assayStrength,
    gridX: assayGridX, gridY: assayGridY,
    verify: !args['assay-no-verify'],
  });
  const result = { file: input, width: info.width, height: info.height, ...report };
  if (args.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`Assay ${input} (${info.width}x${info.height}, profile ${report.profile}, strength ${report.strength})`);
    console.log(`  measured PSNR ${report.psnr} dB, max channel delta ${report.maxChannelDelta}, content ${report.contentClass}`);
    console.log(`  smooth cells ${(report.smoothFraction * 100).toFixed(0)}%, binary cells ${(report.binaryFraction * 100).toFixed(0)}%, grid ${report.grid.x}x${report.grid.y}`);
    if (report.verifiedAtStrength !== null) console.log(`  detector self-verified at strength ${report.verifiedAtStrength} (recommended: ${report.recommendedStrength})`);
    else if (!args['assay-no-verify']) console.log('  detector did NOT self-verify at any strength (exit 2)');
    for (const w of report.warnings) console.log(`  ⚠ ${w}`);
  }
  process.exit(args['assay-no-verify'] || report.verifiedAtStrength !== null ? 0 : 2);
}
if (!input || !output || args.help) {
  console.log(`Usage: archx-protect <input image|folder> <output .archx|folder> [options]
  --key <secret>       scramble key (prefer ARCHX_SCRAMBLE_KEY; argv secrets can leak)
  --grid <n>           tiles per side (default 8)
  --plan-version <1|2> scramble plan seed strength (1 = legacy, 2 = 128-bit; default 2)
  --max-width <px>     down-scale master to this width first (default 1600)
  --quality <1-100>    WebP/JPEG quality (default 95; use --lossless for exact pixels)
  --lossless           lossless WebP/PNG at the delivered size (larger payload)
  --format <fmt>       webp (default), png, jpeg, or avif
  --encrypt            AES-GCM-encrypt (ARCHX_AES_KEY if set; otherwise prints one generated key once)
  --watermark <text>   bake a visible watermark in before scrambling
  --forensic-seed <s>  forensic seed (prefer ARCHX_FORENSIC_SEED)
  --stego <payload>    bake a blind StegoMark ownership fingerprint (detect later with archx-detect)
  --ownership-owner <name> embed signed ownership metadata (needs
                       ARCHX_OWNERSHIP_PRIVATE_KEY, an Ed25519 PEM; verify
                       later with archx-detect --verify-ownership)
  --gen-ownership-key  print a fresh Ed25519 ownership key pair and exit
  --stego-key <s>      StegoMark key (required with --stego; prefer ARCHX_STEGO_KEY; MUST differ from the scramble key)
  --stego-strength <n> StegoMark strength 1–16 (default 6; higher = tougher, slightly more visible)
  --stego-profile <p> standard (default) or robust low-frequency forensic profile
  --stego-grid-x <n>  StegoMark grid columns 4–64 (profile default)
  --stego-grid-y <n>  StegoMark grid rows 4–64 (profile default)
  --max-input-bytes <n> reject masters above this size (default 52428800)
  --max-input-pixels <n> reject masters above this pixel budget (default 40000000)
  --timeout-sec <n> Sharp processing timeout per image (default 10)
  --assay              pre-flight: measure real embed PSNR/content class for one
                       image and self-verify detector recovery (no output file;
                       exit 2 when no strength self-verifies). --json for JSON.`);
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
if (args['ownership-owner'] && !process.env.ARCHX_OWNERSHIP_PRIVATE_KEY) {
  console.warn('⚠  --ownership-owner without ARCHX_OWNERSHIP_PRIVATE_KEY: embedding UNSIGNED copyright metadata only (no verifiable claim). Generate a key with --gen-ownership-key.');
}
if (args.stego && !(process.env.ARCHX_STEGO_KEY || args['stego-key'])) {
  console.error('Archx protect: --stego requires a dedicated forensic key (ARCHX_STEGO_KEY or --stego-key). It is never defaulted to the scramble key: wherever a client can unscramble, that key is public, and keying the watermark with it would let anyone remove or forge marks.');
  process.exit(1);
}
const opts = {
  key,
  grid: args.grid ? Number(args.grid) : 8,
  planVersion: args['plan-version'] ? Number(args['plan-version']) : 2,
  maxWidth: args['max-width'] ? Number(args['max-width']) : 1600,
  quality: args.quality === 'lossless' ? 'lossless' : (args.quality ? Number(args.quality) : 95),
  lossless: !!args.lossless,
  format: args.format || 'webp',
  aesKey,
  watermark: args.watermark || null,
  forensicSeed: process.env.ARCHX_FORENSIC_SEED || args['forensic-seed'] || null,
  stegoPayload: args.stego || null,
  ownership: args['ownership-owner'] ? {
    owner: String(args['ownership-owner']),
    privateKey: process.env.ARCHX_OWNERSHIP_PRIVATE_KEY || null,
  } : null,
  stegoKey: process.env.ARCHX_STEGO_KEY || args['stego-key'] || null,
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
  const fileOpts = opts.ownership
    ? { ...opts, ownership: { ...opts.ownership, imageId: path.basename(inPath) } }
    : opts;
  const { bytes, header, stegoFingerprint, perceptualFingerprint, ownershipToken } = await scrambleImage(inputBytes, fileOpts);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, bytes);
  console.log(`✔ ${inPath} -> ${outPath}  (${header.w}×${header.h}, grid ${header.grid}, ${(bytes.length / 1024).toFixed(0)} kB${stegoFingerprint ? `, StegoMark ${stegoFingerprint} (${stegoProfile})` : ''}${perceptualFingerprint ? `, soft-binding ${perceptualFingerprint}` : ''}${ownershipToken ? ', ownership claim embedded' : ''})`);
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
