#!/usr/bin/env node
/**
 * StegoMark detector: test a suspect screenshot/export for an Archx blind
 * ownership fingerprint. No original image is required.
 *
 *   ARCHX_STEGO_KEY="<embed key>" npx archx-detect suspect.png
 *   ARCHX_STEGO_KEY="<embed key>" npx archx-detect suspect.jpg --expect "ORDER-1042"
 *   ARCHX_SECRET="<server secret>" npx archx-detect suspect.jpg --image-id neon-portrait
 *
 * Prefer environment variables over secret-bearing argv values.
 *
 * Exit code is 0 only when a fingerprint is confidently found (and, when
 * --expect is supplied, it matches). That makes the command scriptable in
 * takedown / monitoring pipelines.
 */
import fs from 'node:fs';
import sharp from 'sharp';
import {
  detectStegoFingerprint, legacyStegoFingerprint, stegoFingerprint, sniffImageInfo, decodeBmpImage,
  perceptualFingerprint, normalizePerceptualFingerprint, comparePerceptualFingerprints,
} from '../src/scramble.js';
import { deriveStegoKey } from './middleware.js';
import { configureSharpSecurity } from './scramble-image.js';

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

const args = parseArgs(process.argv.slice(2), new Set(['json', 'no-search', 'no-geometry', 'help']));
const input = args._[0];
if (!input || args.help) {
  console.log(`Usage: archx-detect <suspect image> [options]
  --key <s>          StegoMark key (prefer ARCHX_STEGO_KEY)
  --secret <s>       server secret (prefer ARCHX_SECRET); derive key with --image-id
  --image-id <id>    image id used with the server secret
  --expect <payload> expected owner/order/viewer payload or 12-hex fingerprint
  --expect-fingerprint <16hex> registered perceptual soft-binding fingerprint
  --max-distance <n> maximum perceptual Hamming distance 0–64 (default 10)
  --profile <p>      auto (default), standard, or robust
  --grid-x <n>       detector grid columns, integer 4–64 (profile default)
  --grid-y <n>       detector grid rows, integer 4–64 (profile default)
  --max-input-bytes <n> reject files above this size before reading (default 52428800)
  --no-search        disable sub-cell offset search (faster, less crop-tolerant)
  --no-geometry      disable crop scale/origin search (faster, less crop-tolerant)
  --json             print machine-readable JSON only`);
  process.exit(input ? 0 : 1);
}

let key = process.env.ARCHX_STEGO_KEY || args.key || '';
const serverSecret = process.env.ARCHX_SECRET || args.secret || '';
if (!key && serverSecret && args['image-id']) key = deriveStegoKey(args['image-id'], serverSecret);
if ((args.key || args.secret) && !args.json) {
  console.warn('⚠  Secret-bearing CLI arguments can leak via shell history/process lists; prefer ARCHX_STEGO_KEY or ARCHX_SECRET.');
}
if (!key && !args.json) {
  console.warn('⚠  No StegoMark key supplied: trying the empty key. Detection needs the embed-time key.');
}

const profile = args.profile || 'auto';
const gridX = args['grid-x'] ? Number(args['grid-x']) : undefined;
const gridY = args['grid-y'] ? Number(args['grid-y']) : undefined;
const maxInputBytes = args['max-input-bytes'] ? Number(args['max-input-bytes']) : 50 * 1024 * 1024;
if (!['auto', 'standard', 'robust'].includes(profile) ||
    (gridX !== undefined && (!Number.isInteger(gridX) || gridX < 4 || gridX > 64)) ||
    (gridY !== undefined && (!Number.isInteger(gridY) || gridY < 4 || gridY > 64)) ||
    !Number.isInteger(maxInputBytes) || maxInputBytes < 1024 || maxInputBytes > 500 * 1024 * 1024) {
  console.error('Archx detect: profile must be auto, standard, or robust; grid values must be integers from 4 to 64; max-input-bytes must be a bounded integer');
  process.exit(2);
}
const expectedPerceptual = args['expect-fingerprint']
  ? normalizePerceptualFingerprint(String(args['expect-fingerprint'])) : null;
const maxPerceptualDistance = args['max-distance'] ? Number(args['max-distance']) : 10;
if ((args['expect-fingerprint'] && !expectedPerceptual) ||
    !Number.isInteger(maxPerceptualDistance) || maxPerceptualDistance < 0 || maxPerceptualDistance > 64) {
  console.error('Archx detect: --expect-fingerprint must be 16 hex characters and --max-distance an integer from 0 to 64');
  process.exit(2);
}

let bytes;
let data;
let info;
let result;
let suspectPerceptualFingerprint;
try {
  // fstat + read through one descriptor (no stat/read race).
  const inputFd = fs.openSync(input, 'r');
  try {
    const stat = fs.fstatSync(inputFd);
    if (!stat.isFile() || stat.size < 1 || stat.size > maxInputBytes) {
      throw new Error('suspect file is empty, not a regular file, or above the byte limit');
    }
    bytes = fs.readFileSync(inputFd);
  } finally { fs.closeSync(inputFd); }
  const sniffed = sniffImageInfo(bytes);
  const detectable = new Set(['jpeg', 'png', 'webp', 'avif', 'gif', 'tiff', 'bmp']);
  if (!sniffed || !detectable.has(sniffed.format)) throw new Error('suspect file is not a supported raster image');
  if (sniffed.width && sniffed.height && sniffed.width * sniffed.height > 100_000_000) {
    throw new Error('suspect image exceeds the detector pixel limit');
  }
  if (sniffed.format === 'bmp') {
    // Sharp has no BMP input decoder. The core decoder accepts only bounded,
    // uncompressed 24/32-bit BI_RGB files and fails closed on anything else.
    const decoded = decodeBmpImage(bytes, { maxPixels: 100_000_000 });
    data = decoded.data;
    info = { width: decoded.width, height: decoded.height, channels: decoded.channels };
  } else {
    configureSharpSecurity(['jpeg', 'png', 'webp', 'avif', 'gif', 'tiff']);
    ({ data, info } = await sharp(bytes, {
      failOn: 'warning',
      limitInputPixels: 100_000_000,
      limitInputChannels: 4,
      sequentialRead: true,
      animated: false,
    }).timeout({ seconds: 30 }).rotate().ensureAlpha().raw().toBuffer({ resolveWithObject: true }));
  }
  if (!info?.width || !info?.height || info.channels !== 4 || data.length < info.width * info.height * 4) {
    throw new Error('suspect image did not decode to RGBA pixels');
  }
  result = detectStegoFingerprint(data, info.width, info.height, {
    key,
    profile,
    gridX,
    gridY,
    searchOffsets: !args['no-search'],
    searchGeometry: !args['no-geometry'],
  });
  // Compute the soft binding from a bounded thumbnail rather than walking a
  // possible 100 MP suspect image a second time in JavaScript.
  const thumb = await sharp(data, {
    raw: { width: info.width, height: info.height, channels: 4 },
  }).timeout({ seconds: 30 })
    .resize({ width: 512, height: 512, fit: 'inside', withoutEnlargement: true })
    .ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  suspectPerceptualFingerprint = perceptualFingerprint(thumb.data, thumb.info.width, thumb.info.height);
} catch (err) {
  if (args.json) console.log(JSON.stringify({ file: input, found: false, error: 'unreadable or unsupported suspect image' }, null, 2));
  else console.error(`Archx detect: ${err?.message || 'unreadable or unsupported suspect image'}`);
  process.exit(2);
}

const expected = args.expect ? stegoFingerprint(args.expect) : null;
// Marks embedded before 1.13 derived non-hex identity strings through
// the legacy hash pair; accept either derivation for --expect so old
// attributions keep resolving (12-hex expectations are identical).
const expectedAlternatives = expected ? [...new Set([expected, legacyStegoFingerprint(args.expect)])] : null;
const matchesExpectation = expectedAlternatives ? expectedAlternatives.includes(result.fingerprint) : null;
const perceptualComparison = expectedPerceptual
  ? comparePerceptualFingerprints(suspectPerceptualFingerprint, expectedPerceptual, { maxDistance: maxPerceptualDistance })
  : null;

if (args.json) {
  console.log(JSON.stringify({
    file: input,
    width: info.width,
    height: info.height,
    ...result,
    repaired: result.found && result.corrections > 0,
    evidenceNote: result.found && result.corrections > 0
      ? 'Repaired decode: corroborate before attributing (collusion can synthesize third-party fingerprints).'
      : undefined,
    expected,
    expectedAlternatives,
    matchesExpectation,
    perceptual: {
      fingerprint: suspectPerceptualFingerprint,
      expected: expectedPerceptual,
      ...(perceptualComparison || {}),
    },
  }, null, 2));
} else if (result.found) {
  console.log(`✔ StegoMark FOUND in ${input}`);
  console.log(`  fingerprint : ${result.fingerprint}`);
  console.log(`  profile     : ${result.profile || 'standard'}`);
  console.log(`  confidence  : ${result.confidence} (cell agreement ${result.agreement}, corrections ${result.corrections})`);
  if (result.geometry) console.log(`  geometry    : scale ${result.geometry.scaleX}×${result.geometry.scaleY}, origin ${result.geometry.originX},${result.geometry.originY}`);
  if (expected) console.log(`  expected    : ${expected} ${matchesExpectation ? '— MATCH' : '— does NOT match'}`);
  console.log(`  soft binding: ${suspectPerceptualFingerprint}${perceptualComparison ? ` (distance ${perceptualComparison.distance}/64 — ${perceptualComparison.match ? 'MATCH' : 'does NOT match'})` : ''}`);
  if (result.mirrored) console.log('  note        : mark was recovered from a horizontally flipped suspect.');
  // Repaired decodes are weaker evidence: the CRC corrector flipped bits to
  // reach a valid codeword, and under multi-buyer collusion averaging that
  // repair can synthesize a fingerprint belonging to none of the colluders.
  if (result.tagScheme === 'crc') {
    console.log('  ⚠ LEGACY CODEWORD: this mark uses the pre-v1.12 CRC tag (linear code).');
    console.log('    Collusion averaging can synthesize third-party fingerprints in legacy');
    console.log('    marks — corroborate before attributing, and re-issue with current code.');
  }
  if (result.corrections > 0) {
    console.log(`  ⚠ REPAIRED DECODE: ${result.corrections} bit(s) were corrected to reach a valid codeword.`);
    console.log('    Do NOT attribute from this alone — corroborate with the issuance registry,');
    console.log('    the perceptual soft binding above, visible marks, and delivery logs.');
  }
  console.log('  Look this fingerprint up in your issuance registry (onStegoIssue) to identify the source view.');
} else {
  console.log(`✘ No confident StegoMark found in ${input}`);
  console.log(`  best candidate: ${result.fingerprint} (confidence ${result.confidence}, CRC ${result.crcValid ? 'valid' : 'invalid'}, agreement ${result.agreement})`);
  console.log(`  soft binding: ${suspectPerceptualFingerprint}${perceptualComparison ? ` (distance ${perceptualComparison.distance}/64 — ${perceptualComparison.match ? 'MATCH' : 'does NOT match'})` : ''}`);
  console.log('  Wrong key/grid, heavy filtering/regeneration, severe cropping, or an unmarked image can all cause this.');
}

const stegoPassed = result.found && matchesExpectation !== false;
const success = expectedPerceptual
  ? (expected ? (stegoPassed && perceptualComparison.match) : perceptualComparison.match)
  : stegoPassed;
process.exit(success ? 0 : 2);
