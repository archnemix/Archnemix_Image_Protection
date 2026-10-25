#!/usr/bin/env node
/**
 * StegoMark detector: test a suspect screenshot/export for an Archx blind
 * ownership fingerprint. No original image is required.
 *
 *   npx archx-detect suspect.png --key "same key used at embed time"
 *   npx archx-detect suspect.jpg --key "k" --expect "ORDER-1042"
 *   npx archx-detect suspect.jpg --secret "$ARCHX_SECRET" --image-id neon-portrait
 *
 * Exit code is 0 only when a fingerprint is confidently found (and, when
 * --expect is supplied, it matches). That makes the command scriptable in
 * takedown / monitoring pipelines.
 */
import fs from 'node:fs';
import sharp from 'sharp';
import { detectStegoFingerprint, stegoFingerprint } from '../src/scramble.js';
import { deriveStegoKey } from './middleware.js';

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
const input = args._[0];
if (!input || args.help) {
  console.log(`Usage: archx-detect <suspect image> [options]
  --key <s>          StegoMark key used at embed time (archx-protect default: its --key)
  --secret <s>       server secret; derive the key with --image-id (token-server marks)
  --image-id <id>    image id used with --secret
  --expect <payload> expected owner/order/viewer payload or 12-hex fingerprint
  --grid-x <n>       detector grid columns (default 24)
  --grid-y <n>       detector grid rows (default 16)
  --no-search        disable sub-cell offset search (faster, less crop-tolerant)
  --json             print machine-readable JSON only`);
  process.exit(input ? 0 : 1);
}

let key = args.key || '';
if (!key && args.secret && args['image-id']) key = deriveStegoKey(args['image-id'], args.secret);
if (!key && !args.json) {
  console.warn('⚠  No --key/--secret supplied: trying the empty key. Detection needs the embed-time key.');
}

const bytes = fs.readFileSync(input);
const { data, info } = await sharp(bytes).rotate().ensureAlpha().raw().toBuffer({ resolveWithObject: true });
const result = detectStegoFingerprint(new Uint8Array(data), info.width, info.height, {
  key,
  gridX: args['grid-x'] ? Number(args['grid-x']) : 24,
  gridY: args['grid-y'] ? Number(args['grid-y']) : 16,
  searchOffsets: !args['no-search'],
});

const expected = args.expect ? stegoFingerprint(args.expect) : null;
const matchesExpectation = expected ? result.fingerprint === expected : null;

if (args.json) {
  console.log(JSON.stringify({
    file: input,
    width: info.width,
    height: info.height,
    ...result,
    expected,
    matchesExpectation,
  }, null, 2));
} else if (result.found) {
  console.log(`✔ StegoMark FOUND in ${input}`);
  console.log(`  fingerprint : ${result.fingerprint}`);
  console.log(`  confidence  : ${result.confidence} (cell agreement ${result.agreement}, corrections ${result.corrections})`);
  if (expected) console.log(`  expected    : ${expected} ${matchesExpectation ? '— MATCH' : '— does NOT match'}`);
  console.log('  Look this fingerprint up in your issuance registry (onStegoIssue) to identify the source view.');
} else {
  console.log(`✘ No confident StegoMark found in ${input}`);
  console.log(`  best candidate: ${result.fingerprint} (confidence ${result.confidence}, CRC ${result.crcValid ? 'valid' : 'invalid'}, agreement ${result.agreement})`);
  console.log('  Wrong key/grid, heavy filtering/regeneration, severe cropping, or an unmarked image can all cause this.');
}

process.exit(result.found && (matchesExpectation !== false) ? 0 : 2);
