#!/usr/bin/env node
/** Create a secret-manager handoff and staged key-rotation timeline. */
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

function parse(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help' || arg === '-h') { out.help = true; continue; }
    if (!arg.startsWith('--') || !argv[i + 1] || argv[i + 1].startsWith('--')) {
      throw new Error(`invalid argument near ${arg}`);
    }
    out[arg.slice(2)] = argv[++i];
  }
  return out;
}

const usage = `Usage: node tools/signing-key-rotation.mjs \\
  --current-id <active-kid> --ttl-sec <max-token-ttl> \\
  --activate-at <ISO-8601 UTC> --output <secure-new-secret-file> [--grace-sec 300]

Writes a mode-0600 secret-manager handoff file with a fresh 256-bit key and
stage/activate/retire timestamps. It never changes a live keyring or deploys
keys; follow docs/OPERATIONS.md §3 for staged rollout and secret-manager use.`;

const args = parse(process.argv.slice(2));
if (args.help) { console.log(usage); process.exit(0); }
const currentId = args['current-id'];
const output = args.output;
const ttlSec = Number(args['ttl-sec']);
const graceSec = args['grace-sec'] === undefined ? 300 : Number(args['grace-sec']);
const activateAtText = args['activate-at'];
const activateAtMs = Date.parse(activateAtText);
if (!currentId || !/^[A-Za-z0-9._-]{1,64}$/.test(currentId)) throw new Error('--current-id must be a 1–64 character key ID');
if (!output) throw new Error('--output is required; refusing to print secret material to stdout');
if (!Number.isSafeInteger(ttlSec) || ttlSec < 5 || ttlSec > 900) throw new Error('--ttl-sec must be an integer from 5 to 900');
if (!Number.isSafeInteger(graceSec) || graceSec < 0 || graceSec > 86400) throw new Error('--grace-sec must be an integer from 0 to 86400');
if (typeof activateAtText !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(activateAtText) ||
    !Number.isFinite(activateAtMs) || activateAtMs < Date.now() + 60_000) {
  throw new Error('--activate-at must be an ISO-8601 UTC time ending in Z and at least one minute in the future');
}
const activateAt = new Date(activateAtMs);
// Authorization callbacks may extend issued tokens up to the library's
// hard ceiling (900 s), so never generate an earlier retirement deadline.
const effectiveMaxTtlSec = Math.max(ttlSec, 900);
const retireAt = new Date(activateAtMs + (effectiveMaxTtlSec + graceSec) * 1000);
const timestamp = activateAt.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
const newId = `k-${timestamp}-${crypto.randomBytes(3).toString('hex')}`;
const outputPath = path.resolve(output);
fs.mkdirSync(path.dirname(outputPath), { recursive: true, mode: 0o700 });
const handoff = {
  format: 'archx-signing-key-rotation-v1',
  currentSecretId: currentId,
  newSecretId: newId,
  newSecret: crypto.randomBytes(32).toString('base64url'),
  keyBytes: 32,
  generatedAt: new Date().toISOString(),
  stageAt: new Date().toISOString(),
  activateAt: activateAt.toISOString(),
  retireOldKeyNoEarlierThan: retireAt.toISOString(),
  schedule: {
    activateSecretId: newId,
    activateAt: activateAt.toISOString(),
    retireSecretId: currentId,
    retireAt: retireAt.toISOString(),
    graceSec,
  },
  requiredActions: [
    'Store newSecret in the secret manager under newSecretId; never commit or log this handoff.',
    'Stage old and new keys on every instance and pass schedule to signingKeySchedule.',
    'Middleware activates newSecretId at activateAt and stops verifying currentSecretId at retireAt.',
    'Confirm all instances loaded the same schedule and have synchronized UTC clocks.',
  ],
};
const fd = fs.openSync(outputPath, 'wx', 0o600);
try { fs.writeFileSync(fd, `${JSON.stringify(handoff, null, 2)}\n`); }
finally { fs.closeSync(fd); }
fs.chmodSync(outputPath, 0o600);
console.log(JSON.stringify({
  output: outputPath,
  currentSecretId: currentId,
  newSecretId: newId,
  stageAt: handoff.stageAt,
  activateAt: handoff.activateAt,
  retireOldKeyNoEarlierThan: handoff.retireOldKeyNoEarlierThan,
  effectiveMaxTtlSec,
  reminder: 'Securely import the handoff into your secret manager and remove the local file; this tool does not deploy or activate keys.',
}, null, 2));
