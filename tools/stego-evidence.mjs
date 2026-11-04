#!/usr/bin/env node
/**
 * Deterministic StegoMark evidence artifact (v1.29, gate G-2).
 *
 * The website prints two bench-derived numbers (robust-profile
 * recovery and the false-accusation sweep). Until now nothing checked
 * them after the day they were measured. This tool distills real bench
 * JSON into docs/evidence/stego-bench.json, and tools/docs-check.mjs
 * fails the build if the website drifts from that artifact. Regenerate
 * only by actually running the bench:
 *   npm run demo:images          (gallery corpus must exist)
 *   npm run bench:stego:evidence (runs matrix + false-positive sweep)
 * or reuse fresh bench output you just produced:
 *   node tools/stego-evidence.mjs --reuse-matrix m.json --reuse-fp f.json
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const argv = process.argv.slice(2);
const opt = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-stego-evidence-'));
let matrixPath = opt('--reuse-matrix');
let fpPath = opt('--reuse-fp');
if (!matrixPath) {
  matrixPath = path.join(tmp, 'matrix.json');
  console.log('running stego matrix (several minutes)…');
  execFileSync(process.execPath, [path.join(root, 'tools/stego-bench.mjs'), '--json', matrixPath], { cwd: root, stdio: 'inherit' });
}
if (!fpPath) {
  fpPath = path.join(tmp, 'fp.json');
  console.log('running false-positive sweep…');
  execFileSync(process.execPath, [path.join(root, 'tools/stego-bench.mjs'), '--fp', '--json', fpPath], { cwd: root, stdio: 'inherit' });
}

const matrix = JSON.parse(fs.readFileSync(matrixPath, 'utf8'));
const fp = JSON.parse(fs.readFileSync(fpPath, 'utf8'));
const tally = (profile) => {
  const mine = (matrix.cases || []).filter((c) => c.profile === profile);
  return { found: mine.filter((c) => c.found).length, total: mine.length };
};
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const evidence = {
  generatedBy: 'npm run bench:stego:evidence',
  packageVersion: pkg.version,
  config: matrix.config || null,
  robust: tally('robust'),
  standard: tally('standard'),
  falsePositives: {
    count: fp.falsePositives?.falsePositives ?? null,
    checks: fp.falsePositives?.checks ?? null,
  },
};
if (!evidence.robust.total || evidence.falsePositives.checks == null) {
  console.error('evidence extraction failed: bench JSON shape unexpected (was demo:images run first?)');
  process.exit(1);
}
// The full corpus has five kinds; without demo-masters/gallery the
// bench silently runs a subset (66 of 99) whose numbers must never
// become the recorded baseline.
const kinds = new Set((matrix.cases || []).map((c) => c.kind));
const missing = ['photo', 'graphic', 'flat', 'text', 'text-periodic'].filter((k) => !kinds.has(k));
if (missing.length) {
  console.error(`evidence refused: bench corpus is incomplete (missing kinds: ${missing.join(', ')}) — run npm run demo:images, then re-run the bench`);
  process.exit(1);
}
fs.mkdirSync(path.join(root, 'docs/evidence'), { recursive: true });
const out = path.join(root, 'docs/evidence/stego-bench.json');
fs.writeFileSync(out, JSON.stringify(evidence, null, 2) + '\n');
console.log(`wrote ${path.relative(root, out)}: robust ${evidence.robust.found}/${evidence.robust.total}, standard ${evidence.standard.found}/${evidence.standard.total}, FP ${evidence.falsePositives.count}/${evidence.falsePositives.checks}`);
