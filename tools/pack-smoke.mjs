#!/usr/bin/env node
/**
 * Release-artifact smoke test (review #7 P0.1/P2.20): the Git checkout
 * passing tests proves nothing about the published tarball. This packs
 * the package, installs it into a clean project, and exercises every
 * public entry point from the ARTIFACT — ESM, CJS, subpaths, the
 * forensic WORKER (the file whose omission from "files" shipped a
 * broken 1.15–1.17 feature), all three CLI bins, SRI, and a tsc
 * type-import check.
 *
 * Usage: node tools/pack-smoke.mjs   (needs npm registry access)
 */
import { execFileSync, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-pack-smoke-'));
const failures = [];
const step = (name, fn) => {
  try { fn(); console.log(`  ok  ${name}`); }
  catch (err) { failures.push(`${name}: ${err.message}`); console.log(`FAIL  ${name}: ${err.message}`); }
};
// Windows: npm/npx are .cmd shims, which execFile cannot spawn without a
// shell (and Node ≥ 20 refuses .cmd spawns without shell:true entirely).
// Routing just those two through the shell keeps the tool identical on
// Linux/macOS and runnable on Windows — the v1.28 CI parity gate caught
// this on its first run.
const IS_WIN = process.platform === 'win32';
const needsShell = (cmd) => IS_WIN && (cmd === 'npm' || cmd === 'npx');
const run = (cmd, args, opts = {}) => execFileSync(cmd, args, {
  encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], shell: needsShell(cmd), ...opts,
});

console.log(`pack-smoke workspace: ${work}`);
let tarball;
step('npm pack', () => {
  const out = run('npm', ['pack', '--json'], { cwd: repoRoot });
  const meta = JSON.parse(out.slice(out.indexOf('[')));
  tarball = path.join(repoRoot, meta[0].filename);
  const names = meta[0].files.map((f) => f.path);
  if (names.some((name) => name.endsWith('.map'))) {
    throw new Error('npm artifact contains large source maps; rebuild with external maps and exclude them from "files"');
  }
  for (const name of names.filter((file) => /^dist\/.*\.js$/.test(file))) {
    if (fs.readFileSync(path.join(repoRoot, name), 'utf8').includes('sourceMappingURL=')) {
      throw new Error(`${name} links to a source map that is intentionally absent from the npm artifact`);
    }
  }
  for (const required of ['server/detect-worker.js', 'server/middleware.js', 'server/scramble-image.js', 'server/ops.js',
    'server/detect-stego-cli.js', 'dist/archx.min.js', 'dist/archx.min.js.sri', 'types/index.d.ts',
    'docs/OPERATIONS.md', 'docs/PAPERS.md', 'examples/archx-showcase.html']) {
    if (!names.includes(required)) throw new Error(`tarball is missing ${required}`);
  }
  // README-relative links are part of the installed package documentation,
  // not just checkout-only navigation: catch future docs/files allowlist drift.
  for (const match of fs.readFileSync(path.join(repoRoot, 'README.md'), 'utf8').matchAll(/\[[^\]]*\]\(([^)]+)\)/g)) {
    const target = match[1].split(/[?#]/)[0];
    if (!target || target.startsWith('#') || /^[a-z][a-z0-9+.-]*:/i.test(target)) continue;
    const normalized = path.posix.normalize(target.replace(/^\.\//, ''));
    if (!names.includes(normalized) && !names.some((name) => name.startsWith(`${normalized.replace(/\/$/, '')}/`))) {
      throw new Error(`README links to '${target}', which is not shipped in the npm artifact`);
    }
  }
  // Structural guard (v1.29): every relative import in every shipped
  // server/src module must resolve to another shipped file. The
  // hand-maintained list above caught omissions one version late
  // (detect-worker in 1.15-1.17, ops.js pre-1.29); this invariant
  // catches the class, not the instance.
  const shipped = new Set(names);
  for (const name of names.filter((n) => /^(server|src)\/.*\.js$/.test(n))) {
    const text = fs.readFileSync(path.join(repoRoot, name), 'utf8');
    for (const m of text.matchAll(/(?:from|import)\s*\(\s*['"](\.[^'"]+)['"]|(?:from|import)\s+['"](\.[^'"]+)['"]|new URL\(\s*['"](\.[^'"]+)['"]\s*,\s*import\.meta\.url\s*\)/g)) {
      const spec = m[1] || m[2] || m[3];
      if (!spec) continue;
      const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(name), spec));
      if (!shipped.has(resolved)) {
        throw new Error(`tarball would break: ${name} imports '${spec}' -> ${resolved}, which is not shipped (add it to package.json "files")`);
      }
    }
  }
});

const appDir = path.join(work, 'app');
fs.mkdirSync(appDir);
step('clean install from tarball', () => {
  run('npm', ['init', '-y'], { cwd: appDir });
  run('npm', ['install', '--no-audit', '--no-fund', tarball, 'sharp@^0.35.5'], { cwd: appDir, timeout: 300_000 });
});

const pkg = JSON.parse(fs.readFileSync(path.join(repoRoot, 'package.json'), 'utf8'));
const name = pkg.name;
const smoke = `
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import Archx, { VERSION, embedStegoFingerprint, assayStegoCollusion } from '${name}';
import { createArchxMiddleware, detectStegoFingerprintInWorker, batchDetectStegoInWorker, closeStegoDetectWorker, formatPrometheusMetrics, createArchxHealthHandler, installArchxShutdown, createJsonEventLogger } from '${name}/server';
assert.equal(typeof formatPrometheusMetrics, 'function');
assert.equal(typeof createArchxHealthHandler, 'function');
assert.equal(typeof installArchxShutdown, 'function');
assert.equal(typeof createJsonEventLogger, 'function');
import {} from '${name}/server/scramble-image';
import {} from '${name}/build';
import {} from '${name}/redis';
import {} from '${name}/scramble';
assert.equal(typeof Archx.load.image, 'function');
assert.match(VERSION, /^\\d+\\.\\d+\\.\\d+$/);
assert.equal(VERSION, '${pkg.version}', 'exported VERSION must equal the packaged version');
const require = createRequire(import.meta.url);
const cjs = require('${name}');
assert.equal(typeof (cjs.default || cjs).load.image, 'function', 'CJS entry exposes the loader');
const W = 320, H = 240;
const px = new Uint8Array(W * H * 4);
for (let i = 0; i < W * H; i++) { const x = i % W, y = (i / W) | 0; px[i*4]=80+((x*3+y)%130); px[i*4+1]=90+((x+y*7)%110); px[i*4+2]=70+((x^y)%120); px[i*4+3]=255; }
const marked = embedStegoFingerprint(px, W, H, 'smoke-buyer', { key: 'smoke-key', profile: 'robust', strength: 6 });
const one = await detectStegoFingerprintInWorker(marked, W, H, { key: 'smoke-key', profile: 'robust' });
assert.equal(one.found, true, 'single worker detect works from the tarball');
const batch = await batchDetectStegoInWorker(marked, W, H, ['nope', 'smoke-key'], { profile: 'robust' });
assert.equal(batch.find((b) => b.key === 'smoke-key').result.found, true, 'batch worker detect works from the tarball');
const assay = assayStegoCollusion(marked, W, H, [{ id: 'a', payload: 'smoke-buyer' }, { id: 'b', payload: 'other' }], { key: 'smoke-key', profile: 'robust' });
assert.equal(assay.results[0].id, 'a');
closeStegoDetectWorker();
console.log('SMOKE-IMPORTS-OK', VERSION);
`;
fs.writeFileSync(path.join(appDir, 'smoke.mjs'), smoke);
step('ESM/CJS/subpath imports + worker detect from artifact', () => {
  const out = run('node', ['smoke.mjs'], { cwd: appDir, timeout: 120_000 });
  if (!out.includes('SMOKE-IMPORTS-OK')) throw new Error(`unexpected output: ${out.slice(-300)}`);
});

step('CLI bins run from artifact', () => {
  for (const bin of ['archx-detect', 'archx-protect', 'archx-build']) {
    const r = spawnSync('npx', [bin, '--help'], { cwd: appDir, encoding: 'utf8', timeout: 60_000, shell: IS_WIN });
    const text = `${r.stdout || ''}${r.stderr || ''}`;
    if (!/archx/i.test(text)) throw new Error(`${bin} --help produced no recognizable output (exit ${r.status})`);
  }
});

step('SRI matches shipped bundle', () => {
  const bundle = fs.readFileSync(path.join(appDir, 'node_modules', ...name.split('/'), 'dist/archx.min.js'));
  const sri = fs.readFileSync(path.join(appDir, 'node_modules', ...name.split('/'), 'dist/archx.min.js.sri'), 'utf8').trim();
  const actual = `sha384-${crypto.createHash('sha384').update(bundle).digest('base64')}`;
  if (actual !== sri) throw new Error('SRI mismatch');
});

step('TypeScript imports type-check against artifact', () => {
  // node_modules/.bin/tsc is a POSIX shell shim (tsc.cmd on Windows);
  // running the compiler's JS entry with this same Node works everywhere.
  const tsc = path.join(repoRoot, 'node_modules/typescript/bin/tsc');
  if (!fs.existsSync(tsc)) throw new Error('repo tsc not available');
  fs.writeFileSync(path.join(appDir, 'smoke.ts'), `
import Archx, { assayStegoCollusion } from '${name}';
import { createArchxMiddleware, batchDetectStegoInWorker } from '${name}/server';
const v: string = Archx ? 'x' : 'y';
void v; void assayStegoCollusion; void createArchxMiddleware; void batchDetectStegoInWorker;
`);
  run(process.execPath, [tsc, '--noEmit', '--strict', '--skipLibCheck', '--module', 'nodenext', '--moduleResolution', 'nodenext', '--target', 'es2022', 'smoke.ts'], { cwd: appDir, timeout: 120_000 });
});

if (tarball && fs.existsSync(tarball)) fs.rmSync(tarball);
if (failures.length) {
  console.error(`\npack-smoke FAILED (${failures.length}):\n- ${failures.join('\n- ')}`);
  process.exit(1);
}
console.log('\npack-smoke PASSED: the npm artifact is functionally equivalent to the checkout.');
