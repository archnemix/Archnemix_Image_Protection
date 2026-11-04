#!/usr/bin/env node
/**
 * Docs-consistency gate (v1.28).
 *
 * Every number the docs and website print about the code — version,
 * test counts, bundle size, SRI hash — is recomputed or cross-checked
 * here, so a doc line cannot silently contradict the code or another
 * doc. Run: npm run docs:check (also part of CI on Linux and Windows).
 *
 * Test-count honesty: node:test files register one test per top-level
 * `test(` call, so their counts are computed statically. The browser
 * suite executes a few checks inside loops, so its runtime total is a
 * verified baseline (BROWSER_RUNTIME) guarded by a static anchor: if
 * the number of `check(` call sites changes, the baseline must be
 * re-verified by a real run before this gate passes again.
 */
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');
const problems = [];
const fail = (msg) => problems.push(msg);

// ---- 1. one version everywhere ----
const pkg = JSON.parse(read('package.json'));
const versionJs = read('src/client/version.js').match(/VERSION\s*=\s*'([^']+)'/)?.[1];
const changelogTop = read('CHANGELOG.md').match(/^## \[([^\]]+)\]/m)?.[1];
if (pkg.version !== versionJs) fail(`version mismatch: package.json ${pkg.version} vs src/client/version.js ${versionJs}`);
if (pkg.version !== changelogTop) fail(`version mismatch: package.json ${pkg.version} vs CHANGELOG top entry ${changelogTop}`);
// The docs page prints the current version in its masthead; any full
// x.y.z token there must be the current release so it cannot rot.
for (const m of read('website/docs.html').matchAll(/\bv(\d+\.\d+\.\d+)\b/g)) {
  if (m[1] !== pkg.version) fail(`website/docs.html prints version v${m[1]}; current release is ${pkg.version}`);
}

// ---- 2. test counts ----
const countTop = (rel, re) => (read(rel).match(re) || []).length;
const unitStatic = countTop('tests/unit.test.mjs', /^test\(/gm);
const fuzzStatic = countTop('tests/fuzz.test.mjs', /^test\(/gm);
const BROWSER_STATIC_ANCHOR = 125; // `check(` call sites at last verified run
const BROWSER_RUNTIME = 129;       // checks executed at that run (loops add 4)
const browserStatic = countTop('tests/browser-test.mjs', /check\(/g);
if (browserStatic !== BROWSER_STATIC_ANCHOR) {
  fail(`browser suite shape changed (${browserStatic} check( call sites, verified baseline ${BROWSER_STATIC_ANCHOR}): run npm run test:browser, then update BROWSER_STATIC_ANCHOR/BROWSER_RUNTIME in tools/docs-check.mjs and every doc that prints the count`);
}
const readme = read('README.md');
if (!readme.includes(`${unitStatic} unit/integration tests`)) {
  fail(`README test count is stale: suite has ${unitStatic} unit/integration tests (+${fuzzStatic} fuzz)`);
}
if (!readme.includes(`${BROWSER_RUNTIME} checks in real headless Chromium`)) {
  fail(`README browser-check count is stale (verified runtime total: ${BROWSER_RUNTIME})`);
}
const siteIndex = read('website/index.html');
const stat = siteIndex.match(/(\d+)<span class="stat-of">\+(\d+)<\/span>/);
if (!stat) fail('website/index.html test stat not found (expected the Node+browser stat)');
else {
  if (Number(stat[1]) !== unitStatic + fuzzStatic) fail(`website Node-test stat ${stat[1]} != ${unitStatic + fuzzStatic} (unit ${unitStatic} + fuzz ${fuzzStatic})`);
  if (Number(stat[2]) !== BROWSER_RUNTIME) fail(`website browser-check stat ${stat[2]} != ${BROWSER_RUNTIME}`);
}

// ---- 2b. test-count claims anywhere in current-facing prose (G-1) ----
// v1.28's gate only checked README + the website stat; REVIEW_GUIDE and
// COMPATIBILITY then carried stale counts while the gate printed "all
// agree". Historical logs (RESEARCH.md, CHANGELOG.md, PAPERS.md) are
// exempt by design — their numbers are true at their version.
const PROSE_EXEMPT = new Set(['docs/RESEARCH.md', 'docs/PAPERS.md']);
const proseFiles = [
  ...fs.readdirSync(path.join(root, 'docs')).filter((f) => f.endsWith('.md')).map((f) => `docs/${f}`),
  'SECURITY.md', 'website/index.html', 'website/docs.html', 'website/technical.html', 'website/limits.html',
].filter((rel) => !PROSE_EXEMPT.has(rel) && fs.existsSync(path.join(root, rel)));
const COUNT_PATTERNS = [
  [/(\d+) browser checks/g, BROWSER_RUNTIME, 'browser checks'],
  [/(\d+)(?:\/\d+)? (?:real-)?Chromium checks/g, BROWSER_RUNTIME, 'Chromium checks'],
  [/(\d+) unit\/integration tests/g, unitStatic, 'unit tests'],
  [/(\d+)(?:\/\d+)? Node tests/g, unitStatic + fuzzStatic, 'total Node tests'],
  [/\((\d+) unit \+ \d+/g, unitStatic, 'unit tests in breakdown'],
  [/\(\d+ unit \+ (\d+) (?:seeded )?fuzz/g, fuzzStatic, 'fuzz tests in breakdown'],
];
for (const rel of proseFiles) {
  const text = read(rel);
  for (const [re, expected, label] of COUNT_PATTERNS) {
    for (const m of text.matchAll(re)) {
      if (Number(m[1]) !== expected) fail(`${rel} prints ${m[1]} for ${label}; the suites currently define ${expected}`);
    }
  }
}

// ---- 2c. website bench stats vs the recorded evidence artifact (G-2) ----
const evidencePath = path.join(root, 'docs/evidence/stego-bench.json');
if (!fs.existsSync(evidencePath)) {
  fail('docs/evidence/stego-bench.json missing — run: npm run demo:images && npm run bench:stego:evidence');
} else {
  const ev = JSON.parse(fs.readFileSync(evidencePath, 'utf8'));
  const slashStats = [...siteIndex.matchAll(/(\d+)<span class="stat-of">\/(\d+)<\/span>/g)]
    .map((m) => ({ n: Number(m[1]), d: Number(m[2]) }));
  const [recovery, falseAcc] = slashStats;
  if (!recovery || recovery.n !== ev.robust.found || recovery.d !== ev.robust.total) {
    fail(`website re-identification stat ${recovery ? `${recovery.n}/${recovery.d}` : '(not found)'} != bench evidence robust ${ev.robust.found}/${ev.robust.total} — re-run the bench or fix the page`);
  }
  if (!falseAcc || falseAcc.n !== ev.falsePositives.count || falseAcc.d !== ev.falsePositives.checks) {
    fail(`website false-accusation stat ${falseAcc ? `${falseAcc.n}/${falseAcc.d}` : '(not found)'} != bench evidence FP ${ev.falsePositives.count}/${ev.falsePositives.checks} — re-run the bench or fix the page`);
  }
  // The docs page quotes the same figures in prose ("85 of 99", "0 of 369").
  for (const m of read('website/docs.html').matchAll(/(\d+) of (\d+)/g)) {
    const pair = `${m[1]}/${m[2]}`;
    if (pair !== `${ev.robust.found}/${ev.robust.total}` && pair !== `${ev.falsePositives.count}/${ev.falsePositives.checks}`) {
      fail(`website/docs.html prints an unrecognized "N of M" figure (${m[0]}) — if it is a bench statistic it must match the evidence artifact (${ev.robust.found}/${ev.robust.total}, ${ev.falsePositives.count}/${ev.falsePositives.checks}); otherwise rephrase`);
    }
  }
}

// ---- 3. bundle size + SRI vs the real dist build ----
const distPath = path.join(root, 'dist', 'archx.min.js');
if (!fs.existsSync(distPath)) {
  fail('dist/archx.min.js missing — run npm run build before docs:check');
} else {
  const bytes = fs.readFileSync(distPath);
  const kib = (bytes.length / 1024).toFixed(1);
  const gz = (zlib.gzipSync(bytes).length / 1024).toFixed(1);
  if (!readme.includes(`${kib} KiB minified`)) fail(`README bundle size is stale: dist is ${kib} KiB minified`);
  if (!readme.includes(`${gz} KiB gzipped`)) fail(`README gzip size is stale: dist gzips to ${gz} KiB`);
  const sri = `sha384-${crypto.createHash('sha384').update(bytes).digest('base64')}`;
  for (const rel of ['README.md', 'website/index.html', 'website/technical.html', 'website/limits.html']) {
    for (const m of read(rel).matchAll(/sha384-[A-Za-z0-9+/=]{40,}/g)) {
      if (m[0] !== sri) fail(`${rel} prints a stale SRI hash (dist is ${sri})`);
    }
  }
}

// ---- 4. npm scripts referenced in docs must exist ----
const docFiles = ['README.md', ...fs.readdirSync(path.join(root, 'docs')).filter((f) => f.endsWith('.md')).map((f) => `docs/${f}`)];
for (const rel of docFiles) {
  for (const m of read(rel).matchAll(/npm run ([a-z0-9:_-]+)/gi)) {
    if (!pkg.scripts[m[1]]) fail(`${rel} references missing npm script "npm run ${m[1]}"`);
  }
}

// ---- 5. website: zero third-party subresources ----
for (const page of ['index.html', 'docs.html', 'technical.html', 'limits.html']) {
  const html = read(`website/${page}`);
  for (const m of html.matchAll(/<(?:link|script|img|source|iframe)\b[^>]*(?:src|href)\s*=\s*["']((?:https?:)?\/\/[^"']+)["']/gi)) {
    fail(`website/${page} loads a third-party subresource: ${m[1]}`);
  }
}

// ---- 6. banned absolute claims (negated/myth/citation contexts allowed) ----
// Scope: buyer-facing surfaces (README, website, and the IP-holder guide's
// claim advice). docs/RESEARCH.md and docs/PAPERS.md quote and dissect
// other people's claims, so they are intentionally out of scope here.
const BANNED = [/screenshot-proof/i, /un-?copyable/i, /100%\s*secure/i, /guaranteed to prevent/i, /impossible to (?:copy|steal|download)/i];
const NEGATED = /\b(not|never|no|nothing|nobody|neither|cannot|isn't|aren't|don't|doesn't|without|myth|avoid)\b/i;
for (const rel of ['README.md', 'docs/IP_HOLDER_GUIDE.md', 'website/index.html', 'website/docs.html', 'website/technical.html', 'website/limits.html']) {
  const lines = read(rel).split('\n');
  lines.forEach((line, i) => {
    for (const re of BANNED) {
      if (!re.test(line)) continue;
      if (/https?:\/\//.test(line)) continue; // citing an external title/URL
      // Negations often sit on the previous wrapped line.
      const context = `${lines[i - 1] || ''} ${line}`;
      if (NEGATED.test(context)) continue;
      fail(`${rel}:${i + 1} states an absolute claim Archx does not make: "${line.trim().slice(0, 120)}"`);
    }
  });
}

if (problems.length) {
  console.error(`docs:check FAILED (${problems.length} problem${problems.length === 1 ? '' : 's'}):`);
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
console.log(`docs:check OK — version ${pkg.version}, ${unitStatic}+${fuzzStatic} Node tests, ${BROWSER_RUNTIME} browser checks, docs/website/code agree.`);
