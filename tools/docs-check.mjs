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
for (const page of ['index.html', 'technical.html', 'limits.html']) {
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
for (const rel of ['README.md', 'docs/IP_HOLDER_GUIDE.md', 'website/index.html', 'website/technical.html', 'website/limits.html']) {
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
