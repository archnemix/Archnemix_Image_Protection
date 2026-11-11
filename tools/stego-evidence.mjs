#!/usr/bin/env node
/**
 * Distill real StegoMark bench JSON into docs/evidence/stego-bench.json.
 * The artifact keeps the recovery counts connected to their corpus, per-call
 * budgets, observed wall-clock timings, false-positive sample bound, and host.
 * Run the matrix and wrong-key sweep, or reuse output produced by those runs:
 *   npm run demo:images
 *   npm run bench:stego:evidence
 *   node tools/stego-evidence.mjs --reuse-matrix m.json --reuse-fp f.json
 * When reusing results after a package-version bump, pass
 *   --measured-version 1.30.2
 * so the artifact does not claim the measurements came from the newer code.
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const argv = process.argv.slice(2);
const opt = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const defaultBudgets = { robust: 20_000, standard: 5_000 };
const defaultFpGeometryBudgetMs = 30_000;
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-stego-evidence-'));
let matrixPath = opt('--reuse-matrix');
let fpPath = opt('--reuse-fp');
if (!matrixPath) {
  matrixPath = path.join(tmp, 'matrix.json');
  console.log('running stego matrix (may take many minutes)…');
  execFileSync(process.execPath, [path.join(root, 'tools/stego-bench.mjs'), '--json', matrixPath], { cwd: root, stdio: 'inherit' });
}
if (!fpPath) {
  fpPath = path.join(tmp, 'fp.json');
  console.log('running false-positive sweep (full geometry checks are CPU-intensive)…');
  execFileSync(process.execPath, [path.join(root, 'tools/stego-bench.mjs'), '--fp', '--json', fpPath], { cwd: root, stdio: 'inherit' });
}

const matrix = JSON.parse(fs.readFileSync(matrixPath, 'utf8'));
const fp = JSON.parse(fs.readFileSync(fpPath, 'utf8'));
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const profileBudgetMs = { ...defaultBudgets, ...(matrix.config?.matrixBudgetMs || {}) };
const nearestRank = (values, p) => {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.max(0, Math.ceil(p * sorted.length) - 1)];
};
const summarize = (profile) => {
  const cases = (matrix.cases || []).filter((item) => item.profile === profile);
  const times = cases.map((item) => item.ms).filter(Number.isFinite);
  const byKind = {};
  for (const item of cases) {
    byKind[item.kind] ??= { found: 0, total: 0, timedOut: 0 };
    byKind[item.kind].total++;
    if (item.found) byKind[item.kind].found++;
    if (item.timedOut) byKind[item.kind].timedOut++;
  }
  return {
    found: cases.filter((item) => item.found).length,
    total: cases.length,
    timedOut: cases.filter((item) => item.timedOut).length,
    budgetMs: profileBudgetMs[profile],
    byKind,
    timingsMs: {
      p50: nearestRank(times, 0.50),
      p95: nearestRank(times, 0.95),
      p99: nearestRank(times, 0.99),
      max: times.length ? Math.max(...times) : null,
      sumOfDetectorCalls: times.reduce((sum, value) => sum + value, 0),
    },
  };
};
const deriveImages = () => {
  if (Array.isArray(matrix.corpus?.images)) return matrix.corpus.images;
  const byName = new Map();
  for (const item of matrix.cases || []) byName.set(item.image, { name: item.image, kind: item.kind });
  return [...byName.values()];
};
const images = deriveImages();
const imageCountsByKind = Object.fromEntries([...new Set(images.map((item) => item.kind))]
  .map((kind) => [kind, images.filter((item) => item.kind === kind).length]));
const transformNames = matrix.config?.matrixTransforms || [...new Set((matrix.cases || []).map((item) => item.transform))];
const fpChecks = fp.falsePositives?.checks ?? null;
const fpCount = fp.falsePositives?.falsePositives ?? null;
const fpNativeChecks = fp.falsePositives?.nativeChecks ?? 360; // 9 hosts × 40 wrong keys
const fpGeometryChecks = fp.falsePositives?.geometryChecks ?? 9; // 3 photos × 3 wrong keys
const measuredPackageVersion = opt('--measured-version') || matrix.packageVersion || pkg.version;
const host = matrix.environment || {
  node: process.version,
  platform: process.platform,
  arch: process.arch,
  logicalCpus: os.availableParallelism?.() || os.cpus().length,
  cpuModel: os.cpus()[0]?.model || null,
  totalMemoryBytes: os.totalmem(),
};

const evidence = {
  schemaVersion: 2,
  generatedBy: 'npm run bench:stego:evidence',
  measuredPackageVersion,
  currentPackageVersion: pkg.version,
  config: matrix.config || null,
  host,
  corpus: {
    imageCount: images.length,
    images,
    imageCountsByKind,
    transformsPerImage: transformNames.length,
    transformCases: transformNames,
    containsScreenshotCapture: false,
    notes: 'Three demo photos, three generated gallery graphics, one synthetic flat image, one synthetic periodic-bar stress image, and one SVG-rendered document. Fixed operations include crop+resize, transpose, and brightness+JPEG; there is no screenshot/camera capture and no general transform-chain claim.',
  },
  timing: {
    unit: 'milliseconds measured around each detector call with Date.now() (wall time)',
    matrixBudgetMs: profileBudgetMs,
    falsePositiveGeometryBudgetMs: matrix.config?.falsePositiveGeometryBudgetMs ?? defaultFpGeometryBudgetMs,
    matrixWallMs: matrix.benchmarkWallMs ?? null,
    falsePositiveSweepWallMs: fp.falsePositives?.sweepMs ?? null,
    robust: summarize('robust'),
    standard: summarize('standard'),
    runNote: opt('--duration-note') || null,
  },
  robust: summarize('robust'),
  standard: summarize('standard'),
  falsePositives: {
    count: fpCount,
    checks: fpChecks,
    upperBound95Percent: fp.falsePositives?.upperBound95 ?? (fpCount === 0 && fpChecks ? Math.round(30_000 / fpChecks) / 100 : null),
    nativeWrongKeyChecks: fpNativeChecks,
    geometryWrongKeyChecks: fpGeometryChecks,
    geometryBudgetMs: matrix.config?.falsePositiveGeometryBudgetMs ?? defaultFpGeometryBudgetMs,
  },
  limitations: [
    'Results are specific to this corpus, fixed transform cases, strength, layout, detector budgets, and host; they are not a universal survival or false-positive guarantee.',
    'Detector timeouts are reported separately and remain unsuccessful cases in the recovery denominator.',
    'Zero false positives in this finite wrong-key sweep has a one-sided 95% upper bound; it does not prove a zero false-positive rate.',
    'The matrix does not measure StegoMark recovery from screenshots, camera captures, arbitrary image-edit chains, real-world leaks, or collusion.',
  ],
};
if (!evidence.robust.total || !evidence.standard.total || evidence.falsePositives.checks == null) {
  console.error('evidence extraction failed: bench JSON shape unexpected (run npm run demo:images first?)');
  process.exit(1);
}
// The public benchmark claims are pinned to strength 6/layout 3 and the
// complete 9×11 corpus. Never replace that evidence with a smaller or
// differently budgeted run that happens to have the same JSON shape.
const missing = ['photo', 'graphic', 'flat', 'text', 'text-periodic'].filter((kind) => !imageCountsByKind[kind]);
const configurationMatches = matrix.config?.strength === 6 && matrix.config?.layoutVersion === 3 &&
  fp.config?.strength === matrix.config.strength && fp.config?.layoutVersion === matrix.config.layoutVersion;
const fullMatrix = evidence.robust.total === 99 && evidence.standard.total === 99;
const fullWrongKeySweep = evidence.falsePositives.checks === 369;
const screenshotCaseIncluded = transformNames.some((name) => /screenshot|camera/i.test(name));
if (!configurationMatches || !fullMatrix || !fullWrongKeySweep || screenshotCaseIncluded || missing.length || images.length !== 9 || transformNames.length !== 11) {
  console.error(`evidence refused: expected strength 6/layout 3, 9 images × 11 transforms, 99 cases/profile, and 369 wrong-key checks (got images=${images.length}, transforms=${transformNames.length}, robust=${evidence.robust.total}, standard=${evidence.standard.total}, wrongKeys=${evidence.falsePositives.checks}, screenshot/cameraCase=${screenshotCaseIncluded}, missing kinds: ${missing.join(', ')}) — run npm run demo:images and the default benches`);
  process.exit(1);
}
fs.mkdirSync(path.join(root, 'docs/evidence'), { recursive: true });
const out = path.join(root, 'docs/evidence/stego-bench.json');
fs.writeFileSync(out, JSON.stringify(evidence, null, 2) + '\n');
console.log(`wrote ${path.relative(root, out)}: robust ${evidence.robust.found}/${evidence.robust.total} (${evidence.robust.timedOut} timeouts), standard ${evidence.standard.found}/${evidence.standard.total}, FP ${evidence.falsePositives.count}/${evidence.falsePositives.checks}`);
