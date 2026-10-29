#!/usr/bin/env node
/**
 * Repeatable StegoMark benchmark (review #7 P1.11-13). Emits
 * machine-readable JSON with per-case outcomes plus a human summary.
 * Modes:
 *   node tools/stego-bench.mjs [--json out.json] [--strength N]
 *   node tools/stego-bench.mjs --fp         false-positive sweep
 *   node tools/stego-bench.mjs --collusion  assay ranking benchmark
 * Detector calls run under maxTimeMs budgets; timedOut cases are
 * reported distinctly from clean misses. Numbers describe THIS
 * corpus and configuration only — not a universal survival rate.
 */
import fs from 'node:fs';
import path from 'node:path';
import sharp from 'sharp';
import {
  embedStegoFingerprint, detectStegoFingerprint, stegoFingerprint, assayStegoCollusion,
} from '../src/scramble.js';

const argv = process.argv.slice(2);
const opt = (name, fallback) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : fallback;
};
const STRENGTH = Number(opt('--strength', '6'));
const KEY = 'bench-stego-key';
const results = { config: { strength: STRENGTH, layoutVersion: 3, key: '(fixed bench key)' }, cases: [] };

async function loadRaw(file, width = 800) {
  const { data, info } = await sharp(file).resize(width).ensureAlpha().raw()
    .toBuffer({ resolveWithObject: true });
  return { buf: new Uint8Array(data), w: info.width, h: info.height };
}
function synthetic(kind, w = 800, h = 520) {
  const buf = new Uint8Array(w * h * 4);
  for (let i = 0; i < w * h; i++) {
    const x = i % w, y = (i / w) | 0;
    if (kind === 'flat') {
      buf[i * 4] = 150 + Math.min(60, (x + y) / 20); buf[i * 4 + 1] = 160; buf[i * 4 + 2] = 170;
    } else { // 'text': high-contrast bars simulating text/screenshot edges
      const on = ((x >> 3) + (y >> 4)) % 3 === 0;
      buf[i * 4] = on ? 30 : 235; buf[i * 4 + 1] = on ? 40 : 230; buf[i * 4 + 2] = on ? 60 : 225;
    }
    buf[i * 4 + 3] = 255;
  }
  return { buf, w, h };
}
const toRaw = async (pipe) => {
  const { data, info } = await pipe.ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  return { buf: new Uint8Array(data), w: info.width, h: info.height };
};

async function corpus() {
  const items = [];
  for (const f of ['aurora-valley.jpg', 'luxury-watch.jpg', 'neon-portrait.jpg']) {
    items.push({ name: f.replace('.jpg', ''), kind: 'photo', ...(await loadRaw(`demo-masters/${f}`)) });
  }
  const galleryDir = 'demo-masters/gallery';
  if (fs.existsSync(galleryDir)) {
    for (const f of fs.readdirSync(galleryDir).filter((x) => x.endsWith('.jpg')).slice(0, 3)) {
      items.push({ name: f.replace('.jpg', ''), kind: 'graphic', ...(await loadRaw(path.join(galleryDir, f), 640)) });
    }
  }
  items.push({ name: 'synthetic-flat', kind: 'flat', ...synthetic('flat') });
  items.push({ name: 'synthetic-text', kind: 'text', ...synthetic('text') });
  return items;
}

function psnr(a, b) {
  let mse = 0;
  for (let i = 0; i < a.length; i += 4) {
    for (let c = 0; c < 3; c++) { const d = a[i + c] - b[i + c]; mse += d * d; }
  }
  mse /= (a.length / 4) * 3;
  return mse === 0 ? Infinity : Math.round(10 * Math.log10((255 * 255) / mse) * 10) / 10;
}

async function transforms(marked, w, h) {
  const base = () => sharp(Buffer.from(marked), { raw: { width: w, height: h, channels: 4 } });
  const cx = (f) => Math.round(w * (1 - f) / 2), cy = (f) => Math.round(h * (1 - f) / 2);
  return [
    ['identity', { buf: marked, w, h }],
    ['jpeg80', await toRaw(base().jpeg({ quality: 80 }))],
    ['jpeg50', await toRaw(base().jpeg({ quality: 50 }))],
    ['resize0.7', await toRaw(base().resize(Math.round(w * 0.7)))],
    ['center0.85', await toRaw(base().extract({ left: cx(0.85), top: cy(0.85), width: Math.round(w * 0.85), height: Math.round(h * 0.85) }).resize(w, h))],
    ['center0.7', await toRaw(base().extract({ left: cx(0.7), top: cy(0.7), width: Math.round(w * 0.7), height: Math.round(h * 0.7) }).resize(w, h))],
    ['corner0.7', await toRaw(base().extract({ left: 0, top: 0, width: Math.round(w * 0.7), height: Math.round(h * 0.7) }).resize(w, h))],
    ['rot90', await toRaw(base().rotate(90))],
    ['flop', await toRaw(base().flop())],
    ['transposeMain', await toRaw(base().rotate(90).flip())],
    ['brightness', await toRaw(base().modulate({ brightness: 1.15, saturation: 0.85 }).jpeg({ quality: 80 }))],
  ];
}

async function runMatrix() {
  const items = await corpus();
  for (const item of items) {
    for (const profile of ['robust', 'standard']) {
      const marked = embedStegoFingerprint(item.buf, item.w, item.h, `bench-${item.name}`, {
        key: KEY, profile, strength: STRENGTH, layoutVersion: 3,
      });
      const quality = psnr(item.buf, marked);
      for (const [tName, suspect] of await transforms(marked, item.w, item.h)) {
        const t0 = Date.now();
        const hit = detectStegoFingerprint(suspect.buf, suspect.w, suspect.h, {
          key: KEY, profile,
          searchGeometry: profile === 'robust',
          searchOffsets: true,
          maxTimeMs: profile === 'robust' ? 20_000 : 5_000,
        });
        results.cases.push({
          image: item.name, kind: item.kind, profile, transform: tName,
          found: hit.found && hit.fingerprint === stegoFingerprint(`bench-${item.name}`),
          timedOut: !!hit.timedOut, ms: Date.now() - t0, psnr: quality,
          erasureDecoded: !!hit.erasureDecoded, corrections: hit.corrections ?? 0,
        });
        process.stdout.write('.');
      }
    }
  }
  console.log('');
}

async function runFp() {
  const items = await corpus();
  let checks = 0, fps = 0;
  // Native-screen wrong-key sweep (fast): the first gate every
  // forensic search must pass. 0/N => 95% upper bound ~= 3/N.
  for (const item of items) {
    for (let k = 0; k < 40; k++) {
      const hit = detectStegoFingerprint(item.buf, item.w, item.h, {
        key: `wrong-key-${k}`, profile: 'robust', searchOffsets: true,
      });
      checks++;
      if (hit.found) fps++;
    }
  }
  // Full-geometry wrong-key on marked suspects (slow path, small N).
  for (const item of items.slice(0, 3)) {
    const marked = embedStegoFingerprint(item.buf, item.w, item.h, 'fp-victim', {
      key: KEY, profile: 'robust', strength: STRENGTH,
    });
    for (let k = 0; k < 3; k++) {
      const hit = detectStegoFingerprint(marked, item.w, item.h, {
        key: `geometry-wrong-${k}`, profile: 'robust', searchGeometry: true, maxTimeMs: 30_000,
      });
      checks++;
      if (hit.found) fps++;
      process.stdout.write('.');
    }
  }
  results.falsePositives = { checks, falsePositives: fps, upperBound95: fps === 0 ? Math.round(30000 / checks) / 100 : null };
  console.log(`\nFP sweep: ${fps}/${checks} false positives`);
}

async function runCollusion() {
  const items = await corpus();
  const item = items[0];
  const names = ['alice', 'bob', 'carol', 'dave', 'erin', 'frank', 'grace', 'heidi'];
  const marks = names.map((n) => embedStegoFingerprint(item.buf, item.w, item.h, n, {
    key: KEY, profile: 'robust', strength: STRENGTH,
  }));
  results.collusion = [];
  for (const k of [2, 3, 4]) {
    const avg = new Uint8Array(item.buf.length);
    for (let i = 0; i < avg.length; i++) {
      let sum = 0;
      for (let j = 0; j < k; j++) sum += marks[j][i];
      avg[i] = Math.round(sum / k);
    }
    const suspect = await toRaw(sharp(Buffer.from(avg), { raw: { width: item.w, height: item.h, channels: 4 } }).jpeg({ quality: 85 }));
    const assay = assayStegoCollusion(suspect.buf, suspect.w, suspect.h,
      names.map((n) => ({ id: n, payload: n })), { key: KEY, profile: 'robust' });
    const participants = new Set(names.slice(0, k));
    const ranks = assay.results.map((r, i) => ({ id: r.id, rank: i + 1, z: r.zScore, participant: participants.has(r.id) }));
    results.collusion.push({ k, ranks });
    const lowestParticipant = Math.max(...ranks.filter((r) => r.participant).map((r) => r.rank));
    const topInnocent = ranks.find((r) => !r.participant);
    console.log(`collusion k=${k}: lowest participant rank ${lowestParticipant}/${names.length}, top innocent ${topInnocent.id} z=${topInnocent.z}`);
  }
}

if (argv.includes('--fp')) await runFp();
else if (argv.includes('--collusion')) await runCollusion();
else await runMatrix();

if (results.cases.length) {
  for (const profile of ['robust', 'standard']) {
    const mine = results.cases.filter((c) => c.profile === profile);
    const found = mine.filter((c) => c.found).length;
    console.log(`${profile}: ${found}/${mine.length} recovered (strength ${STRENGTH})`);
    const byKind = {};
    for (const c of mine) { byKind[c.kind] ??= [0, 0]; byKind[c.kind][1]++; if (c.found) byKind[c.kind][0]++; }
    for (const [kind, [f, n]] of Object.entries(byKind)) console.log(`  ${kind}: ${f}/${n}`);
  }
}
const out = opt('--json', null);
if (out) fs.writeFileSync(out, JSON.stringify(results, null, 2));
