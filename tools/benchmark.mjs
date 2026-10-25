#!/usr/bin/env node
/**
 * Server-side cost benchmarks: how expensive is it to protect an image?
 * (Browser-side gallery numbers are measured by tests/browser-test.mjs.)
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import sharp from 'sharp';
import { buildScramblePlan, scramblePixels } from '../src/scramble.js';
import { scrambleImage } from '../server/scramble-image.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function bench(name, fn, runs = 5) {
  return (async () => {
    await fn(); // warm-up
    const times = [];
    for (let i = 0; i < runs; i++) {
      const t0 = performance.now();
      await fn();
      times.push(performance.now() - t0);
    }
    times.sort((a, b) => a - b);
    const median = times[Math.floor(times.length / 2)];
    console.log(`  ${name.padEnd(58)} median ${median.toFixed(1)} ms  (min ${times[0].toFixed(1)}, max ${times.at(-1).toFixed(1)})`);
    return median;
  })();
}

console.log('Archnemix benchmarks\n--------------------');

// 1) pure pixel scramble throughput (the fundamental operation)
for (const [w, h] of [[800, 533], [1600, 1067], [1920, 1080]]) {
  const pw = Math.ceil(w / 8) * 8, ph = Math.ceil(h / 8) * 8;
  const raw = new Uint8Array(pw * ph * 4);
  for (let i = 0; i < raw.length; i += 997) raw[i] = i % 256;
  const plan = buildScramblePlan(8, 'bench');
  const ms = await bench(`scramblePixels ${pw}×${ph} (${((pw * ph) / 1e6).toFixed(1)} MP)`, () => scramblePixels(raw, pw, ph, plan, 'scramble'), 4);
  console.log(`      -> ${((pw * ph) / 1e6 / (ms / 1000)).toFixed(0)} MP/s`);
}

// 2) full server pipeline on a real photo master
const masterPath = path.join(root, 'demo-masters/aurora-valley.jpg');
if (fs.existsSync(masterPath)) {
  const master = fs.readFileSync(masterPath);
  const meta = await sharp(master).metadata();
  console.log(`\n  master: aurora-valley.jpg ${meta.width}×${meta.height}, ${(master.length / 1024).toFixed(0)} kB`);
  for (const maxWidth of [480, 900, 1600]) {
    let out;
    await bench(`scrambleImage -> ${maxWidth}px .archx (downscale+scramble+WebP)`, async () => {
      out = await scrambleImage(master, { key: 'bench-key', grid: 8, maxWidth, quality: 82 });
    }, 4);
    console.log(`      -> payload ${(out.bytes.length / 1024).toFixed(0)} kB (served from server cache after first hit)`);
  }
  const { generateKeyBase64 } = await import('../src/scramble.js');
  const aesKey = generateKeyBase64();
  await bench('scrambleImage -> 900px .archx + AES-GCM encryption', async () => {
    await scrambleImage(master, { key: 'bench-key', grid: 8, maxWidth: 900, quality: 82, aesKey });
  }, 4);
}

// 3) bundle size
for (const f of ['dist/archx.min.js', 'dist/archx.esm.js']) {
  const p = path.join(root, f);
  if (fs.existsSync(p)) {
    const { gzipSync } = await import('node:zlib');
    const buf = fs.readFileSync(p);
    console.log(`\n  ${f}: ${(buf.length / 1024).toFixed(1)} kB (${(gzipSync(buf).length / 1024).toFixed(1)} kB gzipped)`);
  }
}
console.log('\nBrowser cost per image (measured in tests): 1 fetch + 1 createImageBitmap decode +');
console.log('64 drawImage tile copies (shield) — no per-pixel JS. Vault = 1 GPU texture upload.');
