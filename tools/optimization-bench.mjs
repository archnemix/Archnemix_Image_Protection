#!/usr/bin/env node
/**
 * Optimization-round harness: measures the same server and browser costs
 * before/after a change so deltas are comparable on one machine.
 *
 *   node --expose-gc tools/optimization-bench.mjs --out=/tmp/perf-before.json
 *   node --expose-gc tools/optimization-bench.mjs --out=/tmp/perf-after.json
 *   node tools/optimization-bench.mjs --compare=/tmp/perf-before.json,/tmp/perf-after.json
 *
 * Server metrics: cold-transform wall time, process CPU per image, peak-RSS
 * delta, payload bytes, scramble throughput, warm mint+redeem throughput and
 * batch-mint latency. Browser metrics (real Chromium): single-image
 * time-to-paint for shield/vault, 100-image gallery wall time / request
 * counts / main-thread task time / JS heap, and vault idle rAF rate.
 * Numbers are regression signals on the local machine, not capacity claims.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { gzipSync } from 'node:zlib';
import sharp from 'sharp';
import { scrambleImage } from '../server/scramble-image.js';
import { buildScramblePlan, scramblePixels, generateKeyBase64 } from '../src/scramble.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = Object.fromEntries(process.argv.slice(2).map((a) => {
  const [k, v] = a.replace(/^--/, '').split('=');
  return [k, v ?? true];
}));

if (args.compare) {
  const [beforePath, afterPath] = String(args.compare).split(',');
  const before = JSON.parse(fs.readFileSync(beforePath, 'utf8'));
  const after = JSON.parse(fs.readFileSync(afterPath, 'utf8'));
  const flat = (obj, prefix = '', out = {}) => {
    for (const [k, v] of Object.entries(obj ?? {})) {
      if (v && typeof v === 'object') flat(v, `${prefix}${k}.`, out);
      else if (typeof v === 'number') out[`${prefix}${k}`] = v;
    }
    return out;
  };
  const b = flat(before);
  const a = flat(after);
  console.log(`${'metric'.padEnd(56)} ${'before'.padStart(12)} ${'after'.padStart(12)} ${'change'.padStart(10)}`);
  for (const key of Object.keys(b).sort()) {
    if (!(key in a)) continue;
    const delta = b[key] === 0 ? 0 : ((a[key] - b[key]) / b[key]) * 100;
    console.log(`${key.padEnd(56)} ${b[key].toFixed(2).padStart(12)} ${a[key].toFixed(2).padStart(12)} ${(delta >= 0 ? '+' : '') + delta.toFixed(1) + '%'} `.padEnd(92));
  }
  process.exit(0);
}

const stats = (times) => {
  const sorted = [...times].sort((x, y) => x - y);
  return {
    median: +sorted[Math.floor(sorted.length / 2)].toFixed(2),
    p95: +sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))].toFixed(2),
    min: +sorted[0].toFixed(2),
    max: +sorted.at(-1).toFixed(2),
  };
};

/* ---------------- server: cold transforms ---------------- */
async function makeColdInputs() {
  const master = fs.readFileSync(path.join(root, 'demo-masters/aurora-valley.jpg'));
  const variants = [master];
  variants.push(await sharp(master).flop().jpeg({ quality: 92 }).toBuffer());
  variants.push(await sharp(master).flip().jpeg({ quality: 92 }).toBuffer());
  variants.push(await sharp(master).rotate(180).jpeg({ quality: 92 }).toBuffer());
  variants.push(await sharp(master).extract({ left: 40, top: 30, width: 1300, height: 700 }).jpeg({ quality: 92 }).toBuffer());
  variants.push(await sharp(master).modulate({ brightness: 1.04 }).jpeg({ quality: 92 }).toBuffer());
  return variants;
}

async function coldBench(inputs, label, options, reps = 6) {
  for (let i = 0; i < 2; i++) {
    await scrambleImage(inputs[i % inputs.length], { key: `warmup-${label}`, grid: 8, ...options });
  }
  globalThis.gc?.();
  const rss0 = process.memoryUsage().rss;
  let peakRss = rss0;
  const sampler = setInterval(() => {
    const rss = process.memoryUsage().rss;
    if (rss > peakRss) peakRss = rss;
  }, 4);
  sampler.unref?.();
  const cpu0 = process.cpuUsage();
  const times = [];
  const sizes = [];
  for (let i = 0; i < reps; i++) {
    const t0 = performance.now();
    const out = await scrambleImage(inputs[i % inputs.length], { key: `bench-${label}-${i}`, grid: 8, ...options });
    times.push(performance.now() - t0);
    sizes.push(out.bytes.length / 1024);
  }
  const cpu = process.cpuUsage(cpu0);
  clearInterval(sampler);
  const result = {
    ...stats(times),
    cpuMsPerImage: +(((cpu.user + cpu.system) / 1000) / reps).toFixed(2),
    peakRssDeltaMB: +((peakRss - rss0) / 1048576).toFixed(1),
    payloadKB: +stats(sizes).median.toFixed(1),
  };
  console.log(`  ${label.padEnd(44)} median ${result.median} ms · cpu ${result.cpuMsPerImage} ms/img · peakRSS +${result.peakRssDeltaMB} MB · payload ${result.payloadKB} kB`);
  return result;
}

const catalogProcessing = { webpEffort: 2, webpSmartSubsample: false, resizeKernel: 'lanczos2' };
console.log('Server — cold derivative transforms (1408×768 master family)');
const server = {};

/* ---------------- server: raw scramble throughput ----------------
 * Measured FIRST, before Sharp work fills the heap: large typed-array
 * allocations on a GC-pressured heap measure the collector, not the copy. */
{
  const pw = 1920, ph = 1080;
  const raw = new Uint8Array(pw * ph * 4);
  for (let i = 0; i < raw.length; i += 613) raw[i] = i % 251;
  const plan = buildScramblePlan(8, 'bench');
  scramblePixels(raw, pw, ph, plan, 'scramble');
  const times = [];
  for (let i = 0; i < 8; i++) {
    globalThis.gc?.();
    const t0 = performance.now();
    scramblePixels(raw, pw, ph, plan, 'scramble');
    times.push(performance.now() - t0);
  }
  const s = stats(times);
  server.scramblePixels_1080p = { ...s, megapixelsPerSecond: +(((pw * ph) / 1e6) / (s.median / 1000)).toFixed(1) };
  console.log(`  ${'scramblePixels 1920×1080'.padEnd(44)} median ${s.median} ms · ${server.scramblePixels_1080p.megapixelsPerSecond} MP/s`);
}
const inputs = await makeColdInputs();
for (const width of [640, 960, 1600]) {
  server[`cold_q95_${width}`] = await coldBench(inputs, `q95 default → ${width}px`, { maxWidth: width, quality: 95 });
}
for (const width of [640, 960, 1600]) {
  server[`cold_catalog_${width}`] = await coldBench(inputs, `catalog q88 → ${width}px`, { maxWidth: width, quality: 88, processing: catalogProcessing });
}
server.cold_fullmarks_960 = await coldBench(inputs, 'q95 + watermark + forensic + stego → 960px', {
  maxWidth: 960, quality: 95, watermark: '© ARCHX', forensicSeed: 'bench-session',
  steganography: true, stegoKey: 'bench-only-stego-key',
});
server.cold_aes_catalog_960 = await coldBench(inputs, 'catalog q88 + AES-GCM → 960px', {
  maxWidth: 960, quality: 88, processing: catalogProcessing, aesKey: generateKeyBase64(),
});

/* ---------------- server: warm throughput + batch mint ---------------- */
function runLoadTest() {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, [path.join(root, 'tools/load-test.mjs'),
      '--requests=300', '--concurrency=20', '--width=960', '--warmup=10', '--json'],
    { cwd: root, timeout: 240000, maxBuffer: 8 * 1024 * 1024 }, (err, stdout) => {
      if (err) return reject(err);
      try { resolve(JSON.parse(stdout)); } catch (e) { reject(e); }
    });
  });
}
{
  const lt = await runLoadTest();
  server.warmFlow = {
    requestsPerSecond: lt.requestsPerSecond,
    latencyP50Ms: lt.latencyMs.p50,
    latencyP95Ms: lt.latencyMs.p95,
  };
  console.log(`  ${'warm mint+redeem (load-test)'.padEnd(44)} ${lt.requestsPerSecond} flows/s · p50 ${lt.latencyMs.p50} ms · p95 ${lt.latencyMs.p95} ms`);
}

/* ---------------- browser: user-side cost ---------------- */
const PORT = 4193;
const BASE = `http://127.0.0.1:${PORT}`;
const browser = {};
let demoServer;
try {
  let serverLog = '';
  demoServer = spawn(process.execPath, ['server/demo-server.js'], {
    cwd: root, env: { ...process.env, PORT: String(PORT) }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  demoServer.stdout.on('data', (d) => { serverLog += d; });
  demoServer.stderr.on('data', (d) => { serverLog += d; });
  let serverReady = false;
  for (let i = 0; i < 240 && !serverReady; i++) {
    try { const r = await fetch(BASE + '/test-harness.html'); serverReady = r.ok; } catch {}
    if (!serverReady) await new Promise((r) => setTimeout(r, 250));
  }
  if (!serverReady) throw new Error('demo server did not start:\n' + serverLog.slice(-800));

  const chromium = (await import('@sparticuz/chromium')).default;
  const puppeteer = (await import('puppeteer-core')).default;
  let env = process.env;
  try {
    if (!fs.existsSync('/tmp/al2023/lib/libnspr4.so')) {
      const zlib = await import('node:zlib');
      const { pipeline } = await import('node:stream/promises');
      const { execSync } = await import('node:child_process');
      await pipeline(
        fs.createReadStream(path.join(root, 'node_modules/@sparticuz/chromium/bin/al2023.tar.br')),
        zlib.createBrotliDecompress(), fs.createWriteStream('/tmp/al2023.tar'));
      fs.mkdirSync('/tmp/al2023', { recursive: true });
      execSync('tar -xf /tmp/al2023.tar -C /tmp/al2023');
    }
    env = { ...process.env, LD_LIBRARY_PATH: '/tmp/al2023/lib:' + (process.env.LD_LIBRARY_PATH || '') };
  } catch {}
  const browserInstance = await puppeteer.launch({
    executablePath: await chromium.executablePath(),
    args: [...chromium.args.filter((a) => a !== '--disable-web-security'),
      '--no-sandbox', '--disable-dev-shm-usage', '--enable-unsafe-swiftshader', '--enable-precise-memory-info'],
    headless: true,
    env,
  });
  const page = await browserInstance.newPage();
  await page.setViewport({ width: 1400, height: 1000, deviceScaleFactor: 1 });
  const traffic = { batchMints: 0, singleMints: 0, payloads: 0 };
  page.on('request', (req) => {
    const u = req.url();
    if (u.includes('/archx/tokens')) traffic.batchMints++;
    else if (u.includes('/archx/token/')) traffic.singleMints++;
    else if (u.includes('/archx/i/')) traffic.payloads++;
  });
  await page.goto(BASE + '/demo/perf-bench.html', { waitUntil: 'networkidle2', timeout: 60000 });
  await page.waitForFunction(() => window.__perfReady === true, { timeout: 30000 });

  const singleBench = async (mode, label) => {
    const samples = await page.evaluate(async (m) => {
      const out = [];
      for (let i = 0; i < 7; i++) {
        performance.clearResourceTimings();
        const host = document.createElement('div');
        host.style.cssText = 'width:640px;height:360px';
        document.body.appendChild(host);
        const t0 = performance.now();
        const inst = window.Archx.load.image(host, { id: 'aurora-valley' }, {
          mode: m, lazy: false, cacheBitmap: false,
        });
        await inst.ready;
        const readyMs = performance.now() - t0;
        await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
        const paintedMs = performance.now() - t0;
        const res = performance.getEntriesByType('resource').filter((e) => e.name.includes('/archx/'));
        const token = res.find((e) => e.name.includes('/archx/token/'));
        const payload = res.find((e) => e.name.includes('/archx/i/'));
        out.push({
          readyMs: +readyMs.toFixed(1),
          paintedMs: +paintedMs.toFixed(1),
          preFetchMs: token ? +(token.startTime - t0).toFixed(1) : null,
          tokenMs: token ? +token.duration.toFixed(1) : null,
          payloadMs: payload ? +payload.duration.toFixed(1) : null,
          decodeRenderMs: payload ? +(readyMs - (payload.responseEnd - t0)).toFixed(1) : null,
        });
        inst.destroy();
        host.remove();
      }
      return out;
    }, mode);
    const kept = samples.slice(1); // drop first (JIT/connection warm-up)
    const phase = (key) => stats(kept.map((s) => s[key]).filter((v) => v != null)).median;
    const s = {
      ...stats(kept.map((x) => x.paintedMs)),
      readyMedian: phase('readyMs'),
      preFetchMedian: phase('preFetchMs'),
      tokenMedian: phase('tokenMs'),
      payloadMedian: phase('payloadMs'),
      decodeRenderMedian: phase('decodeRenderMs'),
    };
    console.log(`  ${label.padEnd(44)} median ${s.median} ms to painted (pre-fetch ${s.preFetchMedian} · token ${s.tokenMedian} · payload ${s.payloadMedian} · decode+render ${s.decodeRenderMedian})`);
    return s;
  };
  console.log('\nBrowser — user-side cost (headless Chromium, software GL)');
  // Throwaway warm-up pair so PoP key generation, JIT, shader compile, and
  // the server's first cold derivative are not attributed to either mode.
  await page.evaluate(async () => {
    for (const mode of ['shield', 'vault']) {
      const host = document.createElement('div');
      host.style.cssText = 'width:640px;height:360px';
      document.body.appendChild(host);
      const inst = window.Archx.load.image(host, { id: 'aurora-valley' }, { mode, lazy: false });
      await inst.ready.catch(() => {});
      inst.destroy();
      host.remove();
    }
  });
  browser.shieldSingle640 = await singleBench('shield', 'shield single 640×360 (token flow)');
  browser.vaultSingle640 = await singleBench('vault', 'vault single 640×360 (token flow)');

  /* vault idle cost: rAF callbacks after a static vault image settles */
  browser.vaultIdle = await page.evaluate(async () => {
    const host = document.createElement('div');
    host.style.cssText = 'width:640px;height:360px';
    document.body.appendChild(host);
    const inst = window.Archx.load.image(host, { id: 'aurora-valley' }, { mode: 'vault', lazy: false });
    await inst.ready;
    await new Promise((r) => setTimeout(r, 800));
    let frames = 0;
    const t0 = performance.now();
    await new Promise((resolve) => {
      const loop = () => {
        frames++;
        if (performance.now() - t0 < 2500) requestAnimationFrame(loop);
        else resolve();
      };
      requestAnimationFrame(loop);
    });
    inst.destroy();
    host.remove();
    // The loop itself asks for frames, so also report page-level rAF demand:
    return { probeFramesIn2500ms: frames };
  });
  console.log(`  ${'vault idle (probe rAF in 2.5 s)'.padEnd(44)} ${browser.vaultIdle.probeFramesIn2500ms} frames available`);

  /* 100-image gallery */
  {
    const cdp = await page.createCDPSession();
    const heapMB = async () => {
      try { await cdp.send('HeapProfiler.collectGarbage'); } catch {}
      return page.evaluate(() => performance.memory?.usedJSHeapSize ?? 0);
    };
    const heapBefore = await heapMB();
    const metricsBefore = await page.metrics();
    const before = { ...traffic };
    const gallery = await page.evaluate(async () => {
      const wrap = document.createElement('div');
      wrap.id = 'opt-gallery';
      wrap.style.cssText = 'display:grid;grid-template-columns:repeat(5,260px);gap:8px';
      document.body.appendChild(wrap);
      const t0 = performance.now();
      const instances = [];
      let firstError = null;
      for (let i = 1; i <= 100; i++) {
        const host = document.createElement('div');
        host.style.cssText = 'width:260px;height:180px';
        wrap.appendChild(host);
        instances.push(window.Archx.load.image(host,
          { id: `gallery-${String(i).padStart(3, '0')}` },
          {
            ...window.Archx.preset('catalog'), lazy: false,
            onError: (e) => { if (!firstError) firstError = String(e?.message || e); },
          }));
      }
      await Promise.all(instances.map((x) => x.ready.catch(() => {})));
      const totalMs = performance.now() - t0;
      const loaded = instances.filter((x) => x.loaded).length;
      window.__optGallery = instances;
      return { totalMs: +totalMs.toFixed(1), loaded, firstError };
    });
    if (gallery.loaded === 0) throw new Error(`gallery bench loaded 0 images (first error: ${gallery.firstError})`);
    const heapAfter = await heapMB();
    const metricsAfter = await page.metrics();
    browser.gallery100 = {
      totalMs: gallery.totalMs,
      loaded: gallery.loaded,
      msPerImage: +(gallery.totalMs / Math.max(1, gallery.loaded)).toFixed(2),
      batchMints: traffic.batchMints - before.batchMints,
      singleMints: traffic.singleMints - before.singleMints,
      payloads: traffic.payloads - before.payloads,
      jsHeapDeltaMB: +((heapAfter - heapBefore) / 1048576).toFixed(1),
      mainThreadTaskSeconds: +((metricsAfter.TaskDuration ?? 0) - (metricsBefore.TaskDuration ?? 0)).toFixed(2),
      scriptSeconds: +((metricsAfter.ScriptDuration ?? 0) - (metricsBefore.ScriptDuration ?? 0)).toFixed(2),
    };
    console.log(`  ${'gallery 100 images (catalog)'.padEnd(44)} ${gallery.totalMs} ms total · ${browser.gallery100.msPerImage} ms/img · heap +${browser.gallery100.jsHeapDeltaMB} MB · batch=${browser.gallery100.batchMints} single=${browser.gallery100.singleMints}`);
    await page.evaluate(async () => {
      for (const inst of window.__optGallery || []) inst.destroy();
      document.querySelector('#opt-gallery')?.remove();
      await new Promise((r) => setTimeout(r, 700));
    });
    const heapSettled = await heapMB();
    browser.gallery100.jsHeapResidualMB = +((heapSettled - heapBefore) / 1048576).toFixed(1);
    console.log(`  ${'gallery heap after destroy-all'.padEnd(44)} residual +${browser.gallery100.jsHeapResidualMB} MB`);
  }

  /* batch mint latency against the live server (after browser benches so
   * its token-rate spend cannot starve the gallery) */
  {
    // Token-rate budget note: the demo server allows 300 token hits/min/IP
    // across ALL bench sections (singles ~17 + gallery 100 + batch 150 = 267).
    const items = Array.from({ length: 50 }, (_, i) => ({ ref: `g${i}`, id: `gallery-${String(i + 1).padStart(3, '0')}`, w: 640 }));
    const times = [];
    for (let i = 0; i < 3; i++) {
      const t0 = performance.now();
      const res = await fetch(`${BASE}/archx/tokens`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-archx-request': 'token' },
        body: JSON.stringify({ items }),
      });
      const body = await res.json();
      if (!res.ok || Object.keys(body.tokens ?? {}).length !== 50) throw new Error(`batch mint failed: ${res.status}`);
      times.push(performance.now() - t0);
    }
    server.batchMint50 = stats(times.slice(1));
    console.log(`  ${'batch mint 50 tokens (HTTP)'.padEnd(44)} median ${server.batchMint50.median} ms`);
  }

  await browserInstance.close();
} finally {
  demoServer?.kill();
}

/* ---------------- bundle ---------------- */
const bundles = {};
for (const f of ['dist/archx.min.js', 'dist/archx.esm.js', 'dist/archx.cjs']) {
  const p = path.join(root, f);
  if (fs.existsSync(p)) {
    const buf = fs.readFileSync(p);
    bundles[path.basename(f)] = { kb: +(buf.length / 1024).toFixed(1), gzipKb: +(gzipSync(buf).length / 1024).toFixed(1) };
  }
}
console.log(`\n  ${'bundle archx.min.js'.padEnd(44)} ${bundles['archx.min.js']?.kb} kB (${bundles['archx.min.js']?.gzipKb} kB gzip)`);

const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const report = {
  meta: {
    archx: pkg.version,
    node: process.version,
    cpus: os.cpus().length,
    cpuModel: os.cpus()[0]?.model ?? 'unknown',
    totalMemGB: +(os.totalmem() / 1073741824).toFixed(1),
    date: new Date().toISOString(),
  },
  server,
  browser,
  bundles,
};
if (args.out) {
  fs.writeFileSync(String(args.out), JSON.stringify(report, null, 2));
  console.log(`\nWrote ${args.out}`);
} else {
  console.log(JSON.stringify(report, null, 2));
}
