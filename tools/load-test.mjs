#!/usr/bin/env node
/**
 * Bounded mint+redeem load test for an Archx middleware deployment.
 *
 * Default mode creates a synthetic local master and an in-process server.
 * That is useful for regression comparisons, but it is not evidence that a
 * multi-instance production deployment can sustain the same rate: run the
 * same tool against staging (`--base-url`) with the real state store, load
 * balancer, image sizes, authorization callback, and CDN configuration.
 *
 * Workload shapes (review #7 P1.15): default = one hot image (warm
 * caches — the easiest possible case, never quote it as capacity);
 * --images=N rotates over N distinct masters so transforms stay
 * cold; --viewers=N rotates per-viewer watermarks so every
 * derivative is personalized (cold finish + no cross-viewer reuse).
 *
 * Examples:
 *   npm run load-test -- --requests=500 --concurrency=50 --width=1200
 *   npm run load-test -- --images=25 --viewers=10 --requests=250
 *   npm run load-test -- --base-url=https://staging.example.test \
 *     --image-id=catalog-001 --requests=5000 --concurrency=100 \
 *     --confirm-load-test --json
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import sharp from 'sharp';
import { createArchxMiddleware } from '../server/middleware.js';

function parseArgs(argv) {
  const options = {
    requests: 200,
    concurrency: 20,
    width: 900,
    warmup: 5,
    baseUrl: '',
    basePath: '/archx',
    imageId: 'load',
    headers: {},
    confirmLoadTest: false,
    json: false,
    help: false,
    images: 1,
    viewers: 1,
  };
  for (const arg of argv) {
    if (arg === '--help' || arg === '-h') options.help = true;
    else if (arg === '--json') options.json = true;
    else if (arg === '--confirm-load-test') options.confirmLoadTest = true;
    else if (arg.startsWith('--requests=')) options.requests = Number(arg.slice('--requests='.length));
    else if (arg.startsWith('--concurrency=')) options.concurrency = Number(arg.slice('--concurrency='.length));
    else if (arg.startsWith('--width=')) options.width = Number(arg.slice('--width='.length));
    else if (arg.startsWith('--warmup=')) options.warmup = Number(arg.slice('--warmup='.length));
    else if (arg.startsWith('--base-url=')) options.baseUrl = arg.slice('--base-url='.length);
    else if (arg.startsWith('--images=')) options.images = Number(arg.slice('--images='.length));
    else if (arg.startsWith('--viewers=')) options.viewers = Number(arg.slice('--viewers='.length));
    else if (arg.startsWith('--base-path=')) options.basePath = arg.slice('--base-path='.length);
    else if (arg.startsWith('--image-id=')) options.imageId = arg.slice('--image-id='.length);
    else if (arg.startsWith('--header=')) {
      const raw = arg.slice('--header='.length);
      const separator = raw.indexOf(':');
      const name = separator > 0 ? raw.slice(0, separator).trim() : '';
      const value = separator > 0 ? raw.slice(separator + 1).trim() : '';
      if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name) || !value || value.length > 8192 || /[\r\n]/.test(value)) {
        throw new Error('--header must be in the form "Name: value"');
      }
      options.headers[name] = value;
    }
    else throw new Error(`unknown argument: ${arg}`);
  }
  const integerInRange = (name, value, min, max) => {
    if (!Number.isInteger(value) || value < min || value > max) {
      throw new Error(`--${name} must be an integer from ${min} to ${max}`);
    }
  };
  integerInRange('requests', options.requests, 1, 100000);
  integerInRange('concurrency', options.concurrency, 1, 500);
  integerInRange('width', options.width, 64, 4096);
  integerInRange('warmup', options.warmup, 0, 1000);
  integerInRange('images', options.images, 1, 500);
  integerInRange('viewers', options.viewers, 1, 1000);
  if (options.baseUrl && (options.images > 1 || options.viewers > 1)) {
    throw new Error('--images/--viewers shape the local synthetic server only; against staging, vary --image-id/--header yourself');
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(options.imageId)) throw new Error('--image-id is invalid');
  options.basePath = '/' + String(options.basePath || '').replace(/^\/+|\/+$/g, '');
  if (!/^\/[A-Za-z0-9._~/-]+$/.test(options.basePath) || options.basePath.includes('..')) {
    throw new Error('--base-path must be a simple absolute URL path');
  }
  if (options.baseUrl) {
    const url = new URL(options.baseUrl);
    if (!['http:', 'https:'].includes(url.protocol)) throw new Error('--base-url must use http or https');
    options.baseUrl = url.origin + url.pathname.replace(/\/$/, '');
    const local = ['localhost', '127.0.0.1', '::1'].includes(url.hostname);
    if (!local && !options.confirmLoadTest) {
      throw new Error('refusing to load-test a non-local target without --confirm-load-test');
    }
  }
  return options;
}

function percentile(sorted, p) {
  if (!sorted.length) return 0;
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[index];
}

async function syntheticMaster(seed = 0) {
  const hue = (seed * 47) % 360;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="1000">
    <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="hsl(${hue} 80% 55%)"/><stop offset="0.5" stop-color="hsl(${(hue + 60) % 360} 85% 60%)"/>
      <stop offset="1" stop-color="hsl(${(hue + 160) % 360} 70% 45%)"/>
    </linearGradient></defs>
    <rect width="1600" height="1000" fill="url(#g)"/>
    ${Array.from({ length: 80 }, (_, i) => `<circle cx="${((i + seed) * 173) % 1600}" cy="${((i + seed * 3) * 211) % 1000}" r="${18 + (i % 7) * 9}" fill="rgba(255,255,255,0.30)"/>`).join('')}
    <text x="70" y="910" font-family="sans-serif" font-size="110" font-weight="bold" fill="white">ARCHX LOAD ${seed}</text>
  </svg>`;
  return sharp(Buffer.from(svg)).jpeg({ quality: 92 }).toBuffer(); // files are saved as load*.jpg — bytes must be JPEG
}

async function startLocalServer(options) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-load-'));
  fs.writeFileSync(path.join(dir, 'load.jpg'), await syntheticMaster(0));
  for (let i = 1; i < options.images; i++) {
    fs.writeFileSync(path.join(dir, `load-${i}.jpg`), await syntheticMaster(i));
  }
  const handler = createArchxMiddleware({
    secret: crypto.randomBytes(32).toString('base64url'),
    imagesDir: dir,
    // Per-viewer mode uses a REAL authorize callback (per-viewer
    // watermark => personalized derivative per viewer), because that
    // is the expensive production shape being measured.
    ...(options.viewers > 1
      ? { authorize: async (req) => ({ viewerId: String(req.headers['x-load-viewer'] || 'v0'), watermark: `© load ${req.headers['x-load-viewer'] || 'v0'}` }) }
      : { allowAnonymous: true }),
    allowQueryTokens: false,
    rateLimitPerMinute: 1000000,
    tokenRateLimitPerMinute: 1000000,
    abuseDetection: { distinctImages: 10000, windowMs: 60000, action: 'event' },
  });
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    baseUrl: `http://127.0.0.1:${server.address().port}`,
    stats: () => handler.stats(),
    close: async () => {
      handler.close();
      await new Promise((resolve) => server.close(resolve));
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

async function run() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    console.log('Usage: npm run load-test -- [--requests=N] [--concurrency=N] [--width=N] [--warmup=N] [--images=N] [--viewers=N] [--json]');
    console.log('Staging: --base-url=https://staging.example.test [--base-path=/archx] --image-id=id [--header="Cookie: ..."] --confirm-load-test');
    return;
  }

  const local = options.baseUrl ? null : await startLocalServer(options);
  const baseUrl = options.baseUrl || local.baseUrl;

  let sequence = 0;
  async function mintAndRedeem() {
    const index = sequence++;
    const imageId = options.images > 1
      ? (index % options.images === 0 ? 'load' : `load-${index % options.images}`)
      : options.imageId;
    const viewer = `v${index % options.viewers}`;
    const started = performance.now();
    const tokenResponse = await fetch(`${baseUrl}${options.basePath}/token/${encodeURIComponent(imageId)}?w=${options.width}`, {
      method: 'POST',
      headers: { ...options.headers, 'x-archx-request': 'token', ...(options.viewers > 1 ? { 'x-load-viewer': viewer } : {}) },
      signal: AbortSignal.timeout(30000),
    });
    if (!tokenResponse.ok) {
      await tokenResponse.text().catch(() => '');
      const error = new Error(`token status ${tokenResponse.status}`);
      error.status = tokenResponse.status;
      throw error;
    }
    const token = await tokenResponse.json();
    const imageUrl = token.cleanUrl
      ? new URL(token.cleanUrl, baseUrl).toString()
      : new URL(token.url, baseUrl).toString();
    const imageResponse = await fetch(imageUrl, {
      headers: { ...options.headers, ...(options.viewers > 1 ? { 'x-load-viewer': viewer } : {}), ...(token.token ? { 'x-archx-token': token.token } : {}) },
      signal: AbortSignal.timeout(30000),
    });
    const bytes = await imageResponse.arrayBuffer();
    if (!imageResponse.ok) {
      const error = new Error(`image status ${imageResponse.status}`);
      error.status = imageResponse.status;
      throw error;
    }
    return { elapsedMs: performance.now() - started, bytes: bytes.byteLength, status: imageResponse.status };
  }

  try {
    for (let i = 0; i < options.warmup; i++) await mintAndRedeem();

    const latencies = [];
    const statuses = new Map();
    let errors = 0;
    let totalBytes = 0;
    let next = 0;
    const started = performance.now();
    async function worker() {
      for (;;) {
        const index = next++;
        if (index >= options.requests) return;
        try {
          const result = await mintAndRedeem();
          latencies.push(result.elapsedMs);
          totalBytes += result.bytes;
          statuses.set(result.status, (statuses.get(result.status) || 0) + 1);
        } catch (error) {
          errors++;
          const status = error.status || 'network';
          statuses.set(status, (statuses.get(status) || 0) + 1);
        }
      }
    }
    await Promise.all(Array.from({ length: Math.min(options.concurrency, options.requests) }, () => worker()));
    const elapsedMs = performance.now() - started;
    latencies.sort((a, b) => a - b);
    const result = {
      target: options.baseUrl ? 'external' : 'in-process-local',
      workload: options.viewers > 1 ? 'personalized-per-viewer' : options.images > 1 ? 'cold-multi-image' : 'warm-single-image',
      images: options.images,
      viewers: options.viewers,
      peakRssMb: Number((process.memoryUsage().rss / 1048576).toFixed(1)),
      imageId: options.imageId,
      width: options.width,
      requests: options.requests,
      concurrency: options.concurrency,
      completed: latencies.length,
      errors,
      elapsedMs: Number(elapsedMs.toFixed(1)),
      requestsPerSecond: Number((latencies.length / (elapsedMs / 1000)).toFixed(1)),
      totalBytes,
      latencyMs: {
        p50: Number(percentile(latencies, 50).toFixed(1)),
        p95: Number(percentile(latencies, 95).toFixed(1)),
        p99: Number(percentile(latencies, 99).toFixed(1)),
        max: Number((latencies.at(-1) || 0).toFixed(1)),
      },
      statuses: Object.fromEntries(statuses),
      ...(local ? { handlerStats: local.stats() } : {}),
      note: options.baseUrl
        ? 'External result. Record instance count, state-store backend, region placement, auth latency, and CDN settings with it.'
        : 'In-process synthetic result only; it does not validate a load-balanced or multi-region deployment.',
    };
    if (options.json) console.log(JSON.stringify(result, null, 2));
    else {
      console.log(`Archx mint+redeem load test (${result.target})`);
      console.log(`requests=${result.requests} concurrency=${result.concurrency} width=${result.width}`);
      console.log(`completed=${result.completed} errors=${result.errors} elapsed=${result.elapsedMs}ms`);
      console.log(`throughput=${result.requestsPerSecond} req/s totalBytes=${result.totalBytes}`);
      console.log(`latency ms p50=${result.latencyMs.p50} p95=${result.latencyMs.p95} p99=${result.latencyMs.p99} max=${result.latencyMs.max}`);
      console.log(result.note);
    }
    if (errors) process.exitCode = 1;
  } finally {
    if (local) await local.close();
  }
}

run().catch((error) => {
  console.error(`load test failed: ${error.message}`);
  process.exitCode = 1;
});
