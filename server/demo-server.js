#!/usr/bin/env node
/**
 * Demo server (plain node:http — no framework needed).
 *
 * Security-relevant layout:
 *   demo-masters/            ← masters live here, OUTSIDE every static route.
 *                              GET /demo-masters/... returns 404. The only way
 *                              pixels leave this folder is through /archx/*
 *                              (signed header token + down-scale + tile-scramble).
 *   demo/public-unprotected/ ← intentionally naked copies for comparison.
 *   demo/, src/, dist/       ← normal static assets (code is not secret).
 */
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import crypto from 'node:crypto';
import { createArchxMiddleware } from './middleware.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const requestedPort = Number(process.env.PORT || 4173);
const port = Number.isInteger(requestedPort) && requestedPort >= 0 && requestedPort <= 65535 ? requestedPort : 4173;

// First run on a fresh clone: generate the demo gallery/public copies
// (they're .gitignore'd to keep the repo light) before indexing masters.
const galleryDir = path.join(root, 'demo-masters', 'gallery');
const galleryCount = fs.existsSync(galleryDir) ? fs.readdirSync(galleryDir).filter((f) => f.endsWith('.jpg')).length : 0;
if (galleryCount < 100 || !fs.existsSync(path.join(root, 'demo', 'public-unprotected', 'aurora-valley.jpg'))) {
  console.log('Generating demo images (first run)…');
  try { execFileSync(process.execPath, [path.join(root, 'tools', 'generate-test-images.mjs')], { stdio: 'inherit' }); }
  catch { console.warn('⚠ demo image generation failed — run: npm run demo:images'); }
}

const demoSecret = process.env.ARCHX_SECRET || crypto.randomBytes(32).toString('hex');
if (!process.env.ARCHX_SECRET) {
  console.log('Demo only: generated a fresh random ARCHX_SECRET for this process. Set ARCHX_SECRET (>=32 bytes) for any shared deployment.');
}

const archx = createArchxMiddleware({
  secret: demoSecret,
  // Demo-only explicit opt-in. Production must provide authorize(req,id,{phase})
  // tied to the host site's session/entitlement system instead.
  allowAnonymous: true,
  publicDirs: [
    path.join(root, 'demo'),
    path.join(root, 'src'),
    path.join(root, 'dist'),
  ],
  imagesDirs: [
    path.join(root, 'demo-masters'),
    path.join(root, 'demo-masters', 'gallery'),
  ],
  ttlSec: 120,
  grid: 8,
  quality: 95, // high-fidelity delivered pixels (set lossless:true for exact-size pixels)
  allowClientQuality: true, // demo cards ask for qualityProfile:'original' (lossless)
  // Blind ownership fingerprint in every delivered view. Per-image here so the
  // demo output cache stays effective; production can use perToken + a DB.
  steganography: { perToken: false, strength: 6 },
  // Production hosts persist onStegoIssue fingerprints in their own database.
  // The demo deliberately exposes no HTTP registry/debug endpoint for them.
  // Determined-attacker hardening (all on for the demo):
  oneTimeTokens: true,                    // a captured signed token cannot be replayed
  bindTokenTo: { userAgent: true },       // …and only works in the browser that asked for it
  // Baked in BEFORE scrambling: even a perfectly un-shuffled stolen payload
  // remains watermarked. Gallery thumbs are spared the visible mark.
  serverWatermark: ({ id }) => (id.startsWith('gallery-')
    ? null
    : { text: `© Archnemix Demo · ${id}`, corner: false }), // client adds the corner label
  forensic: { blockSize: 32, delta: 2 },  // invisible block mark, also pre-scramble
  forensicPerToken: false,                // per-image here so cached gallery stays fast
  // encrypt: true, // <- flip this on to see AES-GCM payloads in the demo
});

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.png': 'image/png', '.webp': 'image/webp', '.svg': 'image/svg+xml',
  '.map': 'application/json', '.ico': 'image/x-icon', '.md': 'text/markdown; charset=utf-8',
};

const STATIC_ROOTS = [
  { prefix: '/demo/', dir: fs.realpathSync(path.join(root, 'demo')) },
  { prefix: '/src/', dir: fs.realpathSync(path.join(root, 'src')) },
  { prefix: '/dist/', dir: fs.realpathSync(path.join(root, 'dist')) },
];

function isInsideDir(dir, filePath) {
  const rel = path.relative(dir, filePath);
  return rel === '' || (!rel.startsWith('..' + path.sep) && !path.isAbsolute(rel));
}

const SAFE_ERROR_HEADERS = Object.freeze({
  'Content-Type': 'text/plain; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
});

function sendTextError(res, status, message, extra = {}) {
  res.writeHead(status, { ...SAFE_ERROR_HEADERS, ...extra });
  return res.end(message);
}

function serveStatic(req, res) {
  if (!['GET', 'HEAD'].includes(req.method)) {
    return sendTextError(res, 405, 'method not allowed', { Allow: 'GET, HEAD' });
  }
  let pathname;
  try {
    const url = new URL(req.url, 'http://x');
    pathname = decodeURIComponent(url.pathname);
  } catch {
    return sendTextError(res, 400, 'bad request');
  }
  if (pathname === '/' || pathname === '/index.html') pathname = '/demo/index.html';
  if (pathname === '/test-harness.html') pathname = '/demo/test-harness.html';
  if (pathname === '/favicon.ico') { res.writeHead(204); return res.end(); }
  // Masters are NEVER static. The realpath+relative checks below are the
  // actual boundary; this early return just gives the obvious URL a fast 404.
  if (pathname.startsWith('/demo-masters')) return sendTextError(res, 404, 'not found');

  for (const { prefix, dir } of STATIC_ROOTS) {
    if (!pathname.startsWith(prefix)) continue;
    const rel = pathname.slice(prefix.length);
    const candidate = path.resolve(dir, '.' + path.sep + rel);
    if (!isInsideDir(dir, candidate)) return sendTextError(res, 404, 'not found');
    let filePath;
    try { filePath = fs.realpathSync(candidate); } catch { break; }
    if (!isInsideDir(dir, filePath) || !fs.statSync(filePath).isFile()) break;
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      // Content-hashed .archx variants are immutable by construction and may
      // be cached forever (the documented CDN policy); the manifest and all
      // other files must revalidate so rebuilds are picked up immediately.
      'Cache-Control': ext === '.archx' ? 'public, max-age=31536000, immutable' : 'no-cache',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    });
    if (req.method === 'HEAD') return res.end();
    return fs.createReadStream(filePath).pipe(res);
  }
  return sendTextError(res, 404, 'not found');
}

const server = http.createServer((req, res) => {
  if (req.url.startsWith('/archx/')) return archx(req, res);
  return serveStatic(req, res);
});
server.headersTimeout = 10_000;
server.requestTimeout = 30_000;
server.keepAliveTimeout = 5_000;
server.timeout = 30_000;
server.maxRequestsPerSocket = 1000;

server.listen(port, '0.0.0.0', () => {
  console.log(`\n🛡  Archnemix Image Protection demo: http://0.0.0.0:${port}`);
  console.log(`   Protected images indexed: ${archx.stats().images}`);
  console.log('   Masters folder is not web-accessible — try /demo-masters/aurora-valley.jpg (404)\n');
});
