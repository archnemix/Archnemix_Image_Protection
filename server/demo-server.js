#!/usr/bin/env node
/**
 * Demo server (plain node:http — no framework needed).
 *
 * Security-relevant layout:
 *   demo-masters/            ← masters live here, OUTSIDE every static route.
 *                              GET /demo-masters/... returns 404. The only way
 *                              pixels leave this folder is through /archx/*
 *                              (signed URL + down-scale + tile-scramble).
 *   demo/public-unprotected/ ← intentionally naked copies for comparison.
 *   demo/, src/, dist/       ← normal static assets (code is not secret).
 */
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createArchxMiddleware } from './middleware.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const port = Number(process.env.PORT || 4173);

// First run on a fresh clone: generate the demo gallery/public copies
// (they're .gitignore'd to keep the repo light) before indexing masters.
const galleryDir = path.join(root, 'demo-masters', 'gallery');
const galleryCount = fs.existsSync(galleryDir) ? fs.readdirSync(galleryDir).filter((f) => f.endsWith('.jpg')).length : 0;
if (galleryCount < 100 || !fs.existsSync(path.join(root, 'demo', 'public-unprotected', 'aurora-valley.jpg'))) {
  console.log('Generating demo images (first run)…');
  try { execFileSync(process.execPath, [path.join(root, 'tools', 'generate-test-images.mjs')], { stdio: 'inherit' }); }
  catch { console.warn('⚠ demo image generation failed — run: npm run demo:images'); }
}

const archx = createArchxMiddleware({
  secret: process.env.ARCHX_SECRET || 'demo-secret-change-me-in-production',
  imagesDirs: [
    path.join(root, 'demo-masters'),
    path.join(root, 'demo-masters', 'gallery'),
  ],
  ttlSec: 120,
  grid: 8,
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
  { prefix: '/demo/', dir: path.join(root, 'demo') },
  { prefix: '/src/', dir: path.join(root, 'src') },
  { prefix: '/dist/', dir: path.join(root, 'dist') },
];

function serveStatic(req, res) {
  const url = new URL(req.url, 'http://x');
  let pathname = decodeURIComponent(url.pathname);
  if (pathname === '/' || pathname === '/index.html') pathname = '/demo/index.html';
  if (pathname === '/test-harness.html') pathname = '/demo/test-harness.html';
  if (pathname === '/favicon.ico') { res.writeHead(204); return res.end(); }
  // Masters are NEVER static:
  if (pathname.startsWith('/demo-masters')) { res.writeHead(404); return res.end('not found'); }

  for (const { prefix, dir } of STATIC_ROOTS) {
    if (!pathname.startsWith(prefix)) continue;
    const rel = pathname.slice(prefix.length);
    const filePath = path.resolve(dir, rel);
    if (!filePath.startsWith(dir)) { res.writeHead(403); return res.end('forbidden'); }
    if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) break;
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
    });
    return fs.createReadStream(filePath).pipe(res);
  }
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('not found');
}

const server = http.createServer((req, res) => {
  if (req.url.startsWith('/archx/')) return archx(req, res);
  return serveStatic(req, res);
});

server.listen(port, '0.0.0.0', () => {
  console.log(`\n🛡  Archnemix Image Protection demo: http://0.0.0.0:${port}`);
  console.log(`   Protected images indexed: ${archx.index.size}`);
  console.log('   Masters folder is not web-accessible — try /demo-masters/aurora-valley.jpg (404)\n');
});
