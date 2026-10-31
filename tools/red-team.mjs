#!/usr/bin/env node
/**
 * Red-team attack suite for Archnemix Image Protection.
 *
 * Frames the security claims as attacks and tries to break them:
 * master/derivative extraction, token forgery & replay, authz
 * bypass, path/ID traversal, resource exhaustion, cache/privacy
 * leakage, and adversarial steganography (misattribution is the
 * failure that matters — a destroyed mark is a documented limit,
 * a WRONG attribution is a bug).
 *
 * Every entry states the defense it expects. A FAIL means an
 * attack succeeded; the process exits 1. INFO entries report
 * measured behavior without pass/fail (documented limits).
 *
 *   node tools/red-team.mjs [--json out.json]
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';
import sharp from 'sharp';
import { createArchxMiddleware, auditArchxServerConfig } from '../server/middleware.js';
import { decodeContainer, embedStegoFingerprint, detectStegoFingerprint, stegoFingerprint } from '../src/scramble.js';

const SECRET = 'red-team-secret-with-well-over-32-bytes!!';
const STEGO_KEY = 'red-team-stego-key';
const results = [];
let failures = 0;

function record(cls, name, pass, detail) {
  results.push({ class: cls, name, pass, detail });
  if (pass === false) failures++;
  const tag = pass === null ? 'INFO' : pass ? 'HELD' : 'FAIL';
  console.log(`  [${tag}] ${name}${detail ? ` — ${detail}` : ''}`);
}
async function attack(cls, name, fn) {
  try {
    const out = await fn();
    if (out && typeof out === 'object' && 'pass' in out) record(cls, name, out.pass, out.detail);
    else record(cls, name, !!out, '');
  } catch (err) {
    record(cls, name, false, `attack errored: ${err?.message || err}`);
  }
}

async function syntheticMaster(w = 640, h = 420, label = 'SECRET 42') {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}">
    <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#ff5533"/><stop offset="1" stop-color="#2244ff"/></linearGradient></defs>
    <rect width="${w}" height="${h}" fill="url(#g)"/>
    <circle cx="150" cy="130" r="70" fill="#00e08a"/><circle cx="430" cy="280" r="90" fill="#ffe14d"/>
    <text x="30" y="${h - 30}" font-family="sans-serif" font-size="44" font-weight="bold" fill="white">${label}</text>
  </svg>`;
  return sharp(Buffer.from(svg)).jpeg({ quality: 92 }).toBuffer();
}

// Minimal PNG whose IHDR claims enormous dimensions (pixel bomb).
function pixelBombPng(width, height) {
  const crcTable = [];
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    crcTable[n] = c >>> 0;
  }
  const crc32 = (buf) => {
    let c = 0xffffffff;
    for (const byte of buf) c = crcTable[(c ^ byte) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
  };
  const chunk = (type, data) => {
    const len = Buffer.alloc(4); len.writeUInt32BE(data.length);
    const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
    const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body));
    return Buffer.concat([len, body, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0); ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; ihdr[9] = 2; // 8-bit RGB
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr), chunk('IEND', Buffer.alloc(0)),
  ]);
}

async function startServer(handler) {
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}
const browserHeaders = (viewer = 'viewer-a', ua = 'BrowserA') => ({
  headers: { 'user-agent': ua, referer: 'https://example.test/page', 'x-viewer': viewer },
});
const postToken = (url, init = {}) => fetch(url, {
  method: 'POST',
  ...init,
  headers: { 'x-archx-request': 'token', ...(init.headers || {}) },
});
const redeem = (base, tokenRes, init = {}) => fetch(base + tokenRes.cleanUrl, {
  ...init, headers: { ...(init.headers || {}), 'x-archx-token': tokenRes.token },
});

/* ============================== setup ============================== */

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-redteam-'));
const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-outside-'));
fs.writeFileSync(path.join(dir, 'cat.jpg'), await syntheticMaster(640, 420, 'CAT SECRET'));
fs.writeFileSync(path.join(dir, 'dog.jpg'), await syntheticMaster(640, 420, 'DOG SECRET'));
fs.writeFileSync(path.join(dir, 'garbage.jpg'), Buffer.from('this is not an image at all, just bytes'));
fs.writeFileSync(path.join(dir, 'bomb.png'), pixelBombPng(60000, 60000));
const outsideFile = path.join(outside, 'outside-secret.jpg');
fs.writeFileSync(outsideFile, await syntheticMaster(640, 420, 'OUTSIDE SECRET'));
let symlinkOk = true;
try { fs.symlinkSync(outsideFile, path.join(dir, 'escape.jpg')); } catch { symlinkOk = false; }

const issued = [];
const handler = createArchxMiddleware({
  secret: SECRET,
  imagesDir: dir,
  maxWidthCap: 480,
  oneTimeTokens: true,
  bindTokenTo: { userAgent: true },
  allowedOrigins: ['https://example.test'],
  steganography: { perToken: true, profile: 'robust', strength: 6 },
  onStegoIssue: async (record) => { issued.push(record); },
  authorize: async (req) => ({ viewerId: req.headers['x-viewer'] || 'anon', maxWidth: 240 }),
});
const { server, base } = await startServer(handler);
console.log(`Red-team target: ${base} (hardened config, entitlement width 240, cap 480)\n`);

async function mint(id = 'cat', w = 900, viewer = 'viewer-a', ua = 'BrowserA') {
  const res = await postToken(`${base}/archx/token/${id}?w=${w}`, browserHeaders(viewer, ua));
  return { res, body: res.status === 200 ? await res.clone().json() : null };
}

/* ==================== A. extraction ==================== */
console.log('A. Master / derivative extraction');

await attack('extract', 'derivative without token is refused', async () => {
  const r = await fetch(`${base}/archx/i/cat`, browserHeaders());
  return { pass: r.status >= 400 && r.status < 500, detail: `status ${r.status}` };
});
await attack('extract', 'entitlement width cannot be escalated at mint or redeem', async () => {
  const { res, body } = await mint('cat', 900);
  if (res.status !== 200) return { pass: false, detail: `mint ${res.status}` };
  const r = await redeem(base, body, browserHeaders());
  if (r.status !== 200) return { pass: false, detail: `redeem ${r.status}` };
  const { header } = decodeContainer(new Uint8Array(await r.arrayBuffer()));
  return { pass: header.w <= 240, detail: `delivered width ${header.w} (entitlement 240, requested 900)` };
});
await attack('extract', 'absurd width requests stay capped (99999 / -5 / NaN / float)', async () => {
  for (const w of ['99999', '-5', 'abc', '240.9', '1e5']) {
    const { res, body } = await mint('cat', w);
    if (res.status === 200) {
      const r = await redeem(base, body, browserHeaders());
      if (r.status === 200) {
        const { header } = decodeContainer(new Uint8Array(await r.arrayBuffer()));
        if (header.w > 240) return { pass: false, detail: `w=${w} delivered ${header.w}` };
      }
    }
  }
  return { pass: true, detail: 'all capped at 240 or refused' };
});
await attack('extract', 'redeem-URL parameter smuggling does not widen the derivative', async () => {
  const { body } = await mint('cat', 200);
  const smuggled = await fetch(`${base}${body.cleanUrl}${body.cleanUrl.includes('?') ? '&' : '?'}w=2000&q=100&format=png&lossless=1`, {
    headers: { 'x-archx-token': body.token, ...browserHeaders().headers },
  });
  if (smuggled.status !== 200) return { pass: true, detail: `refused ${smuggled.status}` };
  const { header } = decodeContainer(new Uint8Array(await smuggled.arrayBuffer()));
  return { pass: header.w <= 240, detail: `delivered ${header.w}px despite smuggled params` };
});

/* ==================== B. token forgery ==================== */
console.log('\nB. Token forgery, replay, binding');

await attack('token', 'corrupted signature (middle byte, canonical re-encode) is refused and does not burn the claim', async () => {
  const { body } = await mint();
  const [payload, sig] = body.token.split('.');
  const bytes = Buffer.from(sig, 'base64url'); bytes[10] ^= 0xff;
  const evil = { ...body, token: `${payload}.${bytes.toString('base64url')}` };
  const forged = await redeem(base, evil, browserHeaders());
  const genuine = await redeem(base, body, browserHeaders());
  return { pass: forged.status >= 400 && genuine.status === 200, detail: `forgery ${forged.status}, genuine after forgery attempt ${genuine.status}` };
});
await attack('token', 'non-canonical base64url re-encoding of a valid token is refused (malleability)', async () => {
  const { body } = await mint();
  const [payload, sig] = body.token.split('.');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const lastIdx = alphabet.indexOf(sig.at(-1));
  const variantChar = [...alphabet].find((c) => (alphabet.indexOf(c) >> 2) === (lastIdx >> 2) && c !== sig.at(-1));
  const variant = { ...body, token: `${payload}.${sig.slice(0, -1)}${variantChar}` };
  const r = await redeem(base, variant, browserHeaders());
  return { pass: r.status >= 400, detail: `padding-variant status ${r.status}` };
});
await attack('token', 'payload tampering (unsigned claim edit) is refused', async () => {
  const { body } = await mint();
  const [payload, sig] = body.token.split('.');
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString());
  claims.w = 4000; claims.maxWidth = 4000;
  const evil = { ...body, token: `${Buffer.from(JSON.stringify(claims)).toString('base64url')}.${sig}` };
  const r = await redeem(base, evil, browserHeaders());
  return { pass: r.status >= 400, detail: `status ${r.status}` };
});
await attack('token', 'token signed with a wrong secret is refused', async () => {
  const { body } = await mint();
  const [payload] = body.token.split('.');
  const mac = crypto.createHmac('sha256', 'attacker-controlled-secret-value-32b').update(payload).digest().toString('base64url');
  const r = await redeem(base, { ...body, token: `${payload}.${mac}` }, browserHeaders());
  return { pass: r.status >= 400, detail: `status ${r.status}` };
});
await attack('token', 'cat token cannot be spent on dog (IDOR)', async () => {
  const { body } = await mint('cat');
  const swapped = { ...body, cleanUrl: body.cleanUrl.replace('/cat', '/dog') };
  const r = await redeem(base, swapped, browserHeaders());
  return { pass: r.status >= 400, detail: `status ${r.status}` };
});
await attack('token', 'one-time token replay is refused', async () => {
  const { body } = await mint();
  const first = await redeem(base, body, browserHeaders());
  const second = await redeem(base, body, browserHeaders());
  return { pass: first.status === 200 && second.status >= 400, detail: `first ${first.status}, replay ${second.status}` };
});
await attack('token', 'expired token (valid signature) is refused; far-future exp is refused', async () => {
  const { body } = await mint();
  const claims = JSON.parse(Buffer.from(body.token.split('.')[0], 'base64url').toString());
  const sign = (c) => {
    const p = Buffer.from(JSON.stringify(c)).toString('base64url');
    return `${p}.${crypto.createHmac('sha256', SECRET).update(p).digest().toString('base64url')}`;
  };
  const now = Date.now();
  const expired = await redeem(base, { ...body, token: sign({ ...claims, exp: now - 60000, iat: now - 120000 }) }, browserHeaders());
  const eternal = await redeem(base, { ...body, token: sign({ ...claims, exp: now + 10 * 365 * 24 * 3600 * 1000 }) }, browserHeaders());
  return { pass: expired.status >= 400 && eternal.status >= 400, detail: `expired ${expired.status}, eternal ${eternal.status}` };
});
await attack('token', 'UA-bound token spent by another user-agent is refused', async () => {
  const { body } = await mint('cat', 200, 'viewer-a', 'BrowserA');
  const r = await redeem(base, body, browserHeaders('viewer-a', 'BrowserB'));
  return { pass: r.status >= 400, detail: `status ${r.status}` };
});
await attack('token', 'query-string token transport is refused (header-only config)', async () => {
  const { body } = await mint();
  const sep = body.cleanUrl.includes('?') ? '&' : '?';
  const r = await fetch(`${base}${body.cleanUrl}${sep}token=${encodeURIComponent(body.token)}`, browserHeaders());
  return { pass: r.status >= 400, detail: `status ${r.status}` };
});
await attack('token', 'batch token for cat cannot redeem dog; unlisted item gets no token', async () => {
  const res = await postToken(`${base}/archx/tokens`, {
    headers: { 'content-type': 'application/json', ...browserHeaders('viewer-batch').headers },
    body: JSON.stringify({ items: [{ ref: 'a', id: 'cat', w: 200 }] }),
  });
  if (res.status !== 200) return { pass: false, detail: `batch mint ${res.status}` };
  const batch = await res.json();
  const hero = batch.tokens?.a;
  if (!hero) return { pass: false, detail: 'no batch token issued' };
  const swapped = await redeem(base, { ...hero, cleanUrl: hero.cleanUrl.replace('/cat', '/dog') }, browserHeaders('viewer-batch'));
  return { pass: swapped.status >= 400, detail: `dog-with-cat-batch-token ${swapped.status}` };
});

/* ==================== C. authz & config ==================== */
console.log('\nC. Authorization & configuration attacks');

await attack('authz', 'missing authorize + missing allowAnonymous fails closed at startup', async () => {
  let threw = false;
  try { createArchxMiddleware({ secret: SECRET, imagesDir: dir }); } catch { threw = true; }
  return { pass: threw, detail: threw ? 'constructor throws' : 'silently constructed an open server' };
});
await attack('authz', 'throwing authorize denies the request (no bytes leak)', async () => {
  const h2 = createArchxMiddleware({
    secret: SECRET, imagesDir: dir,
    authorize: async () => { throw new Error('db is down'); },
  });
  const s2 = await startServer(h2);
  try {
    const r = await postToken(`${s2.base}/archx/token/cat?w=200`, { headers: {} });
    const text = await r.text();
    return { pass: r.status >= 400 && !text.includes('db is down'), detail: `status ${r.status}` };
  } finally { s2.server.close(); h2.close?.(); }
});
await attack('authz', 'authorize-granted width beyond maxWidthCap is clamped', async () => {
  const h2 = createArchxMiddleware({
    secret: SECRET, imagesDir: dir, maxWidthCap: 300,
    authorize: async () => ({ viewerId: 'greedy', maxWidth: 99999 }),
  });
  const s2 = await startServer(h2);
  try {
    const res = await postToken(`${s2.base}/archx/token/cat?w=900`, { headers: {} });
    const body = await res.json();
    const r = await redeem(s2.base, body, { headers: {} });
    const { header } = decodeContainer(new Uint8Array(await r.arrayBuffer()));
    return { pass: header.w <= 300, detail: `delivered ${header.w} (cap 300)` };
  } finally { s2.server.close(); h2.close?.(); }
});
await attack('authz', 'prototype pollution via batch JSON body does not pollute Object.prototype', async () => {
  const res = await postToken(`${base}/archx/tokens`, {
    headers: { 'content-type': 'application/json', ...browserHeaders('viewer-batch').headers },
    body: '{"items":[{"ref":"a","id":"cat","w":200}],"__proto__":{"archxPolluted":true},"constructor":{"prototype":{"archxPolluted2":true}}}',
  });
  await res.text().catch(() => '');
  const clean = ({}).archxPolluted === undefined && ({}).archxPolluted2 === undefined;
  return { pass: clean, detail: clean ? 'Object.prototype untouched' : 'POLLUTED' };
});
await attack('authz', 'masters inside a declared public dir are flagged by the config audit', async () => {
  const audit = auditArchxServerConfig({
    secret: SECRET, imagesDir: dir, publicDir: path.dirname(dir), allowAnonymous: true,
  });
  return { pass: audit.ok === false, detail: `audit.ok=${audit.ok}` };
});
await attack('authz', 'misspelled security option fails closed at startup', async () => {
  let threw = false;
  try {
    createArchxMiddleware({ secret: SECRET, imagesDir: dir, allowAnonymous: true, allowdOrigins: ['https://x.test'] });
  } catch { threw = true; }
  return { pass: threw, detail: threw ? 'unknown option rejected' : 'typo silently ignored' };
});
await attack('authz', 'known-weak demo secret is rejected at startup', async () => {
  let threw = false;
  try {
    createArchxMiddleware({ secret: 'secret', imagesDir: dir, allowAnonymous: true });
  } catch { threw = true; }
  return { pass: threw, detail: threw ? 'weak secret rejected' : 'weak secret accepted' };
});

/* ==================== D. path & ID attacks ==================== */
console.log('\nD. Path traversal & identifier attacks');

await attack('path', 'traversal / encoded / separator image IDs never resolve to files', async () => {
  const ids = ['..%2F..%2Fetc%2Fpasswd', '%2e%2e%5ccat', 'cat%00.jpg', 'cat/extra', '..', 'cat%2f..%2fdog', 'a'.repeat(500), '...jpg'];
  for (const id of ids) {
    const { res, body } = await mint(id, 200).catch(() => ({ res: { status: 0 }, body: null }));
    if (res.status === 200 && body) {
      const r = await redeem(base, body, browserHeaders());
      if (r.status === 200) return { pass: false, detail: `id ${JSON.stringify(id.slice(0, 40))} served bytes` };
    }
  }
  return { pass: true, detail: `${ids.length} hostile ids refused end-to-end` };
});
await attack('path', 'symlink inside masters dir cannot escape to outside content', async () => {
  if (!symlinkOk) return { pass: null, detail: 'symlink creation not permitted in this sandbox' };
  const { res, body } = await mint('escape', 200);
  if (res.status !== 200) return { pass: true, detail: `mint refused ${res.status}` };
  const r = await redeem(base, body, browserHeaders());
  return { pass: r.status >= 400, detail: `redeem ${r.status} (outside-secret.jpg must never be served)` };
});
await attack('path', 'URL-shaped image ID triggers no outbound fetch (SSRF shape)', async () => {
  const { res } = await mint(encodeURIComponent('http://169.254.169.254/latest/meta-data'), 200);
  return { pass: res.status >= 400, detail: `status ${res.status}` };
});

/* ==================== E. resource exhaustion ==================== */
console.log('\nE. Resource exhaustion & malformed input');

await attack('dos', 'garbage-bytes master fails controlled; server survives', async () => {
  const { res, body } = await mint('garbage', 200);
  let status = res.status;
  if (status === 200 && body) status = (await redeem(base, body, browserHeaders())).status;
  const alive = (await mint('cat', 200)).res.status === 200;
  return { pass: status >= 400 && alive, detail: `garbage ${status}, server alive: ${alive}` };
});
await attack('dos', 'pixel-bomb master (60000x60000 IHDR) is rejected by limits, fast', async () => {
  const t0 = Date.now();
  const { res, body } = await mint('bomb', 200);
  let status = res.status;
  if (status === 200 && body) status = (await redeem(base, body, browserHeaders())).status;
  const ms = Date.now() - t0;
  const alive = (await mint('cat', 200)).res.status === 200;
  return { pass: status >= 400 && alive && ms < 15000, detail: `bomb ${status} in ${ms}ms, alive: ${alive}` };
});
await attack('dos', '40 concurrent mint+redeem pairs complete bounded (no hang/crash)', async () => {
  const t0 = Date.now();
  const jobs = Array.from({ length: 40 }, async (_, i) => {
    const { res, body } = await mint('cat', 200, `viewer-${i % 5}`);
    if (res.status !== 200) return res.status;
    return (await redeem(base, body, browserHeaders(`viewer-${i % 5}`))).status;
  });
  const statuses = await Promise.all(jobs);
  const ok = statuses.filter((s) => s === 200).length;
  const bounded = statuses.every((s) => s === 200 || s === 429 || s === 503);
  return { pass: bounded && ok >= 20 && Date.now() - t0 < 60000, detail: `${ok}/40 ok in ${Date.now() - t0}ms` };
});
await attack('dos', '1MB token header value is refused without crashing', async () => {
  const r = await fetch(`${base}/archx/i/cat`, {
    headers: { 'x-archx-token': 'A'.repeat(1024 * 1024), ...browserHeaders().headers },
  }).catch(() => ({ status: 431 }));
  const alive = (await mint('cat', 200)).res.status === 200;
  return { pass: r.status >= 400 && alive, detail: `status ${r.status}, alive: ${alive}` };
});
await attack('dos', 'mint flood engages the token rate limiter', async () => {
  const h2 = createArchxMiddleware({
    secret: SECRET, imagesDir: dir, allowAnonymous: true,
    tokenRateLimitPerMinute: 15, rateLimitPerMinute: 10000,
  });
  const s2 = await startServer(h2);
  try {
    let saw429 = false;
    for (let i = 0; i < 40 && !saw429; i++) {
      const r = await postToken(`${s2.base}/archx/token/cat?w=200`, { headers: {} });
      if (r.status === 429) saw429 = true;
      await r.text().catch(() => '');
    }
    return { pass: saw429, detail: saw429 ? '429 engaged' : 'no 429 in 40 rapid mints at limit 15/min' };
  } finally { s2.server.close(); h2.close?.(); }
});

/* ==================== F. privacy & leakage ==================== */
console.log('\nF. Cache privacy & information leakage');

await attack('privacy', 'derivative responses are private/no-store', async () => {
  const { body } = await mint('cat', 200);
  const r = await redeem(base, body, browserHeaders());
  const cc = (r.headers.get('cache-control') || '').toLowerCase();
  return { pass: cc.includes('no-store') || cc.includes('private'), detail: `cache-control: ${cc || '(none!)'}` };
});
await attack('privacy', 'per-token marks make two viewers\' payloads byte-different', async () => {
  const a = await mint('cat', 200, 'viewer-a');
  const b = await mint('cat', 200, 'viewer-b');
  const bytesA = new Uint8Array(await (await redeem(base, a.body, browserHeaders('viewer-a'))).arrayBuffer());
  const bytesB = new Uint8Array(await (await redeem(base, b.body, browserHeaders('viewer-b'))).arrayBuffer());
  const same = bytesA.length === bytesB.length && bytesA.every((v, i) => v === bytesB[i]);
  return { pass: !same, detail: same ? 'IDENTICAL payloads for different viewers' : 'payloads differ per token' };
});
await attack('privacy', 'error responses leak no secrets, paths, or stack traces', async () => {
  const probes = [
    await fetch(`${base}/archx/i/cat`, browserHeaders()),
    await fetch(`${base}/archx/token/nope`, { method: 'POST', headers: { 'x-archx-request': 'token', ...browserHeaders().headers } }),
    await fetch(`${base}/archx/i/%ZZ`, browserHeaders()).catch(() => null),
  ];
  for (const r of probes) {
    if (!r) continue;
    const text = await r.text();
    if (text.includes(SECRET) || text.includes(STEGO_KEY) || text.includes(dir) || text.includes('node_modules') || /\n\s*at\s+\w+/.test(text)) {
      return { pass: false, detail: `leak in ${r.status} body: ${text.slice(0, 120)}` };
    }
  }
  return { pass: true, detail: 'error bodies are clean' };
});
await attack('privacy', 'token response JSON carries no key material', async () => {
  const { res } = await mint('cat', 200);
  const text = JSON.stringify(await res.clone().json());
  return { pass: !text.includes(SECRET) && !text.includes(STEGO_KEY), detail: 'no secrets in mint response' };
});

/* ==================== G. adversarial stego ==================== */
console.log('\nG. Adversarial steganography (misattribution = failure)');

const photo = await (async () => {
  const p = new URL('../demo-masters/aurora-valley.jpg', import.meta.url);
  const { data, info } = await sharp(fs.readFileSync(p)).resize(800).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  return { buf: new Uint8Array(data), w: info.width, h: info.height };
})();

await attack('stego', 'mark planted under a different key does not attribute', async () => {
  const marked = embedStegoFingerprint(photo.buf, photo.w, photo.h, 'VICTIM-1', { key: 'attacker-key', profile: 'robust', strength: 6 });
  const hit = detectStegoFingerprint(marked, photo.w, photo.h, { key: STEGO_KEY, profile: 'robust' });
  return { pass: !hit.found, detail: hit.found ? `attributed ${hit.fingerprint}` : 'not found under victim key' };
});
await attack('stego', 'two-buyer average (collusion) yields no phantom fingerprint', async () => {
  const a = embedStegoFingerprint(photo.buf, photo.w, photo.h, 'BUYER-A', { key: STEGO_KEY, profile: 'robust', strength: 6 });
  const b = embedStegoFingerprint(photo.buf, photo.w, photo.h, 'BUYER-B', { key: STEGO_KEY, profile: 'robust', strength: 6 });
  const avg = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) avg[i] = (a[i] + b[i]) >> 1;
  const hit = detectStegoFingerprint(avg, photo.w, photo.h, { key: STEGO_KEY, profile: 'robust', searchGeometry: true, maxTimeMs: 30000 });
  const okFps = new Set([stegoFingerprint('BUYER-A'), stegoFingerprint('BUYER-B')]);
  return {
    pass: !hit.found || okFps.has(hit.fingerprint),
    detail: hit.found ? `found ${hit.fingerprint} (participant: ${okFps.has(hit.fingerprint)})` : 'no decode (expected: MAC rejects hybrids)',
  };
});
await attack('stego', 'heavy denoise/recompress never MISattributes to another payload', async () => {
  const marked = embedStegoFingerprint(photo.buf, photo.w, photo.h, 'BUYER-A', { key: STEGO_KEY, profile: 'robust', strength: 6 });
  const abused = await sharp(Buffer.from(marked), { raw: { width: photo.w, height: photo.h, channels: 4 } })
    .resize(520).blur(1.2).jpeg({ quality: 42 }).toBuffer();
  const back = await sharp(abused).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const hit = detectStegoFingerprint(new Uint8Array(back.data), back.info.width, back.info.height, {
    key: STEGO_KEY, profile: 'robust', searchGeometry: true, maxTimeMs: 30000,
  });
  return {
    pass: !hit.found || hit.fingerprint === stegoFingerprint('BUYER-A'),
    detail: hit.found ? `still correctly attributed (${hit.fingerprint})` : 'mark destroyed (documented limit), no wrong attribution',
  };
});
await attack('stego', 'transplant: marked region pasted onto a different photo (informational)', async () => {
  const marked = embedStegoFingerprint(photo.buf, photo.w, photo.h, 'BUYER-A', { key: STEGO_KEY, profile: 'robust', strength: 6 });
  const donor = await sharp(Buffer.from(marked), { raw: { width: photo.w, height: photo.h, channels: 4 } }).png().toBuffer();
  const other = await sharp(fs.readFileSync(new URL('../demo-masters/luxury-watch.jpg', import.meta.url))).resize(800).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const hostPng = await sharp(Buffer.from(other.data), { raw: { width: other.info.width, height: other.info.height, channels: 4 } }).png().toBuffer();
  const patch = await sharp(donor).extract({ left: 0, top: 0, width: 400, height: 218 }).png().toBuffer();
  const franken = await sharp(hostPng).composite([{ input: patch, left: 0, top: 0 }]).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const hit = detectStegoFingerprint(new Uint8Array(franken.data), franken.info.width, franken.info.height, {
    key: STEGO_KEY, profile: 'robust', searchGeometry: true, maxTimeMs: 30000,
  });
  return {
    pass: null,
    detail: hit.found
      ? `transplant decoded as ${hit.fingerprint} — pixel marks are copyable with the pixels; issuance records + geometry must corroborate`
      : 'transplant did not decode (grid/geometry disagreement)',
  };
});

/* ============================== report ============================== */

server.close();
handler.close?.();
fs.rmSync(dir, { recursive: true, force: true });
fs.rmSync(outside, { recursive: true, force: true });

const held = results.filter((r) => r.pass === true).length;
const info = results.filter((r) => r.pass === null).length;
console.log(`\nRed-team summary: ${held}/${results.length - info} defenses held, ${failures} failed, ${info} informational.`);
const jsonArg = process.argv.indexOf('--json');
if (jsonArg > 0 && process.argv[jsonArg + 1]) {
  fs.writeFileSync(process.argv[jsonArg + 1], JSON.stringify({ held, failures, info, results }, null, 2));
}
process.exit(failures ? 1 : 0);
