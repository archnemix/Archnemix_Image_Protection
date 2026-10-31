#!/usr/bin/env node
/**
 * Red-team attack suite for Archnemix Image Protection.
 *
 * Frames the security claims as attacks and tries to break them:
 * master/derivative extraction, token forgery & replay, authz
 * bypass, path/ID traversal, resource exhaustion, cache/privacy
 * leakage, adversarial steganography (misattribution is the
 * failure that matters — a destroyed mark is a documented limit,
 * a WRONG attribution is a bug), plus section H: redemption races,
 * HTTP method/header/cache semantics, signed-claim fuzzing,
 * keyring confusion, batch abuse, slow-trickle bodies, scrape
 * quotas, and proof-of-possession theft/replay.
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
import { createArchxMiddleware, auditArchxServerConfig, computeJwkThumbprint } from '../server/middleware.js';
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

/* ==================== H. races, HTTP semantics, claim fuzz ==================== */
console.log('\nH. Races, HTTP semantics, claim validation, sender constraints');

await attack('race', '16-way concurrent redeem of a one-time token: exactly one wins', async () => {
  const { body } = await mint();
  const statuses = await Promise.all(Array.from({ length: 16 }, () =>
    redeem(base, body, browserHeaders()).then((x) => x.status).catch(() => 0)));
  const wins = statuses.filter((s) => s === 200).length;
  return { pass: wins === 1, detail: `${wins}/16 succeeded (TOCTOU race must admit exactly one)` };
});
await attack('http', 'POST/HEAD/PUT on the redeem URL deliver nothing and do not spend the claim', async () => {
  const { body } = await mint();
  const attempts = [];
  for (const method of ['POST', 'PUT', 'HEAD', 'DELETE']) {
    const r = await fetch(base + body.cleanUrl, { method, headers: { 'x-archx-token': body.token, ...browserHeaders().headers } });
    await r.text().catch(() => '');
    attempts.push(`${method}:${r.status}`);
    if (r.status === 200) return { pass: false, detail: `${method} returned 200 on a GET-only route` };
  }
  const genuine = await redeem(base, body, browserHeaders());
  return { pass: genuine.status === 200, detail: `${attempts.join(' ')}; genuine GET after: ${genuine.status}` };
});
await attack('http', 'GET on the mint endpoint does not mint', async () => {
  const r = await fetch(`${base}/archx/token/cat?w=200`, { headers: { 'x-archx-request': 'token', ...browserHeaders().headers } });
  const text = await r.text();
  return { pass: r.status >= 400 && !text.includes('"token"'), detail: `status ${r.status}` };
});
await attack('http', 'conditional/range headers open no side door (If-None-Match without token; Range with token)', async () => {
  const noTok = await fetch(`${base}/archx/i/cat`, { headers: { 'if-none-match': '*', ...browserHeaders().headers } });
  await noTok.text().catch(() => '');
  const { body } = await mint();
  const ranged = await fetch(base + body.cleanUrl, { headers: { range: 'bytes=0-99', 'x-archx-token': body.token, ...browserHeaders().headers } });
  const len = (await ranged.arrayBuffer()).byteLength;
  return {
    pass: noTok.status >= 400 && ranged.status !== 206,
    detail: `no-token+INM ${noTok.status}; ranged redeem ${ranged.status} (${len} bytes, must never be 206 partial)`,
  };
});
await attack('token', 'duplicate token headers (garbage + genuine smuggled together) are refused, claim unburned', async () => {
  const { body } = await mint();
  const hdrs = new Headers(browserHeaders().headers);
  hdrs.append('x-archx-token', 'garbage.token');
  hdrs.append('x-archx-token', body.token);
  const smuggled = await fetch(base + body.cleanUrl, { headers: hdrs });
  await smuggled.text().catch(() => '');
  const genuine = await redeem(base, body, browserHeaders());
  return { pass: smuggled.status >= 400 && genuine.status === 200, detail: `dup-header ${smuggled.status}, genuine ${genuine.status}` };
});
await attack('token', 'structurally malformed tokens are all refused; genuine token still spends', async () => {
  const { body } = await mint();
  // Note: leading/trailing-space shapes are excluded deliberately —
  // HTTP field parsing strips optional whitespace (RFC 9110) before
  // the app sees the value, so a spaced header IS the genuine token
  // (possession is the credential; whitespace adds no forgery power).
  const shapes = ['', '.', 'a.', '.b', 'a.b.c', 'a..b', body.token + '.extra', body.token.toUpperCase(),
    body.token + '=', body.token.replace('.', ' .'), 'eyJhbGciOiJub25lIn0.' + body.token, '🔑.🔑', body.token.replace('.', '..')];
  for (const t of shapes) {
    const r = await fetch(base + body.cleanUrl, { headers: { 'x-archx-token': t, ...browserHeaders().headers } }).catch(() => ({ status: 400 }));
    if (r.status === 200) return { pass: false, detail: `shape ${JSON.stringify(t.slice(0, 24))} accepted` };
  }
  const genuine = await redeem(base, body, browserHeaders());
  return { pass: genuine.status === 200, detail: `${shapes.length} malformed shapes refused; genuine ${genuine.status}` };
});
await attack('token', 'validly-signed but claim-fuzzed tokens gain nothing (insider-secret defense in depth)', async () => {
  const { body } = await mint();
  const claims = JSON.parse(Buffer.from(body.token.split('.')[0], 'base64url').toString());
  const now = Date.now();
  const nonce = () => crypto.randomBytes(12).toString('base64url');
  const sign = (c) => {
    const p = Buffer.from(JSON.stringify(c)).toString('base64url');
    return `${p}.${crypto.createHmac('sha256', SECRET).update(p).digest().toString('base64url')}`;
  };
  const variants = [
    ['w as string', { w: '240' }], ['w negative', { w: -5 }], ['w astronomical', { w: 1e9 }],
    ['id swapped', { id: 'dog' }], ['aud wrong', { aud: 'archx:other' }], ['scope escalated', { scope: 'image:admin' }],
    ['extra claim', { admin: true }], ['iat 1h in future', { iat: now + 3600000, exp: now + 3660000 }],
    ['exp as string', { exp: String(now + 60000) }], ['v futuristic', { v: 99 }],
  ];
  for (const [label, patch] of variants) {
    const r = await redeem(base, { ...body, token: sign({ ...claims, ...patch, n: nonce() }) }, browserHeaders());
    if (r.status === 200) {
      const { header } = decodeContainer(new Uint8Array(await r.arrayBuffer()));
      return { pass: false, detail: `${label}: accepted (delivered ${header.w}px) — claim validation should refuse` };
    }
  }
  const noNonce = { ...claims }; delete noNonce.n;
  const r = await redeem(base, { ...body, token: sign(noNonce) }, browserHeaders());
  return { pass: r.status >= 400, detail: `${variants.length} fuzzed claims + missing-nonce all refused (last ${r.status})` };
});
await attack('token', 'keyring kid confusion: MAC from key A presented under kid B is refused', async () => {
  const SECRET_A = 'keyring-secret-AAAA-well-over-32-bytes!!';
  const SECRET_B = 'keyring-secret-BBBB-well-over-32-bytes!!';
  const h2 = createArchxMiddleware({ secrets: { keyA: SECRET_A, keyB: SECRET_B }, secretId: 'keyA', imagesDir: dir, allowAnonymous: true });
  const s2 = await startServer(h2);
  try {
    const res = await postToken(`${s2.base}/archx/token/cat?w=200`, { headers: {} });
    const minted = await res.json();
    const claims = JSON.parse(Buffer.from(minted.token.split('.')[0], 'base64url').toString());
    const signAs = (c, secret) => {
      const p = Buffer.from(JSON.stringify(c)).toString('base64url');
      return `${p}.${crypto.createHmac('sha256', secret).update(p).digest().toString('base64url')}`;
    };
    const sanity = await redeem(s2.base, minted, { headers: {} });
    const confused = await redeem(s2.base, { ...minted, token: signAs({ ...claims, kid: 'keyB', n: crypto.randomBytes(12).toString('base64url') }, SECRET_A) }, { headers: {} });
    const pathy = await redeem(s2.base, { ...minted, token: signAs({ ...claims, kid: '../keyA', n: crypto.randomBytes(12).toString('base64url') }, SECRET_A) }, { headers: {} });
    return {
      pass: sanity.status === 200 && confused.status >= 400 && pathy.status >= 400,
      detail: `genuine ${sanity.status}, A-signed-as-B ${confused.status}, pathy-kid ${pathy.status}`,
    };
  } finally { s2.server.close(); h2.close?.(); }
});
await attack('batch', 'batch abuse shapes are bounded (2000 items, non-array items, __proto__ ref)', async () => {
  const bigItems = Array.from({ length: 2000 }, (_, i) => ({ ref: `r${i}`, id: 'cat', w: 100 }));
  const t0 = Date.now();
  const huge = await postToken(`${base}/archx/tokens`, {
    headers: { 'content-type': 'application/json', ...browserHeaders('viewer-batch').headers },
    body: JSON.stringify({ items: bigItems }),
  });
  let mintedCount = 0;
  if (huge.status === 200) mintedCount = Object.keys((await huge.json()).tokens || {}).length;
  else await huge.text().catch(() => '');
  const nonArray = await postToken(`${base}/archx/tokens`, {
    headers: { 'content-type': 'application/json', ...browserHeaders('viewer-batch').headers },
    body: JSON.stringify({ items: { a: 1 } }),
  });
  await nonArray.text().catch(() => '');
  const protoRef = await postToken(`${base}/archx/tokens`, {
    headers: { 'content-type': 'application/json', ...browserHeaders('viewer-batch').headers },
    body: JSON.stringify({ items: [{ ref: '__proto__', id: 'cat', w: 100 }] }),
  });
  await protoRef.text().catch(() => '');
  const clean = ({}).cat === undefined && ({}).archxPolluted === undefined;
  return {
    pass: (huge.status >= 400 || mintedCount <= 256) && nonArray.status >= 400 && clean && Date.now() - t0 < 30000,
    detail: `2000-item batch: ${huge.status} (minted ${mintedCount}), non-array: ${nonArray.status}, proto-ref clean: ${clean}`,
  };
});
await attack('dos', 'slow-trickle batch body is cut by the read deadline', async () => {
  const h2 = createArchxMiddleware({ secret: SECRET, imagesDir: dir, allowAnonymous: true, callbackTimeoutMs: 1500 });
  const s2 = await startServer(h2);
  try {
    const outcome = await new Promise((resolve) => {
      const url = new URL(`${s2.base}/archx/tokens`);
      const t0 = Date.now();
      const req = http.request({
        hostname: url.hostname, port: url.port, path: url.pathname, method: 'POST',
        headers: { 'content-type': 'application/json', 'x-archx-request': 'token', 'transfer-encoding': 'chunked' },
      }, (res) => { res.resume(); res.on('end', () => resolve({ kind: 'response', status: res.statusCode, ms: Date.now() - t0 })); });
      req.on('error', () => resolve({ kind: 'socket-cut', status: 0, ms: Date.now() - t0 }));
      req.write('{"items":[{"ref":"a","id":"cat","w":100}');
      const iv = setInterval(() => { try { req.write(' '); } catch { clearInterval(iv); } }, 500);
      setTimeout(() => { clearInterval(iv); try { req.destroy(); } catch {} resolve({ kind: 'still-open', status: 0, ms: Date.now() - t0 }); }, 9000);
    });
    const alive = (await postToken(`${s2.base}/archx/token/cat?w=100`, { headers: {} })).status === 200;
    return {
      pass: outcome.kind !== 'still-open' && outcome.ms < 9000 && alive,
      detail: `trickle ${outcome.kind} after ${outcome.ms}ms (deadline 1500ms), server alive: ${alive}`,
    };
  } finally { s2.server.close(); h2.close?.(); }
});
await attack('http', 'CRLF in the image id injects no response headers', async () => {
  const r = await fetch(`${base}/archx/i/cat%0d%0aX-Injected:%20pwned`, browserHeaders()).catch(() => null);
  const m = await postToken(`${base}/archx/token/cat%0d%0aX-Injected:%20pwned?w=100`, browserHeaders()).catch(() => null);
  const injected = (x) => x && x.headers.get('x-injected') !== null;
  return { pass: !injected(r) && !injected(m), detail: `redeem ${r?.status}, mint ${m?.status}, x-injected absent` };
});
await attack('http', 'cache-deception suffixes (.css / ;param) on the redeem path get no cacheable derivative', async () => {
  for (const suffix of ['.css', ';v=2', '.js']) {
    const { body } = await mint('cat', 200);
    const mutated = body.cleanUrl.replace('/cat', `/cat${suffix}`);
    const r = await fetch(base + mutated, { headers: { 'x-archx-token': body.token, ...browserHeaders().headers } });
    await r.arrayBuffer().catch(() => {});
    if (r.status === 200) {
      const cc = (r.headers.get('cache-control') || '').toLowerCase();
      return { pass: false, detail: `${suffix}: derivative served under a mutated id (cache-control: ${cc})` };
    }
  }
  return { pass: true, detail: 'all suffix mutations refused' };
});
await attack('quota', 'distinct-image scrape quota denies the 4th distinct image (action: deny)', async () => {
  const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-redteam-quota-'));
  for (const id of ['im1', 'im2', 'im3', 'im4', 'im5']) {
    fs.writeFileSync(path.join(dir2, `${id}.jpg`), await syntheticMaster(200, 150, id.toUpperCase()));
  }
  const h2 = createArchxMiddleware({
    secret: SECRET, imagesDir: dir2, allowAnonymous: true,
    abuseDetection: { distinctImages: 3, action: 'deny' },
  });
  const s2 = await startServer(h2);
  try {
    const statuses = [];
    for (const id of ['im1', 'im2', 'im3', 'im4']) {
      const r = await postToken(`${s2.base}/archx/token/${id}?w=100`, { headers: {} });
      await r.text().catch(() => '');
      statuses.push(r.status);
    }
    return {
      pass: statuses[0] === 200 && statuses[1] === 200 && statuses[2] === 200 && statuses[3] === 429,
      detail: `mints: ${statuses.join(',')} (4th distinct must 429; deny stays sticky for the window by design)`,
    };
  } finally { s2.server.close(); h2.close?.(); fs.rmSync(dir2, { recursive: true, force: true }); }
});
await attack('pop', 'proof-of-possession: bearer copy, wrong key, wrong target, and proof replay all fail', async () => {
  const makeKey = () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const ex = publicKey.export({ format: 'jwk' });
    const jwk = { kty: 'EC', crv: 'P-256', x: ex.x, y: ex.y };
    return { privateKey, jwk, header: Buffer.from(JSON.stringify(jwk)).toString('base64url') };
  };
  const makeProof = (key, token, target) => {
    const proof = {
      jwk: key.jwk, jti: crypto.randomBytes(18).toString('base64url'),
      iat: Date.now(), exp: Date.now() + 60000, htm: 'GET', htu: target,
      ath: crypto.createHash('sha256').update(token).digest().toString('base64url'),
    };
    const input = `v1.${Buffer.from(JSON.stringify(proof)).toString('base64url')}`;
    const sig = crypto.sign('sha256', Buffer.from(input), { key: key.privateKey, dsaEncoding: 'ieee-p1363' });
    return `${input}.${sig.toString('base64url')}`;
  };
  const h2 = createArchxMiddleware({
    secret: SECRET, imagesDir: dir, allowAnonymous: true,
    proofOfPossession: 'required', oneTimeTokens: false,
  });
  const s2 = await startServer(h2);
  try {
    const key = makeKey(), wrong = makeKey();
    const noKey = await postToken(`${s2.base}/archx/token/cat?w=160`, { headers: {} });
    await noKey.text().catch(() => '');
    const mintRes = await postToken(`${s2.base}/archx/token/cat?w=160`, { headers: { 'x-archx-proof-key': key.header } });
    const minted = await mintRes.json();
    const spend = (proof) => fetch(s2.base + minted.cleanUrl, {
      headers: { 'x-archx-token': minted.token, ...(proof ? { 'x-archx-proof': proof } : {}) },
    }).then(async (r) => { await r.arrayBuffer().catch(() => {}); return r.status; });
    const bearer = await spend(null);
    const wrongKey = await spend(makeProof(wrong, minted.token, minted.cleanUrl));
    const wrongTarget = await spend(makeProof(key, minted.token, '/archx/i/dog'));
    const good = makeProof(key, minted.token, minted.cleanUrl);
    const first = await spend(good);
    const replayed = await spend(good);
    const fresh = await spend(makeProof(key, minted.token, minted.cleanUrl));
    return {
      pass: noKey.status === 403 && bearer === 403 && wrongKey === 403 && wrongTarget === 403 && first === 200 && replayed === 403 && fresh === 200,
      detail: `no-key mint ${noKey.status}; bearer ${bearer}; wrong-key ${wrongKey}; wrong-target ${wrongTarget}; good ${first}; proof-replay ${replayed}; fresh ${fresh}`,
    };
  } finally { s2.server.close(); h2.close?.(); }
});
await attack('extract', 'derivative cache never serves one width under another width\'s token', async () => {
  const widths = [];
  for (const w of [100, 240, 100]) {
    const { body } = await mint('cat', w);
    const r = await redeem(base, body, browserHeaders());
    widths.push(decodeContainer(new Uint8Array(await r.arrayBuffer())).header.w);
  }
  return {
    pass: widths[1] > widths[0] && widths[2] === widths[0] && widths[1] <= 240,
    detail: `delivered widths ${widths.join(', ')} for requests 100/240/100`,
  };
});
await attack('authz', 'authorize returning garbage shapes never widens access (true / string / null / NaN / negative)', async () => {
  const shapes = [
    ['true', async () => true], ['string', async () => 'yes'], ['null', async () => null],
    ['string-maxWidth', async () => ({ viewerId: 's', maxWidth: '99999' })],
    ['NaN-maxWidth', async () => ({ viewerId: 'n', maxWidth: NaN })],
    ['negative-maxWidth', async () => ({ viewerId: 'neg', maxWidth: -50 })],
  ];
  for (const [label, authorize] of shapes) {
    const h2 = createArchxMiddleware({ secret: SECRET, imagesDir: dir, maxWidthCap: 300, authorize });
    const s2 = await startServer(h2);
    try {
      const res = await postToken(`${s2.base}/archx/token/cat?w=900`, { headers: {} });
      if (res.status === 200) {
        const body = await res.json();
        const r = await redeem(s2.base, body, { headers: {} });
        if (r.status === 200) {
          const { header } = decodeContainer(new Uint8Array(await r.arrayBuffer()));
          if (header.w > 300) return { pass: false, detail: `${label}: delivered ${header.w} > cap 300` };
        }
      } else {
        const text = await res.text();
        if (/^\s*at\s+\w+/m.test(text) || text.includes(SECRET)) return { pass: false, detail: `${label}: error body leaks internals` };
      }
    } finally { s2.server.close(); h2.close?.(); }
  }
  return { pass: true, detail: '6 garbage shapes: denied or clamped to cap, no leaks' };
});
await attack('stego', 'median + noise + 0.55x + q38 chain never MISattributes; wrong key finds nothing', async () => {
  const marked = embedStegoFingerprint(photo.buf, photo.w, photo.h, 'BUYER-A', { key: STEGO_KEY, profile: 'robust', strength: 6 });
  let s = 1234;
  const rnd = () => (s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  const noisy = new Uint8Array(marked);
  for (let i = 0; i < noisy.length; i += 4) {
    const n = Math.round((rnd() - 0.5) * 28);
    noisy[i] = Math.max(0, Math.min(255, noisy[i] + n));
    noisy[i + 1] = Math.max(0, Math.min(255, noisy[i + 1] + n));
    noisy[i + 2] = Math.max(0, Math.min(255, noisy[i + 2] + n));
  }
  const abused = await sharp(Buffer.from(noisy), { raw: { width: photo.w, height: photo.h, channels: 4 } })
    .median(3).resize(Math.round(photo.w * 0.55)).jpeg({ quality: 38 }).toBuffer();
  const back = await sharp(abused).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const px = new Uint8Array(back.data);
  const hit = detectStegoFingerprint(px, back.info.width, back.info.height, { key: STEGO_KEY, profile: 'robust', searchGeometry: true, maxTimeMs: 30000 });
  const wrongKey = detectStegoFingerprint(px, back.info.width, back.info.height, { key: 'someone-else', profile: 'robust', searchGeometry: true, maxTimeMs: 30000 });
  return {
    pass: (!hit.found || hit.fingerprint === stegoFingerprint('BUYER-A')) && !wrongKey.found,
    detail: hit.found ? 'still BUYER-A after the chain; wrong key: nothing' : 'mark destroyed (limit), wrong key: nothing, no misattribution',
  };
});
await attack('timing', 'MAC-validity timing oracle (informational measurement)', async () => {
  // One retry: after ~53 attacks the sandbox socket pool can hiccup;
  // an INFO measurement must never fail the suite on plumbing noise.
  let mintOut;
  try { mintOut = await mint(); } catch { await new Promise((r) => setTimeout(r, 300)); mintOut = await mint().catch(() => null); }
  if (!mintOut?.body) return { pass: null, detail: 'measurement unavailable (transient fetch failure at mint)' };
  const { body } = mintOut;
  const claims = JSON.parse(Buffer.from(body.token.split('.')[0], 'base64url').toString());
  const p = Buffer.from(JSON.stringify({ ...claims, exp: Date.now() - 1000 })).toString('base64url');
  const expiredValidMac = `${p}.${crypto.createHmac('sha256', SECRET).update(p).digest().toString('base64url')}`;
  const garbageMac = `${p}.${'A'.repeat(43)}`;
  const time = async (token) => {
    const samples = [];
    for (let i = 0; i < 40; i++) {
      const t0 = performance.now();
      await fetch(base + body.cleanUrl, { headers: { 'x-archx-token': token, ...browserHeaders().headers } })
        .then((r) => r.text()).catch(() => '');
      samples.push(performance.now() - t0);
    }
    samples.sort((a, b) => a - b);
    return samples[20].toFixed(2);
  };
  const g = await time(garbageMac);
  const v = await time(expiredValidMac);
  return { pass: null, detail: `median garbage-MAC ${g}ms vs valid-MAC-expired ${v}ms (HTTP noise dominates; HMAC compare is timingSafeEqual + canonical-gated)` };
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
