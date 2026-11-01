#!/usr/bin/env node
/**
 * Red-team suite v2 for Archnemix Image Protection (v1.24).
 *
 * A second, independent battery aimed at the classes the first
 * suite did not frame as attacks: HTTP parsing ambiguity (duplicate
 * headers, method override, parameter pollution, duplicate
 * Content-Length smuggling shapes, absolute-form targets, oversized
 * headers), injection into the JSON/config plane (prototype
 * pollution, mass assignment, deeply nested bodies, content-type
 * confusion), cache/CORS/error-surface leakage, attribution abuse
 * (wrong-key lottery, noise false positives, screenshot chains,
 * two-buyer collusion averaging), and resource bounds.
 *
 * Same rules as tools/red-team.mjs: every entry states the defense
 * it expects; FAIL exits 1; INFO reports measured limits.
 *
 *   node tools/red-team-v2.mjs [--json out.json]
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import net from 'node:net';
import sharp from 'sharp';
import { createArchxMiddleware } from '../server/middleware.js';
import { decodeContainer, embedStegoFingerprint, detectStegoFingerprint, stegoFingerprint } from '../src/scramble.js';

const SECRET = 'red-team-v2-secret-with-well-over-32-bytes!';
const STEGO_KEY = 'red-team-v2-stego-key';
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
  } catch (err) { record(cls, name, false, `attack errored: ${err?.message || err}`); }
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
async function startServer(handler) {
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { server, base: `http://127.0.0.1:${server.address().port}` };
}
const browserHeaders = (viewer = 'viewer-a', ua = 'BrowserA') => ({
  headers: { 'user-agent': ua, referer: 'https://example.test/page', 'x-viewer': viewer },
});
const postToken = (url, init = {}) => fetch(url, {
  method: 'POST', ...init,
  headers: { 'x-archx-request': 'token', ...(init.headers || {}) },
});
const redeem = (base, tokenRes, init = {}) => fetch(base + tokenRes.cleanUrl, {
  ...init, headers: { ...(init.headers || {}), 'x-archx-token': tokenRes.token },
});
function rawHttp(base, raw, timeoutMs = 5000) {
  const { hostname, port } = new URL(base);
  return new Promise((resolve) => {
    const chunks = [];
    const sock = net.connect(Number(port), hostname, () => sock.write(raw));
    const done = () => { try { sock.destroy(); } catch { /* already gone */ } resolve(Buffer.concat(chunks).toString('latin1')); };
    sock.setTimeout(timeoutMs, done);
    sock.on('data', (c) => chunks.push(c));
    sock.on('end', done);
    sock.on('error', done);
  });
}
function httpRequestWithHeaders(url, { method = 'GET', headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    req.end();
  });
}

/* ============================== setup ============================== */
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-redteam2-'));
fs.writeFileSync(path.join(dir, 'cat.jpg'), await syntheticMaster(640, 420, 'CAT SECRET'));
fs.writeFileSync(path.join(dir, 'dog.jpg'), await syntheticMaster(640, 420, 'DOG SECRET'));
const catBytes = fs.readFileSync(path.join(dir, 'cat.jpg'));
fs.writeFileSync(path.join(dir, 'trunc.jpg'), catBytes.subarray(0, Math.floor(catBytes.length * 0.4)));

const handler = createArchxMiddleware({
  secret: SECRET,
  imagesDir: dir,
  maxWidthCap: 480,
  oneTimeTokens: true,
  bindTokenTo: { userAgent: true },
  allowedOrigins: ['https://example.test'],
  steganography: { perToken: true, profile: 'robust', strength: 6 },
  onStegoIssue: async () => {},
  authorize: async (req) => ({ viewerId: req.headers['x-viewer'] || 'anon', maxWidth: 240 }),
});
const { server, base } = await startServer(handler);
console.log(`Red-team v2 target: ${base} (entitlement width 240, cap 480)\n`);

async function mint(id = 'cat', w = 900, viewer = 'viewer-a', ua = 'BrowserA') {
  const res = await postToken(`${base}/archx/token/${id}?w=${w}`, browserHeaders(viewer, ua));
  return { res, body: res.status === 200 ? await res.clone().json() : null };
}
const alive = async () => (await mint('cat', 200)).res.status === 200;

/* ==================== A. HTTP parsing & ambiguity ==================== */
console.log('A. HTTP parsing & ambiguity');

await attack('http', 'duplicate X-Archx-Token headers (garbage first, valid second) never redeem and do not burn the claim', async () => {
  const { body } = await mint();
  if (!body) return { pass: false, detail: 'mint failed' };
  const dup = await httpRequestWithHeaders(base + body.cleanUrl, {
    headers: { 'x-archx-token': ['garbage.token', body.token], 'user-agent': 'BrowserA', referer: 'https://example.test/page', 'x-viewer': 'viewer-a' },
  });
  const genuine = await redeem(base, body, browserHeaders());
  return { pass: dup.status >= 400 && genuine.status === 200, detail: `dup ${dup.status}, genuine after ${genuine.status}` };
});
await attack('http', 'X-HTTP-Method-Override cannot mint (GET+override) or redeem (POST+override)', async () => {
  const getMint = await fetch(`${base}/archx/token/cat?w=200`, {
    headers: { 'x-archx-request': 'token', 'x-http-method-override': 'POST', ...browserHeaders().headers },
  });
  const { body } = await mint();
  const postRedeem = await fetch(base + body.cleanUrl, {
    method: 'POST',
    headers: { 'x-archx-token': body.token, 'x-http-method-override': 'GET', ...browserHeaders().headers },
  });
  const genuine = await redeem(base, body, browserHeaders());
  return {
    pass: getMint.status >= 400 && postRedeem.status >= 400 && genuine.status === 200,
    detail: `GET-mint ${getMint.status}, POST-redeem ${postRedeem.status}, genuine ${genuine.status}`,
  };
});
await attack('http', 'HTTP parameter pollution (?w=4000&w=100 and reverse) cannot exceed entitlement', async () => {
  for (const q of ['w=4000&w=100', 'w=100&w=4000']) {
    const res = await postToken(`${base}/archx/token/cat?${q}`, browserHeaders());
    if (res.status !== 200) continue;
    const body = await res.json();
    const r = await redeem(base, body, browserHeaders());
    if (r.status !== 200) continue;
    const { header } = decodeContainer(new Uint8Array(await r.arrayBuffer()));
    if (header.w > 240) return { pass: false, detail: `${q} delivered ${header.w}` };
  }
  return { pass: true, detail: 'both orders capped at 240' };
});
await attack('http', 'duplicate Content-Length (smuggling shape) is rejected by the parser, server stays alive', async () => {
  const raw = await rawHttp(base,
    'POST /archx/tokens HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n' +
    'Content-Length: 2\r\nContent-Length: 44\r\nx-archx-request: token\r\nConnection: close\r\n\r\n{}');
  const status = Number(raw.match(/^HTTP\/1\.1 (\d+)/)?.[1] || 0);
  return { pass: status >= 400 && (await alive()), detail: `parser status ${status || 'closed'}, alive after` };
});
await attack('http', 'absolute-form request target cannot reach the image route', async () => {
  const raw = await rawHttp(base,
    'GET http://evil.example/archx/i/cat HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n');
  const status = Number(raw.match(/^HTTP\/1\.1 (\d+)/)?.[1] || 0);
  return { pass: status >= 400, detail: `status ${status}` };
});
await attack('http', 'oversized single header value is refused (431/4xx), server stays alive', async () => {
  const r = await fetch(`${base}/archx/i/cat`, {
    headers: { 'x-viewer': 'v'.repeat(128 * 1024), ...browserHeaders().headers },
  }).catch(() => ({ status: 431 }));
  return { pass: r.status >= 400 && (await alive()), detail: `status ${r.status}` };
});

/* ==================== B. injection into the JSON/config plane ==================== */
console.log('\nB. Injection into the JSON/config plane');

await attack('inject', 'prototype pollution via batch body (__proto__/constructor keys) does not pollute Object.prototype', async () => {
  const res = await postToken(`${base}/archx/tokens`, {
    headers: { 'content-type': 'application/json', ...browserHeaders('viewer-pollute').headers },
    body: '{"items":[{"ref":"a","id":"cat","w":200}],"__proto__":{"archxPolluted":"yes"},"constructor":{"prototype":{"archxPolluted2":"yes"}}}',
  });
  await res.text().catch(() => '');
  const clean = ({}).archxPolluted === undefined && ({}).archxPolluted2 === undefined
    && Object.prototype.archxPolluted === undefined;
  return { pass: clean && res.status !== 500, detail: `status ${res.status}, prototype clean: ${clean}` };
});
await attack('inject', 'mass-assignment query params (maxWidth/ttlSec/admin) cannot widen or lengthen a token', async () => {
  const res = await postToken(`${base}/archx/token/cat?w=200&maxWidth=4000&ttlSec=999999&admin=1&authorize=true`, browserHeaders());
  if (res.status !== 200) return { pass: true, detail: `refused ${res.status}` };
  const body = await res.json();
  const claims = JSON.parse(Buffer.from(body.token.split('.')[0], 'base64url').toString('utf8'));
  const ttlMs = claims.exp - claims.iat;
  const r = await redeem(base, body, browserHeaders());
  let delivered = 0;
  if (r.status === 200) delivered = decodeContainer(new Uint8Array(await r.arrayBuffer())).header.w;
  return {
    pass: claims.w <= 240 && ttlMs <= 15 * 60_000 && delivered <= 240,
    detail: `claims.w=${claims.w}, ttl=${Math.round(ttlMs / 1000)}s, delivered=${delivered}`,
  };
});
await attack('inject', 'deeply nested JSON batch body fails controlled (no crash, no hang)', async () => {
  let nested = '"x"';
  for (let i = 0; i < 400; i++) nested = `{"a":${nested}}`;
  const t0 = Date.now();
  const res = await postToken(`${base}/archx/tokens`, {
    headers: { 'content-type': 'application/json', ...browserHeaders().headers },
    body: `{"items":${nested}}`,
  }).catch(() => ({ status: 400 }));
  return { pass: res.status >= 400 && res.status < 500 && Date.now() - t0 < 10_000 && (await alive()), detail: `status ${res.status} in ${Date.now() - t0}ms` };
});
await attack('inject', 'content-type confusion (text/plain JSON batch) grants nothing extra', async () => {
  const res = await postToken(`${base}/archx/tokens`, {
    headers: { 'content-type': 'text/plain', ...browserHeaders('viewer-ct').headers },
    body: JSON.stringify({ items: [{ ref: 'a', id: 'cat', w: 4000 }, { ref: 'b', id: 'nope', w: 4000 }] }),
  });
  if (res.status >= 400) return { pass: res.status < 500, detail: `refused ${res.status}` };
  const batch = await res.json();
  const hero = batch.tokens?.a;
  if (!hero || batch.tokens?.b) return { pass: !batch.tokens?.b, detail: 'unknown id got a token via text/plain' };
  const r = await redeem(base, hero, browserHeaders('viewer-ct'));
  const w = r.status === 200 ? decodeContainer(new Uint8Array(await r.arrayBuffer())).header.w : 0;
  return { pass: w <= 240, detail: `parsed as JSON anyway but capped at ${w}` };
});

/* ==================== C. cache / CORS / error surface ==================== */
console.log('\nC. Cache, CORS & error surface');

await attack('cache', 'CORS preflight from an evil origin is not granted', async () => {
  const r = await fetch(`${base}/archx/token/cat`, {
    method: 'OPTIONS',
    headers: { origin: 'https://evil.test', 'access-control-request-method': 'POST', 'access-control-request-headers': 'x-archx-request' },
  });
  const acao = r.headers.get('access-control-allow-origin');
  return { pass: acao !== 'https://evil.test' && acao !== '*', detail: `ACAO=${acao}` };
});
await attack('cache', 'unkeyed-header cache poisoning cannot stick (payload private/no-store; taint bytes constant)', async () => {
  const clean = await fetch(`${base}/archx/taint.png`);
  const cleanBytes = Buffer.from(await clean.arrayBuffer());
  const poisoned = await fetch(`${base}/archx/taint.png`, {
    headers: { 'x-forwarded-host': 'evil.test', 'x-original-url': '/admin', 'x-forwarded-scheme': 'http' },
  });
  const poisonedBytes = Buffer.from(await poisoned.arrayBuffer());
  const { body } = await mint('cat', 200);
  const r = await redeem(base, body, { headers: { 'x-forwarded-host': 'evil.test', ...browserHeaders().headers } });
  const cc = (r.headers.get('cache-control') || '').toLowerCase();
  const vary = (r.headers.get('vary') || '').toLowerCase();
  return {
    pass: cleanBytes.equals(poisonedBytes) && cc.includes('no-store') && cc.includes('private') && vary.includes('x-archx-token'),
    detail: `taint identical=${cleanBytes.equals(poisonedBytes)}, cc="${cc.slice(0, 40)}…"`,
  };
});
await attack('cache', 'error responses disclose no stack traces, paths, or secrets', async () => {
  const probes = [
    fetch(`${base}/archx/i/..%2f..%2fetc%2fpasswd`, browserHeaders()),
    fetch(`${base}/archx/token/%00cat`, browserHeaders()),
    postToken(`${base}/archx/tokens`, { headers: { 'content-type': 'application/json' }, body: '{not json' }),
    fetch(`${base}/definitely/not/a/route`, browserHeaders()),
  ];
  const bodies = await Promise.all(probes.map(async (p) => { const r = await p; return r.text().catch(() => ''); }));
  const leak = bodies.find((b) => /\/home\/|node_modules|\.mjs:\d+|\.js:\d+|red-team-v2-secret|at\s+\w+\s*\(/i.test(b));
  return { pass: !leak, detail: leak ? `leak: ${leak.slice(0, 120)}` : `${bodies.length} error bodies clean` };
});
await attack('cache', 'TRACE and OPTIONS on the image route are refused (405)', async () => {
  const trace = await fetch(`${base}/archx/i/cat`, { method: 'TRACE', ...browserHeaders() }).catch(() => ({ status: 405 }));
  const opt = await fetch(`${base}/archx/i/cat`, { method: 'OPTIONS', ...browserHeaders() });
  return { pass: trace.status === 405 && opt.status === 405, detail: `TRACE ${trace.status}, OPTIONS ${opt.status}` };
});

/* ==================== D. attribution abuse (stego) ==================== */
console.log('\nD. Attribution abuse');

const hostRaw = await sharp(await syntheticMaster(900, 491, 'HOST')).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
const H = { buf: new Uint8Array(hostRaw.data), w: hostRaw.info.width, h: hostRaw.info.height };
const markedA = embedStegoFingerprint(H.buf, H.w, H.h, 'BUYER-A', { key: STEGO_KEY, profile: 'robust', strength: 6 });
const markedB = embedStegoFingerprint(H.buf, H.w, H.h, 'BUYER-B', { key: STEGO_KEY, profile: 'robust', strength: 6 });
const fpA = stegoFingerprint('BUYER-A');
async function xform(buf, w, h, pipe) {
  const png = await sharp(Buffer.from(buf), { raw: { width: w, height: h, channels: 4 } }).png().toBuffer();
  const out = await pipe(sharp(png)).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  return { buf: new Uint8Array(out.data), w: out.info.width, h: out.info.height };
}

await attack('stego', 'wrong-key lottery: 12 wrong keys produce zero attributions', async () => {
  let hits = 0;
  for (let i = 0; i < 12; i++) {
    const hit = detectStegoFingerprint(markedA, H.w, H.h, {
      key: `lottery-key-${i}`, profile: 'robust', searchGeometry: false, maxTimeMs: 4000,
    });
    if (hit.found) hits++;
  }
  return { pass: hits === 0, detail: `${hits}/12 wrong keys attributed` };
});
await attack('stego', 'unmarked noise suspects produce zero attributions (false-positive screen)', async () => {
  let hits = 0;
  for (let s = 0; s < 3; s++) {
    const noise = new Uint8Array(H.buf.length);
    let x = 0x1234567 + s * 7919;
    for (let i = 0; i < noise.length; i++) { x = (x * 1103515245 + 12345) & 0x7fffffff; noise[i] = (x >>> 8) & 0xff; }
    for (let i = 3; i < noise.length; i += 4) noise[i] = 255;
    const hit = detectStegoFingerprint(noise, H.w, H.h, {
      key: STEGO_KEY, profile: 'robust', searchGeometry: false, maxTimeMs: 6000,
    });
    if (hit.found) hits++;
  }
  return { pass: hits === 0, detail: `${hits}/3 noise suspects attributed` };
});
await attack('stego', 'screenshot chain (0.8x + blur + JPEG50 + brightness) never misattributes', async () => {
  const shot = await xform(markedA, H.w, H.h, (p) => p
    .resize(Math.round(H.w * 0.8)).blur(0.6).modulate({ brightness: 1.12 }).jpeg({ quality: 50 }));
  const hit = detectStegoFingerprint(shot.buf, shot.w, shot.h, {
    key: STEGO_KEY, profile: 'robust', searchGeometry: true, searchOffsets: true, maxTimeMs: 20_000,
  });
  const wrong = detectStegoFingerprint(shot.buf, shot.w, shot.h, {
    key: 'not-the-key', profile: 'robust', searchGeometry: false, maxTimeMs: 6000,
  });
  return {
    pass: (!hit.found || hit.fingerprint === fpA) && !wrong.found,
    detail: hit.found ? 'still BUYER-A after screenshot chain' : 'mark destroyed by chain (documented limit), never wrong buyer',
  };
});
await attack('stego', 'two-buyer averaging collusion never attributes an innocent third party', async () => {
  const avg = new Uint8Array(H.buf.length);
  for (let i = 0; i < avg.length; i++) avg[i] = (markedA[i] + markedB[i]) >> 1;
  const hit = detectStegoFingerprint(avg, H.w, H.h, {
    key: STEGO_KEY, profile: 'robust', searchGeometry: false, maxTimeMs: 10_000,
  });
  const allowed = new Set([fpA, stegoFingerprint('BUYER-B')]);
  return {
    pass: !hit.found || allowed.has(hit.fingerprint),
    detail: hit.found ? 'average attributed to one actual participant' : 'average undecodable as a single buyer (assay territory, documented)',
  };
});

/* ==================== E. resource bounds ==================== */
console.log('\nE. Resource bounds');

await attack('dos', 'truncated JPEG master fails controlled at delivery; server stays alive', async () => {
  const m = await mint('trunc', 200);
  let status = m.res.status;
  if (m.res.status === 200) {
    const r = await redeem(base, m.body, browserHeaders());
    status = r.status;
    await r.text().catch(() => '');
  }
  return { pass: status !== 200 && (await alive()), detail: `truncated-master flow ended ${status}, alive after` };
});
await attack('dos', 'batch item with a 100KB id fails controlled (no 500, no hang)', async () => {
  const res = await postToken(`${base}/archx/tokens`, {
    headers: { 'content-type': 'application/json', ...browserHeaders().headers },
    body: JSON.stringify({ items: [{ ref: 'a', id: 'x'.repeat(100 * 1024), w: 200 }] }),
  }).catch(() => ({ status: 413 }));
  return { pass: res.status >= 400 && res.status < 500 && (await alive()), detail: `status ${res.status}` };
});
await attack('dos', '30-way parallel mint stampede stays bounded and the server remains responsive', async () => {
  const t0 = Date.now();
  const statuses = await Promise.all(Array.from({ length: 30 }, (_, i) =>
    postToken(`${base}/archx/token/cat?w=200`, browserHeaders(`stampede-${i}`))
      .then(async (r) => { await r.text().catch(() => ''); return r.status; })
      .catch(() => 0)));
  const bounded = statuses.every((s) => s === 200 || s === 429 || s === 503);
  return {
    pass: bounded && Date.now() - t0 < 30_000 && (await alive()),
    detail: `${statuses.filter((s) => s === 200).length}/30 ok in ${Date.now() - t0}ms`,
  };
});

/* ============================== summary ============================== */
server.close();
handler.close?.();
const held = results.filter((r) => r.pass === true).length;
const failed = results.filter((r) => r.pass === false).length;
const info = results.filter((r) => r.pass === null).length;
console.log(`\nRed-team v2 summary: ${held}/${held + failed} defenses held, ${failed} failed, ${info} informational.`);
const jsonIdx = process.argv.indexOf('--json');
if (jsonIdx > 0 && process.argv[jsonIdx + 1]) fs.writeFileSync(process.argv[jsonIdx + 1], JSON.stringify(results, null, 2));
process.exit(failures ? 1 : 0);
