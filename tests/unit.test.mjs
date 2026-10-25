import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import sharp from 'sharp';
import {
  buildScramblePlan, scramblePixels, paddedSize,
  encodeContainer, decodeContainer, isArchxContainer,
  encryptPayload, decryptPayload, generateKeyBase64,
  applyForensicBlocks, forensicScore, forensicBlockSigns,
  embedStegoFingerprint, detectStegoFingerprint, stegoFingerprint,
} from '../src/scramble.js';
// (decryptPayload used by the AES .archx test below)
import { scrambleImage, unscrambleImage } from '../server/scramble-image.js';
import {
  createArchxMiddleware, signToken, verifyToken, deriveStegoKey,
  auditArchxServerConfig, validateTokenClaims, validateImageId,
  SlidingWindowLimiter, BoundedTtlSet, AsyncSemaphore,
} from '../server/middleware.js';

/* ---------- scramble plan ---------- */

test('scramble plan is deterministic per key and differs across keys', () => {
  const a = buildScramblePlan(8, 'correct horse battery staple');
  const b = buildScramblePlan(8, 'correct horse battery staple');
  const c = buildScramblePlan(8, 'a different key');
  assert.deepEqual(a.order, b.order);
  assert.deepEqual(a.flips, b.flips);
  assert.notDeepEqual(a.order, c.order);
  // inverse consistency
  a.order.forEach((orig, scrambledPos) => assert.equal(a.inverse[orig], scrambledPos));
  // it is a real permutation of 0..63
  assert.deepEqual([...a.order].sort((x, y) => x - y), Array.from({ length: 64 }, (_, i) => i));
});

test('pixel scramble round-trips exactly (random RGBA buffer)', () => {
  const w = 64, h = 48;
  const raw = new Uint8Array(w * h * 4);
  for (let i = 0; i < raw.length; i++) raw[i] = (i * 2654435761) % 256;
  const plan = buildScramblePlan(8, 'roundtrip-key');
  const scrambled = scramblePixels(raw, w, h, plan, 'scramble');
  const restored = scramblePixels(scrambled, w, h, plan, 'unscramble');
  assert.deepEqual(restored, raw);
  // and the scrambled version is actually different in most bytes
  let same = 0;
  for (let i = 0; i < raw.length; i++) if (raw[i] === scrambled[i]) same++;
  assert.ok(same / raw.length < 0.08, `scrambled too similar: ${same}/${raw.length} bytes identical`);
});

test('forensic block mark: seeded signs are embedded and recoverable by correlation', () => {
  const w = 256, h = 192;
  const reference = new Uint8Array(w * h * 4);
  for (let i = 0; i < reference.length; i += 4) {
    reference[i] = 110; reference[i + 1] = 120; reference[i + 2] = 130; reference[i + 3] = 255;
  }
  const marked = applyForensicBlocks(new Uint8Array(reference), w, h, 'viewer-session-42', { blockSize: 32, delta: 3 });
  assert.notDeepEqual(marked, reference);
  const hit = forensicScore(marked, reference, w, h, 'viewer-session-42', { blockSize: 32 });
  const miss = forensicScore(marked, reference, w, h, 'someone-else', { blockSize: 32 });
  assert.ok(hit.score > 0.9, `expected strong correlation, got ${hit.score}`);
  assert.ok(Math.abs(miss.score) < 0.55, `wrong seed should not correlate, got ${miss.score}`);
  assert.equal(forensicBlockSigns('x', 8).length, 8);
});

test('StegoMark: blind fingerprint decodes without a reference and survives re-encode/resize', async () => {
  const master = await syntheticMaster(640, 420);
  const { data, info } = await sharp(master).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const raw = new Uint8Array(data);
  const marked = embedStegoFingerprint(raw, info.width, info.height, 'ORDER-1042', { key: 'owner-key' });

  const direct = detectStegoFingerprint(marked, info.width, info.height, { key: 'owner-key' });
  assert.equal(direct.found, true, JSON.stringify(direct));
  assert.equal(direct.fingerprint, stegoFingerprint('ORDER-1042'));

  // A realistic stolen-copy path: downscale + lossy JPEG re-encode.
  const copied = await sharp(Buffer.from(marked), {
    raw: { width: info.width, height: info.height, channels: 4 },
  }).resize({ width: 448 }).jpeg({ quality: 85 }).toBuffer();
  const copiedRaw = await sharp(copied).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const afterCopy = detectStegoFingerprint(
    new Uint8Array(copiedRaw.data), copiedRaw.info.width, copiedRaw.info.height,
    { key: 'owner-key', searchOffsets: true },
  );
  assert.equal(afterCopy.found, true, JSON.stringify(afterCopy));
  assert.equal(afterCopy.fingerprint, direct.fingerprint);

  // Negative controls must not produce a confident ownership claim.
  assert.equal(detectStegoFingerprint(raw, info.width, info.height, { key: 'owner-key' }).found, false);
  assert.equal(detectStegoFingerprint(marked, info.width, info.height, { key: 'wrong-key' }).found, false);
});

test('paddedSize rounds up to grid multiples', () => {
  assert.deepEqual(paddedSize(100, 50, 8), { tw: 13, th: 7, pw: 104, ph: 56 });
  assert.deepEqual(paddedSize(64, 64, 8), { tw: 8, th: 8, pw: 64, ph: 64 });
});

/* ---------- container + crypto ---------- */

test('.archx container encode/decode round-trips', () => {
  const header = { v: 1, w: 10, h: 10, pw: 16, ph: 16, grid: 8, mime: 'image/webp', scrambled: true, encrypted: false };
  const payload = new Uint8Array([1, 2, 3, 250, 0, 99]);
  const bytes = encodeContainer(header, payload);
  assert.ok(isArchxContainer(bytes));
  const back = decodeContainer(bytes);
  assert.deepEqual(back.header, header);
  assert.deepEqual([...back.payload], [...payload]);
  assert.throws(() => decodeContainer(new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11])));
});

test('AES-GCM payload encrypt/decrypt round-trips and tamper fails', async () => {
  const key = generateKeyBase64();
  const plain = new TextEncoder().encode('pretend these are image bytes '.repeat(50));
  const { cipher, iv } = await encryptPayload(plain, key);
  assert.notDeepEqual(cipher.subarray(0, 16), plain.subarray(0, 16));
  const back = await decryptPayload(cipher, key, iv);
  assert.deepEqual(back, plain);
  const tampered = new Uint8Array(cipher); tampered[0] ^= 0xff;
  await assert.rejects(decryptPayload(tampered, key, iv));
  await assert.rejects(decryptPayload(cipher, generateKeyBase64(), iv));
});

/* ---------- image scrambling via sharp ---------- */

async function syntheticMaster(w = 320, h = 240) {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}">
    <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#ff5533"/><stop offset="1" stop-color="#2244ff"/></linearGradient></defs>
    <rect width="${w}" height="${h}" fill="url(#g)"/>
    <circle cx="90" cy="80" r="45" fill="#00e08a"/><circle cx="230" cy="160" r="55" fill="#ffe14d"/>
    <text x="24" y="${h - 24}" font-family="sans-serif" font-size="40" font-weight="bold" fill="white">SECRET 42</text>
  </svg>`;
  return sharp(Buffer.from(svg)).png().toBuffer();
}

function postToken(url, { headers = {}, ...init } = {}) {
  return fetch(url, {
    method: 'POST',
    headers: { 'x-archx-request': 'token', ...headers },
    ...init,
  });
}

async function meanAbsDiff(bufA, bufB, w, h) {
  const rawA = await sharp(bufA).resize(w, h).removeAlpha().raw().toBuffer();
  const rawB = await sharp(bufB).resize(w, h).removeAlpha().raw().toBuffer();
  let sum = 0;
  for (let i = 0; i < rawA.length; i++) sum += Math.abs(rawA[i] - rawB[i]);
  return sum / rawA.length;
}

test('scrambleImage: payload looks scrambled, unscrambles back to (near) original', async () => {
  const master = await syntheticMaster();
  const { bytes, header } = await scrambleImage(master, { key: 'unit-key', grid: 8, format: 'png', maxWidth: 320 });
  assert.ok(isArchxContainer(bytes));
  assert.equal(header.w, 320); assert.equal(header.h, 240);
  assert.equal(header.scrambled, true);
  const { payload } = decodeContainer(bytes);
  const diffScrambled = await meanAbsDiff(master, Buffer.from(payload), 160, 120);
  const restored = await unscrambleImage(Buffer.from(payload), { grid: 8, key: 'unit-key', w: header.w, h: header.h });
  const diffRestored = await meanAbsDiff(master, restored, 160, 120);
  assert.ok(diffScrambled > 28, `scrambled payload too recognisable (MAD=${diffScrambled.toFixed(1)})`);
  assert.ok(diffRestored < 6, `unscrambled image diverged (MAD=${diffRestored.toFixed(1)})`);
  // wrong key stays scrambled
  const wrong = await unscrambleImage(Buffer.from(payload), { grid: 8, key: 'WRONG-key', w: header.w, h: header.h });
  assert.ok((await meanAbsDiff(master, wrong, 160, 120)) > 28);
});

test('encrypted .archx: payload is ciphertext, decrypt+unscramble restores the image', async () => {
  const master = await syntheticMaster();
  const aesKey = generateKeyBase64();
  const { bytes, header } = await scrambleImage(master, { key: 'enc-key', grid: 8, format: 'png', maxWidth: 320, aesKey });
  const { payload } = decodeContainer(bytes);
  assert.equal(header.encrypted, true);
  // ciphertext must not be a decodable image
  await assert.rejects(sharp(Buffer.from(payload)).metadata());
  // correct key restores a scrambled image, which un-scrambles to the original
  const plain = await decryptPayload(payload, aesKey, header.iv);
  const restored = await unscrambleImage(Buffer.from(plain), { grid: 8, key: 'enc-key', w: header.w, h: header.h });
  assert.ok((await meanAbsDiff(master, restored, 160, 120)) < 6);
  // wrong AES key fails closed
  await assert.rejects(decryptPayload(payload, generateKeyBase64(), header.iv));
});

test('delivery quality: default WebP is visibly cleaner than q82; lossless is pixel-exact', async () => {
  // Fine lines/text are where low-quality scrambled WebP turns into slurry.
  const details = Array.from({ length: 28 }, (_, i) =>
    `<line x1="${8 + i * 11}" y1="8" x2="${28 + i * 11}" y2="150" stroke="${i % 2 ? '#ffffff' : '#00e0ff'}" stroke-width="1"/>`).join('');
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="320" height="240">
    <rect width="320" height="240" fill="#182238"/>${details}
    <text x="18" y="202" font-family="sans-serif" font-size="25" font-weight="700" fill="#ffe14d">DETAILS 0123456789</text>
    <text x="18" y="228" font-family="sans-serif" font-size="13" fill="white">small sharp text should survive delivery</text>
  </svg>`;
  const master = await sharp(Buffer.from(svg)).png().toBuffer();
  const reference = await sharp(master).removeAlpha().raw().toBuffer();
  const restoreRaw = async (result) => {
    const { payload, header } = decodeContainer(result.bytes);
    const restored = await unscrambleImage(Buffer.from(payload), {
      grid: header.grid, key: 'quality-key', w: header.w, h: header.h,
    });
    return sharp(restored).removeAlpha().raw().toBuffer();
  };
  const mad = (raw) => {
    let sum = 0;
    for (let i = 0; i < reference.length; i++) sum += Math.abs(reference[i] - raw[i]);
    return sum / reference.length;
  };

  const oldDefault = await scrambleImage(master, { key: 'quality-key', grid: 8, maxWidth: 320, quality: 82 });
  const newDefault = await scrambleImage(master, { key: 'quality-key', grid: 8, maxWidth: 320 });
  const lossless = await scrambleImage(master, { key: 'quality-key', grid: 8, maxWidth: 320, lossless: true });

  const oldMad = mad(await restoreRaw(oldDefault));
  const newMad = mad(await restoreRaw(newDefault));
  const losslessMad = mad(await restoreRaw(lossless));
  assert.ok(newMad < oldMad * 0.85, `default quality should retain more detail (q82 MAD=${oldMad.toFixed(2)}, default MAD=${newMad.toFixed(2)})`);
  assert.equal(losslessMad, 0, 'lossless delivery must reproduce the delivered-size pixels exactly');
});

test('server-baked watermark survives into the un-scrambled reconstruction', async () => {
  const dark = await sharp({ create: { width: 320, height: 240, channels: 3, background: { r: 8, g: 10, b: 18 } } }).png().toBuffer();
  const plain = await scrambleImage(dark, { key: 'wm-key', grid: 8, format: 'png', maxWidth: 320 });
  const forensicOnly = await scrambleImage(dark, { key: 'wm-key', grid: 8, format: 'png', maxWidth: 320, forensicSeed: 'sess-1', forensic: { blockSize: 32, delta: 4 } });
  const marked = await scrambleImage(dark, { key: 'wm-key', grid: 8, format: 'png', maxWidth: 320, watermark: 'SECRET VIEWER 42', forensicSeed: 'sess-1', forensic: { blockSize: 32, delta: 4 } });
  assert.equal(marked.header.wm, 1);
  assert.equal(marked.header.fx, 1);
  const restore = async (bytes) => {
    const { payload, header } = decodeContainer(bytes);
    return unscrambleImage(Buffer.from(payload), { grid: 8, key: 'wm-key', w: header.w, h: header.h });
  };
  const plainImg = await restore(plain.bytes);
  const markedImg = await restore(marked.bytes);
  const diff = await meanAbsDiff(plainImg, markedImg, 320, 240);
  assert.ok(diff > 2.5, `reconstructed stolen copy should visibly carry the watermark (MAD=${diff.toFixed(2)})`);
  // And the marked reconstruction is full of bright watermark pixels on a dark field.
  const raw = await sharp(markedImg).removeAlpha().raw().toBuffer();
  let bright = 0;
  for (let i = 0; i < raw.length; i += 3) if ((raw[i] + raw[i + 1] + raw[i + 2]) / 3 > 60) bright++;
  assert.ok(bright > 250, `expected watermark text pixels, got ${bright}`);

  // The pre-scramble block mark must actually be present after a stolen
  // payload is perfectly un-shuffled — not merely advertised by a header flag.
  const forensicImg = await restore(forensicOnly.bytes);
  const [controlRaw, forensicRaw] = await Promise.all([
    sharp(plainImg).ensureAlpha().raw().toBuffer(),
    sharp(forensicImg).ensureAlpha().raw().toBuffer(),
  ]);
  const score = forensicScore(
    new Uint8Array(forensicRaw),
    new Uint8Array(controlRaw),
    320,
    240,
    'sess-1',
    { blockSize: 32 },
  );
  assert.ok(score.score > 0.7, `server forensic mark should survive reconstruction (score=${score.score.toFixed(2)})`);
});

test('scrambleImage bakes StegoMark before scrambling; reconstructed copies remain attributable', async () => {
  const master = await syntheticMaster(640, 420);
  const result = await scrambleImage(master, {
    key: 'stego-scramble-key', grid: 8, maxWidth: 640, lossless: true,
    stegoPayload: 'BUYER-77', stegoKey: 'stego-secret',
  });
  assert.equal(result.header.sg, 1);
  assert.equal(result.stegoFingerprint, stegoFingerprint('BUYER-77'));
  const { payload, header } = decodeContainer(result.bytes);
  const restored = await unscrambleImage(Buffer.from(payload), {
    grid: header.grid, key: 'stego-scramble-key', w: header.w, h: header.h,
  });
  const { data, info } = await sharp(restored).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const found = detectStegoFingerprint(new Uint8Array(data), info.width, info.height, { key: 'stego-secret' });
  assert.equal(found.found, true, JSON.stringify(found));
  assert.equal(found.fingerprint, result.stegoFingerprint);
});

test('scrambleImage down-scales masters and strips them out of the payload', async () => {
  const master = await syntheticMaster(1600, 1200);
  const { header } = await scrambleImage(master, { key: 'k', maxWidth: 500 });
  assert.equal(header.w, 500);
  assert.equal(header.h, 375);
});

/* ---------- signed tokens + HTTP middleware ---------- */

test('token verify accepts valid, rejects tampered/expired', () => {
  const secret = 'token-secret';
  const ok = signToken({ id: 'a', w: 800, exp: Date.now() + 60000, n: 'x' }, secret);
  assert.equal(verifyToken(ok, secret)?.id, 'a');
  assert.equal(verifyToken(ok.replace(/[^.]+$/, 'AAAA'), secret), null);
  assert.equal(verifyToken(signToken({ id: 'a', exp: Date.now() - 1000 }, secret), secret), null);
  assert.equal(verifyToken(ok, 'other-secret'), null);
  assert.equal(verifyToken('garbage', secret), null);
});

test('HTTP middleware: token flow serves scrambled container, blocks everything else', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-test-'));
  fs.writeFileSync(path.join(dir, 'cat.jpg'), await syntheticMaster());
  const handler = createArchxMiddleware({ secret: 'http-secret-for-unit-tests-32chars-minimum', imagesDir: dir, ttlSec: 60, allowAnonymous: true });
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;

  // unknown id -> 404 (no existence leaks)
  assert.equal((await postToken(base + '/archx/token/nope')).status, 404);
  // path traversal style id -> 404
  assert.equal((await postToken(base + '/archx/token/..%2Fsecret')).status, 404);
  // image route without token -> 403
  assert.equal((await fetch(base + '/archx/i/cat')).status, 403);

  const tokenRes = await postToken(base + '/archx/token/cat?w=300');
  assert.equal(tokenRes.status, 200);
  const token = await tokenRes.json();
  assert.ok(token.url.startsWith('/archx/i/cat?t='));
  assert.ok(token.key, 'token response carries the un-scramble key for the legitimate client');

  const imgRes = await fetch(base + token.url);
  assert.equal(imgRes.status, 200);
  assert.equal(imgRes.headers.get('content-type'), 'application/octet-stream');
  assert.match(imgRes.headers.get('cache-control') || '', /no-store/);
  const bytes = new Uint8Array(await imgRes.arrayBuffer());
  assert.ok(isArchxContainer(bytes), 'payload is an .archx container, not an image file');
  const { header, payload } = decodeContainer(bytes);
  assert.equal(header.scrambled, true);
  assert.equal(header.w, 300, 'server down-scaled to the requested width');
  // payload pixels are scrambled vs the master
  const master = fs.readFileSync(path.join(dir, 'cat.jpg'));
  // syntheticMaster was PNG bytes saved as .jpg — sharp sniffs content, fine.
  assert.ok((await meanAbsDiff(master, Buffer.from(payload), 150, 112)) > 25);
  // ...but unscramble with the token key restores it
  const restored = await unscrambleImage(Buffer.from(payload), { grid: header.grid, key: token.key, w: header.w, h: header.h });
  assert.ok((await meanAbsDiff(master, restored, 150, 112)) < 22, 'high-quality WebP tolerance');

  // Cover-aware sizing: a 320x240 source in a 120x120 box needs a 160px-wide
  // derivative (120 * 4/3), not a 120px one that would be cropped+upscaled.
  const coverToken = await (await postToken(base + '/archx/token/cat?bw=120&bh=120&fit=cover')).json();
  const coverBytes = new Uint8Array(await (await fetch(base + coverToken.url)).arrayBuffer());
  assert.equal(decodeContainer(coverBytes).header.w, 160);

  // tampered token -> 403
  const tampered = token.url.replace(/t=([^.]+)\./, (_, b) => 't=' + b.slice(0, -2) + 'XX.');
  assert.equal((await fetch(base + tampered)).status, 403);
  // expired token -> 403 (sign one in the past with the same secret)
  const expired = signToken({ id: 'cat', w: 300, exp: Date.now() - 5000, n: 'n' }, 'http-secret-for-unit-tests-32chars-minimum');
  assert.equal((await fetch(`${base}/archx/i/cat?t=${expired}`)).status, 403);
  // token minted for a different id -> 403
  const other = signToken({ id: 'dog', w: 300, exp: Date.now() + 60000, n: 'n' }, 'http-secret-for-unit-tests-32chars-minimum');
  assert.equal((await fetch(`${base}/archx/i/cat?t=${other}`)).status, 403);
});

test('hardened middleware: one-time + UA-bound tokens, entitlement width cap, origin allowlist, server watermark/forensic', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-hard-'));
  fs.writeFileSync(path.join(dir, 'cat.jpg'), await syntheticMaster());
  const handler = createArchxMiddleware({
    secret: 'hardened-secret-for-unit-tests-32chars',
    imagesDir: dir,
    oneTimeTokens: true,
    bindTokenTo: { userAgent: true },
    allowedOrigins: ['https://example.test'],
    serverWatermark: ({ viewerId }) => `VIEWER ${viewerId}`,
    forensic: true,
    forensicPerToken: true,
    authorize: async () => ({ viewerId: 'user-42', maxWidth: 180 }),
  });
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;
  const asBrowser = (ua, withOrigin = true) => ({
    headers: { 'user-agent': ua, ...(withOrigin ? { referer: 'https://example.test/page' } : {}) },
  });

  // No allowed origin/referer -> 403 even for the token endpoint
  assert.equal((await postToken(base + '/archx/token/cat?w=900', asBrowser('BrowserA', false))).status, 403);

  const tokenRes = await postToken(base + '/archx/token/cat?w=900', asBrowser('BrowserA'));
  assert.equal(tokenRes.status, 200);
  const token = await tokenRes.json();

  // Wrong User-Agent cannot spend the token…
  assert.equal((await fetch(base + token.url, asBrowser('BrowserB'))).status, 403);
  // …the right browser can, exactly once.
  const ok = await fetch(base + token.url, asBrowser('BrowserA'));
  assert.equal(ok.status, 200);
  const bytes = new Uint8Array(await ok.arrayBuffer());
  const { header } = decodeContainer(bytes);
  assert.equal(header.w, 180, 'entitlement maxWidth overrides the client-requested 900px');
  assert.equal(header.wm, 1, 'server watermark baked pre-scramble');
  assert.equal(header.fx, 1, 'forensic mark baked pre-scramble');
  // Replay of the same (still unexpired) URL -> 403: one-time use.
  assert.equal((await fetch(base + token.url, asBrowser('BrowserA'))).status, 403);
});

test('middleware direct controls: entitlement quality/format wins and StegoMark issuance is registered', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-stego-http-'));
  fs.writeFileSync(path.join(dir, 'cat.jpg'), await syntheticMaster(640, 420));
  const issued = [];
  const handler = createArchxMiddleware({
    secret: 'stego-http-secret-for-unit-tests-32chars',
    imagesDir: dir,
    steganography: { perToken: true, strength: 6 },
    onStegoIssue: async (record) => { issued.push(record); },
    // The backend grants this buyer lossless PNG pixels; the browser asking
    // for q=10 must not downgrade (or upgrade beyond) that entitlement.
    authorize: async () => ({ viewerId: 'buyer-7', quality: 'lossless', format: 'png' }),
  });
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;

  const token = await (await postToken(base + '/archx/token/cat?w=640&q=10')).json();
  assert.equal(issued.length, 1);
  assert.equal(issued[0].viewerId, 'buyer-7');
  assert.match(issued[0].fingerprint, /^[0-9a-f]{12}$/);

  const bytes = new Uint8Array(await (await fetch(base + token.url)).arrayBuffer());
  const { header, payload } = decodeContainer(bytes);
  assert.equal(header.sg, 1);
  assert.equal(header.mime, 'image/png');

  const restored = await unscrambleImage(Buffer.from(payload), {
    grid: header.grid, key: token.key, w: header.w, h: header.h,
  });
  const { data, info } = await sharp(restored).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const found = detectStegoFingerprint(new Uint8Array(data), info.width, info.height, {
    key: deriveStegoKey('cat', 'stego-http-secret-for-unit-tests-32chars'),
  });
  assert.equal(found.found, true, JSON.stringify(found));
  assert.equal(found.fingerprint, issued[0].fingerprint);
});

/* ---------- v1.4 production-hardening regressions ---------- */

const TEST_SECRET = 'unit-test-secret-with-more-than-32-bytes';

async function startArchxFixture(t, options, images = { cat: [320, 240] }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-v14-'));
  for (const [id, [w, h]] of Object.entries(images)) {
    fs.writeFileSync(path.join(dir, `${id}.jpg`), await syntheticMaster(w, h));
  }
  const handler = createArchxMiddleware({
    secret: TEST_SECRET,
    imagesDir: dir,
    ...options,
  });
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    handler.close();
    await new Promise((resolve) => server.close(resolve));
  });
  return { dir, handler, base: `http://127.0.0.1:${server.address().port}` };
}

test('strict server configuration fails closed and rejects unsafe deployments', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-config-'));
  fs.writeFileSync(path.join(dir, 'cat.jpg'), await syntheticMaster());

  const weak = auditArchxServerConfig({
    secret: 'short', imagesDir: dir, allowAnonymous: true,
  });
  assert.equal(weak.ok, false);
  assert.ok(weak.issues.some((issue) => /secret/i.test(issue)));
  assert.equal(JSON.stringify(weak).includes(TEST_SECRET), false, 'config audit never returns secret material');

  assert.throws(
    () => createArchxMiddleware({ secret: TEST_SECRET, imagesDir: dir }),
    /authorize.*required/i,
    'missing authorize() must never silently mean public access',
  );
  assert.throws(
    () => createArchxMiddleware({
      secret: TEST_SECRET, imagesDir: dir, allowAnonymous: true,
      allowedOrigins: ['*'],
    }),
    /allowedOrigins/i,
  );
  assert.throws(
    () => createArchxMiddleware({
      secret: TEST_SECRET, imagesDir: dir, allowAnonymous: true,
      processing: { maxInputPixels: 12 },
    }),
    /maxInputPixels/i,
  );
  assert.throws(
    () => createArchxMiddleware({
      secret: TEST_SECRET, imagesDir: dir, publicDir: dir, allowAnonymous: true,
    }),
    /public directory/i,
    'masters must not overlap a declared public root',
  );

  // A symlink inside a masters directory that points outside it is not indexed.
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-outside-'));
  const outsideFile = path.join(outside, 'outside.jpg');
  fs.writeFileSync(outsideFile, await syntheticMaster());
  const symlinkDir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-links-'));
  fs.symlinkSync(outsideFile, path.join(symlinkDir, 'escape.jpg'));
  assert.throws(
    () => createArchxMiddleware({ secret: TEST_SECRET, imagesDir: symlinkDir, allowAnonymous: true }),
    /no supported master images/i,
  );

  assert.equal(validateImageId('cat-01_final'), true);
  for (const bad of ['', '.', '..', '../cat', 'cat/dog', 'cat\\dog', 'cat.jpg', '-cat', 'a'.repeat(129), null, 42]) {
    assert.equal(validateImageId(bad), false, `rejected id: ${String(bad)}`);
  }
});

test('v2 token claims validate every security-relevant field', () => {
  const now = 1_800_000_000_000;
  const valid = {
    v: 2, aud: 'archx:image', scope: 'image:view', id: 'cat',
    w: 800, iat: now, exp: now + 60_000, n: 'nonce-1234567890', q: 95, fmt: 'webp',
  };
  const opts = { id: 'cat', maxWidthCap: 1920, maxTtlMs: 120_000, now: now + 1_000 };
  assert.equal(validateTokenClaims(valid, opts), true);
  for (const mutation of [
    { v: 1 }, { aud: 'other' }, { scope: 'image:download' }, { id: '../cat' },
    { id: 'dog' }, { w: 63 }, { w: 1921.5 }, { w: 1921 },
    { iat: now + 10 * 60_000 }, { exp: now + 20 * 60_000 },
    { n: 'short' }, { n: '../../nonce' }, { q: 101 }, { fmt: 'gif' },
  ]) {
    assert.equal(validateTokenClaims({ ...valid, ...mutation }, opts), false, JSON.stringify(mutation));
  }
});

test('bounded security stores expire/evict and processing semaphore fails predictably', async () => {
  const limiter = new SlidingWindowLimiter({ windowMs: 100, maxClients: 2, cleanupIntervalMs: 0 });
  assert.equal(limiter.hit('a', 1, 1000).limited, false);
  assert.equal(limiter.hit('a', 1, 1001).limited, true);
  limiter.hit('b', 1, 1002);
  limiter.hit('c', 1, 1003);
  assert.ok(limiter.size <= 2, 'client map is hard-bounded');
  limiter.cleanup(1200);
  assert.equal(limiter.size, 0, 'stale clients are forgotten');
  limiter.close();

  const nonces = new BoundedTtlSet({ maxEntries: 1, cleanupIntervalMs: 0 });
  assert.equal(nonces.claim('one', 2000, 1000), true);
  assert.equal(nonces.claim('one', 2000, 1000), false, 'synchronous duplicate claim loses');
  assert.equal(nonces.claim('two', 2000, 1000), false, 'saturated nonce store fails closed');
  assert.equal(nonces.claim('expired', 999, 1000), false);
  nonces.cleanup(2001);
  assert.equal(nonces.claim('two', 3000, 2001), true);
  nonces.close();

  const semaphore = new AsyncSemaphore({ maxConcurrent: 1, maxQueue: 0, queueTimeoutMs: 0 });
  let release;
  const first = semaphore.run(() => new Promise((resolve) => { release = resolve; }));
  await assert.rejects(
    semaphore.run(async () => 'never'),
    (err) => err.code === 'ARCHX_PROCESSING_BUSY',
  );
  release('done');
  assert.equal(await first, 'done');
});

test('hardened HTTP edge cases: malformed requests, race-safe replay, redemption reauthorization', async (t) => {
  let allowed = true;
  let viewerId = 'alice';
  let entitlementWidth = 220;
  const events = [];
  const { base, handler } = await startArchxFixture(t, {
    bindTokenTo: { session: true },
    onSecurityEvent: (event) => events.push(event),
    authorize: async () => (allowed
      ? { viewerId, maxWidth: entitlementWidth, permissions: ['image:view'] }
      : false),
  });

  assert.equal(handler.configAudit.ok, true);
  assert.equal(handler.stats().images, 1);

  const getToken = await fetch(base + '/archx/token/cat?w=200');
  assert.equal(getToken.status, 405, 'POST-only token minting is the secure default');
  assert.equal(getToken.headers.get('allow'), 'POST');
  assert.match(getToken.headers.get('cache-control') || '', /no-store/);
  assert.equal(getToken.headers.get('x-content-type-options'), 'nosniff');

  assert.equal((await postToken(base + '/archx/token/%E0%A4%A')).status, 400);
  assert.equal((await postToken(base + '/archx/token/..%2Fsecret')).status, 404);
  assert.equal((await postToken(base + '/archx/token/%252e%252e%252fsecret')).status, 404);
  assert.equal((await postToken(base + '/archx/token/cat/extra')).status, 404);
  assert.equal((await postToken(base + '/archx/token/cat', { body: 'x'.repeat(1025) })).status, 413);
  assert.equal((await postToken(base + '/archx/token/cat?w=12abc')).status, 400);
  assert.equal((await postToken(base + '/archx/token/cat?bw=100&bh=0&fit=cover')).status, 400);
  assert.equal((await postToken(base + '/archx/token/cat?w=100&fit=evil')).status, 400);
  assert.equal((await postToken(base + '/archx/token/cat?w=100', {
    headers: { 'sec-fetch-site': 'cross-site' },
  })).status, 403);

  const mint = async () => {
    const res = await postToken(base + '/archx/token/cat?w=220');
    assert.equal(res.status, 200);
    return res.json();
  };

  // Twenty truly parallel spends of one URL: exactly one may win.
  const raced = await mint();
  const statuses = await Promise.all(Array.from({ length: 20 }, async () => {
    const res = await fetch(base + raced.url);
    await res.arrayBuffer();
    return res.status;
  }));
  assert.equal(statuses.filter((status) => status === 200).length, 1, JSON.stringify(statuses));
  assert.equal(statuses.filter((status) => status === 403).length, 19);

  // A token issued to Alice cannot be redeemed after the session becomes Mallory.
  const transferred = await mint();
  viewerId = 'mallory';
  assert.equal((await fetch(base + transferred.url)).status, 403);
  viewerId = 'alice';

  // Revocation during the token TTL wins over a valid signature/expiry.
  const revoked = await mint();
  allowed = false;
  assert.equal((await fetch(base + revoked.url)).status, 403);
  allowed = true;

  // Redemption authorization can tighten the signed resolution, never widen it.
  const narrowed = await mint();
  entitlementWidth = 120;
  const narrowedRes = await fetch(base + narrowed.url);
  assert.equal(narrowedRes.status, 200);
  assert.equal(narrowedRes.headers.get('content-security-policy'), "default-src 'none'; sandbox");
  assert.equal(narrowedRes.headers.get('cross-origin-resource-policy'), 'same-origin');
  const narrowedBytes = new Uint8Array(await narrowedRes.arrayBuffer());
  assert.equal(decodeContainer(narrowedBytes).header.w, 120);
  entitlementWidth = 220;

  const duplicateToken = `${narrowed.url}&t=second-token`;
  assert.equal((await fetch(base + duplicateToken)).status, 403);
  assert.equal((await fetch(base + '/archx/i/cat?t=' + 'A'.repeat(9000))).status, 403);

  assert.ok(events.length > 5, 'security hook receives denial telemetry');
  assert.equal(JSON.stringify(events).includes(TEST_SECRET), false);
  assert.ok(events.every((event) => !('token' in event) && !('key' in event) && !('headers' in event)));
});

test('rate limits, quotas, and distinct-image abuse policy are independently enforceable', async (t) => {
  const rate = await startArchxFixture(t, {
    allowAnonymous: true,
    tokenRateLimitPerMinute: 2,
  });
  assert.equal((await postToken(rate.base + '/archx/token/unknown?w=100')).status, 404,
    'unknown-ID enumeration attempts still consume the bounded request budget');
  assert.equal((await postToken(rate.base + '/archx/token/cat?w=100')).status, 200);
  const limited = await postToken(rate.base + '/archx/token/cat?w=100');
  assert.equal(limited.status, 429);
  assert.ok(Number(limited.headers.get('retry-after')) >= 1);

  const quota = await startArchxFixture(t, {
    quotas: { perViewerImage: 1, windowMs: 60_000 },
    authorize: async () => ({ viewerId: 'quota-user' }),
  });
  assert.equal((await postToken(quota.base + '/archx/token/cat?w=100')).status, 200);
  const quotaDenied = await postToken(quota.base + '/archx/token/cat?w=100');
  assert.equal(quotaDenied.status, 429);
  assert.ok(Number(quotaDenied.headers.get('retry-after')) >= 1);

  const abuseEvents = [];
  const abuse = await startArchxFixture(t, {
    abuseDetection: { distinctImages: 1, windowMs: 60_000, action: 'deny' },
    onSecurityEvent: (event) => abuseEvents.push(event),
    authorize: async () => ({ viewerId: 'collector' }),
  }, { cat: [320, 240], dog: [320, 240] });
  assert.equal((await postToken(abuse.base + '/archx/token/cat?w=100')).status, 200);
  assert.equal((await postToken(abuse.base + '/archx/token/dog?w=100')).status, 429);
  assert.ok(abuseEvents.some((event) => event.type === 'archx.suspicious_scraping'));
});

test('image processing limits reject corrupt/oversized/format-mismatched masters with typed errors', async () => {
  const master = await syntheticMaster(320, 240);
  const rejectsWith = async (promise, code) => assert.rejects(promise, (err) => err.code === code);

  await rejectsWith(
    scrambleImage(Buffer.from('this is definitely not an image'), { key: 'limits' }),
    'ARCHX_UNSUPPORTED_IMAGE',
  );
  await rejectsWith(
    scrambleImage(master, { key: 'limits', maxInputBytes: 1024 }),
    'ARCHX_INPUT_TOO_LARGE',
  );
  await rejectsWith(
    scrambleImage(master, { key: 'limits', maxInputPixels: 10000 }),
    'ARCHX_INPUT_TOO_LARGE',
  );
  await rejectsWith(
    scrambleImage(master, { key: 'limits', allowedInputFormats: ['jpeg'] }),
    'ARCHX_UNSUPPORTED_IMAGE',
  );
  await assert.rejects(
    scrambleImage(master, { key: 'limits', grid: 99 }),
    /grid must be/,
  );

  const bounded = await scrambleImage(master, {
    key: 'limits', maxWidth: 320, maxOutputPixels: 10000,
  });
  assert.ok(bounded.header.w * bounded.header.h <= 10000, JSON.stringify(bounded.header));
});

test('StegoMark geometry search recovers a uniform center crop without accepting the unmarked control', async () => {
  const master = await syntheticMaster(640, 420);
  const { data, info } = await sharp(master).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const raw = new Uint8Array(data);
  const marked = embedStegoFingerprint(raw, info.width, info.height, 'CROP-90', { key: 'geometry-key' });
  const markedPng = await sharp(Buffer.from(marked), {
    raw: { width: info.width, height: info.height, channels: 4 },
  }).png().toBuffer();
  const cropped = await sharp(markedPng)
    .extract({ left: 32, top: 21, width: 576, height: 378 })
    .jpeg({ quality: 85 }).toBuffer();
  const croppedRaw = await sharp(cropped).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const found = detectStegoFingerprint(new Uint8Array(croppedRaw.data), croppedRaw.info.width, croppedRaw.info.height, {
    key: 'geometry-key', searchOffsets: true, searchGeometry: true,
  });
  assert.equal(found.found, true, JSON.stringify(found));
  assert.equal(found.fingerprint, stegoFingerprint('CROP-90'));
  assert.ok(Math.abs(found.geometry.scaleX - 1.111) < 0.02, JSON.stringify(found.geometry));

  const unmarked = detectStegoFingerprint(raw, info.width, info.height, {
    key: 'geometry-key', searchOffsets: true, searchGeometry: true,
  });
  assert.equal(unmarked.found, false, JSON.stringify(unmarked));
});
