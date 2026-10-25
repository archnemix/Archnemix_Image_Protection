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
} from '../src/scramble.js';
// (decryptPayload used by the AES .archx test below)
import { scrambleImage, unscrambleImage } from '../server/scramble-image.js';
import { createArchxMiddleware, signToken, verifyToken } from '../server/middleware.js';

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
  const handler = createArchxMiddleware({ secret: 'http-secret', imagesDir: dir, ttlSec: 60 });
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address().port}`;

  // unknown id -> 404 (no existence leaks)
  assert.equal((await fetch(base + '/archx/token/nope')).status, 404);
  // path traversal style id -> 404
  assert.equal((await fetch(base + '/archx/token/..%2Fsecret')).status, 404);
  // image route without token -> 403
  assert.equal((await fetch(base + '/archx/i/cat')).status, 403);

  const tokenRes = await fetch(base + '/archx/token/cat?w=300');
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
  const coverToken = await (await fetch(base + '/archx/token/cat?bw=120&bh=120&fit=cover')).json();
  const coverBytes = new Uint8Array(await (await fetch(base + coverToken.url)).arrayBuffer());
  assert.equal(decodeContainer(coverBytes).header.w, 160);

  // tampered token -> 403
  const tampered = token.url.replace(/t=([^.]+)\./, (_, b) => 't=' + b.slice(0, -2) + 'XX.');
  assert.equal((await fetch(base + tampered)).status, 403);
  // expired token -> 403 (sign one in the past with the same secret)
  const expired = signToken({ id: 'cat', w: 300, exp: Date.now() - 5000, n: 'n' }, 'http-secret');
  assert.equal((await fetch(`${base}/archx/i/cat?t=${expired}`)).status, 403);
  // token minted for a different id -> 403
  const other = signToken({ id: 'dog', w: 300, exp: Date.now() + 60000, n: 'n' }, 'http-secret');
  assert.equal((await fetch(`${base}/archx/i/cat?t=${other}`)).status, 403);
});

test('hardened middleware: one-time + UA-bound tokens, entitlement width cap, origin allowlist, server watermark/forensic', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-hard-'));
  fs.writeFileSync(path.join(dir, 'cat.jpg'), await syntheticMaster());
  const handler = createArchxMiddleware({
    secret: 'hard-secret',
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
  assert.equal((await fetch(base + '/archx/token/cat?w=900', asBrowser('BrowserA', false))).status, 403);

  const tokenRes = await fetch(base + '/archx/token/cat?w=900', asBrowser('BrowserA'));
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
