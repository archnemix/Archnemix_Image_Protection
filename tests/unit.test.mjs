import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';
import sharp from 'sharp';
import {
  buildScramblePlan, scramblePixels, scramblePixelsPadded, paddedSize,
  encodeContainer, decodeContainer, isArchxContainer,
  encryptPayload, decryptPayload, generateKeyBase64,
  applyForensicBlocks, forensicScore, forensicBlockSigns,
  embedStegoFingerprint, detectStegoFingerprint, stegoFingerprint,
  sniffImageInfo, decodeBmpImage, base64ToBytes,
  perceptualFingerprint, perceptualFingerprintDistance, comparePerceptualFingerprints,
} from '../src/scramble.js';
// (decryptPayload used by the AES .archx test below)
import { inspectImageMetadata, scrambleImage, unscrambleImage } from '../server/scramble-image.js';
import { buildArchxAssets } from '../server/build-assets.js';
import {
  DEFAULT_SOURCE_WIDTH_BUCKETS, PRESETS,
  TEMPORAL_INTERLACE_PROFILES, normalizeTemporalInterlace,
} from '../src/archx.js';
import {
  createArchxMiddleware, createMemoryStateStore, deriveStegoKey,
  auditArchxServerConfig, auditArchxProductionConfig, withHardenedProductionDefaults,
  withCatalogThroughputDefaults, canonicalDerivativeWidth, DEFAULT_WIDTH_BUCKETS,
  validateTokenClaims, validateImageId,
  normalizeAuthorizationResult, validateWatermarkValue, computeJwkThumbprint,
  SlidingWindowLimiter, BoundedTtlSet, AsyncSemaphore,
} from '../server/middleware.js';
import { createRedisStateStore, REDIS_STATE_STORE_SCRIPTS } from '../server/redis-state-store.js';

function signTokenForTest(payload, secret) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', secret).update(body).digest().toString('base64url');
  return `${body}.${mac}`;
}

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

test('fused pad+scramble is byte-identical to pad-then-scramble (incl. awkward sizes)', () => {
  const manualPad = (raw, w, h, pw, ph) => {
    const out = new Uint8Array(pw * ph * 4);
    for (let y = 0; y < ph; y++) {
      for (let x = 0; x < pw; x++) {
        const di = (y * pw + x) * 4;
        if (x < w && y < h) out.set(raw.subarray((y * w + x) * 4, (y * w + x) * 4 + 4), di);
        else out[di + 3] = 255;
      }
    }
    return out;
  };
  for (const [w, h, grid] of [[64, 48, 8], [61, 47, 8], [10, 10, 8], [333, 17, 16], [129, 257, 4], [7, 7, 32]]) {
    const raw = new Uint8Array(w * h * 4);
    for (let i = 0; i < raw.length; i++) raw[i] = (i * 40503 + 17) % 256;
    const plan = buildScramblePlan(grid, `fused-${w}x${h}-${grid}`);
    const { pw, ph } = paddedSize(w, h, grid);
    const expected = scramblePixels(manualPad(raw, w, h, pw, ph), pw, ph, plan, 'scramble');
    assert.deepEqual(scramblePixelsPadded(raw, w, h, plan), expected, `${w}x${h} grid ${grid}`);
    const out = Buffer.alloc(pw * ph * 4);
    assert.equal(scramblePixelsPadded(raw, w, h, plan, out), out);
    assert.deepEqual(new Uint8Array(out), expected, `${w}x${h} grid ${grid} (provided buffer)`);
    // and the fused output unscrambles back to the padded original
    assert.deepEqual(
      scramblePixels(scramblePixelsPadded(raw, w, h, plan), pw, ph, plan, 'unscramble'),
      manualPad(raw, w, h, pw, ph));
  }
  assert.throws(() => scramblePixelsPadded(new Uint8Array(8), 64, 64, buildScramblePlan(8, 'k')), /smaller/);
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

function redeemToken(base, tokenResponse, { headers = {}, ...init } = {}) {
  return fetch(base + tokenResponse.cleanUrl, {
    ...init,
    headers: { ...headers, 'x-archx-token': tokenResponse.token },
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

test('public server surface does not export generic token signing/verification primitives', async () => {
  const middleware = await import('../server/middleware.js');
  assert.equal('signToken' in middleware, false);
  assert.equal('verifyToken' in middleware, false);
  // Tamper/expiry/wrong-ID signature handling is asserted at HTTP level below,
  // against the real redemption path rather than a test-only helper.
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
  assert.equal(token.url, '/archx/i/cat', 'query bearer transport is off by default');
  assert.equal(token.cleanUrl, '/archx/i/cat');
  assert.ok(token.key, 'token response carries the un-scramble key for the legitimate client');

  const imgRes = await redeemToken(base, token);
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
  const coverBytes = new Uint8Array(await (await redeemToken(base, coverToken)).arrayBuffer());
  assert.equal(decodeContainer(coverBytes).header.w, 160);

  // tampered token -> 403
  const tampered = token.token.replace(/^([^.]+)\./, (_, b) => b.slice(0, -2) + 'XX.');
  assert.equal((await fetch(base + token.cleanUrl, {
    headers: { 'x-archx-token': tampered },
  })).status, 403);
  // expired token -> 403 (sign one in the past with the same secret)
  const expired = signTokenForTest({
    v: 2, aud: 'archx:image', scope: 'image:view', id: 'cat', w: 300,
    iat: Date.now() - 120000, exp: Date.now() - 5000, n: 'expired-nonce-123',
  }, 'http-secret-for-unit-tests-32chars-minimum');
  assert.equal((await fetch(`${base}/archx/i/cat`, { headers: { 'x-archx-token': expired } })).status, 403);
  // token minted for a different id -> 403
  const other = signTokenForTest({
    v: 2, aud: 'archx:image', scope: 'image:view', id: 'dog', w: 300,
    iat: Date.now(), exp: Date.now() + 60000, n: 'other-nonce-12345',
  }, 'http-secret-for-unit-tests-32chars-minimum');
  assert.equal((await fetch(`${base}/archx/i/cat`, { headers: { 'x-archx-token': other } })).status, 403);
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
  assert.equal((await redeemToken(base, token, asBrowser('BrowserB'))).status, 403);
  // …the right browser can, exactly once.
  const ok = await redeemToken(base, token, asBrowser('BrowserA'));
  assert.equal(ok.status, 200);
  const bytes = new Uint8Array(await ok.arrayBuffer());
  const { header } = decodeContainer(bytes);
  assert.equal(header.w, 180, 'entitlement maxWidth overrides the client-requested 900px');
  assert.equal(header.wm, 1, 'server watermark baked pre-scramble');
  assert.equal(header.fx, 1, 'forensic mark baked pre-scramble');
  // Replay of the same (still unexpired) URL -> 403: one-time use.
  assert.equal((await redeemToken(base, token, asBrowser('BrowserA'))).status, 403);
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

  const bytes = new Uint8Array(await (await redeemToken(base, token)).arrayBuffer());
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
    const res = await redeemToken(base, raced);
    await res.arrayBuffer();
    return res.status;
  }));
  assert.equal(statuses.filter((status) => status === 200).length, 1, JSON.stringify(statuses));
  assert.equal(statuses.filter((status) => status === 403).length, 19);

  // A token issued to Alice cannot be redeemed after the session becomes Mallory.
  const transferred = await mint();
  viewerId = 'mallory';
  assert.equal((await redeemToken(base, transferred)).status, 403);
  viewerId = 'alice';

  // Revocation during the token TTL wins over a valid signature/expiry.
  const revoked = await mint();
  allowed = false;
  assert.equal((await redeemToken(base, revoked)).status, 403);
  allowed = true;

  // Redemption authorization can tighten the signed resolution, never widen it.
  const narrowed = await mint();
  entitlementWidth = 120;
  const narrowedRes = await redeemToken(base, narrowed);
  assert.equal(narrowedRes.status, 200);
  assert.equal(narrowedRes.headers.get('content-security-policy'), "default-src 'none'; sandbox");
  assert.equal(narrowedRes.headers.get('cross-origin-resource-policy'), 'same-origin');
  const narrowedBytes = new Uint8Array(await narrowedRes.arrayBuffer());
  assert.equal(decodeContainer(narrowedBytes).header.w, 120);
  entitlementWidth = 220;

  const duplicateToken = `${narrowed.cleanUrl}?t=${narrowed.token}&t=second-token`;
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

/* ---------- v1.5 backdoor-surface / fail-closed regressions ---------- */

test('v1.5 strict configuration rejects typos, weak-secret bypasses, and ambiguous authorization results', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-v15-config-'));
  fs.writeFileSync(path.join(dir, 'cat.jpg'), await syntheticMaster());
  const base = { secret: TEST_SECRET, imagesDir: dir, allowAnonymous: true };

  for (const mutation of [
    { allowWeakSecretForTests: true },
    { allowAnon: true },
    { oneTimeTokens: 'false' },
    { trustProxy: 'yes' },
    { quotas: { perIP: 1 } },
    { bindTokenTo: { sessions: true } },
    { processing: { maxInputPixel: 10000 } },
    { abuseDetection: { distinctImages: 10001 } },
    { steganography: { strength: 99 } },
    { serverWatermark: { text: 'ok', onclick: 'alert(1)' } },
  ]) {
    const audited = auditArchxServerConfig({ ...base, ...mutation });
    assert.equal(audited.ok, false, JSON.stringify(mutation));
    assert.throws(() => createArchxMiddleware({ ...base, ...mutation }), /configuration is invalid/i);
  }

  assert.deepEqual(normalizeAuthorizationResult(true), {});
  assert.equal(normalizeAuthorizationResult({ viewerId: 42, maxWidth: 800 })?.viewerId, '42');
  for (const denied of [
    null, false, 'yes', [], {}, { allowed: false, viewerId: 'x' }, { allow: 0, viewerId: 'x' },
    { permissions: 'image:view' }, { permissions: [] }, { scope: '' }, { viewerId: '' },
    { maxWidth: '800' }, { quality: 101 }, { format: 'tiff' },
    { watermark: { text: 'x', evil: true } }, { steganography: { strength: 99 } },
    { stegoFingerprint: '' }, { unknownOnly: true },
  ]) assert.equal(normalizeAuthorizationResult(denied), null, JSON.stringify(denied));

  assert.equal(validateWatermarkValue('© Studio'), true);
  assert.equal(validateWatermarkValue({ text: '© Studio', opacity: 0.2, tile: false }), true);
  assert.equal(validateWatermarkValue({ text: 'x'.repeat(513) }), false);
  assert.equal(validateWatermarkValue({ angle: '0);evil' }), false);

  const now = 1_800_000_000_000;
  const valid = {
    v: 2, aud: 'archx:image', scope: 'image:view', id: 'cat', w: 800,
    iat: now, exp: now + 60000, n: 'nonce-1234567890', q: 95, fmt: 'webp',
    vh: 'A'.repeat(20), sge: 1, sgs: 6, sgx: 24, sgy: 16,
    wm: { text: 'Viewer 42', opacity: 0.2 }, b: { ip: 'B'.repeat(16) },
  };
  const claimOpts = { id: 'cat', maxWidthCap: 1920, maxTtlMs: 120000, now: now + 1000 };
  assert.equal(validateTokenClaims(valid, claimOpts), true);
  for (const mutation of [
    { surprise: true }, { vh: 'short' }, { sgp: 1 }, { sgs: 99 }, { sgx: 65 },
    { b: { ip: 'B'.repeat(24) } }, { b: { ip: 'B'.repeat(16), admin: 'C'.repeat(16) } },
    { wm: { text: 'x', evil: 1 } }, { wm: 'x'.repeat(513) }, { sg: 'bad\nvalue' },
  ]) assert.equal(validateTokenClaims({ ...valid, ...mutation }, claimOpts), false, JSON.stringify(mutation));
});

test('v1.5 core sniffing, strict containers, base64, and byte-only Sharp inputs reject hostile payloads early', async () => {
  const master = await syntheticMaster(320, 240);
  assert.deepEqual(sniffImageInfo(master), { format: 'png', mime: 'image/png', width: 320, height: 240 });
  const jpeg = await sharp(master).jpeg().toBuffer();
  assert.equal(sniffImageInfo(jpeg)?.format, 'jpeg');
  assert.equal(sniffImageInfo(jpeg)?.width, 320);

  // BMP detector path: 2×2, bottom-up, 24-bit BI_RGB. Rows are padded to
  // four bytes and stored BGR. Sharp cannot decode BMP input, so Archx has a
  // strict bounded decoder for ordinary screenshot files.
  const bmp = Buffer.alloc(54 + 16);
  bmp.write('BM', 0, 'ascii');
  bmp.writeUInt32LE(bmp.length, 2);
  bmp.writeUInt32LE(54, 10);
  bmp.writeUInt32LE(40, 14);
  bmp.writeInt32LE(2, 18);
  bmp.writeInt32LE(2, 22);
  bmp.writeUInt16LE(1, 26);
  bmp.writeUInt16LE(24, 28);
  bmp.writeUInt32LE(16, 34);
  bmp.set([
    255, 0, 0, 0, 255, 0, 0, 0,       // bottom row: blue, green
    0, 0, 255, 255, 255, 255, 0, 0,   // top row: red, white
  ], 54);
  const decodedBmp = decodeBmpImage(bmp);
  assert.deepEqual([decodedBmp.width, decodedBmp.height, decodedBmp.channels], [2, 2, 4]);
  assert.deepEqual([...decodedBmp.data], [
    255, 0, 0, 255, 255, 255, 255, 255,
    0, 0, 255, 255, 0, 255, 0, 255,
  ]);
  const compressedBmp = Buffer.from(bmp);
  compressedBmp.writeUInt32LE(1, 30); // BI_RLE8
  assert.throws(() => decodeBmpImage(compressedBmp), /only uncompressed/);
  assert.throws(() => decodeBmpImage(bmp.subarray(0, bmp.length - 1)), /declared file size|truncated/);
  assert.throws(() => decodeBmpImage(bmp, { maxPixels: 3 }), /pixel limit/);

  const hugePngHeader = Buffer.from([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
    0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52,
    0, 0, 0x27, 0x10, 0, 0, 0x27, 0x10, 8, 6, 0, 0, 0,
  ]);
  assert.deepEqual(sniffImageInfo(hugePngHeader), { format: 'png', mime: 'image/png', width: 10000, height: 10000 });
  await assert.rejects(
    scrambleImage(hugePngHeader, { key: 'sniff' }),
    (err) => err.code === 'ARCHX_INPUT_TOO_LARGE',
    'dimension header is rejected before the native decoder is reached',
  );
  await assert.rejects(
    scrambleImage('/etc/passwd', { key: 'sniff' }),
    (err) => err.code === 'ARCHX_UNSUPPORTED_IMAGE',
    'a path string must never become a Sharp local-file read',
  );
  await assert.rejects(scrambleImage(master, { key: 'x', quality: '95' }), /quality must be/);
  await assert.rejects(scrambleImage(master, { key: 'x', allowedInputFormats: ['png', 'exe'] }), /allowedInputFormats/);

  const validHeader = { v: 1, w: 10, h: 10, pw: 16, ph: 16, grid: 8, mime: 'image/webp', scrambled: true, encrypted: false };
  assert.equal(decodeContainer(encodeContainer(validHeader, new Uint8Array([1, 2, 3]))).header.grid, 8);
  assert.throws(() => encodeContainer({ ...validHeader, pw: 999 }, new Uint8Array([1])), /padded dimensions/);
  assert.throws(() => encodeContainer({ ...validHeader, mime: 'image/svg+xml' }, new Uint8Array([1])), /MIME/);
  assert.throws(() => encodeContainer({ ...validHeader, surprise: true }, new Uint8Array([1])), /unknown field/);
  assert.throws(() => encodeContainer({ ...validHeader, encrypted: true, iv: 'AA==' }, new Uint8Array([1])), /IV/);

  assert.equal(new TextDecoder().decode(base64ToBytes('aGVsbG8')), 'hello');
  assert.deepEqual([...base64ToBytes('AB-_')], [0, 31, 191]);
  for (const bad of ['A', 'a===', '***', 42]) assert.throws(() => base64ToBytes(bad));

  const plan = buildScramblePlan(8, 'strict-pixels');
  assert.throws(() => scramblePixels(new Uint8Array(64 * 64 * 4), 64, 64, plan, 'sideways'), /direction/);
  assert.throws(() => scramblePixels(new Uint8Array(10), 64, 64, plan, 'scramble'), /smaller/);
});

test('v1.5 HTTP: required mint header, clean header-token transport, callback timeout, and entitlement-only StegoMark', async (t) => {
  let authMode = 'ok';
  let slowAuthorize = false;
  const issued = [];
  const { base, handler } = await startArchxFixture(t, {
    callbackTimeoutMs: 100,
    allowQueryTokens: true, // explicit compatibility opt-in under test
    onStegoIssue: async (record) => { issued.push(record); },
    authorize: async () => {
      if (slowAuthorize) await new Promise((resolve) => setTimeout(resolve, 250));
      if (authMode === 'denied') return { allowed: false, viewerId: 'mallory' };
      if (authMode === 'stego') {
        return {
          viewerId: 'buyer-99',
          steganography: { perToken: false, strength: 6, gridX: 24, gridY: 16 },
          stegoFingerprint: 'ORDER-99',
        };
      }
      return { viewerId: 'viewer-1' };
    },
  }, { cat: [640, 420] });

  assert.equal(handler.index, undefined, 'live file index is not a public handler property');
  assert.equal(handler._test, undefined, 'test hooks are not a public handler property');

  assert.equal((await fetch(base + '/archx/token/cat?w=200', { method: 'POST' })).status, 403,
    'the custom X-Archx-Request mint header is enforced by default');
  assert.equal((await postToken(base + '/archx/token/cat?w=200', {
    headers: { 'sec-fetch-site': 'same-site' },
  })).status, 403, 'same-site is not silently treated as same-origin');

  const mint = async (query = 'w=200') => {
    const res = await postToken(`${base}/archx/token/cat?${query}`);
    assert.equal(res.status, 200);
    return res.json();
  };
  const first = await mint();
  assert.ok(first.token && first.cleanUrl && !first.cleanUrl.includes('?t='));
  assert.ok(first.url.includes('?t='), 'query URL remains available only with explicit allowQueryTokens compatibility opt-in');

  assert.equal((await fetch(base + first.url, {
    headers: { 'x-archx-token': first.token },
  })).status, 403, 'simultaneous query + header tokens are ambiguous and fail closed');
  const headerRes = await fetch(base + first.cleanUrl, {
    headers: { 'x-archx-token': first.token },
  });
  assert.equal(headerRes.status, 200, 'the rejected duplicate attempt did not spend the one-time token');
  assert.ok(isArchxContainer(new Uint8Array(await headerRes.arrayBuffer())));

  const second = await mint();
  assert.equal((await fetch(base + second.url)).status, 200, 'legacy query transport still works only when explicitly enabled');

  authMode = 'denied';
  assert.equal((await postToken(base + '/archx/token/cat?w=200')).status, 403,
    'an explicit allowed:false authorization result can never widen into access');
  authMode = 'ok';

  slowAuthorize = true;
  assert.equal((await postToken(base + '/archx/token/cat?w=200')).status, 403,
    'a hung authorize callback times out closed');
  slowAuthorize = false;

  authMode = 'stego';
  const stegoToken = await mint('w=640');
  assert.equal(issued.length, 1);
  assert.equal(issued[0].fingerprint, stegoFingerprint('ORDER-99'));
  const stegoRes = await fetch(base + stegoToken.cleanUrl, {
    headers: { 'x-archx-token': stegoToken.token },
  });
  assert.equal(stegoRes.status, 200, 'entitlement-only StegoMark survives from mint claims to redemption');
  const stegoBytes = new Uint8Array(await stegoRes.arrayBuffer());
  const { header, payload } = decodeContainer(stegoBytes);
  assert.equal(header.sg, 1);
  const restored = await unscrambleImage(Buffer.from(payload), {
    grid: header.grid, key: stegoToken.key, w: header.w, h: header.h,
  });
  const raw = await sharp(restored).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const found = detectStegoFingerprint(new Uint8Array(raw.data), raw.info.width, raw.info.height, {
    key: deriveStegoKey('cat', TEST_SECRET), gridX: 24, gridY: 16,
  });
  assert.equal(found.found, true, JSON.stringify(found));
  assert.equal(found.fingerprint, stegoFingerprint('ORDER-99'));

  assert.equal(handler.stats().outputInFlight, 0);
  assert.equal(handler.stats().dimensionInFlight, 0);
});

test('v1.5 HTTP: hardened query-token opt-out and trusted-hop X-Forwarded-For selection', async (t) => {
  const hardened = await startArchxFixture(t, { allowAnonymous: true, allowQueryTokens: false });
  const tokenRes = await postToken(hardened.base + '/archx/token/cat?w=120');
  assert.equal(tokenRes.status, 200);
  const token = await tokenRes.json();
  assert.equal(token.url, token.cleanUrl);
  assert.equal(token.url.includes('?t='), false);
  assert.equal((await fetch(`${hardened.base}${token.cleanUrl}?t=${token.token}`)).status, 403);
  assert.equal((await fetch(hardened.base + token.cleanUrl, {
    headers: { 'x-archx-token': token.token },
  })).status, 200);

  const spoofed = await startArchxFixture(t, {
    allowAnonymous: true,
    quotas: { perIp: 1, windowMs: 60000 },
  });
  assert.equal((await postToken(spoofed.base + '/archx/token/cat?w=100', {
    headers: { 'x-forwarded-for': '1.2.3.4' },
  })).status, 200);
  assert.equal((await postToken(spoofed.base + '/archx/token/cat?w=100', {
    headers: { 'x-forwarded-for': '5.6.7.8' },
  })).status, 429, 'untrusted XFF cannot rotate around the socket-IP quota');

  const trusted = await startArchxFixture(t, {
    allowAnonymous: true,
    trustProxy: true,
    trustedProxyHops: 1,
    quotas: { perIp: 1, windowMs: 60000 },
  });
  assert.equal((await postToken(trusted.base + '/archx/token/cat?w=100', {
    headers: { 'x-forwarded-for': '9.9.9.9, 1.2.3.4' },
  })).status, 200);
  assert.equal((await postToken(trusted.base + '/archx/token/cat?w=100', {
    headers: { 'x-forwarded-for': '8.8.8.8, 1.2.3.4' },
  })).status, 429, 'the rightmost trusted-hop address is selected, not the spoofable leftmost value');
  assert.equal((await postToken(trusted.base + '/archx/token/cat?w=100', {
    headers: { 'x-forwarded-for': '8.8.8.8, 5.6.7.8' },
  })).status, 200);
});

function makeProofKeyForTest() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const exported = publicKey.export({ format: 'jwk' });
  const jwk = { kty: 'EC', crv: 'P-256', x: exported.x, y: exported.y };
  return {
    privateKey,
    jwk,
    jkt: computeJwkThumbprint(jwk),
    header: Buffer.from(JSON.stringify(jwk)).toString('base64url'),
  };
}

function makeProofForTest(proofKey, token, {
  target = '/archx/i/cat',
  jti = crypto.randomBytes(18).toString('base64url'),
  iat = Date.now(),
  exp = Date.now() + 60000,
} = {}) {
  const proof = {
    jwk: proofKey.jwk,
    jti,
    iat,
    exp,
    htm: 'GET',
    htu: target,
    ath: crypto.createHash('sha256').update(token).digest().toString('base64url'),
  };
  const payloadPart = Buffer.from(JSON.stringify(proof)).toString('base64url');
  const signingInput = `v1.${payloadPart}`;
  const signature = crypto.sign('sha256', Buffer.from(signingInput), {
    key: proofKey.privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return `${signingInput}.${signature.toString('base64url')}`;
}

test('sender-constrained tokens require the page proof key and one-time proof', async (t) => {
  assert.equal(auditArchxServerConfig({
    secret: TEST_SECRET,
    allowAnonymous: true,
    imagesDir: '/tmp/archx-proof-audit-images',
    proofOfPossession: 'sometimes',
  }).ok, false);

  const proofKey = makeProofKeyForTest();
  const wrongProofKey = makeProofKeyForTest();
  assert.match(proofKey.jkt, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(computeJwkThumbprint({ ...proofKey.jwk, x: wrongProofKey.jwk.x }) === proofKey.jkt, false);

  const { base, handler } = await startArchxFixture(t, {
    allowAnonymous: true,
    allowQueryTokens: false,
    proofOfPossession: 'required',
    oneTimeTokens: false,
  });
  assert.equal(handler.configAudit.summary.proofOfPossession, 'required');

  assert.equal((await postToken(base + '/archx/token/cat?w=160')).status, 403,
    'a required proof key cannot be omitted at mint');
  assert.equal((await postToken(base + '/archx/token/cat?w=160', {
    headers: { 'x-archx-proof-key': 'not-a-jwk' },
  })).status, 403, 'a malformed proof key fails closed');

  const mintRes = await postToken(base + '/archx/token/cat?w=160', {
    headers: { 'x-archx-proof-key': proofKey.header },
  });
  assert.equal(mintRes.status, 200);
  assert.equal(mintRes.headers.get('cdn-cache-control'), 'private, no-store');
  assert.equal(mintRes.headers.get('surrogate-control'), 'no-store');
  assert.match(mintRes.headers.get('vary') || '', /X-Archx-Proof/);
  const minted = await mintRes.json();
  assert.equal(minted.url, minted.cleanUrl);
  const claims = JSON.parse(Buffer.from(minted.token.split('.')[0], 'base64url').toString('utf8'));
  assert.equal(claims.jkt, proofKey.jkt);
  assert.equal(validateTokenClaims(claims, { id: 'cat', maxWidthCap: 1920, maxTtlMs: 120000 }), true);
  assert.equal(validateTokenClaims({ ...claims, jkt: 'short' }, { id: 'cat', maxWidthCap: 1920, maxTtlMs: 120000 }), false);

  assert.equal((await fetch(base + minted.cleanUrl, {
    headers: { 'x-archx-token': minted.token },
  })).status, 403, 'a copied bearer token without the private proof key is useless');
  assert.equal((await fetch(base + minted.cleanUrl, {
    headers: {
      'x-archx-token': minted.token,
      'x-archx-proof': makeProofForTest(wrongProofKey, minted.token),
    },
  })).status, 403, 'a proof from a different key does not satisfy the signed thumbprint');

  const proof = makeProofForTest(proofKey, minted.token);
  const ok = await fetch(base + minted.cleanUrl, {
    headers: { 'x-archx-token': minted.token, 'x-archx-proof': proof },
  });
  assert.equal(ok.status, 200);
  assert.ok(isArchxContainer(new Uint8Array(await ok.arrayBuffer())));
  assert.equal((await fetch(base + minted.cleanUrl, {
    headers: { 'x-archx-token': minted.token, 'x-archx-proof': proof },
  })).status, 403, 'the exact proof header cannot be replayed even when reusable tokens are enabled');
  assert.equal((await fetch(base + minted.cleanUrl, {
    headers: {
      'x-archx-token': minted.token,
      'x-archx-proof': makeProofForTest(proofKey, minted.token),
    },
  })).status, 200, 'the legitimate key holder can create a fresh proof');
  assert.ok(handler.stats().consumedProofs >= 2);
});

test('perceptual soft-binding fingerprint survives resize/re-encode and separates different images', async () => {
  const master = await syntheticMaster(320, 240);
  const original = await sharp(master).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const fingerprint = perceptualFingerprint(new Uint8Array(original.data), original.info.width, original.info.height);
  assert.match(fingerprint, /^[0-9a-f]{16}$/);

  const protectedResult = await scrambleImage(master, {
    key: 'soft-binding-key', maxWidth: 320, contentFingerprint: true,
  });
  assert.equal(protectedResult.perceptualFingerprint, fingerprint);

  const copiedBytes = await sharp(master).resize({ width: 224 }).jpeg({ quality: 82 }).toBuffer();
  const copied = await sharp(copiedBytes).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const copiedFingerprint = perceptualFingerprint(new Uint8Array(copied.data), copied.info.width, copied.info.height);
  const comparison = comparePerceptualFingerprints(fingerprint, copiedFingerprint, { maxDistance: 10 });
  assert.equal(comparison.match, true, JSON.stringify({ fingerprint, copiedFingerprint, comparison }));
  assert.equal(perceptualFingerprintDistance(fingerprint, fingerprint), 0);

  const different = new Uint8Array(320 * 240 * 4);
  for (let y = 0; y < 240; y++) {
    for (let x = 0; x < 320; x++) {
      const i = (y * 320 + x) * 4;
      const v = ((x + y) % 32 < 16) ? 20 : 235;
      different[i] = v; different[i + 1] = 255 - v; different[i + 2] = 128; different[i + 3] = 255;
    }
  }
  const differentFingerprint = perceptualFingerprint(different, 320, 240);
  assert.ok(perceptualFingerprintDistance(fingerprint, differentFingerprint) > 10,
    `unrelated synthetic image should separate: ${fingerprint} vs ${differentFingerprint}`);
  assert.throws(() => perceptualFingerprintDistance(fingerprint, 'not-hex'), /16 hex/);
  assert.throws(() => comparePerceptualFingerprints(fingerprint, fingerprint, { maxDistance: 65 }), /maxDistance/);
});

test('temporal interlace profiles are 60 Hz-safe by default and remain directly configurable', () => {
  assert.deepEqual(Object.keys(TEMPORAL_INTERLACE_PROFILES), [
    'balanced60', 'pixels60', 'strips60', 'blocks60', 'fortress60',
  ]);
  assert.equal(normalizeTemporalInterlace(false), null);
  assert.equal(normalizeTemporalInterlace('off'), null);
  assert.equal(normalizeTemporalInterlace({ enabled: false }), null);
  assert.equal(normalizeTemporalInterlace({ profile: false }), null);

  const balanced = normalizeTemporalInterlace(true);
  assert.equal(balanced.profile, 'balanced60');
  assert.equal(balanced.engine, 'auto');
  assert.equal(balanced.layout, 'checker');
  assert.equal(balanced.phases, 2);
  assert.equal(balanced.phaseHz, 30);
  assert.equal(balanced.fill, 'lowres');
  assert.equal(balanced.respectReducedMotion, true);

  const strips = normalizeTemporalInterlace({
    profile: 'strips60', engine: 'gpu', phases: 4, refreshHz: 60,
  });
  assert.equal(strips.engine, 'shader');
  assert.equal(strips.layout, 'strips');
  assert.equal(strips.requestedPhases, 4);
  assert.equal(strips.phases, 2, '60 Hz optimization must not drop a subset below the 30 Hz floor');

  const highRefresh = normalizeTemporalInterlace({
    layout: 'pixels', phases: 4, refreshHz: 120, fill: 'black',
  });
  assert.equal(highRefresh.layout, 'pixels');
  assert.equal(highRefresh.cellSize, 1);
  assert.equal(highRefresh.phases, 4);
  assert.equal(highRefresh.phaseHz, 30);
  assert.ok(highRefresh.activeGain > 1 && highRefresh.activeGain <= 4);

  const blocks = normalizeTemporalInterlace({ layout: 'blocks', engine: 'canvas' });
  assert.equal(blocks.engine, 'frames');
  assert.equal(blocks.cellSize, 8);

  const fortress = normalizeTemporalInterlace('fortress60');
  assert.equal(fortress.phases, 3);
  assert.equal(fortress.phaseHz, 20);
  assert.equal(fortress.fill, 'noise');
  assert.equal(fortress.layout, 'blocks');
  assert.equal(fortress.activeGain, 1);
});

function tokenPayloadForTest(token) {
  return JSON.parse(Buffer.from(token.split('.')[0], 'base64url').toString('utf8'));
}

async function listenForTest(t, handler) {
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    handler.close();
    await new Promise((resolve) => server.close(resolve));
  });
  return `http://127.0.0.1:${server.address().port}`;
}

test('shared state store blocks cross-instance replay and quota bypass', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-shared-state-'));
  fs.writeFileSync(path.join(dir, 'cat.jpg'), await syntheticMaster());
  const inner = createMemoryStateStore();
  // This wrapper gives two handlers one in-process store so the test can
  // prove the middleware contract without requiring Redis in CI. Production
  // multi-instance mode deliberately rejects kind:'memory' itself.
  const sharedStore = Object.freeze({
    kind: 'shared-test',
    claimOnce: (...args) => inner.claimOnce(...args),
    hitWindow: (...args) => inner.hitWindow(...args),
    trackDistinct: (...args) => inner.trackDistinct(...args),
    getCache: (...args) => inner.getCache(...args),
    setCache: (...args) => inner.setCache(...args),
    stats: () => inner.stats(),
    close: () => inner.close(),
  });
  t.after(() => sharedStore.close());
  const events = [];
  const makeHandler = () => createArchxMiddleware({
    secret: TEST_SECRET,
    imagesDir: dir,
    allowAnonymous: true,
    deploymentMode: 'multi-instance',
    stateStore: sharedStore,
    quotas: { perIp: 2, windowMs: 60000 },
    onSecurityEvent: (event) => events.push(event),
  });
  const handlerA = makeHandler();
  const handlerB = makeHandler();
  const baseA = await listenForTest(t, handlerA);
  const baseB = await listenForTest(t, handlerB);

  const token = await (await postToken(baseA + '/archx/token/cat?w=160')).json();
  assert.equal(tokenPayloadForTest(token.token).kid, 'primary');
  assert.equal((await redeemToken(baseB, token)).status, 200, 'instance B may redeem a token minted by A');
  assert.equal((await redeemToken(baseA, token)).status, 403, 'the shared nonce claim blocks replay back on A');

  assert.equal((await postToken(baseB + '/archx/token/cat?w=160')).status, 200);
  assert.equal((await postToken(baseA + '/archx/token/cat?w=160')).status, 429,
    'the per-IP quota is shared rather than reset per process');

  const replayEvent = events.find((event) => event.reason === 'token-replay');
  assert.equal(replayEvent.schemaVersion, 1);
  assert.equal(replayEvent.service, 'archx');
  assert.equal(replayEvent.imageId, 'cat');
  assert.equal(replayEvent.actor.ip, '127.0.0.1');
  assert.equal(replayEvent.request.route, '/archx/i/:id');
  assert.match(replayEvent.eventId, /^[0-9a-f-]{36}$/);
  assert.equal(handlerA.stats().stateStoreShared, true);
  assert.ok(handlerB.stats().consumedTokens >= 1);
});

test('signing-key rotation verifies old tokens with their issuing key and signs new tokens with the active key', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-key-rotation-'));
  fs.writeFileSync(path.join(dir, 'cat.jpg'), await syntheticMaster());
  const oldSecret = 'old-rotation-secret-with-32-plus-bytes';
  const newSecret = 'new-rotation-secret-with-32-plus-bytes';
  const authorize = async () => ({ viewerId: 'rotation-viewer' });
  const oldHandler = createArchxMiddleware({
    secret: oldSecret, secretId: '2026-01', imagesDir: dir, authorize,
  });
  const rotatedHandler = createArchxMiddleware({
    secrets: { '2026-01': oldSecret, '2026-02': newSecret },
    activeSecretId: '2026-02', imagesDir: dir, authorize,
  });
  const retiredHandler = createArchxMiddleware({
    secret: newSecret, secretId: '2026-02', imagesDir: dir, authorize,
  });
  const oldBase = await listenForTest(t, oldHandler);
  const rotatedBase = await listenForTest(t, rotatedHandler);
  const retiredBase = await listenForTest(t, retiredHandler);

  const oldToken = await (await postToken(oldBase + '/archx/token/cat?w=160')).json();
  assert.equal(tokenPayloadForTest(oldToken.token).kid, '2026-01');
  const oldResponse = await redeemToken(rotatedBase, oldToken);
  assert.equal(oldResponse.status, 200, 'rollover keyring still verifies the previous key');
  const oldBytes = new Uint8Array(await oldResponse.arrayBuffer());
  const oldDecoded = decodeContainer(oldBytes);
  const restored = await unscrambleImage(Buffer.from(oldDecoded.payload), {
    grid: oldDecoded.header.grid, key: oldToken.key, w: oldDecoded.header.w, h: oldDecoded.header.h,
  });
  assert.ok((await meanAbsDiff(fs.readFileSync(path.join(dir, 'cat.jpg')), restored, 80, 60)) < 22,
    'redemption derivations use the issuing secret received by the client at mint time');

  const newToken = await (await postToken(rotatedBase + '/archx/token/cat?w=160')).json();
  assert.equal(tokenPayloadForTest(newToken.token).kid, '2026-02');
  assert.equal((await redeemToken(retiredBase, newToken)).status, 200);

  const retiredOldToken = await (await postToken(oldBase + '/archx/token/cat?w=160')).json();
  assert.equal((await redeemToken(retiredBase, retiredOldToken)).status, 403,
    'removing the old key completes retirement after the rollover window');
  assert.equal(rotatedHandler.configAudit.summary.activeSecretId, '2026-02');
  assert.equal(rotatedHandler.configAudit.summary.signingKeyCount, 2);
  assert.equal(JSON.stringify(rotatedHandler.configAudit).includes(oldSecret), false);
  assert.equal(JSON.stringify(rotatedHandler.configAudit).includes(newSecret), false);
});

test('multi-instance configuration and state-store failures fail closed with structured events', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-state-failure-'));
  fs.writeFileSync(path.join(dir, 'cat.jpg'), await syntheticMaster());

  const missingStore = auditArchxServerConfig({
    secret: TEST_SECRET, imagesDir: dir, allowAnonymous: true, deploymentMode: 'multi-instance',
  });
  assert.equal(missingStore.ok, false);
  assert.ok(missingStore.issues.some((issue) => /stateStore/i.test(issue)));

  const memoryStore = createMemoryStateStore();
  const memoryAudit = auditArchxServerConfig({
    secret: TEST_SECRET, imagesDir: dir, allowAnonymous: true,
    deploymentMode: 'multi-instance', stateStore: memoryStore,
  });
  assert.equal(memoryAudit.ok, false, 'a process-local store must not masquerade as shared infrastructure');
  memoryStore.close();

  const events = [];
  const failingStore = Object.freeze({
    kind: 'failing-test-store',
    claimOnce: async () => { throw new Error('backend down'); },
    hitWindow: async () => { throw new Error('backend down'); },
    trackDistinct: async () => { throw new Error('backend down'); },
  });
  const handler = createArchxMiddleware({
    secret: TEST_SECRET,
    imagesDir: dir,
    allowAnonymous: true,
    deploymentMode: 'multi-instance',
    stateStore: failingStore,
    stateStoreTimeoutMs: 25,
    onSecurityEvent: (event) => events.push(event),
  });
  const base = await listenForTest(t, handler);
  assert.equal((await postToken(base + '/archx/token/cat?w=160')).status, 503);
  const failure = events.find((event) => event.reason === 'state-store-unavailable');
  assert.equal(failure.schemaVersion, 1);
  assert.equal(failure.severity, 'error');
  assert.equal(failure.outcome, 'error');
  assert.equal(failure.request.method, 'POST');
});

test('hardened production defaults and production audit expose unsafe combinations without secrets', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-production-audit-'));
  fs.writeFileSync(path.join(dir, 'cat.jpg'), await syntheticMaster());
  const authorize = async () => ({ viewerId: 'viewer-1' });
  const hardened = withHardenedProductionDefaults({
    secret: TEST_SECRET,
    imagesDir: dir,
    authorize,
    steganography: true,
    onStegoIssue: async () => {},
  });
  assert.equal(hardened.allowQueryTokens, false);
  assert.equal(hardened.proofOfPossession, 'required');
  assert.equal(hardened.oneTimeTokens, true);
  assert.equal(hardened.abuseDetection.action, 'deny');
  assert.equal(withHardenedProductionDefaults({ allowQueryTokens: true }).allowQueryTokens, true,
    'explicit host compatibility choices are preserved for audit rather than silently rewritten');

  const unsafe = auditArchxProductionConfig({
    secret: TEST_SECRET,
    imagesDir: dir,
    allowAnonymous: true,
    allowQueryTokens: true,
    proofOfPossession: 'off',
    oneTimeTokens: false,
    tokenMethods: ['GET', 'POST'],
    steganography: true,
  }, { expectedInstances: 3 });
  assert.equal(unsafe.ok, true, 'the configuration is internally valid even though it is not production-ready');
  assert.equal(unsafe.ready, false);
  assert.ok(unsafe.blockers.some((issue) => /allowQueryTokens/i.test(issue)));
  assert.ok(unsafe.blockers.some((issue) => /proofOfPossession/i.test(issue)));
  assert.ok(unsafe.blockers.some((issue) => /expectedInstances > 1/i.test(issue)));
  assert.ok(unsafe.blockers.some((issue) => /onStegoIssue/i.test(issue)));
  assert.ok(unsafe.recommendations.some((issue) => /does not block/i.test(issue)));
  assert.equal(JSON.stringify(unsafe).includes(TEST_SECRET), false);

  const sharedStore = Object.freeze({
    kind: 'shared-production-test',
    claimOnce: async () => true,
    hitWindow: async () => ({ limited: false, retryAfterSec: 0, count: 1 }),
    trackDistinct: async () => ({ distinct: 1, isNew: true }),
  });
  const ready = auditArchxProductionConfig(withHardenedProductionDefaults({
    secret: TEST_SECRET,
    imagesDir: dir,
    authorize,
    steganography: { profile: 'robust' },
    onStegoIssue: async () => {},
    onSecurityEvent: () => {},
    quotas: { perViewer: 25 },
    deploymentMode: 'multi-instance',
    stateStore: sharedStore,
  }), { expectedInstances: 3 });
  assert.equal(ready.ready, true, JSON.stringify(ready.blockers));
  assert.equal(ready.summary.allowQueryTokens, false);
  assert.equal(ready.summary.stateStore, 'shared-production-test');

  const traced = normalizeAuthorizationResult({
    viewerId: 'viewer-1', buyerId: 42, orderId: 'ORDER-42', deliveryId: 'D-1', traceId: 'TRACE-1',
  });
  assert.equal(traced.buyerId, '42');
  assert.equal(traced.orderId, 'ORDER-42');
  assert.equal(normalizeAuthorizationResult({ viewerId: 'v', orderId: { id: 1 } }), null);
});

test('buyer/order authorization drives signed caps, robust Stego registry, provenance, and key-free delivery hooks', async (t) => {
  const stegoRecords = [];
  const provenanceRecords = [];
  const deliveryEvents = [];
  const securityEvents = [];
  const { base } = await startArchxFixture(t, {
    encrypt: true,
    serverWatermark: 'BUYER {buyer} ORDER {order}',
    steganography: { perToken: true, profile: 'robust', strength: 6 },
    onStegoIssue: async (record) => { stegoRecords.push(record); },
    onProvenanceIssue: async (record) => { provenanceRecords.push(record); },
    onDelivery: (event) => { deliveryEvents.push(event); },
    onSecurityEvent: (event) => { securityEvents.push(event); },
    authorize: async () => ({
      viewerId: 'viewer-42',
      buyerId: 'buyer-42',
      orderId: 'ORDER-42',
      deliveryId: 'DELIVERY-42',
      traceId: 'TRACE-42',
      maxWidth: 220,
      quality: 42,
      format: 'jpeg',
    }),
  }, { cat: [640, 420] });

  const tokenRes = await postToken(base + '/archx/token/cat?w=4000&q=100');
  assert.equal(tokenRes.status, 200);
  const token = await tokenRes.json();
  const claims = tokenPayloadForTest(token.token);
  assert.equal(claims.w, 220, 'tampered client width cannot widen the server entitlement');
  assert.equal(claims.q, 42, 'tampered client quality cannot widen the server entitlement');
  assert.equal(claims.fmt, 'jpeg');
  assert.equal(claims.sgv, 2, 'robust Stego profile is signed into the token');
  assert.match(claims.th, /^[A-Za-z0-9_-]{20}$/);
  assert.equal(token.url, token.cleanUrl);
  assert.equal(token.url.includes('?t='), false);

  assert.equal(stegoRecords.length, 1);
  assert.equal(stegoRecords[0].buyerId, 'buyer-42');
  assert.equal(stegoRecords[0].orderId, 'ORDER-42');
  assert.equal(stegoRecords[0].deliveryId, 'DELIVERY-42');
  assert.equal(stegoRecords[0].traceId, 'TRACE-42');
  assert.equal(stegoRecords[0].profile, 'robust');
  assert.match(stegoRecords[0].fingerprint, /^[0-9a-f]{12}$/);
  assert.equal(provenanceRecords.length, 1);
  assert.equal(provenanceRecords[0].stegoFingerprint, stegoRecords[0].fingerprint);
  assert.equal(provenanceRecords[0].traceHash, claims.th);

  assert.equal((await fetch(`${base}${token.cleanUrl}?t=${token.token}`)).status, 403,
    'query transport is rejected by default and does not spend the token');
  const imageRes = await redeemToken(base, token);
  assert.equal(imageRes.status, 200);
  const bytes = new Uint8Array(await imageRes.arrayBuffer());
  const { header } = decodeContainer(bytes);
  assert.equal(header.w, 220);
  assert.equal(header.mime, 'image/jpeg');
  assert.equal(header.sg, 1);
  assert.equal(header.wm, 1);
  assert.equal(header.encrypted, true);

  const stripRequest = (record) => {
    const { req, ...safe } = record;
    return safe;
  };
  const hookMaterial = JSON.stringify({
    stego: stegoRecords.map(stripRequest),
    provenance: provenanceRecords.map(stripRequest),
    delivery: deliveryEvents,
    security: securityEvents,
  });
  for (const secretMaterial of [TEST_SECRET, token.token, token.key, token.aesKey]) {
    assert.equal(hookMaterial.includes(secretMaterial), false, 'hooks/events must never receive token or key material');
  }
  assert.deepEqual(deliveryEvents.map((event) => event.type), ['archx.token_issued', 'archx.image_delivered']);
  assert.equal(deliveryEvents[1].stegoProfile, 'robust');
  assert.equal(deliveryEvents[1].traceHash, claims.th);
});

test('provenance hook failure denies issuance by default and emits a structured event', async (t) => {
  const events = [];
  const { base } = await startArchxFixture(t, {
    allowAnonymous: true,
    onProvenanceIssue: async () => { throw new Error('registry unavailable'); },
    onSecurityEvent: (event) => { events.push(event); },
  });
  assert.equal((await postToken(base + '/archx/token/cat?w=160')).status, 503);
  assert.ok(events.some((event) => event.type === 'archx.provenance_failed'));
});

test('robust StegoMark profile survives direct, resized/JPEG, edited, and center-cropped copies', async () => {
  const master = await syntheticMaster(640, 420);
  const { data, info } = await sharp(master).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const raw = new Uint8Array(data);
  const marked = embedStegoFingerprint(raw, info.width, info.height, 'ORDER-ROBUST', {
    key: 'owner-key', profile: 'robust',
  });
  const expected = stegoFingerprint('ORDER-ROBUST');

  const direct = detectStegoFingerprint(marked, info.width, info.height, { key: 'owner-key', profile: 'robust' });
  assert.equal(direct.found, true, JSON.stringify(direct));
  assert.equal(direct.fingerprint, expected);
  assert.equal(direct.profile, 'robust');

  const detectBytes = async (bytes, options = {}) => {
    const decoded = await sharp(bytes).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
    return detectStegoFingerprint(new Uint8Array(decoded.data), decoded.info.width, decoded.info.height, {
      key: 'owner-key', profile: 'auto', searchOffsets: true, ...options,
    });
  };
  const rawInput = { raw: { width: info.width, height: info.height, channels: 4 } };
  const resized = await sharp(Buffer.from(marked), rawInput).resize({ width: 448 }).jpeg({ quality: 82 }).toBuffer();
  const resizedFound = await detectBytes(resized);
  assert.equal(resizedFound.found, true, JSON.stringify(resizedFound));
  assert.equal(resizedFound.fingerprint, expected);
  assert.equal(resizedFound.profile, 'robust');

  const edited = await sharp(Buffer.from(marked), rawInput)
    .modulate({ brightness: 1.05, saturation: 1.1 }).blur(0.4).jpeg({ quality: 80 }).toBuffer();
  const editedFound = await detectBytes(edited);
  assert.equal(editedFound.found, true, JSON.stringify(editedFound));
  assert.equal(editedFound.fingerprint, expected);

  // Crop recovery is asserted on photographic content (the catalog use case),
  // rather than the flat SVG fixture whose hard edges deliberately stress
  // cell voting. The same 90% center-crop + resize + JPEG path is used.
  const photoBytes = fs.readFileSync(new URL('../demo-masters/aurora-valley.jpg', import.meta.url));
  const photoRaw = await sharp(photoBytes).resize(640, 420, { fit: 'fill' }).ensureAlpha().raw()
    .toBuffer({ resolveWithObject: true });
  const photoMarked = embedStegoFingerprint(new Uint8Array(photoRaw.data), 640, 420, 'ORDER-ROBUST', {
    key: 'owner-key', profile: 'robust',
  });
  const cropped = await sharp(Buffer.from(photoMarked), rawInput)
    .extract({ left: 32, top: 21, width: 576, height: 378 }).resize(640, 420).jpeg({ quality: 85 }).toBuffer();
  const croppedFound = await detectBytes(cropped, { profile: 'robust', searchGeometry: true });
  assert.equal(croppedFound.found, true, JSON.stringify(croppedFound));
  assert.equal(croppedFound.fingerprint, expected);
  assert.ok(croppedFound.observedBits >= 88);

  assert.equal(detectStegoFingerprint(raw, info.width, info.height, {
    key: 'owner-key', profile: 'robust',
  }).found, false, 'unmarked control must not become a confident robust attribution');
});

test('Redis state-store adapter uses atomic client operations and preserves the middleware contract', async () => {
  const calls = [];
  const values = new Map();
  const client = {
    defineCommand() {},
    async set(key, value, px, ttl, nx) {
      calls.push(['set', key, value, px, ttl, nx || null]);
      if (nx === 'NX' && values.has(key)) return null;
      values.set(key, Buffer.isBuffer(value) ? value : Buffer.from(String(value)));
      return 'OK';
    },
    async getBuffer(key) {
      calls.push(['getBuffer', key]);
      return values.get(key) || null;
    },
    async eval(script, numKeys, key, ...args) {
      calls.push(['eval', key, numKeys, args.map(String), script === REDIS_STATE_STORE_SCRIPTS.hitWindow ? 'window' : 'distinct']);
      if (script === REDIS_STATE_STORE_SCRIPTS.hitWindow) {
        const count = Number(values.get(key)?.toString() || 0) + 1;
        values.set(key, Buffer.from(String(count)));
        return count > Number(args[2]) ? [1, 7, count - 1] : [0, 0, count];
      }
      const member = String(args[0]);
      const members = new Set(JSON.parse(values.get(key)?.toString() || '[]'));
      const isNew = members.has(member) ? 0 : 1;
      members.add(member);
      values.set(key, Buffer.from(JSON.stringify([...members])));
      return [members.size, isNew];
    },
  };
  const store = createRedisStateStore({ client, prefix: 'archx:test:', clientFlavor: 'ioredis' });
  assert.equal(store.kind, 'redis');
  assert.equal(await store.claimOnce('nonce:abc', 1000), true);
  assert.equal(await store.claimOnce('nonce:abc', 1000), false);
  assert.equal(await store.claimOnce('nonce:bad', 0), false);
  assert.deepEqual(await store.hitWindow('rate:ip', { limit: 1, windowMs: 60000, now: 1000 }),
    { limited: false, retryAfterSec: 0, count: 1 });
  assert.deepEqual(await store.hitWindow('rate:ip', { limit: 1, windowMs: 60000, now: 1001 }),
    { limited: true, retryAfterSec: 7, count: 1 });
  assert.deepEqual(await store.trackDistinct('abuse:viewer', 'cat', { now: 1000 }),
    { distinct: 1, isNew: true });
  assert.deepEqual(await store.trackDistinct('abuse:viewer', 'cat', { now: 1001 }),
    { distinct: 1, isNew: false });
  assert.equal(await store.setCache('cache:item', Buffer.from([1, 2, 3]), { ttlMs: 5000 }), true);
  assert.deepEqual([...await store.getCache('cache:item')], [1, 2, 3]);
  assert.ok(calls.every((call) => String(call[1]).startsWith('archx:test:')));
  assert.ok(calls.some((call) => call[0] === 'set' && call[3] === 'PX' && call[5] === 'NX'));
  assert.ok(calls.some((call) => call[0] === 'eval' && call[4] === 'window'));
  assert.ok(calls.some((call) => call[0] === 'eval' && call[4] === 'distinct'));
  assert.throws(() => createRedisStateStore({ client: {}, prefix: 'x' }), /eval|call|sendCommand/);
});

test('catalog scale helpers canonicalize widths and expose throughput trade-offs', () => {
  assert.deepEqual(DEFAULT_SOURCE_WIDTH_BUCKETS, DEFAULT_WIDTH_BUCKETS);
  assert.equal(canonicalDerivativeWidth(641, 1920), 800);
  assert.equal(canonicalDerivativeWidth(100, 500), 160);
  assert.equal(canonicalDerivativeWidth(1200, 1100), 960);
  assert.equal(canonicalDerivativeWidth(2000, 180), 160, 'canonicalization never exceeds the entitlement cap');
  assert.equal(canonicalDerivativeWidth(2000, 32), 32, 'even a sub-bucket cap remains a hard cap');
  assert.equal(canonicalDerivativeWidth(333, 1920, []), 333, 'empty bucket list preserves exact widths');

  const base = {
    secret: 'catalog-throughput-secret-for-unit-tests-32',
    imagesDir: '/tmp/archx-catalog-images',
    authorize: async () => true,
    forensic: true,
    steganography: true,
  };
  const catalog = withCatalogThroughputDefaults(base);
  assert.equal(catalog.quality, 88);
  assert.deepEqual(catalog.widthBuckets, DEFAULT_WIDTH_BUCKETS);
  assert.equal(catalog.forensicScope, 'image');
  assert.deepEqual(catalog.steganography, { perToken: false, scope: 'image' });
  assert.equal(catalog.processing.webpEffort, 2);
  assert.equal(catalog.processing.webpSmartSubsample, false);
  assert.equal(catalog.processing.resizeKernel, 'lanczos2');
  assert.equal(catalog.processing.sharpConcurrency, 1);
  const summary = auditArchxServerConfig(catalog).summary;
  assert.deepEqual(summary.widthBuckets, DEFAULT_WIDTH_BUCKETS);
  assert.equal(summary.batchTokenMaxItems, 100);
  assert.equal(summary.diskOutputCache, false);
  assert.equal(PRESETS.catalog.qualityProfile, 'catalog');
  assert.equal(PRESETS.catalog.tokenBatch, true);
  assert.equal(PRESETS.gallery.sourceOversample, 1);

  for (const bad of [
    { widthBuckets: [63] },
    { forensicScope: 'session' },
    { batchTokenMaxItems: 501 },
    { outputCacheDiskMaxEntries: -1 },
    { processing: { webpEffort: 7 } },
    { processing: { resizeKernel: 'nearest-neighbor' } },
  ]) {
    assert.equal(auditArchxServerConfig({ ...base, ...bad }).ok, false, JSON.stringify(bad));
  }
});

test('catalog HTTP path: canonical widths, batch minting, and persistent cross-viewer derivative reuse', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-catalog-http-'));
  const mastersDir = path.join(root, 'masters');
  const cacheDir = path.join(root, 'derivative-cache');
  fs.mkdirSync(mastersDir);
  const master = await syntheticMaster(640, 420);
  fs.writeFileSync(path.join(mastersDir, 'cat.jpg'), master);
  const stegoIssues = [];
  const makeHandler = () => createArchxMiddleware({
    secret: 'catalog-http-secret-for-unit-tests-32chars',
    imagesDir: mastersDir,
    ttlSec: 120,
    quality: 88,
    widthBuckets: [160, 320, 640],
    outputCacheMax: 0,
    outputCacheMaxBytes: 0,
    outputCacheDir: cacheDir,
    forensic: true,
    forensicPerToken: false,
    forensicScope: 'image',
    steganography: { scope: 'image', perToken: false, strength: 6 },
    onStegoIssue: async (record) => { stegoIssues.push(record); },
    processing: {
      webpEffort: 0,
      webpSmartSubsample: false,
      resizeKernel: 'lanczos2',
      sharpConcurrency: 1,
    },
    authorize: async (req) => ({ viewerId: String(req.headers['x-viewer'] || 'viewer-a') }),
  });
  const start = async (handler) => {
    const server = http.createServer((req, res) => handler(req, res));
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    return { server, base: `http://127.0.0.1:${server.address().port}` };
  };

  let handler = makeHandler();
  let running = await start(handler);
  t.after(async () => {
    await new Promise((resolve) => running.server.close(resolve));
    handler.close();
  });
  const redeemAs = (base, tokenResponse, viewer) => redeemToken(base, tokenResponse, {
    headers: { 'x-viewer': viewer },
  });

  const tokenA = await (await postToken(running.base + '/archx/token/cat?w=300', {
    headers: { 'x-viewer': 'viewer-a' },
  })).json();
  const responseA = await redeemAs(running.base, tokenA, 'viewer-a');
  assert.equal(responseA.status, 200);
  const bytesA = new Uint8Array(await responseA.arrayBuffer());
  assert.equal(decodeContainer(bytesA).header.w, 320, '300px request uses the canonical 320px derivative');
  let stats = handler.stats();
  assert.equal(stats.derivativeCache.misses, 1);
  assert.equal(stats.derivativeCache.diskWrites, 1);
  assert.equal(stats.outputCacheEntries, 0, 'memory cache is disabled so reuse must come from disk');

  const tokenB = await (await postToken(running.base + '/archx/token/cat?w=301', {
    headers: { 'x-viewer': 'viewer-b' },
  })).json();
  const responseB = await redeemAs(running.base, tokenB, 'viewer-b');
  assert.equal(responseB.status, 200);
  const bytesB = new Uint8Array(await responseB.arrayBuffer());
  assert.deepEqual(bytesB, bytesA, 'image-scoped marks make the catalog derivative byte-identical across viewers');
  stats = handler.stats();
  assert.equal(stats.derivativeCache.diskHits, 1);
  assert.equal(stats.derivativeCache.misses, 1, 'second viewer does not pay another Sharp transform');
  assert.equal(new Set(stegoIssues.map((record) => record.fingerprint)).size, 1);

  const batchRes = await fetch(running.base + '/archx/tokens', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-archx-request': 'token',
      'x-viewer': 'viewer-batch',
    },
    body: JSON.stringify({
      items: [
        { ref: 'hero', id: 'cat', w: 319 },
        { ref: 'missing', id: 'nope', w: 320 },
      ],
    }),
  });
  assert.equal(batchRes.status, 200);
  const batch = await batchRes.json();
  assert.ok(batch.tokens.hero.token, 'batch returns an ordinary one-time token per authorized item');
  assert.equal(batch.errors.missing.status, 404);
  const batchImage = await redeemAs(running.base, batch.tokens.hero, 'viewer-batch');
  assert.equal(batchImage.status, 200);
  assert.deepEqual(new Uint8Array(await batchImage.arrayBuffer()), bytesA);
  assert.equal(handler.stats().derivativeCache.diskHits, 2);

  await new Promise((resolve) => running.server.close(resolve));
  handler.close();
  handler = makeHandler();
  running = await start(handler);
  const tokenC = await (await postToken(running.base + '/archx/token/cat?w=319', {
    headers: { 'x-viewer': 'viewer-c' },
  })).json();
  const responseC = await redeemAs(running.base, tokenC, 'viewer-c');
  assert.equal(responseC.status, 200);
  assert.deepEqual(new Uint8Array(await responseC.arrayBuffer()), bytesA);
  stats = handler.stats();
  assert.equal(stats.derivativeCache.diskHits, 1, 'a restarted process reuses the persistent derivative');
  assert.equal(stats.derivativeCache.misses, 0);
});

test('cold derivative stampede: concurrent redemptions coalesce into one Sharp transform', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-stampede-'));
  const mastersDir = path.join(root, 'masters');
  fs.mkdirSync(mastersDir);
  fs.writeFileSync(path.join(mastersDir, 'cat.jpg'), await syntheticMaster(640, 420));
  const handler = createArchxMiddleware({
    secret: 'stampede-secret-for-unit-tests-32chars!',
    imagesDir: mastersDir,
    ttlSec: 120,
    quality: 88,
    widthBuckets: [160, 320, 640],
    // Full-effort WebP keeps the leader busy long enough that the whole
    // herd provably arrives while the first transform is still in flight.
    processing: { webpEffort: 4, webpSmartSubsample: true, resizeKernel: 'lanczos3', sharpConcurrency: 1 },
    authorize: async () => true,
  });
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    handler.close();
  });
  const base = `http://127.0.0.1:${server.address().port}`;

  // Eight distinct one-time tokens that all canonicalize to the same 320px derivative.
  const batchRes = await fetch(base + '/archx/tokens', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-archx-request': 'token' },
    body: JSON.stringify({
      items: Array.from({ length: 8 }, (_, i) => ({ ref: `r${i}`, id: 'cat', w: 300 + i })),
    }),
  });
  assert.equal(batchRes.status, 200);
  const batch = await batchRes.json();
  const tokenResponses = Object.values(batch.tokens);
  assert.equal(tokenResponses.length, 8);

  const responses = await Promise.all(tokenResponses.map((tokenResponse) => redeemToken(base, tokenResponse)));
  const payloads = [];
  for (const response of responses) {
    assert.equal(response.status, 200);
    payloads.push(new Uint8Array(await response.arrayBuffer()));
  }
  for (const payload of payloads) assert.deepEqual(payload, payloads[0]);

  const cache = handler.stats().derivativeCache;
  assert.equal(cache.misses, 1, 'an eight-way stampede runs exactly one cold transform');
  assert.equal(
    cache.coalesced + cache.memoryHits, 7,
    'every other request joined the in-flight derivative or the just-filled cache',
  );
  assert.ok(cache.coalesced >= 1, 'waiters are reported as coalesced, not hidden inside misses');
});

test('taint image endpoint: public constant pixel, no CORS, method-bounded, disableable', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-taint-'));
  const mastersDir = path.join(root, 'masters');
  fs.mkdirSync(mastersDir);
  fs.writeFileSync(path.join(mastersDir, 'cat.jpg'), await syntheticMaster(64, 48));
  const startWith = async (extra) => {
    const handler = createArchxMiddleware({
      secret: 'taint-endpoint-secret-for-unit-tests-32',
      imagesDir: mastersDir,
      authorize: async () => true,
      ...extra,
    });
    const server = http.createServer((req, res) => handler(req, res));
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    return { handler, server, base: `http://127.0.0.1:${server.address().port}` };
  };
  let running = await startWith({});
  t.after(async () => {
    await new Promise((resolve) => running.server.close(resolve));
    running.handler.close();
  });

  const res = await fetch(running.base + '/archx/taint.png');
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'image/png');
  assert.equal(res.headers.get('access-control-allow-origin'), null,
    'no CORS headers: a CORS-approved load would stay origin-clean and not taint');
  assert.match(res.headers.get('cache-control') || '', /immutable/);
  const png = new Uint8Array(await res.arrayBuffer());
  assert.ok(png.length > 0 && png.length < 256);
  assert.deepEqual([...png.slice(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
    'real PNG signature');

  const head = await fetch(running.base + '/archx/taint.png', { method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal((await head.arrayBuffer()).byteLength, 0);

  const post = await fetch(running.base + '/archx/taint.png', { method: 'POST' });
  assert.equal(post.status, 405);

  await new Promise((resolve) => running.server.close(resolve));
  running.handler.close();
  running = await startWith({ taintImage: false });
  const disabled = await fetch(running.base + '/archx/taint.png');
  assert.equal(disabled.status, 404, 'taintImage:false removes the public route');
});

test('poisoned disk derivative cache entries are rejected and regenerated', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-cache-poison-'));
  const mastersDir = path.join(root, 'masters');
  const cacheDir = path.join(root, 'derivative-cache');
  fs.mkdirSync(mastersDir);
  fs.writeFileSync(path.join(mastersDir, 'cat.jpg'), await syntheticMaster(640, 420));
  const makeHandler = () => createArchxMiddleware({
    secret: 'cache-poison-secret-for-unit-tests-32ch',
    imagesDir: mastersDir,
    ttlSec: 120,
    quality: 88,
    outputCacheDir: cacheDir,
    processing: { webpEffort: 0, webpSmartSubsample: false, resizeKernel: 'lanczos2', sharpConcurrency: 1 },
    authorize: async () => true,
  });
  const start = async (handler) => {
    const server = http.createServer((req, res) => handler(req, res));
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    return { server, base: `http://127.0.0.1:${server.address().port}` };
  };
  let handler = makeHandler();
  let running = await start(handler);
  t.after(async () => {
    await new Promise((resolve) => running.server.close(resolve));
    handler.close();
  });
  const redeemFresh = async (base) => {
    const token = await (await postToken(base + '/archx/token/cat?w=320')).json();
    const response = await redeemToken(base, token);
    assert.equal(response.status, 200);
    return new Uint8Array(await response.arrayBuffer());
  };

  const original = await redeemFresh(running.base);
  assert.ok(isArchxContainer(original));
  await new Promise((resolve) => running.server.close(resolve));
  handler.close();

  const cacheFiles = [];
  (function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.archx-cache')) cacheFiles.push(full);
    }
  })(cacheDir);
  assert.equal(cacheFiles.length, 1);
  fs.writeFileSync(cacheFiles[0], Buffer.alloc(original.length, 0x41));

  handler = makeHandler();
  running = await start(handler);
  const regenerated = await redeemFresh(running.base);
  assert.deepEqual(regenerated, original,
    'poisoned cache bytes are never served; the derivative is regenerated');
  const cache = handler.stats().derivativeCache;
  assert.equal(cache.diskHits, 0);
  assert.equal(cache.misses, 1);
  assert.ok(cache.diskErrors >= 1, 'the invalid entry is counted and evicted');
});

test('batch minting accepts framework string/Buffer bodies with the same strict parsing', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-batch-body-'));
  const mastersDir = path.join(root, 'masters');
  fs.mkdirSync(mastersDir);
  fs.writeFileSync(path.join(mastersDir, 'cat.jpg'), await syntheticMaster(320, 240));
  const handler = createArchxMiddleware({
    secret: 'batch-body-secret-for-unit-tests-32chars',
    imagesDir: mastersDir,
    authorize: async () => true,
  });
  const invoke = (body) => new Promise((resolvePromise, rejectPromise) => {
    const req = {
      method: 'POST',
      url: '/archx/tokens',
      headers: { 'content-type': 'application/json', 'x-archx-request': 'token', host: 'unit.test' },
      body,
      socket: { remoteAddress: '127.0.0.1' },
    };
    const res = {
      statusCode: 0,
      headers: {},
      writeHead(status, headers) {
        this.statusCode = status;
        Object.assign(this.headers, headers);
        return this;
      },
      end(payload) {
        resolvePromise({
          status: this.statusCode,
          body: payload ? JSON.parse(String(payload)) : null,
        });
      },
    };
    Promise.resolve(handler(req, res)).catch(rejectPromise);
  });

  const payload = JSON.stringify({ items: [{ ref: 'a', id: 'cat', w: 160 }] });
  for (const body of [payload, Buffer.from(payload, 'utf8'), new TextEncoder().encode(payload)]) {
    const out = await invoke(body);
    assert.equal(out.status, 200);
    assert.ok(out.body.tokens.a.token, 'string, Buffer, and Uint8Array bodies all mint');
  }
  const malformed = await invoke('{not json');
  assert.equal(malformed.status, 400, 'malformed pre-parsed bodies still fail closed');
  handler.close();
});

test('precomputed asset builder is incremental, canonical, and emits a usable manifest', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-build-assets-'));
  const mastersDir = path.join(root, 'masters');
  const outputDir = path.join(root, 'protected');
  fs.mkdirSync(mastersDir);
  const cat = await syntheticMaster(640, 420);
  const dog = await syntheticMaster(480, 320);
  fs.writeFileSync(path.join(mastersDir, 'cat.png'), cat);
  fs.writeFileSync(path.join(mastersDir, 'dog.png'), dog);
  assert.deepEqual(await inspectImageMetadata(cat), {
    format: 'png', width: 640, height: 420, orientation: 1,
    hasAlpha: true, channels: 4, pages: 1,
  });

  const buildOptions = {
    inputDir: mastersDir,
    outputDir,
    baseUrl: '/protected/',
    widths: [160, 320],
    maxWidth: 320,
    key: 'build-test-key',
    quality: 82,
    jobs: 2,
    processing: { webpEffort: 0, webpSmartSubsample: false, resizeKernel: 'lanczos2', sharpConcurrency: 1 },
  };
  await assert.rejects(buildArchxAssets({ ...buildOptions, key: '' }), /key must be a non-empty string/);
  const first = await buildArchxAssets(buildOptions);
  assert.equal(first.assets, 2);
  assert.equal(first.variants, 4);
  assert.equal(first.generated, 4);
  assert.equal(first.skipped, 0);
  const manifestBytes = fs.readFileSync(first.manifestPath);
  assert.equal(
    first.manifestSha256,
    crypto.createHash('sha256').update(manifestBytes).digest('hex'),
    'build summary reports the exact manifest digest browsers can pin',
  );
  const manifest = JSON.parse(manifestBytes.toString('utf8'));
  assert.deepEqual(Object.keys(manifest.assets).sort(), ['cat', 'dog']);
  assert.equal(manifest.assets.cat.key, 'build-test-key');
  assert.deepEqual(manifest.assets.cat.variants.map((variant) => variant.width), [160, 320]);
  assert.ok(manifest.assets.cat.variants.every((variant) => variant.url.startsWith('/protected/cat-')));
  for (const asset of Object.values(manifest.assets)) {
    for (const variant of asset.variants) {
      const file = path.join(outputDir, decodeURIComponent(path.basename(variant.url)));
      const variantBytes = fs.readFileSync(file);
      assert.ok(isArchxContainer(variantBytes), file);
      assert.equal(
        variant.sha256,
        crypto.createHash('sha256').update(variantBytes).digest('hex'),
        'manifest records a verifiable digest for every variant',
      );
    }
  }
  const catVariant = manifest.assets.cat.variants[1];
  const catBytes = fs.readFileSync(path.join(outputDir, decodeURIComponent(path.basename(catVariant.url))));
  const decoded = decodeContainer(catBytes);
  const restored = await unscrambleImage(Buffer.from(decoded.payload), {
    grid: decoded.header.grid,
    key: manifest.assets.cat.key,
    w: decoded.header.w,
    h: decoded.header.h,
  });
  assert.ok((await meanAbsDiff(cat, restored, 160, 105)) < 22);

  const second = await buildArchxAssets(buildOptions);
  assert.equal(second.generated, 0, 'unchanged masters/options reuse every variant');
  assert.equal(second.skipped, 4);

  const tamperedPath = path.join(outputDir, decodeURIComponent(path.basename(catVariant.url)));
  const tampered = fs.readFileSync(tamperedPath);
  tampered[tampered.length - 1] ^= 0xff;
  fs.writeFileSync(tamperedPath, tampered);
  const repaired = await buildArchxAssets(buildOptions);
  assert.equal(repaired.generated, 1, 'a same-size hash mismatch regenerates only the damaged variant');
  assert.equal(repaired.skipped, 3);

  const narrowed = await buildArchxAssets({ ...buildOptions, widths: [160], maxWidth: 160 });
  assert.equal(narrowed.variants, 2);
  assert.ok(narrowed.removed >= 2, 'stale versioned variants are cleaned from prior state');
});

test('StegoMark in-place server path is byte-identical to the copying public path', async () => {
  const master = await syntheticMaster(256, 192);
  const { data, info } = await sharp(master).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const original = new Uint8Array(data);
  for (const profile of ['standard', 'robust']) {
    const copied = embedStegoFingerprint(original, info.width, info.height, 'INPLACE', { key: 'k', profile });
    const inPlaceInput = new Uint8Array(original);
    const inPlace = embedStegoFingerprint(inPlaceInput, info.width, info.height, 'INPLACE', {
      key: 'k', profile, inPlace: true,
    });
    assert.equal(inPlace, inPlaceInput);
    assert.deepEqual(inPlace, copied, `${profile} profile must be byte-identical in-place`);
  }
  assert.deepEqual(original, new Uint8Array(data), 'default public path still does not mutate its input');
});
