import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawnSync, execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import sharp from 'sharp';
import {
  buildScramblePlan, scramblePixels, scramblePixelsPadded, paddedSize,
  encodeContainer, decodeContainer, isArchxContainer,
  encryptPayload, decryptPayload, generateKeyBase64,
  applyForensicBlocks, forensicScore, forensicBlockSigns,
  embedStegoFingerprint, detectStegoFingerprint, stegoFingerprint, assayStegoCollusion, assayStegoEmbed,
  sha256Bytes, hmacSha256Bytes,
  sniffImageInfo, decodeBmpImage, base64ToBytes,
  perceptualFingerprint, perceptualFingerprintDistance, comparePerceptualFingerprints,
} from '../src/scramble.js';
// (decryptPayload used by the AES .archx test below)
import { inspectImageMetadata, scrambleImage, unscrambleImage, prepareDerivativeBase, finishDerivative, configureSharpSecurity } from '../server/scramble-image.js';
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
  detectStegoFingerprintInWorker, closeStegoDetectWorker,
  batchDetectStegoInWorker, configureStegoDetectWorker,
  generateOwnershipKeyPair, verifyOwnershipClaim, extractOwnershipClaim, verifyOwnership,
  embedOwnershipMetadata, createIssuanceLog, verifyIssuanceChain,
} from '../server/middleware.js';
import { createRedisStateStore, REDIS_STATE_STORE_SCRIPTS } from '../server/redis-state-store.js';
import { bchEncode64, bchDecode188, bchSolveObserved, bchOsdSolve, bchIsdSolve, BCH_CODE_BITS } from '../src/core/bch.js';
import { bchStegoCodeBits, bchStegoDecode, bchStegoSolveObserved } from '../src/core/stego-code.js';
import * as archxServerModule from '../server/middleware.js';

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

test('scramble plan v2 (128-bit seed) is deterministic, distinct from v1, and round-trips', () => {
  const v1 = buildScramblePlan(8, 'correct horse battery staple', 1); // explicit legacy pin (default is v2 since 1.17)
  const v2 = buildScramblePlan(8, 'correct horse battery staple', 2);
  const v2Again = buildScramblePlan(8, 'correct horse battery staple', 2);
  assert.equal(v1.version, 1);
  assert.equal(v2.version, 2);
  assert.deepEqual(v2.order, v2Again.order);
  assert.deepEqual(v2.flips, v2Again.flips);
  assert.notDeepEqual(v2.order, v1.order, 'v2 must not reproduce the 32-bit-seed permutation');
  assert.deepEqual([...v2.order].sort((a, b) => a - b), Array.from({ length: 64 }, (_, i) => i));
  v2.order.forEach((orig, pos) => assert.equal(v2.inverse[orig], pos));
  assert.throws(() => buildScramblePlan(8, 'k', 3), /plan version/);
  // round-trip through the fused padded path at an awkward size
  const w = 61, h = 47;
  const raw = new Uint8Array(w * h * 4);
  for (let i = 0; i < raw.length; i++) raw[i] = (i * 2654435761) % 256;
  const { pw, ph } = paddedSize(w, h, 8);
  const scrambled = scramblePixelsPadded(raw, w, h, v2);
  const restoredPadded = scramblePixels(scrambled, pw, ph, v2, 'unscramble');
  for (let y = 0; y < h; y++) {
    assert.deepEqual(
      restoredPadded.subarray(y * pw * 4, (y * pw + w) * 4),
      raw.subarray(y * w * 4, (y + 1) * w * 4));
  }
  // container header carries pv only for v2 and validation enforces the enum
  const header = { v: 1, w, h, pw, ph, grid: 8, mime: 'image/webp', scrambled: true, encrypted: false, pv: 2 };
  assert.equal(decodeContainer(encodeContainer(header, new Uint8Array([1, 2, 3]))).header.pv, 2);
  assert.throws(() => encodeContainer({ ...header, pv: 9 }, new Uint8Array([1])), /plan version/);
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

test('fused pad+scramble round-trips exactly on the displayed region (incl. awkward sizes)', () => {
  // The fused pass's contract is about the DISPLAYED pixels: pad content
  // is keyed shifted-wrap filler (v1.13) that the client crops away and
  // never regenerates, so the invariant worth pinning is exact
  // round-tripping of the real region at every awkward geometry.
  for (const [w, h, grid] of [[64, 48, 8], [61, 47, 8], [10, 10, 8], [333, 17, 16], [129, 257, 4], [7, 7, 32]]) {
    const raw = new Uint8Array(w * h * 4);
    for (let i = 0; i < raw.length; i++) raw[i] = (i * 40503 + 17) % 256;
    const plan = buildScramblePlan(grid, `fused-${w}x${h}-${grid}`);
    const { pw, ph } = paddedSize(w, h, grid);
    const scrambled = scramblePixelsPadded(raw, w, h, plan);
    assert.deepEqual(scramblePixelsPadded(raw, w, h, plan), scrambled, `${w}x${h} grid ${grid} deterministic`);
    const out = Buffer.alloc(pw * ph * 4);
    assert.equal(scramblePixelsPadded(raw, w, h, plan, out), out);
    assert.deepEqual(new Uint8Array(out), scrambled, `${w}x${h} grid ${grid} (provided buffer)`);
    const restored = scramblePixels(scrambled, pw, ph, plan, 'unscramble');
    for (let y = 0; y < h; y++) {
      assert.deepEqual(
        restored.subarray((y * pw) * 4, (y * pw + w) * 4),
        raw.subarray((y * w) * 4, (y * w + w) * 4),
        `${w}x${h} grid ${grid} row ${y} must round-trip byte-exactly`);
    }
  }
  // Pad filler is keyed by the plan: a different scramble key produces
  // different pad bytes (displayed region still identical), so a solver
  // cannot precompute the filler for a known image.
  const w = 61, h = 47, grid = 8;
  const raw = new Uint8Array(w * h * 4);
  for (let i = 0; i < raw.length; i++) raw[i] = (i * 40503 + 17) % 256;
  const { pw, ph } = paddedSize(w, h, grid);
  const padOf = (key) => {
    const plan = buildScramblePlan(grid, key);
    return scramblePixels(scramblePixelsPadded(raw, w, h, plan), pw, ph, plan, 'unscramble')
      .subarray((h * pw) * 4);
  };
  assert.notDeepEqual(padOf('key-a'), padOf('key-b'), 'pad filler must depend on the scramble key');
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
  const restored = await unscrambleImage(Buffer.from(payload), { grid: header.grid, key: token.key, w: header.w, h: header.h, planVersion: header.pv ?? 1 });
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
    grid: header.grid, key: token.key, w: header.w, h: header.h, planVersion: header.pv ?? 1,
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
  let symlinkCreated = true;
  try {
    fs.symlinkSync(outsideFile, path.join(symlinkDir, 'escape.jpg'));
  } catch (err) {
    // Windows refuses file symlinks without Developer Mode or elevation
    // (EPERM). The escape check itself is platform-independent and stays
    // covered on POSIX; skip only this sub-check where the OS forbids
    // creating the fixture.
    if (err.code !== 'EPERM' && err.code !== 'EACCES') throw err;
    symlinkCreated = false;
  }
  if (symlinkCreated) {
    assert.throws(
      () => createArchxMiddleware({ secret: TEST_SECRET, imagesDir: symlinkDir, allowAnonymous: true }),
      /no supported master images/i,
    );
  }

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
  // v1.15: saturation evicts the OLDEST live entry (smallest remaining
  // replay window) instead of failing every legitimate claim globally.
  assert.equal(nonces.claim('two', 2000, 1000), true, 'saturated store evicts oldest instead of global fail-closed');
  assert.equal(nonces.claim('two', 2000, 1000), false, 'live duplicate still loses');
  assert.equal(nonces.claim('expired', 999, 1000), false);
  nonces.cleanup(2001);
  assert.equal(nonces.claim('three', 3000, 2001), true);
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
  // Pinned to layout v2: per-layout crop resilience varies with the
  // shuffle (v3-standard lands a couple of low-repetition bits on the
  // crop boundary of this fixture; v3-robust recovers it in test 83+).
  const marked = embedStegoFingerprint(raw, info.width, info.height, 'CROP-90', { key: 'geometry-key', layoutVersion: 2 });
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
    grid: header.grid, key: stegoToken.key, w: header.w, h: header.h, planVersion: header.pv ?? 1,
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
    planVersion: oldDecoded.header.pv ?? 1,
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

test('forged-but-plausible disk cache containers are rejected by the HMAC entry tag', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-cache-forge-'));
  const mastersDir = path.join(root, 'masters');
  const cacheDir = path.join(root, 'derivative-cache');
  fs.mkdirSync(mastersDir);
  fs.writeFileSync(path.join(mastersDir, 'cat.jpg'), await syntheticMaster(640, 420));
  const makeHandler = () => createArchxMiddleware({
    secret: 'cache-forge-secret-for-unit-tests-32chr',
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
  await new Promise((resolve) => running.server.close(resolve));
  handler.close();

  // The attacker (write access to the cache dir, no server secret) plants a
  // structurally valid .archx of a DIFFERENT image with matching geometry —
  // it passes every plausibility check, so only the HMAC tag can stop it.
  const forged = await scrambleImage(await syntheticMaster(320, 210), {
    key: 'attacker-key', grid: 8, maxWidth: 320, quality: 88,
    processing: { webpEffort: 0, webpSmartSubsample: false, resizeKernel: 'lanczos2' },
  });
  assert.ok(isArchxContainer(forged.bytes));
  assert.notDeepEqual(new Uint8Array(forged.bytes), original);
  const cacheFiles = [];
  (function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.archx-cache')) cacheFiles.push(full);
    }
  })(cacheDir);
  assert.equal(cacheFiles.length, 1);
  fs.writeFileSync(cacheFiles[0], forged.bytes);

  handler = makeHandler();
  running = await start(handler);
  const after = await redeemFresh(running.base);
  assert.deepEqual(after, original, 'the forged derivative is never served; the authorized one is regenerated');
  assert.equal(handler.stats().derivativeCache.diskHits, 0);
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

test('batch body stream reads are deadline-bounded (slow-trickle fails fast with 408)', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-batch-trickle-'));
  const mastersDir = path.join(root, 'masters');
  fs.mkdirSync(mastersDir);
  fs.writeFileSync(path.join(mastersDir, 'cat.jpg'), await syntheticMaster(320, 240));
  const handler = createArchxMiddleware({
    secret: 'batch-trickle-secret-for-unit-tests-32c',
    imagesDir: mastersDir,
    callbackTimeoutMs: 100,
    authorize: async () => true,
  });
  const started = Date.now();
  const out = await new Promise((resolvePromise, rejectPromise) => {
    const req = {
      method: 'POST',
      url: '/archx/tokens',
      headers: { 'content-type': 'application/json', 'x-archx-request': 'token', host: 'unit.test' },
      socket: { remoteAddress: '127.0.0.1' },
      destroyed: false,
      destroy() { this.destroyed = true; },
      async *[Symbol.asyncIterator]() {
        await new Promise((r) => setTimeout(r, 500));
        yield Buffer.from('{"items":[]}');
      },
    };
    const res = {
      statusCode: 0,
      headers: {},
      writeHead(status, headers) { this.statusCode = status; Object.assign(this.headers, headers); return this; },
      end(payload) { resolvePromise({ status: this.statusCode, body: payload ? String(payload) : '' }); },
    };
    Promise.resolve(handler(req, res)).catch(rejectPromise);
  });
  const elapsed = Date.now() - started;
  assert.equal(out.status, 408, JSON.stringify(out));
  assert.ok(elapsed < 400, `deadline must fire before the trickled first chunk (elapsed ${elapsed} ms)`);
  handler.close();
});

test('taint image supports ETag revalidation (304 with no CORS leakage)', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-taint-etag-'));
  const mastersDir = path.join(root, 'masters');
  fs.mkdirSync(mastersDir);
  fs.writeFileSync(path.join(mastersDir, 'cat.jpg'), await syntheticMaster(64, 48));
  const handler = createArchxMiddleware({
    secret: 'taint-etag-secret-for-unit-tests-32chars',
    imagesDir: mastersDir,
    authorize: async () => true,
  });
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    handler.close();
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  const first = await fetch(base + '/archx/taint.png');
  assert.equal(first.status, 200);
  assert.equal(first.headers.get('etag'), '"archx-taint-1"');
  assert.equal((await first.arrayBuffer()).byteLength, 68);
  const revalidated = await fetch(base + '/archx/taint.png', {
    headers: { 'if-none-match': '"archx-taint-1"' },
  });
  assert.equal(revalidated.status, 304);
  assert.equal((await revalidated.arrayBuffer()).byteLength, 0);
  assert.equal(revalidated.headers.get('access-control-allow-origin'), null,
    'even the 304 must not become CORS-approved (that would un-taint)');
});

test('middleware scramblePlanVersion 2 issues pv=2 payloads that only unscramble with the v2 plan', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-planv2-'));
  const mastersDir = path.join(root, 'masters');
  fs.mkdirSync(mastersDir);
  const master = await syntheticMaster(640, 420);
  fs.writeFileSync(path.join(mastersDir, 'cat.jpg'), master);
  const start = async (extra) => {
    const handler = createArchxMiddleware({
      secret: 'planv2-secret-for-unit-tests-min-32chars',
      imagesDir: mastersDir,
      authorize: async () => true,
      ...extra,
    });
    const server = http.createServer((req, res) => handler(req, res));
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    return { handler, server, base: `http://127.0.0.1:${server.address().port}` };
  };
  const redeem = async (base) => {
    const token = await (await postToken(base + '/archx/token/cat?w=320')).json();
    const response = await redeemToken(base, token);
    assert.equal(response.status, 200);
    return { token, bytes: new Uint8Array(await response.arrayBuffer()) };
  };

  const v1 = await start({ scramblePlanVersion: 1 });
  t.after(async () => { await new Promise((r) => v1.server.close(r)); v1.handler.close(); });
  const one = await redeem(v1.base);
  const oneHeader = decodeContainer(one.bytes).header;
  assert.equal(oneHeader.pv, undefined, 'v1 payloads omit pv (byte-compatible with deployed clients)');

  const v2 = await start({ scramblePlanVersion: 2 });
  t.after(async () => { await new Promise((r) => v2.server.close(r)); v2.handler.close(); });
  const two = await redeem(v2.base);
  const twoDecoded = decodeContainer(two.bytes);
  assert.equal(twoDecoded.header.pv, 2);
  assert.notDeepEqual(two.bytes, one.bytes, 'v1 and v2 permutations must differ');

  const restoredV2 = await unscrambleImage(Buffer.from(twoDecoded.payload), {
    grid: twoDecoded.header.grid, key: two.token.key,
    w: twoDecoded.header.w, h: twoDecoded.header.h, planVersion: 2,
  });
  assert.ok((await meanAbsDiff(master, restoredV2, 320, 210)) < 22,
    'v2 payload unscrambles back to the master with the v2 plan');
  const restoredWrongPlan = await unscrambleImage(Buffer.from(twoDecoded.payload), {
    grid: twoDecoded.header.grid, key: two.token.key,
    w: twoDecoded.header.w, h: twoDecoded.header.h, planVersion: 1,
  });
  assert.ok((await meanAbsDiff(master, restoredWrongPlan, 320, 210)) > 22,
    'the v1 plan must NOT reconstruct a v2 payload');
  assert.throws(() => createArchxMiddleware({
    secret: 'planv2-secret-for-unit-tests-min-32chars', imagesDir: mastersDir,
    authorize: async () => true, scramblePlanVersion: 3,
  }), /scramblePlanVersion/);
});

test('AVIF derivatives round-trip, carry the avif MIME, and beat WebP bytes at comparable quality', async () => {
  const master = await syntheticMaster(640, 420);
  const webp = await scrambleImage(master, {
    grid: 8, key: 'avif-test', maxWidth: 640, quality: 88, format: 'webp',
    processing: { webpEffort: 2 },
  });
  const avif = await scrambleImage(master, {
    grid: 8, key: 'avif-test', maxWidth: 640, quality: 70, format: 'avif',
    processing: { avifEffort: 2 },
  });
  assert.equal(avif.header.mime, 'image/avif');
  const decoded = decodeContainer(avif.bytes);
  assert.equal(decoded.header.mime, 'image/avif');
  assert.equal(sniffImageInfo(decoded.payload).format, 'avif');
  const restored = await unscrambleImage(Buffer.from(decoded.payload), {
    grid: 8, key: 'avif-test', w: decoded.header.w, h: decoded.header.h,
  });
  assert.ok((await meanAbsDiff(master, restored, 640, 420)) < 22,
    'AVIF derivative unscrambles back near the master');
  assert.ok(avif.bytes.length < webp.bytes.length,
    `expected AVIF (${avif.bytes.length}) to be smaller than WebP q88 (${webp.bytes.length}) for photographic content`);
});

/* ---------- v1.11 external-review fixes ---------- */

test('embedding a StegoMark requires an explicit stegoKey distinct from the scramble key', async () => {
  const master = await syntheticMaster(640, 420);
  await assert.rejects(
    scrambleImage(master, { key: 'test-key', stegoPayload: 'buyer-1' }),
    /stegoKey is required/,
    'silent fallback to the (public) scramble key must never happen again',
  );
  await assert.rejects(
    scrambleImage(master, { key: 'test-key', stegoPayload: 'buyer-1', stegoKey: 'test-key' }),
    /stegoKey/,
  );
  const ok = await scrambleImage(master, {
    key: 'test-key', stegoPayload: 'buyer-1', stegoKey: 'a-private-stego-key',
  });
  assert.equal(ok.header.sg, 1);
  // The builder must fail closed the same way instead of embedding with the
  // public manifest key.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-stego-key-'));
  const mastersDir = path.join(root, 'masters');
  fs.mkdirSync(mastersDir);
  fs.writeFileSync(path.join(mastersDir, 'cat.jpg'), master);
  await assert.rejects(buildArchxAssets({
    inputDir: mastersDir,
    outputDir: path.join(root, 'out'),
    key: 'public-manifest-key',
    stegoPayload: 'buyer-shared',
  }), /explicit dedicated secret/);
  fs.rmSync(root, { recursive: true, force: true });
});

test('scramble padding is keyed shifted wrap (no black, duplication, or palindrome oracle)', () => {
  const w = 103, h = 61, grid = 8;
  const src = new Uint8Array(w * h * 4);
  for (let i = 0; i < w * h; i++) {
    src[i * 4] = 200; src[i * 4 + 1] = 180; src[i * 4 + 2] = 160; src[i * 4 + 3] = 255;
  }
  const { pw, ph } = paddedSize(w, h, grid);
  assert.ok(pw > w && ph > h, 'test geometry must actually need padding');
  const plan = buildScramblePlan(grid, 'pad-oracle', 1); // seam statistics below were calibrated against the v1 permutation
  const scrambled = scramblePixelsPadded(src, w, h, plan);
  assert.equal(scrambled.length, pw * ph * 4);
  // A uniform source stays within the keyed noise band (+-3) everywhere:
  // wrap of a constant is the constant; pad pixels are never black.
  for (let i = 0; i < pw * ph; i++) {
    assert.ok(Math.abs(scrambled[i * 4] - 200) <= 3 &&
      Math.abs(scrambled[i * 4 + 1] - 180) <= 3 &&
      Math.abs(scrambled[i * 4 + 2] - 160) <= 3,
      `padded pixel ${i} must stay near the edge color, never black`);
  }
  // Textured source: after unscrambling, pad rows must neither duplicate
  // the edge row (v1.11 oracle) nor mirror it (v1.12 palindrome seam:
  // MAD(pad, reflected edge) was ~0.6 vs ~17 for real texture).
  const tex = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const i = (y * w + x) * 4;
    tex[i] = (x * 3 + y * 5) % 256; tex[i + 1] = (x * 7 + y * 2) % 256; tex[i + 2] = (x * y) % 251; tex[i + 3] = 255;
  }
  const restored = scramblePixels(scramblePixelsPadded(tex, w, h, plan), pw, ph, plan, 'unscramble');
  let padExactDupes = 0, padCompared = 0;
  for (let y = h; y < ph; y++) {
    for (let x = 0; x < w; x++) {
      padCompared++;
      if (restored[(y * pw + x) * 4] === restored[((h - 1) * pw + x) * 4]) padExactDupes++;
    }
  }
  assert.ok(padExactDupes < padCompared * 0.05,
    `pad rows must not duplicate the edge row (got ${padExactDupes}/${padCompared} exact)`);
  const rowMAD = (y1, y2) => {
    let s = 0;
    for (let x = 0; x < w; x++) {
      const a = (y1 * pw + x) * 4, b = (y2 * pw + x) * 4;
      s += Math.abs(restored[a] - restored[b]) + Math.abs(restored[a + 1] - restored[b + 1]) + Math.abs(restored[a + 2] - restored[b + 2]);
    }
    return s / (w * 3);
  };
  const seamMAD = rowMAD(h, h - 2); // first pad row vs the row a mirror would copy
  const textureMAD = rowMAD(20, 22); // an ordinary interior row pair
  assert.ok(seamMAD > textureMAD * 0.5,
    `pad seam must not be palindromic (seam MAD ${seamMAD.toFixed(2)} vs texture ${textureMAD.toFixed(2)})`);
});

test('stego confidence is capped below 0.5 whenever nothing is found', () => {
  // Attribution tooling must never print {found:false, confidence:0.99}:
  // a high number next to a negative verdict reads as evidence.
  const w = 360, h = 240;
  const noise = new Uint8Array(w * h * 4);
  let s = 1234567;
  const rnd = () => { s = (s * 1103515245 + 12345) & 0x7fffffff; return s / 0x7fffffff; };
  for (let i = 0; i < noise.length; i++) noise[i] = Math.floor(rnd() * 256);
  for (let i = 3; i < noise.length; i += 4) noise[i] = 255;
  for (const profile of ['standard', 'robust', 'auto']) {
    const r = detectStegoFingerprint(noise, w, h, { key: 'conf-cap', profile });
    if (!r.found) assert.ok(r.confidence <= 0.49, `${profile}: confidence ${r.confidence} must stay <= 0.49 when !found`);
  }
});

test('mirrored (flopped) suspects are recovered and flagged', () => {
  const w = 360, h = 240;
  const src = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const i = (y * w + x) * 4;
    src[i] = (x * 255 / w) | 0; src[i + 1] = (y * 255 / h) | 0; src[i + 2] = ((x + y) * 255 / (w + h)) | 0; src[i + 3] = 255;
  }
  const marked = embedStegoFingerprint(src, w, h, 'mirror-probe', { key: 'mk', profile: 'robust', strength: 6 });
  const flipped = new Uint8Array(marked.length);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    flipped.set(marked.subarray((y * w + x) * 4, (y * w + x) * 4 + 4), (y * w + (w - 1 - x)) * 4);
  }
  const blind = detectStegoFingerprint(flipped, w, h, { key: 'mk', profile: 'robust', searchMirror: false });
  assert.equal(blind.found, false, 'with the mirror probe disabled a flopped grid must not decode');
  // Explicit profiles mirror-probe by default (v1.12): found + flagged.
  const direct = detectStegoFingerprint(flipped, w, h, { key: 'mk', profile: 'robust' });
  assert.equal(direct.found, true);
  assert.equal(direct.mirrored, true);
  assert.equal(direct.fingerprint, stegoFingerprint('mirror-probe'));
  const r = detectStegoFingerprint(flipped, w, h, { key: 'mk', profile: 'auto', searchGeometry: true });
  assert.equal(r.found, true);
  assert.equal(r.mirrored, true);
  assert.equal(r.fingerprint, stegoFingerprint('mirror-probe'));
});

test('Redis cache values survive a string-returning (default node-redis v4) client', async () => {
  const store = new Map();
  // Simulates node-redis v4 WITHOUT returnBuffers: GET yields a UTF-8 string.
  const stringyClient = {
    async get(key) {
      const v = store.get(key);
      if (v == null) return null;
      return Buffer.isBuffer(v) ? v.toString('utf8') : v;
    },
    async set(key, value) { store.set(key, value); return 'OK'; },
    async eval() { throw new Error('not used in this test'); },
  };
  const redis = createRedisStateStore({ client: stringyClient, prefix: 'test111' });
  const binary = Buffer.from(Array.from({ length: 512 }, (_, i) => i % 256));
  await redis.setCache('k1', binary, { ttlMs: 60000 });
  const back = await redis.getCache('k1');
  assert.ok(Buffer.isBuffer(back), 'getCache must return a Buffer');
  assert.deepEqual(back, binary, 'every byte >= 0x80 must survive the string round-trip');
});

test('malformed token requests do not burn quota; per-IP quota still binds valid ones', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-quota-order-'));
  fs.writeFileSync(path.join(root, 'cat.jpg'), await syntheticMaster(320, 240));
  const handler = createArchxMiddleware({
    secret: 'quota-order-secret-for-unit-tests-32ch',
    imagesDir: root,
    authorize: async () => true,
    quotas: { windowMs: 60000, perIp: 2 },
  });
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(async () => { await new Promise((r) => server.close(r)); handler.close(); fs.rmSync(root, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  for (let i = 0; i < 5; i++) {
    const bad = await postToken(`${base}/archx/token/cat?w=abc`);
    assert.equal(bad.status, 400, 'malformed width rejected');
  }
  for (let i = 0; i < 2; i++) {
    const ok = await postToken(`${base}/archx/token/cat?w=320`);
    assert.equal(ok.status, 200, `valid mint ${i + 1} must not be starved by earlier 400s`);
  }
  const limited = await postToken(`${base}/archx/token/cat?w=320`);
  assert.equal(limited.status, 429, 'third valid mint hits the per-IP quota');
});

test('distinct-image abuse alert latches: one suspicious event, continued enforcement', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-siem-latch-'));
  for (let i = 0; i < 8; i++) fs.writeFileSync(path.join(root, `img${i}.jpg`), await syntheticMaster(320, 240));
  let suspicious = 0;
  const handler = createArchxMiddleware({
    secret: 'siem-latch-secret-for-unit-tests-32chr',
    imagesDir: root,
    authorize: async () => true,
    abuseDetection: { distinctImages: 2, windowMs: 60000, action: 'deny' },
    onSecurityEvent: (event) => { if (event.type === 'archx.suspicious_scraping') suspicious++; },
  });
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(async () => { await new Promise((r) => server.close(r)); handler.close(); fs.rmSync(root, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const statuses = [];
  for (let i = 0; i < 8; i++) statuses.push((await postToken(`${base}/archx/token/img${i}?w=320`)).status);
  assert.equal(suspicious, 1, 'suspicious alert fires once per threshold crossing, not per request');
  assert.ok(statuses.slice(-3).every((s) => s === 429), 'deny action keeps enforcing after the latched alert');
});

test('per-token stego derivatives are not written to the shared output cache', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-pertoken-cache-'));
  fs.writeFileSync(path.join(root, 'cat.jpg'), await syntheticMaster(480, 320));
  const handler = createArchxMiddleware({
    secret: 'pertoken-cache-secret-for-tests-32chr!',
    imagesDir: root,
    authorize: async () => true,
    steganography: { perToken: true, scope: 'viewer' },
  });
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(async () => { await new Promise((r) => server.close(r)); handler.close(); fs.rmSync(root, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  for (let i = 0; i < 2; i++) {
    const token = await (await postToken(`${base}/archx/token/cat?w=320`, { headers: { 'x-viewer': 'v1' } })).json();
    const res = await redeemToken(base, token);
    assert.equal(res.status, 200);
    await res.arrayBuffer();
  }
  assert.equal(handler.stats().outputCacheEntries, 0,
    'unique per-token derivatives must not pollute the RAM output cache');
});

test('IPv6 limiter keys group by /64 (rotation inside the prefix shares one quota)', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-ipv6-quota-'));
  fs.writeFileSync(path.join(root, 'cat.jpg'), await syntheticMaster(320, 240));
  const handler = createArchxMiddleware({
    secret: 'ipv6-quota-secret-for-unit-tests-32chr',
    imagesDir: root,
    authorize: async () => true,
    trustProxy: true,
    trustedProxyHops: 1,
    quotas: { windowMs: 60000, perIp: 2 },
  });
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(async () => { await new Promise((r) => server.close(r)); handler.close(); fs.rmSync(root, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const mint = (ip) => postToken(`${base}/archx/token/cat?w=320`, { headers: { 'x-forwarded-for': ip } });
  assert.equal((await mint('2001:db8:85a3:8d3:1:2:3:4')).status, 200);
  assert.equal((await mint('2001:db8:85a3:8d3:9:9:9:9')).status, 200, 'same /64, second mint');
  assert.equal((await mint('2001:db8:85a3:8d3:ffff::1')).status, 429, 'same /64 rotated IID shares the exhausted quota');
  assert.equal((await mint('2001:db8:85a3:9999::1')).status, 200, 'different /64 has its own quota');
});

test('stego keyScope viewer diversifies layout keys per viewer (anti-collusion alignment)', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-keyscope-'));
  fs.writeFileSync(path.join(root, 'cat.jpg'), await syntheticMaster(480, 320));
  const registry = [];
  const handler = createArchxMiddleware({
    secret: 'keyscope-secret-for-unit-tests-32chrs',
    imagesDir: root,
    authorize: async (req) => ({ viewerId: req.headers['x-viewer'] || 'anon' }),
    steganography: { perToken: false, scope: 'viewer', keyScope: 'viewer' },
    onStegoIssue: (record) => registry.push(record),
  });
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(async () => { await new Promise((r) => server.close(r)); handler.close(); fs.rmSync(root, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const fetchDerivative = async (viewer) => {
    const token = await (await postToken(`${base}/archx/token/cat?w=320`, { headers: { 'x-viewer': viewer } })).json();
    const res = await redeemToken(base, token, { headers: { 'x-viewer': viewer } });
    assert.equal(res.status, 200);
    return new Uint8Array(await res.arrayBuffer());
  };
  const alice1 = await fetchDerivative('alice');
  const alice2 = await fetchDerivative('alice');
  const bob = await fetchDerivative('bob');
  assert.deepEqual(alice1, alice2, 'same viewer reuses the same keyed derivative');
  assert.notDeepEqual(alice1, bob, 'different viewers get different layout keys => different marked pixels');
  assert.ok(registry.length >= 3 && registry.every((r) => r.keyScope === 'viewer'),
    'issuance registry records the key scope needed to reproduce detection keys');
});

test('hardened defaults now encrypt; config audit warns on unencrypted or v1-plan deployments', () => {
  const hardened = withHardenedProductionDefaults({ secret: 'x'.repeat(40), authorize: () => true, images: [] });
  assert.equal(hardened.encrypt, true);
  const audit = auditArchxServerConfig({
    secret: 'x'.repeat(40), authorize: () => true, images: [], scramblePlanVersion: 1,
  });
  assert.ok(audit.warnings.some((w) => /encrypt is off/.test(w)), 'audit must call out jigsaw-solvable unencrypted payloads');
  assert.ok(audit.warnings.some((w) => /scramblePlanVersion 1/.test(w)), 'audit must call out the 32-bit plan seed');
});

/* ---------- v1.12 second external-review fixes ---------- */

test('pure-JS SHA-256/HMAC match node:crypto (stego MAC primitive)', () => {
  const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
  for (const msg of ['', 'abc', 'x'.repeat(1000), 'Archx ✓']) {
    assert.equal(hex(sha256Bytes(new TextEncoder().encode(msg))),
      crypto.createHash('sha256').update(msg).digest('hex'));
  }
  for (const keyLen of [3, 32, 64, 131]) {
    const key = new Uint8Array(keyLen).fill(0x5a);
    const msg = new TextEncoder().encode('tag me');
    assert.equal(hex(hmacSha256Bytes(key, msg)),
      crypto.createHmac('sha256', Buffer.from(key)).update(msg).digest('hex'));
  }
});

test('stego codeword v2 uses keyed MAC tags; legacy CRC marks still detect (flagged)', () => {
  const w = 360, h = 240;
  const src = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const i = (y * w + x) * 4;
    src[i] = (x * 255 / w) | 0; src[i + 1] = (y * 255 / h) | 0; src[i + 2] = ((x + y) * 255 / (w + h)) | 0; src[i + 3] = 255;
  }
  for (const profile of ['standard', 'robust']) {
    const mac = embedStegoFingerprint(src, w, h, 'mac-buyer', { key: 'tagkey', profile, strength: 6 });
    const rMac = detectStegoFingerprint(mac, w, h, { key: 'tagkey', profile });
    assert.equal(rMac.found, true, `${profile} MAC mark detects`);
    assert.equal(rMac.tagScheme, 'mac');
    assert.equal(rMac.fingerprint, stegoFingerprint('mac-buyer'));
    const legacy = embedStegoFingerprint(src, w, h, 'legacy-buyer', { key: 'tagkey', profile, strength: 6, legacyCode: true });
    const rLegacy = detectStegoFingerprint(legacy, w, h, { key: 'tagkey', profile });
    assert.equal(rLegacy.found, true, `${profile} legacy mark still detects`);
    assert.equal(rLegacy.tagScheme, 'crc', 'legacy decodes are flagged for corroboration');
    assert.equal(rLegacy.fingerprint, stegoFingerprint('legacy-buyer'));
    // A MAC mark must not validate under a wrong key via the CRC fallback.
    const wrong = detectStegoFingerprint(mac, w, h, { key: 'wrong-key', profile });
    assert.equal(wrong.found, false, `${profile} MAC mark rejects wrong keys`);
  }
});

test('compound flip + 90% center crop recovers under an explicit profile', () => {
  const w = 360, h = 240;
  const src = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const i = (y * w + x) * 4;
    src[i] = (x * 255 / w) | 0; src[i + 1] = (y * 255 / h) | 0; src[i + 2] = ((x + y) * 255 / (w + h)) | 0; src[i + 3] = 255;
  }
  const marked = embedStegoFingerprint(src, w, h, 'flip-crop', { key: 'fc', profile: 'robust', strength: 6 });
  // flop, then keep the center 90% at native resolution
  const cw = Math.floor(w * 0.9), ch = Math.floor(h * 0.9);
  const ox = Math.floor(w * 0.05), oy = Math.floor(h * 0.05);
  const suspect = new Uint8Array(cw * ch * 4);
  for (let y = 0; y < ch; y++) for (let x = 0; x < cw; x++) {
    const si = ((oy + y) * w + (w - 1 - (ox + x))) * 4;
    suspect.set(marked.subarray(si, si + 4), (y * cw + x) * 4);
  }
  const r = detectStegoFingerprint(suspect, cw, ch, { key: 'fc', profile: 'robust', searchGeometry: true, searchOffsets: true });
  assert.equal(r.found, true, 'flip+crop must recover (was the v1.11 compound blindspot)');
  assert.equal(r.mirrored, true);
  assert.equal(r.fingerprint, stegoFingerprint('flip-crop'));
});

test('SlidingWindowLimiter pins blocked entries against churn eviction', () => {
  const limiter = new SlidingWindowLimiter({ windowMs: 60000, maxClients: 3, cleanupIntervalMs: 0 });
  const t0 = 1_000_000;
  limiter.hit('victim', 2, t0);
  limiter.hit('victim', 2, t0 + 1);
  assert.equal(limiter.hit('victim', 2, t0 + 2).limited, true);
  for (let i = 0; i < 12; i++) limiter.hit('churn-' + i, 100, t0 + 3 + i);
  assert.equal(limiter.hit('victim', 2, t0 + 20).limited, true,
    'a blocked client must not be evicted (and un-throttled) by fresh-key churn');
  limiter.close();
});

test('IPv6 /48 aggregate ceiling binds across rotating /64s', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-ipv6-48-'));
  fs.writeFileSync(path.join(root, 'cat.jpg'), await syntheticMaster(320, 240));
  const handler = createArchxMiddleware({
    secret: 'ipv6-48-secret-for-unit-tests-32chars',
    imagesDir: root,
    authorize: async () => true,
    trustProxy: true,
    trustedProxyHops: 1,
    quotas: { windowMs: 60000, perIp: 2 },
  });
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(async () => { await new Promise((r) => server.close(r)); handler.close(); fs.rmSync(root, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const mint = (ip) => postToken(`${base}/archx/token/cat?w=320`, { headers: { 'x-forwarded-for': ip } });
  // /48 = 2001:db8:85a3::/48 — rotate the /64 (4th group) each 2 mints.
  const statuses = [];
  for (let subnet = 1; subnet <= 5; subnet++) {
    for (let k = 0; k < 2; k++) statuses.push((await mint(`2001:db8:85a3:${subnet}::1`)).status);
  }
  assert.deepEqual(statuses.slice(0, 8), Array(8).fill(200), 'first 8 mints allowed (2 per /64, /48 ceiling 8)');
  assert.deepEqual(statuses.slice(8), [429, 429], 'the /48 aggregate (4x perIp) binds the 9th+ mint despite fresh /64s');
  assert.equal((await mint('2001:db8:9999:1::1')).status, 200, 'a different /48 is unaffected');
});

test('Redis store uses raw Buffers when the client supports returnBuffers', async () => {
  const store = new Map();
  const client = {
    options: {},
    // node-redis v4 shape
    commandOptions(opts) { return { __opts: opts }; },
    async get(arg1, arg2) {
      const key = arg2 ?? arg1;
      const v = store.get(key);
      if (v == null) return null;
      if (arg1 && arg1.__opts?.returnBuffers) return Buffer.isBuffer(v) ? v : Buffer.from(String(v));
      return Buffer.isBuffer(v) ? v.toString('utf8') : v;
    },
    async set(key, value) { store.set(key, value); return 'OK'; },
    async eval() { throw new Error('not used'); },
  };
  const redis = createRedisStateStore({ client, prefix: 'test112', clientFlavor: 'node-redis' });
  const binary = Buffer.from(Array.from({ length: 300 }, (_, i) => (i * 7) % 256));
  await redis.setCache('raw1', binary, { ttlMs: 1000 });
  const stored = [...store.values()][0];
  assert.ok(Buffer.isBuffer(stored) && stored.equals(binary), 'stored raw, no base64 armor');
  assert.deepEqual(await redis.getCache('raw1'), binary);
});

test('prepare+finish is byte-identical to scrambleImage, and finish never mutates a shared base', async () => {
  const master = await syntheticMaster(640, 420);
  const opts = {
    key: 'split-key', grid: 8, maxWidth: 480, quality: 90,
    watermark: '© SPLIT', forensicSeed: 'sess-1',
    stegoPayload: 'buyer-split', stegoKey: 'split-stego-secret',
    processing: { webpEffort: 2 },
  };
  const direct = await scrambleImage(master, opts);
  const base = await prepareDerivativeBase(master, opts);
  const baseSnapshot = Buffer.from(base.data);
  const staged = await finishDerivative(base, opts);
  assert.deepEqual(new Uint8Array(staged.bytes), new Uint8Array(direct.bytes),
    'two-stage output must equal single-call output byte for byte');
  assert.deepEqual(new Uint8Array(base.data), new Uint8Array(baseSnapshot),
    'finishDerivative must not poison a reusable base with per-viewer marks');
  const staged2 = await finishDerivative(base, { ...opts, stegoPayload: 'buyer-other' });
  assert.notDeepEqual(new Uint8Array(staged2.bytes), new Uint8Array(direct.bytes),
    'a second viewer finished from the same base carries a different mark');
});

test('per-token redemptions populate the base-frame cache (decode+resize amortized)', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-basecache-'));
  fs.writeFileSync(path.join(root, 'cat.jpg'), await syntheticMaster(640, 420));
  const handler = createArchxMiddleware({
    secret: 'basecache-secret-for-unit-tests-32ch',
    imagesDir: root,
    authorize: async () => true,
    steganography: { perToken: true, scope: 'viewer' },
  });
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  t.after(async () => { await new Promise((r) => server.close(r)); handler.close(); fs.rmSync(root, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const seen = new Set();
  for (let i = 0; i < 3; i++) {
    const token = await (await postToken(`${base}/archx/token/cat?w=480`)).json();
    const res = await redeemToken(base, token);
    assert.equal(res.status, 200);
    seen.add(Buffer.from(await res.arrayBuffer()).toString('base64').slice(0, 64) + i);
    await res.arrayBuffer().catch(() => {});
  }
  const stats = handler.stats();
  assert.equal(stats.baseCacheEntries, 1, 'one shared base frame for repeated per-token views of one geometry');
  assert.ok(stats.baseCacheBytes > 0);
  assert.equal(stats.outputCacheEntries, 0, 'per-token derivatives still skip the output cache');
});

/* ---------- v1.13 review-response regressions ---------- */

test('v1.13: a per-viewer watermark never leaks to another viewer via the shared derivative base', async (t) => {
  // Review #3 Bug #1: the viewer-independent base cache key omitted the
  // watermark while the watermark was baked INTO the cached base, so the
  // second viewer of a geometry received the first viewer's mark. The
  // base is now watermark-free; marks are applied per-token in stage 2.
  let currentViewer = 'alice@client-alpha.example';
  const fx = await startArchxFixture(t, {
    authorize: async () => ({
      allow: true,
      viewerId: currentViewer,
      watermark: { text: 'CONFIDENTIAL {viewer}', opacity: 0.55, corner: true },
    }),
    // Per-token marks engage the prepare/finish split whose shared base
    // cache this regression is about.
    steganography: { perToken: true, scope: 'viewer' },
  });
  const viewAs = async (viewer) => {
    currentViewer = viewer;
    const tokenRes = await postToken(fx.base + '/archx/token/cat?w=240');
    assert.equal(tokenRes.status, 200);
    const token = await tokenRes.json();
    const res = await redeemToken(fx.base, token);
    assert.equal(res.status, 200);
    const { header, payload } = decodeContainer(Buffer.from(await res.arrayBuffer()));
    return unscrambleImage(Buffer.from(payload), {
      grid: header.g, key: token.key, w: header.w, h: header.h, planVersion: header.pv ?? 1,
    });
  };
  const Alice = await viewAs('alice@client-alpha.example');
  const Bob = await viewAs('bob@competitor-beta.example');
  // Bob's cache-free reference rendering.
  const master = fs.readFileSync(path.join(fx.dir, 'cat.jpg'));
  const ref = await scrambleImage(master, {
    key: 'ref-key', grid: 8, maxWidth: 240,
    watermark: { text: 'CONFIDENTIAL bob@competitor-beta.example', opacity: 0.55, corner: true },
  });
  const refDecoded = decodeContainer(Buffer.from(ref.bytes));
  const bobRef = await unscrambleImage(Buffer.from(refDecoded.payload), {
    grid: refDecoded.header.g, key: 'ref-key', w: refDecoded.header.w, h: refDecoded.header.h,
    planVersion: refDecoded.header.pv ?? 1,
  });
  const madBobRef = await meanAbsDiff(Bob, bobRef, 160, 120);
  const madBobAlice = await meanAbsDiff(Bob, Alice, 160, 120);
  assert.ok(madBobAlice > 1.5, `Alice and Bob derivatives must actually differ (MAD=${madBobAlice.toFixed(2)})`);
  assert.ok(madBobRef < madBobAlice,
    `Bob must receive Bob's watermark, not Alice's (vs-ref MAD=${madBobRef.toFixed(2)}, vs-Alice MAD=${madBobAlice.toFixed(2)})`);
  assert.equal(fx.handler.stats().baseCacheEntries, 1, 'geometry still shares ONE clean base');
});

test('v1.13: IPv4-mapped and re-spelled IPv6 clients share one quota identity', async (t) => {
  const fx = await startArchxFixture(t, {
    allowAnonymous: true,
    trustProxy: true,
    trustedProxyHops: 1,
    quotas: { perIp: 1, windowMs: 60000 },
  });
  const mint = (xff) => postToken(fx.base + '/archx/token/cat?w=100', { headers: { 'x-forwarded-for': xff } });
  assert.equal((await mint('::ffff:9.9.9.9')).status, 200);
  assert.equal((await mint('9.9.9.9')).status, 429, '::ffff:9.9.9.9 and 9.9.9.9 are one client');
  assert.equal((await mint('0:0:0:0:0:ffff:0909:0909')).status, 429, 'expanded mapped form is the same client');
  assert.equal((await mint('2001:db8::1')).status, 200);
  assert.equal((await mint('2001:0db8:0000:0000:0000:0000:0000:0001')).status, 429,
    're-spelling one IPv6 address must not mint a fresh quota');
});

test('v1.14: stego layout v3 + forensic signs v3 (SHA-256 seeded), triple-read of v1/v2 marks', () => {
  const w = 360, h = 240;
  const src = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const i = (y * w + x) * 4;
    src[i] = (x * 255 / w) | 0; src[i + 1] = (y * 255 / h) | 0; src[i + 2] = ((x + y) * 255 / (w + h)) | 0; src[i + 3] = 255;
  }
  for (const profile of ['standard', 'robust']) {
    for (const layoutVersion of [1, 2, 3]) {
      const marked = embedStegoFingerprint(src, w, h, 'layout-buyer', {
        key: 'layout-key', profile, strength: 6, layoutVersion,
      });
      const auto = detectStegoFingerprint(marked, w, h, { key: 'layout-key', profile });
      assert.equal(auto.found, true, `${profile} layout v${layoutVersion} must auto-detect`);
      assert.equal(auto.fingerprint, stegoFingerprint('layout-buyer'));
      assert.equal(auto.layoutVersion, layoutVersion, 'detector reports the layout vintage');
      for (const wrong of [1, 2, 3].filter((v) => v !== layoutVersion)) {
        const pinnedWrong = detectStegoFingerprint(marked, w, h, {
          key: 'layout-key', profile, layoutVersion: wrong,
        });
        assert.equal(pinnedWrong.found, false, `${profile} v${layoutVersion} mark must not validate under layout v${wrong}`);
      }
    }
    // New embeds default to layout v3.
    const def = embedStegoFingerprint(src, w, h, 'layout-buyer', { key: 'layout-key', profile, strength: 6 });
    assert.equal(detectStegoFingerprint(def, w, h, { key: 'layout-key', profile }).layoutVersion, 3);
  }
  // Forensic block signs: every vintage scores under triple-read and
  // the result names the vintage; new embeds default to v3.
  const flat = new Uint8Array(w * h * 4);
  for (let i = 0; i < flat.length; i += 4) { flat[i] = 110; flat[i + 1] = 120; flat[i + 2] = 130; flat[i + 3] = 255; }
  for (const signsVersion of [1, 2, 3]) {
    const marked = applyForensicBlocks(new Uint8Array(flat), w, h, 'seed-1', { blockSize: 32, delta: 3, signsVersion });
    const score = forensicScore(marked, flat, w, h, 'seed-1', { blockSize: 32 });
    assert.ok(score.score > 0.9, `v${signsVersion} forensic mark must triple-read (score=${score.score})`);
    assert.equal(score.signsVersion, signsVersion);
  }
  const defMarked = applyForensicBlocks(new Uint8Array(flat), w, h, 'seed-1', { blockSize: 32, delta: 3 });
  assert.equal(forensicScore(defMarked, flat, w, h, 'seed-1', { blockSize: 32 }).signsVersion, 3);
  assert.notDeepEqual(forensicBlockSigns('seed-1', 64, 1), forensicBlockSigns('seed-1', 64, 2));
  assert.notDeepEqual(forensicBlockSigns('seed-1', 64, 2), forensicBlockSigns('seed-1', 64, 3),
    'v2/v3 sign sequences must actually differ (SHA-256 seed, not a relabel)');
});

test('v1.13: Sharp loader policy re-blocks a loader a later stricter config excludes', async () => {
  // Process-global and most-restrictive-wins by design; appended last and
  // targets AVIF (allowed by default, unused as test INPUT elsewhere).
  const avif = await sharp({
    create: { width: 8, height: 8, channels: 3, background: { r: 10, g: 20, b: 30 } },
  }).avif().toBuffer();
  assert.equal((await sharp(avif).metadata()).format, 'heif', 'AVIF loader starts unblocked');
  configureSharpSecurity(['jpeg', 'png', 'webp']);
  await assert.rejects(sharp(avif).metadata(), 'stricter later config must re-block the HEIF loader');
});

test('v1.14: /server export surface, config acceptance, hardened processing defaults, presets', async () => {
  // P1: the documented /server surface includes the image-processing API,
  // and both import paths resolve to ONE module singleton.
  for (const name of ['scrambleImage', 'unscrambleImage', 'inspectImageMetadata',
    'prepareDerivativeBase', 'finishDerivative', 'configureSharpSecurity',
    'configureSharpPerformance', 'generateKeyBase64', 'acquireSharpSecurityLease',
    'ensureUntrustedSharpLoadersBlocked']) {
    assert.equal(typeof archxServerModule[name], 'function', `/server must export ${name}`);
  }
  assert.equal(archxServerModule.scrambleImage, scrambleImage, 'singleton identity across import paths');
  assert.equal(archxServerModule.inspectImageMetadata, inspectImageMetadata);
  assert.equal(archxServerModule.configureSharpSecurity, configureSharpSecurity);

  // P8: typed/implemented options are accepted end-to-end...
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-v14-cfg-'));
  fs.writeFileSync(path.join(dir, 'cat.jpg'), await syntheticMaster());
  const okHandler = createArchxMiddleware({
    secret: TEST_SECRET, imagesDir: dir, allowAnonymous: true,
    processing: { avifEffort: 6, avifChromaSubsampling: '4:4:4' },
    forensic: { blockSize: 32, delta: 2, signsVersion: 3 },
    steganography: { perToken: true, layoutVersion: 3, legacyCode: false },
  });
  okHandler.close();
  // ...and invalid values still fail closed.
  for (const bad of [
    { processing: { avifEffort: 10 } },
    { processing: { avifChromaSubsampling: '4:2:2' } },
    { forensic: { signsVersion: 4 } },
    { steganography: { layoutVersion: 9 } },
    { steganography: { legacyCode: 'yes' } },
  ]) {
    assert.throws(() => createArchxMiddleware({
      secret: TEST_SECRET, imagesDir: dir, allowAnonymous: true, ...bad,
    }), TypeError, `must reject ${JSON.stringify(bad)}`);
  }

  // S7: hardened defaults contribute sharpConcurrency 1 + sharpCache false,
  // per-key overridable.
  const hardened = withHardenedProductionDefaults({ secret: TEST_SECRET, imagesDir: dir });
  assert.equal(hardened.processing.sharpConcurrency, 1);
  assert.equal(hardened.processing.sharpCache, false);
  const overridden = withHardenedProductionDefaults({
    secret: TEST_SECRET, imagesDir: dir, processing: { sharpConcurrency: 4 },
  });
  assert.equal(overridden.processing.sharpConcurrency, 4, 'host value wins');
  assert.equal(overridden.processing.sharpCache, false, 'unset key still defaults');

  // P2b + P6a: marketplace preset exists; fortress60 noiseStrength unclamped.
  assert.equal(PRESETS.marketplace.mode, 'vault');
  assert.equal(normalizeTemporalInterlace('fortress60').noiseStrength, 0.55);
});

test('v1.14: NAT64, 6to4, Teredo and zone-id spellings share one quota identity', async (t) => {
  const fx = await startArchxFixture(t, {
    allowAnonymous: true,
    trustProxy: true,
    trustedProxyHops: 1,
    quotas: { perIp: 1, windowMs: 60000 },
  });
  const mint = (xff) => postToken(fx.base + '/archx/token/cat?w=100', { headers: { 'x-forwarded-for': xff } });
  assert.equal((await mint('64:ff9b::909:909')).status, 200, 'NAT64 form (9.9.9.9) mints');
  assert.equal((await mint('9.9.9.9')).status, 429, 'plain IPv4 is the same client');
  assert.equal((await mint('2002:909:909::1')).status, 429, '6to4 form is the same client');
  assert.equal((await mint('2001:0000:4136:e378:8000:63bf:f6f6:f6f6')).status, 429, 'Teredo form is the same client');
  assert.equal((await mint('64:ff9b:1::909:909')).status, 429, 'local-use NAT64 form is the same client');
  assert.equal((await mint('fe80::1%eth0')).status, 200, 'zone-id form mints');
  assert.equal((await mint('fe80::1')).status, 429, 'zoneless spelling is the same client');
  assert.equal((await mint('9.9.9.10')).status, 200, 'a genuinely different client still mints');
});

test('v1.14: padding is texture-coherent with a sub-texture seam; displayed region exact', () => {
  const w = 61, h = 44, grid = 8; // padded 64x48: 3 pad columns, 4 pad rows
  const src = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const i = (y * w + x) * 4;
    src[i] = 128 + Math.round(60 * Math.sin(x / 9) + 30 * Math.cos(y / 7));
    src[i + 1] = 120 + Math.round(50 * Math.cos(x / 11));
    src[i + 2] = 110 + Math.round(40 * Math.sin((x + y) / 13));
    src[i + 3] = 255;
  }
  const plan = buildScramblePlan(grid, 'pad-v14', 2);
  const { pw, ph } = paddedSize(w, h, grid);
  const scrambled = scramblePixelsPadded(src, w, h, plan);
  const restored = scramblePixels(scrambled, pw, ph, plan, 'unscramble');
  const px = (buf, stride, x, y, c) => buf[(y * stride + x) * 4 + c];
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) for (let c = 0; c < 4; c++) {
    assert.equal(px(restored, pw, x, y, c), px(src, w, x, y, c), `displayed pixel ${x},${y},${c}`);
  }
  const madPairs = (pairs) => {
    let sum = 0;
    for (const [a, b] of pairs) for (let c = 0; c < 3; c++) sum += Math.abs(a[c] - b[c]);
    return sum / (pairs.length * 3);
  };
  const P = (x, y) => [px(restored, pw, x, y, 0), px(restored, pw, x, y, 1), px(restored, pw, x, y, 2)];
  const interiorH = [], padH = [], seamH = [], interiorV = [], padV = [], seamV = [];
  for (let y = 4; y < h - 4; y++) {
    for (let x = 4; x < w - 5; x++) interiorH.push([P(x, y), P(x + 1, y)]);
    for (let x = w; x < pw - 1; x++) padH.push([P(x, y), P(x + 1, y)]);
    seamH.push([P(w - 1, y), P(w, y)]);
  }
  for (let x = 4; x < w - 4; x++) {
    for (let y = 4; y < h - 5; y++) interiorV.push([P(x, y), P(x, y + 1)]);
    for (let y = h; y < ph - 1; y++) padV.push([P(x, y), P(x, y + 1)]);
    seamV.push([P(x, h - 1), P(x, h)]);
  }
  const inH = madPairs(interiorH), inV = madPairs(interiorV);
  assert.ok(madPairs(padH) / inH < 2.5, `right strip texture ratio ${madPairs(padH) / inH}`);
  assert.ok(madPairs(padV) / inV < 2.5, `bottom strip texture ratio ${madPairs(padV) / inV}`);
  assert.ok(madPairs(seamH) < 5, `right seam absolute MAD ${madPairs(seamH)}`);
  assert.ok(madPairs(seamV) < 5, `bottom seam absolute MAD ${madPairs(seamV)}`);
});

test('v1.14: finishDerivative is copy-on-write; watermark finishes are cache-stable', async () => {
  const master = await syntheticMaster(320, 240);
  const base = await prepareDerivativeBase(master, { key: 'cow-key', grid: 8, maxWidth: 320 });
  const before = Buffer.from(base.data.buffer, base.data.byteOffset, base.data.byteLength);
  const opts = { key: 'cow-key', grid: 8 };
  const a1 = await finishDerivative(base, { ...opts, watermark: 'ALICE' });
  const b = await finishDerivative(base, { ...opts, watermark: 'BOB' });
  const a2 = await finishDerivative(base, { ...opts, watermark: 'ALICE' });
  assert.notDeepEqual(a1.bytes, b.bytes, 'per-viewer watermarks differ');
  assert.deepEqual(a2.bytes, a1.bytes, 'repeat finish (overlay-cache hit) is byte-stable');
  const afterWm = Buffer.from(base.data.buffer, base.data.byteOffset, base.data.byteLength);
  assert.equal(Buffer.compare(before, afterWm), 0, 'watermark finishes must not mutate the shared base');
  await finishDerivative(base, {
    ...opts, forensicSeed: 'cow-seed',
    stegoPayload: 'buyer-cow', stegoKey: 'cow-stego-key',
  });
  const afterMarks = Buffer.from(base.data.buffer, base.data.byteOffset, base.data.byteLength);
  assert.equal(Buffer.compare(before, afterMarks), 0, 'in-place marks copy-on-write, never touch base.data');
});

test('v1.14: build summary exposes totalBytes and manifest variants carry file names', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-v14-build-'));
  const inputDir = path.join(root, 'masters');
  const outputDir = path.join(root, 'public');
  fs.mkdirSync(inputDir, { recursive: true });
  fs.writeFileSync(path.join(inputDir, 'cat.jpg'), await syntheticMaster(160, 120));
  const result = await buildArchxAssets({
    inputDir, outputDir, key: 'build-v14-key', widths: [160], baseUrl: '/protected/',
  });
  assert.equal(typeof result.totalBytes, 'number');
  assert.equal(result.totalBytes, result.bytes, 'totalBytes mirrors the long-standing bytes field');
  const manifest = JSON.parse(fs.readFileSync(result.manifestPath, 'utf8'));
  const variant = manifest.assets.cat.variants[0];
  assert.equal(typeof variant.file, 'string', 'manifest variant carries its file name (typed since 1.x)');
  assert.ok(variant.url.endsWith(variant.file), 'url is derived from file');
});

test('v1.14: Sharp loads lazily and loader leases are scoped to instance lifetime', () => {
  // Child process: loader policy is process-global and this suite's own
  // last test deliberately narrows permanents; isolate lease semantics.
  const script = `
    import { createRequire } from 'node:module';
    import fs from 'node:fs';
    import os from 'node:os';
    import path from 'node:path';
    const req = createRequire(import.meta.url);
    const sharpHits = () => Object.keys(req.cache).filter((k) => k.includes('node_modules/sharp')).length;
    const server = await import('./server/middleware.js');
    if (sharpHits() !== 0) throw new Error('sharp loaded eagerly by /server import');
    const sharp = (await import('sharp')).default;
    const jpg = await sharp({ create: { width: 8, height: 8, channels: 3, background: { r: 1, g: 2, b: 3 } } }).jpeg().toBuffer();
    const release = server.acquireSharpSecurityLease(['png']);
    let blocked = false;
    try { await sharp(jpg).metadata(); } catch { blocked = true; }
    if (!blocked) throw new Error('jpeg loader not blocked under png lease');
    release(); release();
    if ((await sharp(jpg).metadata()).format !== 'jpeg') throw new Error('jpeg loader not restored after release');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-lease-'));
    fs.writeFileSync(path.join(dir, 'x.png'), await sharp({ create: { width: 8, height: 8, channels: 3, background: { r: 9, g: 9, b: 9 } } }).png().toBuffer());
    const handler = server.createArchxMiddleware({
      secret: 'lease-test-secret-with-more-than-32-bytes', imagesDir: dir,
      allowAnonymous: true, allowedInputFormats: ['png'],
    });
    blocked = false;
    try { await sharp(jpg).metadata(); } catch { blocked = true; }
    if (!blocked) throw new Error('middleware lease did not narrow loaders');
    handler.close();
    if ((await sharp(jpg).metadata()).format !== 'jpeg') throw new Error('handler.close() did not release its lease');
    console.log('LEASES-OK');
  `;
  const out = execFileSync(process.execPath, ['--input-type=module', '-e', script], {
    cwd: path.join(import.meta.dirname, '..'),
    encoding: 'utf8',
    timeout: 120000,
  });
  assert.ok(out.includes('LEASES-OK'), out);
});

test('v1.14: per-token derivatives share one stage-1 base (S1 base-first + singleflight)', async (t) => {
  const fx = await startArchxFixture(t, {
    allowAnonymous: true,
    steganography: { perToken: true, profile: 'robust', layoutVersion: 3 },
  });
  const view = async () => {
    const res = await postToken(fx.base + '/archx/token/cat?w=320');
    assert.equal(res.status, 200);
    const token = await res.json();
    const payloadRes = await redeemToken(fx.base, token);
    assert.equal(payloadRes.status, 200);
    const body = Buffer.from(await payloadRes.arrayBuffer());
    assert.ok(body.length > 0);
    return body;
  };
  // Two concurrent first-views + one later view: all succeed, exactly one
  // stage-1 base is cached and reused, and no flight leaks afterwards.
  await Promise.all([view(), view()]);
  await view();
  const stats = fx.handler.stats();
  assert.equal(stats.baseInFlight, 0, 'singleflight map drains');
  assert.ok((stats.baseCacheEntries ?? 0) >= 1, 'stage-1 base cached for reuse');
});
test('variant-scoped per-image keys: a free-tier key cannot open the paid-tier derivative (S1)', async (t) => {
  let tier = 'free';
  const { base } = await startArchxFixture(t, {
    encrypt: true,
    scrambleKeyMode: 'per-image',
    authorize: () => tier === 'free'
      ? { maxWidth: 120, quality: 40 }
      : { maxWidth: 320, lossless: true },
  }, { consult: [320, 240] });
  const freeToken = await (await postToken(`${base}/archx/token/consult?w=120`)).json();
  tier = 'vip';
  const vipToken = await (await postToken(`${base}/archx/token/consult?w=320`)).json();
  assert.notEqual(freeToken.key, vipToken.key, 'different tiers derive different scramble keys');
  const res = await redeemToken(base, vipToken);
  assert.equal(res.status, 200);
  const bytes = Buffer.from(await res.arrayBuffer());
  const { header, payload } = decodeContainer(bytes);
  // The free-tier AES key cannot open the paid payload at all…
  await assert.rejects(
    () => decryptPayload(Buffer.from(payload), freeToken.aesKey, header.iv),
    'free-tier AES key must not decrypt the lossless derivative',
  );
  const plain = await decryptPayload(Buffer.from(payload), vipToken.aesKey, header.iv);
  const wrong = await unscrambleImage(plain, { key: freeToken.key, grid: header.grid, format: 'webp', lossless: true, planVersion: header.pv ?? 1 });
  const right = await unscrambleImage(plain, { key: vipToken.key, grid: header.grid, format: 'webp', lossless: true, planVersion: header.pv ?? 1 });
  assert.ok((await meanAbsDiff(right, wrong, header.origW, header.origH)) > 20,
    'free-tier scramble key leaves the paid derivative scrambled');
});

test('short X-Forwarded-For chains fall back to the socket identity (S2)', async (t) => {
  const { base } = await startArchxFixture(t, {
    allowAnonymous: true,
    trustProxy: true,
    trustedProxyHops: 2,
    quotas: { perIp: 1, windowMs: 60000 },
  });
  const mintWith = (xff) => postToken(`${base}/archx/token/cat?w=100`, { headers: { 'x-forwarded-for': xff } });
  assert.equal((await mintWith('198.51.100.10')).status, 200);
  // A too-short chain cannot select the identity: a DIFFERENT first hop
  // still lands in the socket bucket and is now over quota.
  assert.equal((await mintWith('203.0.113.99')).status, 429,
    'single-hop XFF must not mint a fresh identity per spoofed value');
  // A complete chain (length === trusted hops) still selects chain[0].
  assert.equal((await mintWith('198.51.100.10, 10.0.0.1')).status, 200);
});

test('saturated BoundedTtlSet evicts the oldest entries instead of failing closed globally', () => {
  const set = new BoundedTtlSet({ maxEntries: 64, cleanupIntervalMs: 0 });
  const exp = Date.now() + 60_000;
  for (let i = 0; i < 64; i++) assert.equal(set.claim(`k-${i}`, exp), true);
  assert.equal(set.claim('fresh-viewer', exp), true, 'new viewers are not locked out by saturation');
  assert.ok(set.size <= 64, 'the store stays bounded');
  assert.equal(set.claim('k-63', exp), false, 'recent entries remain claimed');
  assert.equal(set.claim('k-0', exp), true, 'the oldest entry was evicted to make room');
});

test('array bindTokenTo and authorize-provided ttlSec are honoured', async (t) => {
  const { base } = await startArchxFixture(t, {
    bindTokenTo: ['ip', 'ua'],
    authorize: () => ({ ttlSec: 5 }),
  });
  const token = await (await postToken(`${base}/archx/token/cat?w=100`)).json();
  const payload = tokenPayloadForTest(token.token);
  assert.equal(payload.exp - payload.iat, 5_000, 'ttlSec from authorize controls token lifetime');
  const ok = await redeemToken(base, token);
  assert.equal(ok.status, 200);
  const token2 = await (await postToken(`${base}/archx/token/cat?w=100`)).json();
  const foreign = await redeemToken(base, token2, { headers: { 'user-agent': 'archx-agent/2' } });
  assert.equal(foreign.status, 403, 'array-form ua binding rejects a different user agent');
});

test('plan v2 is the default everywhere; builder manifest is web-servable', async (t) => {
  const master = await syntheticMaster(96, 64);
  const packed = await scrambleImage(master, { key: 'pv-default', format: 'webp' });
  assert.equal(decodeContainer(packed.bytes).header.pv, 2, 'scrambleImage defaults to plan v2');

  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-pv15-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const inputDir = path.join(root, 'in'); const outputDir = path.join(root, 'out');
  fs.mkdirSync(inputDir);
  fs.writeFileSync(path.join(inputDir, 'a.png'), master);
  const built = await buildArchxAssets({ inputDir, outputDir, key: 'pv-build', encrypt: true, widths: [96] });
  assert.equal(built.manifest.assets.a.planVersion, 2, 'builder defaults to plan v2');
  if (process.platform !== 'win32') {
    const mode = fs.statSync(path.join(outputDir, 'archx-manifest.json')).mode & 0o777;
    assert.equal(mode & 0o044, 0o044, `manifest must be readable by the web server user (got 0${mode.toString(8)})`);
    const stateMode = fs.statSync(path.join(outputDir, '.archx-build-state.json')).mode & 0o777;
    assert.equal(stateMode & 0o077, 0, 'build state stays owner-only');
  }
});

test('detector recovers vertical flips and moderate corner crops; worker API round-trips', async () => {
  const w = 480, h = 320;
  const gradient = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const i = (y * w + x) * 4;
    gradient[i] = (x * 255 / w) | 0; gradient[i + 1] = (y * 255 / h) | 0;
    gradient[i + 2] = (x ^ y) % 256; gradient[i + 3] = 255;
  }
  const marked = embedStegoFingerprint(gradient, w, h, 'buyer-9', { key: 'g15-key', profile: 'robust', strength: 8, layoutVersion: 3 });
  const flippedY = new Uint8Array(marked.length);
  for (let y = 0; y < h; y++) flippedY.set(marked.subarray((h - 1 - y) * w * 4, (h - y) * w * 4), y * w * 4);
  const vflip = detectStegoFingerprint(flippedY, w, h, { key: 'g15-key', profile: 'robust' });
  assert.equal(vflip.found, true, 'vertical flip no longer evades detection');
  assert.equal(vflip.mirrorAxis, 'y');

  const cropW = Math.round(w * 0.88), cropH = Math.round(h * 0.88);
  const cropped = await sharp(Buffer.from(marked), { raw: { width: w, height: h, channels: 4 } })
    .extract({ left: 0, top: 0, width: cropW, height: cropH }).resize(w, h)
    .ensureAlpha().raw().toBuffer();
  const cropHit = detectStegoFingerprint(new Uint8Array(cropped), w, h, { key: 'g15-key', profile: 'robust', searchGeometry: true });
  assert.equal(cropHit.found, true, '88% corner crop recovered by geometry stage 2');

  const viaWorker = await detectStegoFingerprintInWorker(marked, w, h, { key: 'g15-key', profile: 'robust' });
  assert.equal(viaWorker.found, true, 'worker-thread detection round-trips');
  closeStegoDetectWorker();
});

test('CLI parsers never eat positional paths and honour --flag=value', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-cli15-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const input = path.join(root, 'in.png');
  const output = path.join(root, 'out.archx');
  fs.writeFileSync(input, await syntheticMaster(64, 48));
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  execFileSync(process.execPath, [
    path.join(repoRoot, 'server/scramble-cli.js'), input, output,
    '--key', 'cli-key', '--grid=4', '--encrypt=false',
  ], { cwd: repoRoot, stdio: 'pipe' });
  const packed = fs.readFileSync(output);
  const { header } = decodeContainer(packed);
  assert.equal(header.grid, 4, '--grid=4 sets the grid');
  assert.equal(header.encrypted, false, '--encrypt=false disables encryption');
  assert.equal(header.pv, 2);
  // --json before the positional must not consume the file path
  const detectRun = spawnSync(process.execPath, [
    path.join(repoRoot, 'server/detect-stego-cli.js'), '--json', input, '--key', 'k',
  ], { cwd: repoRoot, encoding: 'utf8' });
  const detectOut = detectRun.stdout; // exit code 1 = 'not found' is fine here
  const parsed = JSON.parse(detectOut);
  assert.equal(parsed.file, input, 'detect CLI saw the real suspect path');
});

test('detector recovers rotations, deep crops and reframes via erasure decoding', async () => {
  const w = 480, h = 320;
  const gradient = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const i = (y * w + x) * 4;
    gradient[i] = (x * 255 / w) | 0; gradient[i + 1] = (y * 255 / h) | 0;
    gradient[i + 2] = (x ^ y) % 256; gradient[i + 3] = 255;
  }
  const marked = embedStegoFingerprint(gradient, w, h, 'buyer-9', { key: 'g16-key', profile: 'robust', strength: 8, layoutVersion: 3 });
  const basePipe = () => sharp(Buffer.from(marked), { raw: { width: w, height: h, channels: 4 } });
  const toRaw = async (pipe) => {
    const { data, info } = await pipe.ensureAlpha().raw().toBuffer({ resolveWithObject: true });
    return { buf: new Uint8Array(data), w: info.width, h: info.height };
  };
  const detect = (s, extra = {}) => detectStegoFingerprint(s.buf, s.w, s.h,
    { key: 'g16-key', profile: 'robust', searchGeometry: true, ...extra });

  const rot90 = await toRaw(basePipe().rotate(90));
  const rotHit = detect(rot90);
  assert.equal(rotHit.found, true, '90°-rotated suspect recovered');
  assert.equal(rotHit.rotated, 90);
  const rot270 = await toRaw(basePipe().rotate(270));
  const rotHit2 = detect(rot270);
  assert.equal(rotHit2.found, true, '270°-rotated suspect recovered');
  assert.equal(rotHit2.rotated, 270);

  // 65% center crop: >20 code bits lose every repetition — recoverable
  // only because erased payload bits are enumerated against the
  // recomputed CRC/MAC/marker (erasure decoding, not flip repair).
  const deep = await toRaw(basePipe()
    .extract({ left: 84, top: 56, width: 312, height: 208 }).resize(w, h));
  const deepHit = detect(deep);
  assert.equal(deepHit.found, true, '65% center crop recovered');
  assert.equal(deepHit.erasureDecoded, true, 'recovery path is flagged as erasure-decoded');
  assert.ok(deepHit.erasedBits >= 8, `erased bit count reported (got ${deepHit.erasedBits})`);

  // Aspect reframes (the social-media shapes): 1:1 and 4:5 crops of a
  // 3:2 original need one-axis scale pairs the old tables never tried.
  const square = await toRaw(basePipe().extract({ left: 80, top: 0, width: 320, height: 320 }));
  assert.equal(detect(square).found, true, '1:1 native reframe recovered');
  const portrait = await toRaw(basePipe().extract({ left: 112, top: 0, width: 256, height: 320 }));
  assert.equal(detect(portrait).found, true, '4:5 native reframe recovered');

  // Standard profile: a single erased bit previously blocked the flip
  // corrector behind the coverage pre-gate; the assist is MAC-only.
  const markedStd = embedStegoFingerprint(gradient, w, h, 'buyer-9', { key: 'g16-key', profile: 'standard', strength: 6, layoutVersion: 3 });
  const stdPipe = sharp(Buffer.from(markedStd), { raw: { width: w, height: h, channels: 4 } })
    .extract({ left: 48, top: 32, width: 384, height: 256 }).resize(w, h);
  const stdSuspect = await toRaw(stdPipe);
  const stdHit = detectStegoFingerprint(stdSuspect.buf, stdSuspect.w, stdSuspect.h,
    { key: 'g16-key', profile: 'standard', searchGeometry: true });
  assert.equal(stdHit.found, true, 'standard 80% center crop recovered');

  // Negative control under the full forensic stack (mirrors, rotations,
  // erasure stage): an unmarked suspect must stay not-found.
  const clean = detectStegoFingerprint(gradient, w, h,
    { key: 'g16-key', profile: 'robust', searchGeometry: true });
  assert.equal(clean.found, false, 'unmarked suspect is not manufactured into a match');

  // Rotation probes are opt-out for callers bounding worst-case time.
  const noRot = detect(rot90, { searchRotation: false });
  assert.equal(noRot.found, false, 'searchRotation:false disables rotation recovery');
});

/* ---------- v1.17: plan default, watermark claims, stores, assay, worker ---------- */

test('v1.17 scramble plan default is v2 and round-trips; v1 stays explicit', () => {
  const plan = buildScramblePlan(8, 'plan-default-key');
  assert.equal(plan.version, 2, 'default plan version is 2 (no fixed-origin seam)');
  const px = new Uint8Array(64 * 64 * 4);
  for (let i = 0; i < px.length; i++) px[i] = (i * 7) & 255;
  const scrambled = scramblePixels(px, 64, 64, plan, 'scramble');
  assert.deepEqual(scramblePixels(scrambled, 64, 64, plan, 'unscramble'), px);
  assert.equal(buildScramblePlan(8, 'plan-default-key', 1).version, 1, 'legacy v1 remains available explicitly');
});

test('v1.17 watermark opt-out: nwm claim minted, validated, and honored', async (t) => {
  const { base } = await startArchxFixture(t, {
    allowAnonymous: false,
    authorize: async (req) => req.headers['x-clean']
      ? { viewerId: 'clean-viewer', watermark: false }
      : { viewerId: 'marked-viewer' },
    serverWatermark: 'GLOBAL MARK',
  });
  const cleanToken = await (await postToken(base + '/archx/token/cat', { headers: { 'x-clean': '1' } })).json();
  const cleanClaims = tokenPayloadForTest(cleanToken.token);
  assert.equal(cleanClaims.nwm, 1, 'opt-out is recorded inside the signed claims');
  assert.equal(cleanClaims.wm, undefined, 'opt-out token carries no watermark text');
  const markedToken = await (await postToken(base + '/archx/token/cat')).json();
  const markedClaims = tokenPayloadForTest(markedToken.token);
  assert.equal(markedClaims.wm, 'GLOBAL MARK');
  assert.equal(markedClaims.nwm, undefined);
  const cleanRes = await redeemToken(base, cleanToken, { headers: { 'x-clean': '1' } });
  const markedRes = await redeemToken(base, markedToken);
  assert.equal(cleanRes.status, 200);
  assert.equal(markedRes.status, 200);
  const cleanBytes = new Uint8Array(await cleanRes.arrayBuffer());
  const markedBytes = new Uint8Array(await markedRes.arrayBuffer());
  assert.notDeepEqual(cleanBytes, markedBytes, 'opt-out delivery differs from watermarked delivery');
  // Forged claim shapes are rejected by the claim validator itself.
  const nowMs = Date.now();
  const baseClaims = {
    v: 2, aud: 'archx:image', scope: 'image:view', id: 'cat', n: 'probe-nonce-1234567890',
    iat: nowMs, exp: nowMs + 60_000, w: 320,
  };
  assert.equal(validateTokenClaims({ ...baseClaims, nwm: 1 }, { id: 'cat' }), true, 'well-formed nwm claim validates');
  assert.equal(validateTokenClaims({ ...baseClaims, nwm: 2 }, { id: 'cat' }), false, 'nwm accepts only the exact value 1');
  assert.equal(validateTokenClaims({ ...baseClaims, nwm: 1, wm: 'X' }, { id: 'cat' }), false, 'nwm and wm are mutually exclusive');
});

test('v1.17 variant cache scope separates watermark/forensic variants end-to-end', async (t) => {
  const { base } = await startArchxFixture(t, {
    authorize: async (req) => ({ viewerId: String(req.headers['x-who'] || 'a'), watermark: String(req.headers['x-who'] || 'a') }),
    forensicScope: 'image',
  });
  const take = async (who) => {
    const tok = await (await postToken(base + '/archx/token/cat', { headers: { 'x-who': who } })).json();
    const res = await redeemToken(base, tok, { headers: { 'x-who': who } });
    assert.equal(res.status, 200);
    return new Uint8Array(await res.arrayBuffer());
  };
  const first = await take('ALPHA');
  const second = await take('BRAVO');
  const again = await take('ALPHA');
  assert.notDeepEqual(first, second, 'different watermark text must not share a cached finished variant');
  assert.deepEqual(again, first, 'same variant scope reuses identical bytes');
});

test('v1.17 BoundedTtlSet reports live evictions only', () => {
  const evicted = [];
  const set = new BoundedTtlSet({
    maxEntries: 2, cleanupIntervalMs: 0,
    onLiveEvict: (count) => evicted.push(count),
  });
  const now = Date.now();
  assert.equal(set.claim('a', now + 60_000), true);
  assert.equal(set.claim('stale', now - 1), false, 'already-expired claims are refused');
  assert.equal(set.claim('b', now + 60_000), true);
  assert.equal(set.claim('c', now + 60_000), true, 'third live claim forces FIFO eviction of entry a');
  assert.deepEqual(evicted, [1], 'exactly one live eviction is reported, as a count');
  set.close();
});

test('v1.17 production audit blocks tiny replay stores; AVIF/memory profiles normalize', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-v17-audit-'));
  fs.writeFileSync(path.join(dir, 'cat.jpg'), await syntheticMaster());
  const base = {
    secret: TEST_SECRET, imagesDir: dir, authorize: async () => ({ viewerId: 'auditor' }),
    stateStore: createMemoryStateStore(),
  };
  const tiny = auditArchxProductionConfig({ ...base, oneTimeTokenMaxEntries: 500 });
  assert.ok(tiny.blockers.some((b) => /oneTimeTokenMaxEntries/.test(b)), 'sub-10k replay store is a named blocker');
  const fine = auditArchxProductionConfig(base);
  assert.ok(!fine.blockers.some((b) => /oneTimeTokenMaxEntries/.test(b)));

  const clamped = createArchxMiddleware({ ...base, processing: { avifEffort: 6 } });
  assert.equal(clamped.configAudit.summary.processing.avifEffort, 2, 'request-path AVIF effort clamps to 2');
  assert.equal(clamped.configAudit.summary.oneTimeTokenMaxEntries, 250000, 'standard profile default replay store');
  clamped.close();
  const allowed = createArchxMiddleware({ ...base, processing: { avifEffort: 6, allowSlowRequestAvif: true } });
  assert.equal(allowed.configAudit.summary.processing.avifEffort, 6, 'explicit opt-in preserves high effort');
  allowed.close();
  const compact = createArchxMiddleware({ ...base, memoryProfile: 'compact' });
  assert.equal(compact.configAudit.summary.oneTimeTokenMaxEntries, 50000, 'compact profile scales store defaults down');
  compact.close();
  assert.throws(() => createArchxMiddleware({ ...base, memoryProfile: 'tiny' }), /memoryProfile/);
});

test('v1.17 transpose (D4 diagonal) suspects are recovered and labelled', async () => {
  const w = 480, h = 320;
  const gradient = new Uint8Array(w * h * 4);
  for (let i = 0; i < w * h; i++) {
    const x = i % w, y = (i / w) | 0;
    gradient[i * 4] = (x * 3 + y) & 255; gradient[i * 4 + 1] = (x + y * 5) & 255;
    gradient[i * 4 + 2] = 128 + ((x ^ y) & 63); gradient[i * 4 + 3] = 255;
  }
  const marked = embedStegoFingerprint(gradient, w, h, 'buyer-d4', { key: 'd4-key', profile: 'robust', strength: 6, layoutVersion: 3 });
  const transpose = (buf, bw, bh, anti) => {
    // Mirrors the detector's own transposePixels: both are self-inverse.
    const out = new Uint8Array(bw * bh * 4);
    for (let y = 0; y < bh; y++) for (let x = 0; x < bw; x++) {
      const si = (y * bw + x) * 4;
      const di = (anti ? ((bw - 1 - x) * bh + (bh - 1 - y)) : (x * bh + y)) * 4;
      for (let c = 0; c < 4; c++) out[di + c] = buf[si + c];
    }
    return out;
  };
  for (const [anti, label] of [[false, 'main'], [true, 'anti']]) {
    const suspect = transpose(marked, w, h, anti);
    const hit = detectStegoFingerprint(suspect, h, w, { key: 'd4-key', profile: 'robust', searchGeometry: true });
    assert.equal(hit.found, true, `${label} transpose recovered`);
    assert.equal(hit.transposed, label);
    assert.equal(hit.fingerprint, stegoFingerprint('buyer-d4'));
  }
});

test('v1.17 tilt search deskews small-angle rotations', () => {
  const w = 640, h = 400;
  const gradient = new Uint8Array(w * h * 4);
  for (let i = 0; i < w * h; i++) {
    const x = i % w, y = (i / w) | 0;
    gradient[i * 4] = 60 + ((x * 5 + y * 2) % 160); gradient[i * 4 + 1] = 80 + ((x + y * 3) % 140);
    gradient[i * 4 + 2] = 90 + (((x >> 1) ^ (y >> 1)) % 120); gradient[i * 4 + 3] = 255;
  }
  const marked = embedStegoFingerprint(gradient, w, h, 'tilt-buyer', { key: 'tilt-key', profile: 'robust', strength: 7, layoutVersion: 3 });
  // Rotate +2 degrees clockwise in place (bilinear, edge-replicated):
  // the phone-straighten shape the deskew search targets.
  const rad = (2 * Math.PI) / 180, cos = Math.cos(rad), sin = Math.sin(rad);
  const cx = (w - 1) / 2, cy = (h - 1) / 2;
  const tilted = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) for (let x = 0; x < w; x++) {
    const dx = x - cx, dy = y - cy;
    const sx = Math.min(w - 1.001, Math.max(0, cx + dx * cos + dy * sin));
    const sy = Math.min(h - 1.001, Math.max(0, cy - dx * sin + dy * cos));
    const x0 = sx | 0, y0 = sy | 0, fx = sx - x0, fy = sy - y0;
    const o = (y * w + x) * 4;
    for (let c = 0; c < 4; c++) {
      const p00 = marked[(y0 * w + x0) * 4 + c], p10 = marked[(y0 * w + x0 + 1) * 4 + c];
      const p01 = marked[((y0 + 1) * w + x0) * 4 + c], p11 = marked[((y0 + 1) * w + x0 + 1) * 4 + c];
      tilted[o + c] = (p00 * (1 - fx) + p10 * fx) * (1 - fy) + (p01 * (1 - fx) + p11 * fx) * fy;
    }
  }
  const noTilt = detectStegoFingerprint(tilted, w, h, { key: 'tilt-key', profile: 'robust', searchGeometry: true });
  assert.equal(noTilt.found, false, 'axis-aligned search cannot register a 2-degree tilt');
  const hit = detectStegoFingerprint(tilted, w, h, { key: 'tilt-key', profile: 'robust', searchGeometry: true, searchTilt: true });
  assert.equal(hit.found, true, 'deskew search recovers the mark');
  assert.equal(hit.fingerprint, stegoFingerprint('tilt-buyer'));
  assert.ok(Math.abs(hit.deskewed ?? 0) >= 0.75 && Math.abs(hit.deskewed ?? 0) <= 3,
    `reported tilt in the applied range (got ${hit.deskewed})`);
});

test('v1.17 collusion assay ranks averaging participants above innocents', () => {
  const w = 640, h = 480;
  const base = new Uint8Array(w * h * 4);
  for (let i = 0; i < w * h; i++) {
    const x = i % w, y = (i / w) | 0;
    base[i * 4] = 90 + ((x * 7 + y) % 120); base[i * 4 + 1] = 70 + ((x + y * 5) % 130);
    base[i * 4 + 2] = 110 + ((x ^ y) % 90); base[i * 4 + 3] = 255;
  }
  const opts = { key: 'assay-key', profile: 'robust', strength: 6, layoutVersion: 3 };
  const a = embedStegoFingerprint(base, w, h, 'alice', opts);
  const b = embedStegoFingerprint(base, w, h, 'bob', opts);
  const avg = new Uint8Array(w * h * 4);
  for (let i = 0; i < avg.length; i++) avg[i] = (a[i] + b[i]) >> 1;
  assert.equal(detectStegoFingerprint(avg, w, h, { key: 'assay-key', profile: 'robust' }).found, false,
    'the averaged copy itself does not decode at bit level');
  const assay = assayStegoCollusion(avg, w, h, [
    { id: 'alice', payload: 'alice' }, { id: 'bob', payload: 'bob' },
    { id: 'carol', payload: 'carol' }, { id: 'dave', payload: 'dave' },
  ], { key: 'assay-key', profile: 'robust' });
  const top2 = assay.results.slice(0, 2).map((r) => r.id).sort();
  assert.deepEqual(top2, ['alice', 'bob'], 'both colluders rank at the top');
  assert.ok(assay.results[1].zScore > assay.results[2].zScore + 2, 'separation from innocents is material');
  assert.throws(() => assayStegoCollusion(avg, w, h, [], { key: 'k' }), /candidates/);
});

test('v1.17 detect worker: batch screening, queue cap, config validation', async (t) => {
  t.after(() => closeStegoDetectWorker());
  const w = 480, h = 320;
  const base = new Uint8Array(w * h * 4);
  for (let i = 0; i < w * h; i++) {
    const x = i % w, y = (i / w) | 0;
    base[i * 4] = 80 + ((x * 3 + y) % 130); base[i * 4 + 1] = 90 + ((x + y * 7) % 110);
    base[i * 4 + 2] = 70 + ((x ^ y) % 120); base[i * 4 + 3] = 255;
  }
  const marked = embedStegoFingerprint(base, w, h, 'worker-buyer', { key: 'right-key', profile: 'robust', strength: 6 });
  const batch = await batchDetectStegoInWorker(marked, w, h, ['k1', 'k2', 'right-key', 'k4'], { profile: 'robust' });
  assert.equal(batch.length, 4);
  assert.equal(batch.find((e) => e.key === 'right-key').result.found, true, 'batch screen identifies the marking key');
  assert.ok(batch.filter((e) => e.escalated).length <= 2, 'full searches stay bounded by escalateTop');

  assert.throws(() => configureStegoDetectWorker({ maxPending: 0 }), /maxPending/);
  const cfg = configureStegoDetectWorker({ maxPending: 1 });
  assert.equal(cfg.maxPending, 1);
  const slow = detectStegoFingerprintInWorker(base, w, h, { key: 'none', profile: 'robust', searchGeometry: true });
  await assert.rejects(
    detectStegoFingerprintInWorker(marked, w, h, { key: 'right-key', profile: 'robust' }),
    /queue is full/, 'cap rejects immediately instead of growing an unbounded queue',
  );
  await slow;
  configureStegoDetectWorker({ maxPending: 64 });
});

/* ---------- v1.18: saturation policy, preview policy, worker budgets, ownership ---------- */

test('v1.18 crypto known-answer vectors and AES-GCM nonce uniqueness', async () => {
  const hex = (bytes) => Buffer.from(bytes).toString('hex');
  const enc = new TextEncoder();
  // FIPS 180-4 examples
  assert.equal(hex(sha256Bytes(enc.encode(''))),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(hex(sha256Bytes(enc.encode('abc'))),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(hex(sha256Bytes(enc.encode('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))),
    '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
  // RFC 4231 HMAC-SHA-256 cases 1, 2, and 6 (key longer than block size)
  assert.equal(hex(hmacSha256Bytes(new Uint8Array(20).fill(0x0b), enc.encode('Hi There'))),
    'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
  assert.equal(hex(hmacSha256Bytes(enc.encode('Jefe'), enc.encode('what do ya want for nothing?'))),
    '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
  assert.equal(hex(hmacSha256Bytes(new Uint8Array(131).fill(0xaa),
    enc.encode('Test Using Larger Than Block-Size Key - Hash Key First'))),
    '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54');
  // Cross-check the pure implementation against Node on random inputs
  for (let i = 0; i < 24; i++) {
    const msg = crypto.randomBytes(i * 37 % 512);
    assert.equal(hex(sha256Bytes(msg)), crypto.createHash('sha256').update(msg).digest('hex'));
    const key = crypto.randomBytes(1 + (i * 13) % 100);
    assert.equal(hex(hmacSha256Bytes(key, msg)), crypto.createHmac('sha256', key).update(msg).digest('hex'));
  }
  // AES-GCM IVs never repeat under one key (nonce reuse would be fatal)
  const aesKey = generateKeyBase64();
  const ivs = new Set();
  for (let i = 0; i < 200; i++) {
    const { cipher, iv } = await encryptPayload(new Uint8Array([1, 2, 3, i & 255]), aesKey);
    ivs.add(iv);
    assert.ok(cipher.length > 4);
  }
  assert.equal(ivs.size, 200, 'every encryption used a distinct IV');
});

test('v1.18 legacy marks (layout v1/v2, CRC tag) still decode under auto settings', () => {
  const w = 480, h = 320;
  const gradient = new Uint8Array(w * h * 4);
  for (let i = 0; i < w * h; i++) {
    const x = i % w, y = (i / w) | 0;
    gradient[i * 4] = (x * 3 + y) & 255; gradient[i * 4 + 1] = (x + y * 5) & 255;
    gradient[i * 4 + 2] = 128 + ((x ^ y) & 63); gradient[i * 4 + 3] = 255;
  }
  for (const [layoutVersion, legacyCode, scheme] of [
    [1, true, 'crc'], [2, true, 'crc'], [1, false, 'mac'], [2, false, 'mac'], [3, false, 'mac'],
  ]) {
    const marked = embedStegoFingerprint(gradient, w, h, 'legacy-buyer', {
      key: 'legacy-key', profile: 'robust', strength: 7, layoutVersion, legacyCode,
    });
    const hit = detectStegoFingerprint(marked, w, h, { key: 'legacy-key', profile: 'auto' });
    assert.equal(hit.found, true, `layout v${layoutVersion} legacyCode=${legacyCode} decodes`);
    assert.equal(hit.tagScheme, scheme);
    assert.equal(hit.fingerprint, stegoFingerprint('legacy-buyer'));
  }
});

test('v1.18 replay saturation: strict rejects new claims, evict keeps availability', async () => {
  const now = Date.now();
  const strictSet = new BoundedTtlSet({ maxEntries: 2, cleanupIntervalMs: 0, saturation: 'strict' });
  assert.equal(strictSet.claim('a', now + 60000), true);
  assert.equal(strictSet.claim('b', now + 60000), true);
  assert.equal(strictSet.claim('c', now + 60000), false, 'strict: saturated store rejects new claims');
  assert.equal(strictSet.claim('a', now + 60000), false, 'strict: earlier claim was NOT evicted (replay still blocked)');
  assert.equal(strictSet.stats().saturationRejections, 1);
  assert.equal(strictSet.stats().liveEvictions, 0);
  strictSet.close();

  const evictSet = new BoundedTtlSet({ maxEntries: 2, cleanupIntervalMs: 0 });
  assert.equal(evictSet.claim('a', now + 60000), true);
  assert.equal(evictSet.claim('b', now + 60000), true);
  assert.equal(evictSet.claim('c', now + 60000), true, 'evict: availability preserved');
  assert.equal(evictSet.stats().liveEvictions, 1);
  evictSet.close();

  const strictStore = createMemoryStateStore({ maxEntries: 2, cleanupIntervalMs: 0, saturation: 'strict' });
  assert.equal(await strictStore.claimOnce('nonce:1', 60000), true);
  assert.equal(await strictStore.claimOnce('nonce:2', 60000), true);
  assert.equal(await strictStore.claimOnce('nonce:3', 60000), false);
  assert.equal(strictStore.stats().replaySets.nonce.saturation, 'strict');
  strictStore.close();
});

test('v1.18 strict replay mode + preview fraction are wired through middleware and audit', async (t) => {
  const { base, handler } = await startArchxFixture(t, {
    authorize: async () => ({ viewerId: 'v18' }),
    replaySaturation: 'strict',
    maxWidthFraction: 0.5,
    widthBuckets: [],
  }, { cat: [640, 420] });
  assert.equal(handler.configAudit.summary.replaySaturation, 'strict');
  const tok = await (await postToken(base + '/archx/token/cat?w=640')).json();
  const claims = tokenPayloadForTest(tok.token);
  assert.ok(claims.w <= 320, `mint clamped to half the master width (got ${claims.w})`);
  const res = await redeemToken(base, tok);
  assert.equal(res.status, 200);
  const header = decodeContainer(new Uint8Array(await res.arrayBuffer())).header;
  assert.ok(header.w <= 320, `delivered derivative respects the fraction (got ${header.w})`);
  const stats = handler.stats();
  assert.equal(stats.replaySets?.nonce?.saturation, 'strict', 'live replay-store counters are exposed');
  assert.equal(stats.replaySets?.nonce?.maxEntries, 250000);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-v18-preview-'));
  fs.writeFileSync(path.join(dir, 'cat.jpg'), await syntheticMaster());
  const warned = auditArchxServerConfig({
    secret: TEST_SECRET, imagesDir: dir, authorize: async () => ({ viewerId: 'x' }),
    lossless: true, maxWidthCap: 4096,
  });
  assert.ok(warned.warnings.some((w) => /FULL-RESOLUTION/.test(w)), 'audit warns about full-resolution lossless delivery');
  const quiet = auditArchxServerConfig({
    secret: TEST_SECRET, imagesDir: dir, authorize: async () => ({ viewerId: 'x' }),
    lossless: true, maxWidthCap: 4096, maxWidthFraction: 0.6,
  });
  assert.ok(!quiet.warnings.some((w) => /FULL-RESOLUTION/.test(w)), 'fraction policy silences the warning deliberately');
  assert.throws(() => createArchxMiddleware({
    secret: TEST_SECRET, imagesDir: dir, authorize: async () => ({ viewerId: 'x' }), maxWidthFraction: 1.5,
  }), /maxWidthFraction/);
});

test('v1.18 entitlement can only tighten: width downgrade between mint and redemption applies', async (t) => {
  let cap = 640;
  const { base } = await startArchxFixture(t, {
    authorize: async () => ({ viewerId: 'shrink', maxWidth: cap }),
    widthBuckets: [],
  }, { cat: [640, 420] });
  const tok = await (await postToken(base + '/archx/token/cat?w=640')).json();
  assert.equal(tokenPayloadForTest(tok.token).w, 640);
  cap = 200; // plan downgraded after issuance
  const res = await redeemToken(base, tok);
  assert.equal(res.status, 200);
  const header = decodeContainer(new Uint8Array(await res.arrayBuffer())).header;
  assert.ok(header.w <= 200, `redemption honors the CURRENT tighter cap (got ${header.w})`);
});

test('v1.18 mixed batch: allowed, denied, unknown, and malformed items are partitioned', async (t) => {
  const { base } = await startArchxFixture(t, {
    authorize: async (req, id) => (id === 'dog' ? null : { viewerId: 'batchy' }),
  }, { cat: [320, 240], dog: [320, 240] });
  const res = await fetch(base + '/archx/tokens', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-archx-request': 'token' },
    body: JSON.stringify({
      items: [
        { ref: 'ok', id: 'cat', w: 200 },
        { ref: 'denied', id: 'dog', w: 200 },
        { ref: 'ghost', id: 'ghost', w: 200 },
        { ref: 'bad', id: 'cat', w: 200, evil: true },
      ],
    }),
  });
  assert.equal(res.status, 200);
  const batch = await res.json();
  assert.ok(batch.tokens.ok?.token, 'authorized item minted');
  assert.equal(batch.tokens.denied, undefined);
  assert.equal(batch.errors.denied?.status, 403, 'denied item reports 403');
  assert.equal(batch.errors.ghost?.status, 404, 'unknown image reports 404');
  assert.equal(batch.errors.bad?.status, 400, 'malformed item reports 400');
});

test('v1.18 proof-of-possession negatives: wrong path and expired proof are rejected', async (t) => {
  const { base } = await startArchxFixture(t, {
    authorize: async () => ({ viewerId: 'pop' }),
    proofOfPossession: 'required',
    oneTimeTokens: false,
  });
  const proofKey = makeProofKeyForTest();
  const mintRes = await postToken(base + '/archx/token/cat?w=160', {
    headers: { 'x-archx-proof-key': proofKey.header },
  });
  assert.equal(mintRes.status, 200);
  const minted = await mintRes.json();
  const wrongPath = makeProofForTest(proofKey, minted.token, { target: '/archx/i/dog' });
  assert.equal((await fetch(base + minted.cleanUrl, {
    headers: { 'x-archx-token': minted.token, 'x-archx-proof': wrongPath },
  })).status, 403, 'proof bound to a different path is rejected');
  const expired = makeProofForTest(proofKey, minted.token, { iat: Date.now() - 120000, exp: Date.now() - 60000 });
  assert.equal((await fetch(base + minted.cleanUrl, {
    headers: { 'x-archx-token': minted.token, 'x-archx-proof': expired },
  })).status, 403, 'expired proof is rejected');
  const good = makeProofForTest(proofKey, minted.token);
  assert.equal((await fetch(base + minted.cleanUrl, {
    headers: { 'x-archx-token': minted.token, 'x-archx-proof': good },
  })).status, 200, 'fresh correct proof still passes after the failures');
});

test('v1.18 worker budgets: RGBA validation, pixel cap, queued-byte cap, batch key bounds', async (t) => {
  t.after(() => closeStegoDetectWorker());
  const w = 320, h = 240;
  const rgb = new Uint8Array(w * h * 3);
  await assert.rejects(
    detectStegoFingerprintInWorker(rgb, w, h, { key: 'k' }),
    /RGBA w\*h\*4/, 'RGB-sized buffers are rejected before any copy',
  );
  const rgba = new Uint8Array(w * h * 4).fill(120);
  configureStegoDetectWorker({ maxPixels: 4096 });
  await assert.rejects(
    detectStegoFingerprintInWorker(rgba, w, h, { key: 'k' }),
    /at most 4096 pixels/, 'pixel cap is enforced pre-queue',
  );
  configureStegoDetectWorker({ maxPixels: 50_000_000, maxPending: 8, maxQueuedBytes: rgba.length + 1000 });
  const slow = detectStegoFingerprintInWorker(rgba, w, h, { key: 'none', profile: 'robust', searchGeometry: true, searchTilt: true });
  await assert.rejects(
    detectStegoFingerprintInWorker(rgba, w, h, { key: 'k' }),
    /queued-byte budget/, 'second job exceeds the total queued-byte budget',
  );
  await slow;
  configureStegoDetectWorker({ maxQueuedBytes: 512 * 1024 * 1024 });
  await assert.rejects(
    batchDetectStegoInWorker(rgba, w, h, ['x'.repeat(1025)], {}),
    /1024 chars/, 'oversized batch keys are rejected',
  );
  assert.equal(configureStegoDetectWorker().queuedBytes, 0, 'byte accounting drains to zero');
});

test('v1.18 detector maxTimeMs bounds forensic search and reports timedOut', async () => {
  const master = await syntheticMaster(640, 420);
  const { data, info } = await sharp(master).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const clean = new Uint8Array(data);
  const t0 = Date.now();
  const bounded = detectStegoFingerprint(clean, info.width, info.height, {
    key: 'none', profile: 'robust', searchGeometry: true, maxTimeMs: 900,
  });
  const elapsed = Date.now() - t0;
  assert.equal(bounded.found, false);
  assert.equal(bounded.timedOut, true, 'budget expiry is reported, not silent');
  assert.ok(elapsed < 6000, `returned near the budget (took ${elapsed}ms)`);
  const marked = embedStegoFingerprint(clean, info.width, info.height, 'budget-buyer', { key: 'bk', profile: 'robust', strength: 6 });
  const hit = detectStegoFingerprint(marked, info.width, info.height, {
    key: 'bk', profile: 'robust', searchGeometry: true, maxTimeMs: 900,
  });
  assert.equal(hit.found, true, 'native hits are unaffected by the budget');
  assert.ok(!hit.timedOut);
});

test('v1.18 ownership: signed claim in metadata verifies a stripped leaked copy', async (t) => {
  const keyPair = generateOwnershipKeyPair();
  const master = await syntheticMaster(640, 420);
  const result = await scrambleImage(master, {
    key: 'own-scramble', format: 'png', lossless: true, maxWidth: 640,
    stegoPayload: 'ORDER-OWN-1', stegoKey: 'own-stego', stegoProfile: 'robust', stegoStrength: 7,
    ownership: { owner: 'Studio Example', imageId: 'cat', privateKey: keyPair.privateKey },
  });
  assert.ok(result.ownershipToken?.startsWith('ARCHX1.'), 'claim token issued');
  const { payload } = decodeContainer(result.bytes);
  assert.equal(extractOwnershipClaim(payload), result.ownershipToken, 'claim rides in payload metadata');
  assert.equal(verifyOwnershipClaim(result.ownershipToken, keyPair.publicKey).valid, true);
  const tampered = result.ownershipToken.slice(0, -4) + 'AAAA';
  assert.equal(verifyOwnershipClaim(tampered, keyPair.publicKey).valid, false, 'tampered signature rejected');

  // Simulate the leak: display (unscramble) then screenshot-reencode (metadata gone).
  const restored = await unscrambleImage(Buffer.from(payload), {
    grid: result.header.grid, key: 'own-scramble', w: result.header.w, h: result.header.h, planVersion: result.header.pv,
  });
  assert.equal(extractOwnershipClaim(restored), null, 'leaked copy has no metadata claim');
  const report = await verifyOwnership(restored, {
    publicKey: keyPair.publicKey, stegoKey: 'own-stego', claim: result.ownershipToken,
  });
  assert.equal(report.verdict, 'verified', JSON.stringify(report));
  assert.equal(report.owner, 'Studio Example');
  assert.equal(report.stego.matchesClaim, true);

  // Middleware: audit summarizes ownership without leaking key material.
  const { handler } = await startArchxFixture(t, {
    authorize: async () => ({ viewerId: 'owner-viewer' }),
    ownership: { owner: 'Studio Example', privateKey: keyPair.privateKey },
  });
  const summary = handler.configAudit.summary;
  assert.equal(summary.ownership.owner, 'Studio Example');
  assert.equal(summary.ownership.signed, true);
  assert.equal(JSON.stringify(summary).includes('PRIVATE KEY'), false, 'audit never echoes the private key');
});

test('v1.18 documented CLI flow: protect with separate keys, detect, verify ownership', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-v18-cli-'));
  const masterPath = path.join(dir, 'photo.jpg');
  fs.writeFileSync(masterPath, await syntheticMaster(640, 420));
  const keyPair = generateOwnershipKeyPair();
  const pubPath = path.join(dir, 'owner.pub.pem');
  fs.writeFileSync(pubPath, keyPair.publicKey);
  const env = {
    ...process.env,
    ARCHX_SCRAMBLE_KEY: 'readme-scramble-secret-value-0001',
    ARCHX_STEGO_KEY: 'readme-stego-secret-DIFFERENT-0002',
    ARCHX_OWNERSHIP_PRIVATE_KEY: keyPair.privateKey,
  };
  const repoRoot = path.resolve('.');
  const protect = spawnSync(process.execPath, [
    path.join(repoRoot, 'server/scramble-cli.js'), masterPath, path.join(dir, 'photo.archx'),
    '--stego', 'ORDER-README-1', '--stego-profile', 'robust',
    '--ownership-owner', 'Studio Example',
  ], { env, encoding: 'utf8' });
  assert.equal(protect.status, 0, protect.stderr || protect.stdout);
  assert.match(protect.stdout, /ownership claim embedded/);

  const container = decodeContainer(new Uint8Array(fs.readFileSync(path.join(dir, 'photo.archx'))));
  const restored = await unscrambleImage(Buffer.from(container.payload), {
    grid: container.header.grid, key: env.ARCHX_SCRAMBLE_KEY,
    w: container.header.w, h: container.header.h, planVersion: container.header.pv,
  });
  const suspectPath = path.join(dir, 'suspect.png');
  fs.writeFileSync(suspectPath, restored);

  const detect = spawnSync(process.execPath, [
    path.join(repoRoot, 'server/detect-stego-cli.js'), suspectPath,
    '--expect', 'ORDER-README-1', '--profile', 'robust', '--json',
  ], { env, encoding: 'utf8' });
  assert.equal(detect.status, 0, detect.stderr || detect.stdout);
  assert.equal(JSON.parse(detect.stdout).found, true);

  const verify = spawnSync(process.execPath, [
    path.join(repoRoot, 'server/detect-stego-cli.js'), suspectPath,
    '--verify-ownership', '--ownership-pubkey', pubPath,
    '--claim', extractOwnershipClaim(new Uint8Array(container.payload)),
    '--json',
  ], { env, encoding: 'utf8' });
  assert.equal(verify.status, 0, verify.stderr || verify.stdout);
  assert.equal(JSON.parse(verify.stdout).ownership.verdict, 'verified');
});

/* ---------- v1.19: review-#8 regressions + new layers ---------- */

test('v1.19 BoundedTtlSet mixed-TTL saturation: expired tail frees space before any live eviction or strict rejection', () => {
  // The review-#8 disorder case: thousands of LIVE long-TTL heads with a
  // few EXPIRED short-TTL entries at the back. The budget-bounded head
  // scan (1024 + maxEntries/64) cannot reach the tail, so pass 2 (full
  // expired sweep) must free the space. Old behavior: strict rejected a
  // legitimate claim (false saturation) and evict dropped live claims.
  const t0 = 1_000_000;
  for (const saturation of ['strict', 'evict']) {
    const set = new BoundedTtlSet({ maxEntries: 3002, cleanupIntervalMs: 0, saturation });
    for (let i = 0; i < 3000; i++) assert.equal(set.claim('live-' + i, t0 + 1e9, t0), true);
    assert.equal(set.claim('short-1', t0 + 10, t0), true);
    assert.equal(set.claim('short-2', t0 + 10, t0), true);
    assert.equal(set.size, 3002, 'set is full');
    // t0+100: the two tail entries are expired; 3000 heads still live.
    assert.equal(set.claim('new-claim', t0 + 1e9, t0 + 100), true, `${saturation}: expired tail must free space`);
    assert.equal(set.liveEvictions, 0, `${saturation}: no live claim was evicted to make room`);
    assert.equal(set.has('live-0', t0 + 100), true, `${saturation}: oldest live claim survives`);
    assert.equal(set.has('short-1', t0 + 100), false, `${saturation}: expired claim is not live`);
    assert.equal(set.has('new-claim', t0 + 100), true);
    set.close();
  }
  // has() is a non-mutating peek: expired entries report false but the
  // map is untouched (challenge clearances rely on this).
  const peek = new BoundedTtlSet({ maxEntries: 4, cleanupIntervalMs: 0 });
  assert.equal(peek.claim('a', 2000, 1000), true);
  assert.equal(peek.has('a', 3000), false);
  assert.equal(peek.size, 1, 'has() must not delete');
  assert.equal(peek.has('missing', 1000), false);
  peek.close();
});

test('v1.19 maxWidthFraction fails closed: invalid values rejected, fraction caps the delivered width', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-v119-frac-'));
  fs.writeFileSync(path.join(dir, 'cat.jpg'), await syntheticMaster(640, 400));
  for (const bad of [1.5, 0, -0.5, NaN, Infinity, '0.5']) {
    const audit = auditArchxServerConfig({
      secret: TEST_SECRET, imagesDir: dir, allowAnonymous: true, maxWidthFraction: bad,
    });
    assert.equal(audit.ok, false, `maxWidthFraction ${String(bad)} must be rejected`);
    assert.ok(audit.issues.some((issue) => /maxWidthFraction/.test(issue)));
  }
  const { base } = await startArchxFixture(t, {
    authorize: async () => ({ viewerId: 'frac-viewer' }),
    maxWidthFraction: 0.5,
  }, { cat: [640, 400] });
  const mint = await postToken(base + '/archx/token/cat?w=640');
  assert.equal(mint.status, 200, await mint.clone().text().catch(() => ''));
  const tokenResponse = await mint.json();
  const redeemed = await redeemToken(base, tokenResponse);
  assert.equal(redeemed.status, 200);
  const container = decodeContainer(new Uint8Array(await redeemed.arrayBuffer()));
  assert.ok(container.header.w <= 320, `fraction 0.5 of a 640px master caps delivery at 320 (got ${container.header.w})`);
});

test('v1.19 step-up challenge gates single AND batch mints; a passed proof clears the subject', async (t) => {
  const { base } = await startArchxFixture(t, {
    authorize: async () => ({ viewerId: 'challenged-viewer' }),
    abuseDetection: { distinctImages: 1, windowMs: 60_000, action: 'challenge' },
    challenge: { verify: async (req, proof) => proof === 'good-proof' },
  }, { cat: [320, 240], dog: [320, 240], bird: [320, 240] });

  const first = await postToken(base + '/archx/token/cat?w=200');
  assert.equal(first.status, 200, 'first distinct image is under the abuse threshold');

  const gated = await postToken(base + '/archx/token/dog?w=200');
  assert.equal(gated.status, 403, 'second distinct image steps up to a challenge');
  assert.equal(gated.headers.get('x-archx-challenge'), 'required');

  // Batch must not bypass the gate: the same subject, still uncleared.
  const batch = await fetch(base + '/archx/tokens', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-archx-request': 'token' },
    body: JSON.stringify({ items: [{ ref: 'doggy', id: 'dog', w: 200 }] }),
  });
  assert.equal(batch.status, 200);
  const batchJson = await batch.json();
  assert.equal(batchJson.tokens.doggy, undefined, 'batch mint is challenge-gated too');
  assert.equal(batchJson.errors.doggy?.status, 403);

  const wrong = await postToken(base + '/archx/token/dog?w=200', { headers: { 'x-archx-challenge': 'bogus' } });
  assert.equal(wrong.status, 403, 'failing proof stays gated');

  const passed = await postToken(base + '/archx/token/dog?w=200', { headers: { 'x-archx-challenge': 'good-proof' } });
  assert.equal(passed.status, 200, 'passing proof mints');

  const cleared = await postToken(base + '/archx/token/bird?w=200');
  assert.equal(cleared.status, 200, 'clearance covers subsequent mints inside its TTL');
});

test('v1.19 challenge config fails closed: action challenge without a verifier is rejected', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-v119-chal-'));
  fs.writeFileSync(path.join(dir, 'cat.jpg'), await syntheticMaster());
  assert.throws(
    () => createArchxMiddleware({
      secret: TEST_SECRET, imagesDir: dir, allowAnonymous: true,
      abuseDetection: { distinctImages: 5, windowMs: 60000, action: 'challenge' },
    }),
    /challenge\.verify/,
    'a challenge gate with no verifier must not silently become allow-all',
  );
});

test('v1.19 issuance log: chain verifies; edits, reordering and deletion are detected', () => {
  const secret = 'issuance-log-secret-0123456789';
  assert.throws(() => createIssuanceLog({ secret: 'short' }), /at least 16 bytes/);
  const log = createIssuanceLog({ secret });
  log.append({ imageId: 'cat', viewerHash: 'v1', fingerprint: 'abc123' });
  log.append({ imageId: 'dog', viewerHash: 'v2', fingerprint: 'def456' });
  assert.equal(log.size, 2);
  assert.equal(log.verify().ok, true);
  assert.equal(verifyIssuanceChain(log.entries(), secret).ok, true);

  const edited = log.entries().map((e) => ({ ...e, record: { ...e.record } }));
  edited[0] = { ...edited[0], record: { ...edited[0].record, viewerHash: 'someone-else' } };
  const editCheck = verifyIssuanceChain(edited, secret);
  assert.equal(editCheck.ok, false, 'rewriting history breaks the chain');
  assert.equal(editCheck.badIndex, 0);
  assert.equal(editCheck.reason, 'mac-mismatch');

  const entries = log.entries();
  assert.equal(verifyIssuanceChain([entries[1], entries[0]], secret).ok, false, 'reordering breaks the chain');
  assert.equal(verifyIssuanceChain([entries[1]], secret).ok, false, 'deleting the first entry breaks the chain');
  assert.throws(() => createIssuanceLog({ secret, entries: edited }), /chain verification failed/);

  const reloaded = createIssuanceLog({ secret, entries: log.entries() });
  assert.equal(reloaded.head(), log.head());
  reloaded.append({ imageId: 'bird', viewerHash: 'v3', fingerprint: 'ghi789' });
  assert.equal(reloaded.verify().ok, true, 'a reloaded log keeps chaining');
});

test('v1.19 assayStegoEmbed measures the real embedder and self-verifies recovery', async () => {
  const master = await syntheticMaster(640, 420);
  const { data, info } = await sharp(master).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const report = assayStegoEmbed(new Uint8Array(data), info.width, info.height, {
    key: 'assay-test-key', profile: 'robust', strength: 6, verify: true,
  });
  assert.ok(report.psnr > 15 && report.psnr < 60, `measured PSNR is a sane number (${report.psnr})`);
  assert.ok(report.maxChannelDelta >= 1 && report.maxChannelDelta <= 32, 'embed actually moved pixels, bounded');
  assert.ok(['photo-textured', 'flat-minimal', 'binary-graphic'].includes(report.contentClass));
  assert.notEqual(report.verifiedAtStrength, null, 'detector recovers a fresh mark at some strength');
  assert.equal(report.recommendedStrength, report.verifiedAtStrength);
  assert.ok(Array.isArray(report.warnings));

  // Near-binary periodic graphics: the documented weak class must be
  // classified (and warned about), not silently reported as fine.
  const w = 640, h = 480;
  const checker = new Uint8Array(w * h * 4);
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const v = ((x >> 3) + (y >> 3)) % 2 ? 255 : 0;
      const i = (y * w + x) * 4;
      checker[i] = v; checker[i + 1] = v; checker[i + 2] = v; checker[i + 3] = 255;
    }
  }
  const binary = assayStegoEmbed(checker, w, h, { key: 'assay-test-key', profile: 'robust', strength: 6, verify: false });
  assert.equal(binary.contentClass, 'binary-graphic');
  assert.ok(binary.warnings.some((w) => /weak class/i.test(w)), 'binary content carries the weak-class warning');
});

test('v1.19 ownership XMP declares xmpRights:Marked and usage terms for external tools', async () => {
  const jpeg = await sharp(await syntheticMaster(320, 240)).jpeg().toBuffer();
  const stamped = await embedOwnershipMetadata(jpeg, {
    artist: 'Studio Example', copyright: 'Copyright 2026 Studio Example. All rights reserved.',
  });
  const xmp = await sharp(stamped).metadata().then((m) => m.xmp?.toString('utf8') || '');
  assert.match(xmp, /<xmpRights:Marked>True<\/xmpRights:Marked>/);
  assert.match(xmp, /<xmpRights:UsageTerms>/);
  assert.match(xmp, /Studio Example/);
});

test('v1.19 archx-protect --assay CLI reports measured PSNR and verifies recovery', async (t) => {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-v119-assaycli-'));
  const photoPath = path.join(dir, 'photo.jpg');
  fs.writeFileSync(photoPath, await sharp(await syntheticMaster(640, 420)).jpeg().toBuffer());
  const env = { ...process.env, ARCHX_STEGO_KEY: 'assay-cli-key' };
  const run = spawnSync(process.execPath, [
    path.join(repoRoot, 'server/scramble-cli.js'), photoPath, '--assay', '--json',
  ], { env, encoding: 'utf8' });
  assert.equal(run.status, 0, run.stderr || run.stdout);
  const report = JSON.parse(run.stdout);
  assert.equal(report.profile, 'robust');
  assert.ok(report.psnr > 15 && report.psnr < 60);
  assert.notEqual(report.verifiedAtStrength, null);
});

test('v1.19 type declarations match the runtime export surface (no declaration drift)', async () => {
  // Review #8 found ~10 declaration/runtime mismatches. Pin the contract:
  // every callable/value declared in types/*.d.ts must exist at runtime
  // with a compatible typeof. Parses only top-level `export function`,
  // `export class`, and `export const` lines.
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const pairs = [
    ['types/scramble.d.ts', await import('../src/scramble.js')],
    ['types/server.d.ts', archxServerModule],
    ['types/index.d.ts', await import('../src/archx.js')],
  ];
  for (const [file, mod] of pairs) {
    const src = fs.readFileSync(path.join(repoRoot, file), 'utf8');
    for (const [, kind, name] of src.matchAll(/^export (function|class|const) ([A-Za-z_$][A-Za-z0-9_$]*)/gm)) {
      assert.ok(name in mod, `${file} declares ${name} but the runtime module does not export it`);
      if (kind === 'function' || kind === 'class') {
        assert.equal(typeof mod[name], 'function', `${file}: ${name} should be callable at runtime`);
      }
    }
  }
});

/* ---------- v1.20: BCH layout v4, hardened saturation, review-#9 ---------- */

test('v1.20 BCH(188,64): full-radius errors+erasures decode; beyond radius rejects', () => {
  let seed = 4242;
  const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  const trial = (errors, erasures, runs, mustPass) => {
    for (let r = 0; r < runs; r++) {
      const data = Uint8Array.from({ length: 64 }, () => (rnd() < 0.5 ? 1 : 0));
      const rx = Uint8Array.from(bchEncode64(data));
      const idx = [...Array(BCH_CODE_BITS).keys()];
      for (let i = idx.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [idx[i], idx[j]] = [idx[j], idx[i]]; }
      const era = idx.slice(errors, errors + erasures);
      for (const p of idx.slice(0, errors)) rx[p] ^= 1;
      for (const p of era) rx[p] = rnd() < 0.5 ? 1 : 0;
      const dec = bchDecode188(rx, era);
      if (mustPass) {
        assert.ok(dec, `e=${errors} s=${erasures} must decode`);
        assert.deepEqual([...dec.data], [...data]);
        assert.equal(dec.errors, errors);
      } else if (dec) {
        // Bounded-distance decoders may miscorrect past the radius,
        // but must never claim a small correction count for it.
        assert.ok(2 * dec.errors + dec.erasures <= 36);
      }
    }
  };
  trial(18, 0, 60, true);
  trial(0, 36, 60, true);
  trial(9, 18, 60, true);
  trial(12, 12, 60, true);
  trial(19, 0, 60, false);
  assert.equal(bchDecode188(new Uint8Array(188), [...Array(37).keys()]), null, '>36 erasures rejected up front');
  assert.throws(() => bchEncode64(new Uint8Array(10)), /exactly 64 bits/);
  // ML erasure solve: 90 erased bits, 3 corrupted low-reliability ones.
  for (let r = 0; r < 30; r++) {
    const data = Uint8Array.from({ length: 64 }, () => (rnd() < 0.5 ? 1 : 0));
    const rx = Uint8Array.from(bchEncode64(data));
    const order = [...Array(BCH_CODE_BITS).keys()];
    for (let i = order.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [order[i], order[j]] = [order[j], order[i]]; }
    const observed = order.slice(0, 98); // most reliable first
    for (const p of observed.slice(-3)) rx[p] ^= 1; // errors among the least reliable
    const solved = bchSolveObserved(rx, observed);
    assert.ok(solved, 'ML solve must recover from 90 erasures');
    assert.deepEqual([...solved.data], [...data]);
    assert.equal(solved.mismatches, 3);
  }
  // Stego wrapper: interleave + MAC roundtrip and wrong-key rejection.
  const wire = bchStegoCodeBits('a1b2c3d4e5f6', 'k');
  assert.equal(wire.length, 188);
  const hit = bchStegoDecode(wire, [], 'k');
  assert.equal(hit.fingerprint, 'a1b2c3d4e5f6');
  assert.equal(bchStegoDecode(wire, [], 'other-key'), null, 'wrong key cannot validate (MAC inside payload)');
});

test('v1.20 layout v4: auto-detects, reports vintage, isolated from v3 pins', async () => {
  const master = await syntheticMaster(640, 420);
  const { data, info } = await sharp(master).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const raw = new Uint8Array(data);
  for (const profile of ['standard', 'robust']) {
    const marked = embedStegoFingerprint(raw, info.width, info.height, 'ORDER-V4-1', {
      key: 'v4-key', profile, strength: 6, layoutVersion: 4,
    });
    const auto = detectStegoFingerprint(marked, info.width, info.height, { key: 'v4-key', profile });
    assert.equal(auto.found, true, `${profile} v4 must auto-detect (${JSON.stringify(auto)})`);
    assert.equal(auto.fingerprint, stegoFingerprint('ORDER-V4-1'));
    assert.equal(auto.layoutVersion, 4);
    const pinnedV3 = detectStegoFingerprint(marked, info.width, info.height, { key: 'v4-key', profile, layoutVersion: 3 });
    assert.equal(pinnedV3.found, false, 'v4 mark must not validate under a v3 pin');
    // And the reverse: a v3 mark must not validate under a v4 pin,
    // nor may legacyCode be combined with v4.
    const markedV3 = embedStegoFingerprint(raw, info.width, info.height, 'ORDER-V4-1', {
      key: 'v4-key', profile, strength: 6, layoutVersion: 3,
    });
    assert.equal(detectStegoFingerprint(markedV3, info.width, info.height, { key: 'v4-key', profile, layoutVersion: 4 }).found, false);
  }
  assert.throws(
    () => embedStegoFingerprint(raw, info.width, info.height, 'X', { layoutVersion: 4, legacyCode: true }),
    /layoutVersion 4 always uses the keyed MAC/,
  );
});

test('v1.20 layout v4: deep crop recovers through ML erasure solving', async () => {
  const photoBytes = fs.readFileSync(new URL('../demo-masters/aurora-valley.jpg', import.meta.url));
  const { data, info } = await sharp(photoBytes).resize(800).ensureAlpha().raw()
    .toBuffer({ resolveWithObject: true });
  const marked = embedStegoFingerprint(new Uint8Array(data), info.width, info.height, 'BUYER-DEEP-CROP', {
    key: 'v4-crop-key', profile: 'robust', strength: 6, layoutVersion: 4,
  });
  const keepW = Math.round(info.width * 0.7), keepH = Math.round(info.height * 0.7);
  const cropped = await sharp(Buffer.from(marked), { raw: { width: info.width, height: info.height, channels: 4 } })
    .extract({ left: Math.round((info.width - keepW) / 2), top: Math.round((info.height - keepH) / 2), width: keepW, height: keepH })
    .resize(info.width, info.height).jpeg({ quality: 80 }).toBuffer();
  const back = await sharp(cropped).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const hit = detectStegoFingerprint(new Uint8Array(back.data), back.info.width, back.info.height, {
    key: 'v4-crop-key', profile: 'robust', layoutVersion: 4, searchGeometry: true, maxTimeMs: 60_000,
  });
  assert.equal(hit.found, true, JSON.stringify(hit));
  assert.equal(hit.fingerprint, stegoFingerprint('BUYER-DEEP-CROP'));
  assert.equal(hit.erasureDecoded, true, 'recovery must come through the erasure channel');
  assert.ok(hit.erasedBits > 36, `erased ${hit.erasedBits} bits: beyond the bounded-distance radius, so the ML solve did the work`);
});

test('v1.20 assay reports layoutVersion and self-verifies a v4 embed', async () => {
  const master = await syntheticMaster(640, 420);
  const { data, info } = await sharp(master).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const report = assayStegoEmbed(new Uint8Array(data), info.width, info.height, {
    key: 'assay-v4', profile: 'robust', strength: 6, layoutVersion: 4, verify: true,
  });
  assert.equal(report.layoutVersion, 4);
  assert.notEqual(report.verifiedAtStrength, null);
});

test('v1.20 hardened preset fails closed on replay saturation; layout 4 is valid server config', async () => {
  const hardened = withHardenedProductionDefaults({ secret: TEST_SECRET, imagesDir: '/nonexistent', allowAnonymous: true });
  assert.equal(hardened.replaySaturation, 'strict', 'hardened preset must not silently reopen replay windows under saturation');
  assert.equal(withHardenedProductionDefaults({ replaySaturation: 'evict' }).replaySaturation, 'evict',
    'explicit host availability choice is preserved, not silently rewritten');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-v120-'));
  fs.writeFileSync(path.join(dir, 'cat.jpg'), await syntheticMaster());
  const okAudit = auditArchxServerConfig({
    secret: TEST_SECRET, imagesDir: dir, allowAnonymous: true,
    steganography: { profile: 'robust', strength: 6, layoutVersion: 4 },
  });
  assert.equal(okAudit.ok, true, okAudit.issues?.join('; '));
  const badAudit = auditArchxServerConfig({
    secret: TEST_SECRET, imagesDir: dir, allowAnonymous: true,
    steganography: { profile: 'robust', layoutVersion: 5 },
  });
  assert.equal(badAudit.ok, false, 'layout 5 does not exist and must stay rejected');
});

test('v1.20 golden freeze: layouts 1-3 embeds stay byte-identical to shipped v1.19', () => {
  // Golden SHA-256 values computed with the shipped v1.19.0 code.
  // If this test fails, someone changed the embedding physics of a
  // SHIPPED layout — every previously issued marked image would
  // stop verifying identically. New physics must ship as a new
  // layout version, never as an edit to 1-3.
  const w = 512, h = 384;
  const buf = new Uint8Array(w * h * 4);
  for (let i = 0; i < w * h; i++) {
    const x = i % w, y = (i / w) | 0; const v = 90 + ((x * 7 + y * 13) % 80);
    buf[i * 4] = v; buf[i * 4 + 1] = v + 20; buf[i * 4 + 2] = 200 - v; buf[i * 4 + 3] = 255;
  }
  const fp = stegoFingerprint('golden-freeze');
  const golden = {
    '1:robust': 'edccf824dbf67902eb082b4fee9f71b7d4d4204318c01c3b0b65334b62166bdc',
    '1:standard': '2da23a49f1d775c3672476f04718d6f7a06475cd62110ba106b710ecee55be48',
    '2:robust': 'dec61ecc431494a10355c518722927167b45e7211e29853a54811e7bebad3da2',
    '2:standard': '2dad0a4ece4f7b9de62f96eac3ca5a685472c36187e6b5baffc54cc77762dac8',
    '3:robust': '714d2500f1f251663ebf325e22453d1becea75d27358fc30e7b1edbc2ec6eb4c',
    '3:standard': '66424874cf6e0ed09b14bb6b9362759ad7cc3c1c8ccaa44ee9d0f00cdea74bc9',
  };
  for (const layoutVersion of [1, 2, 3]) for (const profile of ['robust', 'standard']) {
    const out = embedStegoFingerprint(new Uint8Array(buf), w, h, fp,
      { key: 'golden-key', strength: 6, profile, layoutVersion });
    assert.equal(crypto.createHash('sha256').update(out).digest('hex'), golden[layoutVersion + ':' + profile],
      `layout ${layoutVersion} ${profile} embed drifted from shipped bytes`);
  }
});

test('v1.20 two-phase auto: a v4 suspect is not starved by the v3 geometry search', async () => {
  // Regression for the measured v1.20 bench collapse: single-phase
  // auto-detection let the first layout's exhaustive crop search
  // consume the whole shared deadline, so even an untouched v4
  // suspect timed out. Phase-1 native screens must resolve it.
  const photoBytes = fs.readFileSync(new URL('../demo-masters/aurora-valley.jpg', import.meta.url));
  const { data, info } = await sharp(photoBytes).resize(800).ensureAlpha().raw()
    .toBuffer({ resolveWithObject: true });
  const marked = embedStegoFingerprint(new Uint8Array(data), info.width, info.height, 'BUYER-STARVE', {
    key: 'two-phase-key', profile: 'robust', strength: 6, layoutVersion: 4,
  });
  const jpeg = await sharp(Buffer.from(marked), { raw: { width: info.width, height: info.height, channels: 4 } })
    .jpeg({ quality: 80 }).toBuffer();
  const back = await sharp(jpeg).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const hit = detectStegoFingerprint(new Uint8Array(back.data), back.info.width, back.info.height, {
    key: 'two-phase-key', profile: 'robust', searchGeometry: true, searchOffsets: true, maxTimeMs: 10_000,
  });
  assert.equal(hit.found, true, JSON.stringify(hit));
  assert.equal(hit.layoutVersion, 4);
  assert.equal(hit.fingerprint, stegoFingerprint('BUYER-STARVE'));
  assert.ok(!hit.timedOut, 'phase-1 screen must resolve well inside the budget');
});

test('v1.20 fast dihedral screens: transposed suspect resolves without the geometry sweep', async () => {
  // Transpose/rotation probes used to run only after the full
  // forward geometry search failed (9.9-13.9 s on bench photos).
  // The native screens now run first; an 8 s budget separates the
  // two orders on this image size.
  const photoBytes = fs.readFileSync(new URL('../demo-masters/aurora-valley.jpg', import.meta.url));
  const { data, info } = await sharp(photoBytes).resize(800).ensureAlpha().raw()
    .toBuffer({ resolveWithObject: true });
  const marked = embedStegoFingerprint(new Uint8Array(data), info.width, info.height, 'BUYER-TRANSPOSE', {
    key: 'dihedral-key', profile: 'robust', strength: 6, layoutVersion: 3,
  });
  const transposed = await sharp(Buffer.from(marked), { raw: { width: info.width, height: info.height, channels: 4 } })
    .rotate(90).flip().png().toBuffer();
  const back = await sharp(transposed).ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const hit = detectStegoFingerprint(new Uint8Array(back.data), back.info.width, back.info.height, {
    key: 'dihedral-key', profile: 'robust', searchGeometry: true, searchOffsets: true, maxTimeMs: 8_000,
  });
  assert.equal(hit.found, true, JSON.stringify(hit));
  assert.equal(hit.transposed, 'main');
  assert.ok(!hit.timedOut);
});

test('v1.20 OSD: two poisoned basis bits defeat the plain ML solve; reprocessing recovers', () => {
  // The ML erasure solve trusts its 64-bit basis absolutely: any
  // wrong basis bit scrambles the whole solution. OSD flips the
  // least-reliable basis bits (singly, then in pairs) — this test
  // poisons exactly two WEAK basis bits, the case OSD-2 exists for.
  let seed = 777;
  const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  for (let trial = 0; trial < 8; trial++) {
    const data = Uint8Array.from({ length: 64 }, () => (rnd() < 0.5 ? 1 : 0));
    const code = bchEncode64(data);
    const order = [...Array(BCH_CODE_BITS).keys()];
    for (let i = order.length - 1; i > 0; i--) { const j = Math.floor(rnd() * (i + 1)); [order[i], order[j]] = [order[j], order[i]]; }
    const observed = order.slice(0, 140); // 48 erasures
    const clean = bchSolveObserved(code, observed);
    assert.ok(clean && clean.basis, 'clean solve exposes its basis');
    const rx = Uint8Array.from(code);
    const weakest = clean.basis.slice(-6);
    rx[weakest[1]] ^= 1; rx[weakest[4]] ^= 1;
    const verify = (d) => d.every((v, i) => v === data[i]);
    const plainSol = bchSolveObserved(rx, observed);
    assert.ok(!plainSol || !verify(plainSol.data), 'plain solve must NOT recover through 2 basis errors');
    const osd = bchOsdSolve(rx, observed, { maxMismatches: 10, verify });
    assert.ok(osd, 'OSD must recover');
    assert.equal(osd.osdFlips, 2);
    assert.equal(osd.mismatches, 2);
    assert.ok(verify(osd.data));
  }
});

test('v1.20 ISD: 69 erasures + 13 tail-biased errors recover via information sets (watch-crop channel)', () => {
  // Channel measured on the bench's luxury-watch center0.7 suspect:
  // 119/188 bits observed, 13 voted-bit errors with NONE in the top
  // 27 reliability ranks — beyond OSD (several basis errors),
  // routine for reliability-biased information-set resampling.
  const key = 'isd-test-key';
  const fp = stegoFingerprint('ISD-CHANNEL');
  const truth = bchStegoCodeBits(fp, key);
  const rx = Uint8Array.from(truth);
  const order = [...Array(BCH_CODE_BITS).keys()];
  const errRanks = [27, 28, 57, 62, 86, 91, 104, 108, 109, 110, 114, 115, 117];
  for (const rk of errRanks) rx[order[rk]] ^= 1;
  const observed = order.slice(0, 119);
  // Plain ML and OSD are not asserted to fail (seed-dependent), but
  // the mismatch cap IS asserted: 13 true mismatches can never
  // pass an 8-mismatch cap, MAC or not.
  assert.equal(bchStegoSolveObserved(rx, observed, key, { maxMismatches: 8, isdTrials: 4000, seedSalt: 1 }), null);
  let recovered = null;
  for (let salt = 1; salt <= 6 && !recovered; salt++) {
    recovered = bchStegoSolveObserved(rx, observed, key, { maxMismatches: 16, isdTrials: 1500, seedSalt: salt });
  }
  assert.ok(recovered, 'ISD must recover within a few salted escalations');
  assert.equal(recovered.fingerprint, fp);
  assert.equal(recovered.mismatches, 13);
  // Wrong key: the deinterleave differs, no MAC-valid word exists.
  assert.equal(bchStegoSolveObserved(rx, observed, 'isd-WRONG-key', { maxMismatches: 16, isdTrials: 800, seedSalt: 1 }), null);
  // ISD on pure noise must come back empty, not invent a codeword.
  const noise = Uint8Array.from({ length: BCH_CODE_BITS }, (_, i) => ((i * 2654435761) >>> 13) & 1);
  assert.equal(bchIsdSolve(noise, order, { maxMismatches: 20, verify: () => false, trials: 600, seedSalt: 3 }), null);
});
