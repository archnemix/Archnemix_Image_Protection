/**
 * Seeded robustness/fuzz cases for every attacker-controlled parser.
 *
 * The invariant under test is uniform: library code either returns a sane,
 * schema-valid value or throws a controlled `Archx:` error — never an
 * unhandled crash, a stack-leaking TypeError, or a silently accepted forgery.
 * Deterministic (fixed PRNG seed) so CI is reproducible; extend the iteration
 * counts locally with ARCHX_FUZZ_MULTIPLIER for a longer campaign.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import sharp from 'sharp';
import {
  mulberry32, buildScramblePlan, scramblePixels, scramblePixelsPadded, paddedSize,
  encodeContainer, decodeContainer, sniffImageInfo, detectStegoFingerprint,
} from '../src/scramble.js';
import { createArchxMiddleware } from '../server/middleware.js';

const MULT = Math.max(1, Number(process.env.ARCHX_FUZZ_MULTIPLIER) || 1);
const rand = mulberry32(0xa8c4f00d);
const ri = (n) => Math.floor(rand() * n);
const pick = (arr) => arr[ri(arr.length)];
const isArchxError = (err) => err instanceof Error && /^Archx:/.test(err.message);

const VALID_HEADER = {
  v: 1, w: 320, h: 240, pw: 320, ph: 240, grid: 8,
  mime: 'image/webp', scrambled: true, encrypted: false,
};

test('fuzz: corrupted .archx containers fail controlled or stay schema-valid', () => {
  const good = encodeContainer(VALID_HEADER, new Uint8Array(512).map((_, i) => i % 251));
  let rejected = 0; let accepted = 0;
  for (let i = 0; i < 300 * MULT; i++) {
    const mutant = new Uint8Array(good);
    const mode = ri(3);
    if (mode === 0) {
      for (let f = 0, flips = 1 + ri(8); f < flips; f++) mutant[ri(mutant.length)] ^= 1 << ri(8);
    } else if (mode === 1) {
      const len = ri(mutant.length);
      try {
        decodeContainer(mutant.subarray(0, len));
        accepted++;
      } catch (err) {
        assert.ok(isArchxError(err), `truncation ${len}: ${err}`);
        rejected++;
      }
      continue;
    } else {
      // corrupt the declared header length (bytes 6..10)
      for (let b = 6; b < 10; b++) mutant[b] = ri(256);
    }
    try {
      const { header } = decodeContainer(mutant);
      assert.ok(Number.isInteger(header.grid) && header.grid >= 2 && header.grid <= 32);
      assert.ok(header.w >= 1 && header.h >= 1);
      assert.ok(header.pv === undefined || header.pv === 1 || header.pv === 2);
      accepted++;
    } catch (err) {
      assert.ok(isArchxError(err), `mutation mode ${mode}: ${err}`);
      rejected++;
    }
  }
  assert.ok(rejected > 100, `fuzzer should mostly produce rejects (got ${rejected})`);
  assert.ok(accepted > 0, 'payload-region flips must still parse (payload is opaque)');
});

test('fuzz: hostile header field values are rejected at encode time', () => {
  const hostile = [
    { grid: 1e21 }, { grid: 1.5 }, { grid: '8' }, { grid: -8 }, { grid: null },
    { w: -1 }, { w: 0 }, { w: 2 ** 53 }, { w: NaN }, { h: Infinity },
    { mime: 'image/svg+xml' }, { mime: 'text/html' }, { mime: 42 },
    { pv: 3 }, { pv: '2' }, { pv: 0 }, { encrypted: 'yes' }, { scrambled: 1 },
    { iv: 'x'.repeat(500) }, { unknownField: true }, { v: 2 }, { v: '1' },
    { pw: 319 }, { ph: 100000 }, { w: 321 },
  ];
  for (const patch of hostile) {
    assert.throws(
      () => encodeContainer({ ...VALID_HEADER, ...patch }, new Uint8Array([1, 2, 3])),
      (err) => isArchxError(err),
      `patch ${JSON.stringify(patch)} must be a controlled rejection`);
  }
  // random single-field type confusion
  const fields = Object.keys(VALID_HEADER);
  const junk = [null, undefined, NaN, Infinity, -0, 1e308, [], {}, 'x', true, -1, 0.5];
  for (let i = 0; i < 150 * MULT; i++) {
    const header = { ...VALID_HEADER, [pick(fields)]: pick(junk) };
    try {
      decodeContainer(encodeContainer(header, new Uint8Array([1, 2, 3])));
    } catch (err) {
      assert.ok(isArchxError(err), `${JSON.stringify(header)}: ${err}`);
    }
  }
});

test('fuzz: sniffImageInfo never throws and only reports known formats', () => {
  const magics = [
    [0x89, 0x50, 0x4e, 0x47], [0xff, 0xd8, 0xff], [0x52, 0x49, 0x46, 0x46],
    [0x47, 0x49, 0x46, 0x38], [0x42, 0x4d], [0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70],
  ];
  const known = new Set(['png', 'jpeg', 'webp', 'avif', 'gif', 'bmp', 'tiff', 'svg']);
  for (let i = 0; i < 300 * MULT; i++) {
    const len = ri(600);
    const buf = new Uint8Array(len);
    for (let b = 0; b < len; b++) buf[b] = ri(256);
    if (rand() < 0.6 && len > 8) {
      const magic = pick(magics);
      buf.set(magic.slice(0, Math.min(magic.length, len)), 0);
    }
    const info = sniffImageInfo(buf);
    if (info === null) continue;
    assert.ok(known.has(info.format), `unknown format ${info.format}`);
    if (info.width !== null) assert.ok(Number.isSafeInteger(info.width) && info.width >= 0);
    if (info.height !== null) assert.ok(Number.isSafeInteger(info.height) && info.height >= 0);
  }
});

test('fuzz: scramble round-trips exactly across grids, sizes, keys, and plan versions', () => {
  const keys = ['', 'k', 'correct horse', '🔑 unicode κλειδί', 'x'.repeat(512), '0', '\n\t'];
  for (let i = 0; i < 120 * MULT; i++) {
    const grid = 2 + ri(31);
    const w = 1 + ri(97);
    const h = 1 + ri(97);
    const version = rand() < 0.5 ? 1 : 2;
    const plan = buildScramblePlan(grid, pick(keys), version);
    const raw = new Uint8Array(w * h * 4);
    for (let b = 0; b < raw.length; b++) raw[b] = ri(256);
    const { pw, ph } = paddedSize(w, h, grid);
    const restored = scramblePixels(scramblePixelsPadded(raw, w, h, plan), pw, ph, plan, 'unscramble');
    for (let y = 0; y < h; y++) {
      assert.deepEqual(
        restored.subarray(y * pw * 4, (y * pw + w) * 4),
        raw.subarray(y * w * 4, (y + 1) * w * 4),
        `grid ${grid} ${w}x${h} v${version} row ${y}`);
    }
  }
});

test('fuzz: stego detection on random pixels never crashes and never reports a hit', () => {
  for (let i = 0; i < 40 * MULT; i++) {
    const w = 64 + ri(260);
    const h = 64 + ri(260);
    const rgba = new Uint8Array(w * h * 4);
    for (let b = 0; b < rgba.length; b++) rgba[b] = ri(256);
    let result;
    try {
      result = detectStegoFingerprint(rgba, w, h, {});
    } catch (err) {
      assert.ok(isArchxError(err), `${err}`);
      continue;
    }
    if (result !== null && result !== undefined) {
      assert.equal(typeof result, 'object');
      assert.ok(!result.found,
        `unmarked noise must never attribute (got ${result.fingerprint} @ ${result.confidence})`);
    }
  }
});

test('regression: the exact noise buffers that once false-positived stay rejected', () => {
  // mulberry32(seed * 7919) streams; both previously returned found:true
  // with confidences 0.82 / 0.75 before the evidence-density gates landed.
  for (const seed of [14, 31]) {
    const r = mulberry32(seed * 7919);
    const next = (n) => Math.floor(r() * n);
    for (let i = 0; i < 25; i++) {
      const w = 64 + next(200);
      const h = 64 + next(200);
      const rgba = new Uint8Array(w * h * 4);
      for (let b = 0; b < rgba.length; b++) rgba[b] = next(256);
      const result = detectStegoFingerprint(rgba, w, h, {});
      assert.ok(!result?.found, `seed ${seed} case ${i} (${w}x${h}) must not attribute`);
    }
  }
});

test('fuzz: mutated tokens never redeem and never 500', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-fuzz-'));
  const mastersDir = path.join(root, 'masters');
  fs.mkdirSync(mastersDir);
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="320" height="240"><rect width="320" height="240" fill="#3366cc"/></svg>`;
  fs.writeFileSync(path.join(mastersDir, 'cat.jpg'), await sharp(Buffer.from(svg)).png().toBuffer());
  const handler = createArchxMiddleware({
    secret: 'fuzz-token-secret-for-unit-tests-min-32-chars',
    imagesDir: mastersDir,
    authorize: async () => true,
    rateLimitPerMinute: 100000,
    tokenRateLimitPerMinute: 100000,
  });
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { await new Promise((r) => server.close(r)); handler.close(); });
  const base = `http://127.0.0.1:${server.address().port}`;

  const mint = await fetch(base + '/archx/token/cat?w=320', {
    method: 'POST', headers: { 'x-archx-request': 'token' },
  });
  const minted = await mint.json();
  assert.ok(minted.token && minted.cleanUrl);
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=.';
  for (let i = 0; i < 120 * MULT; i++) {
    const chars = [...minted.token];
    const mode = ri(3);
    if (mode === 0) chars[ri(chars.length)] = pick([...alphabet]);
    else if (mode === 1) chars.splice(ri(chars.length), 1);
    else chars.splice(ri(chars.length), 0, pick([...alphabet]));
    const forged = chars.join('');
    if (forged === minted.token) continue; // no-op mutation
    const res = await fetch(base + minted.cleanUrl, { headers: { 'x-archx-token': forged } });
    await res.body?.cancel().catch(() => {});
    assert.ok(res.status !== 200, `mutated token redeemed (${mode}): ${forged.slice(0, 24)}…`);
    assert.ok(res.status < 500, `mutated token caused ${res.status} (must be a clean 4xx)`);
  }
  const legit = await fetch(base + minted.cleanUrl, { headers: { 'x-archx-token': minted.token } });
  assert.equal(legit.status, 200, 'server must stay healthy after the fuzz run');
});
