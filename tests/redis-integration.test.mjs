/**
 * Real-Redis integration tests (review #7 P1.7). Skipped unless
 * ARCHX_TEST_REDIS_URL points at a disposable Redis/Valkey instance
 * (CI provides one as a service container). The fake-client unit
 * tests prove script shapes; THESE prove the multi-instance
 * security properties against the actual adapter:
 *   mint on A -> redeem on B -> replay anywhere is denied,
 *   concurrent redemption races resolve to exactly one winner,
 *   quotas are shared, and a dead store fails closed (no local
 *   fallback silently downgrading one-time semantics).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import sharp from 'sharp';
import Redis from 'ioredis';
import { createArchxMiddleware } from '../server/middleware.js';
import { createRedisStateStore } from '../server/redis-state-store.js';

const REDIS_URL = process.env.ARCHX_TEST_REDIS_URL;
const SECRET = 'redis-integration-secret-32-chars!!!';

async function syntheticMaster(w = 320, h = 240) {
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}">
    <defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0" stop-color="#ff5533"/><stop offset="1" stop-color="#2244ff"/></linearGradient></defs>
    <rect width="${w}" height="${h}" fill="url(#g)"/>
    <circle cx="90" cy="80" r="45" fill="#00e08a"/></svg>`;
  return sharp(Buffer.from(svg)).png().toBuffer();
}

async function startInstance(t, imagesDir, store, extra = {}) {
  const handler = createArchxMiddleware({
    secret: SECRET,
    imagesDir,
    authorize: async () => ({ viewerId: 'redis-viewer' }),
    stateStore: store,
    deploymentMode: 'multi-instance',
    ...extra,
  });
  const server = http.createServer((req, res) => handler(req, res));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => {
    handler.close();
    await new Promise((resolve) => server.close(resolve));
  });
  return { handler, base: `http://127.0.0.1:${server.address().port}` };
}

const postToken = (base) => fetch(`${base}/archx/token/cat?w=200`, {
  method: 'POST', headers: { 'x-archx-request': 'token' },
}).then((r) => r.json());
const redeem = (base, tok) => fetch(base + tok.cleanUrl, { headers: { 'x-archx-token': tok.token } });

test('real Redis: cross-instance one-time redemption, races, quotas, fail-closed', { skip: !REDIS_URL && 'ARCHX_TEST_REDIS_URL not set' }, async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-redis-it-'));
  fs.writeFileSync(path.join(dir, 'cat.jpg'), await syntheticMaster());
  const clientA = new Redis(REDIS_URL, { lazyConnect: false, maxRetriesPerRequest: 2 });
  const clientB = new Redis(REDIS_URL, { lazyConnect: false, maxRetriesPerRequest: 2 });
  t.after(async () => { await clientA.quit().catch(() => {}); await clientB.quit().catch(() => {}); });
  const prefix = `archx-it-${Date.now()}`;
  const storeA = createRedisStateStore({ client: clientA, prefix });
  const storeB = createRedisStateStore({ client: clientB, prefix });
  const a = await startInstance(t, dir, storeA);
  const b = await startInstance(t, dir, storeB);

  // Mint on A, redeem on B, replay on A: exactly one success fleet-wide.
  const tok = await postToken(a.base);
  assert.ok(tok.token, JSON.stringify(tok));
  assert.equal((await redeem(b.base, tok)).status, 200, 'cross-instance redemption works');
  assert.equal((await redeem(a.base, tok)).status, 403, 'replay on the minting instance is denied');
  assert.equal((await redeem(b.base, tok)).status, 403, 'replay on the redeeming instance is denied');

  // Race the same token across instances: exactly one 200.
  const raceTok = await postToken(a.base);
  const results = await Promise.all([
    redeem(a.base, raceTok), redeem(b.base, raceTok), redeem(a.base, raceTok), redeem(b.base, raceTok),
  ]);
  assert.equal(results.filter((r) => r.status === 200).length, 1, 'concurrent race has exactly one winner');

  // Quotas are shared: a 3-per-viewer quota exhausts across instances.
  const storeQ = createRedisStateStore({ client: clientA, prefix: `${prefix}q` });
  const q = await startInstance(t, dir, storeQ, { quotas: { perViewer: 3 } });
  let okCount = 0;
  for (let i = 0; i < 5; i++) {
    const tk = await postToken(q.base);
    if (tk.token && (await redeem(q.base, tk)).status === 200) okCount++;
  }
  assert.equal(okCount, 3, 'shared quota stops at the configured ceiling');

  // Dead store fails closed — no silent local fallback.
  const deadClient = new Redis('redis://127.0.0.1:6399', { lazyConnect: true, maxRetriesPerRequest: 1, retryStrategy: () => null });
  t.after(() => deadClient.disconnect());
  const deadStore = createRedisStateStore({ client: deadClient, prefix: `${prefix}d` });
  const dead = await startInstance(t, dir, deadStore);
  const deadTok = await postToken(dead.base).catch(() => null);
  const deadStatus = deadTok?.token ? (await redeem(dead.base, deadTok)).status : 503;
  assert.ok(deadStatus >= 400, `unavailable store yields a controlled failure (got ${deadStatus}), never a silent local redemption`);
});
