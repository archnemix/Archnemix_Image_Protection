/*
 * Redis state-store adapter for Archx.
 *
 * This module deliberately does not import or bundle a Redis client. Pass a
 * connected ioredis or node-redis client owned by the host application:
 *
 *   import Redis from 'ioredis';
 *   import { createRedisStateStore } from '@archnemix/image-protection/redis';
 *
 *   const redis = new Redis(process.env.REDIS_URL);
 *   const stateStore = createRedisStateStore({ client: redis, prefix: 'archx:prod' });
 *
 * Atomicity is the security property that matters:
 * - claimOnce uses SET key value PX ttl NX;
 * - hitWindow and trackDistinct use single Lua scripts against sorted sets,
 *   so prune/check/write cannot interleave with another instance.
 *
 * Redis Cluster note: every operation here touches exactly one key, so no
 * multi-key cross-slot transaction is required. The key prefix is still part
 * of that key; if a deployment needs several Archx keys pinned to one slot,
 * include a Redis hash tag in the prefix (for example 'archx:{prod}').
 */

import crypto from 'node:crypto';

export const REDIS_STATE_STORE_SCRIPTS = Object.freeze({
  hitWindow: `
local key = KEYS[1]
local now = tonumber(ARGV[1])
local windowMs = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - windowMs)
local count = redis.call('ZCARD', key)
if count >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local retryAfterSec = 60
  if oldest[2] then
    retryAfterSec = math.max(1, math.ceil((windowMs - (now - tonumber(oldest[2]))) / 1000))
  end
  redis.call('PEXPIRE', key, windowMs)
  return {1, retryAfterSec, count}
end
redis.call('ZADD', key, now, member)
redis.call('PEXPIRE', key, windowMs)
return {0, 0, count + 1}
`.trim(),
  trackDistinct: `
local key = KEYS[1]
local member = ARGV[1]
local now = tonumber(ARGV[2])
local windowMs = tonumber(ARGV[3])
local maxMembers = tonumber(ARGV[4])
redis.call('ZREMRANGEBYSCORE', key, '-inf', now - windowMs)
local existing = redis.call('ZSCORE', key, member)
local isNew = 1
if existing then isNew = 0 end
redis.call('ZADD', key, now, member)
local count = redis.call('ZCARD', key)
if count > maxMembers then
  redis.call('ZREMRANGEBYRANK', key, 0, count - maxMembers - 1)
  count = maxMembers
end
redis.call('PEXPIRE', key, windowMs)
return {count, isNew}
`.trim(),
});

function detectClientFlavor(client, requested) {
  if (requested && requested !== 'auto') return requested;
  if (typeof client?.defineCommand === 'function') return 'ioredis';
  if ('isOpen' in Object(client) || 'isReady' in Object(client)) return 'node-redis';
  if (typeof client?.call === 'function') return 'ioredis';
  if (typeof client?.sendCommand === 'function') return 'node-redis';
  return 'generic';
}

function integerReply(value, fallback = 0) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.floor(number) : fallback;
}

/**
 * Create a shared Archx state store backed by Redis.
 *
 * @param {object} options
 * @param {object} options.client Connected ioredis/node-redis-compatible client.
 * @param {string} [options.prefix='archx'] Key prefix; use a deployment-specific value.
 * @param {'auto'|'ioredis'|'node-redis'|'generic'} [options.clientFlavor='auto']
 * @param {boolean} [options.closeClient=false] Whether store.close() may close the host client.
 */
export function createRedisStateStore({
  client,
  prefix = 'archx',
  clientFlavor = 'auto',
  closeClient = false,
} = {}) {
  if (!client || typeof client !== 'object') {
    throw new TypeError('Archx Redis state store: a connected Redis client is required');
  }
  if (typeof client.eval !== 'function' && typeof client.sendCommand !== 'function' && typeof client.call !== 'function') {
    throw new TypeError('Archx Redis state store: client must support eval, call, or sendCommand for atomic Lua operations');
  }
  if (typeof prefix !== 'string' || !prefix || prefix.length > 128 || /[\u0000-\u0020\u007f]/.test(prefix)) {
    throw new TypeError('Archx Redis state store: prefix must be a non-empty string up to 128 characters without whitespace/control characters');
  }
  if (!['auto', 'ioredis', 'node-redis', 'generic'].includes(clientFlavor)) {
    throw new TypeError("Archx Redis state store: clientFlavor must be 'auto', 'ioredis', 'node-redis', or 'generic'");
  }

  const flavor = detectClientFlavor(client, clientFlavor);
  const cleanPrefix = prefix.replace(/:+$/, '');
  const keyFor = (key) => `${cleanPrefix}:${String(key)}`;
  // Binary-safe fast path: clients that can return raw Buffers skip the
  // base64 armor (saves ~33% Redis RAM/bandwidth). node-redis v4+ exposes
  // commandOptions({ returnBuffers: true }); ioredis exposes getBuffer.
  // Mixed fleets stay safe: getCache decodes `b64:` values from either
  // representation, and unarmored values read as UTF-8 strings by an older
  // peer simply fail the middleware's HMAC cache tag and regenerate.
  const binaryCapable = typeof client.getBuffer === 'function' ||
    (flavor === 'node-redis' && typeof client.commandOptions === 'function');

  async function evalScript(script, key, args) {
    const redisKey = keyFor(key);
    const stringArgs = args.map((value) => String(value));
    if (flavor === 'node-redis' && typeof client.eval === 'function') {
      return client.eval(script, { keys: [redisKey], arguments: stringArgs });
    }
    if (typeof client.eval === 'function') {
      return client.eval(script, 1, redisKey, ...stringArgs);
    }
    if (typeof client.call === 'function') {
      return client.call('EVAL', script, 1, redisKey, ...stringArgs);
    }
    if (typeof client.sendCommand === 'function') {
      return client.sendCommand(['EVAL', script, '1', redisKey, ...stringArgs]);
    }
    throw new Error('Archx Redis state store: no compatible Lua eval method');
  }

  async function setNxPx(key, ttlMs) {
    const redisKey = keyFor(key);
    if (typeof client.set === 'function') {
      if (flavor === 'node-redis') {
        return client.set(redisKey, '1', { PX: ttlMs, NX: true });
      }
      return client.set(redisKey, '1', 'PX', ttlMs, 'NX');
    }
    if (typeof client.call === 'function') {
      return client.call('SET', redisKey, '1', 'PX', ttlMs, 'NX');
    }
    if (typeof client.sendCommand === 'function') {
      return client.sendCommand(['SET', redisKey, '1', 'PX', String(ttlMs), 'NX']);
    }
    throw new Error('Archx Redis state store: no compatible SET method');
  }

  return Object.freeze({
    kind: 'redis',

    async claimOnce(key, ttlMs) {
      if (typeof key !== 'string' || !key || !Number.isFinite(ttlMs)) return false;
      const safeTtlMs = Math.floor(ttlMs);
      if (safeTtlMs < 1) return false;
      const result = await setNxPx(key, safeTtlMs);
      return result === 'OK' || result === true || result === 1;
    },

    async hitWindow(key, { limit, windowMs = 60000, now = Date.now() } = {}) {
      const safeLimit = Math.floor(Number(limit));
      if (!Number.isFinite(safeLimit) || safeLimit <= 0) {
        return { limited: false, retryAfterSec: 0, count: 0 };
      }
      const safeWindowMs = Number.isFinite(windowMs) && windowMs > 0 ? Math.floor(windowMs) : 60000;
      const safeNow = Number.isFinite(now) ? Math.floor(now) : Date.now();
      const member = `${safeNow}:${crypto.randomUUID()}`;
      const result = await evalScript(REDIS_STATE_STORE_SCRIPTS.hitWindow, key, [
        safeNow, safeWindowMs, safeLimit, member,
      ]);
      if (!Array.isArray(result) || result.length < 3) {
        throw new Error('Archx Redis state store: malformed hitWindow reply');
      }
      return {
        limited: integerReply(result[0]) === 1,
        retryAfterSec: Math.max(0, integerReply(result[1])),
        count: Math.max(0, integerReply(result[2])),
      };
    },

    async trackDistinct(key, member, {
      windowMs = 600000,
      maxMembers = 251,
      now = Date.now(),
    } = {}) {
      const safeWindowMs = Number.isFinite(windowMs) && windowMs > 0 ? Math.floor(windowMs) : 600000;
      const safeMaxMembers = Number.isInteger(maxMembers) && maxMembers > 0
        ? Math.min(maxMembers, 10001)
        : 251;
      const safeNow = Number.isFinite(now) ? Math.floor(now) : Date.now();
      const result = await evalScript(REDIS_STATE_STORE_SCRIPTS.trackDistinct, key, [
        String(member), safeNow, safeWindowMs, safeMaxMembers,
      ]);
      if (!Array.isArray(result) || result.length < 2) {
        throw new Error('Archx Redis state store: malformed trackDistinct reply');
      }
      return {
        distinct: Math.max(0, integerReply(result[0])),
        isNew: integerReply(result[1]) === 1,
      };
    },

    async getCache(key) {
      const redisKey = keyFor(key);
      let value = null;
      if (typeof client.getBuffer === 'function') value = await client.getBuffer(redisKey);
      else if (binaryCapable && flavor === 'node-redis' && typeof client.get === 'function') {
        value = await client.get(client.commandOptions({ returnBuffers: true }), redisKey);
      }
      else if (typeof client.get === 'function') value = await client.get(redisKey);
      else if (typeof client.call === 'function') value = await client.call('GET', redisKey);
      else if (typeof client.sendCommand === 'function') value = await client.sendCommand(['GET', redisKey]);
      if (value == null) return null;
      // Cache blobs are stored base64-armored with a `b64:` prefix (see
      // setCache): node-redis v4 GETs return UTF-8 strings by default,
      // which lossily mangles bytes >= 0x80 and silently corrupted every
      // shared derivative. Legacy unprefixed Buffer replies (ioredis
      // getBuffer) are returned as-is; the middleware's HMAC entry tag
      // rejects anything else, so mixed fleets self-heal.
      if (typeof value === 'string') {
        return value.startsWith('b64:')
          ? Buffer.from(value.slice(4), 'base64')
          : Buffer.from(value, 'latin1');
      }
      if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
        const buf = Buffer.isBuffer(value) ? value : Buffer.from(value);
        return buf.subarray(0, 4).toString('latin1') === 'b64:'
          ? Buffer.from(buf.subarray(4).toString('latin1'), 'base64')
          : buf;
      }
      throw new Error('Archx Redis state store: malformed cache reply');
    },

    async setCache(key, bytes, { ttlMs = 0 } = {}) {
      if (!bytes || typeof bytes.length !== 'number' || !bytes.length) return false;
      const raw = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
      // Raw Buffers when the client can read them back intact; otherwise
      // base64 armor (+33% size, binary-safe across every client flavor).
      const value = binaryCapable ? raw : 'b64:' + raw.toString('base64');
      const redisKey = keyFor(key);
      const safeTtlMs = Number.isFinite(ttlMs) ? Math.floor(ttlMs) : 0;
      let result;
      if (typeof client.set === 'function') {
        if (flavor === 'node-redis') {
          result = await client.set(redisKey, value, safeTtlMs > 0 ? { PX: safeTtlMs } : undefined);
        } else if (safeTtlMs > 0) {
          result = await client.set(redisKey, value, 'PX', safeTtlMs);
        } else {
          result = await client.set(redisKey, value);
        }
      } else if (typeof client.call === 'function') {
        result = safeTtlMs > 0
          ? await client.call('SET', redisKey, value, 'PX', safeTtlMs)
          : await client.call('SET', redisKey, value);
      } else if (typeof client.sendCommand === 'function') {
        result = safeTtlMs > 0
          ? await client.sendCommand(['SET', redisKey, value, 'PX', String(safeTtlMs)])
          : await client.sendCommand(['SET', redisKey, value]);
      } else {
        throw new Error('Archx Redis state store: no compatible SET method');
      }
      return result === 'OK' || result === true || result === 1;
    },

    stats() {
      return Object.freeze({
        kind: 'redis',
        clientFlavor: flavor,
        prefixConfigured: true,
        // Deliberately no SCAN/KEYS accounting: production Redis monitoring
        // belongs in Redis INFO/metrics, not an unbounded request-path scan.
        sharedState: true,
      });
    },

    async close() {
      if (!closeClient) return;
      if (typeof client.quit === 'function') await client.quit();
      else if (typeof client.close === 'function') await client.close();
      else if (typeof client.disconnect === 'function') client.disconnect();
    },
  });
}

export default createRedisStateStore;
