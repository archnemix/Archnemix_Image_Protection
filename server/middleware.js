/**
 * Archnemix server middleware (Express-compatible, also works with plain
 * node:http). Masters stay on disk OUTSIDE your static folder; this is the
 * only route that can read them, and it only ever returns a down-scaled,
 * tile-scrambled (optionally AES-GCM-encrypted) .archx payload behind a
 * short-lived HMAC-signed token.
 *
 *   POST {basePath}/token/:id?w=1200 -> { url, cleanUrl, token, key, aesKey?, grid, exp }
 *   GET  {basePath}/i/:id + X-Archx-Token -> application/octet-stream (.archx)
 *        (`?t=` is accepted only with explicit legacy `allowQueryTokens:true`)
 *
 * Secure defaults are deny-by-default: startup fails unless the host supplies
 * an `authorize(req, id, { phase })` callback or explicitly sets
 * `allowAnonymous: true` for an intentionally public catalog. Authorization
 * runs again when the signed token is redeemed, so revocation/session changes
 * take effect inside the token TTL. There is no URL that returns the master.
 *
 * Client-side scrambling/AES is NOT DRM: any key delivered to a browser must
 * be assumed recoverable by that browser's operator. The security boundary is
 * server authorization + never shipping the master + resolution/quality caps.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';
import { isIP } from 'node:net';
import {
  stegoFingerprint as resolveStegoFingerprint,
  sniffImageInfo,
  isArchxContainer,
  decodeContainer,
} from '../src/scramble.js';

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const SECRET_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const TOKEN_AUDIENCE = 'archx:image';
const TOKEN_SCOPE = 'image:view';
/* 1x1 transparent PNG served from `{basePath}/taint.png`. A browser that
 * draws it into a canvas cross-origin WITHOUT CORS approval flips that
 * canvas's origin-clean flag to false, after which every readback API —
 * including prototype-call bypasses of instance-level poisoning — throws
 * SecurityError. The bytes are constant and input-independent. */
const TAINT_PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=',
  'base64',
);
const FORMAT_EXTENSIONS = Object.freeze({
  jpeg: ['.jpg', '.jpeg'],
  png: ['.png'],
  webp: ['.webp'],
  avif: ['.avif'],
  gif: ['.gif'],
  tiff: ['.tif', '.tiff'],
});
const KNOWN_WEAK_SECRETS = new Set([
  'secret', 'change-me', 'changeme', 'demo-secret', 'test-secret',
  'demo-secret-change-me-in-production', 'archx-secret',
]);

/** Canonical responsive derivative widths for image-heavy catalogs. Serving a
 * handful of reusable widths instead of every viewport/DPR combination is
 * what lets memory/disk/CDN derivative caches reach a high hit rate. */
export const DEFAULT_WIDTH_BUCKETS = Object.freeze([
  160, 240, 320, 480, 640, 800, 960, 1200, 1440, 1600, 1920, 2240, 2560,
]);

/** Round a requested derivative width to a canonical bucket without ever
 * exceeding the server's entitlement cap. If the cap falls between buckets,
 * the largest bucket at or below the cap wins; exact-width serving remains
 * available by not configuring buckets. */
export function canonicalDerivativeWidth(requestedWidth, widthCap, buckets = DEFAULT_WIDTH_BUCKETS) {
  const cap = Math.floor(Number(widthCap));
  const requested = Math.ceil(Number(requestedWidth));
  if (!Number.isFinite(cap) || cap < 1) return 1;
  if (!Number.isFinite(requested) || requested < 1) return cap;
  const desired = Math.min(cap, requested);
  const normalized = [...new Set((Array.isArray(buckets) ? buckets : [])
    .filter((value) => Number.isInteger(value) && value >= 64 && value <= 8192))]
    .sort((a, b) => a - b);
  if (!normalized.length) return desired;
  for (const bucket of normalized) {
    if (bucket >= desired && bucket <= cap) return bucket;
  }
  const atOrBelowCap = normalized.filter((bucket) => bucket <= cap);
  return atOrBelowCap.length ? atOrBelowCap[atOrBelowCap.length - 1] : desired;
}

export function validateImageId(id) {
  return typeof id === 'string' && ID_RE.test(id);
}

function isPathInside(parent, child) {
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..' + path.sep) && !path.isAbsolute(rel));
}

function pathsOverlap(a, b) {
  return isPathInside(a, b) || isPathInside(b, a);
}

function parseStrictInt(value) {
  if (value == null || !/^\d{1,9}$/.test(String(value))) return null;
  const n = Number(value);
  return Number.isSafeInteger(n) ? n : null;
}

/** Bounded sliding-window limiter. Old clients expire and the client map is
 * hard-capped, so an attacker churning source IPs cannot grow memory forever. */
export class SlidingWindowLimiter {
  #map = new Map();
  #timer = null;

  constructor({ windowMs = 60000, maxClients = 10000, cleanupIntervalMs = 60000 } = {}) {
    this.windowMs = windowMs;
    this.maxClients = maxClients;
    if (cleanupIntervalMs > 0) {
      this.#timer = setInterval(() => this.cleanup(), cleanupIntervalMs);
      this.#timer.unref?.();
    }
  }

  get size() { return this.#map.size; }

  // Timestamps are appended in non-decreasing order, so expiry is a
  // front-prune: one splice instead of a filter+copy on every hit/cleanup.
  #prune(list, now) {
    let firstFresh = 0;
    while (firstFresh < list.length && now - list[firstFresh] >= this.windowMs) firstFresh++;
    if (firstFresh) list.splice(0, firstFresh);
    return list;
  }

  cleanup(now = Date.now()) {
    for (const [key, entry] of this.#map) {
      if (!this.#prune(entry.list, now).length) this.#map.delete(key);
    }
    this.#evict(now);
  }

  hit(key, max, now = Date.now()) {
    if (!max || max <= 0) return { limited: false, retryAfterSec: 0, count: 0 };
    const entry = this.#map.get(key) || { list: [], max };
    entry.max = max;
    const list = this.#prune(entry.list, now);
    if (list.length >= max) {
      this.#map.set(key, entry);
      this.#bound(now);
      return {
        limited: true,
        retryAfterSec: Math.max(1, Math.ceil((this.windowMs - (now - list[0])) / 1000)),
        count: list.length,
      };
    }
    list.push(now);
    // Refresh LRU position before enforcing the bound.
    this.#map.delete(key);
    this.#map.set(key, entry);
    this.#bound(now);
    return { limited: false, retryAfterSec: 0, count: list.length };
  }

  // Eviction preference order: expired/empty, then oldest UNBLOCKED
  // entries, and only then blocked ones. Plain LRU lets an attacker
  // churning fresh keys (e.g. rotating IPv6 prefixes) evict the entries
  // of clients who are actively throttled, resetting their windows.
  #evict(now = Date.now()) {
    if (this.#map.size <= this.maxClients) return;
    for (const [key, entry] of this.#map) {
      if (this.#map.size <= this.maxClients) return;
      const blocked = entry.max > 0 && this.#prune(entry.list, now).length >= entry.max;
      if (!blocked) this.#map.delete(key);
    }
    while (this.#map.size > this.maxClients) {
      this.#map.delete(this.#map.keys().next().value);
    }
  }

  #bound(now = Date.now()) {
    if (this.#map.size <= this.maxClients) return;
    this.cleanup(now);
    this.#evict(now);
  }

  close() {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
    this.#map.clear();
  }
}

/** Race-safe one-time claim set. `claim()` is deliberately synchronous: in
 * Node's event loop there is no await between check and set, so parallel
 * requests carrying the same nonce cannot both pass. */
export class BoundedTtlSet {
  #map = new Map();
  #timer = null;

  constructor({ maxEntries = 100000, cleanupIntervalMs = 60000 } = {}) {
    this.maxEntries = maxEntries;
    if (cleanupIntervalMs > 0) {
      this.#timer = setInterval(() => this.cleanup(), cleanupIntervalMs);
      this.#timer.unref?.();
    }
  }

  get size() { return this.#map.size; }

  cleanup(now = Date.now()) {
    for (const [key, exp] of this.#map) if (exp <= now) this.#map.delete(key);
  }

  claim(key, exp, now = Date.now()) {
    if (!key || !Number.isFinite(exp) || exp <= now) return false;
    if (this.#map.has(key)) return false;
    if (this.#map.size >= this.maxEntries) this.cleanup(now);
    if (this.#map.size >= this.maxEntries) return false; // fail closed when saturated
    this.#map.set(key, exp);
    return true;
  }

  close() {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
    this.#map.clear();
  }
}

/** Small FIFO semaphore for expensive image work. Queue length and wait are
 * bounded; overload produces a controlled busy error instead of CPU collapse. */
export class AsyncSemaphore {
  #active = 0;
  #queue = [];
  #queueHead = 0;

  constructor({ maxConcurrent = 2, maxQueue = 100, queueTimeoutMs = 5000 } = {}) {
    this.maxConcurrent = Math.max(1, maxConcurrent);
    this.maxQueue = Math.max(0, maxQueue);
    this.queueTimeoutMs = Math.max(0, queueTimeoutMs);
  }

  get active() { return this.#active; }
  get queued() { return Math.max(0, this.#queue.length - this.#queueHead); }

  async run(fn) {
    if (this.#active >= this.maxConcurrent) {
      if (this.queued >= this.maxQueue) {
        const err = new Error('image processing busy');
        err.code = 'ARCHX_PROCESSING_BUSY';
        throw err;
      }
      await new Promise((resolve, reject) => {
        const waiter = { resolve, reject, timer: null };
        if (this.queueTimeoutMs > 0) {
          waiter.timer = setTimeout(() => {
            const i = this.#queue.indexOf(waiter);
            if (i >= 0) this.#queue.splice(i, 1);
            const err = new Error('image processing busy');
            err.code = 'ARCHX_PROCESSING_BUSY';
            reject(err);
          }, this.queueTimeoutMs);
          waiter.timer.unref?.();
        }
        this.#queue.push(waiter);
      });
    }
    this.#active++;
    try { return await fn(); }
    finally {
      this.#active--;
      const next = this.#queueHead < this.#queue.length ? this.#queue[this.#queueHead++] : null;
      if (this.#queueHead >= this.#queue.length) { this.#queue.length = 0; this.#queueHead = 0; }
      else if (this.#queueHead > 1024 && this.#queueHead * 2 >= this.#queue.length) {
        this.#queue.splice(0, this.#queueHead); this.#queueHead = 0;
      }
      if (next) {
        if (next.timer) clearTimeout(next.timer);
        next.resolve();
      }
    }
  }
}

/** Distinct-object access tracker for scraping detection (bounded both by
 * tracked clients and by IDs retained per client). */
class DistinctAccessTracker {
  #map = new Map();
  #timer = null;

  constructor({ windowMs = 600000, maxClients = 10000, maxIdsPerClient = 251 } = {}) {
    this.windowMs = windowMs;
    this.maxClients = maxClients;
    this.maxIdsPerClient = Math.max(1, Math.min(10001, Math.floor(maxIdsPerClient) || 251));
    this.#timer = setInterval(() => this.cleanup(), Math.min(60000, windowMs));
    this.#timer.unref?.();
  }

  cleanup(now = Date.now()) {
    for (const [key, ids] of this.#map) {
      for (const [id, seen] of ids) if (now - seen >= this.windowMs) ids.delete(id);
      if (!ids.size) this.#map.delete(key);
    }
    while (this.#map.size > this.maxClients) this.#map.delete(this.#map.keys().next().value);
  }

  hit(key, id, now = Date.now()) {
    let ids = this.#map.get(key);
    if (!ids) { ids = new Map(); this.#map.set(key, ids); }
    for (const [oldId, seen] of ids) if (now - seen >= this.windowMs) ids.delete(oldId);
    const isNew = !ids.has(id);
    ids.set(id, now);
    while (ids.size > this.maxIdsPerClient) ids.delete(ids.keys().next().value);
    this.#map.delete(key); this.#map.set(key, ids);
    if (this.#map.size > this.maxClients) this.cleanup(now);
    return { distinct: ids.size, isNew };
  }

  close() {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
    this.#map.clear();
  }
}

/**
 * Create the built-in process-local state store.
 *
 * The middleware uses this object shape for both the default memory store
 * and a host-supplied distributed store:
 *
 *   claimOnce(key, ttlMs)                         -> Promise<boolean>
 *   hitWindow(key, { limit, windowMs, now })      -> Promise<{limited,retryAfterSec,count}>
 *   trackDistinct(key, member, { windowMs, ... }) -> Promise<{distinct,isNew}>
 *   getCache(key)                                 -> Promise<Buffer|Uint8Array|null> (optional)
 *   setCache(key, bytes, { ttlMs })               -> Promise<*> (optional)
 *   stats() / close()                             -> optional
 *
 * `claimOnce`, `hitWindow`, and `trackDistinct` must be atomic in a shared
 * implementation. A read-then-write Redis/Dynamo implementation is not
 * sufficient: use `SET ... NX PX`, Lua/transactions, conditional writes, or
 * the equivalent atomic primitive in the selected backend.
 *
 * Passing one memory-store instance to several middleware handlers in the
 * same process makes them share state for tests, but it is not a substitute
 * for Redis/Dynamo/etc. across processes or machines.
 */
export function createMemoryStateStore({
  maxClients = 10000,
  maxEntries = 100000,
  maxCacheEntries = 100,
  maxCacheBytes = 64 * 1024 * 1024,
  cleanupIntervalMs = 60000,
} = {}) {
  const claimSets = new Map();
  const windowLimiters = new Map();
  const distinctTrackers = new Map();
  const cache = new Map();
  let cacheBytes = 0;

  const namespaceOf = (key) => String(key || '').split(':', 1)[0] || 'default';
  const claimSetFor = (namespace) => {
    let set = claimSets.get(namespace);
    if (!set) {
      if (claimSets.size >= 16) throw new Error('too many state-store claim namespaces');
      set = new BoundedTtlSet({ maxEntries, cleanupIntervalMs });
      claimSets.set(namespace, set);
    }
    return set;
  };
  const windowLimiterFor = (namespace, windowMs) => {
    const key = `${namespace}:${windowMs}`;
    let limiter = windowLimiters.get(key);
    if (!limiter) {
      if (windowLimiters.size >= 32) throw new Error('too many state-store window configurations');
      limiter = new SlidingWindowLimiter({ windowMs, maxClients, cleanupIntervalMs });
      windowLimiters.set(key, limiter);
    }
    return limiter;
  };
  const distinctTrackerFor = (windowMs, maxMembers) => {
    const key = `${windowMs}:${maxMembers}`;
    let tracker = distinctTrackers.get(key);
    if (!tracker) {
      if (distinctTrackers.size >= 16) throw new Error('too many state-store distinct configurations');
      tracker = new DistinctAccessTracker({ windowMs, maxClients, maxIdsPerClient: maxMembers });
      distinctTrackers.set(key, tracker);
    }
    return tracker;
  };
  const cleanupCache = (now = Date.now()) => {
    for (const [key, entry] of cache) {
      if (entry.exp <= now) {
        cacheBytes -= entry.bytes.length;
        cache.delete(key);
      }
    }
  };

  return Object.freeze({
    kind: 'memory',

    async claimOnce(key, ttlMs, now = Date.now()) {
      if (typeof key !== 'string' || !key || !Number.isFinite(ttlMs) || ttlMs <= 0) return false;
      return claimSetFor(namespaceOf(key)).claim(key, now + ttlMs, now);
    },

    async hitWindow(key, { limit, windowMs = 60000, now = Date.now() } = {}) {
      if (!limit || limit <= 0) return { limited: false, retryAfterSec: 0, count: 0 };
      const safeWindowMs = Number.isFinite(windowMs) && windowMs > 0 ? windowMs : 60000;
      return windowLimiterFor(namespaceOf(key), safeWindowMs).hit(String(key), limit, now);
    },

    async trackDistinct(key, member, {
      windowMs = 600000,
      maxMembers = 251,
      now = Date.now(),
    } = {}) {
      const safeWindowMs = Number.isFinite(windowMs) && windowMs > 0 ? windowMs : 600000;
      const safeMaxMembers = Number.isInteger(maxMembers) && maxMembers > 0 ? maxMembers : 251;
      return distinctTrackerFor(safeWindowMs, safeMaxMembers).hit(String(key), String(member), now);
    },

    async getCache(key, now = Date.now()) {
      const entry = cache.get(String(key));
      if (!entry) return null;
      if (entry.exp <= now) {
        cacheBytes -= entry.bytes.length;
        cache.delete(String(key));
        return null;
      }
      cache.delete(String(key));
      cache.set(String(key), entry);
      return entry.bytes;
    },

    async setCache(key, bytes, { ttlMs = 0, now = Date.now() } = {}) {
      if (!maxCacheEntries || !maxCacheBytes || !bytes || typeof bytes.length !== 'number') return false;
      const value = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
      if (!value.length || value.length > maxCacheBytes) return false;
      cleanupCache(now);
      const cacheKey = String(key);
      const previous = cache.get(cacheKey);
      if (previous) {
        cacheBytes -= previous.bytes.length;
        cache.delete(cacheKey);
      }
      cache.set(cacheKey, {
        bytes: value,
        exp: Number.isFinite(ttlMs) && ttlMs > 0 ? now + ttlMs : Number.POSITIVE_INFINITY,
      });
      cacheBytes += value.length;
      while (cache.size > maxCacheEntries || cacheBytes > maxCacheBytes) {
        const oldestKey = cache.keys().next().value;
        if (oldestKey === undefined) break;
        cacheBytes -= cache.get(oldestKey).bytes.length;
        cache.delete(oldestKey);
        if (oldestKey === cacheKey) break;
      }
      return cache.has(cacheKey);
    },

    stats() {
      cleanupCache();
      const sumWindowClients = (prefix) => {
        let total = 0;
        for (const [key, limiter] of windowLimiters) if (key.startsWith(prefix + ':')) total += limiter.size;
        return total;
      };
      return Object.freeze({
        kind: 'memory',
        consumedTokens: claimSets.get('nonce')?.size || 0,
        consumedProofs: claimSets.get('proof')?.size || 0,
        rateLimitClients: sumWindowClients('rate'),
        quotaClients: sumWindowClients('quota'),
        sharedCacheEntries: cache.size,
        sharedCacheBytes: cacheBytes,
      });
    },

    close() {
      for (const set of claimSets.values()) set.close();
      for (const limiter of windowLimiters.values()) limiter.close();
      for (const tracker of distinctTrackers.values()) tracker.close();
      claimSets.clear();
      windowLimiters.clear();
      distinctTrackers.clear();
      cache.clear();
      cacheBytes = 0;
    },
  });
}


function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}
function signToken(payload, secret) {
  const body = b64url(JSON.stringify(payload));
  const mac = crypto.createHmac('sha256', secret).update(body).digest();
  return body + '.' + b64url(mac);
}
function verifyToken(token, secretOrKeyring) {
  if (!token || typeof token !== 'string' || token.length > 8192) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, mac] = parts;
  if (!/^[A-Za-z0-9_-]+$/.test(body) || !/^[A-Za-z0-9_-]+$/.test(mac)) return null;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch { return null; }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;

  const isKeyring = secretOrKeyring instanceof Map ||
    (secretOrKeyring && typeof secretOrKeyring === 'object' && !Buffer.isBuffer(secretOrKeyring) &&
      !(secretOrKeyring instanceof Uint8Array));
  const candidates = [];
  if (isKeyring) {
    const entries = secretOrKeyring instanceof Map
      ? [...secretOrKeyring.entries()]
      : Object.entries(secretOrKeyring);
    if (typeof payload.kid === 'string' && SECRET_ID_RE.test(payload.kid)) {
      const selected = entries.find(([keyId]) => keyId === payload.kid);
      if (selected) candidates.push(selected);
    } else if (payload.kid === undefined) {
      // Short rolling-upgrade compatibility for tokens minted immediately
      // before `kid` was introduced. They still expire within the normal TTL.
      candidates.push(...entries.slice(0, 16));
    }
  } else if (typeof secretOrKeyring === 'string' || secretOrKeyring instanceof Uint8Array) {
    candidates.push([typeof payload.kid === 'string' ? payload.kid : 'primary', secretOrKeyring]);
  }
  if (!candidates.length) return null;

  const given = Buffer.from(mac, 'base64url');
  for (const [keyId, candidateSecret] of candidates) {
    if (typeof candidateSecret !== 'string' && !(candidateSecret instanceof Uint8Array)) continue;
    const expected = crypto.createHmac('sha256', candidateSecret).update(body).digest();
    if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) continue;
    if (!Number.isFinite(payload.exp) || Date.now() > payload.exp) return null;
    payload.kid = keyId;
    return payload;
  }
  return null;
}

const WATERMARK_FIELDS = new Set(['text', 'color', 'opacity', 'cornerOpacity', 'tile', 'corner', 'angle']);

/** True only for the bounded string/object shapes that may travel in a token. */
export function validateWatermarkValue(value) {
  try {
    if (typeof value === 'string') return value.length > 0 && value.length <= 512 && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value);
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
    const keys = Object.keys(value);
    if (!keys.length || keys.some((key) => !WATERMARK_FIELDS.has(key))) return false;
    if (value.text !== undefined && (typeof value.text !== 'string' || !value.text || value.text.length > 512)) return false;
    if (value.color !== undefined && (typeof value.color !== 'string' || !value.color || value.color.length > 64)) return false;
    for (const field of ['opacity', 'cornerOpacity']) {
      if (value[field] !== undefined && (typeof value[field] !== 'number' || !Number.isFinite(value[field]) || value[field] < 0 || value[field] > 1)) return false;
    }
    for (const field of ['tile', 'corner']) {
      if (value[field] !== undefined && typeof value[field] !== 'boolean') return false;
    }
    if (value.angle !== undefined && (typeof value.angle !== 'number' || !Number.isFinite(value.angle) || value.angle < -360 || value.angle > 360)) return false;
    return true;
  } catch { return false; }
}

function isPlainObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

const TOKEN_CLAIM_FIELDS = new Set([
  'v', 'kid', 'aud', 'scope', 'id', 'w', 'iat', 'exp', 'n', 'q', 'fmt', 'ls', 'vh', 'th', 'wm',
  'sg', 'sgp', 'sgs', 'sge', 'sgv', 'sgx', 'sgy', 'sgi', 'sgk', 'nsg', 'b', 'jkt',
]);

/** Strict server-side claim validation for v2 Archx image tokens. Signature
 * verification alone is not enough: audience, scope, image, width, issued-at,
 * expiry window, nonce shape, optional delivery claims, and the claim-key
 * allowlist are all checked before a token is spent. */
export function validateTokenClaims(payload, {
  id,
  maxWidthCap = 8192,
  maxTtlMs = 900000,
  now = Date.now(),
  clockSkewMs = 300000,
} = {}) {
  try {
    if (!isPlainObject(payload)) return false;
    if (Object.keys(payload).some((field) => !TOKEN_CLAIM_FIELDS.has(field))) return false;
    if (payload.v !== 2 || payload.aud !== TOKEN_AUDIENCE || payload.scope !== TOKEN_SCOPE) return false;
    if (payload.kid !== undefined && (typeof payload.kid !== 'string' || !SECRET_ID_RE.test(payload.kid))) return false;
    if (!validateImageId(payload.id) || (id && payload.id !== id)) return false;
    if (!Number.isSafeInteger(payload.w) || payload.w < 64 || payload.w > maxWidthCap) return false;
    if (!Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp)) return false;
    if (payload.iat > now + clockSkewMs || payload.exp <= payload.iat) return false;
    if (payload.exp - payload.iat > maxTtlMs + clockSkewMs || payload.exp <= now) return false;
    if (typeof payload.n !== 'string' || !/^[A-Za-z0-9_-]{8,86}$/.test(payload.n)) return false;
    if (payload.q != null && payload.q !== 'lossless' &&
        !(Number.isInteger(payload.q) && payload.q >= 1 && payload.q <= 100)) return false;
    if (payload.fmt != null && !['webp', 'png', 'jpeg', 'avif'].includes(payload.fmt)) return false;
    if (payload.ls !== undefined && payload.ls !== 1) return false;
    if (payload.sgp !== undefined && payload.sgp !== 0) return false;
    if (payload.sgv !== undefined && payload.sgv !== 2) return false;
    if (payload.sge !== undefined && payload.sge !== 0 && payload.sge !== 1) return false;
    if (payload.sgi !== undefined && payload.sgi !== 1) return false;
    if (payload.sgk !== undefined && payload.sgk !== 1) return false;
    if (payload.nsg !== undefined && payload.nsg !== 1) return false;
    if (payload.sgs !== undefined && (typeof payload.sgs !== 'number' || !Number.isFinite(payload.sgs) || payload.sgs < 1 || payload.sgs > 16)) return false;
    if (payload.sgx !== undefined && (!Number.isInteger(payload.sgx) || payload.sgx < 4 || payload.sgx > 64)) return false;
    if (payload.sgy !== undefined && (!Number.isInteger(payload.sgy) || payload.sgy < 4 || payload.sgy > 64)) return false;
    if (payload.vh !== undefined && (typeof payload.vh !== 'string' || !/^[A-Za-z0-9_-]{20}$/.test(payload.vh))) return false;
    if (payload.th !== undefined && (typeof payload.th !== 'string' || !/^[A-Za-z0-9_-]{20}$/.test(payload.th))) return false;
    if (payload.jkt !== undefined && (typeof payload.jkt !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(payload.jkt))) return false;
    if (payload.sg !== undefined && (typeof payload.sg !== 'string' || !payload.sg || payload.sg.length > 512 || /[\u0000-\u001f\u007f]/.test(payload.sg))) return false;
    if (payload.wm !== undefined && payload.wm !== null && !validateWatermarkValue(payload.wm)) return false;
    if (payload.b !== undefined) {
      if (!isPlainObject(payload.b)) return false;
      const bindFields = new Set(['ip', 'ua', 'sess']);
      for (const [field, value] of Object.entries(payload.b)) {
        if (!bindFields.has(field) || typeof value !== 'string' || !/^[A-Za-z0-9_-]{16}$/.test(value)) return false;
      }
    }
    return true;
  } catch { return false; }
}

function decodeBase64UrlStrict(value, { minBytes = 1, maxBytes = 4096 } = {}) {
  if (typeof value !== 'string' || !value || value.length > Math.ceil(maxBytes * 4 / 3) + 4 ||
      !/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try {
    const bytes = Buffer.from(value, 'base64url');
    if (bytes.length < minBytes || bytes.length > maxBytes || bytes.toString('base64url') !== value) return null;
    return bytes;
  } catch { return null; }
}

function normalizeProofJwk(value) {
  if (!isPlainObject(value)) return null;
  const fields = Object.keys(value);
  if (fields.length !== 4 || fields.some((field) => !['kty', 'crv', 'x', 'y'].includes(field))) return null;
  if (value.kty !== 'EC' || value.crv !== 'P-256') return null;
  const x = decodeBase64UrlStrict(value.x, { minBytes: 32, maxBytes: 32 });
  const y = decodeBase64UrlStrict(value.y, { minBytes: 32, maxBytes: 32 });
  if (!x || !y) return null;
  return { kty: 'EC', crv: 'P-256', x: value.x, y: value.y };
}

/** RFC 7638 JWK thumbprint for the only accepted proof key type (EC P-256).
 * Returns null for unsupported, malformed, or off-curve keys. */
export function computeJwkThumbprint(value) {
  const jwk = normalizeProofJwk(value);
  if (!jwk) return null;
  try {
    // Importing through Node's JWK loader rejects points that are not on
    // P-256; the canonical member order below is required by RFC 7638.
    crypto.createPublicKey({ key: jwk, format: 'jwk' });
    const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
    return crypto.createHash('sha256').update(canonical, 'utf8').digest().toString('base64url');
  } catch { return null; }
}

function parseProofPublicKeyHeader(value) {
  if (typeof value !== 'string' || !value || value.length > 1024) return null;
  const bytes = decodeBase64UrlStrict(value, { minBytes: 2, maxBytes: 512 });
  if (!bytes) return null;
  try {
    const jwk = normalizeProofJwk(JSON.parse(bytes.toString('utf8')));
    const jkt = jwk ? computeJwkThumbprint(jwk) : null;
    return jkt ? { jwk, jkt } : null;
  } catch { return null; }
}

/**
 * Verify an Archx DPoP-style proof-of-possession header. This is intentionally
 * narrower than a general JWT/DPoP library: one algorithm (ECDSA P-256 with
 * SHA-256), one method/path, a two-minute maximum lifetime, an access-token
 * hash, and a caller-claimed one-time proof id. It makes a token copied out of
 * logs/history/tooling useless in another browser that lacks the page's
 * non-extractable private key; it does not stop script running in the
 * legitimate page or the browser operator from requesting a proof.
 */
const proofKeyCache = new Map(); // jkt -> KeyObject (bounded, process-local)

function verifyProofOfPossession({ header, token, expectedJkt, method, target, now = Date.now() }) {
  try {
    if (typeof header !== 'string' || !header || header.length > 4096 ||
        typeof token !== 'string' || !token || !/^[A-Za-z0-9_-]{43}$/.test(String(expectedJkt || ''))) return null;
    const parts = header.split('.');
    if (parts.length !== 3 || parts[0] !== 'v1') return null;
    const payloadBytes = decodeBase64UrlStrict(parts[1], { minBytes: 2, maxBytes: 2048 });
    const signature = decodeBase64UrlStrict(parts[2], { minBytes: 64, maxBytes: 64 });
    if (!payloadBytes || !signature) return null;
    const proof = JSON.parse(payloadBytes.toString('utf8'));
    if (!isPlainObject(proof)) return null;
    const allowed = new Set(['jwk', 'jti', 'iat', 'exp', 'htm', 'htu', 'ath']);
    if (Object.keys(proof).length !== allowed.size || Object.keys(proof).some((field) => !allowed.has(field))) return null;
    const jwk = normalizeProofJwk(proof.jwk);
    if (!jwk || computeJwkThumbprint(jwk) !== expectedJkt) return null;
    if (typeof proof.jti !== 'string' || !/^[A-Za-z0-9_-]{8,86}$/.test(proof.jti)) return null;
    if (!Number.isSafeInteger(proof.iat) || !Number.isSafeInteger(proof.exp)) return null;
    if (proof.exp <= proof.iat || proof.exp - proof.iat > 120000) return null;
    if (proof.iat > now + 30000 || proof.exp <= now) return null;
    if (proof.htm !== String(method || '').toUpperCase() || proof.htu !== target) return null;
    const expectedAth = crypto.createHash('sha256').update(token, 'utf8').digest();
    const givenAth = decodeBase64UrlStrict(proof.ath, { minBytes: 32, maxBytes: 32 });
    if (!givenAth || !crypto.timingSafeEqual(givenAth, expectedAth)) return null;
    // KeyObject construction (JWK parse + curve validation) dominates the
    // non-signature cost of proof verification; cache by RFC 7638
    // thumbprint, which was just proven to identify this exact JWK.
    let publicKey = proofKeyCache.get(expectedJkt);
    if (!publicKey) {
      publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
      if (proofKeyCache.size >= 512) proofKeyCache.clear();
      proofKeyCache.set(expectedJkt, publicKey);
    }
    const ok = crypto.verify(
      'sha256',
      Buffer.from(`v1.${parts[1]}`, 'utf8'),
      { key: publicKey, dsaEncoding: 'ieee-p1363' },
      signature,
    );
    return ok ? { jti: proof.jti, exp: proof.exp, jkt: expectedJkt } : null;
  } catch { return null; }
}

function validateStegoConfig(value) {
  try {
    if (typeof value === 'boolean') return true;
    if (!isPlainObject(value)) return false;
    const fields = new Set(['perToken', 'scope', 'keyScope', 'profile', 'strength', 'gridX', 'gridY']);
    if (Object.keys(value).some((field) => !fields.has(field))) return false;
    if (value.perToken !== undefined && typeof value.perToken !== 'boolean') return false;
    if (value.scope !== undefined && !['viewer', 'image'].includes(value.scope)) return false;
    if (value.keyScope !== undefined && !['image', 'viewer'].includes(value.keyScope)) return false;
    if (value.profile !== undefined && !['standard', 'robust'].includes(value.profile)) return false;
    if (value.strength !== undefined && (typeof value.strength !== 'number' || !Number.isFinite(value.strength) || value.strength < 1 || value.strength > 16)) return false;
    if (value.gridX !== undefined && (!Number.isInteger(value.gridX) || value.gridX < 4 || value.gridX > 64)) return false;
    if (value.gridY !== undefined && (!Number.isInteger(value.gridY) || value.gridY < 4 || value.gridY > 64)) return false;
    return true;
  } catch { return false; }
}

/**
 * Fail-closed normalization of an authorize() result. Ambiguous host return
 * shapes such as `{ allowed:false }`, `{ allow:0 }`, `{ permissions:"view" }`,
 * unknown-only objects, or invalid entitlement values deny instead of being
 * silently widened into an authorized full-size delivery.
 */
export function normalizeAuthorizationResult(auth) {
  try {
    if (auth === true) return Object.freeze({});
    if (!auth || typeof auth !== 'object' || Array.isArray(auth)) return null;
    for (const field of ['allow', 'allowed', 'authorized']) {
      if (field in auth && auth[field] !== true) return null;
    }
    if (auth.deny === true || auth.ok === false || auth.success === false || auth.error) return null;

    let scopes = null;
    if ('permissions' in auth || 'scopes' in auth) {
      const raw = 'permissions' in auth ? auth.permissions : auth.scopes;
      if (!Array.isArray(raw) || raw.some((scope) => typeof scope !== 'string')) return null;
      scopes = raw;
    } else if ('scope' in auth) {
      if (typeof auth.scope !== 'string') return null;
      scopes = auth.scope.split(/[\s,]+/).filter(Boolean);
    }
    if (scopes && !scopes.some((scope) => ['image:view', 'archx:image:view', '*'].includes(scope))) return null;

    const knownFields = [
      'allow', 'allowed', 'authorized', 'viewerId', 'userId', 'subject', 'sessionId',
      'buyerId', 'orderId', 'deliveryId', 'traceId',
      'permissions', 'scopes', 'scope', 'maxWidth', 'quality', 'lossless', 'format',
      'watermark', 'steganography', 'stegoFingerprint',
    ];
    if (!knownFields.some((field) => field in auth && auth[field] !== undefined)) return null;

    let viewerId = '';
    for (const field of ['viewerId', 'userId', 'subject', 'sessionId']) {
      if (!(field in auth) || auth[field] == null) continue;
      if (!['string', 'number', 'bigint'].includes(typeof auth[field])) return null;
      viewerId = String(auth[field]);
      if (!viewerId || viewerId.length > 512 || /[\u0000-\u001f\u007f]/.test(viewerId)) return null;
      break;
    }
    const traceFields = {};
    for (const field of ['buyerId', 'orderId', 'deliveryId', 'traceId']) {
      if (!(field in auth) || auth[field] == null) continue;
      if (!['string', 'number', 'bigint'].includes(typeof auth[field])) return null;
      const value = String(auth[field]);
      if (!value || value.length > 256 || /[\u0000-\u001f\u007f]/.test(value)) return null;
      traceFields[field] = value;
    }
    if ('maxWidth' in auth && auth.maxWidth !== undefined &&
        (typeof auth.maxWidth !== 'number' || !Number.isFinite(auth.maxWidth) || auth.maxWidth < 64 || auth.maxWidth > 1000000)) return null;
    if ('quality' in auth && auth.quality !== undefined && auth.quality !== 'lossless' &&
        (!Number.isInteger(auth.quality) || auth.quality < 1 || auth.quality > 100)) return null;
    if ('lossless' in auth && auth.lossless !== undefined && typeof auth.lossless !== 'boolean') return null;
    if ('format' in auth && auth.format !== undefined && !['webp', 'png', 'jpeg', 'avif'].includes(auth.format)) return null;
    if ('watermark' in auth && auth.watermark != null && typeof auth.watermark !== 'function' &&
        !validateWatermarkValue(auth.watermark)) return null;
    if ('steganography' in auth && auth.steganography !== undefined && !validateStegoConfig(auth.steganography)) return null;
    if ('stegoFingerprint' in auth && auth.stegoFingerprint !== undefined &&
        (typeof auth.stegoFingerprint !== 'string' || !auth.stegoFingerprint || auth.stegoFingerprint.length > 512 || /[\u0000-\u001f\u007f]/.test(auth.stegoFingerprint))) return null;

    const normalized = {};
    for (const field of knownFields) {
      if (!(field in auth) || auth[field] === undefined) continue;
      normalized[field] = isPlainObject(auth[field]) ? { ...auth[field] } : auth[field];
    }
    if (viewerId) normalized.viewerId = viewerId;
    Object.assign(normalized, traceFields);
    return Object.freeze(normalized);
  } catch { return null; }
}

function inspectServerConfig(options = {}) {
  const issues = [];
  const warnings = [];
  const fail = (msg) => issues.push(msg);
  const warn = (msg) => warnings.push(msg);
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    return { ok: false, issues: ['options must be an object'], warnings, config: null };
  }

  const knownTopLevelOptions = new Set([
    'abuseDetection', 'activeSecretId', 'allowAnonymous', 'allowClientQuality', 'allowQueryTokens',
    'taintImage',
    'allowedInputFormats', 'allowedOrigins', 'authorize', 'authorizeTimeoutMs',
    'basePath', 'batchTokenMaxBytes', 'batchTokenMaxItems', 'bindTokenTo',
    'blockUntrustedSharpLoaders', 'cacheMasters',
    'callbackTimeoutMs', 'deploymentMode', 'encrypt', 'forensic', 'forensicPerToken',
    'forensicScope', 'format', 'grid',
    'images', 'imagesDir', 'imagesDirs', 'lossless', 'masterCacheMaxBytes',
    'maxConcurrentProcessing', 'maxInputBytes', 'maxInputHeight', 'maxInputPixels',
    'maxInputWidth', 'maxOutputPixels', 'maxTrackedClients', 'maxWidthCap', 'onAbuse',
    'onDelivery', 'onProvenanceIssue', 'onSecurityEvent', 'onStegoIssue', 'oneTimeTokenMaxEntries',
    'oneTimeTokens', 'proofOfPossession', 'provenanceFailure',
    'outputCacheDir', 'outputCacheDiskMaxBytes', 'outputCacheDiskMaxEntries',
    'outputCacheDiskTtlMs', 'outputCacheMax', 'outputCacheMaxBytes', 'processing', 'processingConcurrency',
    'processingQueueMax', 'processingQueueTimeoutMs', 'processingTimeoutSec',
    'publicDir', 'publicDirs', 'quality', 'quotas', 'rateLimitMaxClients',
    'rateLimitPerMinute', 'requireSameSiteTokenRequests', 'requireTokenRequestHeader',
    'scrambleKeyMode', 'scramblePlanVersion', 'secret', 'secretId', 'secrets', 'serverWatermark', 'sharedCacheTtlMs',
    'stateStore', 'stateStoreTimeoutMs', 'steganography',
    'stegoRegistryFailure', 'timeoutSec', 'tokenMethods', 'tokenRateLimitPerMinute',
    'trustProxy', 'trustedProxyHops', 'ttlSec', 'widthBuckets',
  ]);
  for (const field of Object.keys(options)) {
    if (!knownTopLevelOptions.has(field)) fail(`unknown option ${field} (refusing to silently ignore a possible security-setting typo)`);
  }

  const normalizeSecretValue = (value) => {
    if (typeof value === 'string') return value;
    if (value instanceof Uint8Array) {
      return Buffer.isBuffer(value)
        ? value
        : Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    }
    return null;
  };
  const signingKeys = new Map();
  const directSecretId = options.secretId == null || options.secretId === ''
    ? (process.env.ARCHX_SECRET_ID || 'primary')
    : String(options.secretId);
  if (!SECRET_ID_RE.test(directSecretId)) fail('secretId must contain 1-64 letters, digits, dot, underscore, or hyphen characters and start with a letter or digit');
  // An explicit `secrets` keyring is authoritative: do not silently add an
  // ambient ARCHX_SECRET (and potentially make it active) alongside it. The
  // environment remains the fallback for the original single-secret form.
  const directSecretRaw = options.secret ??
    (options.secrets === undefined ? process.env.ARCHX_SECRET : undefined);
  if (directSecretRaw != null && directSecretRaw !== '') {
    const directSecret = normalizeSecretValue(directSecretRaw);
    if (directSecret == null) fail('secret must be a string or byte array');
    else signingKeys.set(directSecretId, directSecret);
  }
  if (options.secrets !== undefined) {
    let entries = null;
    if (options.secrets instanceof Map) entries = [...options.secrets.entries()];
    else if (isPlainObject(options.secrets)) entries = Object.entries(options.secrets);
    if (!entries) fail('secrets must be an object or Map mapping key IDs to secret strings/byte arrays');
    else {
      for (const [keyIdRaw, valueRaw] of entries) {
        const keyId = String(keyIdRaw);
        if (!SECRET_ID_RE.test(keyId)) {
          fail(`secrets key "${keyId}" has an invalid key ID`);
          continue;
        }
        const value = normalizeSecretValue(valueRaw);
        if (value == null || (typeof value === 'string' && !value) || (Buffer.isBuffer(value) && !value.length)) {
          fail(`secrets["${keyId}"] must be a non-empty string or byte array`);
          continue;
        }
        if (signingKeys.has(keyId)) {
          const existing = signingKeys.get(keyId);
          const same = Buffer.isBuffer(existing) && Buffer.isBuffer(value)
            ? existing.equals(value)
            : String(existing) === String(value);
          if (!same) fail(`secrets["${keyId}"] conflicts with secret/secretId`);
          continue;
        }
        signingKeys.set(keyId, value);
      }
    }
  }
  if (signingKeys.size > 16) fail('the signing keyring may contain at most 16 keys');
  let activeSecretId = options.activeSecretId == null || options.activeSecretId === ''
    ? null
    : String(options.activeSecretId);
  if (activeSecretId && !SECRET_ID_RE.test(activeSecretId)) fail('activeSecretId has an invalid key ID');
  if (!activeSecretId) {
    if (signingKeys.has(directSecretId)) activeSecretId = directSecretId;
    else if (signingKeys.size === 1) activeSecretId = signingKeys.keys().next().value;
  }
  if (!signingKeys.size) fail('secret is required (options.secret, options.secrets + activeSecretId, or ARCHX_SECRET)');
  else if (!activeSecretId || !signingKeys.has(activeSecretId)) fail('activeSecretId must identify the key used to sign new tokens');
  const secretDigests = new Set();
  for (const [keyId, value] of signingKeys) {
    const rawSecret = Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
    const digest = crypto.createHash('sha256').update(rawSecret).digest('hex');
    if (secretDigests.has(digest)) fail('signing-key IDs must not reuse the same secret value');
    secretDigests.add(digest);
    const secretText = typeof value === 'string' ? value.toLowerCase() : '';
    if (rawSecret.length < 32 || KNOWN_WEAK_SECRETS.has(secretText)) {
      fail(`secret for signing key "${keyId}" must be at least 32 bytes and not a known demo/test value`);
    } else if (new Set(rawSecret).size < 8) {
      warn(`signing key "${keyId}" has very low byte diversity; use at least 32 random bytes from a CSPRNG`);
    }
  }
  const secret = activeSecretId ? signingKeys.get(activeSecretId) : undefined;

  const deploymentMode = options.deploymentMode ?? 'single-instance';
  if (!['single-instance', 'multi-instance'].includes(deploymentMode)) {
    fail("deploymentMode must be 'single-instance' or 'multi-instance'");
  }
  const suppliedStateStore = options.stateStore ?? null;
  if (options.stateStore !== undefined && options.stateStore !== null) {
    const requiredMethods = ['claimOnce', 'hitWindow', 'trackDistinct'];
    if (typeof suppliedStateStore !== 'object' || requiredMethods.some((method) => typeof suppliedStateStore[method] !== 'function')) {
      fail('stateStore must implement claimOnce(key, ttlMs), hitWindow(key, options), and trackDistinct(key, member, options)');
    }
    for (const method of ['getCache', 'setCache', 'stats', 'close']) {
      if (suppliedStateStore?.[method] !== undefined && typeof suppliedStateStore[method] !== 'function') {
        fail(`stateStore.${method} must be a function when present`);
      }
    }
  } else if (options.stateStore === null && deploymentMode === 'multi-instance') {
    fail('stateStore is required in multi-instance deployments');
  }
  if (deploymentMode === 'multi-instance' && !suppliedStateStore) {
    fail('deploymentMode "multi-instance" requires a shared, atomic stateStore; the built-in memory store is process-local');
  }
  if (deploymentMode === 'multi-instance' && suppliedStateStore?.kind === 'memory') {
    fail('the built-in memory stateStore cannot coordinate multiple processes; supply a shared atomic store');
  }
  if (!suppliedStateStore) {
    warn('stateStore defaults to process-local memory: run one middleware process or supply a shared atomic stateStore before scaling horizontally');
  }

  const authorize = options.authorize ?? null;
  if (authorize != null && typeof authorize !== 'function') fail('authorize must be a function');
  if (options.allowAnonymous !== undefined && typeof options.allowAnonymous !== 'boolean') fail('allowAnonymous must be boolean');
  const allowAnonymous = options.allowAnonymous === true;
  if (!authorize && !allowAnonymous) {
    fail('authorize(req, id, { phase }) is required; set allowAnonymous:true only for an intentionally public catalog');
  }
  if (allowAnonymous && !authorize) warn('allowAnonymous is enabled: anyone who can reach the site can request authorized-size derivatives');

  if (options.imagesDir !== undefined && (typeof options.imagesDir !== 'string' || !options.imagesDir)) fail('imagesDir must be a non-empty string');
  if (options.imagesDirs !== undefined && (!Array.isArray(options.imagesDirs) || options.imagesDirs.some((dir) => typeof dir !== 'string' || !dir))) {
    fail('imagesDirs must be an array of non-empty strings');
  }
  if (options.images !== undefined) {
    if (!isPlainObject(options.images) || Object.values(options.images).some((value) => typeof value !== 'string' || !value)) {
      fail('images must be an explicit object map of image id to file path strings');
    }
  }
  if (options.publicDir !== undefined && (typeof options.publicDir !== 'string' || !options.publicDir)) fail('publicDir must be a non-empty string');
  if (options.publicDirs !== undefined && (!Array.isArray(options.publicDirs) || options.publicDirs.some((dir) => typeof dir !== 'string' || !dir))) {
    fail('publicDirs must be an array of non-empty strings');
  }
  const dirs = options.imagesDirs || (options.imagesDir ? [options.imagesDir] : []);
  if ((!Array.isArray(dirs) || !dirs.length) && !options.images) {
    fail('imagesDir, imagesDirs, or an explicit images map is required');
  }
  if (!Array.isArray(dirs)) fail('imagesDirs must be an array');

  const checkInt = (name, value, min, max) => {
    if (value == null) return;
    if (!Number.isInteger(value) || value < min || value > max) fail(`${name} must be an integer from ${min} to ${max}`);
  };
  const checkNumber = (name, value, min, max) => {
    if (value == null) return;
    if (typeof value !== 'number' || !Number.isFinite(value) || value < min || value > max) fail(`${name} must be from ${min} to ${max}`);
  };
  const checkBoolean = (name, value) => {
    if (value !== undefined && typeof value !== 'boolean') fail(`${name} must be boolean`);
  };
  const checkUnknownKeys = (name, value, allowed) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return;
    for (const field of Object.keys(value)) {
      if (!allowed.has(field)) fail(`${name}.${field} is not a supported option`);
    }
  };

  const basePathRaw = options.basePath ?? '/archx';
  const basePathSegments = typeof basePathRaw === 'string' ? basePathRaw.split('/').filter(Boolean) : [];
  if (typeof basePathRaw !== 'string' || basePathRaw.length > 128 || !basePathRaw.startsWith('/') ||
      basePathRaw.includes('\\') || basePathRaw.includes('?') || basePathRaw.includes('#') ||
      basePathSegments.length < 1 || basePathSegments.some((part) => part === '.' || part === '..' || !/^[A-Za-z0-9._~-]+$/.test(part))) {
    fail('basePath must be a simple absolute URL path without traversal, query, or fragment');
  }
  checkInt('ttlSec', options.ttlSec, 5, 900);
  checkInt('batchTokenMaxItems', options.batchTokenMaxItems, 1, 500);
  checkInt('batchTokenMaxBytes', options.batchTokenMaxBytes, 1024, 1024 * 1024);
  if (options.forensicScope !== undefined && !['viewer', 'image'].includes(options.forensicScope)) {
    fail("forensicScope must be 'viewer' or 'image'");
  }
  if (options.widthBuckets !== undefined && options.widthBuckets !== null) {
    if (!Array.isArray(options.widthBuckets) || options.widthBuckets.length > 32 ||
        options.widthBuckets.some((value) => !Number.isInteger(value) || value < 64 || value > 8192)) {
      fail('widthBuckets must be an array of up to 32 integer widths from 64 to 8192, or null to disable canonical widths');
    }
  }
  if (options.outputCacheDir !== undefined && options.outputCacheDir !== null &&
      (typeof options.outputCacheDir !== 'string' || !options.outputCacheDir ||
       options.outputCacheDir.length > 4096 || options.outputCacheDir.includes('\0'))) {
    fail('outputCacheDir must be a non-empty filesystem path string');
  }
  checkInt('outputCacheDiskMaxBytes', options.outputCacheDiskMaxBytes, 0, 16 * 1024 * 1024 * 1024 * 1024);
  checkInt('outputCacheDiskMaxEntries', options.outputCacheDiskMaxEntries, 0, 1000000);
  checkInt('outputCacheDiskTtlMs', options.outputCacheDiskTtlMs, 0, 365 * 24 * 3600 * 1000);
  checkInt('grid', options.grid, 2, 32);
  checkInt('maxWidthCap', options.maxWidthCap, 64, 8192);
  checkInt('callbackTimeoutMs', options.callbackTimeoutMs ?? options.authorizeTimeoutMs, 100, 60000);
  checkInt('trustedProxyHops', options.trustedProxyHops, 0, 20);
  for (const field of [
    'oneTimeTokens', 'encrypt', 'lossless', 'allowClientQuality', 'forensicPerToken',
    'cacheMasters', 'trustProxy', 'requireSameSiteTokenRequests',
    'requireTokenRequestHeader', 'allowQueryTokens', 'taintImage',
  ]) checkBoolean(field, options[field]);
  if (options.quality != null && options.quality !== 'lossless') checkInt('quality', options.quality, 1, 100);
  if (options.format != null && !['webp', 'png', 'jpeg', 'avif'].includes(options.format)) fail("format must be 'webp', 'png', 'jpeg', or 'avif'");
  if (options.scrambleKeyMode != null && !['per-image', 'per-token'].includes(options.scrambleKeyMode)) fail('scrambleKeyMode is invalid');
  if (options.scramblePlanVersion != null && options.scramblePlanVersion !== 1 && options.scramblePlanVersion !== 2) fail('scramblePlanVersion must be 1 or 2');
  checkInt('rateLimitPerMinute', options.rateLimitPerMinute, 1, 1000000);
  checkInt('tokenRateLimitPerMinute', options.tokenRateLimitPerMinute, 1, 1000000);
  checkInt('rateLimitMaxClients', options.rateLimitMaxClients, 10, 1000000);
  checkInt('maxTrackedClients', options.maxTrackedClients, 10, 1000000);
  checkInt('oneTimeTokenMaxEntries', options.oneTimeTokenMaxEntries, 100, 5000000);
  checkInt('stateStoreTimeoutMs', options.stateStoreTimeoutMs, 1, 10000);
  checkInt('sharedCacheTtlMs', options.sharedCacheTtlMs, 0, 31 * 24 * 3600 * 1000);

  const tokenMethodsRaw = options.tokenMethods ?? ['POST'];
  if (!Array.isArray(tokenMethodsRaw) || !tokenMethodsRaw.length ||
      tokenMethodsRaw.some((m) => !['GET', 'POST'].includes(String(m).toUpperCase()))) {
    fail("tokenMethods must contain only 'GET' and/or 'POST'");
  } else if (tokenMethodsRaw.map((m) => String(m).toUpperCase()).includes('GET')) {
    warn('GET token minting is enabled for legacy clients; POST is preferred');
  }

  if (options.allowedOrigins != null) {
    if (!Array.isArray(options.allowedOrigins) || options.allowedOrigins.includes('*')) {
      fail("allowedOrigins must be an array of exact origins; '*' is not accepted for credentialed protected delivery");
    } else {
      for (const origin of options.allowedOrigins) {
        try {
          if (new URL(origin).origin !== origin) throw new Error('origin mismatch');
        } catch { fail(`allowedOrigins contains an invalid origin: ${String(origin)}`); }
      }
    }
  }

  if (options.processing !== undefined && (!isPlainObject(options.processing))) fail('processing must be an object');
  const processing = isPlainObject(options.processing) ? options.processing : {};
  checkUnknownKeys('processing', processing, new Set([
    'maxInputBytes', 'maxInputPixels', 'maxInputWidth', 'maxInputHeight', 'maxOutputPixels',
    'processingTimeoutSec', 'timeoutSec', 'allowedInputFormats', 'processingConcurrency',
    'maxConcurrentProcessing', 'processingQueueMax', 'processingQueueTimeoutMs',
    'blockUntrustedSharpLoaders', 'webpEffort', 'encoderEffort', 'webpSmartSubsample',
    'smartSubsample', 'resizeKernel', 'pngCompressionLevel', 'jpegChromaSubsampling',
    'sharpConcurrency', 'sharpCache',
  ]));
  const pick = (...names) => {
    for (const name of names) {
      if (options[name] != null) return options[name];
      if (processing[name] != null) return processing[name];
    }
    return undefined;
  };
  checkInt('maxInputBytes', pick('maxInputBytes'), 1024, 500 * 1024 * 1024);
  checkInt('maxInputPixels', pick('maxInputPixels'), 10000, 268402689);
  checkInt('maxInputWidth', pick('maxInputWidth'), 64, 65536);
  checkInt('maxInputHeight', pick('maxInputHeight'), 64, 65536);
  checkInt('maxOutputPixels', pick('maxOutputPixels'), 10000, 268402689);
  checkNumber('processingTimeoutSec', pick('processingTimeoutSec', 'timeoutSec'), 1, 120);
  checkInt('processingConcurrency', pick('processingConcurrency', 'maxConcurrentProcessing'), 1, 64);
  checkInt('processingQueueMax', pick('processingQueueMax'), 0, 10000);
  checkInt('processingQueueTimeoutMs', pick('processingQueueTimeoutMs'), 0, 120000);
  checkBoolean('blockUntrustedSharpLoaders', pick('blockUntrustedSharpLoaders'));
  checkInt('webpEffort', pick('webpEffort', 'encoderEffort'), 0, 6);
  checkBoolean('webpSmartSubsample', pick('webpSmartSubsample', 'smartSubsample'));
  checkInt('pngCompressionLevel', pick('pngCompressionLevel'), 0, 9);
  checkInt('sharpConcurrency', pick('sharpConcurrency'), 0, 1024);
  checkBoolean('sharpCache', pick('sharpCache'));
  if (pick('resizeKernel') !== undefined &&
      !['nearest', 'cubic', 'mitchell', 'lanczos2', 'lanczos3', 'mks2013', 'mks2021'].includes(pick('resizeKernel'))) {
    fail('processing.resizeKernel is invalid');
  }
  if (pick('jpegChromaSubsampling') !== undefined &&
      !['4:2:0', '4:4:4'].includes(pick('jpegChromaSubsampling'))) {
    fail("processing.jpegChromaSubsampling must be '4:2:0' or '4:4:4'");
  }
  const allowedInputFormatsRaw = pick('allowedInputFormats') ?? ['jpeg', 'png', 'webp', 'avif'];
  if (!Array.isArray(allowedInputFormatsRaw) || !allowedInputFormatsRaw.length ||
      allowedInputFormatsRaw.some((f) => !FORMAT_EXTENSIONS[String(f).toLowerCase()])) {
    fail('allowedInputFormats contains an unsupported format');
  }

  checkInt('outputCacheMax', options.outputCacheMax, 0, 100000);
  checkInt('outputCacheMaxBytes', options.outputCacheMaxBytes, 0, 4 * 1024 * 1024 * 1024);
  checkInt('masterCacheMaxBytes', options.masterCacheMaxBytes, 0, 4 * 1024 * 1024 * 1024);
  if (options.onSecurityEvent != null && typeof options.onSecurityEvent !== 'function') fail('onSecurityEvent must be a function');
  if (options.onAbuse != null && typeof options.onAbuse !== 'function') fail('onAbuse must be a function');
  if (options.onStegoIssue != null && typeof options.onStegoIssue !== 'function') fail('onStegoIssue must be a function');
  if (options.onProvenanceIssue != null && typeof options.onProvenanceIssue !== 'function') fail('onProvenanceIssue must be a function');
  if (options.onDelivery != null && typeof options.onDelivery !== 'function') fail('onDelivery must be a function');
  if (options.serverWatermark != null && typeof options.serverWatermark !== 'function' &&
      !validateWatermarkValue(options.serverWatermark)) fail('serverWatermark must be a bounded string, watermark object, or function');
  if (options.forensic !== undefined) {
    if (typeof options.forensic !== 'boolean' && !isPlainObject(options.forensic)) {
      fail('forensic must be boolean or an object');
    } else if (isPlainObject(options.forensic)) {
      checkUnknownKeys('forensic', options.forensic, new Set(['blockSize', 'delta']));
      checkInt('forensic.blockSize', options.forensic.blockSize, 4, 1024);
      checkNumber('forensic.delta', options.forensic.delta, 0, 16);
    }
  }
  if (options.steganography !== undefined && !validateStegoConfig(options.steganography)) {
    fail('steganography must be boolean or a bounded { perToken, scope, keyScope, profile, strength, gridX, gridY } object');
  }
  if (options.bindTokenTo !== undefined) {
    if (!isPlainObject(options.bindTokenTo)) fail('bindTokenTo must be an object');
    else {
      checkUnknownKeys('bindTokenTo', options.bindTokenTo, new Set(['ip', 'userAgent', 'session']));
      for (const [field, value] of Object.entries(options.bindTokenTo)) {
        if (value === undefined) continue;
        if (typeof value !== 'boolean' && typeof value !== 'function' &&
            (typeof value !== 'string' || !value || value.length > 128 || /[\u0000-\u001f\u007f]/.test(value))) {
          fail(`bindTokenTo.${field} must be boolean, a function, or a bounded header name`);
        }
      }
    }
  }
  if (options.trustProxy === true && !(options.trustedProxyHops > 0)) {
    warn('trustProxy has no effect until trustedProxyHops names the exact number of trusted proxy hops; socket IP remains authoritative');
  }

  if (options.quotas !== undefined && !isPlainObject(options.quotas)) fail('quotas must be an object');
  const quotas = isPlainObject(options.quotas) ? options.quotas : {};
  checkUnknownKeys('quotas', quotas, new Set(['windowMs', 'perIp', 'perViewer', 'perIpImage', 'perViewerImage']));
  for (const name of ['perIp', 'perViewer', 'perIpImage', 'perViewerImage']) {
    if (quotas[name] != null) checkInt(`quotas.${name}`, quotas[name], 1, 100000000);
  }
  checkInt('quotas.windowMs', quotas.windowMs, 1000, 31 * 24 * 3600 * 1000);

  if (options.abuseDetection !== undefined && !isPlainObject(options.abuseDetection)) fail('abuseDetection must be an object');
  const abuse = isPlainObject(options.abuseDetection) ? options.abuseDetection : {};
  checkUnknownKeys('abuseDetection', abuse, new Set(['distinctImages', 'windowMs', 'action']));
  checkInt('abuseDetection.distinctImages', abuse.distinctImages, 1, 10000);
  checkInt('abuseDetection.windowMs', abuse.windowMs, 1000, 31 * 24 * 3600 * 1000);
  if (abuse.action != null && !['event', 'deny'].includes(abuse.action)) fail("abuseDetection.action must be 'event' or 'deny'");

  const availableParallelism = typeof os.availableParallelism === 'function' ? os.availableParallelism() : (os.cpus()?.length || 2);
  const config = Object.freeze({
    secret,
    signingKeys: Object.freeze(Object.fromEntries(signingKeys)),
    activeSecretId,
    deploymentMode,
    stateStore: suppliedStateStore,
    stateStoreTimeoutMs: options.stateStoreTimeoutMs ?? 250,
    sharedCacheTtlMs: options.sharedCacheTtlMs ?? 3600000,
    authorize,
    allowAnonymous,
    basePath: String(basePathRaw).replace(/\/$/, '') || '/archx',
    ttlMs: (options.ttlSec ?? 120) * 1000,
    grid: options.grid ?? 8,
    maxWidthCap: options.maxWidthCap ?? 1920,
    widthBuckets: options.widthBuckets == null
      ? null
      : Object.freeze([...new Set(options.widthBuckets)].sort((a, b) => a - b)),
    batchTokenMaxItems: options.batchTokenMaxItems ?? 100,
    batchTokenMaxBytes: options.batchTokenMaxBytes ?? 65536,
    forensicScope: options.forensicScope ?? 'viewer',
    tokenMethods: Object.freeze([...new Set((tokenMethodsRaw || ['POST']).map((m) => String(m).toUpperCase()))]),
    oneTimeTokens: options.oneTimeTokens !== false,
    rateLimitMaxClients: options.rateLimitMaxClients ?? options.maxTrackedClients ?? 10000,
    oneTimeTokenMaxEntries: options.oneTimeTokenMaxEntries ?? 100000,
    processing: Object.freeze({
      maxInputBytes: pick('maxInputBytes') ?? 50 * 1024 * 1024,
      maxInputPixels: pick('maxInputPixels') ?? 40000000,
      maxInputWidth: pick('maxInputWidth') ?? 12000,
      maxInputHeight: pick('maxInputHeight') ?? 12000,
      maxOutputPixels: pick('maxOutputPixels') ?? 16777216,
      timeoutSec: Number(pick('processingTimeoutSec', 'timeoutSec') ?? 10),
      allowedInputFormats: Object.freeze(allowedInputFormatsRaw.map((f) => String(f).toLowerCase())),
      blockUntrustedSharpLoaders: pick('blockUntrustedSharpLoaders') !== false,
      webpEffort: pick('webpEffort', 'encoderEffort') ?? 4,
      webpSmartSubsample: pick('webpSmartSubsample', 'smartSubsample') !== false,
      resizeKernel: pick('resizeKernel') ?? 'lanczos3',
      pngCompressionLevel: pick('pngCompressionLevel') ?? 9,
      jpegChromaSubsampling: pick('jpegChromaSubsampling') ?? '4:4:4',
      sharpConcurrency: pick('sharpConcurrency') ?? 0,
      sharpCache: pick('sharpCache'),
    }),
    processingConcurrency: pick('processingConcurrency', 'maxConcurrentProcessing') ?? Math.max(1, Math.min(4, availableParallelism || 2)),
    processingQueueMax: pick('processingQueueMax') ?? 100,
    processingQueueTimeoutMs: pick('processingQueueTimeoutMs') ?? 5000,
    quotas: Object.freeze({
      windowMs: quotas.windowMs ?? 3600000,
      perIp: quotas.perIp ?? null,
      perViewer: quotas.perViewer ?? null,
      perIpImage: quotas.perIpImage ?? null,
      perViewerImage: quotas.perViewerImage ?? null,
    }),
    abuseDetection: Object.freeze({
      distinctImages: abuse.distinctImages ?? 250,
      windowMs: abuse.windowMs ?? 600000,
      action: abuse.action ?? 'event',
    }),
    outputCacheMax: options.outputCacheMax ?? 100,
    outputCacheMaxBytes: options.outputCacheMaxBytes ?? 64 * 1024 * 1024,
    outputCacheDir: options.outputCacheDir ?? null,
    outputCacheDiskMaxBytes: options.outputCacheDiskMaxBytes ?? 2 * 1024 * 1024 * 1024,
    outputCacheDiskMaxEntries: options.outputCacheDiskMaxEntries ?? 20000,
    outputCacheDiskTtlMs: options.outputCacheDiskTtlMs ?? 30 * 24 * 3600 * 1000,
    masterCacheMaxBytes: options.masterCacheMaxBytes ?? 128 * 1024 * 1024,
    cacheMasters: options.cacheMasters !== false,
    trustProxy: options.trustProxy === true && (options.trustedProxyHops ?? 0) > 0,
    trustedProxyHops: options.trustedProxyHops ?? 0,
    requireSameSiteTokenRequests: options.requireSameSiteTokenRequests !== false,
    requireTokenRequestHeader: options.requireTokenRequestHeader !== false,
    // Bearer tokens belong in X-Archx-Token by default. Query transport is
    // retained only as an explicit compatibility opt-in because URL tokens
    // leak through history, Referer headers, screenshots of logs, and many
    // proxy/telemetry pipelines.
    allowQueryTokens: options.allowQueryTokens === true,
    // Public constant-bytes 1x1 PNG used to origin-taint 2D display canvases
    // in cross-origin deployments (see TAINT_PNG). Disable only if the host
    // route policy forbids any unauthenticated route under basePath.
    taintImage: options.taintImage !== false,
    scramblePlanVersion: options.scramblePlanVersion ?? 1,
    proofOfPossession: options.proofOfPossession === true ? 'required'
      : options.proofOfPossession === false ? 'off'
        : (options.proofOfPossession ?? 'optional'),
    callbackTimeoutMs: options.callbackTimeoutMs ?? options.authorizeTimeoutMs ?? 10000,
    stegoRegistryFailure: options.stegoRegistryFailure ?? 'deny',
    provenanceFailure: options.provenanceFailure ?? 'deny',
    publicDirs: Object.freeze([
      ...(options.publicDir ? [options.publicDir] : []),
      ...(Array.isArray(options.publicDirs) ? options.publicDirs : []),
    ]),
  });
  if (!['deny', 'allow'].includes(config.stegoRegistryFailure)) fail("stegoRegistryFailure must be 'deny' or 'allow'");
  if (!['deny', 'allow'].includes(config.provenanceFailure)) fail("provenanceFailure must be 'deny' or 'allow'");
  if (!['optional', 'required', 'off'].includes(config.proofOfPossession)) {
    fail("proofOfPossession must be 'optional', 'required', 'off', true, or false");
  }
  if (config.allowQueryTokens) warn('allowQueryTokens is enabled for compatibility: bearer tokens can leak through URLs, history, Referer headers, and logs; prefer header transport');
  if (config.proofOfPossession === 'off') warn('proofOfPossession is off: tokens remain bearer tokens if copied before expiry');
  if (config.proofOfPossession === 'optional') warn("proofOfPossession is optional: only tokens minted with a browser proof key are sender-constrained; use 'required' for the hardened production baseline when every supported client can present proofs");
  if (config.abuseDetection.action === 'event') warn("abuseDetection.action is 'event': suspicious distinct-image access is recorded through onSecurityEvent but is not blocked by Archx unless the host acts on it or selects action:'deny'");
  if (options.steganography && !options.onStegoIssue) warn('StegoMark is enabled without onStegoIssue: fingerprints will not be registered to a viewer/order, sharply limiting leak tracing');
  if (options.encrypt === true) warn('encrypt is enabled: the AES and scramble keys in the mint response are necessarily visible to the authorized browser/page and are not secrets from that viewer');
  if (options.allowClientQuality) warn('allowClientQuality lets browsers request quality up to the server entitlement; keep authorize() caps strict');
  if (config.oneTimeTokens === false) warn('oneTimeTokens is disabled: signed tokens can be replayed until expiry');
  if (!config.widthBuckets?.length) warn('widthBuckets is not configured: every viewport/DPR combination can create a distinct derivative and fragment the output cache; image-heavy sites should use canonical widths');
  if (!config.outputCacheDir && !suppliedStateStore) warn('no persistent outputCacheDir or shared state-store cache is configured: derivative reuse is limited to this process memory and is lost on restart');
  if (options.scrambleKeyMode === 'per-token') warn('scrambleKeyMode per-token makes every issued view a distinct derivative, defeating cross-viewer output caching');
  if (options.encrypt !== true) warn('encrypt is off: scrambled payloads are obfuscation only and can be reassembled keylessly by tile-edge continuity (jigsaw) solvers — enable encrypt:true for payload secrecy');
  if ((options.scramblePlanVersion ?? 1) !== 2) warn('scramblePlanVersion 1 uses a 32-bit plan seed (brute-forceable permutation); deploy pv-aware clients and switch to scramblePlanVersion:2');
  if (options.forensic && config.forensicScope !== 'image') warn('viewer-scoped forensic marks make derivatives viewer-specific and reduce output-cache sharing; use forensicScope image for reusable catalog derivatives');
  const stegoCfgForWarning = typeof options.steganography === 'object' && options.steganography ? options.steganography : {};
  if (options.steganography && stegoCfgForWarning.scope !== 'image') warn('viewer/token-scoped StegoMark makes derivatives hard to share across viewers; use steganography { scope: "image", perToken: false } for reusable catalog derivatives');
  return { ok: issues.length === 0, issues, warnings, config: issues.length ? null : config };
}

/** Non-throwing production configuration audit. Never returns the secret. */
export function auditArchxServerConfig(options = {}) {
  let inspected;
  try { inspected = inspectServerConfig(options); }
  catch { inspected = { ok: false, issues: ['options could not be inspected safely'], warnings: [], config: null }; }
  const { ok, issues, warnings, config } = inspected;
  return Object.freeze({
    ok,
    issues: Object.freeze([...issues]),
    warnings: Object.freeze([...warnings]),
    summary: config ? Object.freeze({
      basePath: config.basePath,
      authorization: config.authorize ? 'authorize-callback' : 'explicit-anonymous',
      deploymentMode: config.deploymentMode,
      stateStore: config.stateStore ? (config.stateStore.kind || 'custom') : 'memory',
      activeSecretId: config.activeSecretId,
      signingKeyCount: Object.keys(config.signingKeys).length,
      tokenMethods: config.tokenMethods,
      oneTimeTokens: config.oneTimeTokens,
      maxWidthCap: config.maxWidthCap,
      widthBuckets: config.widthBuckets,
      batchTokenMaxItems: config.batchTokenMaxItems,
      forensicScope: config.forensicScope,
      diskOutputCache: !!config.outputCacheDir,
      processing: config.processing,
      processingConcurrency: config.processingConcurrency,
      requireTokenRequestHeader: config.requireTokenRequestHeader,
      requireSameSiteTokenRequests: config.requireSameSiteTokenRequests,
      allowQueryTokens: config.allowQueryTokens,
      taintImage: config.taintImage,
      scramblePlanVersion: config.scramblePlanVersion,
      proofOfPossession: config.proofOfPossession,
      abuseDetection: config.abuseDetection,
      quotasConfigured: Object.values(config.quotas).some((value) => typeof value === 'number' && value > 0),
      stegoRegistryConfigured: typeof options.onStegoIssue === 'function',
      provenanceHookConfigured: typeof options.onProvenanceIssue === 'function',
      deliveryHookConfigured: typeof options.onDelivery === 'function',
      securityEventHookConfigured: typeof (options.onSecurityEvent || options.onAbuse) === 'function',
      trustProxy: config.trustProxy,
      trustedProxyHops: config.trustedProxyHops,
    }) : null,
  });
}

/**
 * Defaults for a hardened paid/premium deployment. This helper only fills
 * fields the host left undefined; it cannot supply the secret, masters,
 * authorization callback, quotas, shared store, or client compatibility
 * decision for proof-of-possession. Run auditArchxProductionConfig() on the
 * final options in deployment tests.
 */
export function withHardenedProductionDefaults(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('Archx hardened production defaults: options must be an object');
  }
  const abuse = isPlainObject(options.abuseDetection) ? options.abuseDetection : {};
  return {
    tokenMethods: ['POST'],
    requireSameSiteTokenRequests: true,
    requireTokenRequestHeader: true,
    allowQueryTokens: false,
    proofOfPossession: 'required',
    oneTimeTokens: true,
    ttlSec: 120,
    callbackTimeoutMs: 10000,
    scramblePlanVersion: 2, // 128-bit permutation seed (see buildScramblePlan)
    // Scrambling alone is obfuscation: tile-edge continuity solvers can
    // reassemble unencrypted payloads without any key. AES-256-GCM is the
    // actual secrecy layer, so the hardened preset turns it on.
    encrypt: true,
    stegoRegistryFailure: 'deny',
    provenanceFailure: 'deny',
    ...options,
    abuseDetection: {
      distinctImages: 250,
      windowMs: 600000,
      ...abuse,
      action: abuse.action ?? 'deny',
    },
  };
}

/**
 * Defaults for a high-traffic, image-heavy catalog. This helper deliberately
 * optimizes for *transform once, reuse many times*: canonical widths, larger
 * bounded caches, faster WebP settings, image-scoped (rather than per-viewer)
 * baked marks when those marks are already enabled, and batch minting. It
 * does not supply authorization, secrets, masters, a state store, or a cache
 * directory, and it does not weaken token entitlement checks. Host-supplied
 * fields always win, including per-viewer tracing when a paid/high-value
 * workflow needs it more than cache sharing.
 */
export function withCatalogThroughputDefaults(options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    throw new TypeError('Archx catalog throughput defaults: options must be an object');
  }
  const processing = isPlainObject(options.processing) ? options.processing : {};
  let steganography = options.steganography;
  if (steganography === true) {
    steganography = { perToken: false, scope: 'image' };
  } else if (isPlainObject(steganography)) {
    steganography = { perToken: false, scope: 'image', ...steganography };
  }
  const available = typeof os.availableParallelism === 'function'
    ? os.availableParallelism()
    : (os.cpus()?.length || 2);
  const out = {
    quality: 88,
    format: 'webp',
    scrambleKeyMode: 'per-image',
    widthBuckets: [...DEFAULT_WIDTH_BUCKETS],
    batchTokenMaxItems: 100,
    outputCacheMax: 1000,
    outputCacheMaxBytes: 256 * 1024 * 1024,
    masterCacheMaxBytes: 256 * 1024 * 1024,
    sharedCacheTtlMs: 24 * 3600 * 1000,
    forensicPerToken: false,
    forensicScope: 'image',
    processingConcurrency: Math.max(1, Math.min(8, available || 2)),
    processingQueueMax: 500,
    ...options,
    processing: {
      webpEffort: 2,
      webpSmartSubsample: false,
      resizeKernel: 'lanczos2',
      pngCompressionLevel: 6,
      jpegChromaSubsampling: '4:2:0',
      sharpConcurrency: 1,
      ...processing,
    },
  };
  if (options.steganography !== undefined) out.steganography = steganography;
  return out;
}

/**
 * Stricter, named production-readiness audit. `auditArchxServerConfig()`
 * answers "is this configuration internally valid and fail-closed?" This
 * audit additionally answers "does it match the hardened baseline for a
 * valuable catalog?" It never returns secret values.
 */
export function auditArchxProductionConfig(options = {}, { expectedInstances = 1 } = {}) {
  const base = auditArchxServerConfig(options);
  const blockers = [...base.issues];
  const recommendations = [];
  if (!Number.isInteger(expectedInstances) || expectedInstances < 1 || expectedInstances > 10000) {
    blockers.push('expectedInstances must be an integer from 1 to 10000');
  }
  const summary = base.summary;
  if (summary) {
    if (summary.authorization !== 'authorize-callback') blockers.push('production deployments for valuable images need an authorize() callback; explicit anonymous access is a public catalog, not an entitlement boundary');
    if (summary.allowQueryTokens) blockers.push('allowQueryTokens must be false so bearer tokens stay out of URLs, history, Referer headers, and logs');
    if (summary.proofOfPossession !== 'required') blockers.push("proofOfPossession must be explicitly set to 'required' for the hardened baseline, after confirming every supported client can present proofs");
    if (!summary.oneTimeTokens) blockers.push('oneTimeTokens must be enabled');
    if (summary.tokenMethods.some((method) => method !== 'POST')) blockers.push("tokenMethods must be ['POST'] for the hardened baseline");
    if (!summary.requireTokenRequestHeader) blockers.push('requireTokenRequestHeader must be enabled');
    if (!summary.requireSameSiteTokenRequests) blockers.push('requireSameSiteTokenRequests must be enabled');
    if (Number.isInteger(expectedInstances) && expectedInstances > 1 &&
        (summary.deploymentMode !== 'multi-instance' || summary.stateStore === 'memory')) {
      blockers.push('expectedInstances > 1 requires deploymentMode multi-instance with a shared, atomic stateStore');
    }
    if (options.steganography && !summary.stegoRegistryConfigured) {
      blockers.push('StegoMark is enabled without onStegoIssue, so issued fingerprints cannot be traced to a buyer/order/delivery registry');
    }
    if (summary.abuseDetection.action !== 'deny') recommendations.push("abuseDetection.action is 'event': Archx records suspicious access but does not block it; select 'deny' or document the host response runbook");
    if (!summary.quotasConfigured) recommendations.push('configure per-viewer/IP/image quotas appropriate to the catalog and pricing model');
    if (!summary.securityEventHookConfigured) recommendations.push('configure onSecurityEvent and alert on replay, quota, scraping, registry, and state-store events');
    if (expectedInstances === 1 && summary.stateStore === 'memory') recommendations.push('the memory state store is valid only for one middleware process; declare and test the shared-store topology before adding a second process');
    if (!summary.provenanceHookConfigured) recommendations.push('configure onProvenanceIssue if an external C2PA/provenance registry or reverse-image monitoring workflow needs a signed issuance record');
    if (!summary.deliveryHookConfigured) recommendations.push('configure onDelivery if token issuance/redemption must feed monitoring, reverse-image-search, or enforcement systems');
    if (!summary.widthBuckets?.length) recommendations.push('configure widthBuckets (or withCatalogThroughputDefaults) so thousands of viewport/DPR combinations reuse a small set of derivatives');
    if (!summary.diskOutputCache && summary.stateStore === 'memory') recommendations.push('configure outputCacheDir on a persistent non-public volume and/or a shared cache-capable stateStore so cold Sharp work survives restarts and is shared across the fleet');
    if (options.scrambleKeyMode === 'per-token' || options.forensicPerToken === true) recommendations.push('per-token scramble/forensic material defeats cross-viewer derivative reuse; reserve it for high-value views and use shared catalog derivatives for ordinary browsing');
    if (options.encrypt === true) recommendations.push('encrypt derives a per-token AES key, so encrypted derivatives cannot be reused across viewers; reserve it for high-value views when catalog-scale derivative sharing matters');
  }
  return Object.freeze({
    ok: base.ok,
    ready: blockers.length === 0,
    blockers: Object.freeze([...new Set(blockers)]),
    recommendations: Object.freeze(recommendations),
    warnings: base.warnings,
    summary,
  });
}

function normalizeServerConfig(options = {}) {
  const inspected = inspectServerConfig(options);
  if (!inspected.ok) {
    throw new TypeError('Archx server configuration is invalid:\n- ' + inspected.issues.join('\n- '));
  }
  return inspected.config;
}


/** Deterministic 48-bit StegoMark ID for one issued view. Store the mapping
 *  from this fingerprint to your image/user/order in your own database. */
export function deriveStegoFingerprint({ id, nonce = '', viewerHash = '', secret, perToken = true } = {}) {
  if (!secret) throw new Error('Archx stego: secret required');
  return crypto.createHmac('sha256', secret)
    .update(`stego:${id}:${viewerHash}:${perToken ? nonce : 'static'}`)
    .digest('hex').slice(0, 12);
}

/** Key controlling StegoMark cell permutation for an image. The detector
 *  needs the same key; derive it from your server secret when investigating. */
export function deriveStegoKey(id, secret) {
  if (!secret) throw new Error('Archx stego: secret required');
  return crypto.createHmac('sha256', secret)
    .update('stego-key:' + id).digest('base64url').slice(0, 24);
}

export function createArchxMiddleware(options = {}) {
  const cfg = normalizeServerConfig(options);
  const signingKeys = cfg.signingKeys;
  const activeSecretId = cfg.activeSecretId;
  const secret = signingKeys[activeSecretId];
  const secretForToken = (payload) => payload?.kid ? signingKeys[payload.kid] : null;
  const basePath = cfg.basePath;
  const ttlMs = cfg.ttlMs;
  const grid = cfg.grid;
  const scramblePlanVersion = cfg.scramblePlanVersion;
  const maxWidthCap = cfg.maxWidthCap;
  const quality = options.quality ?? 95; // 'lossless' is also accepted
  const lossless = options.lossless === true;
  const format = options.format ?? 'webp'; // 'webp' | 'png' | 'jpeg'
  const scrambleKeyMode = options.scrambleKeyMode || 'per-image'; // | 'per-token'
  const encrypt = options.encrypt === true;
  // authorize: async (req, id, { phase:'token'|'image', token? }) =>
  // boolean | { allow?, viewerId?, maxWidth?, quality?, permissions?, watermark? }
  // It is invoked for BOTH token minting and signed-image redemption.
  const authorize = cfg.authorize;
  const rateMax = options.rateLimitPerMinute ?? 600;
  const tokenRateMax = options.tokenRateLimitPerMinute ?? 300;
  const oneTimeTokens = cfg.oneTimeTokens;
  const bindTokenTo = options.bindTokenTo || {}; // { ip?:boolean, userAgent?:boolean, session?:boolean }
  const allowedOrigins = options.allowedOrigins || null; // exact origins; supplemental, never authentication
  const serverWatermark = options.serverWatermark ?? null;
  const forensic = options.forensic ?? false; // true | { blockSize, delta }
  const forensicPerToken = options.forensicPerToken !== false;
  const forensicScope = cfg.forensicScope;
  const allowClientQuality = options.allowClientQuality === true;
  const steganography = options.steganography ?? false;
  const stegoGlobalCfg = typeof steganography === 'object' && steganography ? steganography : {};
  const onStegoIssue = options.onStegoIssue || null;
  const onProvenanceIssue = options.onProvenanceIssue || null;
  const onDelivery = options.onDelivery || null;
  const onSecurityEvent = options.onSecurityEvent || options.onAbuse || null;

  const allowedExtensions = new Set(
    cfg.processing.allowedInputFormats.flatMap((f) => FORMAT_EXTENSIONS[f] || []),
  );
  const publicRoots = cfg.publicDirs.map((dir) => {
    const abs = path.resolve(dir);
    try { return fs.realpathSync(abs); } catch { return abs; }
  });

  // Index masters: id -> { filePath, root }. Real paths are revalidated so a
  // symlink planted inside an approved directory cannot point outside it.
  const index = new Map();
  const dirs = options.imagesDirs || (options.imagesDir ? [options.imagesDir] : []);
  for (const dir of dirs) {
    let root;
    try { root = fs.realpathSync(path.resolve(dir)); }
    catch { throw new TypeError(`Archx server: images directory does not exist: ${String(dir)}`); }
    if (!fs.statSync(root).isDirectory()) throw new TypeError(`Archx server: images path is not a directory: ${String(dir)}`);
    for (const publicRoot of publicRoots) {
      if (pathsOverlap(root, publicRoot)) {
        throw new TypeError('Archx server: masters directory overlaps a configured public directory');
      }
    }
    for (const name of fs.readdirSync(root)) {
      const ext = path.extname(name).toLowerCase();
      if (!allowedExtensions.has(ext)) continue;
      const id = path.basename(name, ext);
      if (!validateImageId(id) || index.has(id)) continue;
      const candidate = path.join(root, name);
      let stat;
      try { stat = fs.lstatSync(candidate); } catch { continue; }
      if (!stat.isFile() && !stat.isSymbolicLink()) continue;
      let real;
      try { real = fs.realpathSync(candidate); } catch { continue; }
      if (!isPathInside(root, real) || !fs.statSync(real).isFile()) continue;
      index.set(id, Object.freeze({ filePath: real, root }));
    }
  }
  if (options.images) {
    if (!options.images || typeof options.images !== 'object' || Array.isArray(options.images)) {
      throw new TypeError('Archx server: images must be an explicit id -> path map');
    }
    for (const [id, p] of Object.entries(options.images)) {
      if (!validateImageId(id)) throw new TypeError(`Archx server: invalid image id in images map: ${id}`);
      const ext = path.extname(String(p)).toLowerCase();
      if (!allowedExtensions.has(ext)) throw new TypeError(`Archx server: unsupported image extension for id ${id}`);
      let real;
      try { real = fs.realpathSync(path.resolve(String(p))); }
      catch { throw new TypeError(`Archx server: image file does not exist for id ${id}`); }
      if (!fs.statSync(real).isFile()) throw new TypeError(`Archx server: image path is not a file for id ${id}`);
      for (const publicRoot of publicRoots) {
        if (isPathInside(publicRoot, real)) throw new TypeError('Archx server: an explicit master is inside a configured public directory');
      }
      index.set(id, Object.freeze({ filePath: real, root: null }));
    }
  }
  if (!index.size) throw new TypeError('Archx server: no supported master images were indexed');

  // Optional persistent L2 derivative cache. It stores only already-scrambled
  // .archx payloads under HMAC-derived names, is consulted only after the
  // normal token/authorization/replay checks, and must never live in a public
  // web root or inside/alongside the master tree it protects.
  let outputCacheDir = null;
  if (cfg.outputCacheDir) {
    const requestedDir = path.resolve(cfg.outputCacheDir);
    try { fs.mkdirSync(requestedDir, { recursive: true, mode: 0o700 }); }
    catch { throw new TypeError('Archx server: outputCacheDir could not be created'); }
    let realDir;
    try { realDir = fs.realpathSync(requestedDir); }
    catch { throw new TypeError('Archx server: outputCacheDir could not be resolved'); }
    if (!fs.statSync(realDir).isDirectory()) {
      throw new TypeError('Archx server: outputCacheDir is not a directory');
    }
    for (const publicRoot of publicRoots) {
      if (pathsOverlap(realDir, publicRoot)) {
        throw new TypeError('Archx server: outputCacheDir overlaps a configured public directory');
      }
    }
    for (const entry of index.values()) {
      if (pathsOverlap(realDir, path.dirname(entry.filePath))) {
        throw new TypeError('Archx server: outputCacheDir overlaps a master-image directory');
      }
    }
    outputCacheDir = realDir;
  }

  // realpath+stat on every request is two synchronous syscalls in the hot
  // path. Cache the resolution for a second: containment is re-verified on
  // every cache fill, and masterVersion (mtime+size) refreshes within the
  // same bound, so a swapped master takes effect ≤1s later.
  const indexedFileCache = new Map(); // id -> { at, filePath, stat }
  function resolveIndexedFile(id) {
    const entry = index.get(id);
    if (!entry) return null;
    const now = Date.now();
    const cached = indexedFileCache.get(id);
    if (cached && now - cached.at < 1000) return { filePath: cached.filePath, stat: cached.stat };
    let real;
    try { real = fs.realpathSync(entry.filePath); } catch { indexedFileCache.delete(id); return null; }
    if (entry.root && !isPathInside(entry.root, real)) { indexedFileCache.delete(id); return null; }
    let stat;
    try { stat = fs.statSync(real); } catch { indexedFileCache.delete(id); return null; }
    if (!stat.isFile()) { indexedFileCache.delete(id); return null; }
    if (indexedFileCache.size > 10000) indexedFileCache.clear();
    indexedFileCache.set(id, { at: now, filePath: real, stat });
    return { filePath: real, stat };
  }

  // per-image scramble key + aes key derivation (stable => output cacheable)
  const deriveScrambleKey = (id, nonce, keySecret = secret) =>
    scrambleKeyMode === 'per-token'
      ? nonce
      : crypto.createHmac('sha256', keySecret).update('scramble:' + id).digest('hex').slice(0, 32);
  const deriveAesKey = (id, nonce, keySecret = secret) =>
    crypto.createHmac('sha256', keySecret)
      .update('aes:' + id + ':' + (scrambleKeyMode === 'per-token' ? nonce : 'static'))
      .digest().toString('base64');

  const masterCache = new Map(); // id -> {mtimeMs,size,bytes}; byte-bounded LRU
  let masterCacheBytes = 0;
  // Resized base-frame cache for UNcacheable (per-token/per-viewer)
  // derivatives: stage-1 output (decoded+resized CLEAN raster) depends
  // only on master version + geometry, so the watermark, per-viewer
  // marks, and encryption can all start from it (stage 2) instead of
  // re-decoding the master.
  const baseCache = new Map(); // baseKey -> {data,w,h,hasAlpha,watermarked}
  let baseCacheBytes = 0;
  function getBaseCache(key) {
    const value = baseCache.get(key);
    if (value === undefined) return undefined;
    baseCache.delete(key); baseCache.set(key, value);
    return value;
  }
  // masterCache (encoded master bytes) and baseCache (decoded stage-1
  // frames) draw on ONE budget, cfg.masterCacheMaxBytes. In 1.12.0 each
  // enforced the cap independently, silently doubling the documented
  // master-side RAM ceiling (2x128 MB by default). Eviction prefers
  // master bytes — re-reading a file is cheap; a base frame costs a
  // Sharp decode+resize to rebuild. The just-inserted entry is never
  // evicted by its own admission.
  function evictMasterSide(protectedCache, protectedKey) {
    const cap = cfg.masterCacheMaxBytes;
    while (masterCacheBytes + baseCacheBytes > cap) {
      let evicted = false;
      for (const oldestKey of masterCache.keys()) {
        if (protectedCache === 'master' && oldestKey === protectedKey) continue;
        masterCacheBytes -= masterCache.get(oldestKey).bytes.length;
        masterCache.delete(oldestKey);
        evicted = true;
        break;
      }
      if (evicted) continue;
      for (const oldestKey of baseCache.keys()) {
        if (protectedCache === 'base' && oldestKey === protectedKey) continue;
        baseCacheBytes -= baseCache.get(oldestKey).data.length;
        baseCache.delete(oldestKey);
        evicted = true;
        break;
      }
      if (!evicted) break;
    }
  }
  function setBaseCache(key, base) {
    if (!cfg.cacheMasters || !base?.data || base.data.length > cfg.masterCacheMaxBytes) return;
    const previous = baseCache.get(key);
    if (previous) { baseCacheBytes -= previous.data.length; baseCache.delete(key); }
    baseCache.set(key, base);
    baseCacheBytes += base.data.length;
    evictMasterSide('base', key);
  }
  const dimensionCache = new Map(); // id -> {mtimeMs,size,width,height}
  const outputCache = new Map(); // cacheKey -> Buffer; entry- and byte-bounded LRU
  let outputCacheBytes = 0;
  const ownsStateStore = !cfg.stateStore;
  const stateStore = cfg.stateStore || createMemoryStateStore({
    maxClients: cfg.rateLimitMaxClients,
    maxEntries: cfg.oneTimeTokenMaxEntries,
    maxCacheEntries: cfg.outputCacheMax,
    maxCacheBytes: cfg.outputCacheMaxBytes,
  });
  const stateStoreUnavailable = (cause) => {
    const err = new Error('Archx state store unavailable');
    err.code = 'ARCHX_STATE_STORE_UNAVAILABLE';
    err.cause = cause;
    return err;
  };
  async function callStateStore(method, ...args) {
    let timer = null;
    try {
      return await Promise.race([
        Promise.resolve().then(() => stateStore[method](...args)),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error(`${method} timed out`)), cfg.stateStoreTimeoutMs);
          timer.unref?.();
        }),
      ]);
    } catch (err) {
      throw stateStoreUnavailable(err);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
  async function stateHitWindow(key, limit, windowMs) {
    const result = await callStateStore('hitWindow', key, { limit, windowMs, now: Date.now() });
    if (!result || typeof result !== 'object' || typeof result.limited !== 'boolean' ||
        !Number.isFinite(Number(result.retryAfterSec ?? 0)) || !Number.isFinite(Number(result.count ?? 0))) {
      throw stateStoreUnavailable(new Error('invalid hitWindow result'));
    }
    return {
      limited: result.limited,
      retryAfterSec: Math.max(0, Math.ceil(Number(result.retryAfterSec ?? 0))),
      count: Math.max(0, Math.floor(Number(result.count ?? 0))),
    };
  }
  async function stateClaimOnce(key, ttlMs) {
    if (!Number.isFinite(ttlMs) || ttlMs <= 0) return false;
    const result = await callStateStore('claimOnce', key, Math.ceil(ttlMs));
    if (typeof result !== 'boolean') throw stateStoreUnavailable(new Error('invalid claimOnce result'));
    return result;
  }
  async function stateTrackDistinct(key, member, limitHint = cfg.abuseDetection.distinctImages) {
    const result = await callStateStore('trackDistinct', key, member, {
      windowMs: cfg.abuseDetection.windowMs,
      // The member set only needs to prove "more than the limit": cap it
      // one past the CALLER's limit (aggregate tiers pass a larger hint).
      maxMembers: Math.min(10001, Math.max(1, Math.floor(limitHint) || 1) + 1),
      now: Date.now(),
    });
    if (!result || typeof result !== 'object' || !Number.isFinite(Number(result.distinct)) ||
        typeof result.isNew !== 'boolean') {
      throw stateStoreUnavailable(new Error('invalid trackDistinct result'));
    }
    return {
      distinct: Math.max(0, Math.floor(Number(result.distinct))),
      isNew: result.isNew,
    };
  }
  const sharedOutputCacheEnabled = !ownsStateStore && cfg.sharedCacheTtlMs > 0 &&
    typeof stateStore.getCache === 'function' && typeof stateStore.setCache === 'function';
  /* A disk/shared derivative cache is operator infrastructure, but its
   * bytes are still never served blind: they must parse as an Archx
   * container whose header matches this exact request (grid, width cap,
   * format, encryption). A poisoned, truncated, or mis-keyed entry then
   * degrades to an authorized reprocess instead of wrong pixels. Header
   * parsing only — no payload decode — so the check is cheap. */
  function isPlausibleCachedDerivative(bytes, expected) {
    if (!expected) return true;
    try {
      if (!isArchxContainer(bytes)) return false;
      const { header } = decodeContainer(bytes);
      return header.scrambled === true &&
        header.grid === expected.grid &&
        (header.pv ?? 1) === (expected.planVersion ?? 1) &&
        header.w >= 1 && header.w <= expected.maxWidth &&
        header.encrypted === expected.encrypted &&
        header.mime === expected.mime;
    } catch { return false; }
  }
  // Disk/shared derivative entries carry an HMAC tag (magic 'A1' + 32-byte
  // MAC over key || bytes). Cache keys are already HMAC-derived, which
  // stops targeted planting by filename; the tag additionally stops
  // content substitution by anyone who can write the cache (shared Redis,
  // host with a writable cache dir) but does not know the server secret:
  // structural validity alone would accept a forged container of matching
  // grid/size/mime. Memory-cache entries are in-process and untagged.
  // Verification accepts ANY keyring secret, not just the active one:
  // during a rolling rotation, peer instances legitimately write entries
  // under the previous active secret, and keying the tag to `secret`
  // alone made those entries fail verification (and, on the disk tier,
  // get unlinked as corrupt — cross-instance cache thrash in 1.12.0).
  // The tag's job is "written by someone holding a deployment secret",
  // and every keyring member qualifies. Entries retire with their kid.
  const cacheTagSecrets = [...new Set([secret, ...Object.values(signingKeys || {})])].slice(0, 17);
  const cacheTag = (key, bytes, keySecret = secret) => crypto.createHmac('sha256', keySecret)
    .update('archx-cache-v1\0', 'utf8').update(String(key), 'utf8').update('\0').update(bytes).digest();
  const tagCacheBytes = (key, bytes) => Buffer.concat([Buffer.from('A1', 'latin1'), cacheTag(key, bytes), bytes]);
  function untagCacheBytes(key, stored) {
    if (!stored || stored.length < 35) return null;
    if (stored[0] !== 0x41 || stored[1] !== 0x31) return null; // legacy/foreign entry → regenerate
    const bytes = stored.subarray(34);
    const presented = stored.subarray(2, 34);
    for (const keySecret of cacheTagSecrets) {
      if (crypto.timingSafeEqual(presented, cacheTag(key, bytes, keySecret))) {
        return Buffer.from(bytes);
      }
    }
    return null;
  }
  async function getSharedOutputCache(key, expected = null) {
    if (!sharedOutputCacheEnabled || !cfg.outputCacheMax || !cfg.outputCacheMaxBytes) return null;
    try {
      const value = await callStateStore('getCache', key);
      let bytes = null;
      if (Buffer.isBuffer(value)) {
        bytes = value.length >= 1 && value.length <= cfg.outputCacheMaxBytes ? value : null;
      } else if (value instanceof Uint8Array) {
        bytes = value.byteLength >= 1 && value.byteLength <= cfg.outputCacheMaxBytes
          ? Buffer.from(value.buffer, value.byteOffset, value.byteLength)
          : null;
      } else if (value instanceof ArrayBuffer) {
        bytes = value.byteLength >= 1 && value.byteLength <= cfg.outputCacheMaxBytes ? Buffer.from(value) : null;
      }
      if (bytes) bytes = untagCacheBytes(key, bytes);
      if (bytes && !isPlausibleCachedDerivative(bytes, expected)) return null;
      return bytes;
    } catch {
      // The derivative cache is an optimization, unlike replay/quota state:
      // a cache-read failure safely falls back to authorized reprocessing.
      return null;
    }
  }
  async function setSharedOutputCache(key, bytes) {
    if (!sharedOutputCacheEnabled || !cfg.outputCacheMax || !cfg.outputCacheMaxBytes ||
        !bytes?.length || bytes.length + 34 > cfg.outputCacheMaxBytes) return;
    try {
      await callStateStore('setCache', key, tagCacheBytes(key, bytes), { ttlMs: cfg.sharedCacheTtlMs });
      derivativeCacheStats.sharedWrites++;
    } catch { /* cache write failures do not change authorization */ }
  }

  const derivativeCacheStats = {
    memoryHits: 0,
    diskHits: 0,
    sharedHits: 0,
    misses: 0,
    coalesced: 0,
    diskWrites: 0,
    sharedWrites: 0,
    diskEntries: 0,
    diskBytes: 0,
    diskPrunes: 0,
    diskErrors: 0,
  };
  let diskWritesSincePrune = 0;
  let diskPrunePromise = null;
  let sharpPerformanceConfigured = false;

  function diskOutputCachePath(sharedCacheKey) {
    const digest = crypto.createHash('sha256').update(sharedCacheKey, 'utf8').digest('hex');
    return {
      digest,
      dir: path.join(outputCacheDir, digest.slice(0, 2)),
      file: path.join(outputCacheDir, digest.slice(0, 2), `${digest}.archx-cache`),
    };
  }

  async function pruneDiskOutputCache() {
    if (!outputCacheDir || diskPrunePromise) return diskPrunePromise;
    diskPrunePromise = (async () => {
      const entries = [];
      let totalBytes = 0;
      let subdirs = [];
      try { subdirs = await fs.promises.readdir(outputCacheDir, { withFileTypes: true }); }
      catch { derivativeCacheStats.diskErrors++; return; }
      for (const subdir of subdirs) {
        if (!subdir.isDirectory() || !/^[0-9a-f]{2}$/.test(subdir.name)) continue;
        const dirPath = path.join(outputCacheDir, subdir.name);
        let files = [];
        try { files = await fs.promises.readdir(dirPath, { withFileTypes: true }); }
        catch { derivativeCacheStats.diskErrors++; continue; }
        for (const file of files) {
          if (!file.isFile() || !/^[0-9a-f]{64}\.archx-cache$/.test(file.name)) continue;
          const filePath = path.join(dirPath, file.name);
          try {
            const stat = await fs.promises.stat(filePath);
            if (!stat.isFile()) continue;
            entries.push({ filePath, size: stat.size, mtimeMs: stat.mtimeMs });
            totalBytes += stat.size;
          } catch { /* a concurrent prune/rename may have removed it */ }
        }
      }
      const staleBefore = cfg.outputCacheDiskTtlMs > 0 ? Date.now() - cfg.outputCacheDiskTtlMs : 0;
      const live = [];
      for (const entry of entries) {
        if (staleBefore && entry.mtimeMs < staleBefore) {
          try { await fs.promises.unlink(entry.filePath); totalBytes -= entry.size; }
          catch { live.push(entry); }
        } else live.push(entry);
      }
      const byteTarget = cfg.outputCacheDiskMaxBytes > 0
        ? Math.floor(cfg.outputCacheDiskMaxBytes * 0.9)
        : 0;
      const entryTarget = cfg.outputCacheDiskMaxEntries > 0
        ? Math.max(0, Math.floor(cfg.outputCacheDiskMaxEntries * 0.9))
        : 0;
      live.sort((a, b) => a.mtimeMs - b.mtimeMs);
      let liveCount = live.length;
      for (const entry of live) {
        const overBytes = cfg.outputCacheDiskMaxBytes > 0 && totalBytes > byteTarget;
        const overEntries = cfg.outputCacheDiskMaxEntries > 0 && liveCount > entryTarget;
        if (!overBytes && !overEntries) break;
        try {
          await fs.promises.unlink(entry.filePath);
          totalBytes -= entry.size;
          liveCount--;
        } catch { /* already removed */ }
      }
      derivativeCacheStats.diskEntries = Math.max(0, liveCount);
      derivativeCacheStats.diskBytes = Math.max(0, totalBytes);
      derivativeCacheStats.diskPrunes++;
      diskWritesSincePrune = 0;
    })().finally(() => { diskPrunePromise = null; });
    return diskPrunePromise;
  }

  async function getDiskOutputCache(sharedCacheKey, expected = null) {
    if (!outputCacheDir || !cfg.outputCacheDiskMaxBytes || !cfg.outputCacheDiskMaxEntries) return null;
    const { file } = diskOutputCachePath(sharedCacheKey);
    let cacheFileHandle = null;
    try {
      // Stat the OPEN handle (fstat) and read from it: the size/TTL facts
      // and the bytes then describe the same file, so no check-then-use
      // race exists even if another writer replaces the path. (The HMAC
      // tag check below remains the content-integrity boundary.)
      cacheFileHandle = await fs.promises.open(file, 'r');
      const stat = await cacheFileHandle.stat();
      if (!stat.isFile() || stat.size < 1 || stat.size > cfg.outputCacheDiskMaxBytes ||
          stat.size > 256 * 1024 * 1024) return null;
      const ageMs = Date.now() - stat.mtimeMs;
      if (cfg.outputCacheDiskTtlMs > 0 && ageMs > cfg.outputCacheDiskTtlMs) {
        await cacheFileHandle.close().catch(() => {}); cacheFileHandle = null;
        try { await fs.promises.unlink(file); } catch {}
        return null;
      }
      const stored = await cacheFileHandle.readFile();
      await cacheFileHandle.close().catch(() => {}); cacheFileHandle = null;
      if (stored.length !== stat.size) return null;
      const bytes = untagCacheBytes(sharedCacheKey, stored);
      if (!bytes || !isPlausibleCachedDerivative(bytes, expected)) {
        derivativeCacheStats.diskErrors++;
        try { await fs.promises.unlink(file); } catch {}
        return null;
      }
      derivativeCacheStats.diskHits++;
      if (ageMs > 3600000) {
        // Refresh at most hourly so mtime is a cheap approximate LRU clock
        // without turning every cache hit into a metadata write.
        const now = new Date();
        fs.promises.utimes(file, now, now).catch(() => {});
      }
      return bytes;
    } catch (err) {
      if (err?.code !== 'ENOENT') derivativeCacheStats.diskErrors++;
      return null;
    } finally {
      if (cacheFileHandle) await cacheFileHandle.close().catch(() => {});
    }
  }

  async function setDiskOutputCache(sharedCacheKey, bytes) {
    if (!outputCacheDir || !bytes?.length || !cfg.outputCacheDiskMaxBytes ||
        !cfg.outputCacheDiskMaxEntries || bytes.length > cfg.outputCacheDiskMaxBytes ||
        bytes.length > 256 * 1024 * 1024) return;
    const target = diskOutputCachePath(sharedCacheKey);
    const tmp = `${target.file}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
    try {
      await fs.promises.mkdir(target.dir, { recursive: true, mode: 0o700 });
      await fs.promises.writeFile(tmp, tagCacheBytes(sharedCacheKey, bytes), { mode: 0o600 });
      await fs.promises.rename(tmp, target.file);
      derivativeCacheStats.diskWrites++;
      diskWritesSincePrune++;
      if (diskWritesSincePrune >= 100) void pruneDiskOutputCache();
    } catch {
      derivativeCacheStats.diskErrors++;
      try { await fs.promises.unlink(tmp); } catch {}
    }
  }
  const processingSemaphore = new AsyncSemaphore({
    maxConcurrent: cfg.processingConcurrency,
    maxQueue: cfg.processingQueueMax,
    queueTimeoutMs: cfg.processingQueueTimeoutMs,
  });
  const outputInFlight = new Map(); // cacheKey -> Promise<Buffer> (singleflight derivatives)
  const dimensionInFlight = new Map(); // id+fileVersion -> Promise<dims|null>
  const masterInFlight = new Map(); // id+fileVersion -> Promise<{bytes,current}>

  async function withCallbackTimeout(fn, args, label) {
    let timer = null;
    try {
      return await Promise.race([
        Promise.resolve().then(() => fn(...args)),
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            const err = new Error(`${label} timed out`);
            err.code = 'ARCHX_CALLBACK_TIMEOUT';
            reject(err);
          }, cfg.callbackTimeoutMs);
          timer.unref?.();
        }),
      ]);
    } finally { if (timer) clearTimeout(timer); }
  }

  function normalizeWatermarkResult(value) {
    if (value == null || value === false) return null;
    if (!validateWatermarkValue(value)) {
      const err = new Error('invalid server watermark');
      err.code = 'ARCHX_INVALID_CALLBACK_RESULT';
      throw err;
    }
    return typeof value === 'object' ? Object.freeze({ ...value }) : value;
  }

  function fileVersion(stat) {
    return [stat.mtimeMs, stat.ctimeMs, stat.size, stat.ino ?? ''].join(':');
  }

  function cacheTouch(map, key) {
    const value = map.get(key);
    if (value === undefined) return undefined;
    map.delete(key); map.set(key, value);
    return value;
  }
  function setMasterCache(id, value) {
    if (!cfg.cacheMasters || value.bytes.length > cfg.masterCacheMaxBytes) return;
    const previous = masterCache.get(id);
    if (previous) { masterCacheBytes -= previous.bytes.length; masterCache.delete(id); }
    masterCache.set(id, value);
    masterCacheBytes += value.bytes.length;
    evictMasterSide('master', id);
  }
  function getOutputCache(key) { return cacheTouch(outputCache, key); }
  function setOutputCache(key, bytes) {
    if (!cfg.outputCacheMax || !cfg.outputCacheMaxBytes || bytes.length > cfg.outputCacheMaxBytes) return;
    const previous = outputCache.get(key);
    if (previous) { outputCacheBytes -= previous.length; outputCache.delete(key); }
    outputCache.set(key, bytes);
    outputCacheBytes += bytes.length;
    while (outputCache.size > cfg.outputCacheMax || outputCacheBytes > cfg.outputCacheMaxBytes) {
      const oldestKey = outputCache.keys().next().value;
      if (oldestKey === undefined) break;
      outputCacheBytes -= outputCache.get(oldestKey).length;
      outputCache.delete(oldestKey);
      if (oldestKey === key) break;
    }
  }

  // Canonical form for IP accounting AND token binding: an IPv4-mapped
  // IPv6 address (::ffff:192.0.2.1, ::ffff:c000:0201, the expanded
  // 0:0:0:0:0:ffff:192.0.2.1, and the ::ffff:0: translated form) IS the
  // IPv4 address. Stripping only the dotted "::ffff:" prefix leaves the
  // hex form as a "valid" IPv6 whose /64 and /48 prefixes are 0:0:0:0 and
  // 0:0:0 — collapsing every IPv4 client on earth into ONE limiter
  // bucket (the CVE-2026-30827 class). Defined before requestIp, which
  // uses it for every candidate it returns.
  const ipv6Groups = (ip) => {
    try {
      let addr = ip.toLowerCase();
      const v4Tail = addr.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
      if (v4Tail) {
        const hi = ((Number(v4Tail[1]) << 8) | Number(v4Tail[2])).toString(16);
        const lo = ((Number(v4Tail[3]) << 8) | Number(v4Tail[4])).toString(16);
        addr = addr.slice(0, addr.length - v4Tail[0].length) + hi + ':' + lo;
      }
      const halves = addr.split('::');
      if (halves.length > 2) return null;
      const head = halves[0] ? halves[0].split(':').filter(Boolean) : [];
      const tail = halves.length === 2 && halves[1] ? halves[1].split(':').filter(Boolean) : [];
      const missing = 8 - head.length - tail.length;
      if (missing < 0) return null;
      const groups = [...head, ...Array(missing).fill('0'), ...tail]
        .map((g) => (parseInt(g, 16) || 0).toString(16));
      return groups.length === 8 ? groups : null;
    } catch { return null; }
  };
  const canonicalIp = (ip) => {
    const kind = isIP(ip);
    if (kind === 4) return ip;
    if (kind !== 6) return null;
    const g = ipv6Groups(ip);
    if (!g) return ip;
    const mapped = g[0] === '0' && g[1] === '0' && g[2] === '0' && g[3] === '0' && g[4] === '0' && g[5] === 'ffff';
    const translated = g[0] === '0' && g[1] === '0' && g[2] === '0' && g[3] === '0' && g[4] === 'ffff' && g[5] === '0';
    if (mapped || translated) {
      const hi = parseInt(g[6], 16) || 0;
      const lo = parseInt(g[7], 16) || 0;
      return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
    }
    // Canonical expanded form: textual variants of one address
    // (2001:db8::1 vs 2001:0db8:0:0:0:0:0:1) are one identity for
    // token binding, quotas, and abuse accounting alike.
    return g.join(':');
  };
  const requestIp = (req) => {
    const socketIp = String(req.socket?.remoteAddress || '');
    if (cfg.trustProxy && cfg.trustedProxyHops > 0) {
      const forwarded = req.headers?.['x-forwarded-for'];
      const raw = Array.isArray(forwarded) ? forwarded.join(',') : String(forwarded || '');
      if (raw.length <= 4096) {
        const chain = raw.split(',').map((part) => part.trim()).filter(Boolean);
        // MDN/OWASP rule: select from the right by the number of proxies you
        // actually control. The leftmost value is attacker-controlled unless
        // every hop in front of this process overwrites/appends correctly.
        const candidate = chain[chain.length - cfg.trustedProxyHops] || (chain.length ? chain[0] : '');
        const canon = canonicalIp(candidate);
        if (canon) return canon;
      }
    }
    const socketCanon = canonicalIp(socketIp);
    if (socketCanon) return socketCanon;
    return 'unknown';
  };
  // Rate/quota/abuse keys group IPv6 clients by /64 prefix: a single host
  // typically controls a whole /64 (privacy extensions rotate interface
  // IDs freely), so per-address limits are trivially evaded by rotation
  // and the rotation also floods bounded limiter maps until blocked
  // clients are evicted. Token IP BINDING deliberately keeps the exact
  // address (requestIp) — only volumetric accounting groups.
  const limiterIp = (req) => {
    const ip = requestIp(req);
    if (isIP(ip) !== 6) return ip;
    const groups = ipv6Groups(ip);
    return groups ? groups.slice(0, 4).join(':') + '::/64' : ip;
  };
  // Volumetric tiers for one request: IPv6 clients get their strict /64
  // bucket AND an aggregate /48 ceiling at 4x, so a holder of a whole /48
  // (65,536 /64s to rotate through) cannot mint unbounded fresh buckets.
  const IPV6_AGGREGATE_MULTIPLIER = 4;
  const limiterIpTiers = (req) => {
    const ip = requestIp(req);
    if (isIP(ip) !== 6) return [{ key: ip, mult: 1 }];
    const groups = ipv6Groups(ip);
    if (!groups) return [{ key: ip, mult: 1 }];
    return [
      { key: groups.slice(0, 4).join(':') + '::/64', mult: 1 },
      { key: groups.slice(0, 3).join(':') + '::/48', mult: IPV6_AGGREGATE_MULTIPLIER },
    ];
  };
  const hmacShort = (label, value, len = 24, keySecret = secret) =>
    crypto.createHmac('sha256', keySecret).update(label + ':' + String(value)).digest('base64url').slice(0, len);
  const safeEqual = (a, b) => {
    const ba = Buffer.from(String(a)); const bb = Buffer.from(String(b));
    return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
  };

  function emitSecurityEvent(type, req, details = {}) {
    if (!onSecurityEvent) return;
    const status = Number.isInteger(details.status) ? details.status : null;
    const phase = details.phase || null;
    const viewerId = details.viewerId || null;
    const severity = type === 'archx.suspicious_scraping'
      ? 'warning'
      : (status != null && status >= 500) || type.includes('error') || type.includes('failed')
        ? 'error'
        : 'notice';
    const outcome = type === 'archx.suspicious_scraping'
      ? 'detected'
      : severity === 'error'
        ? 'error'
        : 'denied';
    const event = Object.freeze({
      // Versioned, SIEM-friendly fields. The original top-level fields remain
      // for backwards compatibility; `actor`/`request` are the structured
      // form documented in docs/OPERATIONS.md.
      schemaVersion: 1,
      eventId: crypto.randomUUID(),
      service: 'archx',
      severity,
      outcome,
      type,
      at: new Date().toISOString(),
      id: details.id || null,
      imageId: details.id || null,
      phase,
      status,
      ip: req ? requestIp(req) : null,
      viewerId,
      actor: Object.freeze({
        ip: req ? requestIp(req) : null,
        viewerHash: viewerId ? hmacShort('event-viewer', viewerId, 24) : null,
      }),
      request: Object.freeze({
        method: req?.method ? String(req.method).toUpperCase() : null,
        route: phase ? `${basePath}/${phase === 'token' ? 'token' : 'i'}/:id` : null,
      }),
      reason: details.reason || null,
    });
    try {
      const result = onSecurityEvent(event);
      if (result && typeof result.catch === 'function') result.catch(() => {});
    } catch { /* monitoring must never alter authorization */ }
  }

  function emitDeliveryEvent(type, details = {}) {
    if (!onDelivery) return;
    // Deliberately metadata-only: never pass the bearer token, scramble key,
    // AES key, proof, request headers, or master path to a monitoring hook.
    const event = Object.freeze({
      schemaVersion: 1,
      eventId: crypto.randomUUID(),
      service: 'archx',
      type,
      at: new Date().toISOString(),
      imageId: details.id || null,
      phase: details.phase || null,
      viewerHash: details.viewerHash || null,
      traceHash: details.traceHash || null,
      keyId: details.keyId || null,
      width: Number.isInteger(details.width) ? details.width : null,
      quality: details.quality ?? null,
      format: details.format || null,
      stegoFingerprint: details.stegoFingerprint || null,
      stegoProfile: details.stegoProfile || null,
      bytes: Number.isInteger(details.bytes) ? details.bytes : null,
    });
    try {
      const result = onDelivery(event);
      if (result && typeof result.catch === 'function') result.catch(() => {});
    } catch { /* monitoring must never alter delivery authorization */ }
  }

  function authorizationViewerId(auth) {
    if (!auth || typeof auth !== 'object') return '';
    try { return String(auth.viewerId || '').slice(0, 256); } catch { return ''; }
  }

  function authorizationTrace(auth, viewerId = '', keySecret = secret) {
    const trace = {
      buyerId: auth?.buyerId ? String(auth.buyerId).slice(0, 256) : null,
      orderId: auth?.orderId ? String(auth.orderId).slice(0, 256) : null,
      deliveryId: auth?.deliveryId ? String(auth.deliveryId).slice(0, 256) : null,
      traceId: auth?.traceId ? String(auth.traceId).slice(0, 256) : null,
    };
    const subject = trace.traceId || [trace.buyerId, trace.orderId, trace.deliveryId, viewerId]
      .filter(Boolean).join(':');
    return Object.freeze({
      ...trace,
      subject,
      hash: subject ? hmacShort('trace', subject, 20, keySecret) : '',
    });
  }

  async function authorizeRequest(req, id, phase, token = null) {
    if (!authorize) return cfg.allowAnonymous ? Object.freeze({}) : null;
    let auth;
    try { auth = await withCallbackTimeout(authorize, [req, id, { phase, token }], 'authorize callback'); }
    catch { return null; }
    return normalizeAuthorizationResult(auth);
  }

  async function imageDimensions(id) {
    const resolved = resolveIndexedFile(id);
    if (!resolved) return null;
    const { filePath, stat } = resolved;
    if (stat.size > cfg.processing.maxInputBytes) return null;
    const version = fileVersion(stat);
    const cached = dimensionCache.get(id);
    if (cached && cached.version === version) return cached;
    const flightKey = `${id}|${version}`;
    if (dimensionInFlight.has(flightKey)) return dimensionInFlight.get(flightKey);
    const pending = (async () => {
      try {
        return await processingSemaphore.run(async () => {
          const liveCached = dimensionCache.get(id);
          if (liveCached && liveCached.version === version) return liveCached;
          // Read only a small header window first. This rejects extension
          // spoofs and many decompression bombs before Sharp sees the file,
          // and Sharp itself receives bytes rather than a filesystem path.
          let headerBytes;
          let handle;
          try {
            handle = await fs.promises.open(filePath, 'r');
            const wanted = Math.min(stat.size, 64 * 1024);
            const buffer = Buffer.alloc(wanted);
            const { bytesRead } = await handle.read(buffer, 0, wanted, 0);
            headerBytes = buffer.subarray(0, bytesRead);
          } finally { await handle?.close().catch(() => {}); }
          const sniffed = sniffImageInfo(headerBytes);
          if (!sniffed || !cfg.processing.allowedInputFormats.includes(sniffed.format)) return null;
          if (sniffed.width && sniffed.height &&
              (sniffed.width > cfg.processing.maxInputWidth ||
               sniffed.height > cfg.processing.maxInputHeight ||
               sniffed.width * sniffed.height > cfg.processing.maxInputPixels)) return null;

          const sourceBytes = stat.size <= 64 * 1024 ? headerBytes : await fs.promises.readFile(filePath);
          const sharpModule = await import('sharp');
          const sharp = sharpModule.default;
          if (cfg.processing.blockUntrustedSharpLoaders) {
            const { configureSharpSecurity } = await import('./scramble-image.js');
            configureSharpSecurity(cfg.processing.allowedInputFormats);
          }
          const meta = await sharp(sourceBytes, {
            failOn: 'warning',
            limitInputPixels: cfg.processing.maxInputPixels,
            limitInputChannels: 4,
            sequentialRead: true,
            animated: false,
          }).timeout({ seconds: cfg.processing.timeoutSec }).metadata();
          const format = meta.format === 'heif' ? 'avif' : meta.format;
          if (!meta.width || !meta.height || format !== sniffed.format ||
              !cfg.processing.allowedInputFormats.includes(format)) return null;
          if (!Number.isSafeInteger(meta.width) || !Number.isSafeInteger(meta.height) ||
              meta.width > cfg.processing.maxInputWidth || meta.height > cfg.processing.maxInputHeight ||
              meta.width * meta.height > cfg.processing.maxInputPixels) return null;
          if ((meta.pages || 1) > 1 || (meta.channels || 3) > 4) return null;
          const current = resolveIndexedFile(id);
          if (!current || fileVersion(current.stat) !== version || current.filePath !== filePath) return null;
          const rotated = meta.orientation >= 5 && meta.orientation <= 8;
          const dims = Object.freeze({
            version,
            mtimeMs: stat.mtimeMs,
            ctimeMs: stat.ctimeMs,
            size: stat.size,
            ino: stat.ino ?? null,
            width: rotated ? meta.height : meta.width,
            height: rotated ? meta.width : meta.height,
          });
          dimensionCache.set(id, dims);
          return dims;
        });
      } catch { return null; }
      finally { if (dimensionInFlight.get(flightKey) === pending) dimensionInFlight.delete(flightKey); }
    })();
    dimensionInFlight.set(flightKey, pending);
    return pending;
  }

  function requestOrigin(req) {
    const origin = req.headers?.origin;
    if (typeof origin === 'string' && origin) return origin;
    const referer = req.headers?.referer || req.headers?.referrer;
    if (typeof referer === 'string' && referer) {
      try { return new URL(referer).origin; } catch { return null; }
    }
    return null;
  }

  function originAllowed(req) {
    // Origin/Referer are useful CSRF/CORS signals, never credentials. The
    // authorize() callback above remains the actual access-control boundary.
    if (!allowedOrigins || !allowedOrigins.length) return true;
    const origin = requestOrigin(req);
    return !!origin && allowedOrigins.includes(origin);
  }

  function fetchSiteAllowed(req) {
    if (!cfg.requireSameSiteTokenRequests) return true;
    const site = String(req.headers?.['sec-fetch-site'] || '').toLowerCase();
    if (site === 'same-origin') return true;
    // Same-site is not same-origin (a sibling subdomain can still ride some
    // cookies). When the browser supplies Fetch Metadata, only an exact
    // configured origin gets a cross-origin/same-site exception.
    if (site) return !!(allowedOrigins?.length && originAllowed(req));
    // Older/non-browser clients may omit Fetch Metadata. The required custom
    // X-Archx-Request header and authorize() remain the hard boundaries, so
    // absence alone is not treated as proof of a cross-site browser request.
    return true;
  }

  function tokenRequestHeaderAllowed(req) {
    if (!cfg.requireTokenRequestHeader) return true;
    const value = req.headers?.['x-archx-request'];
    return typeof value === 'string' && value.toLowerCase() === 'token';
  }

  function corsHeaders(req) {
    if (!allowedOrigins?.length) return {};
    const origin = requestOrigin(req);
    if (!origin || !allowedOrigins.includes(origin)) return {};
    return {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Credentials': 'true',
      'Vary': 'Origin, Cookie, Authorization, X-Archx-Token, X-Archx-Proof, X-Archx-Proof-Key, User-Agent',
    };
  }

  async function quotaExceeded(req, id, viewerId, phase, keySecret = secret) {
    const tiers = limiterIpTiers(req);
    const checks = [];
    // NARROWEST scope first, and stop at the first limiting check:
    // hitWindow both tests and increments, so evaluating wide global
    // counters before a per-image rejection would burn global quota on
    // requests that were never going to be served. IP dimensions expand
    // across tiers (/64 strict, /48 aggregate at 4x for IPv6).
    const ipChecks = (template, max, name) => {
      for (const tier of tiers) checks.push([template(tier.key), max ? max * tier.mult : max, name]);
    };
    if (phase === 'token') {
      if (viewerId) {
        const viewerHash = hmacShort('quota-viewer', viewerId, 24, keySecret);
        checks.push([`quota:viewer-image:${viewerHash}:${id}`, cfg.quotas.perViewerImage, 'perViewerImage']);
        ipChecks((ip) => `quota:ip-image:${ip}:${id}`, cfg.quotas.perIpImage, 'perIpImage');
        checks.push([`quota:viewer:${viewerHash}`, cfg.quotas.perViewer, 'perViewer']);
      } else {
        ipChecks((ip) => `quota:ip-image:${ip}:${id}`, cfg.quotas.perIpImage, 'perIpImage');
      }
      ipChecks((ip) => `quota:ip:${ip}`, cfg.quotas.perIp, 'perIp');
    } else if (!oneTimeTokens) {
      // With replayable tokens, count redemptions too. With one-time tokens
      // the token-phase quota already corresponds to at most one download.
      if (viewerId) {
        checks.push([`quota:redeem-viewer-image:${hmacShort('quota-viewer', viewerId, 24, keySecret)}:${id}`, cfg.quotas.perViewerImage, 'perViewerImage']);
      }
      ipChecks((ip) => `quota:redeem-ip-image:${ip}:${id}`, cfg.quotas.perIpImage, 'perIpImage');
    }
    for (const [key, max, name] of checks) {
      if (!max) continue;
      const result = await stateHitWindow(key, max, cfg.quotas.windowMs);
      if (result.limited) return { name, retryAfterSec: result.retryAfterSec };
    }
    return null;
  }

  const abuseAlertLatch = new BoundedTtlSet({ maxEntries: 100000 });
  async function abusePattern(req, id, viewerId) {
    const threshold = cfg.abuseDetection.distinctImages;
    if (!threshold) return { suspicious: false, distinct: 0 };
    // Distinct-image tracking follows the same IP tiers as rate/quota:
    // the /64 at the configured threshold and its /48 aggregate at 4x.
    // /64-only tracking (the pre-1.13 behavior) let a scraper rotate
    // through the 65,536 /64s of one /48 and never accumulate; the 4x
    // aggregate keeps a legitimately busy shared /48 (NAT, university)
    // from tripping on breadth alone.
    const checks = limiterIpTiers(req).map(({ key, mult }) => ({
      key: `distinct:ip:${key}`,
      limit: Math.max(1, Math.round(threshold * mult)),
    }));
    if (viewerId) checks.push({ key: `distinct:viewer:${hmacShort('quota-viewer', viewerId, 24)}`, limit: threshold });
    let distinct = 0;
    let crossed = false;
    let suspicious = false;
    for (const { key, limit } of checks) {
      const result = await stateTrackDistinct(key, id, limit);
      distinct = Math.max(distinct, result.distinct);
      // Fire the alert at most ONCE per client per window. The tracker's
      // bounded member set caps `distinct` at limit+1, so the naive
      // "distinct === limit+1" edge re-triggers on every subsequent
      // new image (an unbounded SIEM alert storm). The latch remembers
      // the crossing until the window passes; a deny policy still denies
      // on `suspicious` regardless of the latch.
      if (result.distinct > limit) {
        suspicious = true;
        if (abuseAlertLatch.claim(key, Date.now() + cfg.abuseDetection.windowMs)) {
          crossed = true;
        }
      }
    }
    return { suspicious, crossed, distinct };
  }

  function fillPlaceholders(text, ctx) {
    const trace = ctx.trace || {};
    const fallback = String(ctx.nonce).slice(0, 6);
    return String(text)
      .replaceAll('{id}', ctx.id)
      .replaceAll('{nonce}', fallback)
      .replaceAll('{viewer}', ctx.viewerId ? String(ctx.viewerId) : fallback)
      .replaceAll('{buyer}', trace.buyerId ? String(trace.buyerId) : fallback)
      .replaceAll('{order}', trace.orderId ? String(trace.orderId) : fallback)
      .replaceAll('{delivery}', trace.deliveryId ? String(trace.deliveryId) : fallback)
      .replaceAll('{trace}', trace.traceId ? String(trace.traceId) : (trace.hash || fallback));
  }

  async function resolveBindingValue(setting, req, fallback) {
    if (!setting) return null;
    if (setting === true) return fallback;
    if (typeof setting === 'function') {
      const value = await withCallbackTimeout(setting, [req], 'bindTokenTo callback');
      if (!['string', 'number', 'bigint'].includes(typeof value) || String(value).length > 4096) {
        throw new Error('invalid token binding value');
      }
      return String(value);
    }
    if (typeof setting === 'string') {
      const value = req.headers?.[setting.toLowerCase()];
      if (typeof value !== 'string' || value.length > 4096) throw new Error('missing token binding header');
      return value;
    }
    throw new Error('invalid token binding setting');
  }

  async function resolveWatermark(source, ctx) {
    if (source == null) return null;
    const wm = typeof source === 'function'
      ? await withCallbackTimeout(source, [ctx], 'serverWatermark callback')
      : source;
    if (wm == null || wm === false) return null;
    if (typeof wm === 'string') return normalizeWatermarkResult(fillPlaceholders(wm, ctx));
    if (wm && typeof wm === 'object' && !Array.isArray(wm)) {
      let expanded;
      try {
        expanded = normalizeWatermarkResult(wm);
        if (typeof expanded.text === 'string') {
          expanded = normalizeWatermarkResult({ ...expanded, text: fillPlaceholders(expanded.text, ctx) });
        }
      } catch (err) { throw err; }
      return expanded;
    }
    return normalizeWatermarkResult(wm);
  }

  async function rateLimited(req, kind = 'i') {
    const max = kind === 'token' ? tokenRateMax : rateMax;
    // Strict /64 bucket first, then the /48 aggregate ceiling (IPv6).
    let last = { limited: false, retryAfterSec: 0, count: 0 };
    for (const tier of limiterIpTiers(req)) {
      last = await stateHitWindow(`rate:${kind}:${tier.key}`, max * tier.mult, 60000);
      if (last.limited) return last;
    }
    return last;
  }

  function protectedHeaders(req, extra = {}) {
    return {
      'Cache-Control': 'private, no-store, no-cache, must-revalidate, max-age=0',
      'CDN-Cache-Control': 'private, no-store',
      'Surrogate-Control': 'no-store',
      'Vary': 'Cookie, Authorization, X-Archx-Token, X-Archx-Proof, X-Archx-Proof-Key, User-Agent',
      'Pragma': 'no-cache',
      'Expires': '0',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cross-Origin-Resource-Policy': allowedOrigins?.length ? 'cross-origin' : 'same-origin',
      ...corsHeaders(req),
      ...extra,
    };
  }

  function sendJson(req, res, status, obj, extraHeaders = {}) {
    const body = JSON.stringify(obj);
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': Buffer.byteLength(body),
      ...protectedHeaders(req, extraHeaders),
    });
    res.end(body);
  }

  function deny(req, res, status, error, { id = null, phase = null, viewerId = null, reason = null, headers = {} } = {}) {
    emitSecurityEvent('archx.denied', req, { id, phase, viewerId, status, reason: reason || error });
    return sendJson(req, res, status, { error }, headers);
  }

  class MintDenied extends Error {
    constructor(status, error, details = {}) {
      super(error);
      this.name = 'MintDenied';
      this.status = status;
      this.error = error;
      this.details = details;
    }
  }

  async function mintTokenResponse(req, id, params = {}, proofThumbprint = null) {
    const hasParam = (name) => params?.[name] !== undefined && params?.[name] !== null && params?.[name] !== '';
    const paramValue = (name) => (hasParam(name) ? String(params[name]) : null);
    const entitlement = await authorizeRequest(req, id, 'token');
    if (!entitlement) throw new MintDenied(403, 'forbidden', { id, phase: 'token', reason: 'authorization' });
    const viewerId = authorizationViewerId(entitlement);
    const trace = authorizationTrace(entitlement, viewerId);
    // Request-SHAPE validation runs BEFORE any quota counter moves: a
    // malformed request (bad ?w=, bad fit) or a broken entitlement must
    // not burn the viewer's/IP's quota, or garbage requests could lock
    // out legitimate users (worst case: a whole shared-NAT office).
    const entitlementWidth = entitlement.maxWidth == null ? maxWidthCap : Number(entitlement.maxWidth);
    if (!Number.isFinite(entitlementWidth) || entitlementWidth < 64) {
      throw new MintDenied(403, 'forbidden', { id, phase: 'token', viewerId, reason: 'invalid-entitlement-width' });
    }
    // The BROWSER asks for a width; the SERVER's entitlement caps it.
    // A tampered client can no longer "just ask for 1920px" beyond policy.
    const widthCap = Math.min(maxWidthCap, Math.floor(entitlementWidth));
    const rawRequested = paramValue('w') || paramValue('bw') || '1200';
    let requestedW = parseStrictInt(rawRequested);
    const boxW = hasParam('bw') ? parseStrictInt(paramValue('bw')) : null;
    const boxH = hasParam('bh') ? parseStrictInt(paramValue('bh')) : null;
    const rawFit = String(paramValue('fit') || 'cover').toLowerCase();
    if (requestedW == null || requestedW < 1 || requestedW > 100000 ||
        (hasParam('bw') && (boxW == null || boxW < 1 || boxW > 100000)) ||
        (hasParam('bh') && (boxH == null || boxH < 1 || boxH > 100000)) ||
        !['cover', 'contain', 'fill'].includes(rawFit)) {
      throw new MintDenied(400, 'bad request', { id, phase: 'token', viewerId, reason: 'bad-sizing' });
    }
    if (boxW > 0 && boxH > 0) {
      try {
        const dims = await imageDimensions(id);
        if (dims) {
          const aspect = dims.width / dims.height;
          const fit = rawFit;
          // For cover, derivative width must satisfy BOTH box dimensions.
          // Width-only sizing crops a landscape source and then upscales
          // it in a squarer/taller host, visibly softening detail.
          requestedW = fit === 'contain'
            ? Math.min(boxW, boxH * aspect)
            : fit === 'fill'
              ? boxW
              : Math.max(boxW, boxH * aspect);
        }
      } catch { /* fall back to width-only sizing */ }
    }
    const exactW = Math.max(64, Math.min(widthCap, Math.ceil(requestedW)));
    const w = cfg.widthBuckets?.length
      ? canonicalDerivativeWidth(exactW, widthCap, cfg.widthBuckets)
      : exactW;
    const nonce = crypto.randomBytes(18).toString('base64url');
    const iat = Date.now();
    const exp = iat + ttlMs;
    const watermark = await resolveWatermark(
      entitlement.watermark ?? serverWatermark,
      { req, id, nonce, viewerId, trace, exp },
    );
    const tokenPayload = {
      v: 2,
      kid: activeSecretId,
      aud: TOKEN_AUDIENCE,
      scope: TOKEN_SCOPE,
      id, w, iat, exp, n: nonce,
    };
    const viewerHash = viewerId ? hmacShort('viewer', viewerId, 20) : '';
    if (viewerId) tokenPayload.vh = viewerHash;
    if (trace.hash) tokenPayload.th = trace.hash;
    if (proofThumbprint) tokenPayload.jkt = proofThumbprint;
    if (watermark) tokenPayload.wm = watermark;

    // Direct delivery-quality control. Your authorize() entitlement wins;
    // the browser's q=… request is honoured only when you opt in.
    const clientQuality = allowClientQuality ? paramValue('q') : null;
    const rawQuality = entitlement.quality ?? clientQuality ?? quality;
    let deliveryLossless = entitlement.lossless ?? (lossless || rawQuality === 'lossless');
    let deliveryQuality = deliveryLossless
      ? 'lossless'
      : Math.max(1, Math.min(100, Math.round(Number(rawQuality) || 95)));
    const rawFormat = entitlement.format || format;
    const deliveryFormat = ['webp', 'png', 'jpeg', 'avif'].includes(rawFormat) ? rawFormat : 'webp';
    tokenPayload.q = deliveryQuality;
    if (deliveryLossless) tokenPayload.ls = 1;
    if (deliveryFormat !== format) tokenPayload.fmt = deliveryFormat;

    // StegoMark issuance: derive (but do not expose) the fingerprint that
    // will be baked into this view's pixels, and let the host persist the
    // fingerprint -> image/viewer/order mapping via onStegoIssue.
    const effectiveStego = entitlement.steganography ?? steganography;
    let issuedFingerprint = null;
    let issuedStegoProfile = null;
    if (effectiveStego) {
      tokenPayload.sge = 1;
      const entStegoCfg = typeof effectiveStego === 'object' ? effectiveStego : {};
      const stegoScope = entStegoCfg.scope ?? stegoGlobalCfg.scope ?? 'viewer';
      const stegoPerToken = stegoScope === 'image'
        ? false
        : (entStegoCfg.perToken ?? stegoGlobalCfg.perToken ?? true);
      issuedStegoProfile = entStegoCfg.profile ?? stegoGlobalCfg.profile ?? 'standard';
      if (issuedStegoProfile === 'robust') tokenPayload.sgv = 2;
      if (stegoScope === 'image') tokenPayload.sgi = 1;
      // Viewer-scoped layout keys: colluding buyers then hold marks laid
      // out under DIFFERENT spatial keys, so averaging/interleaving their
      // copies no longer aligns cell-by-cell into a majority-vote phantom
      // fingerprint (it can still erase — no pixel mark survives that —
      // but it cannot frame a third party). Costs per-viewer derivatives.
      const stegoKeyScope = entStegoCfg.keyScope ?? stegoGlobalCfg.keyScope ?? 'image';
      if (stegoKeyScope === 'viewer' && stegoScope !== 'image') tokenPayload.sgk = 1;
      const fingerprintSubjectHash = stegoScope === 'image' ? '' : (trace.hash || viewerHash);
      if (entitlement.stegoFingerprint) {
        tokenPayload.sg = String(entitlement.stegoFingerprint);
        issuedFingerprint = resolveStegoFingerprint(entitlement.stegoFingerprint);
      } else {
        if (!stegoPerToken) tokenPayload.sgp = 0;
        issuedFingerprint = deriveStegoFingerprint({
          id, nonce, viewerHash: fingerprintSubjectHash, secret, perToken: stegoPerToken,
        });
      }
      const strength = entStegoCfg.strength ?? stegoGlobalCfg.strength;
      if (strength != null) tokenPayload.sgs = strength;
      const stegoGridX = entStegoCfg.gridX ?? stegoGlobalCfg.gridX;
      const stegoGridY = entStegoCfg.gridY ?? stegoGlobalCfg.gridY;
      if (stegoGridX != null) tokenPayload.sgx = stegoGridX;
      if (stegoGridY != null) tokenPayload.sgy = stegoGridY;
      if (onStegoIssue) {
        try {
          await withCallbackTimeout(onStegoIssue, [{
            req,
            id,
            viewerId,
            buyerId: trace.buyerId,
            orderId: trace.orderId,
            deliveryId: trace.deliveryId,
            traceId: trace.traceId,
            traceHash: trace.hash || null,
            nonce,
            exp,
            issuedAt: new Date(iat).toISOString(),
            fingerprint: issuedFingerprint,
            profile: issuedStegoProfile,
            keyScope: tokenPayload.sgk === 1 ? 'viewer' : 'image',
            keyId: activeSecretId,
          }], 'onStegoIssue callback');
        } catch {
          emitSecurityEvent('archx.stego_registry_failed', req, { id, phase: 'token', viewerId, status: 503 });
          if (cfg.stegoRegistryFailure !== 'allow') {
            throw new MintDenied(503, 'service unavailable', { id, viewerId, reason: 'callback-unavailable' });
          }
        }
      }
    } else if (steganography) {
      tokenPayload.nsg = 1; // entitlement explicitly opted this view out
    }
    if (onProvenanceIssue) {
      // C2PA-ready extension point: the host may create/sign/store a
      // Content Credentials manifest (or another provenance record) and
      // bind it to these soft-binding identifiers. Archx does not claim
      // to implement C2PA signing itself, and this record contains no
      // bearer token, scramble key, AES key, or proof material.
      try {
        await withCallbackTimeout(onProvenanceIssue, [Object.freeze({
          schemaVersion: 1,
          type: 'archx.provenance_issued',
          req,
          id,
          viewerId,
          viewerHash: viewerHash || null,
          buyerId: trace.buyerId,
          orderId: trace.orderId,
          deliveryId: trace.deliveryId,
          traceId: trace.traceId,
          traceHash: trace.hash || null,
          nonce,
          exp,
          issuedAt: new Date(iat).toISOString(),
          keyId: activeSecretId,
          width: w,
          quality: deliveryQuality,
          format: deliveryFormat,
          stegoFingerprint: issuedFingerprint,
          stegoProfile: issuedStegoProfile,
        })], 'onProvenanceIssue callback');
      } catch {
        emitSecurityEvent('archx.provenance_failed', req, { id, phase: 'token', viewerId, status: 503 });
        if (cfg.provenanceFailure !== 'allow') {
          throw new MintDenied(503, 'service unavailable', { id, viewerId, reason: 'callback-unavailable' });
        }
      }
    }
    if (bindTokenTo.session === true && !viewerId) {
      throw new MintDenied(403, 'forbidden', { id, phase: 'token', reason: 'session-binding-unavailable' });
    }
    const bindings = {};
    try {
      const bindingValue = (setting, fallback) => resolveBindingValue(setting, req, fallback);
      const ipBinding = await bindingValue(bindTokenTo.ip, requestIp(req));
      if (ipBinding != null) bindings.ip = hmacShort('bind-ip', ipBinding, 16);
      const uaBinding = await bindingValue(bindTokenTo.userAgent, req.headers?.['user-agent'] || '');
      if (uaBinding != null) bindings.ua = hmacShort('bind-ua', uaBinding, 16);
      const sessionBinding = await bindingValue(bindTokenTo.session, viewerId);
      if (sessionBinding != null) bindings.sess = hmacShort('bind-session', sessionBinding, 16);
    } catch {
      throw new MintDenied(403, 'forbidden', { id, phase: 'token', viewerId, reason: 'binding-unavailable' });
    }
    // Quota and abuse accounting run LAST, once every fallible host
    // callback (registry, provenance, token binding) has succeeded:
    // a transient host-side 503 must not permanently deduct a
    // viewer's quota for a token that was never issued.
    const quota = await quotaExceeded(req, id, viewerId, 'token');
    if (quota) {
      throw new MintDenied(429, 'quota exceeded', {
        id, phase: 'token', viewerId, reason: `quota:${quota.name}`,
        headers: { 'Retry-After': String(quota.retryAfterSec || 60) },
      });
    }
    const abuse = await abusePattern(req, id, viewerId);
    if (abuse.crossed) {
      emitSecurityEvent('archx.suspicious_scraping', req, {
        id, phase: 'token', viewerId, status: 200, reason: `distinct-images:${abuse.distinct}`,
      });
    }
    if (abuse.suspicious && cfg.abuseDetection.action === 'deny') {
      throw new MintDenied(429, 'too many requests', {
        id, phase: 'token', viewerId, reason: 'distinct-image-abuse', headers: { 'Retry-After': '600' },
      });
    }
    if (Object.keys(bindings).length) tokenPayload.b = bindings;
    const token = signToken(tokenPayload, secret);
    const imagePath = `${basePath}/i/${encodeURIComponent(id)}`;
    const out = {
      // `url` is the clean URL by default. Only an explicit
      // allowQueryTokens compatibility opt-in appends ?t=. New clients
      // use `token` in X-Archx-Token with cleanUrl, keeping bearer
      // material out of URLs, browser history, Referer headers, and
      // proxy logs. Header transport does NOT hide token/key/aesKey from
      // JavaScript or a viewer controlling the authorized browser: that
      // browser must receive them to redeem, unscramble, and decrypt.
      // Never log this response object.
      url: cfg.allowQueryTokens ? `${imagePath}?t=${token}` : imagePath,
      cleanUrl: imagePath,
      token,
      key: deriveScrambleKey(id, nonce),
      grid,
      exp,
    };
    if (encrypt) out.aesKey = deriveAesKey(id, nonce);
    emitDeliveryEvent('archx.token_issued', {
      id,
      phase: 'token',
      viewerHash: viewerHash || null,
      traceHash: trace.hash || null,
      keyId: activeSecretId,
      width: w,
      quality: deliveryQuality,
      format: deliveryFormat,
      stegoFingerprint: issuedFingerprint,
      stegoProfile: issuedStegoProfile,
    });
    return out;
  }

  async function readBatchTokenBody(req) {
    if (isPlainObject(req?.body)) {
      let serialized = '';
      try { serialized = JSON.stringify(req.body) || ''; }
      catch { throw new MintDenied(400, 'bad request', { reason: 'batch-json' }); }
      if (Buffer.byteLength(serialized, 'utf8') > cfg.batchTokenMaxBytes) {
        throw new MintDenied(413, 'request too large', { reason: 'batch-body' });
      }
      return req.body;
    }
    // Frameworks with text/raw body parsers deliver a string or Buffer and
    // consume the stream; accept those shapes explicitly (same byte cap and
    // strict JSON rules) instead of failing as "body unavailable".
    const rawParsedBody = typeof req?.body === 'string'
      ? Buffer.from(req.body, 'utf8')
      : Buffer.isBuffer(req?.body)
        ? req.body
        : req?.body instanceof Uint8Array
          ? Buffer.from(req.body.buffer, req.body.byteOffset, req.body.byteLength)
          : null;
    if (rawParsedBody) {
      if (rawParsedBody.length > cfg.batchTokenMaxBytes) {
        throw new MintDenied(413, 'request too large', { reason: 'batch-body' });
      }
      let parsed;
      try {
        parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(rawParsedBody));
      } catch { throw new MintDenied(400, 'bad request', { reason: 'batch-json' }); }
      if (!isPlainObject(parsed)) {
        throw new MintDenied(400, 'bad request', { reason: 'batch-json' });
      }
      return parsed;
    }
    if (!req || typeof req[Symbol.asyncIterator] !== 'function') {
      throw new MintDenied(400, 'bad request', { reason: 'batch-body-unavailable' });
    }
    const chunks = [];
    let total = 0;
    // Byte caps alone do not stop a slow-trickle body from holding the
    // handler open (the host server may have no request timeout): bound
    // the whole read by the same deadline family as hung callbacks.
    const deadline = Date.now() + cfg.callbackTimeoutMs;
    const iterator = req[Symbol.asyncIterator]();
    const BODY_TIMEOUT = Symbol('body-timeout');
    for (;;) {
      const remaining = deadline - Date.now();
      let step = BODY_TIMEOUT;
      if (remaining > 0) {
        let timer;
        try {
          step = await Promise.race([
            iterator.next(),
            new Promise((resolve) => { timer = setTimeout(() => resolve(BODY_TIMEOUT), remaining); timer.unref?.(); }),
          ]);
        } finally { clearTimeout(timer); }
      }
      if (step === BODY_TIMEOUT) {
        // Destroy first: awaiting iterator.return() on a suspended
        // generator would wait for its pending read — exactly what the
        // deadline exists to avoid. Real request streams settle on destroy.
        try { req.destroy?.(); } catch {}
        try { const closing = iterator.return?.(); if (closing?.catch) closing.catch(() => {}); } catch {}
        throw new MintDenied(408, 'request timeout', { reason: 'batch-body-timeout' });
      }
      if (step.done) break;
      const chunk = step.value;
      const bytes = Buffer.isBuffer(chunk)
        ? chunk
        : chunk instanceof Uint8Array
          ? Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength)
          : Buffer.from(String(chunk));
      total += bytes.length;
      if (total > cfg.batchTokenMaxBytes) {
        try { req.destroy?.(); } catch {}
        throw new MintDenied(413, 'request too large', { reason: 'batch-body' });
      }
      if (bytes.length) chunks.push(bytes);
    }
    let parsed;
    try {
      const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, total));
      parsed = JSON.parse(text);
    } catch {
      throw new MintDenied(400, 'bad request', { reason: 'batch-json' });
    }
    if (!isPlainObject(parsed)) {
      throw new MintDenied(400, 'bad request', { reason: 'batch-json' });
    }
    return parsed;
  }

  async function handler(req, res, next) {
    let routeId = null;
    let phase = null;
    try {
      const rawUrl = String(req.originalUrl || req.url || '');
      if (rawUrl.length > 16384) return deny(req, res, 414, 'request too large', { reason: 'url-too-long' });
      let url;
      // Express strips the mount path from req.url; originalUrl keeps it.
      try { url = new URL(rawUrl, 'http://archx.local'); }
      catch { return next ? next() : deny(req, res, 400, 'bad request', { reason: 'bad-url' }); }
      if (!url.pathname.startsWith(basePath + '/')) {
        return next ? next() : sendJson(req, res, 404, { error: 'not found' });
      }
      const parts = url.pathname.slice(basePath.length + 1).split('/');
      const isBatchTokens = parts.length === 1 && parts[0] === 'tokens';
      if (cfg.taintImage && parts.length === 1 && parts[0] === 'taint.png') {
        // Public by design and exempt from token rate budgets: the response
        // is 68 constant bytes with no input-dependent behavior, no secrets,
        // and deliberately no CORS headers, so a cross-origin no-CORS draw
        // marks the destination canvas origin-dirty (see TAINT_PNG).
        if (req.method !== 'GET' && req.method !== 'HEAD') {
          return deny(req, res, 405, 'method not allowed', {
            phase: 'taint', reason: 'taint-method', headers: { Allow: 'GET, HEAD' },
          });
        }
        const taintHeaders = {
          'Content-Type': 'image/png',
          'Cache-Control': 'public, max-age=31536000, immutable',
          ETag: '"archx-taint-1"',
          'X-Content-Type-Options': 'nosniff',
          'Referrer-Policy': 'no-referrer',
          'Cross-Origin-Resource-Policy': 'cross-origin',
        };
        // A 304 still taints when the browser revalidates against its HTTP
        // cache (the cached response is what gets drawn), and immutable
        // caching means revalidation itself is rare.
        if (String(req.headers?.['if-none-match'] || '').includes('"archx-taint-1"')) {
          res.writeHead(304, taintHeaders);
          return res.end();
        }
        res.writeHead(200, { ...taintHeaders, 'Content-Length': TAINT_PNG.length });
        return req.method === 'HEAD' ? res.end() : res.end(TAINT_PNG);
      }
      if (!isBatchTokens && parts.length !== 2) return sendJson(req, res, 404, { error: 'not found' });
      const kind = isBatchTokens ? 'tokens' : parts[0];
      const rawId = isBatchTokens ? null : parts[1];
      if (!['token', 'tokens', 'i'].includes(kind)) return sendJson(req, res, 404, { error: 'not found' });
      phase = kind === 'i' ? 'image' : 'token';
      // Count malformed/unknown-ID attempts too. Otherwise the cheapest
      // enumeration/flood path would bypass every request budget simply by
      // never naming a real image. CORS preflight is the one exemption: it
      // carries no entitlement and is followed by the rate-limited token call.
      if (req.method !== 'OPTIONS') {
        const rate = await rateLimited(req, kind === 'i' ? 'i' : 'token');
        if (rate.limited) {
          return deny(req, res, 429, 'too many requests', {
            phase, reason: 'rate-limit', headers: { 'Retry-After': String(rate.retryAfterSec || 60) },
          });
        }
      }

      if (isBatchTokens) {
        if (req.method === 'OPTIONS') {
          if (!allowedOrigins?.length || !originAllowed(req)) {
            return deny(req, res, 403, 'forbidden', { phase, reason: 'cors-origin' });
          }
          res.writeHead(204, {
            ...protectedHeaders(req),
            'Access-Control-Allow-Methods': 'POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, X-Archx-Request, X-Archx-Proof-Key',
            'Access-Control-Max-Age': '600',
          });
          return res.end();
        }
        if (String(req.method || '').toUpperCase() !== 'POST' || !cfg.tokenMethods.includes('POST')) {
          return deny(req, res, 405, 'method not allowed', {
            phase, reason: 'batch-token-method', headers: { Allow: 'POST' },
          });
        }
        const contentType = String(req.headers?.['content-type'] || '').split(';')[0].trim().toLowerCase();
        const contentEncoding = String(req.headers?.['content-encoding'] || 'identity').trim().toLowerCase();
        const declaredLength = req.headers?.['content-length'] == null
          ? null
          : Number(req.headers['content-length']);
        if (contentType !== 'application/json' || contentEncoding !== 'identity' ||
            (declaredLength !== null &&
             (!Number.isFinite(declaredLength) || declaredLength < 0 || declaredLength > cfg.batchTokenMaxBytes))) {
          return deny(req, res, declaredLength > cfg.batchTokenMaxBytes ? 413 : 415,
            declaredLength > cfg.batchTokenMaxBytes ? 'request too large' : 'unsupported media type', {
              phase, reason: 'batch-content-type',
            });
        }
        if (!originAllowed(req)) return deny(req, res, 403, 'forbidden', { phase, reason: 'origin' });
        if (!fetchSiteAllowed(req)) return deny(req, res, 403, 'forbidden', { phase, reason: 'cross-site-token' });
        if (!tokenRequestHeaderAllowed(req)) {
          return deny(req, res, 403, 'forbidden', { phase, reason: 'token-request-header' });
        }

        let proofThumbprint = null;
        if (cfg.proofOfPossession !== 'off') {
          const proofKeyHeader = req.headers?.['x-archx-proof-key'];
          if (proofKeyHeader !== undefined) {
            const parsedProofKey = parseProofPublicKeyHeader(proofKeyHeader);
            if (!parsedProofKey) {
              return deny(req, res, 403, 'forbidden', { phase, reason: 'proof-key-invalid' });
            }
            proofThumbprint = parsedProofKey.jkt;
          } else if (cfg.proofOfPossession === 'required') {
            return deny(req, res, 403, 'forbidden', { phase, reason: 'proof-key-required' });
          }
        }

        let batchBody;
        try { batchBody = await readBatchTokenBody(req); }
        catch (err) {
          if (err instanceof MintDenied) {
            return deny(req, res, err.status, err.error, {
              phase, reason: err.details.reason || 'batch-body',
            });
          }
          throw err;
        }
        if (Object.keys(batchBody).some((field) => field !== 'items') ||
            !Array.isArray(batchBody.items) || !batchBody.items.length ||
            batchBody.items.length > cfg.batchTokenMaxItems) {
          return deny(req, res, 400, 'bad request', { phase, reason: 'batch-items' });
        }

        const tokens = Object.create(null);
        const errors = Object.create(null);
        const validatedRefs = new Set();
        // Validate the response-addressing refs before any token is minted;
        // discovering a duplicate halfway through would otherwise issue
        // real one-time tokens that can no longer be returned coherently.
        for (let refIndex = 0; refIndex < batchBody.items.length; refIndex++) {
          const candidate = batchBody.items[refIndex];
          const candidateRef = isPlainObject(candidate) && candidate.ref !== undefined
            ? candidate.ref
            : String(refIndex);
          if (typeof candidateRef !== 'string' ||
              !/^[A-Za-z0-9._~-]{1,64}$/.test(candidateRef) || validatedRefs.has(candidateRef)) {
            return deny(req, res, 400, 'bad request', { phase, reason: 'batch-ref' });
          }
          validatedRefs.add(candidateRef);
        }
        const seenRefs = new Set();
        const allowedItemFields = new Set(['ref', 'id', 'w', 'bw', 'bh', 'fit', 'q']);
        let hardFailure = null;
        for (let itemIndex = 0; itemIndex < batchBody.items.length; itemIndex++) {
          const item = batchBody.items[itemIndex];
          const fallbackRef = String(itemIndex);
          const ref = isPlainObject(item) && item.ref !== undefined ? item.ref : fallbackRef;
          if (typeof ref !== 'string' || !/^[A-Za-z0-9._~-]{1,64}$/.test(ref) || seenRefs.has(ref)) {
            return deny(req, res, 400, 'bad request', { phase, reason: 'batch-ref' });
          }
          seenRefs.add(ref);
          if (hardFailure) {
            errors[ref] = hardFailure;
            continue;
          }
          if (itemIndex > 0) {
            // The handler-level limiter paid for item 0. Every additional
            // item pays too, including malformed/unknown IDs, so batching
            // cannot amplify enumeration or mint attempts for free.
            const itemRate = await rateLimited(req, 'token');
            if (itemRate.limited) {
              hardFailure = { status: 429, error: 'too many requests' };
              errors[ref] = hardFailure;
              emitSecurityEvent('archx.denied', req, {
                id: isPlainObject(item) && validateImageId(item.id) ? item.id : null,
                phase, status: 429, reason: 'rate-limit',
              });
              continue;
            }
          }
          if (!isPlainObject(item) || Object.keys(item).some((field) => !allowedItemFields.has(field))) {
            errors[ref] = { status: 400, error: 'bad request' };
            emitSecurityEvent('archx.denied', req, { phase, status: 400, reason: 'batch-item' });
            continue;
          }
          const itemId = item.id;
          if (!validateImageId(itemId) || !index.has(itemId)) {
            errors[ref] = { status: 404, error: 'not found' };
            emitSecurityEvent('archx.denied', req, {
              id: validateImageId(itemId) ? itemId : null,
              phase, status: 404, reason: 'unknown-or-invalid-id',
            });
            continue;
          }
          try {
            tokens[ref] = await mintTokenResponse(req, itemId, item, proofThumbprint);
          } catch (err) {
            if (err instanceof MintDenied) {
              errors[ref] = { status: err.status, error: err.error };
              emitSecurityEvent('archx.denied', req, {
                id: itemId,
                phase,
                viewerId: err.details.viewerId || null,
                status: err.status,
                reason: err.details.reason || err.error,
              });
              continue;
            }
            if (err?.code === 'ARCHX_STATE_STORE_UNAVAILABLE') {
              hardFailure = { status: 503, error: 'service unavailable' };
              errors[ref] = hardFailure;
              emitSecurityEvent('archx.denied', req, {
                id: itemId, phase, status: 503, reason: 'state-store-unavailable',
              });
              continue;
            }
            const status = err?.code === 'ARCHX_CALLBACK_TIMEOUT' ? 503 : 500;
            errors[ref] = {
              status,
              error: status === 503 ? 'service unavailable' : 'image processing failed',
            };
            emitSecurityEvent('archx.processing_error', req, {
              id: itemId, phase, status, reason: err?.code || 'batch-mint',
            });
          }
        }
        return sendJson(req, res, 200, { tokens, errors });
      }

      let id;
      try { id = decodeURIComponent(rawId || ''); }
      catch { return deny(req, res, 400, 'bad request', { phase, reason: 'bad-id-encoding' }); }
      routeId = validateImageId(id) ? id : null;
      if (!validateImageId(id) || !index.has(id)) {
        return deny(req, res, 404, 'not found', { id: routeId, phase, reason: 'unknown-or-invalid-id' });
      }

      if (req.method === 'OPTIONS') {
        if (!allowedOrigins?.length || !originAllowed(req)) {
          return deny(req, res, 403, 'forbidden', { id, phase, reason: 'cors-origin' });
        }
        res.writeHead(204, {
          ...protectedHeaders(req),
          'Access-Control-Allow-Methods': kind === 'token' ? `${cfg.tokenMethods.join(', ')}, OPTIONS` : 'GET, OPTIONS',
          'Access-Control-Allow-Headers': kind === 'token' ? 'Content-Type, X-Archx-Request, X-Archx-Proof-Key' : 'X-Archx-Token, X-Archx-Proof',
          'Access-Control-Max-Age': '600',
        });
        return res.end();
      }
      if (kind === 'token' && !cfg.tokenMethods.includes(String(req.method || '').toUpperCase())) {
        return deny(req, res, 405, 'method not allowed', {
          id, phase, reason: 'token-method', headers: { Allow: cfg.tokenMethods.join(', ') },
        });
      }
      if (kind === 'i' && req.method !== 'GET') {
        return deny(req, res, 405, 'method not allowed', {
          id, phase, reason: 'image-method', headers: { Allow: 'GET' },
        });
      }
      if (kind === 'token') {
        const lengthHeader = req.headers?.['content-length'];
        const declaredLength = lengthHeader == null ? 0 : Number(lengthHeader);
        // This endpoint needs no body. Reject chunked transfer encoding as
        // well as oversized declared bodies, so omitting Content-Length is
        // not a way around the 1 KiB request budget.
        if (req.headers?.['transfer-encoding'] ||
            !Number.isFinite(declaredLength) || declaredLength < 0 || declaredLength > 1024) {
          return deny(req, res, 413, 'request too large', { id, phase, reason: 'token-body' });
        }
      }

      if (!originAllowed(req)) return deny(req, res, 403, 'forbidden', { id, phase, reason: 'origin' });
      if (kind === 'token' && !fetchSiteAllowed(req)) {
        return deny(req, res, 403, 'forbidden', { id, phase, reason: 'cross-site-token' });
      }
      if (kind === 'token' && !tokenRequestHeaderAllowed(req)) {
        return deny(req, res, 403, 'forbidden', { id, phase, reason: 'token-request-header' });
      }

      if (kind === 'token') {
        let proofThumbprint = null;
        if (cfg.proofOfPossession !== 'off') {
          const proofKeyHeader = req.headers?.['x-archx-proof-key'];
          if (proofKeyHeader !== undefined) {
            const parsedProofKey = parseProofPublicKeyHeader(proofKeyHeader);
            if (!parsedProofKey) {
              return deny(req, res, 403, 'forbidden', { id, phase, reason: 'proof-key-invalid' });
            }
            proofThumbprint = parsedProofKey.jkt;
          } else if (cfg.proofOfPossession === 'required') {
            return deny(req, res, 403, 'forbidden', { id, phase, reason: 'proof-key-required' });
          }
        }
        let out;
        try {
          out = await mintTokenResponse(
            req,
            id,
            Object.fromEntries(url.searchParams.entries()),
            proofThumbprint,
          );
        } catch (err) {
          if (err instanceof MintDenied) {
            return deny(req, res, err.status, err.error, {
              id,
              phase,
              viewerId: err.details.viewerId || null,
              reason: err.details.reason || err.error,
              headers: err.details.headers || {},
            });
          }
          throw err;
        }
        return sendJson(req, res, 200, out);
      }

      if (kind === 'i') {
        const queryTokens = url.searchParams.getAll('t');
        const headerTokenRaw = req.headers?.['x-archx-token'];
        const headerTokens = headerTokenRaw === undefined ? [] : (Array.isArray(headerTokenRaw) ? headerTokenRaw : [headerTokenRaw]);
        const tokenValues = [...(cfg.allowQueryTokens ? queryTokens : []), ...headerTokens];
        // Shape alone never grants or denies anything: it only selects the
        // candidate string (and the diagnostic deny reason). The security
        // gate is verifyToken() itself — only a token whose HMAC-SHA256
        // signature verifies under a known key produces a payload at all,
        // and validateTokenClaims() then binds it to this image/TTL.
        const shapeBad = (!cfg.allowQueryTokens && queryTokens.length > 0) || tokenValues.length !== 1 ||
          typeof tokenValues[0] !== 'string' || tokenValues[0].length < 16 || tokenValues[0].length > 8192;
        const payload = verifyToken(shapeBad ? '' : tokenValues[0], signingKeys);
        const issuingSecret = secretForToken(payload);
        if (!issuingSecret || !validateTokenClaims(payload, { id, maxWidthCap, maxTtlMs: ttlMs })) {
          return deny(req, res, 403, 'invalid or expired token',
            { id, phase, reason: shapeBad ? 'token-count' : 'token-claims' });
        }

        let verifiedProof = null;
        if (cfg.proofOfPossession === 'required' && !payload.jkt) {
          return deny(req, res, 403, 'invalid or expired token', { id, phase, reason: 'proof-required' });
        }
        if (payload.jkt) {
          const proofHeaderRaw = req.headers?.['x-archx-proof'];
          const proofHeader = typeof proofHeaderRaw === 'string' ? proofHeaderRaw : null;
          verifiedProof = verifyProofOfPossession({
            header: proofHeader,
            token: tokenValues[0],
            expectedJkt: payload.jkt,
            method: req.method,
            target: `${basePath}/i/${encodeURIComponent(id)}`,
          });
          if (!verifiedProof) {
            return deny(req, res, 403, 'invalid or expired token', { id, phase, reason: 'proof-invalid' });
          }
        }

        // Re-authorize redemption before spending the one-time claim. A
        // still-unexpired token must not survive logout, entitlement
        // revocation, or transfer to another viewer; conversely, a transient
        // authorization failure should not burn an otherwise valid token.
        const entitlement = await authorizeRequest(req, id, 'image', payload);
        if (!entitlement) return deny(req, res, 403, 'forbidden', { id, phase, reason: 'authorization' });
        const currentViewerId = authorizationViewerId(entitlement);
        if (payload.vh) {
          const currentViewerHash = currentViewerId ? hmacShort('viewer', currentViewerId, 20, issuingSecret) : '';
          if (!currentViewerHash || !safeEqual(payload.vh, currentViewerHash)) {
            return deny(req, res, 403, 'invalid or expired token', { id, phase, reason: 'viewer-binding' });
          }
        }
        const currentTrace = authorizationTrace(entitlement, currentViewerId, issuingSecret);
        const currentHasTraceFields = ['buyerId', 'orderId', 'deliveryId', 'traceId']
          .some((field) => entitlement[field] != null);
        if (payload.th && currentHasTraceFields &&
            (!currentTrace.hash || !safeEqual(payload.th, currentTrace.hash))) {
          return deny(req, res, 403, 'invalid or expired token', { id, phase, reason: 'trace-binding' });
        }
        if (payload.b) {
          try {
            const bindingsToCheck = [
              ['ip', bindTokenTo.ip, requestIp(req), 'bind-ip', 'ip-binding'],
              ['ua', bindTokenTo.userAgent, req.headers?.['user-agent'] || '', 'bind-ua', 'ua-binding'],
              ['sess', bindTokenTo.session, currentViewerId, 'bind-session', 'session-binding'],
            ];
            for (const [field, setting, fallback, label, reason] of bindingsToCheck) {
              if (!payload.b[field]) continue;
              if (!setting) throw new Error(reason);
              const value = await resolveBindingValue(setting, req, fallback);
              const expected = value == null ? '' : hmacShort(label, value, 16, issuingSecret);
              if (!expected || !safeEqual(payload.b[field], expected)) throw new Error(reason);
            }
          } catch (err) {
            return deny(req, res, 403, 'invalid or expired token', { id, phase, reason: err?.message || 'binding' });
          }
        }
        // Claims are atomic state-store operations. The built-in memory store
        // is atomic within this process; a shared store must provide the same
        // guarantee across every process/instance (SET NX, conditional write,
        // transaction, or equivalent). A store timeout/error fails closed.
        if (verifiedProof) {
          const proofHash = hmacShort('proof', verifiedProof.jkt + ':' + verifiedProof.jti, 32, issuingSecret);
          if (!await stateClaimOnce(`proof:${proofHash}`, verifiedProof.exp - Date.now())) {
            return deny(req, res, 403, 'invalid or expired token', { id, phase, reason: 'proof-replay' });
          }
        }
        if (oneTimeTokens) {
          const nonceHash = hmacShort('once', id + ':' + payload.n, 32, issuingSecret);
          if (!await stateClaimOnce(`nonce:${nonceHash}`, payload.exp - Date.now())) {
            return deny(req, res, 403, 'invalid or expired token', { id, phase, reason: 'token-replay' });
          }
        }
        const imageQuota = await quotaExceeded(req, id, currentViewerId, 'image', issuingSecret);
        if (imageQuota) {
          return deny(req, res, 429, 'quota exceeded', {
            id, phase, viewerId: currentViewerId, reason: `quota:${imageQuota.name}`,
            headers: { 'Retry-After': String(imageQuota.retryAfterSec || 60) },
          });
        }

        // Current authorization may tighten—but never widen—the signed claim.
        let effectiveWidth = payload.w;
        if (entitlement.maxWidth != null) {
          const currentCap = Number(entitlement.maxWidth);
          if (!Number.isFinite(currentCap) || currentCap < 64) {
            return deny(req, res, 403, 'forbidden', { id, phase, viewerId: currentViewerId, reason: 'invalid-entitlement-width' });
          }
          effectiveWidth = Math.min(effectiveWidth, Math.floor(currentCap));
        }
        let effectiveQuality = payload.q ?? quality;
        let effectiveLossless = payload.ls === 1 || effectiveQuality === 'lossless' || lossless;
        if (entitlement.lossless === false && effectiveLossless) {
          effectiveLossless = false;
          effectiveQuality = quality === 'lossless' ? 95 : quality;
        }
        if (entitlement.quality != null && entitlement.quality !== 'lossless') {
          const currentQuality = Number(entitlement.quality);
          if (!Number.isFinite(currentQuality) || currentQuality < 1 || currentQuality > 100) {
            return deny(req, res, 403, 'forbidden', { id, phase, viewerId: currentViewerId, reason: 'invalid-entitlement-quality' });
          }
          const signedQuality = effectiveLossless ? 100 : Number(effectiveQuality) || 95;
          effectiveQuality = Math.min(signedQuality, Math.round(currentQuality));
          effectiveLossless = false;
        }
        let effectiveFormat = ['webp', 'png', 'jpeg', 'avif'].includes(payload.fmt) ? payload.fmt : format;
        if (entitlement.format != null) {
          if (!['webp', 'png', 'jpeg', 'avif'].includes(entitlement.format)) {
            return deny(req, res, 403, 'forbidden', { id, phase, viewerId: currentViewerId, reason: 'invalid-entitlement-format' });
          }
          effectiveFormat = entitlement.format;
        }

        const scrambleKey = deriveScrambleKey(id, payload.n, issuingSecret);
        const forensicSeed = forensic
          ? hmacShort('forensic', forensicScope === 'image'
              ? `${id}:image`
              : forensicPerToken
                ? `${id}:${payload.n}:${payload.th || payload.vh || ''}`
                : `${id}:static:${payload.th || payload.vh || ''}`, 32, issuingSecret)
          : null;
        const deliveryQuality = effectiveQuality;
        const deliveryLossless = effectiveLossless;
        const deliveryFormat = effectiveFormat;
        const resolvedMaster = resolveIndexedFile(id);
        if (!resolvedMaster) return deny(req, res, 404, 'not found', { id, phase, reason: 'master-missing' });
        if (resolvedMaster.stat.size > cfg.processing.maxInputBytes) {
          return deny(req, res, 413, 'image too large', { id, phase, reason: 'master-too-large' });
        }
        const masterVersion = fileVersion(resolvedMaster.stat);
        const signedStegoEnabled = payload.nsg === 1
          ? false
          : (payload.sge === 1 || !!steganography || !!payload.sg);
        if ((entitlement.steganography === false && signedStegoEnabled) ||
            (entitlement.steganography && !signedStegoEnabled) ||
            (entitlement.stegoFingerprint && entitlement.stegoFingerprint !== payload.sg)) {
          return deny(req, res, 403, 'forbidden', { id, phase, viewerId: currentViewerId, reason: 'stego-entitlement-mismatch' });
        }
        const stegoEnabled = signedStegoEnabled;
        const stegoPayload = stegoEnabled
          ? (payload.sg || deriveStegoFingerprint({
              id,
              nonce: payload.n,
              viewerHash: payload.sgi === 1 ? '' : (payload.th || payload.vh || ''),
              secret: issuingSecret,
              perToken: payload.sgi === 1 ? false : payload.sgp !== 0,
            }))
          : null;
        const effectiveStegoProfile = payload.sgv === 2 ? 'robust' : 'standard';
        const effectiveStegoStrength = payload.sgs ?? stegoGlobalCfg.strength ?? 6;
        const effectiveStegoGridX = payload.sgx ?? stegoGlobalCfg.gridX;
        const effectiveStegoGridY = payload.sgy ?? stegoGlobalCfg.gridY;
        const wmCachePart = payload.wm ? hmacShort('wm', JSON.stringify(payload.wm), 12, issuingSecret) : 'nowm';
        const stegoKeySubject = payload.sgk === 1 ? (payload.th || payload.vh || '') : '';
        const effectiveStegoKey = stegoPayload
          ? deriveStegoKey(stegoKeySubject ? `${id}|viewer:${stegoKeySubject}` : id, issuingSecret)
          : null;
        const stegoCachePart = stegoPayload
          ? `${hmacShort('sg', stegoPayload, 12, issuingSecret)}:${effectiveStegoProfile}:s${effectiveStegoStrength}:x${effectiveStegoGridX ?? (effectiveStegoProfile === 'robust' ? 20 : 24)}:y${effectiveStegoGridY ?? (effectiveStegoProfile === 'robust' ? 14 : 16)}:k${hmacShort('sgkey', effectiveStegoKey || '', 8, issuingSecret)}:tm`
          : 'nosg';
        // Cache identity contains only inputs that can change the delivered
        // bytes. Viewer/trace hashes are not added unconditionally: when a
        // watermark, forensic seed, or StegoMark is viewer-specific, that
        // material is already represented by its own cache fragment below.
        // This is what allows an ordinary catalog derivative to be generated
        // once and reused by every authorized viewer.
        const aesKey = encrypt ? deriveAesKey(id, payload.n, issuingSecret) : null;
        const forensicCachePart = forensicSeed
          ? hmacShort('fxseed', `${forensicSeed}:${typeof forensic === 'object' ? JSON.stringify(forensic) : ''}`, 16, issuingSecret)
          : 'nofx';
        const processingCachePart = [
          `we${cfg.processing.webpEffort}`,
          cfg.processing.webpSmartSubsample ? 'wss1' : 'wss0',
          `rk:${cfg.processing.resizeKernel}`,
          `png${cfg.processing.pngCompressionLevel}`,
          `jpg:${cfg.processing.jpegChromaSubsampling}`,
          `op${cfg.processing.maxOutputPixels}`,
        ].join(':');
        const cacheKey = [
          // Cache-key version bumps ride every pad/mark byte change so
          // warm caches never serve pre-fix bytes: v3 black->edge-
          // replicate (v1.11); v4 reflection->keyed shifted-wrap padding
          // + 128-bit stego layouts (v1.13). Displayed pixels identical.
          'v4', id, masterVersion, `kid:${payload.kid}`, effectiveWidth, `g${grid}`, `pv${scramblePlanVersion}`,
          hmacShort('scramble-key', scrambleKey, 16, issuingSecret),
          aesKey ? hmacShort('aes-key', aesKey, 16, issuingSecret) : 'plain',
          wmCachePart, forensicCachePart,
          `q${deliveryQuality}`, deliveryLossless ? 'ls' : 'lq', deliveryFormat,
          stegoCachePart, processingCachePart,
        ].join('|');
        const sharedCacheKey = `cache:${hmacShort('output-cache', cacheKey, 43, issuingSecret)}`;
        // A derivative whose bytes depend on the one-time token nonce can
        // never be served again (the token dies with this redemption), so
        // writing it to RAM/disk/Redis only thrashes I/O and evicts
        // reusable catalog entries. Skip every cache tier for those.
        const perTokenDerivative = scrambleKeyMode === 'per-token' ||
          (!!forensicSeed && forensicScope !== 'image' && forensicPerToken) ||
          (stegoEnabled && payload.sgi !== 1 && payload.sgp !== 0);
        const cacheable = !perTokenDerivative;
        const expectedCached = {
          grid,
          planVersion: scramblePlanVersion,
          maxWidth: effectiveWidth,
          encrypted: !!aesKey,
          mime: deliveryFormat === 'png' ? 'image/png'
            : deliveryFormat === 'jpeg' ? 'image/jpeg'
            : deliveryFormat === 'avif' ? 'image/avif' : 'image/webp',
        };
        let bytes = cacheable ? getOutputCache(cacheKey) : null;
        if (bytes) derivativeCacheStats.memoryHits++;
        if (!bytes && cacheable) {
          bytes = await getDiskOutputCache(sharedCacheKey, expectedCached);
          if (bytes) setOutputCache(cacheKey, bytes);
        }
        if (!bytes && cacheable) {
          bytes = await getSharedOutputCache(sharedCacheKey, expectedCached);
          if (bytes) {
            derivativeCacheStats.sharedHits++;
            setOutputCache(cacheKey, bytes);
            await setDiskOutputCache(sharedCacheKey, bytes);
          }
        }
        if (!bytes) {
          let pending = outputInFlight.get(cacheKey);
          // Singleflight: the first cold request for a derivative runs the
          // one Sharp job; concurrent waiters join the same promise instead
          // of stampeding the origin with duplicate transforms. Only the
          // leader counts as a cache miss; waiters count as coalesced.
          if (pending) derivativeCacheStats.coalesced++;
          else derivativeCacheStats.misses++;
          if (!pending) {
            pending = (async () => {
              try {
                const liveCached = getOutputCache(cacheKey);
                if (liveCached) return liveCached;
                const { filePath, stat } = resolvedMaster;
                const loadMaster = async () => {
                  let master = cacheTouch(masterCache, id);
                  if (master && master.version === masterVersion) return { bytes: master.bytes, current: true };
                  if (master) {
                    masterCacheBytes -= master.bytes.length;
                    masterCache.delete(id);
                  }
                  const flightKey = `${id}|${masterVersion}`;
                  if (masterInFlight.has(flightKey)) return masterInFlight.get(flightKey);
                  const readPending = (async () => {
                    try {
                      const data = await fs.promises.readFile(filePath);
                      const currentResolved = resolveIndexedFile(id);
                      const current = !!currentResolved && currentResolved.filePath === filePath &&
                        fileVersion(currentResolved.stat) === masterVersion && data.length === stat.size;
                      if (current) {
                        setMasterCache(id, {
                          version: masterVersion, mtimeMs: stat.mtimeMs, ctimeMs: stat.ctimeMs,
                          size: stat.size, ino: stat.ino ?? null, bytes: data,
                        });
                      }
                      return { bytes: data, current };
                    } finally {
                      if (masterInFlight.get(flightKey) === readPending) masterInFlight.delete(flightKey);
                    }
                  })();
                  masterInFlight.set(flightKey, readPending);
                  return readPending;
                };
                const master = await loadMaster();
                // Lazy import so token-only deployments don't need sharp wired early.
                const { scrambleImage, prepareDerivativeBase, finishDerivative, configureSharpPerformance } = await import('./scramble-image.js');
                if (!sharpPerformanceConfigured &&
                    (cfg.processing.sharpConcurrency > 0 || cfg.processing.sharpCache !== undefined)) {
                  configureSharpPerformance({
                    ...(cfg.processing.sharpConcurrency > 0
                      ? { concurrency: cfg.processing.sharpConcurrency }
                      : {}),
                    ...(cfg.processing.sharpCache !== undefined
                      ? { cache: cfg.processing.sharpCache }
                      : {}),
                  });
                  sharpPerformanceConfigured = true;
                }
                const scrambleOpts = {
                  grid,
                  planVersion: scramblePlanVersion,
                  key: scrambleKey,
                  maxWidth: Math.min(maxWidthCap, effectiveWidth),
                  quality: deliveryQuality,
                  lossless: deliveryLossless,
                  format: deliveryFormat,
                  aesKey,
                  watermark: payload.wm || null,
                  forensicSeed,
                  forensic: typeof forensic === 'object' ? forensic : {},
                  stegoPayload,
                  stegoKey: effectiveStegoKey,
                  stegoStrength: effectiveStegoStrength,
                  stegoProfile: effectiveStegoProfile,
                  steganography: stegoPayload ? {
                    ...stegoGlobalCfg,
                    profile: effectiveStegoProfile,
                    ...(effectiveStegoGridX != null ? { gridX: effectiveStegoGridX } : {}),
                    ...(effectiveStegoGridY != null ? { gridY: effectiveStegoGridY } : {}),
                  } : null,
                  processing: cfg.processing,
                  maxInputBytes: cfg.processing.maxInputBytes,
                  maxInputPixels: cfg.processing.maxInputPixels,
                  maxInputWidth: cfg.processing.maxInputWidth,
                  maxInputHeight: cfg.processing.maxInputHeight,
                  maxOutputPixels: cfg.processing.maxOutputPixels,
                  processingTimeoutSec: cfg.processing.timeoutSec,
                  allowedInputFormats: cfg.processing.allowedInputFormats,
                  blockUntrustedSharpLoaders: cfg.processing.blockUntrustedSharpLoaders,
                };
                // Uncacheable (per-token/per-viewer) derivatives reuse the
                // cached stage-1 base frame: decode+resize runs once per
                // (master, geometry) instead of once per view. The base is
                // watermark-free since 1.13 (the watermark is a stage-2
                // finish): in 1.12.0 the base carried the baked watermark
                // and this key hashed object-form watermarks via
                // String() -> "[object Object]", collapsing every viewer
                // onto one shared, wrongly-watermarked frame.
                const result = await processingSemaphore.run(async () => {
                  if (cacheable) return scrambleImage(master.bytes, scrambleOpts);
                  const baseKey = [
                    'base', id, masterVersion, `w${effectiveWidth}`, `g${grid}`,
                    `rk:${cfg.processing.resizeKernel}`,
                    `op${cfg.processing.maxOutputPixels}`,
                  ].join(':');
                  let base = getBaseCache(baseKey);
                  if (!base) {
                    base = await prepareDerivativeBase(master.bytes, scrambleOpts);
                    if (master.current) setBaseCache(baseKey, base);
                  }
                  return finishDerivative(base, scrambleOpts);
                });
                if (master.current && cacheable) {
                  setOutputCache(cacheKey, result.bytes);
                  await setDiskOutputCache(sharedCacheKey, result.bytes);
                  await setSharedOutputCache(sharedCacheKey, result.bytes);
                }
                return result.bytes;
              } finally {
                if (outputInFlight.get(cacheKey) === pending) outputInFlight.delete(cacheKey);
              }
            })();
            outputInFlight.set(cacheKey, pending);
          }
          bytes = await pending;
        }
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Content-Length': bytes.length,
          'Content-Disposition': 'inline; filename="data.bin"',
          'Content-Security-Policy': "default-src 'none'; sandbox",
          ...protectedHeaders(req),
        });
        emitDeliveryEvent('archx.image_delivered', {
          id,
          phase,
          viewerHash: payload.vh || null,
          traceHash: payload.th || null,
          keyId: payload.kid || null,
          width: effectiveWidth,
          quality: deliveryQuality,
          format: deliveryFormat,
          stegoFingerprint: stegoPayload ? resolveStegoFingerprint(stegoPayload) : null,
          stegoProfile: stegoPayload ? effectiveStegoProfile : null,
          bytes: bytes.length,
        });
        return res.end(bytes);
      }

      return sendJson(req, res, 404, { error: 'not found' });
    } catch (err) {
      // Controlled failures only: never leak paths, decoder details, stacks,
      // token material, or authorization internals to the client.
      if (!res.headersSent) {
        if (err?.code === 'ARCHX_INPUT_TOO_LARGE') {
          return deny(req, res, 413, 'image too large', { id: routeId, phase, reason: 'input-too-large' });
        }
        if (err?.code === 'ARCHX_UNSUPPORTED_IMAGE') {
          return deny(req, res, 415, 'unsupported image', { id: routeId, phase, reason: 'unsupported-image' });
        }
        if (err?.code === 'ARCHX_PROCESSING_BUSY') {
          return deny(req, res, 503, 'service unavailable', {
            id: routeId, phase, reason: 'processing-busy', headers: { 'Retry-After': '1' },
          });
        }
        if (err?.code === 'ARCHX_PROCESSING_TIMEOUT') {
          return deny(req, res, 503, 'service unavailable', { id: routeId, phase, reason: 'processing-timeout' });
        }
        if (err?.code === 'ARCHX_STATE_STORE_UNAVAILABLE') {
          return deny(req, res, 503, 'service unavailable', {
            id: routeId, phase, reason: 'state-store-unavailable', headers: { 'Retry-After': '1' },
          });
        }
        emitSecurityEvent('archx.processing_error', req, { id: routeId, phase, status: 500, reason: err?.code || 'internal' });
        return sendJson(req, res, 500, { error: 'image processing failed' });
      }
      try { res.end(); } catch { /* response already closing */ }
      return undefined;
    }
  }

  handler.configAudit = auditArchxServerConfig(options);
  handler.stats = () => {
    let storeStats = {};
    try {
      const maybeStats = typeof stateStore.stats === 'function' ? stateStore.stats() : null;
      if (maybeStats && typeof maybeStats === 'object' && typeof maybeStats.then !== 'function') {
        storeStats = maybeStats;
      }
    } catch { /* stats are diagnostic only */ }
    const statNumber = (value) => Number.isFinite(Number(value)) ? Math.max(0, Math.floor(Number(value))) : 0;
    return Object.freeze({
      images: index.size,
      deploymentMode: cfg.deploymentMode,
      stateStore: storeStats.kind || stateStore.kind || (ownsStateStore ? 'memory' : 'custom'),
      stateStoreShared: !ownsStateStore,
      activeSecretId,
      signingKeyCount: signingKeys.size,
      rateLimitClients: statNumber(storeStats.rateLimitClients),
      quotaClients: statNumber(storeStats.quotaClients),
      consumedTokens: statNumber(storeStats.consumedTokens),
      consumedProofs: statNumber(storeStats.consumedProofs),
      sharedCacheEntries: statNumber(storeStats.sharedCacheEntries),
      sharedCacheBytes: statNumber(storeStats.sharedCacheBytes),
      outputCacheEntries: outputCache.size,
      baseCacheEntries: baseCache.size,
      baseCacheBytes,
      outputCacheBytes,
      derivativeCache: Object.freeze({ ...derivativeCacheStats }),
      masterCacheEntries: masterCache.size,
      masterCacheBytes,
      processingActive: processingSemaphore.active,
      processingQueued: processingSemaphore.queued,
      outputInFlight: outputInFlight.size,
      dimensionInFlight: dimensionInFlight.size,
      masterInFlight: masterInFlight.size,
    });
  };
  handler.close = () => {
    // A host-supplied store may be shared by several handlers/processes and
    // remains host-owned; only the internally created memory store is closed.
    if (ownsStateStore) {
      try { stateStore.close?.(); } catch { /* shutdown best effort */ }
    }
    masterCache.clear(); masterCacheBytes = 0;
    baseCache.clear(); baseCacheBytes = 0;
    outputCache.clear(); outputCacheBytes = 0;
    dimensionCache.clear();
    indexedFileCache.clear();
    try { abuseAlertLatch.close(); } catch { /* shutdown best effort */ }
    outputInFlight.clear();
    dimensionInFlight.clear();
    masterInFlight.clear();
  };
  return handler;
}

export default createArchxMiddleware;
