/**
 * Bounded in-memory admission-control structures: sliding-window rate
 * limiters, TTL replay sets, the async semaphore, distinct-access
 * tracking and the default process-local state store. Every structure
 * has a hard capacity; none grows without bound under hostile input.
 * Re-exported from server/middleware.js for back-compat.
 */

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

  constructor({ maxEntries = 100000, cleanupIntervalMs = 60000, onLiveEvict = null, saturation = 'evict' } = {}) {
    this.maxEntries = maxEntries;
    // Saturation policy is an explicit security/availability choice:
    // 'evict' (availability) drops the oldest live claims when full;
    // 'strict' never evicts a live claim and instead rejects NEW
    // claims — strict one-time semantics, at the cost of rejecting
    // legitimate redemptions while the store is saturated.
    this.saturation = saturation === 'strict' ? 'strict' : 'evict';
    this.liveEvictions = 0;
    this.saturationRejections = 0;
    this.onLiveEvict = typeof onLiveEvict === 'function' ? onLiveEvict : null;
    if (cleanupIntervalMs > 0) {
      this.#timer = setInterval(() => this.cleanup(), cleanupIntervalMs);
      this.#timer.unref?.();
    }
  }

  get size() { return this.#map.size; }

  /** Non-mutating liveness peek (does not claim or evict). */
  has(key, now = Date.now()) {
    const exp = this.#map.get(key);
    return exp !== undefined && exp > now;
  }

  cleanup(now = Date.now()) {
    for (const [key, exp] of this.#map) if (exp <= now) this.#map.delete(key);
  }

  claim(key, exp, now = Date.now()) {
    if (!key || !Number.isFinite(exp) || exp <= now) return false;
    if (this.#map.has(key)) return false;
    if (this.#map.size >= this.maxEntries) {
      // Amortized front eviction: Map insertion order tracks claim time
      // and one deployment shares one TTL, so the front of the map is
      // (approximately) expiry order. Drop expired entries first; if
      // STILL saturated, evict the oldest live entries — the ones with
      // the smallest remaining replay window — instead of the old
      // behavior: an O(N) full-map scan on every claim followed by a
      // global fail-closed rejection of every legitimate viewer (a
      // self-DoS once maxEntries unexpired JTIs accumulated). Evicting
      // one near-expiry JTI re-opens replay for that single signed,
      // PoP-bound, re-authorized token only; failing everyone is worse.
      let budget = 1024 + (this.maxEntries >> 6);
      let liveEvicted = 0;
      // Pass 1 (budget-bounded head scan): drop expired entries only.
      // Live eviction is deferred until expired space is PROVEN
      // exhausted — with mixed per-tier TTLs, expired short-TTL
      // entries can sit behind thousands of live long-TTL ones, and
      // evicting/rejecting at that point would be a false saturation.
      for (const [k, e] of this.#map) {
        if (budget-- <= 0) break;
        if (e <= now) this.#map.delete(k);
        if (this.#map.size < this.maxEntries) break;
      }
      if (this.#map.size >= this.maxEntries) {
        // Pass 2: one full expired sweep. O(N) but reached only when
        // saturated with expiry disorder; it makes 'strict' exact
        // (reject only when truly full of LIVE claims) and keeps
        // 'evict' from dropping live claims unnecessarily.
        this.cleanup(now);
      }
      if (this.#map.size >= this.maxEntries && this.saturation !== 'strict') {
        // Pass 3 ('evict' only): now drop oldest live entries.
        for (const k of this.#map.keys()) {
          if (this.#map.size < this.maxEntries) break;
          this.#map.delete(k);
          liveEvicted++;
        }
      }
      this.liveEvictions += liveEvicted;
      // A live (unexpired) entry lost its replay protection early.
      // That is the S4 safety valve firing: the deployment is minting
      // faster than the store can hold one TTL of JTIs. Surface it so
      // operators can raise oneTimeTokenMaxEntries or tighten mint
      // rates instead of discovering it from a replayed token.
      if (liveEvicted > 0 && this.onLiveEvict) {
        try { this.onLiveEvict(liveEvicted); } catch { /* observer must not break claims */ }
      }
      if (this.#map.size >= this.maxEntries) {
        // 'strict': saturated with live claims -> reject the new one
        // (caller distinguishes nothing: claimOnce=false is a denial,
        // and the unclaimed token may succeed after entries expire).
        // 'evict': only reachable under pathological expiry disorder.
        if (this.saturation === 'strict') this.saturationRejections++;
        return false;
      }
    }
    this.#map.set(key, exp);
    return true;
  }

  stats() {
    return Object.freeze({
      size: this.#map.size,
      maxEntries: this.maxEntries,
      saturation: this.saturation,
      liveEvictions: this.liveEvictions,
      saturationRejections: this.saturationRejections,
    });
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
  onLiveEvict = null,
  saturation = 'evict',
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
      set = new BoundedTtlSet({ maxEntries, cleanupIntervalMs, onLiveEvict, saturation });
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
      const replaySets = {};
      for (const [ns, set] of claimSets) replaySets[ns] = set.stats();
      return Object.freeze({
        kind: 'memory',
        replaySets: Object.freeze(replaySets),
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
