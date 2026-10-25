/**
 * Archnemix server middleware (Express-compatible, also works with plain
 * node:http). Masters stay on disk OUTSIDE your static folder; this is the
 * only route that can read them, and it only ever returns a down-scaled,
 * tile-scrambled (optionally AES-GCM-encrypted) .archx payload behind a
 * short-lived HMAC-signed URL.
 *
 *   POST {basePath}/token/:id?w=1200  -> { url, key, aesKey?, grid, exp }
 *   GET  {basePath}/i/:id?t=...       -> application/octet-stream (.archx)
 *
 * Secure defaults are deny-by-default: startup fails unless the host supplies
 * an `authorize(req, id, { phase })` callback or explicitly sets
 * `allowAnonymous: true` for an intentionally public catalog. Authorization
 * runs again when the signed URL is redeemed, so revocation/session changes
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
import { stegoFingerprint as resolveStegoFingerprint } from '../src/scramble.js';

const ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/;
const TOKEN_AUDIENCE = 'archx:image';
const TOKEN_SCOPE = 'image:view';
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

  cleanup(now = Date.now()) {
    for (const [key, list] of this.#map) {
      const fresh = list.filter((t) => now - t < this.windowMs);
      if (fresh.length) this.#map.set(key, fresh);
      else this.#map.delete(key);
    }
    while (this.#map.size > this.maxClients) {
      this.#map.delete(this.#map.keys().next().value);
    }
  }

  hit(key, max, now = Date.now()) {
    if (!max || max <= 0) return { limited: false, retryAfterSec: 0, count: 0 };
    let list = (this.#map.get(key) || []).filter((t) => now - t < this.windowMs);
    if (list.length >= max) {
      this.#map.set(key, list);
      this.#bound();
      return {
        limited: true,
        retryAfterSec: Math.max(1, Math.ceil((this.windowMs - (now - list[0])) / 1000)),
        count: list.length,
      };
    }
    list.push(now);
    // Refresh LRU position before enforcing the bound.
    this.#map.delete(key);
    this.#map.set(key, list);
    this.#bound(now);
    return { limited: false, retryAfterSec: 0, count: list.length };
  }

  #bound(now = Date.now()) {
    if (this.#map.size <= this.maxClients) return;
    this.cleanup(now);
    while (this.#map.size > this.maxClients) {
      this.#map.delete(this.#map.keys().next().value);
    }
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

  constructor({ maxConcurrent = 2, maxQueue = 100, queueTimeoutMs = 5000 } = {}) {
    this.maxConcurrent = Math.max(1, maxConcurrent);
    this.maxQueue = Math.max(0, maxQueue);
    this.queueTimeoutMs = Math.max(0, queueTimeoutMs);
  }

  get active() { return this.#active; }
  get queued() { return this.#queue.length; }

  async run(fn) {
    if (this.#active >= this.maxConcurrent) {
      if (this.#queue.length >= this.maxQueue) {
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
      const next = this.#queue.shift();
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

  constructor({ windowMs = 600000, maxClients = 10000, maxIdsPerClient = 1000 } = {}) {
    this.windowMs = windowMs;
    this.maxClients = maxClients;
    this.maxIdsPerClient = maxIdsPerClient;
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


function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}
function signToken(payload, secret) {
  const body = b64url(JSON.stringify(payload));
  const mac = crypto.createHmac('sha256', secret).update(body).digest();
  return body + '.' + b64url(mac);
}
function verifyToken(token, secret) {
  if (!token || typeof token !== 'string' || token.length > 8192) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, mac] = parts;
  if (!/^[A-Za-z0-9_-]+$/.test(body) || !/^[A-Za-z0-9_-]+$/.test(mac)) return null;
  const expected = crypto.createHmac('sha256', secret).update(body).digest();
  const given = Buffer.from(mac, 'base64url');
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
    if (!Number.isFinite(payload.exp) || Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

/** Strict server-side claim validation for v2 Archx image tokens. Signature
 * verification alone is not enough: audience, scope, image, width, issued-at,
 * expiry window, and nonce shape are all checked before a token is spent. */
export function validateTokenClaims(payload, {
  id,
  maxWidthCap = 8192,
  maxTtlMs = 900000,
  now = Date.now(),
  clockSkewMs = 300000,
} = {}) {
  if (!payload || typeof payload !== 'object') return false;
  if (payload.v !== 2 || payload.aud !== TOKEN_AUDIENCE || payload.scope !== TOKEN_SCOPE) return false;
  if (!validateImageId(payload.id) || (id && payload.id !== id)) return false;
  if (!Number.isInteger(payload.w) || payload.w < 64 || payload.w > maxWidthCap) return false;
  if (!Number.isFinite(payload.iat) || !Number.isFinite(payload.exp)) return false;
  if (payload.iat > now + clockSkewMs || payload.exp <= payload.iat) return false;
  if (payload.exp - payload.iat > maxTtlMs + clockSkewMs || payload.exp <= now) return false;
  if (typeof payload.n !== 'string' || !/^[A-Za-z0-9_-]{8,86}$/.test(payload.n)) return false;
  if (payload.q != null && payload.q !== 'lossless' &&
      !(Number.isInteger(payload.q) && payload.q >= 1 && payload.q <= 100)) return false;
  if (payload.fmt != null && !['webp', 'png', 'jpeg'].includes(payload.fmt)) return false;
  return true;
}

function inspectServerConfig(options = {}) {
  const issues = [];
  const warnings = [];
  const fail = (msg) => issues.push(msg);
  const warn = (msg) => warnings.push(msg);
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    return { ok: false, issues: ['options must be an object'], warnings, config: null };
  }

  const secret = options.secret ?? process.env.ARCHX_SECRET;
  const secretBytes = Buffer.isBuffer(secret) ? secret.length : Buffer.byteLength(String(secret || ''), 'utf8');
  const secretText = Buffer.isBuffer(secret) ? '' : String(secret || '').toLowerCase();
  if (!secret) fail('secret is required (options.secret or ARCHX_SECRET)');
  else if (!options.allowWeakSecretForTests && (secretBytes < 32 || KNOWN_WEAK_SECRETS.has(secretText))) {
    fail('secret must be at least 32 bytes and not a known demo/test value');
  }
  if (options.allowWeakSecretForTests) warn('allowWeakSecretForTests is enabled; never use it in production');

  const authorize = options.authorize ?? null;
  if (authorize != null && typeof authorize !== 'function') fail('authorize must be a function');
  const allowAnonymous = options.allowAnonymous === true;
  if (!authorize && !allowAnonymous) {
    fail('authorize(req, id, { phase }) is required; set allowAnonymous:true only for an intentionally public catalog');
  }
  if (allowAnonymous && !authorize) warn('allowAnonymous is enabled: anyone who can reach the site can request authorized-size derivatives');

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
    if (!Number.isFinite(Number(value)) || Number(value) < min || Number(value) > max) fail(`${name} must be from ${min} to ${max}`);
  };

  const basePathRaw = options.basePath ?? '/archx';
  if (typeof basePathRaw !== 'string' || !basePathRaw.startsWith('/') || basePathRaw.includes('..') || basePathRaw.includes('\\')) {
    fail('basePath must be an absolute URL path without traversal');
  }
  checkInt('ttlSec', options.ttlSec, 5, 900);
  checkInt('grid', options.grid, 2, 32);
  checkInt('maxWidthCap', options.maxWidthCap, 64, 8192);
  if (options.quality != null && options.quality !== 'lossless') checkInt('quality', Number(options.quality), 1, 100);
  if (options.format != null && !['webp', 'png', 'jpeg'].includes(options.format)) fail("format must be 'webp', 'png', or 'jpeg'");
  if (options.scrambleKeyMode != null && !['per-image', 'per-token'].includes(options.scrambleKeyMode)) fail('scrambleKeyMode is invalid');
  checkInt('rateLimitPerMinute', options.rateLimitPerMinute, 1, 1000000);
  checkInt('tokenRateLimitPerMinute', options.tokenRateLimitPerMinute, 1, 1000000);
  checkInt('rateLimitMaxClients', options.rateLimitMaxClients, 10, 1000000);
  checkInt('maxTrackedClients', options.maxTrackedClients, 10, 1000000);
  checkInt('oneTimeTokenMaxEntries', options.oneTimeTokenMaxEntries, 100, 5000000);

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

  const processing = options.processing && typeof options.processing === 'object' ? options.processing : {};
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

  const quotas = options.quotas && typeof options.quotas === 'object' ? options.quotas : {};
  for (const name of ['perIp', 'perViewer', 'perIpImage', 'perViewerImage']) {
    if (quotas[name] != null) checkInt(`quotas.${name}`, quotas[name], 1, 100000000);
  }
  checkInt('quotas.windowMs', quotas.windowMs, 1000, 31 * 24 * 3600 * 1000);

  const abuse = options.abuseDetection && typeof options.abuseDetection === 'object' ? options.abuseDetection : {};
  checkInt('abuseDetection.distinctImages', abuse.distinctImages, 1, 1000000);
  checkInt('abuseDetection.windowMs', abuse.windowMs, 1000, 31 * 24 * 3600 * 1000);
  if (abuse.action != null && !['event', 'deny'].includes(abuse.action)) fail("abuseDetection.action must be 'event' or 'deny'");

  const availableParallelism = typeof os.availableParallelism === 'function' ? os.availableParallelism() : (os.cpus()?.length || 2);
  const config = Object.freeze({
    secret,
    authorize,
    allowAnonymous,
    basePath: String(basePathRaw).replace(/\/$/, '') || '/archx',
    ttlMs: (options.ttlSec ?? 120) * 1000,
    grid: options.grid ?? 8,
    maxWidthCap: options.maxWidthCap ?? 1920,
    tokenMethods: Object.freeze([...new Set((tokenMethodsRaw || ['POST']).map((m) => String(m).toUpperCase()))]),
    oneTimeTokens: options.oneTimeTokens ?? true,
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
    masterCacheMaxBytes: options.masterCacheMaxBytes ?? 128 * 1024 * 1024,
    cacheMasters: options.cacheMasters !== false,
    trustProxy: options.trustProxy === true,
    requireSameSiteTokenRequests: options.requireSameSiteTokenRequests !== false,
    stegoRegistryFailure: options.stegoRegistryFailure ?? 'deny',
    publicDirs: Object.freeze([
      ...(options.publicDir ? [options.publicDir] : []),
      ...(Array.isArray(options.publicDirs) ? options.publicDirs : []),
    ]),
  });
  if (!['deny', 'allow'].includes(config.stegoRegistryFailure)) fail("stegoRegistryFailure must be 'deny' or 'allow'");
  if (options.allowClientQuality) warn('allowClientQuality lets browsers request quality up to the server entitlement; keep authorize() caps strict');
  if (config.oneTimeTokens === false) warn('oneTimeTokens is disabled: signed URLs can be replayed until expiry');
  return { ok: issues.length === 0, issues, warnings, config: issues.length ? null : config };
}

/** Non-throwing production configuration audit. Never returns the secret. */
export function auditArchxServerConfig(options = {}) {
  const { ok, issues, warnings, config } = inspectServerConfig(options);
  return Object.freeze({
    ok,
    issues: Object.freeze([...issues]),
    warnings: Object.freeze([...warnings]),
    summary: config ? Object.freeze({
      basePath: config.basePath,
      authorization: config.authorize ? 'authorize-callback' : 'explicit-anonymous',
      tokenMethods: config.tokenMethods,
      oneTimeTokens: config.oneTimeTokens,
      maxWidthCap: config.maxWidthCap,
      processing: config.processing,
      processingConcurrency: config.processingConcurrency,
    }) : null,
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
  const secret = cfg.secret;
  const basePath = cfg.basePath;
  const ttlMs = cfg.ttlMs;
  const grid = cfg.grid;
  const maxWidthCap = cfg.maxWidthCap;
  const quality = options.quality ?? 95; // 'lossless' is also accepted
  const lossless = !!options.lossless;
  const format = options.format ?? 'webp'; // 'webp' | 'png' | 'jpeg'
  const scrambleKeyMode = options.scrambleKeyMode || 'per-image'; // | 'per-token'
  const encrypt = !!options.encrypt;
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
  const forensicPerToken = options.forensicPerToken ?? true;
  const allowClientQuality = !!options.allowClientQuality;
  const steganography = options.steganography ?? false;
  const stegoGlobalCfg = typeof steganography === 'object' && steganography ? steganography : {};
  const onStegoIssue = options.onStegoIssue || null;
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

  function resolveIndexedFile(id) {
    const entry = index.get(id);
    if (!entry) return null;
    let real;
    try { real = fs.realpathSync(entry.filePath); } catch { return null; }
    if (entry.root && !isPathInside(entry.root, real)) return null;
    let stat;
    try { stat = fs.statSync(real); } catch { return null; }
    if (!stat.isFile()) return null;
    return { filePath: real, stat };
  }

  // per-image scramble key + aes key derivation (stable => output cacheable)
  const deriveScrambleKey = (id, nonce) =>
    scrambleKeyMode === 'per-token'
      ? nonce
      : crypto.createHmac('sha256', secret).update('scramble:' + id).digest('hex').slice(0, 32);
  const deriveAesKey = (id, nonce) =>
    crypto.createHmac('sha256', secret)
      .update('aes:' + id + ':' + (scrambleKeyMode === 'per-token' ? nonce : 'static'))
      .digest().toString('base64');

  const masterCache = new Map(); // id -> {mtimeMs,size,bytes}; byte-bounded LRU
  let masterCacheBytes = 0;
  const dimensionCache = new Map(); // id -> {mtimeMs,size,width,height}
  const outputCache = new Map(); // cacheKey -> Buffer; entry- and byte-bounded LRU
  let outputCacheBytes = 0;
  const rateLimiter = new SlidingWindowLimiter({
    windowMs: 60000,
    maxClients: cfg.rateLimitMaxClients,
  });
  const quotaLimiter = new SlidingWindowLimiter({
    windowMs: cfg.quotas.windowMs,
    maxClients: cfg.rateLimitMaxClients,
  });
  const consumedNonces = new BoundedTtlSet({ maxEntries: cfg.oneTimeTokenMaxEntries });
  const distinctTracker = new DistinctAccessTracker({
    windowMs: cfg.abuseDetection.windowMs,
    maxClients: cfg.rateLimitMaxClients,
  });
  const processingSemaphore = new AsyncSemaphore({
    maxConcurrent: cfg.processingConcurrency,
    maxQueue: cfg.processingQueueMax,
    queueTimeoutMs: cfg.processingQueueTimeoutMs,
  });

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
    while (masterCacheBytes > cfg.masterCacheMaxBytes && masterCache.size > 1) {
      const oldestKey = masterCache.keys().next().value;
      masterCacheBytes -= masterCache.get(oldestKey).bytes.length;
      masterCache.delete(oldestKey);
    }
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

  const requestIp = (req) => {
    if (cfg.trustProxy) {
      const forwarded = req.headers?.['x-forwarded-for'];
      const first = Array.isArray(forwarded) ? forwarded[0] : String(forwarded || '').split(',')[0].trim();
      if (first) return first.slice(0, 128);
    }
    return String(req.ip || req.socket?.remoteAddress || 'unknown').slice(0, 128);
  };
  const hmacShort = (label, value, len = 24) =>
    crypto.createHmac('sha256', secret).update(label + ':' + String(value)).digest('base64url').slice(0, len);
  const safeEqual = (a, b) => {
    const ba = Buffer.from(String(a)); const bb = Buffer.from(String(b));
    return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
  };

  function emitSecurityEvent(type, req, details = {}) {
    if (!onSecurityEvent) return;
    const event = Object.freeze({
      type,
      at: new Date().toISOString(),
      id: details.id || null,
      phase: details.phase || null,
      status: details.status || null,
      ip: req ? requestIp(req) : null,
      viewerId: details.viewerId || null,
      reason: details.reason || null,
    });
    try {
      const result = onSecurityEvent(event);
      if (result && typeof result.catch === 'function') result.catch(() => {});
    } catch { /* monitoring must never alter authorization */ }
  }

  function authorizationViewerId(auth) {
    if (!auth || typeof auth !== 'object') return '';
    return String(auth.viewerId || auth.userId || auth.subject || auth.sessionId || '').slice(0, 256);
  }

  function authorizationAllows(auth) {
    if (auth === true) return true;
    if (!auth || typeof auth !== 'object' || auth.allow === false) return false;
    const scopes = Array.isArray(auth.permissions) ? auth.permissions
      : Array.isArray(auth.scopes) ? auth.scopes
      : typeof auth.scope === 'string' ? auth.scope.split(/[\s,]+/).filter(Boolean)
      : null;
    if (scopes && !scopes.some((s) => ['image:view', 'archx:image:view', '*'].includes(String(s)))) return false;
    return true;
  }

  async function authorizeRequest(req, id, phase, token = null) {
    if (!authorize) return cfg.allowAnonymous ? {} : null;
    let auth;
    try { auth = await authorize(req, id, { phase, token }); }
    catch { return null; }
    if (!authorizationAllows(auth)) return null;
    return typeof auth === 'object' ? auth : {};
  }

  async function imageDimensions(id) {
    const resolved = resolveIndexedFile(id);
    if (!resolved) return null;
    const { filePath, stat } = resolved;
    if (stat.size > cfg.processing.maxInputBytes) return null;
    const cacheKey = `${stat.mtimeMs}:${stat.size}`;
    const cached = dimensionCache.get(id);
    if (cached && cached.version === cacheKey) return cached;
    const sharp = (await import('sharp')).default;
    const meta = await sharp(filePath, {
      failOn: 'warning',
      limitInputPixels: cfg.processing.maxInputPixels,
      sequentialRead: true,
    }).timeout({ seconds: cfg.processing.timeoutSec }).metadata();
    if (!meta.width || !meta.height || !cfg.processing.allowedInputFormats.includes(meta.format)) return null;
    if (meta.width > cfg.processing.maxInputWidth || meta.height > cfg.processing.maxInputHeight) return null;
    if ((meta.pages || 1) > 1) return null;
    const rotated = meta.orientation >= 5 && meta.orientation <= 8;
    const dims = {
      version: cacheKey,
      mtimeMs: stat.mtimeMs,
      size: stat.size,
      width: rotated ? meta.height : meta.width,
      height: rotated ? meta.width : meta.height,
    };
    dimensionCache.set(id, dims);
    return dims;
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
    if (!site || site === 'same-origin' || site === 'same-site' || site === 'none') return true;
    // A configured exact cross-origin integration may still mint tokens; an
    // arbitrary cross-site page may not use a victim browser as a confused deputy.
    return !!(allowedOrigins?.length && originAllowed(req));
  }

  function corsHeaders(req) {
    if (!allowedOrigins?.length) return {};
    const origin = requestOrigin(req);
    if (!origin || !allowedOrigins.includes(origin)) return {};
    return {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Credentials': 'true',
      'Vary': 'Origin',
    };
  }

  function quotaExceeded(req, id, viewerId, phase) {
    const ip = requestIp(req);
    const checks = [];
    if (phase === 'token') {
      checks.push([`ip:${ip}`, cfg.quotas.perIp, 'perIp']);
      checks.push([`ip-image:${ip}:${id}`, cfg.quotas.perIpImage, 'perIpImage']);
      if (viewerId) {
        checks.push([`viewer:${hmacShort('quota-viewer', viewerId, 24)}`, cfg.quotas.perViewer, 'perViewer']);
        checks.push([`viewer-image:${hmacShort('quota-viewer', viewerId, 24)}:${id}`, cfg.quotas.perViewerImage, 'perViewerImage']);
      }
    } else if (!oneTimeTokens) {
      // With replayable tokens, count redemptions too. With one-time tokens
      // the token-phase quota already corresponds to at most one download.
      checks.push([`redeem-ip-image:${ip}:${id}`, cfg.quotas.perIpImage, 'perIpImage']);
      if (viewerId) checks.push([`redeem-viewer-image:${hmacShort('quota-viewer', viewerId, 24)}:${id}`, cfg.quotas.perViewerImage, 'perViewerImage']);
    }
    let retryAfterSec = 0;
    let exceeded = null;
    for (const [key, max, name] of checks) {
      if (!max) continue;
      const result = quotaLimiter.hit(key, max);
      if (result.limited) {
        exceeded = name;
        retryAfterSec = Math.max(retryAfterSec, result.retryAfterSec);
      }
    }
    return exceeded ? { name: exceeded, retryAfterSec } : null;
  }

  function abusePattern(req, id, viewerId) {
    const threshold = cfg.abuseDetection.distinctImages;
    if (!threshold) return { suspicious: false, distinct: 0 };
    const keys = [`ip:${requestIp(req)}`];
    if (viewerId) keys.push(`viewer:${hmacShort('quota-viewer', viewerId, 24)}`);
    let distinct = 0;
    let crossed = false;
    for (const key of keys) {
      const result = distinctTracker.hit(key, id);
      distinct = Math.max(distinct, result.distinct);
      // Emit once at the crossing edge; a deny policy continues to deny above it.
      if (result.isNew && result.distinct === threshold + 1) crossed = true;
    }
    return { suspicious: distinct > threshold, crossed, distinct };
  }

  function fillPlaceholders(text, ctx) {
    return String(text)
      .replaceAll('{id}', ctx.id)
      .replaceAll('{nonce}', String(ctx.nonce).slice(0, 6))
      .replaceAll('{viewer}', ctx.viewerId ? String(ctx.viewerId) : String(ctx.nonce).slice(0, 6));
  }

  async function resolveWatermark(source, ctx) {
    if (source == null) return null;
    let wm = typeof source === 'function' ? await source(ctx) : source;
    if (wm == null) return null;
    if (typeof wm === 'string') return fillPlaceholders(wm, ctx);
    if (typeof wm === 'object') return { ...wm, text: wm.text ? fillPlaceholders(wm.text, ctx) : wm.text };
    return null;
  }

  function rateLimited(req, kind = 'i') {
    const max = kind === 'token' ? tokenRateMax : rateMax;
    return rateLimiter.hit(kind + ':' + requestIp(req), max);
  }

  function protectedHeaders(req, extra = {}) {
    return {
      'Cache-Control': 'private, no-store, no-cache, must-revalidate, max-age=0',
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
      if (parts.length !== 2) return sendJson(req, res, 404, { error: 'not found' });
      const [kind, rawId] = parts;
      if (!['token', 'i'].includes(kind)) return sendJson(req, res, 404, { error: 'not found' });
      phase = kind === 'token' ? 'token' : 'image';
      // Count malformed/unknown-ID attempts too. Otherwise the cheapest
      // enumeration/flood path would bypass every request budget simply by
      // never naming a real image. CORS preflight is the one exemption: it
      // carries no entitlement and is followed by the rate-limited token call.
      if (!(kind === 'token' && req.method === 'OPTIONS')) {
        const rate = rateLimited(req, kind);
        if (rate.limited) {
          return deny(req, res, 429, 'too many requests', {
            phase, reason: 'rate-limit', headers: { 'Retry-After': String(rate.retryAfterSec || 60) },
          });
        }
      }
      let id;
      try { id = decodeURIComponent(rawId || ''); }
      catch { return deny(req, res, 400, 'bad request', { phase, reason: 'bad-id-encoding' }); }
      routeId = validateImageId(id) ? id : null;
      if (!validateImageId(id) || !index.has(id)) {
        return deny(req, res, 404, 'not found', { id: routeId, phase, reason: 'unknown-or-invalid-id' });
      }

      if (kind === 'token' && req.method === 'OPTIONS') {
        if (!allowedOrigins?.length || !originAllowed(req)) {
          return deny(req, res, 403, 'forbidden', { id, phase, reason: 'cors-origin' });
        }
        res.writeHead(204, {
          ...protectedHeaders(req),
          'Access-Control-Allow-Methods': 'POST, GET, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, X-Archx-Request',
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

      if (kind === 'token') {
        const entitlement = await authorizeRequest(req, id, 'token');
        if (!entitlement) return deny(req, res, 403, 'forbidden', { id, phase, reason: 'authorization' });
        const viewerId = authorizationViewerId(entitlement);
        const quota = quotaExceeded(req, id, viewerId, 'token');
        if (quota) {
          return deny(req, res, 429, 'quota exceeded', {
            id, phase, viewerId, reason: `quota:${quota.name}`,
            headers: { 'Retry-After': String(quota.retryAfterSec || 60) },
          });
        }
        const abuse = abusePattern(req, id, viewerId);
        if (abuse.crossed) {
          emitSecurityEvent('archx.suspicious_scraping', req, {
            id, phase, viewerId, status: 200, reason: `distinct-images:${abuse.distinct}`,
          });
        }
        if (abuse.suspicious && cfg.abuseDetection.action === 'deny') {
          return deny(req, res, 429, 'too many requests', {
            id, phase, viewerId, reason: 'distinct-image-abuse', headers: { 'Retry-After': '600' },
          });
        }
        // The BROWSER asks for a width; the SERVER's entitlement caps it.
        // A tampered client can no longer "just ask for 1920px" beyond policy.
        const entitlementWidth = entitlement.maxWidth == null ? maxWidthCap : Number(entitlement.maxWidth);
        if (!Number.isFinite(entitlementWidth) || entitlementWidth < 64) {
          return deny(req, res, 403, 'forbidden', { id, phase, viewerId, reason: 'invalid-entitlement-width' });
        }
        const widthCap = Math.min(maxWidthCap, Math.floor(entitlementWidth));
        const rawRequested = url.searchParams.get('w') || url.searchParams.get('bw') || '1200';
        let requestedW = parseStrictInt(rawRequested);
        const boxW = url.searchParams.has('bw') ? parseStrictInt(url.searchParams.get('bw')) : null;
        const boxH = url.searchParams.has('bh') ? parseStrictInt(url.searchParams.get('bh')) : null;
        const rawFit = String(url.searchParams.get('fit') || 'cover').toLowerCase();
        if (requestedW == null || requestedW < 1 || requestedW > 100000 ||
            (url.searchParams.has('bw') && (boxW == null || boxW < 1 || boxW > 100000)) ||
            (url.searchParams.has('bh') && (boxH == null || boxH < 1 || boxH > 100000)) ||
            !['cover', 'contain', 'fill'].includes(rawFit)) {
          return deny(req, res, 400, 'bad request', { id, phase, viewerId, reason: 'bad-sizing' });
        }
        if (boxW > 0 && boxH > 0) {
          try {
            const dims = await imageDimensions(id);
            if (dims) {
              const aspect = dims.width / dims.height;
              const fit = String(url.searchParams.get('fit') || 'cover').toLowerCase();
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
        const w = Math.max(64, Math.min(widthCap, Math.ceil(requestedW)));
        const nonce = crypto.randomBytes(18).toString('base64url');
        const iat = Date.now();
        const exp = iat + ttlMs;
        const watermark = await resolveWatermark(
          entitlement.watermark ?? serverWatermark,
          { req, id, nonce, viewerId, exp },
        );
        const tokenPayload = {
          v: 2,
          aud: TOKEN_AUDIENCE,
          scope: TOKEN_SCOPE,
          id, w, iat, exp, n: nonce,
        };
        const viewerHash = viewerId ? hmacShort('viewer', viewerId, 20) : '';
        if (viewerId) tokenPayload.vh = viewerHash;
        if (watermark) tokenPayload.wm = watermark;

        // Direct delivery-quality control. Your authorize() entitlement wins;
        // the browser's q=… request is honoured only when you opt in.
        const clientQuality = allowClientQuality ? url.searchParams.get('q') : null;
        const rawQuality = entitlement.quality ?? clientQuality ?? quality;
        let deliveryLossless = entitlement.lossless ?? (lossless || rawQuality === 'lossless');
        let deliveryQuality = deliveryLossless
          ? 'lossless'
          : Math.max(1, Math.min(100, Math.round(Number(rawQuality) || 95)));
        const rawFormat = entitlement.format || format;
        const deliveryFormat = ['webp', 'png', 'jpeg'].includes(rawFormat) ? rawFormat : 'webp';
        tokenPayload.q = deliveryQuality;
        if (deliveryLossless) tokenPayload.ls = 1;
        if (deliveryFormat !== format) tokenPayload.fmt = deliveryFormat;

        // StegoMark issuance: derive (but do not expose) the fingerprint that
        // will be baked into this view's pixels, and let the host persist the
        // fingerprint -> image/viewer/order mapping via onStegoIssue.
        const effectiveStego = entitlement.steganography ?? steganography;
        if (effectiveStego) {
          const entStegoCfg = typeof effectiveStego === 'object' ? effectiveStego : {};
          const stegoPerToken = entStegoCfg.perToken ?? stegoGlobalCfg.perToken ?? true;
          let issuedFingerprint;
          if (entitlement.stegoFingerprint) {
            tokenPayload.sg = String(entitlement.stegoFingerprint);
            issuedFingerprint = resolveStegoFingerprint(entitlement.stegoFingerprint);
          } else {
            if (!stegoPerToken) tokenPayload.sgp = 0;
            issuedFingerprint = deriveStegoFingerprint({
              id, nonce, viewerHash, secret, perToken: stegoPerToken,
            });
          }
          const strength = entStegoCfg.strength ?? stegoGlobalCfg.strength;
          if (strength != null) {
            const numericStrength = Number(strength);
            if (!Number.isFinite(numericStrength)) {
              return deny(req, res, 503, 'service unavailable', { id, phase, viewerId, reason: 'invalid-stego-config' });
            }
            tokenPayload.sgs = Math.max(1, Math.min(16, numericStrength));
          }
          if (onStegoIssue) {
            try {
              await onStegoIssue({ req, id, viewerId, nonce, exp, fingerprint: issuedFingerprint });
            } catch {
              emitSecurityEvent('archx.stego_registry_failed', req, { id, phase, viewerId, status: 503 });
              if (cfg.stegoRegistryFailure !== 'allow') {
                return sendJson(req, res, 503, { error: 'service unavailable' });
              }
            }
          }
        } else if (steganography) {
          tokenPayload.nsg = 1; // entitlement explicitly opted this view out
        }
        if (bindTokenTo.session && !viewerId) {
          return deny(req, res, 403, 'forbidden', { id, phase, reason: 'session-binding-unavailable' });
        }
        const bindings = {};
        if (bindTokenTo.ip) bindings.ip = hmacShort('bind-ip', requestIp(req));
        if (bindTokenTo.userAgent) bindings.ua = hmacShort('bind-ua', req.headers?.['user-agent'] || '');
        if (bindTokenTo.session) bindings.sess = hmacShort('bind-session', viewerId);
        if (Object.keys(bindings).length) tokenPayload.b = bindings;
        const token = signToken(tokenPayload, secret);
        const out = {
          url: `${basePath}/i/${encodeURIComponent(id)}?t=${token}`,
          key: deriveScrambleKey(id, nonce),
          grid,
          exp,
        };
        if (encrypt) out.aesKey = deriveAesKey(id, nonce);
        return sendJson(req, res, 200, out);
      }

      if (kind === 'i') {
        const tokenValues = url.searchParams.getAll('t');
        if (tokenValues.length !== 1) {
          return deny(req, res, 403, 'invalid or expired token', { id, phase, reason: 'token-count' });
        }
        const payload = verifyToken(tokenValues[0], secret);
        if (!validateTokenClaims(payload, { id, maxWidthCap, maxTtlMs: ttlMs })) {
          return deny(req, res, 403, 'invalid or expired token', { id, phase, reason: 'token-claims' });
        }
        // Optional IP/User-Agent binding is a replay friction layer only;
        // headers are spoofable and are never treated as authentication.
        if (payload.b?.ip && !safeEqual(payload.b.ip, hmacShort('bind-ip', requestIp(req)))) {
          return deny(req, res, 403, 'invalid or expired token', { id, phase, reason: 'ip-binding' });
        }
        if (payload.b?.ua && !safeEqual(payload.b.ua, hmacShort('bind-ua', req.headers?.['user-agent'] || ''))) {
          return deny(req, res, 403, 'invalid or expired token', { id, phase, reason: 'ua-binding' });
        }
        // Claim synchronously BEFORE the first await below. Parallel requests
        // with the same signed URL therefore cannot both pass one-time use.
        if (oneTimeTokens) {
          const nonceHash = hmacShort('once', id + ':' + payload.n, 32);
          if (!consumedNonces.claim(nonceHash, payload.exp)) {
            return deny(req, res, 403, 'invalid or expired token', { id, phase, reason: 'token-replay' });
          }
        }

        // Re-authorize redemption. A still-unexpired token must not survive
        // logout, entitlement revocation, or transfer to another viewer.
        const entitlement = await authorizeRequest(req, id, 'image', payload);
        if (!entitlement) return deny(req, res, 403, 'forbidden', { id, phase, reason: 'authorization' });
        const currentViewerId = authorizationViewerId(entitlement);
        if (payload.vh) {
          const currentViewerHash = currentViewerId ? hmacShort('viewer', currentViewerId, 20) : '';
          if (!currentViewerHash || !safeEqual(payload.vh, currentViewerHash)) {
            return deny(req, res, 403, 'invalid or expired token', { id, phase, reason: 'viewer-binding' });
          }
        }
        if (payload.b?.sess) {
          const currentSessionHash = currentViewerId ? hmacShort('bind-session', currentViewerId) : '';
          if (!currentSessionHash || !safeEqual(payload.b.sess, currentSessionHash)) {
            return deny(req, res, 403, 'invalid or expired token', { id, phase, reason: 'session-binding' });
          }
        }
        const imageQuota = quotaExceeded(req, id, currentViewerId, 'image');
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
        let effectiveFormat = ['webp', 'png', 'jpeg'].includes(payload.fmt) ? payload.fmt : format;
        if (entitlement.format != null) {
          if (!['webp', 'png', 'jpeg'].includes(entitlement.format)) {
            return deny(req, res, 403, 'forbidden', { id, phase, viewerId: currentViewerId, reason: 'invalid-entitlement-format' });
          }
          effectiveFormat = entitlement.format;
        }

        const scrambleKey = deriveScrambleKey(id, payload.n);
        const forensicSeed = forensic
          ? hmacShort('forensic', forensicPerToken
              ? `${id}:${payload.n}:${payload.vh || ''}`
              : `${id}:static:${payload.vh || ''}`, 32)
          : null;
        const deliveryQuality = effectiveQuality;
        const deliveryLossless = effectiveLossless;
        const deliveryFormat = effectiveFormat;
        const resolvedMaster = resolveIndexedFile(id);
        if (!resolvedMaster) return deny(req, res, 404, 'not found', { id, phase, reason: 'master-missing' });
        if (resolvedMaster.stat.size > cfg.processing.maxInputBytes) {
          return deny(req, res, 413, 'image too large', { id, phase, reason: 'master-too-large' });
        }
        const masterVersion = `${resolvedMaster.stat.mtimeMs}:${resolvedMaster.stat.size}`;
        const stegoEnabled = !!steganography && payload.nsg !== 1;
        const stegoPayload = stegoEnabled
          ? (payload.sg || deriveStegoFingerprint({
              id,
              nonce: payload.n,
              viewerHash: payload.vh || '',
              secret,
              perToken: payload.sgp !== 0,
            }))
          : null;
        const wmCachePart = payload.wm ? hmacShort('wm', JSON.stringify(payload.wm), 12) : 'nowm';
        const stegoCachePart = stegoPayload ? hmacShort('sg', stegoPayload, 12) : 'nosg';
        const cacheKey = [
          id, masterVersion, effectiveWidth,
          scrambleKeyMode === 'per-token' ? payload.n : 's',
          encrypt ? 'e' : 'p', wmCachePart,
          forensicSeed ? (forensicPerToken ? payload.n : 'fx') : 'nofx',
          payload.vh || '',
          `q${deliveryQuality}`, deliveryLossless ? 'ls' : 'lq', deliveryFormat, stegoCachePart,
        ].join('|');
        let bytes = getOutputCache(cacheKey);
        if (!bytes) {
          const { filePath, stat } = resolvedMaster;
          let master = cacheTouch(masterCache, id);
          if (!master || master.mtimeMs !== stat.mtimeMs || master.size !== stat.size) {
            if (master) {
              masterCacheBytes -= master.bytes.length;
              masterCache.delete(id);
            }
            master = { mtimeMs: stat.mtimeMs, size: stat.size, bytes: fs.readFileSync(filePath) };
            setMasterCache(id, master);
          }
          // Lazy import so token-only deployments don't need sharp wired early.
          const { scrambleImage } = await import('./scramble-image.js');
          const result = await processingSemaphore.run(() => scrambleImage(master.bytes, {
            grid,
            key: scrambleKey,
            maxWidth: Math.min(maxWidthCap, effectiveWidth),
            quality: deliveryQuality,
            lossless: deliveryLossless,
            format: deliveryFormat,
            aesKey: encrypt ? deriveAesKey(id, payload.n) : null,
            watermark: payload.wm || null,
            forensicSeed,
            forensic: typeof forensic === 'object' ? forensic : {},
            stegoPayload,
            stegoKey: stegoPayload ? deriveStegoKey(id, secret) : null,
            stegoStrength: payload.sgs ?? stegoGlobalCfg.strength ?? 6,
            steganography: stegoPayload ? stegoGlobalCfg : null,
            processing: cfg.processing,
            maxInputBytes: cfg.processing.maxInputBytes,
            maxInputPixels: cfg.processing.maxInputPixels,
            maxInputWidth: cfg.processing.maxInputWidth,
            maxInputHeight: cfg.processing.maxInputHeight,
            maxOutputPixels: cfg.processing.maxOutputPixels,
            processingTimeoutSec: cfg.processing.timeoutSec,
            allowedInputFormats: cfg.processing.allowedInputFormats,
          }));
          bytes = result.bytes;
          setOutputCache(cacheKey, bytes);
        }
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Content-Length': bytes.length,
          'Content-Disposition': 'inline; filename="data.bin"',
          'Content-Security-Policy': "default-src 'none'; sandbox",
          ...protectedHeaders(req),
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
        emitSecurityEvent('archx.processing_error', req, { id: routeId, phase, status: 500, reason: err?.code || 'internal' });
        return sendJson(req, res, 500, { error: 'image processing failed' });
      }
      try { res.end(); } catch { /* response already closing */ }
      return undefined;
    }
  }

  handler.index = index;
  handler.configAudit = auditArchxServerConfig(options);
  handler.stats = () => Object.freeze({
    images: index.size,
    rateLimitClients: rateLimiter.size,
    quotaClients: quotaLimiter.size,
    consumedTokens: consumedNonces.size,
    outputCacheEntries: outputCache.size,
    outputCacheBytes,
    masterCacheEntries: masterCache.size,
    masterCacheBytes,
    processingActive: processingSemaphore.active,
    processingQueued: processingSemaphore.queued,
  });
  handler.close = () => {
    rateLimiter.close();
    quotaLimiter.close();
    consumedNonces.close();
    distinctTracker.close();
    masterCache.clear(); masterCacheBytes = 0;
    outputCache.clear(); outputCacheBytes = 0;
    dimensionCache.clear();
  };
  handler._test = { signToken, verifyToken, validateTokenClaims, SlidingWindowLimiter, BoundedTtlSet, AsyncSemaphore };
  return handler;
}

export { signToken, verifyToken };
export default createArchxMiddleware;
