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
import { isIP } from 'node:net';
import {
  stegoFingerprint as resolveStegoFingerprint,
  sniffImageInfo,
  isArchxContainer,
  decodeContainer,
} from '../src/scramble.js';
import {
  scrambleImage, unscrambleImage, inspectImageMetadata,
  prepareDerivativeBase, finishDerivative,
  configureSharpSecurity, configureSharpPerformance, generateKeyBase64,
  acquireSharpSecurityLease, ensureUntrustedSharpLoadersBlocked,
  detectStegoFingerprintInWorker, closeStegoDetectWorker,
  batchDetectStegoInWorker, configureStegoDetectWorker,
} from './scramble-image.js';
import {
  generateOwnershipKeyPair, signOwnershipClaim, verifyOwnershipClaim,
  parseOwnershipClaim, extractOwnershipClaim, extractOwnershipClaims,
  embedOwnershipMetadata, verifyOwnership, ownershipPublicKeyFingerprint,
  loadOwnershipPrivateKey, loadOwnershipPublicKey,
} from './ownership.js';
import { AsyncSemaphore, BoundedTtlSet, createMemoryStateStore } from './bounded.js';
import { FORMAT_EXTENSIONS, TAINT_PNG, auditArchxServerConfig, canonicalDerivativeWidth, isPathInside, isPlainObject, normalizeAuthorizationResult, normalizeServerConfig, parseStrictInt, pathsOverlap, validateImageId, validateWatermarkValue } from './config.js';
import { TOKEN_AUDIENCE, TOKEN_SCOPE, deriveStegoFingerprint, deriveStegoKey, normalizeBindTokenTo, parseProofPublicKeyHeader, signToken, validateTokenClaims, verifyProofOfPossession, verifyToken } from './tokens.js';

export { AsyncSemaphore, BoundedTtlSet, SlidingWindowLimiter, createMemoryStateStore } from './bounded.js';
export { DEFAULT_WIDTH_BUCKETS, auditArchxProductionConfig, auditArchxServerConfig, canonicalDerivativeWidth, normalizeAuthorizationResult, validateImageId, validateWatermarkValue, withCatalogThroughputDefaults, withHardenedProductionDefaults, withPerformanceDefaults, withMaxProtectionDefaults } from './config.js';
export { computeJwkThumbprint, deriveStegoFingerprint, deriveStegoKey, validateTokenClaims } from './tokens.js';
export {
  scrambleImage, unscrambleImage, inspectImageMetadata,
  prepareDerivativeBase, finishDerivative,
  configureSharpSecurity, configureSharpPerformance, generateKeyBase64,
  acquireSharpSecurityLease, ensureUntrustedSharpLoadersBlocked,
  detectStegoFingerprintInWorker, closeStegoDetectWorker,
  batchDetectStegoInWorker, configureStegoDetectWorker,
};
export {
  generateOwnershipKeyPair, signOwnershipClaim, verifyOwnershipClaim,
  parseOwnershipClaim, extractOwnershipClaim, extractOwnershipClaims,
  embedOwnershipMetadata, verifyOwnership, ownershipPublicKeyFingerprint,
  loadOwnershipPrivateKey, loadOwnershipPublicKey,
};
export { createIssuanceLog, verifyIssuanceChain } from './issuance-log.js';

export function createArchxMiddleware(options = {}) {
  const cfg = normalizeServerConfig(options);
  // Scoped libvips loader policy for this instance's lifetime; released
  // by handler.close() so a strict temporary handler cannot narrow
  // loaders for the whole process forever.
  const releaseSharpSecurity = cfg.processing.blockUntrustedSharpLoaders
    ? acquireSharpSecurityLease(cfg.processing.allowedInputFormats)
    : null;
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
  const bindTokenTo = normalizeBindTokenTo(options.bindTokenTo); // { ip?:boolean, userAgent?:boolean, session?:boolean }
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

  // Per-image keys are scoped to the DERIVATIVE VARIANT pinned in the
  // signed token claims (w/q/fmt): a key minted for a 160px/q45 free
  // preview must never open a captured 1408px lossless payload of the
  // same image (pre-1.15 keys were image-global, so any tier's key
  // opened every tier's bytes). Both phases already pin w/q/fmt in the
  // claims, so no new claim field is needed; the output cache key
  // carries the same scope, so an entitlement that narrows a
  // redemption can never cross-serve bytes encrypted under a wider
  // scope's key. Tokens minted before this change still redeem (the
  // payload fetch succeeds) but their legacy keys will not unscramble
  // post-upgrade derivatives — a one-TTL migration window.
  // Per-image keys are scoped to everything that changes the delivered
  // bytes: variant (w/q/fmt, since 1.15) plus digests of the visible
  // watermark, forensic seed, and stego fingerprint (since 1.17). A
  // key minted for a watermarked preview therefore cannot open the
  // unwatermarked container of the same w:q:fmt even if its ciphertext
  // is obtained — tier isolation holds by construction, not by
  // transport control. All inputs come from signed claims (or values
  // deterministically derived from them) at redemption, and from the
  // identical derivations over the about-to-be-signed payload at mint.
  const ownershipScopeDigests = new Map(); // per issuing-secret (kid rotation safe)
  const ownershipScopeDigest = (keySecret) => {
    if (!cfg.ownership) return null;
    let digest = ownershipScopeDigests.get(keySecret);
    if (!digest) {
      digest = hmacShort('own', JSON.stringify([cfg.ownership.owner, cfg.ownership.copyright, cfg.ownership.artist, cfg.ownership.publicKeyFingerprint]), 12, keySecret);
      ownershipScopeDigests.set(keySecret, digest);
    }
    return digest;
  };
  const variantKeyScope = ({ w, q, fmt, wm, forensicSeed, stegoPayload }, keySecret) => {
    const wmPart = wm ? hmacShort('wm', JSON.stringify(wm), 12, keySecret) : '0';
    const fxPart = forensicSeed ? hmacShort('fxs', forensicSeed, 12, keySecret) : '0';
    const sgPart = stegoPayload ? hmacShort('sg', stegoPayload, 12, keySecret) : '0';
    const ownPart = ownershipScopeDigest(keySecret) ? `:own${ownershipScopeDigest(keySecret)}` : '';
    return `w${w}:q${q}:f${fmt}:wm${wmPart}:fx${fxPart}:sg${sgPart}${ownPart}`;
  };
  const computeForensicSeed = (imageId, payloadLike, keySecret) => (forensic
    ? hmacShort('forensic', forensicScope === 'image'
      ? `${imageId}:image`
      : forensicPerToken
        ? `${imageId}:${payloadLike.n}:${payloadLike.th || payloadLike.vh || ''}`
        : `${imageId}:static:${payloadLike.th || payloadLike.vh || ''}`, 32, keySecret)
    : null);
  const deriveScrambleKey = (id, nonce, keySecret = secret, keyScope = 'legacy') =>
    scrambleKeyMode === 'per-token'
      ? nonce
      : crypto.createHmac('sha256', keySecret).update(`scramble:${id}:${keyScope}`).digest('hex').slice(0, 32);
  const deriveAesKey = (id, nonce, keySecret = secret, keyScope = 'legacy') =>
    crypto.createHmac('sha256', keySecret)
      .update('aes:' + id + ':' + (scrambleKeyMode === 'per-token' ? nonce : keyScope))
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
  // Live-eviction telemetry for the built-in store: if the one-time
  // replay store ever evicts an unexpired JTI (mint rate x TTL exceeds
  // capacity), say so loudly (throttled) instead of silently reopening
  // a replay window. External stores own their eviction semantics.
  let lastEvictEventAt = 0;
  let pendingEvictions = 0;
  const noteLiveEviction = (count) => {
    pendingEvictions += count;
    const now = Date.now();
    if (now - lastEvictEventAt >= 60000) {
      lastEvictEventAt = now;
      const evicted = pendingEvictions;
      pendingEvictions = 0;
      emitSecurityEvent('archx.replay_store_evicted', null, {
        phase: 'state-store', status: 503,
        reason: `live-jti-evicted:${evicted}`,
      });
    }
  };
  const stateStore = cfg.stateStore || createMemoryStateStore({
    maxClients: cfg.rateLimitMaxClients,
    maxEntries: cfg.oneTimeTokenMaxEntries,
    maxCacheEntries: cfg.outputCacheMax,
    maxCacheBytes: cfg.outputCacheMaxBytes,
    onLiveEvict: noteLiveEviction,
    saturation: cfg.replaySaturation === 'strict' ? 'strict' : 'evict',
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
  const baseInFlight = new Map(); // baseKey -> Promise<base> (singleflight stage-1)

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
      let addr = String(ip || '').toLowerCase();
      const pct = addr.indexOf('%');
      if (pct !== -1) addr = addr.slice(0, pct); // zone id (validated in canonicalIp)
      const v4Tail = addr.match(/(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
      if (v4Tail) {
        const octets = [Number(v4Tail[1]), Number(v4Tail[2]), Number(v4Tail[3]), Number(v4Tail[4])];
        if (octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return null;
        const hi = ((octets[0] << 8) | octets[1]).toString(16);
        const lo = ((octets[2] << 8) | octets[3]).toString(16);
        addr = addr.slice(0, addr.length - v4Tail[0].length) + hi + ':' + lo;
      }
      const halves = addr.split('::');
      if (halves.length > 2) return null;
      const head = halves[0] ? halves[0].split(':').filter(Boolean) : [];
      const tail = halves.length === 2 && halves[1] ? halves[1].split(':').filter(Boolean) : [];
      const missing = 8 - head.length - tail.length;
      if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;
      const rawGroups = [...head, ...Array(missing).fill('0'), ...tail];
      if (rawGroups.length !== 8 || rawGroups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
      return rawGroups.map((g) => parseInt(g, 16).toString(16));
    } catch { return null; }
  };
  // Canonical client identity for token binding, quotas and abuse
  // accounting. IPv4-embedding transition forms collapse to the
  // embedded IPv4 address: mapped/translated ::ffff:0:0/96, deprecated
  // IPv4-compatible ::/96, NAT64 64:ff9b::/96 + 64:ff9b:1::/96 (every
  // client behind a carrier NAT64 otherwise shares ONE /64 abuse
  // bucket), 6to4 2002::/16 (one IPv4 = a whole free /48), and Teredo
  // 2001:0::/32 (client IPv4 XORed into the last 32 bits). Zone ids
  // (%eth0) are validated then stripped. All other IPv6 collapses to
  // one expanded-group spelling. ::, ::1 and documentation ranges
  // stay plain IPv6.
  const canonicalIp = (ip) => {
    if (typeof ip !== 'string' || !ip) return null;
    let raw = ip.trim();
    const pct = raw.indexOf('%');
    if (pct !== -1) {
      const zone = raw.slice(pct + 1);
      if (!zone || zone.length > 32 || !/^[0-9A-Za-z._-]+$/.test(zone)) return null;
      raw = raw.slice(0, pct);
    }
    const kind = isIP(raw);
    if (kind === 4) return raw;
    if (kind !== 6) return null;
    const g = ipv6Groups(raw);
    if (!g) return null;
    const toIpv4 = (hiHex, loHex) => {
      const hi = parseInt(hiHex, 16) || 0;
      const lo = parseInt(loHex, 16) || 0;
      return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
    };
    const zero5 = g[0] === '0' && g[1] === '0' && g[2] === '0' && g[3] === '0' && g[4] === '0';
    if ((zero5 && g[5] === 'ffff') ||
        (g[0] === '0' && g[1] === '0' && g[2] === '0' && g[3] === '0' && g[4] === 'ffff' && g[5] === '0')) {
      return toIpv4(g[6], g[7]); // v4-mapped / v4-translated
    }
    if (zero5 && g[5] === '0' && (parseInt(g[6], 16) || 0) >= 0x0100) {
      return toIpv4(g[6], g[7]); // deprecated v4-compatible (not :: or ::1)
    }
    if (g[0] === '64' && g[1] === 'ff9b' && (g[2] === '0' || g[2] === '1') &&
        g[3] === '0' && g[4] === '0' && g[5] === '0') {
      return toIpv4(g[6], g[7]); // NAT64 (RFC 6052 / RFC 8215)
    }
    if (g[0] === '2002') return toIpv4(g[1], g[2]); // 6to4 (RFC 3056)
    if (g[0] === '2001' && g[1] === '0') {
      const hi = (((parseInt(g[6], 16) || 0) ^ 0xffff) & 0xffff);
      const lo = (((parseInt(g[7], 16) || 0) ^ 0xffff) & 0xffff);
      return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`; // Teredo (RFC 4380)
    }
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
        // A chain SHORTER than the trusted hop count means the request did
        // not traverse the expected proxies (direct origin hit, stripped
        // header, miscounted depth): never fall back to chain[0] (fully
        // attacker-controlled) — ignore XFF and use the socket peer.
        const candidate = chain.length >= cfg.trustedProxyHops
          ? chain[chain.length - cfg.trustedProxyHops]
          : '';
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
          if (cfg.processing.blockUntrustedSharpLoaders) ensureUntrustedSharpLoadersBlocked();
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

  // A CORS preflight is an OPTIONS carrying BOTH Origin and
  // Access-Control-Request-Method. Bare OPTIONS requests (curl,
  // scanners, method probes) are not preflights and fall through to
  // the normal method checks (405), instead of receiving a permissive
  // 204 that advertises the route's methods to non-browser callers.
  function isPreflight(req) {
    return req.method === 'OPTIONS'
      && typeof req.headers?.origin === 'string' && req.headers.origin.length > 0
      && typeof req.headers?.['access-control-request-method'] === 'string'
      && req.headers['access-control-request-method'].length > 0;
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
  // Step-up challenge clearances: subject -> expiry, process-local
  // like the alert latch (multi-instance deployments may challenge
  // once per instance; the verification itself is the host's).
  const challengeClearances = new BoundedTtlSet({ maxEntries: 100000 });
  const challengeSubjectKey = (req, viewerId) => (viewerId
    ? `viewer:${hmacShort('quota-viewer', viewerId, 24)}`
    : `ip:${limiterIpTiers(req)[0]?.key || 'unknown'}`);
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
    let widthCap = Math.min(maxWidthCap, Math.floor(entitlementWidth));
    if (cfg.maxWidthFraction < 1) {
      let dims = null;
      try {
        dims = await imageDimensions(id);
      } catch {
        // Measurement THREW (semaphore busy / Sharp timeout): the
        // master exists but its width is temporarily unknown, so the
        // fraction cap cannot be proven — fail closed with 503
        // instead of minting an uncapped token. (A null result means
        // missing/unsupported master; downstream 404/415 applies and
        // no derivative is ever produced.)
        throw new MintDenied(503, 'service unavailable', { id, phase: 'token', viewerId, reason: 'fraction-dims-unavailable' });
      }
      if (dims?.width) widthCap = Math.max(64, Math.min(widthCap, Math.floor(dims.width * cfg.maxWidthFraction)));
    }
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
    // authorize() may tighten (or modestly extend) this token's lifetime;
    // normalizeAuthorizationResult has already bounded it to 5..900 s.
    const exp = iat + (Number.isInteger(entitlement.ttlSec) ? entitlement.ttlSec * 1000 : ttlMs);
    // `watermark: false` (or null) from authorize is an explicit
    // per-viewer opt-out of the global serverWatermark — e.g. paid
    // tiers see no visible mark. Previously `false` failed value
    // validation and denied the whole authorization.
    const watermark = await resolveWatermark(
      'watermark' in entitlement && entitlement.watermark !== undefined
        ? entitlement.watermark
        : serverWatermark,
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
    else if (serverWatermark && (entitlement.watermark === false || entitlement.watermark === null)) {
      tokenPayload.nwm = 1; // entitlement explicitly opted this view out
    }

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
    if (abuse.suspicious && cfg.abuseDetection.action === 'challenge' && cfg.challenge) {
      // Step-up instead of a blunt deny: borderline sessions (shared
      // NATs, eager browsers) can prove humanness via the host's
      // verifier (Turnstile siteverify, WebAuthn assertion, ...).
      // A passed challenge clears the subject for clearanceTtlSec;
      // the proof itself is single-use at the host verifier.
      const subject = challengeSubjectKey(req, viewerId);
      if (!challengeClearances.has(subject)) {
        const provided = req.headers[cfg.challenge.header];
        let result = null;
        if (typeof provided === 'string' && provided && provided.length <= 8192) {
          try {
            result = await withCallbackTimeout(cfg.challenge.verify, [req, provided], 'challenge.verify');
          } catch {
            throw new MintDenied(503, 'service unavailable', { id, phase: 'token', viewerId, reason: 'callback-unavailable' });
          }
        }
        const passed = result === true || (result && typeof result === 'object' && result.ok === true);
        if (!passed) {
          emitSecurityEvent('archx.challenge_required', req, {
            id, phase: 'token', viewerId, status: 403, reason: `distinct-images:${abuse.distinct}`,
          });
          throw new MintDenied(403, 'challenge required', {
            id, phase: 'token', viewerId, reason: 'challenge-required',
            headers: { 'x-archx-challenge': 'required' },
          });
        }
        const ttlSec = Number.isFinite(result?.ttlSec)
          ? Math.min(86400, Math.max(30, Math.floor(result.ttlSec)))
          : cfg.challenge.clearanceTtlSec;
        challengeClearances.claim(subject, Date.now() + ttlSec * 1000);
        emitSecurityEvent('archx.challenge_passed', req, { id, phase: 'token', viewerId, status: 200 });
      }
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
      key: deriveScrambleKey(id, nonce, secret, variantKeyScope({
        w, q: deliveryQuality, fmt: deliveryFormat,
        wm: tokenPayload.wm ?? null,
        forensicSeed: computeForensicSeed(id, tokenPayload, secret),
        stegoPayload: effectiveStego ? (tokenPayload.sg || issuedFingerprint) : null,
      }, secret)),
      grid,
      exp,
    };
    if (encrypt) out.aesKey = deriveAesKey(id, nonce, secret, variantKeyScope({
      w, q: deliveryQuality, fmt: deliveryFormat,
      wm: tokenPayload.wm ?? null,
      forensicSeed: computeForensicSeed(id, tokenPayload, secret),
      stegoPayload: effectiveStego ? (tokenPayload.sg || issuedFingerprint) : null,
    }, secret));
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
        if (isPreflight(req)) {
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

      if (isPreflight(req)) {
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
        if (cfg.maxWidthFraction < 1) {
          let dims = null;
          try {
            dims = await imageDimensions(id);
          } catch (err) {
            // Same fail-closed rule as mint: a thrown measurement
            // (busy/timeout) must not skip the fraction cap. Rethrow
            // into the outer mapper (BUSY/TIMEOUT -> 503).
            throw err;
          }
          if (dims?.width) effectiveWidth = Math.max(64, Math.min(effectiveWidth, Math.floor(dims.width * cfg.maxWidthFraction)));
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

        const forensicSeed = computeForensicSeed(id, payload, issuingSecret);
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
        // Key scope now folds in the mark state (watermark / forensic
        // seed / stego fingerprint), so it is computed after those are
        // resolved from the signed claims.
        const keyScope = variantKeyScope({
          w: payload.w, q: payload.q ?? quality, fmt: payload.fmt || format,
          wm: payload.wm ?? null, forensicSeed, stegoPayload,
        }, issuingSecret);
        const scrambleKey = deriveScrambleKey(id, payload.n, issuingSecret, keyScope);
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
          ? `${hmacShort('sg', stegoPayload, 12, issuingSecret)}:${effectiveStegoProfile}:s${effectiveStegoStrength}:x${effectiveStegoGridX ?? (effectiveStegoProfile === 'robust' ? 20 : 24)}:y${effectiveStegoGridY ?? (effectiveStegoProfile === 'robust' ? 14 : 16)}:k${hmacShort('sgkey', effectiveStegoKey || '', 8, issuingSecret)}:lv${stegoGlobalCfg.layoutVersion ?? 3}:lc${stegoGlobalCfg.legacyCode ? 1 : 0}:tm`
          : 'nosg';
        // Cache identity contains only inputs that can change the delivered
        // bytes. Viewer/trace hashes are not added unconditionally: when a
        // watermark, forensic seed, or StegoMark is viewer-specific, that
        // material is already represented by its own cache fragment below.
        // This is what allows an ordinary catalog derivative to be generated
        // once and reused by every authorized viewer.
        const aesKey = encrypt ? deriveAesKey(id, payload.n, issuingSecret, keyScope) : null;
        const forensicCachePart = forensicSeed
          ? hmacShort('fxseed', `${forensicSeed}:${typeof forensic === 'object' ? JSON.stringify(forensic) : ''}`, 16, issuingSecret)
          : 'nofx';
        const processingCachePart = [
          `we${cfg.processing.webpEffort}`,
          cfg.processing.webpSmartSubsample ? 'wss1' : 'wss0',
          `rk:${cfg.processing.resizeKernel}`,
          `png${cfg.processing.pngCompressionLevel}`,
          `jpg:${cfg.processing.jpegChromaSubsampling}`,
          `av${cfg.processing.avifEffort}`,
          `avs:${cfg.processing.avifChromaSubsampling}`,
          `op${cfg.processing.maxOutputPixels}`,
        ].join(':');
        const cacheKey = [
          // Cache-key version bumps ride every pad/mark byte change so
          // warm caches never serve pre-fix bytes: v3 black->edge-
          // replicate (v1.11); v4 reflection->keyed shifted-wrap padding
          // + 128-bit stego layouts (v1.13); v5 coherent DC-anchored
          // padding + v3 SHA-256-seeded layouts/signs + staggered
          // watermark rows + JS overlay blend (v1.14); v6 variant-scoped
          // per-image keys + planVersion 2 default (v1.15); v7 mark-state
          // digests in the key scope (v1.17). The ks part
          // pins bytes to the key scope they were scrambled under.
          'v7', id, masterVersion, `kid:${payload.kid}`, `ks:${keyScope}`, effectiveWidth, `g${grid}`, `pv${scramblePlanVersion}`,
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
                  ownership: cfg.ownership ? {
                    owner: cfg.ownership.owner, imageId: id,
                    privateKey: cfg.ownership.privateKey,
                    copyright: cfg.ownership.copyright, artist: cfg.ownership.artist,
                  } : null,
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
                // Resolve the master/base WITHOUT touching disk or the
                // master cache when a stage-1 base is already cached:
                // the previous flow loaded (and re-cached) the 5-50 MB
                // master on EVERY per-token view, evicting base entries
                // from the shared RAM pool and forcing re-decodes.
                // masterVersion is already in baseKey, so a replaced
                // master file misses the base cache cleanly.
                const baseKey = cacheable ? null : [
                  'base', id, masterVersion, `w${effectiveWidth}`, `g${grid}`,
                  `rk:${cfg.processing.resizeKernel}`,
                  `op${cfg.processing.maxOutputPixels}`,
                ].join(':');
                let base = baseKey ? getBaseCache(baseKey) : null;
                let master = null;
                if (cacheable) {
                  master = await loadMaster();
                } else if (!base) {
                  // Singleflight stage-1: N concurrent per-viewer
                  // requests share ONE decode+resize (the output
                  // singleflight cannot help: per-token cacheKeys are
                  // unique by construction).
                  let flight = baseInFlight.get(baseKey);
                  if (!flight) {
                    flight = (async () => {
                      try {
                        const again = getBaseCache(baseKey);
                        if (again) return again;
                        const m = await loadMaster();
                        const created = await processingSemaphore.run(() => prepareDerivativeBase(m.bytes, scrambleOpts));
                        if (m.current) setBaseCache(baseKey, created);
                        return created;
                      } finally {
                        if (baseInFlight.get(baseKey) === flight) baseInFlight.delete(baseKey);
                      }
                    })();
                    baseInFlight.set(baseKey, flight);
                  }
                  base = await flight;
                }
                const result = await processingSemaphore.run(async () => {
                  if (cacheable) return scrambleImage(master.bytes, scrambleOpts);
                  return finishDerivative(base, scrambleOpts);
                });
                if (cacheable && master.current) {
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
      replaySets: (storeStats.replaySets && typeof storeStats.replaySets === 'object') ? storeStats.replaySets : undefined,
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
      baseInFlight: baseInFlight.size,
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
    baseInFlight.clear();
    try { releaseSharpSecurity?.(); } catch { /* shutdown best effort */ }
  };
  return handler;
}

export default createArchxMiddleware;
