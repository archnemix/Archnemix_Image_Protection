/**
 * Archnemix server middleware (Express-compatible, also works with plain
 * node:http). Masters stay on disk OUTSIDE your static folder; this is the
 * only route that can read them, and it only ever returns a down-scaled,
 * tile-scrambled (optionally AES-GCM-encrypted) .archx payload behind a
 * short-lived HMAC-signed URL.
 *
 *   GET {basePath}/token/:id?w=1200   -> { url, key, aesKey?, grid, exp }
 *   GET {basePath}/i/:id?t=...        -> application/octet-stream (.archx)
 *
 * A captured image URL dies at `exp` (default 120s). A captured payload is
 * a scrambled mosaic / ciphertext. There is no URL that returns the master.
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const ID_RE = /^[A-Za-z0-9._-]+$/;
const IMAGE_EXT = new Set(['.jpg', '.jpeg', '.png', '.webp', '.avif', '.gif', '.tif', '.tiff']);

function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}
function signToken(payload, secret) {
  const body = b64url(JSON.stringify(payload));
  const mac = crypto.createHmac('sha256', secret).update(body).digest();
  return body + '.' + b64url(mac);
}
function verifyToken(token, secret) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [body, mac] = token.split('.');
  const expected = crypto.createHmac('sha256', secret).update(body).digest();
  const given = Buffer.from(mac, 'base64url');
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

export function createArchxMiddleware(options = {}) {
  const secret = options.secret || process.env.ARCHX_SECRET;
  if (!secret) throw new Error('Archx server: provide options.secret or ARCHX_SECRET');

  const basePath = (options.basePath || '/archx').replace(/\/$/, '');
  const ttlMs = (options.ttlSec ?? 120) * 1000;
  const grid = options.grid ?? 8;
  const maxWidthCap = options.maxWidthCap ?? 1920;
  const quality = options.quality ?? 82;
  const scrambleKeyMode = options.scrambleKeyMode || 'per-image'; // | 'per-token'
  const encrypt = !!options.encrypt;
  // authorize: async (req,id) => boolean | { allow?, viewerId?, maxWidth?, watermark? }
  // Returning an object lets YOUR backend — not the browser — decide who is
  // watching and the maximum resolution they may receive for this image.
  const authorize = options.authorize || null;
  const rateMax = options.rateLimitPerMinute ?? 600;
  const tokenRateMax = options.tokenRateLimitPerMinute ?? 300;
  const oneTimeTokens = !!options.oneTimeTokens; // a signed URL works exactly once
  const bindTokenTo = options.bindTokenTo || {}; // { ip?:boolean, userAgent?:boolean }
  const allowedOrigins = options.allowedOrigins || null; // e.g. ['https://example.com']
  // serverWatermark: string | {text,...} | async ({req,id,nonce,viewerId,exp}) => string|object|null
  // String placeholders: {id} {nonce} {viewer}
  const serverWatermark = options.serverWatermark ?? null;
  const forensic = options.forensic ?? false; // true | { blockSize, delta }
  const forensicPerToken = options.forensicPerToken ?? true;

  // Index masters: id (basename w/o extension) -> absolute path
  const index = new Map();
  const dirs = options.imagesDirs || (options.imagesDir ? [options.imagesDir] : []);
  for (const dir of dirs) {
    const abs = path.resolve(dir);
    if (!fs.existsSync(abs)) continue;
    for (const name of fs.readdirSync(abs)) {
      const ext = path.extname(name).toLowerCase();
      if (!IMAGE_EXT.has(ext)) continue;
      const id = path.basename(name, ext);
      if (ID_RE.test(id) && !index.has(id)) index.set(id, path.join(abs, name));
    }
  }
  if (options.images) {
    for (const [id, p] of Object.entries(options.images)) {
      if (ID_RE.test(id)) index.set(id, path.resolve(p));
    }
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

  const masterCache = new Map(); // id -> {mtimeMs, bytes}
  const outputCache = new Map(); // cacheKey -> Buffer  (LRU-ish, capped)
  const OUTPUT_CACHE_MAX = options.outputCacheMax ?? 100;
  const rateMap = new Map(); // kind:ip -> number[] timestamps
  const consumedNonces = new Map(); // one-time tokens: nonceHash -> exp

  const requestIp = (req) => req.ip || req.socket?.remoteAddress || 'unknown';
  const hmacShort = (label, value, len = 24) =>
    crypto.createHmac('sha256', secret).update(label + ':' + String(value)).digest('base64url').slice(0, len);
  const safeEqual = (a, b) => {
    const ba = Buffer.from(String(a)); const bb = Buffer.from(String(b));
    return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
  };

  function originAllowed(req) {
    if (!allowedOrigins || !allowedOrigins.length) return true;
    const origin = req.headers?.origin;
    if (origin) return allowedOrigins.includes(origin);
    const referer = req.headers?.referer || req.headers?.referrer;
    if (referer) {
      try { return allowedOrigins.includes(new URL(referer).origin); } catch { return false; }
    }
    return false; // configured allowlist + no browser context headers => deny
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
    const mapKey = kind + ':' + requestIp(req);
    const now = Date.now();
    const list = (rateMap.get(mapKey) || []).filter((t) => now - t < 60000);
    list.push(now);
    rateMap.set(mapKey, list);
    return list.length > max;
  }

  function sendJson(res, status, obj) {
    const body = JSON.stringify(obj);
    res.writeHead(status, {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    });
    res.end(body);
  }

  async function handler(req, res, next) {
    let url;
    // Express strips the mount path from req.url; originalUrl keeps it.
    try { url = new URL(req.originalUrl || req.url, 'http://archx.local'); } catch { return next ? next() : sendJson(res, 400, { error: 'bad url' }); }
    if (!url.pathname.startsWith(basePath + '/')) {
      return next ? next() : sendJson(res, 404, { error: 'not found' });
    }
    const rest = url.pathname.slice(basePath.length + 1);
    const [kind, rawId] = rest.split('/');
    const id = decodeURIComponent(rawId || '');
    if (req.method !== 'GET' || !ID_RE.test(id) || !index.has(id)) {
      return sendJson(res, 404, { error: 'not found' });
    }
    if (rateLimited(req, kind)) return sendJson(res, 429, { error: 'too many requests' });
    if (!originAllowed(req)) return sendJson(res, 403, { error: 'forbidden' });

    try {
      if (kind === 'token') {
        let entitlement = {};
        if (authorize) {
          const auth = await authorize(req, id);
          if (!auth || auth.allow === false) return sendJson(res, 403, { error: 'forbidden' });
          if (typeof auth === 'object') entitlement = auth;
        }
        const viewerId = entitlement.viewerId || entitlement.userId || '';
        // The BROWSER asks for a width; the SERVER's entitlement caps it.
        // A tampered client can no longer "just ask for 1920px" beyond policy.
        const widthCap = Math.min(maxWidthCap, entitlement.maxWidth || maxWidthCap);
        const w = Math.max(64, Math.min(widthCap, parseInt(url.searchParams.get('w') || '1200', 10) || 1200));
        const nonce = crypto.randomBytes(9).toString('base64url');
        const exp = Date.now() + ttlMs;
        const watermark = await resolveWatermark(
          entitlement.watermark ?? serverWatermark,
          { req, id, nonce, viewerId, exp },
        );
        const tokenPayload = { id, w, exp, n: nonce };
        if (viewerId) tokenPayload.vh = hmacShort('viewer', viewerId, 20);
        if (watermark) tokenPayload.wm = watermark;
        const bindings = {};
        if (bindTokenTo.ip) bindings.ip = hmacShort('bind-ip', requestIp(req));
        if (bindTokenTo.userAgent) bindings.ua = hmacShort('bind-ua', req.headers?.['user-agent'] || '');
        if (Object.keys(bindings).length) tokenPayload.b = bindings;
        const token = signToken(tokenPayload, secret);
        const out = {
          url: `${basePath}/i/${encodeURIComponent(id)}?t=${token}`,
          key: deriveScrambleKey(id, nonce),
          grid,
          exp,
        };
        if (encrypt) out.aesKey = deriveAesKey(id, nonce);
        return sendJson(res, 200, out);
      }

      if (kind === 'i') {
        const payload = verifyToken(url.searchParams.get('t'), secret);
        if (!payload || payload.id !== id) return sendJson(res, 403, { error: 'invalid or expired token' });
        // Browser binding: a signed URL copied to another machine/browser dies.
        if (payload.b?.ip && !safeEqual(payload.b.ip, hmacShort('bind-ip', requestIp(req)))) {
          return sendJson(res, 403, { error: 'invalid or expired token' });
        }
        if (payload.b?.ua && !safeEqual(payload.b.ua, hmacShort('bind-ua', req.headers?.['user-agent'] || ''))) {
          return sendJson(res, 403, { error: 'invalid or expired token' });
        }
        // One-time use: replaying a captured signed URL gets nothing.
        if (oneTimeTokens) {
          const nonceHash = hmacShort('once', id + ':' + payload.n, 32);
          if (consumedNonces.has(nonceHash)) return sendJson(res, 403, { error: 'invalid or expired token' });
          consumedNonces.set(nonceHash, payload.exp);
          if (consumedNonces.size > 5000) {
            const now = Date.now();
            for (const [k, exp] of consumedNonces) if (exp < now) consumedNonces.delete(k);
          }
        }
        const scrambleKey = deriveScrambleKey(id, payload.n);
        const forensicSeed = forensic
          ? hmacShort('forensic', forensicPerToken
              ? `${id}:${payload.n}:${payload.vh || ''}`
              : `${id}:static:${payload.vh || ''}`, 32)
          : null;
        const wmCachePart = payload.wm ? hmacShort('wm', JSON.stringify(payload.wm), 12) : 'nowm';
        const cacheKey = [
          id, payload.w,
          scrambleKeyMode === 'per-token' ? payload.n : 's',
          encrypt ? 'e' : 'p', wmCachePart,
          forensicSeed ? (forensicPerToken ? payload.n : 'fx') : 'nofx',
          payload.vh || '',
        ].join('|');
        let bytes = outputCache.get(cacheKey);
        if (!bytes) {
          const filePath = index.get(id);
          const stat = fs.statSync(filePath);
          let master = masterCache.get(id);
          if (!master || master.mtimeMs !== stat.mtimeMs) {
            master = { mtimeMs: stat.mtimeMs, bytes: fs.readFileSync(filePath) };
            masterCache.set(id, master);
          }
          // Lazy import so token-only deployments don't need sharp wired early.
          const { scrambleImage } = await import('./scramble-image.js');
          const result = await scrambleImage(master.bytes, {
            grid,
            key: scrambleKey,
            maxWidth: Math.min(maxWidthCap, payload.w || 1200),
            quality,
            aesKey: encrypt ? deriveAesKey(id, payload.n) : null,
            watermark: payload.wm || null,
            forensicSeed,
            forensic: typeof forensic === 'object' ? forensic : {},
          });
          bytes = result.bytes;
          outputCache.set(cacheKey, bytes);
          while (outputCache.size > OUTPUT_CACHE_MAX) {
            outputCache.delete(outputCache.keys().next().value);
          }
        }
        res.writeHead(200, {
          'Content-Type': 'application/octet-stream',
          'Content-Length': bytes.length,
          'Content-Disposition': 'inline; filename="data.bin"',
          'Cache-Control': 'private, no-store',
          'X-Content-Type-Options': 'nosniff',
        });
        return res.end(bytes);
      }

      return sendJson(res, 404, { error: 'not found' });
    } catch (err) {
      return sendJson(res, 500, { error: 'image processing failed' });
    }
  }

  handler.index = index;
  handler._test = { signToken, verifyToken };
  return handler;
}

export { signToken, verifyToken };
export default createArchxMiddleware;
