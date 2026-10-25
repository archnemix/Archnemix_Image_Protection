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
  const authorize = options.authorize || null; // async (req, id) => boolean
  const rateMax = options.rateLimitPerMinute ?? 600;

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
  const rateMap = new Map(); // ip -> number[] timestamps

  function rateLimited(req) {
    const ip = req.socket?.remoteAddress || req.ip || 'unknown';
    const now = Date.now();
    const list = (rateMap.get(ip) || []).filter((t) => now - t < 60000);
    list.push(now);
    rateMap.set(ip, list);
    return list.length > rateMax;
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
    if (rateLimited(req)) return sendJson(res, 429, { error: 'too many requests' });

    try {
      if (kind === 'token') {
        if (authorize && !(await authorize(req, id))) return sendJson(res, 403, { error: 'forbidden' });
        const w = Math.max(64, Math.min(maxWidthCap, parseInt(url.searchParams.get('w') || '1200', 10) || 1200));
        const nonce = crypto.randomBytes(9).toString('base64url');
        const exp = Date.now() + ttlMs;
        const token = signToken({ id, w, exp, n: nonce }, secret);
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
        const scrambleKey = deriveScrambleKey(id, payload.n);
        const cacheKey = [id, payload.w, scrambleKeyMode === 'per-token' ? payload.n : 's', encrypt ? 'e' : 'p'].join('|');
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
