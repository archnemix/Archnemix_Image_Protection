/**
 * Token plumbing: HMAC-signed access tokens, strict claim validation,
 * DPoP-style proof-of-possession verification (RFC 9449 shape), and
 * deterministic StegoMark fingerprint/key derivation from the server
 * secret. Re-exported from server/middleware.js for back-compat.
 */
import path from 'node:path';
import crypto from 'node:crypto';
import { SECRET_ID_RE, isPlainObject, validateImageId, validateWatermarkValue } from './config.js';

export const TOKEN_AUDIENCE = 'archx:image';
export const TOKEN_SCOPE = 'image:view';
function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}
export function signToken(payload, secret) {
  const body = b64url(JSON.stringify(payload));
  const mac = crypto.createHmac('sha256', secret).update(body).digest();
  return body + '.' + b64url(mac);
}
export function verifyToken(token, secretOrKeyring) {
  if (!token || typeof token !== 'string' || token.length > 8192) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [body, mac] = parts;
  if (!/^[A-Za-z0-9_-]+$/.test(body) || !/^[A-Za-z0-9_-]+$/.test(mac)) return null;
  // Canonical encodings only: base64url's final character carries
  // slack bits, so up to four distinct strings decode to the same
  // MAC bytes. Claims are keyed canonically today, but token
  // malleability is a standing invitation for tomorrow's
  // string-keyed cache, log, or denylist — reject re-encodings
  // that differ from what signToken would have emitted.
  const bodyBytes = Buffer.from(body, 'base64url');
  const given = Buffer.from(mac, 'base64url');
  if (bodyBytes.toString('base64url') !== body) return null;
  if (given.toString('base64url') !== mac) return null;

  const isKeyring = secretOrKeyring instanceof Map ||
    (secretOrKeyring && typeof secretOrKeyring === 'object' && !Buffer.isBuffer(secretOrKeyring) &&
      !(secretOrKeyring instanceof Uint8Array));
  // Single-secret deployments (the common case) authenticate before
  // parsing: a forged or malformed payload is never JSON.parse'd, and
  // rejection costs one HMAC instead of a parse plus claim walk. The
  // accept set is unchanged. Keyrings still parse first because key
  // selection needs the payload's `kid`.
  if (!isKeyring) {
    if (typeof secretOrKeyring !== 'string' && !(secretOrKeyring instanceof Uint8Array)) return null;
    const expected = crypto.createHmac('sha256', secretOrKeyring).update(body).digest();
    if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
    let payload;
    try { payload = JSON.parse(bodyBytes.toString('utf8')); } catch { return null; }
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
    if (!Number.isFinite(payload.exp) || Date.now() > payload.exp) return null;
    payload.kid = typeof payload.kid === 'string' ? payload.kid : 'primary';
    return payload;
  }
  let payload;
  try {
    payload = JSON.parse(bodyBytes.toString('utf8'));
  } catch { return null; }
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;

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
  }
  if (!candidates.length) return null;

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

const TOKEN_CLAIM_FIELDS = new Set([
  'v', 'kid', 'aud', 'scope', 'id', 'w', 'iat', 'exp', 'n', 'q', 'fmt', 'ls', 'vh', 'th', 'wm',
  'sg', 'sgp', 'sgs', 'sge', 'sgv', 'sgx', 'sgy', 'sgi', 'sgk', 'nsg', 'nwm', 'b', 'jkt',
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
    if (payload.nwm !== undefined && payload.nwm !== 1) return false;
    if (payload.nwm === 1 && payload.wm != null) return false; // contradictory watermark claims
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

export function parseProofPublicKeyHeader(value) {
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

export function verifyProofOfPossession({ header, token, expectedJkt, method, target, now = Date.now() }) {
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
    if (publicKey) {
      // LRU touch: hot proof keys stay resident under churn.
      proofKeyCache.delete(expectedJkt);
      proofKeyCache.set(expectedJkt, publicKey);
    } else {
      publicKey = crypto.createPublicKey({ key: jwk, format: 'jwk' });
      // Bounded LRU eviction (oldest first). The previous wholesale
      // clear() turned this cache into a periodic full-recompute under
      // DPoP-heavy traffic (audit D6).
      while (proofKeyCache.size >= 512) {
        const oldest = proofKeyCache.keys().next().value;
        if (oldest === undefined) break;
        proofKeyCache.delete(oldest);
      }
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

// Accept both the object form ({ ip, userAgent, session }) and the
// array form (['ip', 'ua', ...]) that shipped type declarations long
// promised; unknown entries are dropped (validation rejects them first).
export function normalizeBindTokenTo(value) {
  if (Array.isArray(value)) {
    const out = {};
    for (const entry of value) {
      if (entry === 'ip') out.ip = true;
      else if (entry === 'userAgent' || entry === 'ua' || entry === 'user-agent') out.userAgent = true;
      else if (entry === 'session') out.session = true;
    }
    return out;
  }
  return isPlainObject(value) ? value : {};
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
