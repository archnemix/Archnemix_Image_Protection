/**
 * Bounded fetching, token minting (single + batch coalescing), DPoP-style proof creation, and strict token-response parsing.
 */
import { NATIVES, nativeCall, nativeFetch, subtleDo, utf8EncodeCaptured } from './native.js';
import { DEFAULTS } from './options.js';
import { boundedInteger, cacheDigest, fetchPriorityInit } from './sampling.js';

export let tokenBatchSequence = 0;

export function deriveTokenBatchEndpoint(endpointUrl, options = {}) {
  if (options.tokenBatchEndpoint) {
    const batchUrl = resolveHttpUrl(options.tokenBatchEndpoint, {
      base: endpointUrl.href,
      label: 'batch token endpoint',
    });
    if (batchUrl.search || batchUrl.hash) {
      throw nonRetryableError('Archx: batch token endpoint must not contain a query or fragment');
    }
    return batchUrl;
  }
  const segments = endpointUrl.pathname.split('/').filter(Boolean);
  if (segments[segments.length - 1] !== 'token') return null;
  const batchUrl = new URL(endpointUrl.href);
  segments[segments.length - 1] = 'tokens';
  batchUrl.pathname = `/${segments.join('/')}`;
  batchUrl.search = '';
  batchUrl.hash = '';
  return batchUrl;
}

export function queueTokenBatchRequest({
  batchUrl,
  item,
  headers,
  credentials,
  controls,
  signal,
  options,
}) {
  const batchSize = boundedInteger(options.tokenBatchSize, DEFAULTS.tokenBatchSize, 1, 500);
  const delayMs = boundedInteger(options.tokenBatchDelayMs, DEFAULTS.tokenBatchDelayMs, 0, 1000);
  const maxDelayMs = Math.max(
    delayMs,
    boundedInteger(options.tokenBatchMaxDelayMs, DEFAULTS.tokenBatchMaxDelayMs, 0, 5000),
  );
  const groupKey = cacheDigest([
    'token-batch', 1, options.cacheScope || '', batchUrl.href, credentials,
    headers?.['X-Archx-Proof-Key'] || '', controls.fetchTimeoutMs, controls.retries, batchSize,
  ]);
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason || new Error('Archx: request aborted'));
      return;
    }
    let group = tokenBatchQueues.get(groupKey);
    if (!group) {
      group = {
        key: groupKey,
        batchUrl,
        headers,
        credentials,
        controls,
        options,
        entries: [],
        timer: 0,
        firstQueuedAt: Date.now(),
        controller: null,
        started: false,
      };
      tokenBatchQueues.set(groupKey, group);
    }
    const entry = {
      ref: `r${tokenBatchSequence++}`,
      item,
      resolve,
      reject,
      signal,
      cancelled: false,
      onAbort: null,
    };
    entry.onAbort = () => {
      if (entry.cancelled) return;
      entry.cancelled = true;
      reject(signal?.reason || new Error('Archx: request aborted'));
      if (!group.started) {
        group.entries = group.entries.filter((candidate) => candidate !== entry);
        if (!group.entries.length) {
          clearTimeout(group.timer);
          if (tokenBatchQueues.get(groupKey) === group) tokenBatchQueues.delete(groupKey);
        }
      } else if (group.entries.every((candidate) => candidate.cancelled)) {
        try { group.controller?.abort(signal?.reason); } catch { group.controller?.abort(); }
      }
    };
    signal?.addEventListener?.('abort', entry.onAbort, { once: true });
    group.entries.push(entry);
    if (group.entries.length >= batchSize) {
      clearTimeout(group.timer);
      void flushTokenBatch(group);
    } else {
      // Debounce rather than flushing strictly N ms after the first entry:
      // stable-size checks and proof-key setup make gallery mints trickle in
      // over a few frames. The max-delay cap keeps first-image latency sane.
      clearTimeout(group.timer);
      const elapsed = Date.now() - group.firstQueuedAt;
      const wait = Math.max(0, Math.min(delayMs, maxDelayMs - elapsed));
      group.timer = setTimeout(() => { void flushTokenBatch(group); }, wait);
    }
  });
}

export async function flushTokenBatch(group) {
  if (group.started) return;
  group.started = true;
  clearTimeout(group.timer);
  if (tokenBatchQueues.get(group.key) === group) tokenBatchQueues.delete(group.key);
  const active = group.entries.filter((entry) => !entry.cancelled);
  if (!active.length) return;
  group.controller = new AbortController();
  const settle = (entry, fn, value) => {
    entry.signal?.removeEventListener?.('abort', entry.onAbort);
    if (!entry.cancelled) fn(value);
  };
  try {
    const body = JSON.stringify({
      items: active.map((entry) => ({ ref: entry.ref, ...entry.item })),
    });
    const response = await fetchBounded(group.batchUrl.href, {
      method: 'POST',
      credentials: group.credentials,
      cache: 'no-store',
      redirect: 'error',
      headers: { ...group.headers, 'Content-Type': 'application/json' },
      body,
      signal: group.controller.signal,
      ...fetchPriorityInit(group.options),
    }, {
      retries: Math.min(1, group.controls.retries),
      maxBytes: Math.min(2 * 1024 * 1024, Math.max(65536, active.length * 16384)),
      timeoutMs: group.controls.fetchTimeoutMs,
      validateResponse: (res) => assertResponseFinalOrigin(res, new Set([group.batchUrl.origin])),
    });
    const parsed = parseBoundedJson(response.bytes);
    if (!isPlainClientObject(parsed.tokens || {}) || !isPlainClientObject(parsed.errors || {})) {
      throw nonRetryableError('Archx: batch token endpoint returned an invalid response');
    }
    for (const entry of active) {
      const raw = parsed.tokens?.[entry.ref];
      const failure = parsed.errors?.[entry.ref];
      if (isPlainClientObject(raw)) {
        settle(entry, entry.resolve, raw);
      } else if (isPlainClientObject(failure) && Number.isInteger(failure.status)) {
        const err = new Error('Archx fetch failed: HTTP ' + failure.status);
        err.status = failure.status;
        err.archxBatchItem = true;
        if (failure.status < 500 && ![408, 425, 429].includes(failure.status)) err.nonRetryable = true;
        settle(entry, entry.reject, err);
      } else {
        settle(entry, entry.reject, nonRetryableError('Archx: batch token response is incomplete'));
      }
    }
  } catch (err) {
    for (const entry of active) settle(entry, entry.reject, err);
  }
}

export function fetchControls(o = {}) {
  return {
    maxResponseBytes: boundedInteger(o.maxResponseBytes, DEFAULTS.maxResponseBytes, 1024, 512 * 1024 * 1024),
    fetchTimeoutMs: boundedInteger(o.fetchTimeoutMs, DEFAULTS.fetchTimeoutMs, 100, 120000),
    maxDecodedPixels: boundedInteger(o.maxDecodedPixels, DEFAULTS.maxDecodedPixels, 10000, 268402689),
    maxDecodedDimension: boundedInteger(o.maxDecodedDimension, DEFAULTS.maxDecodedDimension, 64, 65536),
    retries: boundedInteger(o.retries, 2, 0, 5),
    credentials: ['omit', 'same-origin', 'include'].includes(o.credentials) ? o.credentials : 'same-origin',
  };
}

export function nonRetryableError(message, code = 'ARCHX_INVALID_RESPONSE') {
  const err = new Error(message);
  err.code = code;
  err.nonRetryable = true;
  return err;
}

export function signalWithTimeout(parentSignal, timeoutMs) {
  const ms = Math.max(0, Math.floor(Number(timeoutMs) || 0));
  try {
    if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function' &&
        typeof AbortSignal.any === 'function') {
      const signals = [];
      if (parentSignal) signals.push(parentSignal);
      if (ms > 0) signals.push(AbortSignal.timeout(ms));
      return {
        signal: signals.length === 1 ? signals[0] : AbortSignal.any(signals),
        cleanup() {},
      };
    }
  } catch { /* fall through to the manual controller */ }
  const controller = new AbortController();
  let timer = 0;
  const onParentAbort = () => {
    try { controller.abort(parentSignal?.reason); } catch { controller.abort(); }
  };
  if (parentSignal?.aborted) onParentAbort();
  else parentSignal?.addEventListener?.('abort', onParentAbort, { once: true });
  if (ms > 0) {
    timer = setTimeout(() => {
      let reason;
      try { reason = new DOMException('Archx fetch timed out', 'TimeoutError'); } catch {}
      try { controller.abort(reason); } catch { controller.abort(); }
    }, ms);
  }
  return {
    signal: controller.signal,
    cleanup() {
      if (timer) clearTimeout(timer);
      parentSignal?.removeEventListener?.('abort', onParentAbort);
    },
  };
}

export async function readResponseBytes(response, maxBytes) {
  const limit = Math.max(1, Math.floor(Number(maxBytes) || 1));
  const lengthRaw = response.headers?.get?.('content-length');
  if (lengthRaw != null) {
    const declared = Number(lengthRaw);
    if (!Number.isSafeInteger(declared) || declared < 0 || declared > limit) {
      try { await response.body?.cancel?.(); } catch {}
      throw nonRetryableError('Archx: response exceeds the configured byte limit', 'ARCHX_RESPONSE_TOO_LARGE');
    }
  }
  if (!response.body?.getReader) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length > limit) {
      throw nonRetryableError('Archx: response exceeds the configured byte limit', 'ARCHX_RESPONSE_TOO_LARGE');
    }
    return bytes;
  }
  const reader = NATIVES.streamGetReader
    ? nativeCall(NATIVES.streamGetReader, response.body, [])
    : response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = NATIVES.streamReaderRead
        ? await nativeCall(NATIVES.streamReaderRead, reader, [])
        : await reader.read();
      if (done) break;
      const chunk = value instanceof Uint8Array ? value : new Uint8Array(value || []);
      total += chunk.length;
      if (total > limit) {
        try { await reader.cancel(); } catch {}
        throw nonRetryableError('Archx: response exceeds the configured byte limit', 'ARCHX_RESPONSE_TOO_LARGE');
      }
      if (chunk.length) chunks.push(chunk);
    }
  } finally {
    try { reader.releaseLock(); } catch {}
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.length; }
  return out;
}

export async function fetchBounded(url, options = {}, controls = {}) {
  const retries = boundedInteger(controls.retries, 0, 0, 5);
  const maxBytes = controls.maxBytes ?? DEFAULTS.maxResponseBytes;
  const timeoutMs = controls.timeoutMs ?? DEFAULTS.fetchTimeoutMs;
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    const timeout = signalWithTimeout(options.signal, timeoutMs);
    try {
      const response = await nativeFetch(url, { ...options, signal: timeout.signal });
      if (controls.validateResponse) controls.validateResponse(response);
      if (controls.allowedStatuses?.has(response.status)) {
        try { await response.body?.cancel?.(); } catch {}
        return { response, bytes: null };
      }
      if (!response.ok) {
        try { await response.body?.cancel?.(); } catch {}
        const err = new Error('Archx fetch failed: HTTP ' + response.status);
        err.status = response.status;
        // Server step-up signal (abuseDetection.action 'challenge'):
        // surfaced so the mint path can obtain a proof and retry once.
        try { err.challengeRequired = response.headers?.get?.('x-archx-challenge') === 'required'; } catch { /* headers unavailable */ }
        throw err;
      }
      const bytes = await readResponseBytes(response, maxBytes);
      return { response, bytes };
    } catch (err) {
      lastErr = err;
      if (options.signal?.aborted || err?.nonRetryable) throw err;
      const retryableHttp = err?.status == null || err.status >= 500 || [408, 425, 429].includes(err.status);
      if (!retryableHttp || attempt >= retries) throw err;
      await new Promise((resolve) => setTimeout(resolve, 250 * (attempt + 1)));
    } finally {
      timeout.cleanup();
    }
  }
  throw lastErr;
}

export function isPlainClientObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

export const sharedFatalDecoder = (() => {
  try { return new TextDecoder('utf-8', { fatal: true }); } catch { return null; }
})();

export function parseBoundedJson(bytes) {
  let value;
  try {
    const text = NATIVES.textDecode && sharedFatalDecoder
      ? nativeCall(NATIVES.textDecode, sharedFatalDecoder, [bytes])
      : new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    value = (NATIVES.jsonParse || JSON.parse)(text);
  }
  catch { throw nonRetryableError('Archx: token endpoint returned invalid JSON'); }
  if (!isPlainClientObject(value)) throw nonRetryableError('Archx: token endpoint returned an invalid response');
  return value;
}

export function resolveHttpUrl(raw, { base, label = 'URL', protocols = ['http:', 'https:'] } = {}) {
  if (typeof raw !== 'string' || !raw || raw.length > 16384 || /[\u0000-\u0020\u007f]/.test(raw)) {
    throw nonRetryableError(`Archx: invalid ${label}`);
  }
  let url;
  try {
    const fallbackBase = typeof document !== 'undefined' ? document.baseURI : undefined;
    url = new URL(raw, base || fallbackBase);
  } catch { throw nonRetryableError(`Archx: invalid ${label}`); }
  if (!protocols.includes(url.protocol) || url.username || url.password) {
    throw nonRetryableError(`Archx: disallowed ${label}`);
  }
  return url;
}

export function exactOriginSet(values, endpointUrl) {
  const origins = new Set();
  if (endpointUrl?.origin) origins.add(endpointUrl.origin);
  const list = values == null ? [] : (Array.isArray(values) ? values : [values]);
  for (const value of list) {
    if (typeof value !== 'string' || !value || value.length > 512) {
      throw nonRetryableError('Archx: allowedTokenOrigins must contain exact origins');
    }
    let parsed;
    try { parsed = new URL(value); } catch { throw nonRetryableError('Archx: allowedTokenOrigins must contain exact origins'); }
    const trimmed = value.endsWith('/') ? value.slice(0, -1) : value;
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.origin !== trimmed) {
      throw nonRetryableError('Archx: allowedTokenOrigins must contain exact origins');
    }
    origins.add(parsed.origin);
  }
  return origins;
}

export function assertResponseFinalOrigin(response, origins) {
  if (!response?.url) return;
  let finalUrl;
  try { finalUrl = new URL(response.url); }
  catch { throw nonRetryableError('Archx: response redirected to an invalid URL'); }
  if (!['http:', 'https:'].includes(finalUrl.protocol) || !origins.has(finalUrl.origin)) {
    throw nonRetryableError('Archx: response came from an untrusted origin');
  }
}

export function validTokenString(value, { min = 1, max = 512, pattern = null } = {}) {
  return typeof value === 'string' && value.length >= min && value.length <= max &&
    !/[\u0000-\u001f\u007f]/.test(value) && (!pattern || pattern.test(value));
}

export function bytesToBase64Url(bytes) {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
  if (typeof view.toBase64 === 'function') return view.toBase64({ alphabet: 'base64url', omitPadding: true });
  let binary = '';
  const chunkSize = 32768;
  for (let i = 0; i < view.length; i += chunkSize) {
    binary += String.fromCharCode(...view.subarray(i, Math.min(view.length, i + chunkSize)));
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export let proofKeyPromise = null;

/**
 * One ephemeral ECDSA P-256 key pair per page. The private key is created
 * non-extractable, so ordinary page tooling cannot export it and replay a
 * copied image token in another browser. This is a token-theft control, not
 * DRM: script already running in this page, a malicious extension, or the
 * browser operator can still ask the page to load/display an authorized image.
 */
export function getProofKey(required = false) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle?.generateKey || !subtle?.exportKey || !subtle?.sign || !subtle?.digest ||
      !globalThis.crypto?.getRandomValues) {
    if (required) return Promise.reject(nonRetryableError('Archx: proof-of-possession requires WebCrypto'));
    return Promise.resolve(null);
  }
  if (!proofKeyPromise) {
    proofKeyPromise = (async () => {
      const pair = await subtleDo('generateKey',
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['sign', 'verify'],
      );
      const exported = await subtleDo('exportKey', 'jwk', pair.publicKey);
      if (!exported || exported.kty !== 'EC' || exported.crv !== 'P-256' ||
          typeof exported.x !== 'string' || typeof exported.y !== 'string') {
        throw new Error('unsupported proof public key');
      }
      const jwk = { kty: 'EC', crv: 'P-256', x: exported.x, y: exported.y };
      const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
      const thumbprint = bytesToBase64Url(await subtleDo('digest', 'SHA-256', utf8EncodeCaptured(canonical)));
      return Object.freeze({
        privateKey: pair.privateKey,
        jwk: Object.freeze(jwk),
        jkt: thumbprint,
        header: bytesToBase64Url(utf8EncodeCaptured(JSON.stringify(jwk))),
      });
    })().catch((err) => {
      proofKeyPromise = null;
      throw err;
    });
  }
  return proofKeyPromise.catch((err) => {
    if (required) throw nonRetryableError('Archx: proof-of-possession key generation failed');
    return null;
  });
}

export async function createProofHeader(proofKey, accessToken, payloadUrl) {
  if (!proofKey || !accessToken) return null;
  const subtle = globalThis.crypto?.subtle;
  if (!subtle?.sign || !subtle?.digest) throw nonRetryableError('Archx: proof-of-possession signing is unavailable');
  const now = Date.now();
  const random = new Uint8Array(18);
  globalThis.crypto.getRandomValues(random);
  const proof = {
    jwk: proofKey.jwk,
    jti: bytesToBase64Url(random),
    iat: now,
    exp: now + 60000,
    htm: 'GET',
    htu: payloadUrl.pathname,
    ath: bytesToBase64Url(await subtleDo('digest', 'SHA-256', utf8EncodeCaptured(accessToken))),
  };
  const payloadPart = bytesToBase64Url(utf8EncodeCaptured(JSON.stringify(proof)));
  const signingInput = `v1.${payloadPart}`;
  const signature = await subtleDo('sign',
    { name: 'ECDSA', hash: 'SHA-256' },
    proofKey.privateKey,
    utf8EncodeCaptured(signingInput),
  );
  return `${signingInput}.${bytesToBase64Url(signature)}`;
}

export function parseTokenResponse(raw, options, endpointUrl) {
  if (!isPlainClientObject(raw)) throw nonRetryableError('Archx: token endpoint returned an invalid response');
  if (!validTokenString(raw.key, { min: 1, max: 512 })) throw nonRetryableError('Archx: token response has an invalid key');
  if (!Number.isInteger(raw.grid) || raw.grid < 2 || raw.grid > 32) throw nonRetryableError('Archx: token response has an invalid grid');
  if (raw.aesKey !== undefined && !validTokenString(raw.aesKey, { min: 16, max: 256 })) {
    throw nonRetryableError('Archx: token response has an invalid AES key');
  }
  if (raw.exp !== undefined && (!Number.isSafeInteger(raw.exp) || raw.exp <= Date.now() - 300000)) {
    throw nonRetryableError('Archx: token response is expired');
  }
  const separateToken = raw.token;
  if (separateToken !== undefined &&
      !validTokenString(separateToken, { min: 16, max: 8192, pattern: /^[A-Za-z0-9._~-]+$/ })) {
    throw nonRetryableError('Archx: token response has an invalid token');
  }
  const rawUrl = raw.cleanUrl ?? raw.url;
  const candidate = resolveHttpUrl(rawUrl, { base: endpointUrl.href, label: 'token payload URL' });
  const allowedOrigins = exactOriginSet(options.allowedTokenOrigins, endpointUrl);
  if (!allowedOrigins.has(candidate.origin)) {
    throw nonRetryableError('Archx: token payload URL points to an untrusted origin');
  }
  const payloadUrl = new URL(candidate.href);
  const queryTokens = payloadUrl.searchParams.getAll('t');
  if (queryTokens.length > 1) throw nonRetryableError('Archx: token payload URL is ambiguous');
  const requestedTransport = String(options.tokenTransport || 'header').toLowerCase();
  const transport = ['header', 'query', 'auto'].includes(requestedTransport) ? requestedTransport : 'header';
  let headerToken = null;
  let accessToken = separateToken || queryTokens[0] || null;
  if (transport === 'header' || (transport === 'auto' && separateToken)) {
    headerToken = separateToken || null;
    if (queryTokens.length === 1) {
      if (headerToken && headerToken !== queryTokens[0]) throw nonRetryableError('Archx: token response is ambiguous');
      headerToken = queryTokens[0];
      payloadUrl.searchParams.delete('t');
    }
    if (!validTokenString(headerToken, { min: 16, max: 8192, pattern: /^[A-Za-z0-9._~-]+$/ })) {
      throw nonRetryableError('Archx: token response did not include a header token');
    }
    accessToken = headerToken;
  } else {
    if (separateToken && queryTokens.length === 1 && separateToken !== queryTokens[0]) {
      throw nonRetryableError('Archx: token response is ambiguous');
    }
    if (queryTokens.length === 0) {
      if (!separateToken) throw nonRetryableError('Archx: token response did not include a payload token');
      payloadUrl.searchParams.set('t', separateToken);
    }
  }
  const extra = { key: raw.key, grid: raw.grid };
  if (raw.aesKey !== undefined) extra.aesKey = raw.aesKey;
  return Object.freeze({ extra: Object.freeze(extra), payloadUrl, headerToken, accessToken, allowedOrigins });
}
export const tokenBatchQueues = new Map();
