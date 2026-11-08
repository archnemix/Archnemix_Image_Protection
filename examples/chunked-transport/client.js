const DEFAULT_LIMITS = Object.freeze({
  envelopeBytes: 512 * 1024,
  manifestBytes: 384 * 1024,
  chunks: 256,
  chunkBytes: 1024 * 1024,
  containerBytes: 64 * 1024 * 1024,
});

const isSha256 = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const isAssetId = (value) => typeof value === 'string' && /^[A-Za-z0-9._-]{1,96}$/.test(value);
const toHex = (bytes) => [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');

function fromBase64(value) {
  if (typeof value !== 'string' || value.length > 700_000 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    throw new Error('invalid base64 field');
  }
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function readBounded(response, limit) {
  const reader = response.body?.getReader();
  if (!reader) throw new Error('streaming response body required');
  const pieces = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > limit) {
        await reader.cancel();
        throw new Error('response exceeds byte limit');
      }
      pieces.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const piece of pieces) { bytes.set(piece, offset); offset += piece.byteLength; }
  return bytes;
}

function resolveManifestUrl(url, baseUrl) {
  const base = baseUrl || globalThis.location?.href;
  if (!base && !/^[a-z][a-z\d+.-]*:/i.test(url)) {
    throw new TypeError('baseUrl is required for a relative manifest URL outside a browser');
  }
  return new URL(url, base);
}

/**
 * Fetch, authenticate, and assemble a complete `.archx` container.
 *
 * The complete authenticated container is returned as a Blob; callers never
 * receive partial chunks or unauthenticated prefixes. The verification JWK
 * must be pinned/configured separately from the manifest endpoint.
 */
export async function fetchVerifiedArchx(manifestUrl, {
  publicJwk,
  expectedAssetId,
  signal,
  baseUrl,
  fetchImpl = globalThis.fetch,
  cryptoImpl = globalThis.crypto,
  limits = {},
} = {}) {
  if (!publicJwk || !fetchImpl || !cryptoImpl?.subtle) throw new TypeError('pinned publicJwk, fetch, and WebCrypto are required');
  const cap = { ...DEFAULT_LIMITS, ...limits };
  for (const [name, value] of Object.entries(cap)) {
    if (!Number.isSafeInteger(value) || value < 1 || value > DEFAULT_LIMITS[name]) {
      throw new RangeError(`invalid ${name} transport limit`);
    }
  }
  const manifestLocation = resolveManifestUrl(String(manifestUrl), baseUrl);
  const envelopeResponse = await fetchImpl(manifestLocation, {
    credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal,
  });
  if (!envelopeResponse.ok) throw new Error(`manifest HTTP ${envelopeResponse.status}`);
  if (envelopeResponse.url && new URL(envelopeResponse.url).origin !== manifestLocation.origin) {
    throw new Error('cross-origin manifest redirect refused');
  }
  const envelopeBytes = await readBounded(envelopeResponse, cap.envelopeBytes);
  const envelope = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(envelopeBytes));
  if (envelope?.version !== 1 || typeof envelope.manifest !== 'string' ||
      typeof envelope.signature !== 'string') throw new Error('invalid manifest envelope');

  const manifestBytes = fromBase64(envelope.manifest);
  if (manifestBytes.length > cap.manifestBytes) throw new Error('manifest exceeds byte limit');
  const signature = fromBase64(envelope.signature);
  const verifyKey = await cryptoImpl.subtle.importKey(
    'jwk', publicJwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'],
  );
  if (!await cryptoImpl.subtle.verify('RSASSA-PKCS1-v1_5', verifyKey, signature, manifestBytes)) {
    throw new Error('manifest signature invalid');
  }
  const manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(manifestBytes));
  const expiresAt = Date.parse(manifest.expiresAt);
  if (manifest.version !== 1 || !isAssetId(manifest.assetId) ||
      !Array.isArray(manifest.chunks) || manifest.chunks.length < 1 || manifest.chunks.length > cap.chunks ||
      !Number.isFinite(expiresAt) || Date.now() >= expiresAt ||
      (expectedAssetId !== undefined && manifest.assetId !== expectedAssetId) ||
      !Number.isSafeInteger(manifest.contentLength) || manifest.contentLength < 1 ||
      manifest.contentLength > cap.containerBytes || !isSha256(manifest.containerSha256)) {
    throw new Error('manifest exceeds transport bounds');
  }

  const chunks = [];
  let total = 0;
  for (const descriptor of manifest.chunks) {
    if (!descriptor || typeof descriptor.url !== 'string' ||
        !Number.isSafeInteger(descriptor.length) || descriptor.length < 1 || descriptor.length > cap.chunkBytes ||
        !isSha256(descriptor.sha256)) throw new Error('invalid chunk descriptor');
    const chunkUrl = new URL(descriptor.url, manifestLocation);
    if (chunkUrl.origin !== manifestLocation.origin) throw new Error('cross-origin chunk refused');
    const response = await fetchImpl(chunkUrl, {
      credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal,
    });
    if (!response.ok) throw new Error(`chunk HTTP ${response.status}`);
    if (response.url && new URL(response.url).origin !== manifestLocation.origin) {
      throw new Error('cross-origin chunk redirect refused');
    }
    const bytes = await readBounded(response, descriptor.length);
    if (bytes.length !== descriptor.length ||
        toHex(new Uint8Array(await cryptoImpl.subtle.digest('SHA-256', bytes))) !== descriptor.sha256) {
      throw new Error('chunk length or digest mismatch');
    }
    total += bytes.length;
    if (total > cap.containerBytes || total > manifest.contentLength) throw new Error('container exceeds bounds');
    chunks.push(bytes);
  }
  if (total !== manifest.contentLength) throw new Error('container length mismatch');
  const complete = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { complete.set(chunk, offset); offset += chunk.length; }
  if (toHex(new Uint8Array(await cryptoImpl.subtle.digest('SHA-256', complete))) !== manifest.containerSha256) {
    throw new Error('container digest mismatch');
  }
  return new Blob([complete], { type: 'application/octet-stream' });
}
