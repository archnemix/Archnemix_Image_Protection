# Reference chunked `.archx` transport

Archx's built-in loader accepts a complete `.archx` asset (`Blob`,
`ArrayBuffer`, or `Uint8Array`). It does not define an HTTP chunk protocol.
This reference includes a runnable host-owned client/server example in
[`examples/chunked-transport/`](../examples/chunked-transport/README.md): it
downloads and authenticates bounded chunks, assembles the **entire** container,
then hands it to Archx. It does not progressively render ciphertext or
unauthenticated prefixes. The end-to-end tests run in `tests/unit.test.mjs`.

## Signed manifest format

The origin serves an envelope containing a base64-encoded exact manifest byte
sequence and a detached RSA-SHA256 signature over those bytes. The manifest
contains only bounded metadata:

```json
{
  "version": 1,
  "assetId": "catalog-01",
  "expiresAt": "2026-11-14T00:00:00Z",
  "contentLength": 1234567,
  "containerSha256": "<64 lowercase hex chars>",
  "chunks": [
    { "url": "/chunks/catalog-01/0000", "length": 262144, "sha256": "<64 lowercase hex chars>" }
  ]
}
```

The signer uses an offline-held RSA key. Pin its public JWK in the application
or distribute it through a separately authenticated configuration channel.
Never trust a public key delivered only by the same unverified manifest
endpoint. Each chunk hash and the whole-container digest must be computed over
the exact bytes that will be served.

## Browser reference

```js
const PINNED_RSA_PUBLIC_JWK = Object.freeze({
  kty: 'RSA', n: 'REPLACE_WITH_PINNED_MODULUS', e: 'AQAB',
  alg: 'RS256', ext: true,
});
const MAX_ENVELOPE_BYTES = 512 * 1024;
const MAX_CHUNKS = 256;
const MAX_CHUNK_BYTES = 1024 * 1024;
const MAX_CONTAINER_BYTES = 64 * 1024 * 1024;
const fromBase64 = (value) => Uint8Array.from(atob(value), (ch) => ch.charCodeAt(0));
const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

async function readBounded(response, limit) {
  const reader = response.body?.getReader();
  if (!reader) throw new Error('streaming response body required');
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > limit) { await reader.cancel(); throw new Error('response exceeds byte limit'); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
  return result;
}

async function fetchVerifiedArchx(url, { signal, expectedAssetId } = {}) {
  const envelopeResponse = await fetch(url, {
    credentials: 'same-origin', cache: 'no-store', signal,
  });
  if (!envelopeResponse.ok) throw new Error(`manifest HTTP ${envelopeResponse.status}`);
  const envelopeBytes = await readBounded(envelopeResponse, MAX_ENVELOPE_BYTES);
  const envelope = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(envelopeBytes));
  if (envelope?.version !== 1 || typeof envelope.manifest !== 'string' ||
      typeof envelope.signature !== 'string') throw new Error('invalid manifest envelope');

  const manifestBytes = fromBase64(envelope.manifest);
  if (manifestBytes.length > 384 * 1024) throw new Error('manifest exceeds byte limit');
  const signature = fromBase64(envelope.signature);
  const verifyKey = await crypto.subtle.importKey(
    'jwk', PINNED_RSA_PUBLIC_JWK,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify'],
  );
  if (!await crypto.subtle.verify('RSASSA-PKCS1-v1_5', verifyKey, signature, manifestBytes)) {
    throw new Error('manifest signature invalid');
  }
  const manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(manifestBytes));
  if (manifest.version !== 1 || !Array.isArray(manifest.chunks) ||
      manifest.chunks.length < 1 || manifest.chunks.length > MAX_CHUNKS ||
      !Number.isFinite(Date.parse(manifest.expiresAt)) || Date.now() >= Date.parse(manifest.expiresAt) ||
      (expectedAssetId !== undefined && manifest.assetId !== expectedAssetId) ||
      !Number.isSafeInteger(manifest.contentLength) || manifest.contentLength < 1 ||
      manifest.contentLength > MAX_CONTAINER_BYTES ||
      !/^[0-9a-f]{64}$/.test(manifest.containerSha256)) {
    throw new Error('manifest exceeds transport bounds');
  }

  const parts = [];
  let total = 0;
  for (const chunk of manifest.chunks) {
    if (!chunk || typeof chunk.url !== 'string' ||
        !Number.isSafeInteger(chunk.length) || chunk.length < 1 || chunk.length > MAX_CHUNK_BYTES ||
        !/^[0-9a-f]{64}$/.test(chunk.sha256)) throw new Error('invalid chunk descriptor');
    const chunkUrl = new URL(chunk.url, url);
    if (chunkUrl.origin !== new URL(url, location.href).origin) throw new Error('cross-origin chunk refused');
    const response = await fetch(chunkUrl, { credentials: 'same-origin', cache: 'no-store', signal });
    if (!response.ok) throw new Error(`chunk HTTP ${response.status}`);
    const bytes = await readBounded(response, chunk.length);
    if (bytes.length !== chunk.length ||
        toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))) !== chunk.sha256) {
      throw new Error('chunk length or digest mismatch');
    }
    total += bytes.length;
    if (total > MAX_CONTAINER_BYTES || total > manifest.contentLength) throw new Error('container exceeds bounds');
    parts.push(bytes);
  }
  if (total !== manifest.contentLength) throw new Error('container length mismatch');
  const complete = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) { complete.set(part, offset); offset += part.length; }
  if (toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', complete))) !== manifest.containerSha256) {
    throw new Error('container digest mismatch');
  }
  return new Blob([complete], { type: 'application/octet-stream' });
}

const completeAsset = await fetchVerifiedArchx('/archx/assets/catalog-01.manifest', {
  expectedAssetId: 'catalog-01',
});
Archx.load.image('#protected-image', completeAsset, { mode: 'shield' });
```

## Operational requirements

- Authenticate and authorize the manifest and every chunk request. A signed
  manifest proves integrity, not entitlement; bind its `assetId`, expiry, and
  audience to your application authorization if it can be replayed.
- Cap manifest size before parsing, cap chunk count/size/total bytes before
  allocating, use request deadlines, and abort the remaining requests on error.
  The sample limits total bytes but host production code should also impose a
  finite manifest-response limit and concurrency cap.
- Verify exact-origin URLs, digests, the signature, and the final container
  digest. A deployment that cannot use WebCrypto verification must fail closed
  or verify the signed manifest in a trusted backend.
- Keep the pinned verification key separate from the manifest-serving origin;
  plan key rollover by temporarily accepting both explicitly pinned public
  keys.
- Do not display partial data. The browser receives the complete protected
  derivative just as it would from an ordinary response; chunking changes
  transport behavior, not the legitimate viewer's ability to reconstruct the
  derivative.

The runnable implementation is a host-owned reference example, not a managed
Archx server or a new built-in transport API. The example source is included in
the npm artifact for copying/adaptation; test it against your own authorization,
storage, concurrency, and key-rotation requirements. See the README's `.archx`
source forms and the [package export map](EXPORTS.md).
