# Runnable chunked `.archx` transport reference

This example is a host-owned, same-origin reference transport. It signs the
exact manifest bytes with RSA-SHA256, authenticates each manifest and chunk
request through a required host callback, bounds all sizes, verifies each
chunk and the final container in the browser, and returns a `Blob` only after
complete verification. It never renders partial ciphertext or unauthenticated
prefixes.

## Origin/server

```js
import fs from 'node:fs';
import { createPrivateKey } from 'node:crypto';
import { createChunkedAssetServer } from './server.mjs';

const server = createChunkedAssetServer({
  assets: { 'catalog-01': fs.readFileSync('./protected/catalog-01.archx') },
  privateKey: createPrivateKey(fs.readFileSync(process.env.ARCHX_MANIFEST_PRIVATE_KEY)),
  // Replace with the host's real session/entitlement check. This callback is
  // mandatory and is called independently for the manifest and every chunk.
  authorize: async (req, assetId) => Boolean(req.headers.cookie) && assetId === 'catalog-01',
  chunkBytes: 256 * 1024,
  manifestTtlSec: 300,
});
server.listen(8080);
```

The origin exposes `GET /archx-chunks/:assetId.manifest` and
`GET /archx-chunks/:assetId/:index`. For production, replace the in-memory
asset map with storage-backed bounded reads; retain per-request authorization,
`private, no-store`, the asset/chunk/container caps, and same-origin URLs.
Never serve the private signing key or trust a key fetched from this origin.

## Browser

```js
import { fetchVerifiedArchx } from './client.js';

// Configure this public JWK independently (for example, embed it in the app
// build or deliver it over a separately authenticated configuration path).
const PINNED_MANIFEST_KEY = Object.freeze({
  kty: 'RSA', n: 'REPLACE_WITH_PINNED_MODULUS', e: 'AQAB',
  alg: 'RS256', ext: true,
});
const complete = await fetchVerifiedArchx('/archx-chunks/catalog-01.manifest', {
  publicJwk: PINNED_MANIFEST_KEY,
  expectedAssetId: 'catalog-01',
  signal: abortController.signal,
});
Archx.load.image('#protected-image', complete, { mode: 'shield' });
```

`fetchVerifiedArchx()` enforces the same-origin rule and finite byte/chunk
limits, checks manifest expiry and asset identity, verifies the detached
signature and each SHA-256 chunk digest, then verifies the final container
digest before assembling the `Blob`. A failed signature, digest, bound, or
request abort rejects without returning partial bytes.

## Security boundaries

- The signature proves manifest integrity, not entitlement. The server's
  `authorize(req, assetId)` must validate the authenticated principal for
  **every** manifest and chunk request.
- The application must pin the public JWK outside the manifest-serving
  origin. Rotate keys by explicitly deploying old and new public keys during
  a bounded overlap.
- The in-memory example is for modest assets and reference use, not a
  production storage engine. Keep storage reads, concurrency, request time,
  and total bytes bounded in a deployment.
- Chunking changes transport only. The client still receives a complete
  derivative and must not display unauthenticated prefixes.

`docs/CHUNKED_TRANSPORT.md` gives the protocol details and integration notes.
The client and server modules are packed in the npm artifact as example source;
they do not change Archx's built-in transport or public API.
