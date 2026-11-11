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

The runnable client in [`examples/chunked-transport/client.js`](../examples/chunked-transport/client.js) is the canonical implementation; use it rather than maintaining a second transport copy. It requires a separately pinned RSA public JWK and returns a `Blob` only after verifying the complete manifest and container:

```js
import { fetchVerifiedArchx } from './client.js'; // copy the example module into your app

const completeAsset = await fetchVerifiedArchx('/archx-chunks/catalog-01.manifest', {
  publicJwk: PINNED_RSA_PUBLIC_JWK, // configure independently of the manifest origin
  expectedAssetId: 'catalog-01',
  signal: abortController.signal,
});
Archx.load.image('#protected-image', completeAsset, { mode: 'shield' });
```

The implementation bounds the envelope, manifest, chunk count, individual
chunks, and total container; validates asset IDs, expiry, origin, lengths, and
SHA-256 digests; verifies the detached signature; disables redirects; and
checks the final container digest before returning. Any failed bound or check
rejects without returning partial bytes. The source is a host-owned example,
not a package API or built-in Archx transport.

## Operational requirements

- Authenticate and authorize the manifest and every chunk request. A signed
  manifest proves integrity, not entitlement; bind its `assetId`, expiry, and
  audience to your application authorization if it can be replayed.
- Cap the manifest envelope and decoded manifest before parsing, and cap
  chunk count/size/total bytes before allocating. The reference client enforces
  finite envelope/manifest limits and fetches chunks sequentially (concurrency
  one); pass an `AbortSignal` to enforce an application deadline because the
  sample does not create its own timeout. Production hosts should retain or
  tighten the byte caps, keep concurrency bounded, and abort remaining work on
  error.
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
