# C2PA signing integration recipe

Archx does not claim to be a C2PA signer and does not embed manifests in its
custom encrypted `.archx` container. For standard JPEG/WebP deliverables, or
for source masters that will later feed Archx, use the Content Authenticity
Initiative's open Node SDK in an **offline ingest/precompute job**. Do not put
local-key C2PA signing on Archx's protected-image request path.

## Compatibility and boundary

The current `@contentauth/c2pa-node` 0.10.x package documents Node.js 22+
(the package metadata currently requires `>=22`). Run it in a separate
Node 22+ signing job/service if the rest of your Archx deployment still
supports Node 20. Install it only in that integration, not as an Archx runtime
dependency:

```sh
npm install @contentauth/c2pa-node
```

The SDK accepts JPEG/PNG and other formats supported by its native C2PA
library; `.archx` is not a supported C2PA asset format. Sign the source master
or a standard-image derivative **before** converting it to `.archx`. Archx's
Sharp transforms may drop C2PA metadata, so a signed source does not prove that
a delivered `.archx` payload still carries a manifest. If the final product
needs C2PA verification, sign and verify a standard-image deliverable, and
maintain a separate signed mapping from that deliverable's digest to its
Archx asset ID/manifest version.

## Minimal offline signing example

The example signs a standard JPEG buffer. Supply a C2PA-compatible signing
certificate chain, corresponding PKCS#8 private key, and (in production) a
trusted timestamp authority. For `es256`, the SDK expects an unencrypted EC
key in PKCS#8 PEM form (`BEGIN PRIVATE KEY`); traditional SEC1 PEM
(`BEGIN EC PRIVATE KEY`) is rejected. The example deliberately reads key
material from protected files rather than command-line arguments or source
control.

```js
// Node 22+; install @contentauth/c2pa-node in this isolated signing job.
import fs from 'node:fs/promises';
import { Builder, Context, LocalSigner, Reader } from '@contentauth/c2pa-node';

const [inputPath, outputPath, certificatePath, privateKeyPath] = process.argv.slice(2);
if (!inputPath || !outputPath || !certificatePath || !privateKeyPath) {
  throw new Error('usage: node sign-jpeg.mjs input.jpg output.jpg certificate.pem private-key.pem');
}

const input = await fs.readFile(inputPath);
const certificate = await fs.readFile(certificatePath);
const privateKey = await fs.readFile(privateKeyPath);
const builder = await Builder.newAsync(new Context({ builder: { generateC2paArchive: true } }));
// Select the truthful DigitalSourceType for your asset; do not label an edit
// or AI-generated image as a camera capture. `create` adds c2pa.created.
builder.setIntent({ create: 'http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture' });
const signer = LocalSigner.newSigner(certificate, privateKey, 'es256', process.env.C2PA_TSA_URL);
const destination = { buffer: null };
// In SDK 0.10.x, sign() is synchronous and returns manifest bytes while
// filling DestinationBufferAsset.buffer with the signed image bytes.
const manifestBytes = builder.sign(signer,
  { buffer: input, mimeType: 'image/jpeg' },
  destination);
if (!manifestBytes?.length || !destination.buffer) {
  throw new Error('C2PA SDK did not produce a manifest and signed output buffer');
}
await fs.writeFile(outputPath, destination.buffer, { mode: 0o644 });

// Read the final bytes back and make verification part of the job's success
// criteria. Production policy should additionally validate trust and revocation.
const reader = await Reader.fromAsset(
  { buffer: await fs.readFile(outputPath), mimeType: 'image/jpeg' },
  new Context({ verify: { verifyAfterReading: true } }),
);
if (!reader?.isEmbedded() || !reader.getActive()) throw new Error('signed C2PA manifest not found');
console.log('C2PA output verified:', outputPath);
```

> The verification above checks that an embedded manifest is readable; it is
> not a substitute for validating certificate trust, signer identity, claims,
> revocation, and timestamp policy. Those policies are deployment-specific.
> Never treat “manifest present” as proof that a claim is truthful.

## Archx integration pattern

1. At ingest, preserve and sign the original master or generate a signed
   standard-image derivative in the offline job above.
2. Store the signed asset digest, C2PA manifest/claim identifier, certificate
   identity, and Archx asset ID in your own immutable ingest record.
3. Build encrypted `.archx` derivatives separately with `archx-build`; do not
   copy the private signing key into the Archx web server or browser.
4. If an SEO preview is delivered as an ordinary WebP/JPEG, generate and sign
   that final preview in an offline precompute pipeline. The current dynamic
   `seoCrawler` route is not a C2PA signing endpoint.
5. Independently verify the exact standard-image bytes that will be published.
   If any resize, watermark, recompression, or metadata rewrite occurs after
   signing, verify again and re-sign the final bytes as appropriate.

## SDK smoke validation

The example was exercised end-to-end with Node 22 and
`@contentauth/c2pa-node` 0.10.0, using a throwaway P-256 leaf certificate
signed by a temporary test CA (no timestamp service). `Builder.sign()`
returned manifest bytes and a signed JPEG buffer; `Reader.fromAsset()`
reopened the output with an embedded active manifest. This validates the
recipe's API/runtime path only—not certificate trust, revocation, signer
identity, timestamp policy, or the truth of the asserted capture claim.

The Archx ownership claim and issuance-log APIs are separate mechanisms; they
do not produce C2PA manifests and should not be described as equivalent.
See the [SDK documentation](https://github.com/contentauth/c2pa-node) and
[Archx public exports](EXPORTS.md) for their distinct boundaries.
