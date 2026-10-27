# Changelog

All notable changes to Archnemix Image Protection (`Archx`) are documented
here. The project follows semantic versioning once a version is released.

## [1.8.0] — Unreleased

Scattered-memory display hardening: browser-enforced readback denial and
fail-safe cache/body handling, with measurement proof that display remains
pixel-exact.

### Added

- **Origin-tainted 2D readback.** The middleware serves a constant 1×1
  transparent PNG at `{basePath}/taint.png` (public, immutable-cached,
  deliberately without CORS headers; disable with `taintImage:false`).
  When the token API is cross-origin to the page — or the client is given
  any cross-origin `taintUrl` — the client draws that pixel into every 2D
  display/split-tile canvas before painting, flipping the canvas's
  origin-clean flag: `toDataURL`/`toBlob`/`getImageData`/`captureStream`
  then throw `SecurityError` at the browser-platform level, including
  `HTMLCanvasElement.prototype...call(canvas)` bypasses, and the taint
  propagates through copied canvases/`ImageBitmap`s. Controlled by client
  `taintReadback:'auto'|'off'` and `taintUrl` (also `taint-readback` /
  `taint-url` element attributes). Display pixels are unchanged: the
  browser suite measures a mean absolute difference of 0 between the
  painted shield canvas and the authorized derivative at 1:1. Same-origin
  deployments cannot taint and keep instance-poisoned readback.
- WebGL display canvases now receive the same instance-level read/record
  API shadowing as 2D canvases, in addition to the platform's black
  non-preserved readback, so `captureStream`-style recording of animated
  vault/temporal frames meets an explicit poison first line.

### Security

- Disk/shared derivative-cache hits are validated before serving: bytes
  must parse as an `.archx` container matching the expected scramble grid,
  width cap, encryption state, and content type. Tampered or poisoned
  cache entries are evicted and regenerated instead of being trusted by
  key alone.

### Fixed

- Batch token minting accepts framework-parsed string/`Buffer`/
  `Uint8Array` request bodies under the same byte cap and strict JSON
  validation (previously only a live request stream worked; pre-parsed
  object bodies still fail closed with 400).
- The Chromium test harness no longer launches with
  `--disable-web-security`, so CORS and canvas origin-taint behavior are
  exercised exactly as production browsers enforce them.

### Tests

- 47 Node tests and 104 Chromium checks (up from 44/98), adding the taint
  endpoint contract, poisoned-cache regeneration, parsed-body minting,
  tainted-canvas `SecurityError` assertions, WebGL API shadowing, and
  pixel-exact display verification.

## [1.7.0] — Unreleased

### Added

- Static-catalog integrity pinning: `archx-build` now prints (and
  `buildArchxAssets()` returns) the SHA-256 of the exact manifest bytes, and
  the browser gained `assetManifestIntegrity: 'sha256-<hex>'` to reject a
  substituted manifest before any key or variant URL is trusted, plus
  `assetIntegrity: 'auto' | 'require' | 'off'` to verify each fetched
  variant against the per-variant SHA-256 recorded in the manifest. This
  detects CDN/object-store tampering or mixed deployments between build
  and browser; it does not make a public manifest confidential.
- `Archx.preloadAssets(ids, options)` (also exported as `preloadAssets`):
  warms the manifest and browser HTTP caches for `{ assetId }` sources
  without mounting viewers, so hero images and next-slide detail views skip
  the network at first paint. Per-id outcomes are reported instead of
  throwing, and Save-Data connections are skipped when `networkAware` is on.
- Network-aware sampling: with `networkAware: true` (now in the
  `catalog`/`gallery` presets and gallery loader defaults), a Save-Data
  preference or a slow `effectiveType` (Network Information API,
  Chromium-family) caps DPR/oversampling and numeric request quality so
  constrained users receive a materially smaller derivative. Browsers
  without the API keep the configured sampling; an explicit `lossless`
  request is never silently downgraded.
- `<archx-image>` attributes for the new options: `network-aware`,
  `asset-integrity`, and `asset-manifest-integrity`.
- Build hygiene: `npm run build` now emits `dist/archx.min.js.sri`
  (a `sha384-…` Subresource Integrity pin for CDN-hosted bundles), a new
  `npm run lint` syntax gate runs `node --check` over all shipped/test
  sources (wired into `npm run verify` and CI), and Dependabot groups
  minor/patch updates.

### Changed

- Derivative-cache accounting is more precise: `handler.stats().derivativeCache`
  now reports `coalesced` (requests that joined an in-flight cold transform
  through singleflight stampede protection) separately from `misses`, which
  counts only the request that actually ran the Sharp job.
- The demo server serves content-hashed `.archx` files with
  `Cache-Control: public, max-age=31536000, immutable` (the documented CDN
  policy); manifests and all other files still revalidate.

## [1.6.0] — Unreleased

### Added

- A scale path for image-heavy catalogs: canonical server/client width
  buckets, a `catalog` browser quality profile and preset, batch token
  minting at `POST {basePath}/tokens`, and gallery mint coalescing ahead of
  the bounded payload/decode limiter.
- Persistent derivative reuse after the normal authorization/replay checks:
  process memory, an optional bounded private disk cache, and the optional
  shared state-store cache, with secret-free derivative-cache statistics.
- `withCatalogThroughputDefaults()` for reusable catalog derivatives:
  WebP q88, canonical widths, faster encoder/resampling settings, larger
  bounded caches, image-scoped baked marks when marks are enabled, and
  explicit Sharp job/thread controls.
- A precomputed responsive-asset builder at
  `@archnemix/image-protection/build` and an `archx-build` CLI. It emits
  incremental, immutable `.archx` variants plus a version-1 manifest for
  static/CDN hosting; the browser can load them with `{ assetId }`,
  `Archx.load.gallery()`, or `<archx-image asset-id>`.
- Browser `httpCache`, `assetHttpCache`, `fetchPriority`, canonical
  `sourceWidthBuckets`, and bounded shared manifest caching for static and
  catalog delivery.

### Changed

- Gallery/catalog defaults now use device-pixel sampling, canonical widths,
  static rendering, decoded-bitmap unloading with retained payloads, batch
  minting, and no resize reminting.
- Server image processing exposes WebP effort/smart-subsample, resize-kernel,
  PNG/JPEG encoder, and Sharp performance controls without changing the
  historical quality-first defaults.
- Batch mint items each consume token-rate budget, including malformed or
  unknown IDs, so the batch envelope cannot amplify enumeration for free.
- The static asset builder fails closed without a usable scramble key and
  keeps encrypted repeat builds incremental by reusing the manifest AES key
  when `ARCHX_AES_KEY` is not supplied.

### Performance notes

On the repository's 1408×768 demo master, catalog q88/effort-2 produced a
960 px derivative in about 57 ms/170 KiB versus about 144 ms/249 KiB for
quality-first q95 in the local benchmark. The Chromium gallery regression
paints 100 images using two batch mint requests and no single mints. These
are local regression measurements, not a substitute for staging capacity
tests with the host authorization database, state store, TLS, and CDN.

## [1.5.0] — Unreleased

### Added

- Configurable 60 Hz-first temporal interlace with checker, pixel, strip,
  and randomized-block phase layouts.
- Selectable temporal-interlace drawing engines: WebGL fragment shader or
  pre-rendered Canvas2D phase frames, plus an automatic mode.
- Sender-constrained token redemption using an ephemeral, non-extractable
  browser P-256 proof key.
- Header-carried payload tokens against clean payload URLs by default.
- Optional 64-bit perceptual soft-binding fingerprints for offline
  attribution workflows.
- Strict BMP screenshot decoding in the `archx-detect` investigation path.
- Security policy, Dependabot configuration, Node 20/22 CI, and a dedicated
  reviewer guide.
- Pluggable state-store interface for atomic one-time claims, rate windows,
  quotas, distinct-image tracking, and an optional shared derivative cache;
  declared multi-instance deployments fail startup without shared state.
- Versioned signing-key rotation with token `kid`, an active/previous
  keyring, and issuing-key derivations during rollover.
- Versioned structured security-event fields for SIEM forwarding while
  retaining the existing event types and top-level compatibility fields.
- Operations, compliance-readiness, compatibility, and plain-language
  IP-holder guides, plus a bounded mint+redeem load-test tool.
- `withHardenedProductionDefaults()` and
  `auditArchxProductionConfig()` for deploy-time production-readiness
  checks that flag query tokens, non-required proof of possession,
  reusable tokens, missing shared state, and unregistered StegoMark
  issuance.
- First-class buyer/order leak tracing through `buyerId`, `orderId`,
  `deliveryId`, and `traceId` authorization fields, signed trace hashes,
  watermark placeholders, richer `onStegoIssue` records, metadata-only
  `onDelivery` events, and a key-free `onProvenanceIssue` hook for
  external C2PA/provenance workflows.
- A `robust` StegoMark profile with larger macro-cells, a redundant
  96-bit codeword, median voting, syndrome-guided correction, detector
  `profile:'auto'`, CLI profile controls, and regression coverage for
  resize/JPEG, ordinary edits, and a photographic center crop.
- A bundled Redis/Valkey-compatible state-store adapter at
  `@archnemix/image-protection/redis`, using `SET ... NX PX` claims and
  single-key Lua scripts for atomic windows and distinct-image tracking.
- Detailed browser integrity reporting, early-load integrity snapshots,
  sanitized `Archx.on()` telemetry, per-instance `onEvent`, and a
  `Archx.use()` plugin surface for monitoring integrations.
- A harsher three-phase `fortress60` temporal-interlace profile.

### Changed

- Server requirements are Node.js `>=20.9.0` and Sharp `^0.35.5`.
- Server configuration and authorization results are validated strictly and
  fail closed when ambiguous, misspelled, weak, or unsafe.
- Token, payload, image-container, response, and decoded-image handling now
  enforce explicit byte, dimension, pixel, channel, output, and time
  budgets.
- Proxy IP handling uses the socket address unless an exact trusted-hop
  configuration selects an `X-Forwarded-For` value from the trusted side.
- Cache-deception controls now cover standard, CDN, and surrogate cache
  headers for token and payload responses.
- **Breaking server default:** query-string payload tokens are disabled
  unless `allowQueryTokens:true` is explicitly selected for legacy
  clients. `token.url` is now the clean URL by default; redeem
  `token.token` in `X-Archx-Token` against `token.cleanUrl`.
- Browser integrity auditing now covers WebGL/WebGL2 texture,
  framebuffer, shader/program, draw, and readback methods; invalid
  client `integrity` values fail closed, and the WebGL renderer invokes
  its captured `drawArrays` reference.
- `scrambled` extraction decoys are downscaled to destroy detail and
  visibly marked before tile scrambling; shadow viewers prefer
  constructable stylesheets where supported.
- StegoMark CRC evaluation and robust repair are substantially faster,
  while the standard profile remains backwards-compatible.

### Removed

- Public generic token signing/verification helpers.
- `handler._test` and the live `handler.index` surface.
- Weak-secret test bypasses and other fail-open compatibility paths.

### Security notes

Archx remains layered theft friction and attribution, not DRM. The server
must keep masters outside public roots and enforce `authorize()` at both
token minting and redemption. Displayed pixels can still be captured by an
authorized recipient, operating system, browser-privileged tool, or camera;
see `SECURITY.md` and `docs/RESEARCH.md` for the full model.
