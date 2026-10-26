# Changelog

All notable changes to Archnemix Image Protection (`Archx`) are documented
here. The project follows semantic versioning once a version is released.

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
