# Changelog

All notable changes to Archnemix Image Protection (`Archx`) are documented
here. The project follows semantic versioning once a version is released.

## [1.13.0] — Unreleased

Third external adversarial-review response (claim-by-claim verification
in `docs/RESEARCH.md` §2.21). Seven bug groups were raised against
1.12.0; all confirmed items are fixed with regression tests, one claim
did not reproduce, and the seven optimization proposals were decided on
measurements (three implemented, three rejected/deferred with numbers,
one documented as a knob).

### Security

- **Per-viewer visible watermarks can no longer leak across viewers.**
  The shared derivative-base cache held a watermarked base under a
  viewer-independent key; watermarks are now applied only in the
  per-token finishing stage and cached bases are always clean.
- **Canonical client-IP identity.** IPv4-mapped/translated IPv6 forms
  and alternate IPv6 spellings collapse to one identity for token IP
  binding, quotas, rate limits, and abuse detection — re-spelling an
  address no longer mints a fresh budget.
- **128-bit stego layout and forensic sign seeds.** StegoMark cell
  layouts (`layoutVersion: 2`) and forensic block signs
  (`signsVersion: 2`) now derive from 128-bit SHA-256 seeds instead of
  enumerable 32-bit hashes. Detectors/scoring dual-read v1 marks
  bit-exactly and report the matched vintage. Identity→fingerprint
  derivation for non-hex payloads moved to SHA-256;
  `legacyStegoFingerprint()` preserves pre-1.13 lookups, the detection
  CLI accepts either derivation for `--expect`, and issued registries
  plus 12-hex payloads are unaffected.
- **Robust decoder accepts only observed tag bits.** Syndrome repair
  no longer synthesizes acceptance-tag bytes when ranking candidates
  (a latent flaw that could mislabel legacy CRC marks as `mac` and
  starve the CRC fallback); tag-region agreement must be observed
  within a 2-flip vote-error allowance.
- **Keyed shifted-wrap scramble padding.** Mirror padding's
  palindrome seam (an oracle for keyless tile solvers) is replaced by
  a plan-keyed toroidal wrap of interior texture plus keyed noise, in
  both the core fused pass and the client's local canvas scrambler.
  Displayed pixels still round-trip byte-exactly; derivative cache
  namespace bumped to `v4`.
- **Visible watermarks tile on both axes** (server SVG, client 2D
  bake, client WebGL texture): measured-width steps with alternating
  row offsets, so cropping no longer deletes attribution by bands.
- **Tiered distinct-IP abuse detection**, quota/abuse accounting after
  host authorization callbacks, one shared RAM budget for master+base
  caches, any-of-keyring shared-cache tags, cache-clearing `close()`,
  and most-restrictive-wins Sharp loader policy (later stricter
  configurations re-block loaders).

### Performance

- **Detector rewrite (Opt A).** Integral-image (summed-area) cell
  statistics replace strided sampling — exact full-population means,
  strict-superset recovery in A/B testing (4 extra weak-mark
  recoveries, 0 losses, 0 false positives) — plus scratch-buffer
  reuse, an arithmetic repair pre-gate, outcome-identical depth caps,
  and a marker prefilter before MAC evaluation. Unmarked
  auto+geometry search: 32s → 6.0s; 90%-crop recovery: 5.3s → 1.5s
  (800px reference). Geometry scale candidates are also deduplicated
  at 0.001 precision instead of 0.1.
- **Perceptual fingerprint ~1.45× faster, bit-identical output**
  (precomputed overlap spans + static DCT basis).
- Integrity audit no longer allocates a stream per call; dead
  contain-fit math removed from the WebGL presenter.

### Notes

- Cascading builder resize and a native-HMAC backend were measured and
  rejected/deferred with numbers in §2.21; WebP effort stays 4 by
  default with `processing.webpEffort: 2` documented for CPU-bound
  fleets (−24% encode time, +1.7% bytes).
- 84 Node tests (4 new), 108 Chromium checks, fuzz + type suites in
  `npm run verify`.

## [1.12.0] — Unreleased

Second external adversarial-review response (claim-by-claim verification in
`docs/RESEARCH.md` §2.20). Eight file-level findings were raised against
1.11.0; each was reproduced or refuted against the code before fixing.
All eight real findings are addressed below, plus the feasible subset of
the proposed optimizations. Larger roadmap items (A/B tile-sheet
streaming, worker-thread pools, FFT sync templates, IIIF pyramids,
learned watermarks) are evaluated and deferred with reasoning in §2.20 —
not silently dropped.

### Security

- **Fortress no longer gifts a 2D fallback when `preserveDrawingBuffer`
  is rewritten.** If a pre-loaded `getContext` proxy forces a preserved
  drawing buffer, the attribute check now runs through the *captured*
  `getContextAttributes`, and a one-time behavioral canary (paint, hold
  two frames, `readPixels` before the next draw) catches proxies that
  also spoof the attribute report. Under `integrity: 'lock'` (fortress
  default) either signal is fatal: hard blackout instead of the previous
  untainted Canvas2D downgrade. The canary only judges frames that were
  provably presented (canvas inside the layout viewport) — a below-fold
  canvas is never composited and would otherwise false-positive.
- **StegoMark codeword v2: keyed HMAC-16 acceptance tag.** The previous
  acceptance check was a linear CRC keyed by a single derived byte, so a
  majority-vote hybrid of several buyers' marks could validate under a
  fingerprint nobody was issued (collusion framing). Standard codewords
  now carry a 16-bit truncated HMAC-SHA256 over the 48-bit fingerprint
  (domain-separated, shared stego key) in place of the public CRC;
  robust codewords keep their first CRC purely as a repair oracle and
  carry the MAC in bytes 8–9. Detection stays O(1)-per-suspect under
  the image key — no `keyScope:'viewer'` O(N) scan needed. Results
  report `tagScheme: 'mac' | 'crc' | null`; legacy CRC decodes are
  still detected but under tightened gates (robust ≤3 corrected bits,
  standard ≤1 flip with ≥0.95 agreement) and the CLI prints a
  corroboration warning. `legacyCode: true` reproduces old codewords.
- **Core crypto no longer touches page-visible primitives.** The shared
  core (`src/scramble.js`) gains pure-JS `sha256Bytes`/`hmacSha256Bytes`
  (verified byte-identical to `node:crypto`) and a `useWebCrypto()`
  injection point: the client hands over boot-captured SubtleCrypto
  methods and every core encrypt/decrypt/digest/importKey call runs
  through them with the correct receiver. Raw AES key bytes are zeroed
  after import. The client also captures and routes `reader.read`,
  `Response.text`, and `TextDecoder.decode` (shared fatal decoder for
  bounded JSON) — closing the "captured at boot, but the sensitive call
  still used the live global" gap for streaming, DPoP, and hashing.
- **Paced lens stitching is now counted cumulatively.** The lens keeps
  a 120-second last-visit ledger over an 8×8 coverage grid; sweeping
  ≥56 of 64 cells inside the horizon raises `lens-scan` even when each
  burst stays under the 8-second threshold (`scanCellsCumulative`
  tunable). Lens radius also jitters ±6% (re-rolled ≤4×/s) so stitched
  frames no longer share an exact disc geometry.
- **Temporal shield resists order-independent medians.** The shader
  path adds an asymmetric-duty spatial bias (duty cycle
  [+2⁄3, −1⁄3, −1⁄3] at 24px blocks, amplitude 0.55×strength, bias
  seed re-rolled every ~90 temporal frames): the per-pixel *mean* is
  still exact for the viewer, but a sample *median* of captured frames
  converges to a block-varying wrong value that keeps moving. Long
  averaging still converges to the displayed image — that is inherent
  to anything a person can watch, and remains documented as such.
- **IPv6 /48 rotation + limiter eviction churn.** IP-keyed limits now
  apply two tiers — the /64 at the configured limit and its /48 at 4× —
  checked narrow-first, so rotating through a routed /48 no longer
  multiplies the budget (distinct-image abuse tracking stays /64).
  The sliding-window limiter pins blocked entries: cache churn evicts
  unblocked entries first, so an attacker can no longer flush their own
  block by flooding the table with fresh identities.

### Fixed

- **Mirror+crop blindspot in StegoMark detection.** `searchMirror`
  (new, default `true`) probes a horizontally flipped copy for *all*
  profiles — previously only `auto`+geometry did — and the flipped
  probe inherits `searchOffsets`/`searchGeometry`, so flip+90%-crop
  suspects recover in explicit standard and robust modes too.
  Asymmetric heavy crops (~82%) still defeat cell voting; that needs
  sync templates/registration (v2 roadmap, §2.20).
- **Edge-replicate padding leaked a row-duplication oracle.** Pad rows
  were exact copies of the edge row (100% duplicated rows on a
  gradient probe), handing tile-edge solvers free boundary matches.
  Padding is now interior reflection with a deterministic ±1 dither on
  pad pixels only (<5% exact-duplicate rows). Displayed pixels are
  unchanged and old payloads still decode — the client crops the pad
  either way, so this is wire-compatible across versions.

### Performance

- **Two-stage derivative pipeline.** `scrambleImage` is now
  `prepareDerivativeBase` (decode/resize/watermark → raw base) +
  `finishDerivative` (mark/scramble/encode/encrypt), byte-identical
  output. The middleware caches bases (byte-bounded LRU, capped by
  `masterCacheMaxBytes`) for derivatives that can never output-cache —
  per-token/per-viewer variants skip the decode+resize on every hit.
  `stats` reports `baseCacheEntries`/`baseCacheBytes`.
- **Redis binary mode.** When the client is binary-capable
  (`getBuffer`, or node-redis `commandOptions({ returnBuffers: true })`
  shape), cache values are stored as raw Buffers instead of `b64:`
  armor (≈33% smaller, no encode/decode per hit). Legacy-armored
  entries still decode; mixed fleets self-heal through the existing
  HMAC entry tags.
- **WebGL contexts are released off-screen.** Viewport unload now
  loses the GL context on purpose, returning its slot to the browser's
  active-context budget; the restore path re-runs the one-time canary.
- **Temporal idle throttle.** A continuous temporal loop with no
  pointer activity over the instance for 5 s draws 1 frame in 3
  (~20 Hz at 60 Hz panels) — modulation (and its capture friction)
  continues at a third of the GPU/battery cost; any interaction
  restores full rate. It never fully stops: a static frame would be
  a free clean capture.

### Compatibility

- Detectors **older than 1.12 cannot read marks embedded by 1.12+**
  (the acceptance tag changed) and may report spurious "repaired"
  decodes on them: upgrade detection tooling first. 1.12 reads legacy
  marks and flags them (`tagScheme: 'crc'`).
- Stego derivative cache keys gained a `:tm` (tag-migration) suffix:
  stego-bearing derivatives regenerate once after upgrade.
- Client bundle: 133.9 KiB minified / 43.3 KiB gzipped (+10.6/+3.2 KiB
  vs 1.11 — inline SHA-256/HMAC, canary, lens ledger, duty bias).

## [1.11.0] — Unreleased

External adversarial-review response (full verification matrix in
`docs/RESEARCH.md` §2.19). The review's real server bugs are fixed; its
client-side bypasses that are fixable in-page are mitigated; the rest is
documented as measured, named residual risk.

### Breaking (security)

- **StegoMark embedding now requires an explicit, dedicated `stegoKey`.**
  `scrambleImage`, `buildArchxAssets`, and the CLIs previously defaulted the
  forensic layout key to the tile-scramble key — which is *public* wherever
  browsers unscramble (e.g. printed in static-build manifests) — letting
  anyone detect, subtract, or forge marks. Embedding with a payload but no
  `stegoKey`, or with `stegoKey === key`, now throws. The middleware fleet
  path already derived a secret key per image and is unaffected. Marks
  embedded under the old default should be treated as unkeyed: rotate by
  re-issuing derivatives with a dedicated secret.
- **Scramble padding is now edge-replicate, not black.** The opaque-black
  pad let keyless solvers identify every boundary tile (and its flip) for
  free. Displayed pixels are unchanged (browsers crop the pad), but padded
  derivatives regenerate (middleware cache namespace bumped to `v3`; static
  builds re-hash naturally). The client-side local scramble matches.
- `withHardenedProductionDefaults()` now sets `encrypt: true` (AES-256-GCM
  per response). Unencrypted scrambled payloads are reassemblable by
  tile-edge "jigsaw" solvers without any key; scrambling is obfuscation,
  encryption is the secrecy layer. `configAudit` now warns when
  `encrypt` is off or the v1 (32-bit-seed) plan is in use. (Deliberate
  opt-outs in host options still win.)

### Fixed

- **Redis shared cache corruption with node-redis v4 defaults.** String
  GETs UTF-8-mangled binary derivatives (bytes ≥ 0x80) so every shared read
  missed. Cache values are now base64-armored (`b64:` prefix, ≈ +33–37%
  storage); legacy entries degrade to HMAC-tag misses and self-heal.
- **Quota burn by malformed requests.** Token minting now validates the
  request shape (width syntax/bounds, box params, entitlement width)
  *before* any quota counter moves, and quota dimensions are checked
  narrow→wide with early exit. Junk `?w=` traffic can no longer starve a
  victim IP's budget, and exhausted narrow limits stop inflating wider ones.
- **SIEM alert storm.** The suspicious-scraping alert now latches: it fires
  once per client per detection window (the deny action keeps enforcing).
  One scraper can no longer mint an alert per request.
- **IPv6 rotation evaded every IP-keyed control.** Rate/quota/distinct keys
  now group IPv6 clients by /64 prefix (token IP *binding* deliberately
  keeps the exact address).
- **Per-token derivatives polluted shared caches.** Per-token scramble keys,
  per-token forensic seeds, and per-token stego now skip RAM/disk/Redis
  output-cache reads and writes entirely (unique bytes were evicting the
  reusable majority and could never hit).
- **StegoMark `{found:false, confidence:0.99}`.** Confidence is capped at
  0.49 whenever `found` is false; it no longer presents a negative verdict
  as near-certain to attribution tooling.

### Security / forensics

- `steganography.keyScope: 'viewer'` (opt-in): per-viewer layout keys so
  colluding buyers' copies no longer align cell-by-cell — averaging can
  still erase marks but cannot majority-vote a third party's phantom
  fingerprint. The issuance registry records the scope. `archx-detect`
  warns prominently on repaired decodes (corrections > 0) and the JSON
  output carries `repaired`/`evidenceNote`.
- Detection: mirrored (flopped) suspects are recovered automatically
  (`profile:'auto', searchGeometry:true` → `mirrored:true`); geometry
  search gained quarter-point origins, fine scale refinement, and a
  native-resolution offset roam (±4 cells). Rotation/warp remain
  unsupported — measured limits documented in RESEARCH §2.19.
- Client: `JSON.parse`, `Element.attachShadow`, and
  `ReadableStream.getReader` are captured at load and *used* on sensitive
  paths (container headers carry AES keys; a hooked attachShadow could
  downgrade closed roots), and audited. The vault verifies
  `getContextAttributes().preserveDrawingBuffer === false` after context
  creation and fails closed. Observed hook defeats against proxies,
  CDP-level capture, and same-origin untainted canvas reads remain
  documented residual risks.
- Temporal shield/interlace no longer uses fixed algebra: per-frame noise
  re-seeding, amplitude jitter, shuffled phase order, and balance-corrected
  random signs replace the deterministic `{c, c+d, c−d}` cycle whose
  6-frame median was exactly `c`. (Long captures still average out — cost
  raised, not a wall; see SECURITY.md.)
- Lens anti-stitching accounting counts every cell the revealed disc
  touches (8×8 grid) instead of only the center cell; default threshold
  recalibrated (26/36 → 46/64).
- Client events: `archx-taint-unavailable` (shield/lite without a
  cross-origin taint pixel), `archx-webgl-budget` (8-context budget forced
  a 2D fallback), `archx-integrity` (rewritten context attributes).

### Performance

- Hot path: 1 s TTL cache for indexed-master realpath/stat; DPoP public
  keys cached by JWK thumbprint (bounded). Bench vs v1.10: payloads and
  timings within noise; AES-GCM adds ≈0.5 ms per 960 px derivative.

## [1.10.0] — Unreleased

Industry-standard hardening round: `docs/STANDARDS.md` now maps every control
to the external standard it answers (OWASP API Top 10 2023, RFC 9111, NIST
key management, C2PA, OpenSSF/supply-chain, WCAG) with an honest Met/Partial
status. Default (plan v1) derivative bytes are byte-identical to v1.9.0
(verified against the released implementation), and `npm run bench:opt`
shows payloads unchanged with all timings within noise.

### Security

- **Derivative-cache entry integrity.** Disk and shared-store cache entries
  now carry an `A1` + 32-byte HMAC-SHA256 tag over key + bytes under the
  server secret. A cache writer without the secret (a compromised cache
  host, a rogue bucket user) can no longer substitute a structurally valid
  forged derivative; forged or legacy untagged entries silently become
  misses and regenerate (one-time re-warm, no correctness risk).
- **Scramble plan v2 (128-bit seed).** `buildScramblePlan(grid, key, 2)`
  derives the tile permutation from cyrb128 + sfc32 (128-bit state) instead
  of the legacy 32-bit seed, so the permutation of an *unencrypted* payload
  is no longer recoverable by seed brute force in seconds. Opt-in via
  middleware `scramblePlanVersion: 2` (set by
  `withHardenedProductionDefaults`), builder `planVersion` /
  `--plan-version`, CLI `--plan-version`, and client `planVersion` for
  container-less sources; containers self-describe via header `pv`. Plan v1
  output is byte-for-byte unchanged. Roll out client-first: pre-v1.10
  clients cannot unscramble v2 payloads. Scrambling remains obfuscation —
  AES-256-GCM (`encrypt: true`) is the secrecy layer.
- **StegoMark false-positive gates.** Fuzzing found that the standard
  profile could, on tiny unmarked noise, manufacture a CRC-valid candidate
  by flipping near-zero-reliability bits (confidence up to 0.82 on random
  pixels — a false-attribution risk). Detection now requires dense evidence
  (≥3 cells/bit average, ≥2 for every bit) and demands clearly genuine raw
  signal whenever 2+ bits need repair; 3,000 seeded noise scans now produce
  0 false positives while the full robustness matrix still passes. Results
  also expose `minBitRepetitions` for investigators.
- **Deadline-bounded batch bodies.** Streamed batch-token request bodies
  are now bounded by `callbackTimeoutMs` (returns 408), closing a
  slow-trickle connection-holding gap that the byte cap alone did not
  cover.
- `stats().signingKeyCount` previously always reported 0 (counted a `Map`
  incorrectly); fixed.

### Features

- **AVIF derivatives** (`format: 'avif'`, `processing.avifEffort`,
  `processing.avifChromaSubsampling`): ~40–55% smaller than WebP on
  scrambled tiles at comparable quality (76 vs 171 KiB measured at 960 px),
  at 8–70× the encode CPU — intended for precomputed `archx-build`
  catalogs; requires an AVIF-capable browser (Safari 16.4+/Chrome 85+/FF
  113+).
- **TypeScript declarations** ship for all five entry points
  (`.`/`server`/`build`/`redis`/`scramble`) with a `tsc --noEmit` smoke
  test (`npm run test:types`) in CI and `npm run verify`.
- The taint pixel (`{basePath}/taint.png`) now answers conditional requests
  with `ETag`/`304` while remaining deliberately non-CORS.

### Supply chain / CI

- CodeQL workflow (javascript-typescript, security-extended queries,
  weekly schedule) — its first run flagged 7 alerts: four stat→read
  filesystem races (fixed with fstat/handle-based reads in the disk
  cache, both CLIs, and the build SRI step) and three "user-controlled
  bypass" flags on the token shape pre-check (restructured so the HMAC
  verification result is the only gate; behavior unchanged). Zero open
  alerts. Dependabot (npm + GitHub Actions), and an OIDC
  trusted-publishing workflow with automatic npm provenance (operator
  configures the npm trusted publisher once). CI also runs the type smoke
  test and the seeded fuzz suite (`tests/fuzz.test.mjs`, part of
  `npm test`): 61 Node tests, 107 real-Chromium checks.

### Performance

- Shared `TextEncoder`/`TextDecoder` instances in the core (one fewer
  construction per sniff/container decode); local decoy/texture scrambles
  use the 128-bit plan (free, ephemeral). Bench vs v1.9: identical
  payloads, timings within noise, bundle +1.1 kB (+0.4 kB gzip).

## [1.9.0] — Unreleased

Measured optimization round: every change below was benchmarked before and
after on the same 2-vCPU machine (`npm run bench:opt`, interleaved A/B
against v1.8.0). WebP/JPEG output bytes are unchanged (21/21 fixture
hashes identical); the only output that changes is PNG, which gets
smaller with identical decoded pixels.

### Performance

- **Fused pad+scramble+encode input.** New `scramblePixelsPadded()` core
  primitive writes the padded, scrambled frame directly into the encoder's
  raw input buffer in one pass, replacing pad-copy → scramble-copy →
  `Buffer.from` copy. A unit test pins byte-equality with the old two-step
  path across awkward sizes/grids, including provided-buffer use.
- **Skip EXIF autorotate when absent.** `scrambleImage()` now calls
  Sharp's `.rotate()` only when the master carries an orientation other
  than 1; output is re-encoded from raw pixels either way, so no metadata
  can leak through the skip.
- **Drop the synthesized alpha band for opaque masters** before WebP/PNG
  encoding. PNG payloads shrink ~11–13% and encode ~34% faster at 960 px;
  WebP encode saves ~6% (libwebp no longer analyzes a uniform alpha
  plane). Masters with real alpha are untouched.
- **In-place sliding-window pruning.** `SlidingWindowLimiter` front-prunes
  expired timestamps with one splice instead of a `filter()` copy on every
  hit/cleanup. Warm loopback mint+redeem throughput rose from 859 to
  915 flows/s over 6,000 requests (p50 21.3 → 20.3 ms) in back-to-back
  A/B; the earlier same-shape pair measured 772 → 881 flows/s.
- Cold transforms overall: ~3–10% faster across the 640–1600 px
  quality/catalog matrix in interleaved A/B (encode remains the dominant
  cost and is user-tunable via `processing` profiles); peak transform RSS
  a few MB lower per 1600 px job. Evaluated and rejected: raising the
  bundle target to es2022 (−1.4 kB gzip for a higher browser floor).

### Tooling

- `npm run bench:opt` (`tools/optimization-bench.mjs`): repeatable
  before/after harness covering cold-transform wall/CPU/peak-RSS/payload,
  scramble throughput, warm throughput, batch-mint latency, and Chromium
  time-to-paint phase timings, 100-image gallery wall/requests/heap, and
  bundle sizes, with JSON output and a `--compare` delta table. Uses the
  new inert `demo/perf-bench.html` so animated demo instances cannot
  pollute timings.

### Tests

- 48 Node tests (new fused-scramble equality proof) and 104 Chromium
  checks.

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
