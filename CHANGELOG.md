# Changelog

All notable changes to Archnemix Image Protection (`Archx`) are documented
here. The project follows semantic versioning once a version is released.

## Unreleased

- **npm `bin` path normalization**: CLI bin targets in `package.json` no
  longer use `./` prefixes; current npm rewrites/removes such entries during
  publish (observed as “script name … was invalid and removed”), which could
  drop `archx-protect`, `archx-build`, and `archx-detect` from the published
  manifest. No runtime code or payload format change.

- **Test-suite Windows portability** (no shipped-code change; tests are not
  in the npm artifact): three tests derived the repo root from
  `new URL(import.meta.url).pathname`, which on Windows yields `/F:/...`
  and resolved to doubled-drive paths (`F:\F:\...`) — now via
  `fileURLToPath`, matching the rest of the suite; CLI subprocess tests
  spawn `process.execPath` instead of relying on `node` PATH lookup; the
  symlink-escape fixture skips its sub-check when Windows refuses file
  symlink creation without Developer Mode/elevation (EPERM) instead of
  failing the test. Result: 138/138 on Windows (was 134/138) and Linux.

- **Website, now multi-page** (not part of the npm artifact; no library
  version change): the overview hero gained drag-orbit, per-tile raycast
  tracing, and 4×4/8×8/16×16 grids; a new **technical decision atlas**
  documents all 21 engineering decisions (problem / chosen / alternatives
  rejected / pros / cons / measured evidence) with five live widgets —
  a bit-exact port of the scramble-plan builder (60/60 parity against
  `src/core/plan.js`), a WebCrypto token explorer including the canonical
  base64url malleability gate, a replay-saturation sizing calculator, a
  BCH errors/erasures recovery map, and the measured StegoMark survival
  chart; a new **threat-model page** with an eight-attacker interactive
  matrix and explicit "choose something else" guidance. All interactions
  browser-verified (zero console errors), lint now covers 63 files.

## [1.22.0] — 2026-10-31

Large-payload optimization pass + red-team expansion
(`docs/RESEARCH.md` §2.30). No format, API, or output-byte
changes anywhere: every optimization is probe-verified
byte-identical (135 hash cases + golden freeze + payload sizes).

### Performance (measured at 6000×4000 / 24 MP)

- `flipPixels` word-level paths: 152 → 54 ms (mirror),
  157 → 69 ms (180°).
- `rotatePixels90` / `transposePixels` cache-tiled word scatter:
  ~270 → ~140 ms.
- `applyForensicBlocks` two-LUT clamped-add: 238 → 150 ms.
- `perceptualFingerprint`: flattened span tables, opaque-pixel
  fast path, (w,h)-keyed weight-sum cache: 301 → 259 ms.
- `buildLumaIntegral` fused single pass; `resampleRgba`
  precomputed column parameters; `rotateRgba` hoisted row terms.
- Derivative encryption no longer copies the ciphertext
  (zero-copy Buffer view); native `toBase64`/`fromBase64`
  fast paths where the runtime provides them.
- Unmarked-image detect screen at 2400px: 562 → 430 ms.
- One measured non-win was reverted (rotateRgba interior-row
  clamp skipping: branch cost exceeded clamp savings).

### Added

- **Red-team section H** (55 cases total, **53/53 scored
  defenses held**, 2 informational): 16-way one-time-token
  redemption race (exactly one winner), method confusion on
  mint/redeem routes, If-None-Match/Range side doors, duplicate
  token-header smuggling, structural token fuzz, validly-signed
  claim fuzzing (insider-secret depth), keyring `kid` confusion,
  batch abuse shapes (2000 items → 413), slow-trickle body
  deadline, CRLF header injection, cache-deception suffixes,
  distinct-image scrape quota (4th distinct image → 429),
  proof-of-possession battery (bearer copy / wrong key / wrong
  target / proof replay), authorize garbage shapes, derivative
  cache width-confusion probe, harsher stego removal chain
  (median+noise+0.55×+q38: still correct attribution, never a
  wrong one), and a MAC timing-oracle measurement
  (1.02 vs 1.01 ms medians — no signal at HTTP granularity).

## [1.21.0] — 2026-10-31

Final completion round (`docs/RESEARCH.md` §2.29): permissive
relicensing, a red-team attack suite, measured everywhere.

### Changed

- **License: MIT → 0BSD** (BSD Zero Clause). Use, copy, modify and
  distribute for any purpose, with or without fee; attribution is
  appreciated but explicitly not required.
- **Token verification hardening**: non-canonical base64url
  re-encodings of a valid token are now rejected (base64url slack
  bits previously let up to four distinct strings carry the same
  MAC), and single-secret verification authenticates before
  parsing claims. One-time-claim semantics unchanged.
- **Config-audit parity**: `auditArchxServerConfig` now flags
  masters/output-cache directories that overlap a configured
  public directory — previously only middleware startup caught
  this, so a preflight audit could report `ok` for a config the
  server would refuse to start.
- **Modularity**: the collusion assay moved from
  `src/core/stego-detect.js` to `src/core/stego-assay.js` (public
  export paths unchanged); duplicate path helpers in
  `server/build-assets.js` deduplicated into `server/config.js`;
  orphaned documentation blocks and unused imports removed.

### Security

- Dev-dependency advisory closed during the ship run:
  `follow-redirects` (via `@sparticuz/chromium`, test-only)
  1.16.1 → 1.16.2 for GHSA-mrwp-f3q8-3g9p; `npm audit` is clean.
  The published package has zero runtime dependencies and was
  never exposed.

### Performance (byte-identical outputs, probe-verified)

- Scramble mirror rows now copy+reverse natively:
  `scramblePixels` 1080p 5.67 → 3.2 ms in the repo bench.
- StegoMark embed inner loop restructured around per-cell clamp
  tables and precomputed band ranges: 960×640 10.4 → 9.2 ms.
- End-to-end cold transforms are Sharp-bound and unchanged within
  noise; payload bytes identical before/after.

### Added

- **`npm run redteam`** — `tools/red-team.mjs`, a 36-attack
  adversarial suite against a live hardened server (token forgery/
  tampering/replay/malleability, sender binding, entitlement and
  width-cap escapes, batch-IDOR, fail-open config probes,
  prototype pollution, traversal/symlink escapes, malformed-image
  and pixel-bomb handling, concurrency/mint floods, cache-header
  and error-body hygiene, wrong-key/collusion/denoise stego
  attacks). Result at ship time: **36/36 defenses held**, 1
  informational. The suite found and fixed the two issues above.
- **`website/`** — the static Archnemix product site: editorial
  paper design, a WebGL tile-scramble hero that scrambles the way
  the real payload does, measured-numbers page copy, no build step
  and no third-party JavaScript (Three.js vendored).

## [1.20.0] — 2026-10-31

Critique response (`docs/RESEARCH.md` §2.28): a measured answer to
the four post-release concerns about StegoMark recovery, the
28.6 dB robust PSNR, replay-saturation policy, and the
Node/Puppeteer floor. Headline: a new opt-in BCH codeword layout
with a four-rung decode ladder, two-phase auto-detection, and
byte-frozen layouts 1–3 (golden-hash regression test).

### Added

- **StegoCode layout version 4 (opt-in, `steganography.layoutVersion: 4`)**:
  shortened BCH(188,64) code (48-bit fingerprint + keyed MAC-16 +
  124 parity, key-seeded interleaving, guaranteed radius 2e+s ≤ 36)
  over the unchanged v3 cell layout, with a gentler texture-cap
  amplitude curve. Detector ladder: bounded-distance decoding →
  ML erasure solve (recovers with 70/188 bits erased) → OSD-1/2
  reprocessing → inline information-set decoding → deep forensic
  ISD over the strongest failed candidates. Deterministic
  (input-seeded) sampling throughout. Requires a v1.20+ detector;
  layouts 1–3 remain the default and are byte-identical to v1.19.
- **Two-phase auto-detection**: native screens for all layouts
  before geometry searches, with the time budget sliced fairly
  across layouts; fast dihedral (mirror/rotate/transpose) screens
  now run before the geometry sweep (13.9 s → 0.6 s class).
- `archx-detect --max-time-ms` and `--layout 4`; assay reports
  `layoutVersion`, gained a cells-per-codeword warning, and its
  extreme-luma diagnostic now matches the embedder (`<64`/`>191`).
- `.nvmrc` (Node 22 for contributors/browser suite).

### Changed

- `hardened` preset now selects replay saturation `strict`
  (explicit host choice still wins); OPERATIONS documents the
  evict-vs-strict decision. Neither policy replaces sizing.
- Bench corpus distinguishes realistic rendered `text` documents
  from the adversarial `text-periodic` class.

### Measured

- Same-detector A/B at strength 6 (99 cases/profile):
  robust v4 84/99 vs v3 85/99 (photos 30 vs 33, graphics 33 vs
  31, flat/text tied), standard tied at 63/99, FP 0/369, PSNR
  +1.4 dB photos / +0.7 graphics / +1.2 documents.
  v4 therefore ships opt-in rather than as the new default.
- Realistic text documents recover under the *shipped* additive
  mark (10/11 robust incl. JPEG/crop cases); three binary-aware
  flip embeddings were built, measured worse (PSNR 15 / 12 /
  24.6–26 vs 28.9–32.9), and removed. 1-bit re-binarization
  remains a documented envelope limit.
- Puppeteer 24 pin for Node 20 evaluated and rejected: its
  `basic-ftp`/`extract-zip` chain fails the audit-high CI gate.
  The library floor (≥20.9, zero runtime deps) vs browser-suite
  floor (≥22.12) split is documented in README/REVIEW_GUIDE.

## [1.19.0] — 2026-10-30

Eighth-review response + modularity (`docs/RESEARCH.md` §2.27): ownership
trust hardening, fail-closed width fractions, mixed-TTL replay
saturation fix, step-up challenges, tamper-evident issuance log, an
embed pre-flight assay, a detect worker pool, and a full
responsibility-based module split with unchanged public paths.

### Security fixes

- **Ownership trust discipline**: unverified embedded claims no longer
  count as their own evidence; `contentTrusted` is the only act-on-it
  signal. Malformed perceptual hashes no longer crash verification,
  a decoy claim can no longer shadow a real one, and the detect CLI
  no longer reports false success (exit codes + `spawnSync`-friendly).
- **`maxWidthFraction` fails closed**: invalid values are rejected at
  startup; if master dimensions cannot be measured, minting returns
  503 instead of issuing an uncapped token.
- **Mixed-TTL replay saturation**: `BoundedTtlSet.claim()` now proves
  expired space is exhausted (full sweep) before evicting a live claim
  or strict-rejecting — expired short-TTL entries behind long-TTL heads
  no longer cause false saturation. New non-mutating `has()`.
- **Temporal canvas natives captured**: `putImageData` (and friends)
  are captured at load and audited like the other canvas natives; a
  prototype-level hook can no longer silently sit on the temporal path.

### Added

- **Step-up challenges** (`abuseDetection.action: 'challenge'` +
  `challenge.verify`): suspicious subjects get `403` +
  `x-archx-challenge: required` instead of a blunt deny; a host
  verifier (Turnstile, WebAuthn, …) grants a process-local clearance
  (`clearanceTtlSec`, default 600 s). Single and batch mints share the
  gate; the bundled client's auto-retry (`onChallenge`) covers single
  mints — batch keepers see `errors[ref].status === 403` and retry
  after solving. Verifier outages return 503, never allow.
- **Tamper-evident issuance log** (`createIssuanceLog`,
  `verifyIssuanceChain`): HMAC-chained append-only issuance records;
  edits, deletions, and reordering are detectable. Records ≤ 16 KiB;
  keep the log secret separate from the data. Not a timestamp proof.
- **Embed pre-flight assay** (`assayStegoEmbed()` +
  `archx-protect --assay [--json]`): runs the real embedder to report
  measured PSNR/max delta/content class and the minimum
  self-verifying strength per image. CLI exit 2 = no verifying
  strength (e.g. near-binary periodic graphics, the weak class).
- **Detect worker pool**: `configureStegoDetectWorker({ maxWorkers })`
  (1–16, default 1) with per-slot crash isolation and shared budgets;
  `handler.stats()`-style config reporting includes live worker count.
- **XMP rights flags**: ownership metadata now declares
  `xmpRights:Marked=True` + usage terms so stock/IPTC tooling sees the
  restriction even without the Archx claim token.
- **Faster server-side HMAC for detection** via injectable Node crypto
  (`server/node-crypto.js`, `useSyncCrypto()`), Uint32 integral images,
  and typed scratch buffers — measured as micro-wins (detector wall
  time is candidate-evaluation-bound; earlier projections withdrawn),
  with peak RSS ≈ 90 MiB on the 800×436 geometry sweep.
- Automation-signal aliases on the client (webdriver/CDP surface
  parity with the integrity report).

### Changed

- **Modular split, same public surface**: `src/scramble.js` →
  `src/core/` (12 modules), `src/archx.js` → `src/client/` (15
  modules), `server/middleware.js` → `bounded.js` / `tokens.js` /
  `config.js` + factory. `src/scramble.js` and `server/middleware.js`
  re-export everything; package exports unchanged. A runtime contract
  test now pins `types/*.d.ts` to the actual export surface.
  See `docs/ARCHITECTURE.md` for the module map and dependency rules.
- Bundle: 146.2 KiB minified / 47.0 KiB gzipped.

### Refuted / deferred (with measurements, §2.27)

- Per-call process spawn for detection (already `worker_threads`);
  755 MiB tilt RSS (measured ≈ 90 MiB); cross-tier cache poisoning via
  `variantKeyScope` (key includes the post-downgrade width).
- True tile streaming / deep-zoom stays deferred: authorized-resolution
  single-response delivery is the documented architectural limit;
  IIIF-style tiered access is the tracked design (§2.27).
- JND/DCT layout-v4 or Fourier-Mellin embedding remains R&D, not a
  patch; the Tardos bound keeps blind collusion-proof decoding out of
  reach of the 96-bit channel, so the assay framing stands.

## [1.18.0]

Seventh-review response + ownership claims (`docs/RESEARCH.md` §2.26):
packaged-artifact proof, explicit replay-saturation and preview
policies, worker/detector resource budgets, Ed25519-signed ownership
metadata with layered rescan, and a measured benchmark round.

### Added

- **Signed ownership claims** (`server/ownership.js`): Ed25519 token
  binding owner + image id + perceptual hash + stego fingerprint,
  embedded in derivative EXIF/XMP alongside chosen Copyright/Artist
  metadata. `verifyOwnership()` + `archx-detect --verify-ownership`
  rescan in three layers (signature, perceptual soft binding,
  StegoMark) — metadata-stripped leaks still identify. Middleware
  `ownership` option and `archx-protect --ownership-owner` /
  `--gen-ownership-key`. Provenance evidence, not C2PA, not title.
- **`replaySaturation: 'evict' | 'strict'`**: explicit policy for
  one-time-claim store pressure, with saturation counters in
  `handler.stats().replaySets`.
- **`maxWidthFraction`**: hard ceiling on delivered width as a
  fraction of the master's own width, enforced at mint and
  redemption; startup audit warns on lossless full-size delivery.
- **Detect-worker byte budgets**: `maxQueuedBytes`, `maxPixels`,
  `queueTimeoutMs`, pre-copy RGBA validation, batch key-byte caps.
- **Detector `maxTimeMs`**: shared wall-clock budget across all
  search layers; expired searches return best-so-far + `timedOut`.
- **`tools/pack-smoke.mjs`** (`npm run test:pack`, in CI): packs and
  clean-installs the tarball, runs worker detection + CLIs + SRI +
  consumer type-check from the installed tree.
- **Real-Redis integration tests** (`npm run test:redis`, CI):
  cross-instance one-time semantics, redemption races, shared
  quotas, dead-store fail-closed.
- **`tools/stego-bench.mjs`** (`npm run bench:stego`, `--fp`,
  `--collusion`): mixed-corpus matrix (robust 75/88 @ strength 6;
  periodic-text identified as a weak class), 0/329 false positives,
  collusion participants ranked top-k for k=2..4.
- **Load-test workload shapes** (`--images`, `--viewers`): warm vs
  cold vs per-viewer-personalized throughput measured separately
  (406 / 53 / 25 flows/s loopback @800 px).
- Crypto known-answer tests (FIPS 180-4, RFC 4231) + IV uniqueness;
  legacy-mark migration tests (layouts v1–v3, CRC/MAC eras);
  entitlement downgrade + batch partition + PoP negative tests.
- Chromium accessibility checks: `prefers-reduced-motion` disables
  temporal interlace with a usable static image; viewer host role/alt
  semantics. Browser harness parameterized for Firefox
  (`ARCHX_BROWSER=firefox`).

### Fixed

- **`server/detect-worker.js` missing from the npm tarball** (worker
  detection would have failed for package consumers). `files` now
  includes it plus `server/ownership.js`, guarded by the pack smoke
  test's required-files assertion.
- README `--stego` examples reused the browser-delivered scramble
  key; they now use a private `ARCHX_STEGO_KEY`, and a test executes
  the documented protect → detect → verify round-trip.
- Stale documentation: withdrawn "~99% of theft" figure, plan-v1
  "default", saturation "fail closed", obsolete test counts.


## [1.17.0] — Unreleased

Sixth-review response (`docs/RESEARCH.md` §2.25): client dispatch
capture, variant-scope v2, watermark opt-out claims, detector
forensic reach (D4 transposes, MAC-era gates, tilt deskew, collusion
assay), a bounded detect worker, and request-path AVIF/memory
guardrails.

### Added

- **Tilt deskew search** (`searchTilt`, CLI `--tilt`): ±6° small-angle
  recovery with canvas-expansion-aware screening and centroid angle
  estimation; results carry `deskewed`. Recovers pure tilts and
  tilt+JPEG50; tilt+crop+resize+JPEG compounds remain out of
  envelope (oracle-verified signal loss).
- **D4 transpose recovery**: EXIF 5/7 diagonal reflections join the
  mirror/rotation fan-out (`transposed: 'main' | 'anti'`).
- **Collusion assay** (`assayStegoCollusion`): per-bit soft-evidence
  ranking of candidate recipients for averaging investigations.
  Investigative aid only — not a Tardos code.
- **Detect-worker bounds**: `configureStegoDetectWorker()`
  (queue cap, per-job timeout with worker recycle),
  `batchDetectStegoInWorker()` (shared-plane many-key screening with
  bounded escalation), zero-copy transfer.
- **Watermark opt-out**: `authorize` may return `watermark: false`;
  the signed token carries `nwm: 1` (validator rejects any other
  value and `nwm`+`wm` combinations).
- **Replay-store telemetry**: `archx.replay_store_evicted` security
  event when live JTIs are evicted under pressure.
- **`memoryProfile: 'compact'`**: scales bounded-store defaults for
  small containers; explicit options win.

### Changed

- **Scramble plan v2 is the default** in `buildScramblePlan()`
  (explicit `1` still available). Delivered containers embed their
  plan version and keep decoding.
- **Derivative variant scope v2 / cache namespace `v7`**: keys now
  mix watermark/forensic/stego digests; mint and redemption derive
  identical scopes. Per-image key mode has a one-TTL re-mint window.
- **Request-path AVIF effort clamps to 2** unless
  `allowSlowRequestAvif: true` (offline builds unaffected).
- **`oneTimeTokenMaxEntries` defaults to 250,000**; production audit
  blocks under 10,000.
- **Robust embed masking** lets textured cells exceed nominal
  amplitude (cap 1.4×). Measured PSNR at strength 6 is 27.9–28.9 dB
  on the photo corpus (was 30.4–31.4 dB) with better crop recovery;
  the reviewed ≥34 dB target was not reachable without losing the
  envelope and is documented as such. Strength 8 is now recommended
  for smooth product photography.
- MAC-tagged correction/erasure gates relaxed to signal-based
  thresholds (CRC legacy stays strict); real-photo matrix 39/51 →
  42/51 at strength 6, 18/18 negative controls still clean.
- Watermark overlay blend touches only nonzero-alpha pixels
  (byte-identical output).
- `VERSION` constant in the client was stale (1.14.0); fixed.

### Security

- Client sensitive dispatch routes through a load-time-captured
  `Reflect.apply`; canvas sizing through captured setters; integrity
  audit covers both (plus `createImageBitmap`). Images load with
  `Reflect.apply` sabotaged.
- DevTools polling idles while the document is hidden.

## [1.16.0] — Unreleased

StegoMark forensic-envelope release (`docs/RESEARCH.md` §2.24). The
§2.20 "sync-template mark v2" item was re-measured before redesigning
any embed: deep-crop suspects were already registering exactly and
then failing the decode, so the entire fix is detector-side — **every
already-issued mark gains the new envelope; nothing needs re-embedding.**

### Added

- **Erasure decoding (robust).** Deep crops erase every repetition of
  10–32 code bits, beyond flip-repair depth. The detector now treats
  zero-vote bits as erasures at known positions: only erased *payload*
  bits are enumerated (check bytes recomputed, CRC-prefiltered, MACand marker-verified against observed bits), behind strong-signal
  gates, with stricter budgets as erasures grow. Results carry
  `erasureDecoded` + `erasedBits`. Center/corner crops now recover to
  60% retained (was ~80%).
- **Standard-profile erasure assist.** A single sparse bit (<2 votes)
  no longer blocks the MAC-first flip corrector behind the coverage
  pre-gate (≤6 sparse bits, MAC-acceptance only).
- **Rotation recovery.** 90°/270° rotated suspects are probed by
  default (`rotated: 90 | 270` reported; `searchRotation: false` opts
  out). 180° was already covered by the xy-mirror probe.
- **Reframe registration.** Stage-3 one-axis/diagonal scale seeds
  ((1.5, 1), (16/9, 1), uniform to 55% …) plus a coordinate-descent
  scale escape seeded by raw signal instead of self-agreement —
  3:2 → 1:1 and 4:5 reframes now recover at exact geometry.

### Notes

- Measured on a 21-transform synthetic matrix (robust, forensic
  mode): 7/21 → 21/21 recovered; 20 unmarked/wrong-key controls,
  zero false positives. Synthetic-fixture numbers — calibrate on
  your own catalog before relying on the deep end of the envelope.
- Not-found worst case in auto forensic mode rose (~7 s photos,
  ~30 s noise-like suspects, roughly resolution-independent). Pin
  `profile`/`layoutVersion` or use `detectStegoFingerprintInWorker`
  for pipelines. Small-angle rotation, perspective, sub-55% crops
  and rotate+flip transposes remain out of envelope (future
  sync-template mark version; see §2.24).
- Tests: 99 Node (+1 comprehensive detector-envelope test).

## [1.15.0] — Unreleased

Fifth external adversarial-review response (claim-by-claim verification
in `docs/RESEARCH.md` §2.23). Repository integration note: six of the
review's concrete details did not exist in the shipped code; everything
below was reproduced locally before it was changed.

### Security

- **Per-tier cryptographic isolation (S1).** `per-image` scramble/AES keys
  are now derived per delivered variant (`w:q:fmt` scope from the signed
  token claims), so a free-tier viewer's key cannot decrypt or
  unscramble the lossless/paid derivative. Output cache namespace `v6`.
  Per-image tokens minted just before upgrade fail until re-minted
  (bounded by token TTL).
- **XFF short chains no longer trust the leftmost hop (S2).** When the
  forwarded chain is shorter than `trustedProxyHops`, identity falls
  back to the canonical socket IP instead of the spoofable `chain[0]`.
- **One-time-token store no longer self-DoSes (S4).** Saturated
  `BoundedTtlSet` claims evict expired/oldest entries within a bounded
  budget instead of an O(N) scan + global fail-closed for all viewers.
- **Post-load prototype hooks are bypassed (C1/C2).** All WebGL
  draw-path methods (`uniform1f/2f/1i`, viewport, texture setup, …) and
  Canvas2D transform calls on off-DOM buffers now go through natives
  captured at module load; the integrity audit names them.
- **Plan v2 is now the default everywhere (M1).** Middleware,
  `scrambleImage`/`unscrambleImage`, builder, and CLIs. Raw stored v1
  payloads require explicit `planVersion: 1`; containers stay
  header-authoritative. `encrypt: false` and plan v1 are
  production-audit blockers (M2); hardened preset pins per-token keys.

### Fixed

- CLI parsers: boolean flags no longer swallow positional paths;
  `--flag=value` works with boolean coercion (S5). Build manifest is
  written `0644` (state stays `0600`).
- Type/runtime drift (S6): `deploymentMode` union corrected;
  `bindTokenTo` accepts the documented array form at runtime too;
  stego `scope/keyScope` unions corrected; `validateWatermarkValue`
  returns `boolean`; `authorize` results may set `ttlSec` (5–900 s),
  now implemented end-to-end.
- Detector: vertical-flip and 180°-rotated suspects are recovered
  (`mirrorAxis` reported); geometry stage 2 recovers moderate corner
  crops (e.g. 88% retained) that previously evaded (M3). Deep crops
  and rotation remain documented non-goals pending sync-template v2.
- `maxInputPixels` default unified at 50 MP; AVIF effort > 2 warns at
  middleware construction. Browser asset manifests now carry
  `planVersion` through to the client (header stays authoritative).

### Added

- `detectStegoFingerprintInWorker()` / `closeStegoDetectWorker()` on
  `/server`: forensic detection on a worker thread, never on a
  request path.
- `archx.webgl_budget` telemetry event alongside the existing
  `archx-webgl-budget` DOM event (the fallback was never silent).
- Tests: 98 Node (+7: S1 cross-tier, S2 short-XFF, S4 eviction, array
  binding + `ttlSec`, pv2 defaults + manifest mode, mirror/geometry
  recovery + worker, CLI parsing) and 118 Chromium checks (+4
  post-load hook resistance).

## [1.14.0] — Unreleased

Fourth external adversarial-review response (claim-by-claim verification
in `docs/RESEARCH.md` §2.22). Thirteen problems, seven server
optimizations, and six browser optimizations were raised against
1.13.0; confirmed items are fixed with regression tests, two proposed
patches were corrected before landing, one item was already shipped,
and one was rejected with evidence.

### Security

- **Stego/forensic seed derivation is now a real KDF.** New
  `layoutVersion: 3` / `signsVersion: 3` seed the layout/sign PRNG
  from SHA-256(key material) (`sha256SeededPrng()`) instead of a fast
  string hash. Embed defaults moved to v3; detectors triple-read
  v1/v2/v3 bit-exactly and report the matched vintage. Pre-1.14
  detectors cannot read v3 marks — pin `layoutVersion: 2` during
  migration.
- **Canonical IP identity unwraps transition mechanisms.** NAT64
  (both prefixes), 6to4, Teredo, and v4-compatible forms collapse to
  the embedded IPv4 for token binding, quotas, and abuse accounting,
  closing both the carrier-NAT64 shared-bucket lockout and the
  one-IPv4-many-IPv6-identities evasion. Zone IDs are validated and
  stripped; IPv6 parsing is strict.
- **Scramble padding no longer confesses boundary tiles.** Core
  padding rebuilt on a keyed best-match toroidal wrap with DC
  anchoring, block-coherent noise, and an edge feather (photo seam
  gradients 4.8×→1.25× interior, displayed pixels exact); the
  client's local scramble uses a dual-wrap blend plus edge taper.
- **Temporal-median recovery is biased off-target.** Interlace
  noise fill gains a cycle-zero-mean per-block bias in both engines,
  so short screen recordings no longer median-recover ~50% of pixels
  exactly; the `fortress60` profile also stops being silently
  clamped (0.55 now honored, clamp 0.65).
- **Sharp loader policy is scoped and restorable.** Middleware
  instances hold refcounted loader leases released on
  `handler.close()`; `configureSharpSecurity()` remains available as
  an explicit permanent policy. Server watermark rows are
  brick-staggered.

### Fixed

- The `/server` entry now exports the image-processing API
  (`scrambleImage`, `unscrambleImage`, `inspectImageMetadata`,
  `prepareDerivativeBase`/`finishDerivative`,
  `configureSharpSecurity`/`configureSharpPerformance`,
  `generateKeyBase64`, lease helpers) plus a
  `./server/scramble-image` subpath — previously unreachable through
  the package exports and undeclared in types. Sharp loads lazily,
  so this costs token-only processes nothing.
- Type/runtime drift reconciled: `{ imageId }` token sources work,
  `preset('marketplace')` exists, `renderer: 'canvas2d'` means
  canvas, and the declared enums for mode/qualityProfile/onExtract/
  renderLoop/tokenTransport/memory/strikes now match the runtime.
- Middleware accepts and plumbs `processing.avifEffort`,
  `avifChromaSubsampling`, `forensic.signsVersion`, and stego
  `layoutVersion`/`legacyCode` (all previously rejected), with
  cache-key identity updated to match.
- `<archx-image>` boolean attributes parse values
  (`scrambled="false"` no longer enables scrambling), absent
  booleans no longer clobber presets, and all observed attributes
  now react (source attributes hot-reload; others re-mount).
- Build summaries report `totalBytes`, manifest variants carry
  `file`, and incremental builds regenerate on derivative-format
  changes (`derivativeFormatVersion: 'v5'`; middleware cache
  namespace likewise `v5`). CLI help lists AVIF and stops claiming a
  scramble-key stego default; the demo server handles aborted
  static streams; the load tester writes real JPEG bytes.

### Performance

- Per-token views resolve the cached stage-1 base before touching
  the master (no 5–50 MB master read/re-cache per view), and
  concurrent first-views share one stage-1 decode via singleflight.
- `finishDerivative` is copy-on-write; watermark rasterization is
  cached as a raw overlay and blended in JS (~37 ms → ~2 ms per
  derivative at 960px, ≤1 LSB vs libvips). `handler.stats()` gains
  `baseInFlight`.
- Detector hypotheses share one luma/integral plane set per image
  (bit-identical results; the win is allocation, honestly not the
  reviewer's claimed wall-clock cut).
- Browser: black-policy decoys build lazily on first readback
  attempt, temporal frames reuse one scratch buffer with column
  LUTs, the GL watermark texture right-sizes to the backing store,
  and the dynamic-trace timer idles while hidden/off-screen.
- Hardened/catalog server presets default `sharpConcurrency: 1`
  and `sharpCache: false`.

### Tests

- 91 Node tests (7 new: export surface + config acceptance,
  transition-mechanism IP identity, padding coherence,
  copy-on-write, build summary shape, Sharp lazy-load/leases in a
  child process, stage-1 sharing), 114 Chromium checks (6 new:
  `{imageId}` alias, marketplace preset, `canvas2d` alias, element
  boolean/reload semantics), fuzz + type suites in `npm run verify`.

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
