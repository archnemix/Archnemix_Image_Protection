# Requirements tracker

**Source of truth:** requirements stated by the user in this conversation. This file records the authoritative A/B/C audit checklist, current implementation status, evidence, and future requirements. For each newly stated requirement, append it here before treating it as work scope. Update status only after checking the implementation and relevant tests; do not infer completion from documentation alone when working code or runtime evidence is required.

**Audit date:** 2026-10-25  
**Branch:** `arena/1ba8a4fa-archnemix-image-protection`
**PR:** #34 from earlier work remains closed. PR #35 was merged from the prior Arena branch as commit `4ad9f6b`; this active branch is for the follow-up release-readiness audit. Do not publish to npm from this session.

## Authoritative requirements (22)

### A — Contradictions / defects (6)

1. **A1 — `replaySaturation` documentation:** Remove or correct the README wording that recommends the invalid `deny` value for `replaySaturation`; the only valid values are `evict` and `strict`, and the latter is the hardened behavior.
2. **A2 — enum/docs drift gate:** Make the documentation consistency gate detect documented option values that do not match code enums, including the `replaySaturation` defect in A1.
3. **A3 — install-shaped npm package:** Clarify that `npm run demo`, `generate:test-images`, and similar repository-only scripts are not available from the published npm package; keep the documentation/snippets reachable and package artifact small, free of source maps and test/demo scripts, while retaining imports that work from npm.
4. **A4 — gzip budget:** Provide a reproducible browser gzip-size check (pinned compressor settings) and enforce the budget of at most 52 KiB (53,248 bytes).
5. **A5 — temporal-interlace defaults:** State clearly that temporal interlacing is opt-in for individual images, while `elite` / `maxProtection` presets explicitly opt in.
6. **A6 — API documentation:** Document the export surface and plugin/event APIs (`usePlugin`, `listPlugins`, `onClientEvent`, `offClientEvent`, `assayStegoEmbed`, and `applyForensicBlocks`) in README plus a dedicated exports reference.

### B — Security / features (10)

1. **B1 — deep/asymmetric crop recovery:** Extend the sync-template v2 search to recover fingerprints after asymmetric/deep crops below roughly 80% retained content, rather than only easy centered crops.
2. **B2 — phone-photo rotation and perspective:** Add an offline feature-match/affine deskew pre-pass that handles routine 10–30° phone-photo rotations and perspective skew of a monitor.
3. **B3 — C2PA integration:** Provide and validate a C2PA integration recipe using the official SDK; sign a genuine image, reopen/verify it, and document trust/revocation limitations without implying that a valid signature proves a platform will honor it.
4. **B4 — verified-crawler SEO mode:** Provide an explicitly configured mode that serves only crawler-verified, low-resolution, heavily watermarked previews; it must be separately routed and fail closed.
5. **B5 — calibration harness:** Add a documented harness that estimates perceptual-score distributions and false-positive rates by resize distance.
6. **B6 — one-time-token saturation hardening:** Either default one-time-token replay saturation to `strict`, or make the production audit a blocker when one-time tokens are enabled with non-strict saturation.
7. **B7 — proof-of-possession telemetry:** Emit a public client event when proof-of-possession is skipped because of HTTPS/crypto unavailability.
8. **B8 — deep nightly fuzzing:** Add a scheduled nightly fuzz run with multiple randomized seeds and deeper coverage than the quick test.
9. **B9 — signing-key rotation helper:** Add a small `rotateSigningKeys()`-style helper that mints under a new `kid`, retains the old key for the maximum token TTL, then retires it and emits a retirement event.
10. **B10 — batch response envelope:** Return an explicit batch-token envelope containing `ok: false` and requested/issued/denied counts when individual items fail.

### C — Optimization / performance (6)

1. **C1 — worker-thread image operations:** Move StegoMark embedding and forensic-block work off the request main thread.
2. **C2 — package source-map exclusion:** Stop shipping the roughly 2.3 MB source maps in the main npm package; keep them available only through a debug/repository build.
3. **C3 — generated declarations:** Generate TypeScript declarations from JSDoc or another maintained source, rather than hand-maintaining types separately.
4. **C4 — reference chunked transport:** Ship a reference chunked/streaming `.archx` transport so integrators can avoid inventing unsafe transport protocols themselves.
5. **C5 — file decomposition:** Decompose the large `server/middleware.js` closure and `src/client/viewer.js` into modules.
6. **C6 — catalog AVIF policy:** Enforce AVIF as precompute-only in the catalog-throughput profile and document the latency/throughput trade-off.

## Item-by-item audit status

Status meanings: **Complete** = acceptance criterion is implemented and supported by evidence; **Partial** = relevant code/docs exist but one or more requested acceptance criteria remain unproven or absent; **Not started** = no meaningful implementation found.

| ID | Status | Evidence / remaining gap |
|---|---|---|
| A1 | Complete | README uses `evict` / `strict`; no invalid `deny` instruction found. |
| A2 | Complete | `tools/docs-check.mjs` checks current-facing enum literals, including `replaySaturation`, against `server/config.js`; `requireEveryValue` ensures both legal values are documented. |
| A3 | Complete | `tools/package-artifact.mjs` strips repository-only scripts from the packed manifest; package allowlist includes public docs/examples and excludes test/demo tooling plus this workspace-only tracker. `tools/pack-smoke.mjs` is the artifact gate. |
| A4 | Complete | `tools/bundle-size.mjs` uses pinned `fflate` gzip settings and enforces the 53,248-byte budget. Current measurement after production build: 51,722 bytes / 50.5 KiB gzip (156,672 bytes / 153.0 KiB minified). |
| A5 | Complete | README, website, and docs gate describe individual-image default off and explicit `elite` / `maxProtection` opt-in. |
| A6 | Complete | `README.md`, `docs/EXPORTS.md`, and `tools/docs-check.mjs` cover named APIs and cross-check runtime exports. |
| B1 | Complete | `tests/helpers/stego-crop-corpus.mjs` supplies deterministic textured RGBA; v5 regression covers four asymmetric crop windows retaining 56–62% area across varied left/top positions and aspect ratios, requiring the same fingerprint, ≥10 pilot cells, and ≥0.70 agreement. This is synthetic texture evidence, not a claim of universal or real-photo crop recovery. |
| B2 | Complete | `src/core/stego-deskew.js` uses the keyed v5 sync pilot as a spatial feature matcher, screens ±5° steps through ±30°, refines leading candidates, then confirms at full resolution; `--tilt` exposes the opt-in offline pass. Regression evidence covers 10°/20°/30° rotations and a textured 20°+keystone synthetic capture; the separate perspective sweep is also tested. This is synthetic transform coverage, not a real-phone-photo corpus or arbitrary homography guarantee. |
| B3 | Complete | `docs/C2PA_INTEGRATION.md` provides an official SDK recipe and runtime sign/reopen smoke evidence; limitations/trust caveats are documented. |
| B4 | Complete | Opt-in `seoCrawler` route requires host-supplied trusted verification, never trusts User-Agent alone, and fails closed. There is intentionally no built-in crawler identity database; deployments supply the verifier. |
| B5 | Complete | `tools/calibrate-perceptual.mjs` and its docs calculate score distributions/false positives across resize distances. |
| B6 | Complete | Hardened production audit blocks one-time tokens with non-`strict` saturation; satisfies the explicit audit-blocker alternative. |
| B7 | Complete | Client emits `archx.pop_skipped`; tests assert the downgrade reason. |
| B8 | Complete | `.github/workflows/nightly-fuzz.yml` runs on a schedule with `ARCHX_FUZZ_MULTIPLIER=3` and a run-specific seed. Coverage-guided fuzzing was described as ideal/optional, not required. |
| B9 | Complete | `tools/signing-key-rotation.mjs` mints a new key ID/secret and schedules activation/retirement no earlier than max token TTL plus grace; `server/signing-keyring.js` activates/retires at request boundaries and now emits one metadata-only `archx.signing_key_retired` event (plus activation event). `tests/unit.test.mjs` asserts lifecycle events contain IDs but no secrets. Deployment remains an explicit secret-manager handoff, documented in `docs/OPERATIONS.md`. |
| B10 | Complete | Batch mint response in `server/middleware.js` returns `{ ok, counts: { requested, issued, denied }, tokens, errors }`; README documents it. |
| C1 | Complete | Request-path forensic blocks and StegoMark embedding are run through the bounded worker queue in `server/scramble-image.js` / `server/detect-worker.js`; `tests/unit.test.mjs` covers worker execution. |
| C2 | Complete | Package allowlist omits source maps; the pack smoke test exercises the npm artifact and repository-only scripts are removed from its manifest. |
| C3 | Complete | `types-src/` is the source for `tools/generate-types.mjs`; `types:check` and `test:types` verify generated declarations. |
| C4 | Complete | `examples/chunked-transport/` ships browser WebCrypto assembly plus a Node reference origin that requires per-request authorization, signs the exact manifest, bounds chunks/total bytes, and uses private no-store responses. End-to-end unit test verifies signature, every chunk/final digest, per-request auth, and tamper rejection. The example is packaged but remains host-owned and is not the built-in viewer transport. |
| C5 | Complete | Responsibilities now have explicit module boundaries: server IP identity (`server/request-identity.js`), key state and SEO preview, plus browser token mint/batch transport (`src/client/token-transport.js`), temporal frame generation, shaders, network, assets, sampling, and drawing. Middleware/viewer remain orchestrators for private authorization/lifecycle state (about 2,593/2,450 lines); moved boundaries are integration-tested and do not expose mutable private state. |
| C6 | Complete | `withCatalogThroughputDefaults()` rejects request-path AVIF, including overrides; docs explain precompute/latency trade-offs and tests cover the rejection. |

**Current audit result: 22 complete, 0 partial, 0 not started** for the inherited A/B/C checklist. The previous crop/deskew and transport evidence remains synthetic and fixture-bounded. PR #35 was merged; this branch carries the new release-readiness audit requirement below. No npm publication has occurred.

## Validation evidence

- `npm run test:all`: passed end-to-end after the final implementation, including production build, 167 total Node tests (160 unit/integration plus seven seeded fuzz tests), and all 129 real-Chromium checks.
- `npm run test:pack`: passed from a clean install of the packed tarball; verified source-map/repository-script exclusion, imports, workers, CLI bins, SRI, and TypeScript imports. The tracker is excluded from npm packaging.
- `npm run lint`, `npm run docs:check`, `npm run types:check`, and `npm run test:types`: passed. Docs check confirms version 1.30.1, 167 Node tests, 129 browser checks, and docs/website/code agreement.
- `npm run size:browser`: 156,672 bytes (153.0 KiB) minified; 51,722 bytes (50.5 KiB) gzip level 9 via pinned `fflate`, below the 53,248-byte cap.
- `npm audit --audit-level=high`: passed with 0 vulnerabilities.
- Focused tests for B1 crop corpus, B2 affine deskew/perspective, C4 chunked reference transport, C5 token transport integration, and signing-key rotation passed. Synthetic-only scope limitations are stated in the corresponding rows.
- Final `git diff --check`: passed after the tracker edits; no npm publication has occurred.

## Future-requirement log

### R1 — Complete the four partial items, validate, then PR/merge only if all pass (2026-10-25)

The user directed: “continue and then implement them, test it, then check whether everything has been done; if yes make a PR and merge the code.” Implemented B1, B2, C4, and C5; PR #35 from the previous active branch was merged after full and focused verification. No npm publication occurred.

### R2 — Release-readiness cleanup and cross-check (2026-10-25)

The user requested a final cleanup pass: inspect for unused/dead code, logic flaws, and build integration gaps; read and verify every documentation file for honesty and contradictions against other docs and code; clean up repository structure where justified; audit the website for stale information; then create a PR and merge only if the checks show it is ready for the user to publish. Do not publish to npm. Record concrete findings, fixes, and validation evidence; do not make risky broad moves or delete files merely for cosmetic tidiness.

**Status:** Complete. PR #36 was merged into `main` after GitHub CI passed on Node 20, Node 22, and Windows; CodeQL also passed. Concrete issues found and corrected: the compatibility table understated Windows CI and layout-v5 synthetic coverage; `STANDARDS.md`, `SECURITY.md`, `REVIEW_GUIDE.md`, `README.md`, and the website overstated or understated rotation/AI-watermark evidence; the architecture map placed the opt-in pilot-registration pre-pass in the wrong module boundary; the chunked-transport guide duplicated and lagged its runnable client; and the changelog still said v1.30.1 was awaiting publication although npm reports it published. No source file was deleted: static unused-code findings were reviewed and map to intentional browser/CLI/generated/type/test entry points or helpers used inside their defining modules. The repository is organized by source, server, tools, tests, docs, website, and examples; no structural move was justified.

Validation: `npm ci`, lint, build/type generation, `types:check`, `test:types`, `docs:check`, `size:browser` (156,672 bytes minified; 51,722 bytes gzip), `test:browser` (129 checks), `test:pack`, local Markdown/website links, and `npm audit --audit-level=high` passed. A local `npm run verify` exceeded the 30-minute sandbox limit; its Node run hit internal timeouts in the layout-v5 affine and detect-worker tests while CPU-heavy detector/fuzz cases ran far longer than the ordinary CI profile. This local timeout is not counted as a pass; GitHub CI subsequently passed on PR #36 for Node 20, Node 22, and Windows. npm reports `1.30.1` as already published/latest; its registry timestamp was later than the system date used for this audit. R3 below records the registry-checked bump to `1.30.2`; confirm the chronology before publishing. No npm publish was run.

### R3 — Prepare the next publishable patch and make review materials human-readable (2026-10-25)

The user clarified that the current npm version cannot be published twice and directed us to change the version. Bump from the already-published package version to the next unused patch version only after checking the registry; update every authoritative version field and release note consistently, but do not publish to npm. The user also emphasized that repository readability—not generic or AI-sounding prose—is the goal, so independent security reviewers can navigate, understand, and challenge the implementation. Improve the reviewer-facing path with concise, specific, evidence-linked prose while preserving technical detail, limitations, and facts; do not perform broad code churn or remove substantive security documentation merely to shorten it.

**Status:** Implementation complete. npm confirmed `1.30.1` is latest and returned E404 for `1.30.2`, so the package, lockfile, client version, generated distributions, changelog, and website masthead now consistently prepare `1.30.2`. The reviewer guide now gives one clean-clone command sequence, separates test suites by purpose, and removes a dangling coverage fragment; the existing README reviewer link remains the entry point. No broader code churn was needed. PR #37's GitHub CI and CodeQL checks passed on Node 20, Node 22, and Windows.

Validation passed locally: `npm ci`, build, lint, generated declaration check, TypeScript smoke, `docs:check`, 129 browser checks, package smoke, browser size (156,672 bytes minified / 51,722 gzip), audit (0 vulnerabilities), local links, and `git diff --check`. The earlier local full-suite timeout remains uncounted; GitHub CI subsequently passed the full suite. No npm publication was performed; verify release timing and set a release date before publishing 1.30.2.

Append every new requirement stated by the user here, preserving its scope and acceptance criteria, and add a status/evidence row before implementation work. Never replace a user requirement with a narrower inferred interpretation without recording that scope decision explicitly.
