# Requirements tracker

**Source of truth:** requirements stated by the user in this conversation. This file records the authoritative A/B/C audit checklist, current implementation status, evidence, and future requirements. For each newly stated requirement, append it here before treating it as work scope. Update status only after checking the implementation and relevant tests; do not infer completion from documentation alone when working code or runtime evidence is required.

**Audit date:** 2026-10-25  
**Branch:** `arena/712edce8-archnemix-image-protection`  
**PR:** #34 was opened before this authoritative checklist was supplied and was closed when the audit found incomplete items. Do not merge/reopen or publish to npm unless all requirements below pass.

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
| A4 | Complete | `tools/bundle-size.mjs` uses pinned `fflate` gzip settings and enforces the 53,248-byte budget. Current measurement after production build: 50.4 KiB gzip (152.4 KiB minified). |
| A5 | Complete | README, website, and docs gate describe individual-image default off and explicit `elite` / `maxProtection` opt-in. |
| A6 | Complete | `README.md`, `docs/EXPORTS.md`, and `tools/docs-check.mjs` cover named APIs and cross-check runtime exports. |
| B1 | Partial | Sync-template v2 has dense pixel-origin search and regression tests for two synthetic asymmetric/deep crops. No varied real-photo/crop corpus or broad recovery evidence; do not claim general sub-80% crop recovery yet. |
| B2 | Partial | `src/core/stego-detect.js` has tilt probing limited to -6°..+6° and bounded perspective/keystone transforms. It does not implement the requested feature-match/affine pre-pass or demonstrate 10–30° phone-photo recovery. |
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
| C4 | Partial | `docs/CHUNKED_TRANSPORT.md` contains a bounded browser-side reference protocol/sample, but it is documentation-only: no runnable server/reference package or end-to-end transport test. |
| C5 | Partial | Some modules have been extracted (`server/seo-preview.js`, `server/signing-keyring.js`, `src/client/shaders.js`, `src/client/temporal-frames.js`), but the requested decomposition is incomplete. `server/middleware.js` remains about 2,718 lines and `src/client/viewer.js` about 2,506 lines. |
| C6 | Complete | `withCatalogThroughputDefaults()` rejects request-path AVIF, including overrides; docs explain precompute/latency trade-offs and tests cover the rejection. |

**Current audit result: 18 complete, 4 partial, 0 not started.** The four partial items are B1, B2, C4, and C5. PR #34 was closed after these gaps were discovered; do not present the implementation as satisfying all requirements, and do not merge, reopen the PR, or publish to npm until the four items are completed and verified.

## Validation evidence

- `npm test`: 165 tests passed (158 unit/integration + 7 seeded fuzz); this was rerun after fixing a native-layout deadline starvation exposed by the first full run.
- `npm run test:browser`: all 129 real-Chromium checks passed.
- `npm run test:pack`: passed from a clean install of the packed tarball; checked source-map and repository-script exclusion, README links, imports, workers, CLI bins, SRI, and TypeScript imports. The tracker itself is excluded from npm packaging.
- `npm run docs:check`: passed; documented version, test counts, exports/enums, temporal defaults, and bundle size agree.
- `npm run size:browser`: 156,064 bytes (152.4 KiB) minified; 51,564 bytes (50.4 KiB) gzip level 9 via pinned `fflate`, below the 53,248-byte cap.
- `npm run lint`, `npm run types:check`, `npm run test:types`, `npm audit --audit-level=high`, and `git diff --check`: passed; zero audit vulnerabilities.
- `npm run test:all` first exposed one failure in the `maxTimeMs` native-hit test; after the fair per-layout native-screen deadline fix, the complete Node suite and browser suite passed independently. The complete `test:all` composite was not rerun after that targeted fix.

## Future-requirement log

Append every new requirement stated by the user here, preserving its scope and acceptance criteria, and add a status/evidence row before implementation work. Never replace a user requirement with a narrower inferred interpretation without recording that scope decision explicitly.
