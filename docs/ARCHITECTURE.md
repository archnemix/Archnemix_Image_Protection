# Architecture — module map and dependency rules

v1.19 split the three former monoliths into responsibility-based modules.
Public entry points did not move: `src/scramble.js`, `src/archx.js`, and
`server/middleware.js` still resolve exactly as before (the first is now a
barrel, the second an assembly, the third the middleware factory plus
re-exports). The published `exports` map is unchanged, and a runtime
contract test (`v1.19 type declarations match the runtime export
surface`) pins `types/*.d.ts` to the real export surface.

## `src/core/` — environment-agnostic primitives (browser + Node)

| Module | Responsibility |
|---|---|
| `bytes.js` | Byte/UTF-8/base64 coercion helpers |
| `crypto.js` | Pure-JS SHA-256/HMAC + injectable sync-crypto fast path (`useSyncCrypto()`) |
| `plan.js` | Tile scramble plans (v1/v2 seeds), permutation application |
| `sniff.js` | Image/container byte sniffing, dimension extraction |
| `container.js` | `.archx` container encode/decode (header + AES-GCM payload) |
| `forensic.js` | Forensic block-sign marks and scoring |
| `bch.js` | BCH(188,64) error-correcting code math for stego layouts 4/5 |
| `stego-code.js` | StegoMark codeword layout, syndromes, tag math |
| `pixels.js` | Luma planes, integral images, rotate/mirror/downscale primitives |
| `stego-embed.js` | StegoMark embedding |
| `stego-detect.js` | StegoMark blind detection (geometry search, deskew, erasure repair) |
| `stego-assay.js` | Embed pre-flight assay + collusion ranking |
| `perceptual.js` | 64-bit DCT perceptual fingerprint |

Rules: no DOM, no Node builtins. `pixels.js` owns raw-RGBA transforms;
detector search lives in `stego-detect.js` only. `rotateRgba` always
returns a fresh buffer — the detector's plane cache is keyed by buffer
identity, so scratch reuse there is a correctness bug (found in v1.19).

## `src/client/` — browser runtime (assembled by `src/archx.js`)

| Module | Responsibility |
|---|---|
| `native.js` | Captured platform natives + tamper-resistant dispatch |
| `integrity.js` | Native/extension/automation audits and reports |
| `version.js` | Single `VERSION` source of truth (imported by modules that must not depend on the bundle entry) |
| `options.js` | `DEFAULTS`, profiles/presets, global config, page session ids |
| `registry.js` | Live instance set + host→instance weak map |
| `events.js` | Sanitized plugin event bus |
| `temporal.js` | Temporal interlace profiles, phase scheduler, shared limiter |
| `temporal-frames.js` | CPU-backed temporal frame construction from clean pixels |
| `shaders.js` | WebGL vertex/fragment shader sources, separate from viewer lifecycle |
| `bitmap-cache.js` | Decoded-bitmap LRU bounds |
| `observers.js` | Shared visibility/resize observers, global guards, devtools watcher, WebGL slot budget |
| `sampling.js` | Canonical widths, DPR/connection-aware sampling |
| `assets.js` | Signed asset-manifest loading/validation |
| `network.js` | Bounded fetch, token mint/batch, proof-of-possession, challenge retry |
| `draw.js` | Canvas/WebGL draw + poisoned-readback presentation |
| `styles.js` | Shadow-DOM stylesheet |
| `viewer.js` | `ProtectedImage` element class (the per-image state machine) |
| `loaders.js` | `Archx.load.*` entry points, gallery, preload, custom element |

Rules: shared mutable state is never imported by binding across modules —
it moves through accessors (`getGlobalConfig`/`setGlobalConfig` in
`options.js`, `acquireGlSlot`/`releaseGlSlot` in `observers.js`) or lives
next to its owner (`tokenBatchQueues` in `network.js`). One accepted
cycle remains: `sampling.js` ↔ `network.js` (function-only cross-calls,
resolved at call time, not module-eval time).

## `server/` — Node side

| Module | Responsibility |
|---|---|
| `middleware.js` | `createArchxMiddleware` factory (request handling closure) + the `./server` re-export surface |
| `bounded.js` | `SlidingWindowLimiter`, `BoundedTtlSet`, `AsyncSemaphore`, distinct-access tracking, memory state store |
| `tokens.js` | HMAC token sign/verify, strict claim validation, proof-of-possession, stego derivation |
| `signing-keyring.js` | Active signing-key state and scheduled activation/retirement |
| `config.js` | Strict config inspection/normalization, production audits, width/ID/path rules |
| `scramble-image.js` | Sharp pipeline (lazy libvips), protected derivative generation, detect worker pool |
| `seo-preview.js` | Low-resolution watermarked preview transformation for explicitly verified crawlers |
| `ownership.js` | Ed25519 ownership claims, EXIF/XMP embedding, layered rescan |
| `issuance-log.js` | HMAC-chained tamper-evident issuance records |
| `redis-state-store.js` | Shared state store for multi-instance deployments |
| `detect-worker.js` | `worker_threads` entry for off-thread detection |
| `node-crypto.js` | Injects Node's `createHmac` into the core's sync-crypto slot |
| `ops.js` | Deployment helpers: health/readiness handler, Prometheus metrics, JSONL event logger, graceful shutdown |
| `build-assets.js` (+ CLI) | Offline signed asset manifests |
| `scramble-cli.js`, `detect-stego-cli.js` | `archx-protect` / `archx-detect` |
| `demo-server.js` | Local demo only — never a production template |

Rules: config is normalized exactly once in `config.js`; the factory
closure consumes a frozen config and never re-reads host options.
`middleware.js` re-exports every documented `./server` name so hosts and
tests keep one import path.

## Decomposition boundary

The viewer remains the `ProtectedImage` lifecycle/state machine, while
its separately testable temporal-frame builder and WebGL shader sources
live in `temporal-frames.js` and `shaders.js`. The server middleware still
owns request authorization and response policy, but scheduled keyring state
and the crawler-preview transformation are isolated in `signing-keyring.js`
and `seo-preview.js`. Avoid moving private state or route policy merely to
reduce line counts; split additional code when it has a stable contract and
can be tested independently.

## Refactor guardrails (learned during the v1.19 split)

- After any mechanical move, grep every cross-module identifier and run
  behavior tests — `node --check` and import counts miss missing names
  inside methods, and broad `catch` blocks disguise `ReferenceError`s as
  clean negative results (two real incidents: `MIRROR_AXES`, `$`).
- Watch boundary constants (`keyCache`, `bitmapCache`, …): they are the
  declarations most likely to be orphaned by a line-range move.
- Never reuse a scratch buffer whose identity is used as a cache key.
