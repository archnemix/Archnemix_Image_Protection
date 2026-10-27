# Archx reviewer guide

This guide is the fastest route for an external reviewer to understand,
run, and challenge the repository. The product README is the complete user
manual; `docs/RESEARCH.md` records the threat research and the reasoning
behind individual layers.

## What Archx is—and is not

Archx displays website images without exposing a normal downloadable image
file. Its durable security boundary is the server: keep masters outside the
public web root, authorize every token mint and redemption, and send only an
entitled derivative. Around that boundary it adds scrambled delivery,
one-time/sender-constrained tokens, a protected browser viewer, resolution
caps, watermarks, forensic/StegoMark attribution, and optional capture-cost
layers such as Lens and temporal interlace.

Archx is **not DRM**. A person who controls an authorized browser or camera
can capture displayed pixels. Browser-delivered scramble/AES keys are
obfuscation, closed shadow DOM is friction, and screenshots or AI
regeneration cannot be vetoed by page JavaScript. Review findings should
therefore distinguish:

1. a bypass of authorization, path containment, replay, entitlement, or
   processing limits (a security defect); from
2. recovery of the one derivative an authorized viewer was intentionally
   allowed to see (a documented residual risk, although quality, marks, and
   attribution still matter).

## Fresh-clone verification

Requirements:

- Node.js 20.9+ or 22.x;
- npm;
- for the exact browser-test environment used by CI, Linux or WSL is the
  most faithful setup.

From a clean clone:

```bash
npm ci
npm run demo:images
npm run test:all
npm audit --audit-level=high
npm pack --dry-run
```

`npm run test:all` rebuilds `dist/`, runs the Node unit/integration suite,
and then runs the real-Chromium browser suite. At the current review point
the expected results are 44/44 Node tests and 98/98 Chromium checks,
including precomputed manifest assets, manifest-pinning/tampered-variant
rejection, network-aware sampling, preload cache warming, a cold-stampede
coalescing test, and a 100-image batch-minted gallery
with no protected `<img>` elements.
The Node suite includes production-default/audit tests, a two-handler
shared-state replay/quota test, a Redis adapter fake-client contract test,
buyer/order/provenance hook tests, robust StegoMark transforms, and a
signing-key-rotation test. Chromium additionally patches WebGL draw methods
after load and, in a separate page, installs a framebuffer-reading
`drawArrays` hook before the Archx module evaluates; it contrasts Fortress
fail-closed handling with Vault's documented monitor-and-render residual
risk.

To inspect the product manually:

```bash
npm run demo
# http://localhost:4173
```

The demo intentionally uses a fresh random local secret and demo-only
anonymous access. Do not copy that configuration into production. The
standalone `examples/archx-showcase.html` shows the protection ladder and a
direct custom-flags builder; serve its parent folder over HTTP as described
at the top of that file.

## Repository map

| Path | Purpose | Review priority |
| --- | --- | --- |
| `server/middleware.js` | Token mint/batch/redemption boundary: authorization, hardened/catalog defaults and audit, canonical widths, derivative caches, buyer/order tracing, claims, proof of possession, quotas, replay state, proxy handling, security/delivery/provenance events | Critical |
| `server/redis-state-store.js` | Bundled atomic Redis/Valkey state-store adapter | Critical for multi-instance review |
| `server/scramble-image.js` | Sharp derivative pipeline, format/dimension/pixel/time budgets, marks and StegoMark profiles, scrambling | Critical |
| `src/scramble.js` | Shared container, scramble, AES-GCM, forensic, StegoMark, fingerprint, and BMP primitives | High |
| `src/archx.js` | Browser loader/viewer: token fetch/proofs, decode/cache lifecycle, Canvas/WebGL renderers, guards, Lens, temporal effects | High |
| `server/build-assets.js` / `server/build-assets-cli.js` | Incremental responsive `.archx` builder and `archx-build` CLI for static/CDN catalogs | High for scale/static review |
| `server/scramble-cli.js` | `archx-protect` command-line tool | Medium |
| `server/detect-stego-cli.js` | `archx-detect` attribution tool | Medium |
| `server/demo-server.js` | Local demonstration server only | Medium: verify demo relaxations cannot leak into library defaults |
| `tests/unit.test.mjs` | Node unit/integration and hostile-input tests | High |
| `tests/browser-test.mjs` | Real Chromium behavior, visual, lifecycle, and gallery tests | High |
| `demo/` | Interactive demo and automated-test harness | Medium |
| `examples/archx-showcase.html` | Copy-and-run protection ladder/custom-flags showcase | Low/medium |
| `docs/OPERATIONS.md` | Shared state, key rotation, CDN, SIEM, failover, load testing | Critical for production review |
| `docs/COMPLIANCE.md` | ASVS/SOC 2 self-assessment, audit readiness, supply-chain process | High for enterprise review |
| `docs/COMPATIBILITY.md` | Browser/OS support tiers and fallbacks | Medium |
| `docs/IP_HOLDER_GUIDE.md` | Plain-language owner guidance and claim limits | Medium |
| `tools/` | Build, benchmark, demo-image generation, and bounded load test | Low/medium |
| `dist/` | Committed ESM/CJS/minified bundles for direct download and script-tag use | Verify it matches a fresh build; do not hand-edit |

The three JPEGs in `demo-masters/` are intentional demo fixtures. The
100-image gallery under `demo-masters/gallery/` and the sacrificial copies
under `demo/public-unprotected/` are generated by `npm run demo:images` and
are intentionally ignored by Git.

## Suggested review order

### 1. Server authorization and token boundary

Inspect `createArchxMiddleware()` and follow one request through:

- strict configuration and startup failure modes;
- `withHardenedProductionDefaults()` and
  `auditArchxProductionConfig()`—do supported development settings remain
  distinguishable from production blockers, with no secret in either audit?
- image-ID and path validation/containment;
- `authorize()` at both mint and redemption, including buyer/order/
  delivery/trace changes between the two calls;
- callback deadlines and ambiguous-result handling;
- v2 claim validation and entitlement tightening;
- default rejection of `?t=` query tokens and whether the explicit legacy
  opt-in is impossible to enable accidentally;
- deliberate client attempts to widen width/height or quality—the server
  must retain the lower of the signed/current entitlements;
- one-time nonce and proof replay state, including whether a declared
  multi-instance deployment uses one shared atomic store;
- `kid` selection, active/previous signing keys, and issuing-key derivations
  during rollover and retirement;
- proof-of-possession key binding and signature inputs;
- trusted-proxy/IP selection;
- rate limits, quotas, processing queues, and bounded stores;
- cache-deception and error-response behavior;
- batch-mint item isolation/rate spending and whether derivative-cache hits
  occur only after authorization/replay/quota checks;
- canonical width selection inside, never above, the current entitlement;
- disk-cache path containment, bounds, pruning, and non-public placement.

The key question is whether any unauthenticated, revoked, replayed,
oversized, or cross-viewer request can obtain bytes outside the current
entitlement.

### 2. Image-processing boundary

Review the order in `server/scramble-image.js`: byte/format sniffing,
metadata cross-checks, Sharp limits, resizing, watermark/forensic/StegoMark
embedding, scrambling, and optional encryption. Try corrupt, truncated,
format-mismatched, multi-page, many-channel, and decompression-bomb inputs.
Failures should be bounded and controlled rather than process-fatal or
information-leaking.

### 3. Browser client

Follow a token image through `src/archx.js`:

- token and asset-manifest schema/origin/redirect/size validation;
- batch-mint grouping/fallback and manifest variant selection/cache bounds;
- header-token and proof creation;
- payload/container/decode budgets;
- bitmap/payload cache scopes and logout behavior;
- no implicit remint on visibility or ordinary resize;
- Canvas/WebGL fallback and context-loss paths;
- private fields, shadow-root failure, and public option redaction;
- production instances never enabling `debug:true` accidentally;
- detailed/early integrity snapshots for fetch, canvas, WebCrypto, and
  WebGL texture/framebuffer/shader/draw/readback methods—tripwires only;
- sanitized `onEvent`, `Archx.on()`, and plugin payloads: no token, proof,
  key, source, image bytes, canvas, or raw internal error should cross that
  telemetry boundary;
- the checked-in Chromium CSP and the remaining inline-style caveat.

Then check the rendering-only boundaries: poisoned read-back, split
canvases, Lens, guards, strike lockouts, and temporal effects. These are
valuable friction but should not be mistaken for authorization.

### 4. Temporal interlace

Review `normalizeTemporalInterlace()` and both engines:

- `shader`: phase assignment from backing-pixel coordinates in WebGL;
- `frames`: one pre-rendered altered Canvas2D frame per phase;
- `auto`: follows the effective renderer, with actual engine reported by
  the debug-gated test hook;
- layouts: checker, pixels, strips, and randomized blocks;
- fills: `lowres`, `dim`, `black`, and `noise`;
- refresh optimization: the 60 Hz/30 Hz default clamps to two phases, while
  `fortress60` intentionally chooses three 20 Hz phases;
- reduced-motion behavior and continuous CPU/GPU/memory cost;
- Lens composition and legacy `temporalShield` compatibility.

`refreshHz` is a planning target, not a trustworthy browser measurement of
the physical panel. Multiple screenshots, recordings, compositor captures,
and integrating camera exposures can recombine phases.

### 5. Attribution

Review StegoMark as evidence, not access control. Check key derivation,
trace-derived subjects, fingerprint registration through `onStegoIssue`,
fail-closed registry behavior, detector false-positive controls and
high-correction evidence gates, geometry search limits, standard versus
robust profile selection, and the measured transform matrix in the
README/research notes. Challenge robust decoding on unmarked controls,
wrong keys, errors near the correction limit, and reproductions beyond the
tested axis-aligned transforms. The perceptual soft binding is a second
discovery signal; neither mark is represented as rotation-, perspective-,
or AI-regeneration-proof. `onProvenanceIssue` is intentionally only a
key-free hook for an external provenance/C2PA system, not a built-in signer.

### 6. Operations and assurance claims

Review `docs/OPERATIONS.md` against an actual staging deployment rather than
accepting diagrams or configuration prose:

- run the production audit with the real instance count and keep the
  secret-free summary with release evidence;
- use a real Redis/Valkey deployment—not only the fake-client contract
  test—to mint on instance A, redeem on B, and replay on A;
- exhaust a quota across A and B;
- stop or delay the shared store and confirm `503`, not a local fallback;
- fail or delay the StegoMark registry and provenance hook and confirm the
  configured deny policy and alerts;
- rotate and then retire a signing key during the rollover window;
- repeat the replay and cross-viewer tests through the public CDN hostname;
- forward security/delivery events to the intended SIEM/monitoring system
  and trigger test alerts while proving tokens/keys are absent from logs;
- run the load tool against staging with production-like images, auth,
  batch/single minting, cold and warm derivative caches, and state-store
  placement; for `archx-build`, verify manifest authorization/cache policy
  and that masters/build state are absent from the deployed artifact;
- exercise regional failover with unexpired tokens.

`docs/COMPLIANCE.md` is a self-assessment. Do not report Archx as
independently audited, ASVS-certified, SOC 2 compliant, or covered by a
funded bug bounty unless separate evidence exists outside this repository.

## Manual checks worth performing

- Request a master path directly and confirm it is not served.
- Mint a token, redeem it once, replay it, and present it from another
  proof key/browser context.
- Move the token into `?t=` and confirm hardened production rejects it.
- Revoke or downgrade authorization between mint and redemption; repeat
  with a changed buyer/order/delivery identity.
- Request dimensions/quality beyond an entitlement.
- Patch `fetch` or a WebGL draw method before/after load and compare the
  selected Fortress fail-closed and Vault monitor policies; classify the
  result as a tripwire, not proof of browser integrity.
- Load a large gallery, scroll away/back, resize ordinarily, and confirm
  that the network panel does not show needless remints.
- Try canvas read-back, page source, DevTools capture, print, PrintScreen,
  and a phone photo; classify each result as blocked, degraded, marked, or
  expected residual risk.
- Enable each temporal-interlace engine/layout in the demo or showcase and
  evaluate flicker on a real 60 Hz display before considering production use.

## Reporting findings

Useful findings include:

- severity and affected component;
- exact file/function and configuration;
- a minimal reproduction or failing test;
- the security/quality property expected;
- observed impact: master exposure, authorization bypass, replay,
  entitlement widening, path escape, resource exhaustion, data leakage,
  incorrect rendering, or accessibility/performance regression;
- a suggested fix and regression test, if known.

Please follow `SECURITY.md` for exploitable vulnerabilities and do not put
production secrets, bearer tokens, or private master images in public issues.
