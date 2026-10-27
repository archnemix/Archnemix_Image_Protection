# Compatibility and fallback matrix

This matrix separates what is exercised by the repository's automated tests
from standards-based behavior expected in other evergreen browsers. It is
not a claim that every browser/OS combination below has been certified.

## Server runtime

| Component | Supported baseline | Tested in this repository | Notes |
| --- | --- | --- | --- |
| Node.js | `>=20.9.0` | Node 20 and 22 in GitHub Actions | Use a maintained LTS/current release and record the exact version in production evidence. |
| Sharp | `^0.35.5` peer dependency | Locked development dependency | Keep Sharp/libvips current; image decoding is a security boundary. |
| Express | Express-compatible middleware signature | Plain `node:http` integration tests | Express itself is not a package dependency. Confirm mount-path behavior in your app. |
| Operating system | Any OS supported by Node + Sharp prebuilds/source build | Linux CI/sandbox | File-path, symlink, and timestamp behavior should be tested on the production OS/filesystem. |
| State store | Built-in memory, bundled Redis/Valkey adapter, or custom host adapter | Memory store, shared-store contract tests, and a fake-client Redis adapter test | The bundled adapter accepts an ioredis/node-redis-compatible client; production latency, eviction, persistence, and failover still require staging integration tests. |

## Browser support

| Browser / platform | Status | Expected behavior |
| --- | --- | --- |
| Chromium (headless, repository test build) | **Automated: 107 browser checks** | Canvas/WebGL rendering, protected token flow, proof of possession, WebGL draw-hook tripwires, Fortress fail-closed behavior, degraded decoys, temporal shader/frames modes including `fortress60`, gallery lifecycle, sanitized telemetry/plugin events, guard behavior, manifest integrity pinning/tamper rejection, network-aware sampling, asset preload cache warming, origin-tainted `SecurityError` readback, and pixel-exact display verification are exercised (with real web security enabled — no `--disable-web-security`). |
| Google Chrome, current stable and previous major | Expected | Same Chromium platform family. Test your exact site CSP, cookies, CDN, and extensions before release. |
| Microsoft Edge, current stable and previous major | Expected | Chromium-based; same caveats as Chrome. |
| Brave and other Chromium browsers | Expected with site testing | Privacy/network defaults or extension policies can affect fetch, WebGL, storage, and proof-key behavior. |
| Firefox, current stable/ESR | Expected standards-based support | Canvas2D fallback should work where WebGL/WebCrypto details differ. Proof-of-possession `required` deployments must test the exact Firefox versions they support. |
| Safari on macOS, current and previous major | Expected standards-based support | Test WebGL availability, `createImageBitmap`, WebCrypto ECDSA, fetch/headers, and temporal rendering. Use proof mode `auto`/`optional` unless your supported Safari matrix passes `required`. |
| Safari on iOS/iPadOS, current and previous major | Expected with device testing | Memory limits, display refresh behavior, WebGL context limits, and camera interaction vary by device. Prefer bounded derivative sizes and test low-memory devices. |
| Chrome on Android, current stable and previous major | Expected with device testing | Chromium family; verify GPU/context recovery, data-saver/proxy behavior, and refresh rates on target devices. |
| Samsung Internet and in-app WebViews | Best effort | WebView version, cookie handling, hardware acceleration, and download/screenshot behavior are controlled by the embedding app. |
| Internet Explorer and obsolete non-evergreen browsers | Not supported | Modern modules, Shadow DOM, WebCrypto, Canvas, and fetch assumptions do not target these browsers. |

## Feature fallbacks

| Feature | Primary path | Fallback / operator choice |
| --- | --- | --- |
| Rendering | WebGL where available and selected | Canvas2D renderers remain available; choose modes/flags that match your device matrix. |
| Image decode | Browser image decode with byte/dimension/pixel budgets | Invalid or oversized payloads fail closed rather than being displayed through an unbounded path. |
| Proof of possession | Non-extractable WebCrypto ECDSA P-256 key | Client `auto` can proceed where policy allows; server `required` intentionally rejects clients that cannot present a valid proof. |
| Temporal interlace shader | WebGL fragment shader | `frames` uses pre-rendered Canvas phase frames; `auto` selects an available engine. |
| Temporal interlace phases | Two phases for a 60 Hz-safe default | More phases are clamped by refresh assumptions; reduced-motion settings should disable flicker-oriented presentation. |
| Token transport | `X-Archx-Token` header + clean URL | Query-token compatibility is off by default and requires an explicit server opt-in; it exposes bearer material to URL-logging surfaces. |
| Token mint method | `POST` + `X-Archx-Request` | A temporary GET bridge exists for legacy clients; it is not the preferred production posture. Optional batch minting uses `POST {basePath}/tokens` and the bundled client falls back to single POST mints only when that endpoint is absent (404/405/501). |
| Output cache | Local L1, optional persistent disk L2, and optional shared L2 | Disk/shared derivative-cache failure falls back to authorized reprocessing. Replay/quota state never falls back locally in multi-instance mode. |
| Origin-tainted readback | Cross-origin 1×1 pixel (`{basePath}/taint.png` or client `taintUrl`) drawn into 2D canvases; the browser then throws `SecurityError` on every readback API, prototype calls included | Same-origin deployments cannot taint (origin-clean by definition) and keep instance-poisoned decoys; WebGL modes use platform black readback. Relies on the canvas origin-clean flag, not on a new API, so all evergreen browsers enforce it. |
| Precomputed assets | Version-1 `archx-build` manifest + immutable `.archx` variants | Any static host/CDN can serve public variants. Private catalogs must authorize/sign the key-bearing manifest and URLs; there is no dynamic token fallback unless the host also deploys the middleware. |
| Asset integrity | Per-variant SHA-256 digests in the manifest; optional whole-manifest pin (`assetManifestIntegrity`) | Verification uses WebCrypto `SubtleCrypto` (secure contexts). `assetIntegrity:'auto'` skips verification only when no digest or no WebCrypto exists; `'require'` and a configured manifest pin fail closed in that situation. |
| Network-aware sampling | Network Information API (`navigator.connection.saveData` / `effectiveType`), Chromium-family | Firefox/Safari do not expose the API; `networkAware` is then a no-op and the configured DPR/oversample/quality sampling applies unchanged. It is a performance hint, never a security input. |
| StegoMark | Server-side pixel embedding through Sharp | `standard` remains backward-compatible. `robust` uses larger cells, a dual-CRC/marker codeword, median voting, and bounded correction; detection remains empirical and format/geometry dependent, so test it on your catalog and preserve the issued profile. |
| Scramble plan version | v1 (32-bit seed) default; payloads self-describe via container header `pv` | v2 (128-bit seed) requires a pv-aware client (≥ v1.10). Older clients fail to unscramble v2 payloads (mosaic), so deploy clients first, then enable server `scramblePlanVersion: 2` / rebuild catalogs. |
| AVIF derivatives | Server `format: 'avif'` (opt-in) | Requires browser AVIF decode (Chrome 85+, Safari 16.4+, Firefox 113+). Older browsers fail to decode and the viewer errors — there is no per-browser format fallback today, so keep WebP for mixed/legacy audiences. |

## CSP and viewer construction

Archx does not use `eval`, generated scripts, blob/object image URLs, or
remote code. The browser test exercises a policy built around self-hosted
scripts, `'self'` connections, `worker-src 'none'`, and `img-src 'none'`.
`style-src 'self' 'unsafe-inline'` remains the compatibility baseline because
the viewer also sets element properties that browsers surface in `style`.
The library prefers constructable shadow stylesheets in Chromium and falls
back to a shadow `<style>` element where needed, but deployments should test
the style policy in each supported browser before removing the inline-style
exception.

If an operator captures `Archx.captureEarlyIntegritySnapshot()` from an
early, integrity-pinned first-party script and later calls
`Archx.verifyEarlyIntegritySnapshot(snapshot)`, it can distinguish methods
already patched before the viewer bundle loaded from methods replaced later. A
userscript or extension running before the page can still win that race, so
the snapshot is diagnostic evidence rather than a browser trust proof.

## Operating-system considerations

The browser library does not depend on a Windows, macOS, Linux, Android, or
iOS API to block screenshots. Operating systems and privileged browser
extensions can capture the composited screen outside page JavaScript. Archx
shortcut/visibility reactions are best-effort friction only on every OS.

For support purposes, record issues with:

- browser name/version and OS/device;
- GPU/WebGL status and whether hardware acceleration is enabled;
- display refresh rate for temporal-interlace reports;
- client mode and individual protection flags;
- token transport/proof settings;
- whether the failure is rendering quality, authorization, performance, or a
  protection bypass.

## Pre-release device test checklist

Before claiming a browser as supported for a customer deployment, test:

- first load, cache reuse, logout/account switch, and 100-image gallery;
- Canvas and WebGL modes at the maximum entitled derivative size;
- proof `required` if enabled;
- Lens, camera shield, and temporal interlace for readability, reduced
  motion, battery/GPU use, phone-camera appearance, and photosensitivity;
- screen readers/alt text and keyboard behavior around the viewer;
- offline/timeout/retry behavior and token re-mint after a spent token;
- browser zoom, high-DPI, orientation changes, and low-memory tab eviction.
