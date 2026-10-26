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
| State store | Built-in memory or host adapter | Memory store plus a shared-store contract test | Redis/Dynamo adapters are host-supplied and need their own integration tests. |

## Browser support

| Browser / platform | Status | Expected behavior |
| --- | --- | --- |
| Chromium (headless, repository test build) | **Automated: 72 browser checks** | Canvas/WebGL rendering, protected token flow, proof of possession, temporal shader/frames modes, gallery lifecycle, and guard behavior are exercised. |
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
| Token transport | `X-Archx-Token` header + clean URL | Query-token compatibility can be enabled server-side, but it exposes bearer material to URL-logging surfaces. |
| Token mint method | `POST` + `X-Archx-Request` | A temporary GET bridge exists for legacy clients; it is not the preferred production posture. |
| Output cache | Local L1 plus optional shared L2 | Shared-cache failure falls back to authorized reprocessing. Replay/quota state never falls back locally in multi-instance mode. |
| StegoMark | Server-side pixel embedding through Sharp | Detection is empirical and format/geometry dependent; use the compatibility/robustness limits in the research docs and test your catalog. |

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
