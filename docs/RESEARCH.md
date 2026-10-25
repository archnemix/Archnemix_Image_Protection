# Research: how website images get stolen, how the big platforms fight back, and what Archx does about it

This document is the study phase behind Archnemix Image Protection: the actual
techniques used to take images from websites, the counter-techniques used in
production by museums, stock libraries and streaming platforms, an honest
assessment of what is and isn't possible in a browser, and how those findings
map onto this library's design.

## TL;DR

- **Perfect protection does not exist on the open web.** If a browser can
  display pixels, a sufficiently determined human can copy those pixels at
  screen resolution (screenshot / camera — the "analog hole"). Anyone
  promising otherwise is selling something.
- **But "perfect" is the wrong target.** In practice, image theft is
  overwhelmingly *lazy*: right-click save, drag-and-drop, "open image in new
  tab", DevTools URL copying, bulk-downloader extensions, and automated
  scrapers. Every one of those depends on the site handing out a usable file
  or URL. Remove the file, remove the URL, scramble what crosses the network,
  poison programmatic extraction, cap the resolution, and watermark what
  remains — and you have defeated ~99% of real-world theft while making the
  remaining 1% slow, manual, and traceable.
- That layered strategy is exactly what large rights-holders do (Google Arts
  & Culture's tiled + signed + encrypted delivery; stock agencies' tiled
  zoom + domain-locked derivatives; streaming's DRM for video). Archx packages
  the still-image version of it into one small library + one middleware, and
  its **Fortress** policy adds controls aimed at the next tier up: payload/key
  reconstruction, API hooking, public debug/instance handles, token replay,
  client-chosen oversized derivatives, repeated extraction probing, decoded
  bitmaps lingering in memory, and single-screenshot capture. Those controls
  reduce value and increase attribution/friction; they do not turn an
  attacker-owned browser into a trusted device.

---

## 1. How images are actually stolen (attack taxonomy)

| # | Attack | Skill needed | What it needs from your site |
|---|--------|--------------|------------------------------|
| A1 | Right-click → *Save image as / Copy image / Open in new tab* | none | an `<img>` (or CSS background) |
| A2 | Drag image to desktop / another tab; long-press on mobile | none | a draggable `<img>` |
| A3 | DevTools → Elements: read `src`, open it directly | low | a URL in the DOM |
| A4 | DevTools → Network (filter: Img): copy/save the response | low | an image response |
| A5 | View-source / `curl` the HTML and scrape every image URL | low (scriptable → bulk) | URLs in HTML |
| A6 | Bulk downloader extensions ("Download all images") | none (bulk) | `<img>` in the document DOM |
| A7 | `canvas.toDataURL()` / `toBlob()` / `getImageData()` / `captureStream()` from console, userscript or extension | medium | an origin-clean canvas |
| A8 | Prototype trick: `HTMLCanvasElement.prototype.toDataURL.call(canvas)` to bypass naïve per-canvas patches | medium-high | a 2D canvas |
| A9 | Guessing/enumerating predictable file URLs (`/images/001.jpg`…), hot-linking | low | predictable public paths |
| A10 | Reusing a leaked/shared image URL later | none | long-lived URLs |
| A11 | Print → PDF, full-page screenshot tools | low | printable pixels |
| A12 | OS screenshot / snipping tool / screen recording / photographing the monitor | none–low | pixels on a screen (**unstoppable**) |
| A13 | Intercepting the network payload with a proxy (mitmproxy on your own machine) | medium | a usable file on the wire |
| A14 | Reverse-engineering the viewer JS and re-implementing its decoder | high (per-site, manual) | determination |
| A15 | Capturing both the scrambled payload and the key delivered to the attacker's own browser, then reconstructing offline | high | a legitimate viewing session |
| A16 | Userscript/extension hooking of `fetch`, `createImageBitmap`, canvas or WebGL APIs before/after the viewer loads | medium–high | script execution in the page |
| A17 | Reaching viewer internals through public instance fields, a global registry, DOM expandos, config echoes, or an always-on debug hook | low–medium | accidental API/DOM handles |
| A18 | Replaying or sharing a signed image URL, possibly from another browser/machine | low | a reusable bearer URL |
| A19 | Tampering with the requested width/derivative parameters to obtain a larger copy than the account/page should receive | low | client-controlled delivery policy |
| A20 | Repeated extraction probing until a race, fallback, or read-back route succeeds | medium | unlimited silent attempts |
| A21 | Recovering a decoded bitmap or clean working canvas retained in browser memory after display | high | long-lived decoded pixels + memory/process access |
| A22 | Taking many screenshots while moving an inspection lens and stitching the sharp regions | low–medium (manual) / high (automated) | a user-controlled sharp viewport |
| A23 | Browser-privileged capture: screenshot extension (`captureVisibleTab`-style APIs), DevTools “Capture screenshot”, remote debugging/CDP, browser automation screenshot | low–medium | control of the browser itself, above page JavaScript |
| A24 | View Page Source / save-page / inspect static assets looking for the image or a reusable signed URL | low | secrets or usable URLs accidentally present in HTML |
| A25 | Cross-device analog capture: phone/camera photographing or filming another device's screen | none–low | photons leaving a display (**physically unstoppable/undetectable by the page**) |

The design goal follows directly: **A1–A11, A13, A16–A20 and A24 should yield
nothing clean or reusable; A12/A14/A15/A21–A23/A25 must be pushed toward at
most a server-authorized, screen-resolution, visibly/forensically marked copy
whose production is slow, noisy, and attributable.**

## 2. What production platforms actually do

### 2.1 Google Arts & Culture — tiling + signed URLs + encrypted tiles
Gigapixel artworks are never served as one file. The image is cut into small
tiles; tile URLs are **HMAC-signed**, and the tile bytes themselves are
**AES-128-CBC encrypted** — the open-source `gapdecoder` project documents
both mechanisms after reverse-engineering them (which itself proves the
point: determined experts *eventually* win, but casual copying is
impossible and bulk ripping needs a dedicated tool per platform).
Zoomable-image vendors use the same idea commercially: Sirv, for example,
offers "image zoom tiling" expressly so *the browser never receives the
large image*, paired with domain restriction so the underlying full-size URL
can't be reconstructed.

**Adopted in Archx:** tile-based scrambling (a lighter cousin — one shuffled
file instead of hundreds of tile requests), HMAC-signed expiring URLs,
optional AES-GCM payload encryption, server-enforced down-scaling.

### 2.2 Netflix / streaming — why their screenshots are black (and why ours can't be)
Streaming video is protected by **Encrypted Media Extensions (EME)** with a
CDM such as Widevine: decryption keys never enter JavaScript, frames are
decoded by a protected media pipeline, and with HDCP output protection the
OS compositor itself excludes the surface from captures — hence black
screenshots. This works because there is an OS/GPU-level trusted path for
*video*. **There is no equivalent trusted path for still images or arbitrary
web content**, which is why "prevent screenshots of a webpage" is
fundamentally impossible outside that pipeline — a fact worth stating to
users rather than papering over. Streaming also relies on **per-session
forensic watermarking** so leaks can be traced to an account even when
captured with a camera.

**Adopted in Archx:** the forensic-watermark philosophy (per-session grain +
baked visible watermark with session id). The black-screenshot trick itself
is not available to images; we approximate its *effect* for programmatic
captures (A7/A8) with WebGL drawing-buffer clearing (see 2.5).

### 2.3 Canvas-instead-of-`<img>`, tokenised proxy URLs (portfolio/art platforms)
A common "defence in depth" stack on art/portfolio platforms: paint the image
onto `<canvas>` (killing the native save menu), never expose the storage URL
— issue **time-bound proxy URLs** instead — and obfuscate the token so it
can't be eyeball-parsed. On its own each layer is weak; combined they stop
casual theft cold.

**Adopted in Archx:** all three, plus the hardening they usually skip
(poisoned read-back, closed shadow DOM, no URL in the DOM at all).

### 2.4 "Never let an `HTMLImageElement` exist" + WebCrypto (potproject's experiment)
A widely-cited maximalist experiment goes further than canvas painting: it
avoids `new Image()` entirely (anything loaded as an image shows up in
DevTools' Network *Img* filter), decoding instead from `Blob` +
`createImageBitmap()`; ships the image **AES-encrypted** (AES-CBC + PBKDF2
via WebCrypto) so network capture yields unidentifiable bytes; bakes a
copyright notice into the canvas; and layers interaction/DevTools
obstruction on top. Its author is refreshingly explicit that "absolute"
protection is a clickbait title — the achievement is making scraping
*uneconomical*.

**Adopted in Archx:** `fetch()` → `ArrayBuffer` → `createImageBitmap()`
pipeline (Network tab shows `application/octet-stream`, never an image),
`.archx` container, AES-GCM option, baked-in watermark.
**Deliberately not adopted:** page-wide right-click/keyboard blocking and
anti-Debugger harassment — they punish legitimate users, break accessibility
tools, look like malware, and stop nobody skilled. Archx guards attach to
the protected component only, and DevTools-open blurring is opt-in.

### 2.5 Browser platform primitives that help

- **Tainted canvas.** Drawing a cross-origin image without CORS approval
  *taints* a canvas; the browser then throws `SecurityError` on
  `toDataURL()`/`toBlob()`/`getImageData()` — un-bypassable enforcement, but
  it requires a cross-origin source and conflicts with `fetch()`-based
  scrambling (CORS would block reading the bytes at all). Archx therefore
  doesn't depend on it, but its client-only fallback path (detached `Image`)
  can incidentally benefit.
- **WebGL `preserveDrawingBuffer: false`** (the default). The drawing buffer
  is cleared after compositing, so any later read-back — *including*
  `HTMLCanvasElement.prototype.toDataURL.call(canvas)` (attack A8) — returns
  black/transparent. This is the strongest anti-extraction primitive the
  platform offers for stills, and it is what powers Archx **vault** mode.
  Its constraint is real: browsers only allow ~8–16 simultaneous WebGL
  contexts, so vault is for hero images, not 500-item grids.
- **Closed shadow DOM.** `attachShadow({mode:'closed'})` makes
  `element.shadowRoot` return `null` and removes the subtree from
  `document.querySelectorAll('canvas')` etc. Casual JS and content-script
  extensions (A6) can't see in. (Chrome DevTools' Elements panel can still
  display closed roots — it's a scraper/extension barrier, not a
  DevTools barrier, and we treat it as such.)
- **WebCrypto (AES-GCM)** is hardware-accelerated and available in browsers
  and Node ≥ 19 — encrypting a ~130 kB payload costs a few milliseconds.

### 2.6 The folk techniques — and why they're insufficient alone

Right-click blockers, `pointer-events:none`, transparent overlay GIFs,
CSS-background instead of `<img>`, inline base64 data-URLs, "disable F12"
scripts: each defeats exactly one lazy gesture and collapses the moment the
attacker opens DevTools or curls the page (A3–A6). Several popular libraries
(`ProtectImage.js` and friends) stop at "paint it on a canvas", which still
leaves the original URL fetchable in the Network tab and the canvas one
`toDataURL()` away from a PNG. Archx keeps the useful bits (canvas, overlay,
interaction guards) and adds the missing layers (no-URL delivery,
scrambling, signed expiry, poisoned read-back, resolution caps).

### 2.7 Determined-attacker hardening: make successful extraction low-value

The first design iteration correctly concentrated on the file/URL boundary.
The harder question is what happens when the adversary is also an authorized
viewer and can observe every input their own browser receives. In that model,
payload secrecy from the viewer is impossible: the browser must receive enough
information to display the picture. The useful controls therefore move **before**
delivery (authorization and marking), **around** delivery (replay/binding),
**inside the API surface** (no accidental handles), and **after** display
(memory lifetime and attempt escalation):

- **Bake attribution in before scrambling.** Client-drawn watermarks do not
  help against A15 because the attacker can ignore the client renderer and
  un-shuffle the captured derivative themselves. Archx's server can composite
  a visible SVG watermark and apply a seeded macro-block forensic mark to the
  resized derivative *before* tile permutation/encryption. Perfect offline
  reconstruction then reconstructs the marks too. The CLI can bake the same
  marks into static `.archx` assets.
- **Authorize the derivative, not just the URL.** A signature over an image id
  is insufficient if the browser can append `w=8000`. Middleware entitlements
  let `authorize()` return a viewer identity and maximum width; the capped
  width is included before signing. Viewer identifiers are HMAC-hashed for
  token/cache/forensic derivation instead of being treated as raw secrets.
- **Make bearer URLs expire in more than time.** Optional one-time nonces
  reject replay, and signed IP/User-Agent bindings make a copied URL fail in a
  different browser context. Origin/Referer allowlists and separate signer vs
  image rate limits reduce non-browser harvesting. These are delivery
  controls, not viewer-proof cryptography: the intended browser can still use
  its first (and only) response however its owner instruments it.
- **Remove accidental control handles.** JavaScript `#private` fields,
  module-private `WeakMap` host/element registries, redacted option/config
  views, no public instance list, and a debug hook that exists only when a
  specific instance opts in remove the easy script/extension route from “find
  element” to “call internal canvas/bitmap methods.” DevTools, which operates
  outside normal page privilege, can still inspect more than page JS can.
- **Capture then audit native APIs.** Archx records sensitive function
  references at module evaluation and calls those references internally. The
  audit compares current functions with the captured references and checks
  whether captured functions still report native bodies. Fortress can fail
  closed. This defeats ordinary later monkey-patching and detects naive
  earlier hooks; an attacker who patches below JS, controls the browser
  binary, or successfully forges native fingerprints before module load can
  evade it. It is a tripwire and bypass-reduction layer, not attestation.
- **Turn probing into an incident, not a free oracle.** Extraction attempts
  can feed a strike policy: report, blur, then lock/blackout for a cooldown.
  Automation signals feed the same reporting/lock framework. This cannot stop
  a separate capture process, but it removes unlimited silent retries inside
  the page and gives the site telemetry for account-level action.
- **Shorten clean-pixel lifetime.** Strict memory mode avoids shared decoded
  bitmap retention, closes bitmaps promptly, wipes CPU-side clean canvases
  after GPU upload, and can locally scramble plain sources before uploading a
  WebGL texture. This narrows A21. Composited pixels necessarily exist in the
  browser/GPU/OS path while visible, so process/GPU compromise remains out of
  scope.
- **Attack the “one perfect screenshot” assumption.** Fortress Lens renders
  a pixelated base and only a sharp disc around trusted (`isTrusted`) pointer
  input; synthetic script events do not move the disc, and rapid/broad sweeps
  can be reported as lens scanning. This makes a single screenshot mostly
  degraded and automated stitching harder. A patient human can still move a
  real pointer and stitch, so Lens is a UX/friction tradeoff, not DRM.

The combined objective is **value destruction**: any eventually successful
copy should be no larger than the server chose to authorize, visibly owned,
forensically attributable where geometry/quality permit, and obtained one slow
image at a time after generating suspicious events. That is materially
different from promising that pixels can be both shown to and withheld from
the same untrusted machine.

### 2.8 Screenshot privilege levels — what can and cannot be “stopped”

Screenshot requests often get collapsed into one feature request, but they
sit at four different privilege levels:

1. **Page-level extraction** (`canvas.toDataURL`, DOM downloaders, injected
   page scripts): the site controls this layer. Archx can and does poison
   read-back, seal internals, audit hooks, and make Vault read-back black.
2. **Browser-privileged capture** (screenshot extensions, DevTools screenshot,
   CDP/automation): the capture runs outside the page's JavaScript sandbox.
   A site cannot reliably enumerate extensions, receive a veto callback, or
   distinguish a privileged capture from ordinary compositing. Closed shadow
   DOM and view-source hygiene still deny the *file/URL*, but the visible tab
   can be photographed by the browser that rendered it.
3. **OS-level capture** (PrintScreen, Snipping Tool, macOS Screenshot,
   compositor recorders): the operating system owns the final pixels. Some
   shortcuts/focus transitions leak a signal to the page; many are consumed
   before the page can react or the desktop is frozen at invocation. Archx
   listens on keydown/keyup, blur/focus, visibility, print and page-freeze
   paths and blackouts/blurs when a signal arrives, but this is best-effort,
   not a capture API.
4. **Physical capture** (phone/camera pointed at another screen): no signal
   exists in the displaying device. There is nothing to detect. The only web
   defenses are not showing the whole sharp image at once, capping/marking
   the derivative, and changing attribution over time.

That analysis produced two Fortress additions. **Lens** changes the visible
frame itself, so every capture class inherits the degradation. **Dynamic
capture trace** adds a slowly drifting session/time DOM trace above the image
(optionally with a shifting temporal phase pattern): privileged screenshots
and camera photos carry attribution, and captures taken seconds apart do not
line up as one clean stitching set. Neither should be marketed as “screenshot
blocking”; only a trusted OS/DRM display path could make that claim.

### 2.9 Why protected rendering looked slurry — and the quality fix

Protection quality is not determined by tile permutation (which is lossless).
Measurements isolated four lossy stages:

- **Derivative encode quality.** The old q82 scrambled WebP spent bits on 64
  artificial tile boundaries and chroma detail. On the 800 px watch image,
  reconstruction improved from **36.6 dB PSNR / 2.56 MAD at q82 to 41.0 dB /
  1.43 MAD at q95**. The server/CLI now default to q95 with high-quality
  chroma handling, and offer WebP/PNG lossless delivery for bit-exact pixels
  at the chosen derivative size.
- **Width-only sizing under `object-fit: cover`.** Asking only for the host's
  CSS width is wrong when the host box is squarer/taller than the source: the
  browser crops the derivative and then upscales it. Token requests now carry
  the display box and fit mode; the server uses source aspect to sign the
  cover-safe width, still subject to entitlement caps.
- **Display density and resampling count.** A DPR cap of 2 makes modern 3×
  screens upscale the canvas. Archx now allows DPR 3, requests a supersampled
  derivative (2× for hero images, 1.5× in the gallery helper), reassembles
  tiles at native/oversampled resolution, and does one progressive
  high-quality final downscale instead of scaling every shuffled tile
  directly to its final rectangle.
- **WebGL filtering.** One bilinear tap softens 1:1 detail and aliases when
  minifying. The shader now uses exact `texelFetch` around 1:1 footprints and
  2×2 supersampling when minifying a scrambled texture (whose mipmaps would
  bleed across shuffled tiles); unscrambled textures can use trilinear mips.

The important boundary is unchanged: “original quality” means the pixels of
the **authorized displayed derivative** can be lossless and rendered as
faithfully as an ordinary image at that CSS/DPR size. It cannot mean sending
the full master merely so the browser can downscale it—that would defeat the
resolution boundary. Sites choose the derivative ceiling per viewer.

## 3. Threat model

| Adversary | Goal | Archx outcome |
|---|---|---|
| Casual visitor | save a picture they like | Finds no save path at all (A1/A2 dead-end) |
| Bookmarklet/extension user | strip a page/gallery in one click | DOM has no images; canvas grabs return decoys |
| Scraper bot operator (incl. AI training crawlers) | harvest a whole catalogue | No URLs in HTML; needs JS + fresh signed token per image, rate-limited; payloads are mosaics/ciphertext |
| Script/extension injector | hook web APIs or grab viewer internals wholesale | Captured natives bypass later hooks; audits can fail closed in Fortress; no host expando/public registry/debug handle exposes canvases, bitmaps, or keys |
| Token thief | replay/share a captured delivery URL or inflate its derivative size | Short expiry + optional one-time nonce, IP/User-Agent binding, origin checks, and signed server-side entitlement width |
| Skilled fan / pirate | extract one specific premium image | Must reverse the scramble + capture session keys from their own browser; even perfect reconstruction is capped at the authorized derivative and can retain server-baked visible/forensic marks. Fortress adds strict memory lifetime and probing lockouts |
| Insider / paying customer | leak content they can legitimately view | Screenshot/camera remain possible, but the delivered pixels can carry viewer-specific visible + forensic marks; Lens prevents one screenshot from containing the whole sharp image |
| Screenshot-extension / DevTools user | capture the visible tab with browser privileges | Page JS cannot veto the capture; source/DOM still expose no file or signed URL, Vault read-back is black, and Fortress visible pixels are Lens-degraded + dynamically traced |
| Cross-device photographer | keep the site open on one device and photograph it with another | Undetectable in principle; quality is limited by the entitled derivative and screen/camera losses, with server marks, dynamic trace, and Lens reducing resale value |

Non-goals: hiding that protection exists, DRM-level guarantees, stopping a
camera pointed at a monitor, proving browser integrity on a machine the
attacker owns, defending composited frames against a compromised browser/GPU
process, or compensating for masters also hosted at public URLs (that's a
deployment error — see the README checklist).

## 4. Design decisions (and rejected alternatives)

1. **One scrambled file vs hundreds of tile requests.** True per-tile HTTP
   delivery (Google-style) multiplies requests and server work; a single
   tile-*shuffled* image gives almost the same capture-resistance at one
   request and ~64 `drawImage` calls. Chosen, with `splitCanvases` available
   when "no single canvas may hold the whole image" matters more than DOM
   weight.
2. **Scramble transform = permutation + mirrors (no 90° rotations, no
   per-pixel channel ops in 2D).** Mirrors are self-inverse and free with
   `drawImage` transforms; 90° turns break non-square tiles; per-pixel
   work would kill the "hundreds of images" budget. (The WebGL shader could
   afford more, but sharing one spec between CPU/GPU/server keeps them
   verifiably identical.)
3. **Poison per-instance, never prototype-wide.** Globally replacing
   `HTMLCanvasElement.prototype.toDataURL` (a trick seen in the wild) breaks
   the host page's own canvases (charts, editors, captcha) and is trivially
   detected. Archx shadows the methods on its own canvases only, and is
   upfront that vault mode is the answer to the prototype bypass.
4. **Display-size backing stores as a security boundary.** The canvas never
   holds more pixels than the CSS box × DPR (hard-capped). Combined with
   server-side down-scaling this makes "steal the original quality"
   mathematically impossible rather than merely inconvenient — the bytes
   simply never exist client-side.
5. **Keys delivered to the legitimate client are not "secret" — and that's
   fine.** Any scheme a browser can execute can be observed by its user.
   Archx's cryptography targets *transport* threats (A10/A13: shared links,
   captured payloads, bulk replay), not the viewer themselves; the expiry,
   resolution cap and watermark handle the viewer. Pretending otherwise is
   how vendors end up with security theatre.
6. **Performance is a protection feature.** If protecting 300 product photos
   tanks scrolling, sites will switch it off. Hence: shared
   `IntersectionObserver`, max-6 decode concurrency, bitmap LRU (of
   *scrambled* bitmaps), off-screen unloading, integer-tile reassembly with a
   single smoothing pass (no seams, no per-pixel loops), server output
   caching, and a hard WebGL-context budget with automatic fallback.
7. **Server marks outrank client marks for reconstruction resistance.** A
   client-added `{session}` watermark is useful against screenshots/canvas
   grabs, but the offline reconstruction path bypasses the client renderer.
   Therefore the middleware/CLI can mark the resized derivative before
   scrambling. Header `wm`/`fx` flags let operators verify that the delivered
   container was marked without placing the forensic seed in the payload.
8. **Entitlements are signed policy, not presentation hints.** Width is part
   of the security boundary. The middleware accepts a browser's desired width
   only as a request, clamps it by global and per-viewer `maxWidth`, and signs
   the resulting derivative size. One-time/browser-bound tokens are optional
   because they increase token churn and can interact with retries, mobile IP
   changes, and shared networks.
9. **Encapsulation should be structural, not naming-based.** Calling a field
   `_canvas` is only a convention. `#private` fields and private WeakMap
   registries make internals unavailable to ordinary page script even if it
   obtains the public `ProtectedImage` object or host element. A default-off,
   per-instance debug opt-in preserves testability without shipping an
   always-available extraction handle.
10. **Per-viewer attribution deliberately costs cacheability.** Per-token
    watermarks, forensic seeds, scramble keys, strict bitmap release, and
    one-time URLs all reduce reuse and may force fresh token requests. The
    API therefore exposes the granularity (`forensicPerToken`, static CLI
    marks, normal vs strict memory, `lite` vs `fortress`) rather than forcing
    maximum paranoia onto 500 catalogue thumbnails.
11. **Quality is also a protection feature.** If protected images look slurry,
    sites will publish an unprotected copy beside them. Delivery therefore
    defaults to q95, offers lossless derivatives, sizes by display box +
    source aspect rather than width alone, renders at up to DPR 3, reassembles
    tiles before the final resample, and uses footprint-aware WebGL sampling.
    Security comes from withholding the master and controlling derivative
    entitlement—not from needlessly recompressing/resampling the derivative.
12. **Do not pretend page JS outranks the OS, browser chrome, or physics.**
    Screenshot shortcuts and blur/freeze signals are used opportunistically,
    but the robust anti-capture controls change what is visible (Lens),
    when attribution changes (dynamic trace), and what resolution was ever
    authorized (server entitlement). This avoids brittle “disable F12” theatre
    while making every privileged/physical capture class inherit the same
    value limits.

## 5. Evidence (this repo's measurements)

- **Unit/integration (Node, 14 tests):** scramble plans are deterministic,
  key-sensitive permutations; pixel scramble round-trips exactly; scrambled
  payloads are visually unrecognisable (mean absolute pixel difference vs
  master ≈ 55/255 on photo content) while un-scrambling restores them;
  encrypted payloads don't parse as images and fail closed under wrong keys;
  tokens reject tampering, expiry and id-swaps; the HTTP flow serves only
  down-scaled `.archx` containers. Delivery-quality tests prove the new q95
  default retains materially more fine-line/text detail than q82 and that
  lossless WebP reconstruction is **pixel-exact (MAD 0)** at the delivered
  size. Cover-aware token sizing is regression-tested (a 4:3 source in a
  120×120 box signs 160 px, not a crop-then-upscale 120 px). The hardened
  middleware tests also prove that an entitlement's 180 px cap overrides a
  browser's 900 px request, a disallowed/missing origin fails, the wrong
  User-Agent cannot spend a bound token, the right browser can spend it only
  once, and the payload advertises server `wm`/`fx` embedding. A separate
  reconstruction test verifies the actual visible watermark and a >0.7
  forensic correlation remain after offline un-shuffling—not just flags.
- **Real browser (headless Chromium, 55 checks):** a page with 7 protected
  images + 1 normal `<img>` exposes exactly **1** downloadable image (the
  normal one) — 0 canvases reachable from the document, 0 URLs in any
  protected element's HTML, closed root invisible to JS; protected hosts have
  no `__archx` expando, `Archx._instances` is absent, public option/config
  views redact secrets, instances expose no public canvas property, and
  `_debug()` is null without explicit per-instance opt-in. At native element
  resolution the Shield render now measures **7.03 MAD and 0.85 gradient-detail
  ratio** versus the ordinary `<img>` (the cover/quality work moved this from
  11.28 / 0.53 in the failing intermediate measurement). `toDataURL`/`toBlob`/
  `getImageData` all return decoys and fire attempt events; repeated probes
  trigger the configured strike blackout. Replacing `fetch` is both reported
  by `auditIntegrity()` and causes Fortress to fail closed. Trusted pointer
  movement positions the Lens while a synthetic untrusted event does not; the
  dynamic capture trace is active with session/time text, and a PrintScreen
  signal immediately blackouts. Strict mode reports the bitmap released and
  the GPU source scrambled. The WebGL prototype bypass returns **pure black**
  (mean RGB ≈ 0), split mode uses 9 separately poisoned canvases, guards and
  print blackout engage, and network checks confirm a marked mosaic payload,
  one-time replay rejection, and wrong-User-Agent rejection.
- **Performance/quality tradeoff:** 100/100 gallery images loaded+painted in
  about **2.1 s** in the deliberately non-lazy headless test with high-quality
  derivatives and 0 `<img>` tags; browser bundle **49.5 kB minified / 17.2 kB
  gzipped**. The 900 px q95 server pipeline measured ~147 ms one-time per
  cached variant. Static/per-image server outputs remain cacheable; per-token
  marks/keys and lossless payloads intentionally trade bytes/cache hits for
  attribution and exactness.

## 6. Sources

- MDN, *Use cross-origin images in a canvas* (tainted-canvas rules) —
  https://developer.mozilla.org/en-US/docs/Web/HTML/How_to/CORS_enabled_image
- gapdecoder (Google Arts & Culture internals: HMAC-signed tile URLs,
  AES-128-CBC tile images) — https://github.com/gap-decoder/gapdecoder
- dezoomify-rs (how tiled viewers work / are attacked) —
  https://dezoomify-rs.ophir.dev/
- Sirv help centre, *Protect images from copyright theft* (zoom tiling +
  domain restriction) — https://sirv.com/help/articles/protect-images-copyright-theft/
- *Defense against image scrapers, in Depth* (obfuscated token proxy +
  canvas rendering) —
  https://dev.to/rpi1337/defense-against-image-scrapers-in-depth-shielding-digital-art-with-emojis-proxies-and-pixels-201l
- potproject, *never-scrape-image* (no-`Image()` decoding, AES via WebCrypto,
  honest limits) — https://blog.potproject.net/2023/05/26/never-scrape-image/
  and https://github.com/potproject/never-scrape-image
- Stack Overflow / Webmasters SE discussions on the limits of download
  prevention and on EME/HDCP being video-only —
  https://stackoverflow.com/questions/61764715/how-can-you-prevent-screen-captures-on-the-web-2020
  · https://webmasters.stackexchange.com/questions/132996/how-to-prevent-pictures-from-being-downloaded-by-right-clicking-on-them-or-inspe
- Information Security SE, *Discouraging users from copying images*
  (tiling/XOR-strip schemes, overlay & hotlink techniques) —
  https://security.stackexchange.com/questions/122922/discouraging-users-from-copying-images-off-a-website
- Cambridge in Colour, *How to Protect Online Photos* (hidden layers,
  tiling trade-offs) — https://www.cambridgeincolour.com/tutorials/protect-online-photos.htm
- ProtectImage.js (representative canvas-only library) —
  https://github.com/puffinsoft/ProtectImage.js
- MDN, *Private elements* (language-enforced class privacy) and *WeakMap*
  (non-enumerable object-key associations) —
  https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Classes/Private_elements
  · https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/WeakMap
- MDN, *Event.isTrusted* (distinguishes user-generated events from script-
  dispatched events) and *ImageBitmap.close()* (explicit decoded-bitmap
  disposal) —
  https://developer.mozilla.org/en-US/docs/Web/API/Event/isTrusted
  · https://developer.mozilla.org/en-US/docs/Web/API/ImageBitmap/close
- Chrome Extensions API, `tabs.captureVisibleTab` (privileged visible-tab
  capture available to extensions, not vetoable by page content) —
  https://developer.chrome.com/docs/extensions/reference/api/tabs#method-captureVisibleTab
- MDN, Page Lifecycle / `Document` `freeze` event, `Window.devicePixelRatio`,
  and `CanvasRenderingContext2D.imageSmoothingQuality` (the platform signals
  and quality knobs used by the capture/quality paths) —
  https://developer.mozilla.org/en-US/docs/Web/API/Document/freeze_event
  · https://developer.mozilla.org/en-US/docs/Web/API/Window/devicePixelRatio
  · https://developer.mozilla.org/en-US/docs/Web/API/CanvasRenderingContext2D/imageSmoothingQuality
