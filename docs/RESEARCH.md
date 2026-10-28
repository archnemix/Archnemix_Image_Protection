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
  bitmaps lingering in memory, and single-screenshot capture. v1.3 adds the
  operational complements current sellers rely on: direct per-image policy
  parameters instead of opaque modes, a no-reload/draw-on-demand lifecycle,
  temporal single-frame degradation, and a blind StegoMark fingerprint +
  detector/registry workflow. Those controls reduce value and increase
  attribution/friction; they do not turn an attacker-owned browser into a
  trusted device, and they do not make visible pixels AI-regeneration-proof.
  v1.4 hardens the production boundary around those layers: server startup
  and every token redemption are deny-by-default, token claims and paths are
  strict, security stores and Sharp work are bounded, and the separate-device
  work is split honestly between browser-feasible temporal degradation and
  hardware systems a web page cannot reproduce.
  v1.5 removes remaining fail-open/test/debug-style surfaces, treats token
  endpoints and image bytes as untrusted on both sides of the wire, moves
  bearer tokens out of payload URLs, adds DPoP-style sender-constrained
  redemption, hardens clean URLs against shared-cache deception, and adds a
  perceptual soft binding as a second attribution lookup. It also states the
  modern stealth-browser conclusion plainly: coherent fingerprint spoofing
  and CDP/Juggler control can pierce client-side encapsulation, so the
  security boundary is server authorization + entitled derivative size +
  quotas/revocation + attribution, not the shadow root.

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
| A26 | Defeat temporal/psychovisual defences by screen-recording, averaging many screenshots, or using a long camera exposure | low–medium | multiple presented frames over time |
| A27 | AI-assisted cleanup: denoise, upscale, inpaint watermarks, or diffusion-regenerate a degraded capture until pixel marks are weakened/removed | low (consumer tools)–medium | any visible copy, however degraded |
| A28 | Repost a copy while denying its origin / stripping metadata and visible credit | none | ambiguity about which issued view leaked |
| A29 | Copy a still-valid bearer token from logs, history, a proxy, browser tooling, or a screenshot and redeem it in a different browser | low | a bearer token that is sufficient by itself |
| A30 | Web-cache deception: persuade a CDN/shared cache to store a private derivative under a clean/static-looking URL and serve it to someone else | low–medium | a cache rule that overrides origin privacy or ignores credential/token variance |
| A31 | Stealth automation with source-patched browsers, coherent fingerprint spoofing, raw CDP/Juggler, and DOM piercing of closed shadow roots | medium | client-side bot signals or encapsulation being mistaken for a trust boundary |
| A32 | Fail-open integration mistakes: misspelled security options, ambiguous `authorize()` results, weak/demo secrets, public test/signing hooks, or a debug surface left enabled | none–low | configuration/API ambiguity becoming an accidental bypass |
| A33 | Hostile upstream/token response or image input: redirects to another origin, oversized streamed bodies, decompression bombs, parser-confusing formats, or local-path strings reaching a native decoder | medium | unbounded trust in JSON, URLs, headers, or image bytes |

The design goal follows directly: **A1–A11, A13, A16–A20, A24 and A29–A33
should yield nothing clean or reusable outside the authorized page/session;
A12/A14/A15/A21–A23/A25–A27/A31 must be pushed toward at most a
server-authorized, screen-resolution, visibly/forensically marked copy whose
production is slow, noisy, rate-limited, revocable, and attributable; A28
should leave the owner StegoMark and/or soft-binding evidence rather than
screenshots and assertions.**

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

### 2.10 2026 production patterns: licensed previews, shifting reveals, forensic IDs, temporal frames, and AI

The follow-up research for v1.3 looked specifically at how current image
sellers and protection vendors behave when they accept that screenshots are
possible. Four patterns recur:

- **The control plane is licensing + derivatives, not a clever page trick.**
  Stock/preview businesses keep the valuable file behind authentication and
  commerce, publish a bounded preview derivative, bake marks into that
  derivative, and monitor/enforce afterwards. The browser layer's job is to
  make the preview awkward to harvest; the server's entitlement decision is
  what actually determines what a viewer may receive. Archx mirrors that split:
  signed entitled derivatives, optional per-viewer quality/format caps, and no
  master URL.
- **Gallery vendors now degrade the *visible frame*, not just the file.**
  ShootProof's Screenshot Protection is representative: on desktop it reacts
  to a capture attempt with blur/notice, while on mobile part of every image
  stays blurred and the revealed region shifts under intentional touch, so a
  single screenshot cannot contain the whole clean photograph. The vendor's
  own copy still frames this as discouragement/defence rather than absolute
  prevention. Archx's trusted-pointer Lens is the same product insight with a
  shader/canvas implementation: change what any one capture can contain.
- **Serious leak attribution is per-recipient and detector-backed.**
  Forensic-watermark vendors (IMATAG, NAGRA NexGuard and similar systems)
  embed a unique invisible identifier for each recipient/session, retain an
  issuance record, and later run a detector over a suspect copy to identify
  the source view. Steg.AI's **Light Field Messaging** goes further: it is
  patented deep-learning photographic steganography designed so the hidden ID
  remains recoverable even through screen-to-camera capture. Two lessons
  matter for an open web library. First, a mark without a registry and a
  detector is only half a system. Second, it would be dishonest to claim a
  small classical embedder is “the same as” a trained neural LFM stack.
  Archx therefore implements the tractable part faithfully — a keyed,
  redundant, blindly decodable 48-bit StegoMark payload + CRC, soft repair,
  `onStegoIssue` registry hook and `archx-detect` — and labels it attribution
  evidence with measured robustness, not neural/DRM equivalence.
- **Human-vs-camera temporal separation is real, bounded, and old.**
  Temporal-dithering proofs of concept alternate complementary noisy frames:
  one frame adds a random offset, the next subtracts it, and human temporal
  integration averages the pair back toward the source while one screenshot
  keeps a noisy half. Temporal psychovisual modulation research uses the same
  visual-system gap against camcorders. The limits are equally clear: screen
  recording, averaging several captures, long-exposure photography and good
  denoisers can reconstruct much of the signal; refresh/rolling-shutter
  behaviour varies; and visible flicker can fatigue or exclude users. Archx's
  `temporalShield` therefore degrades a *single* OS/extension/DevTools frame,
  honours `prefers-reduced-motion` by default, and is layered under Lens,
  dynamic trace and baked marks instead of posing as a PrintScreen veto.
  Literal **temporal interlace** is the stricter partition variant: only one
  spatial subset is sharp in a presented phase, while the complementary cells
  carry a low-detail, dim, black, or noise fill. It is also harsher. On the
  60 Hz displays targeted by Archx's default profiles, even an optimal
  two-phase cycle refreshes each subset at only 30 Hz; black inactive cells
  maximize both missing information and luminance flicker. The shipped
  default therefore uses fine 2-device-pixel checker cells and a locally
  averaged fill, while still labelling the result a capture-cost/flicker
  trade-off rather than an invisible selective-viewing system.

The AI update cuts across all of the above. Peer-reviewed work on generative
regeneration shows that adding noise and re-synthesizing an image with a
diffusion model can remove or weaken many pixel-level invisible watermarks
while preserving what the picture *is of*. Consumer watermark-removal and
upscaling tools make the practical version of that attack cheap. The correct
response is not to promise “AI-proof” pixels. It is to (a) never ship the
master/high-value derivative in the first place, (b) reduce what one capture
contains, (c) keep visible attribution where the business model allows it,
(d) retain server issuance logs/fingerprints for evidence, and (e) monitor and
enforce outside the page.

Finally, the same product research argues against modal, all-or-nothing
configuration. A catalogue thumbnail, an editorial hero, a paid product view
and a pre-release proof need different points on the quality/friction/
attribution curve. v1.3 therefore treats modes as presets over direct public
parameters — quality profile/requested quality, cache and reload policy,
render loop, Lens, capture trace, temporal shield, strikes, guards, memory,
integrity and server quality/format/StegoMark issuance — and ships
`Archx.preset(name, overrides)` so sites can state a policy and still flip one
switch without forking the library.


### 2.11 v1.4 deep dive: production access control, bounded image work, and photographing a screen

The v1.4 review started from an uncomfortable conclusion: a polished viewer
does not compensate for a permissive delivery endpoint. Most catastrophic
losses would not require defeating the scramble at all—an attacker would ask
the server for a bigger derivative, replay a URL, enumerate public masters,
wait for an unbounded limiter/cache to pressure the host, or feed the image
pipeline a pathological file. The server therefore now follows the same
deny-by-default model OWASP recommends for application authorization:

- `createArchxMiddleware()` is a **configuration boundary**, not a bag of
  optional hints. Missing/short/known-demo secrets, malformed origins or
  processing values, no indexed supported masters, master/public overlap, or
  “neither `authorize()` nor explicit `allowAnonymous:true`” fail startup. A
  non-throwing `auditArchxServerConfig()` makes that policy testable in CI
  without returning secret material.
- Authentication remains the host site's job; authorization is object-level
  and checked twice. `authorize(req,id,{phase:'token'})` decides whether this
  viewer may receive this image and at what width/quality/format. The same
  callback runs at `phase:'image'` before any payload bytes are sent, with the
  verified token available. A valid signature is therefore *not* a two-minute
  irrevocable capability: logout, cancellation, plan downgrade, or transfer to
  a different viewer can still win, and current entitlements may tighten but
  never widen the signed derivative.
- The token itself became a strict v2 claim set rather than “any JSON with a
  MAC.” Audience, scope, image ID, integer width, issued-at/expiry window,
  bounded quality/format, and nonce shape are all validated. Token minting is
  POST-only by default with an `X-Archx-Request` header and same-site/fetch-
  metadata gating; exact configured origins remain CORS/CSRF signals. None of
  Origin, Referer, IP, or User-Agent is treated as a credential.
- One-time use is claimed synchronously after all redemption checks that can
  legitimately be retried—signature/claims/proof, reauthorization, and
  viewer/IP/User-Agent/session bindings—with no `await` between checking and
  claiming the proof ID and nonce. In Node's event-loop model this removes
  the check/use gap that let twenty parallel copies of one URL race; the
  regression test expects exactly one 200 and nineteen 403s. A transient
  authorization denial therefore does not spend the token, while a later
  quota/processing failure can still burn it and requires a fresh mint.
- Rate limiting needed a memory bound as much as a request bound. Token,
  payload, quota, nonce, distinct-image, master-cache, dimension-cache, and
  output-cache state now has TTL cleanup plus client/entry/byte ceilings.
  Quotas can be keyed by IP, viewer, IP+image, and viewer+image; a distinct-
  image tracker can emit a sanitized suspicious-scraping event or deny after
  an operator-selected catalogue-sweep threshold. `429` responses include
  `Retry-After`, while error bodies stay generic.
- Path safety is based on indexed identity, not string concatenation. Image
  IDs accept only `^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`; directory files and
  explicit map entries are format/extension checked, resolved with
  `realpath`, and containment-tested with `path.relative`. A symlink inside a
  masters folder that points outside is not indexed, and the file is resolved
  again at redemption so a later swap cannot silently escape the approved
  root. The demo's static server uses the same realpath/relative rule rather
  than the classic vulnerable `startsWith(dir)` sibling-prefix test.
- Sharp/libvips is given an untrusted-input budget: maximum source bytes,
  input pixels/width/height, output pixels, detected-format allowlist,
  rejection of animated/multi-page and >4-channel masters,
  `failOn:'warning'`, `limitInputPixels`, sequential reads, native timeouts,
  one metadata pass, metadata-free derivatives, and a bounded semaphore and
  queue in front of processing. This matches Sharp's own “all input is
  untrusted” posture and stops a valid token for a pathological master from
  becoming an unbounded CPU/memory job.

#### What can a browser do about a second-device camera?

The camera research separates into three very different classes:

1. **Selective temporal viewing (strong, but hardware).** Temporal
   Psychovisual Modulation (TPVM) broadcasts high-refresh “atom frames” and
   lets a person wearing a **display-synchronized viewing device** fuse a
   selected combination in the human visual system. It is an elegant display
   paradigm, not a JavaScript feature. Without synchronized shutters or a
   trusted display pipeline, a web page cannot make pixels visible to the
   unaided intended viewer but fundamentally invisible to every camera.
2. **Coded room illumination (stronger artifacts, also hardware).**
   Anti-camera LED / LiShield-style systems modulate multi-colour room lights
   at frequencies chosen for rolling-shutter sensors. Rows exposed during
   different parts of the waveform receive different intensities/colours,
   producing stripes while people perceive approximately steady light. A
   website cannot control the room, the panel backlight waveform, exposure,
   or shutter phase, so Archx does not claim equivalence. The transferable
   insight is narrower: horizontal temporal bands and opponent-colour changes
   are promising page-level degradation patterns because rolling shutters
   sample rows at different times and Bayer arrays sample colour unevenly.
3. **Page-level temporal degradation + attribution.** This is what v1.4
   ships. `temporalShield`/`cameraShield` now share one complementary-frame
   engine with `blocks`, parity `checker`, and horizontal `bands`, plus an
   opponent-colour (`chroma`) transform in both the WebGL shader and Canvas2D
   frame generator. Human temporal integration averages the +/− pair; a
   screenshot, short camera exposure, or asymmetric rolling-shutter sample can
   retain noise, checker phase, or banding. The v1.5 branch adds opt-in
   `temporalInterlace` with pixel-level, checker, strip, and randomized-block
   partitions over 2–4 phases. Its `shader` engine computes the current phase
   mask from backing-pixel coordinates in the fragment shader; its `frames`
   engine pre-renders one altered Canvas2D frame per phase. The 60 Hz
   profiles deliberately clamp to two phases at a 30 Hz per-phase floor and
   use locally averaged inactive colour by default. Lens still prevents one
   frame from containing the whole sharp image; dynamic traces and server
   marks add attribution. The defeats remain obvious and are documented
   rather than hidden: record and average frames, capture/recombine phases,
   use a longer exposure, shift exposure phase, stitch pointer-Lens discs,
   denoise/regenerate, or simply accept the screen-resolution picture.

#### Why StegoMark is not (yet) a phone-photo detector

Screen-shooting-resilient watermark research is a distinct field because the
screen→camera channel combines perspective/RST warp, lens distortion,
defocus, moiré from two sampling grids, colour/gamma changes, glare, sensor
noise, and platform enhancement. Systems such as classical I-SIFT/DCT
screen-shooting watermarking, neural distortion-layer methods, and ScreenMark
therefore spend much of their design on **localization/synchronization**:
find the displayed content, estimate and undo its geometry, then decode a
redundant payload. Archx's classical 24×16 StegoMark originally assumed that
grid still spanned the suspect image.

v1.4 adds a bounded forensic geometry search instead of pretending that one
detector call solves the analog channel. `searchGeometry:true` (the CLI
default) evaluates independent X/Y grid scales for roughly 80–125% retained
areas at edge/centre origins, refines the best candidates by sub-cell phase,
accepts partial cells only with enough overlap/segments, and retains the
CRC + agreement + mean-signal + minimum-cell gates. That makes ordinary
axis-aligned screenshot crops measurable: in the three-photo 800 px matrix,
90% centre, 85%-remaining left-edge, and 90%-remaining bottom-edge crops
decoded 3/3, while 80% centre crops decoded 2/3. A 2° rotation decoded 0/3.
The correct operator workflow for a phone photograph is therefore: crop to
the displayed rectangle, correct perspective and rotation externally, then
run `archx-detect`; a positive result is evidence, a negative result is not
proof that no mark was ever present.

#### Performance work that supports the security posture

Security that forces a 60 fps renderer or an uncached Sharp job for every
thumbnail will be disabled. v1.4 keeps static WebGL draw-on-demand, requests
low-power/no-depth/no-stencil/no-MSAA contexts, generates Canvas2D temporal
frames in block spans with clamped-array writes, scopes browser bitmap/token
caching by viewer (`cacheScope` + `Archx.clearCaches()`), stops retrying
permanent 4xx/aborted fetches, and bounds every server store/queue. Continuous
CPU/GPU work is deliberately opt-in through temporal/camera patterns;
`lite`/static galleries should normally leave it off.

### 2.12 v1.5 deep dive: stealth browsers, stolen-token replay, cache deception, and fail-open APIs

The v1.5 pass started by assuming the next attacker is not using the
right-click menu or a naïve headless browser. Four conclusions changed the
implementation:

1. **Client encapsulation is not a boundary against the browser operator.**
   Current stealth stacks patch browser source or speak raw CDP/Juggler,
   present internally coherent fingerprints, traverse closed shadow trees
   with DOM piercing, and capture composited frames. Adding more canvas- or
   navigator-fingerprint heuristics would mostly add privacy cost, false
   positives, and a false sense of certainty. Archx keeps automation signals
   as tripwires, but puts the enforceable controls where the operator cannot
   rewrite them: object-level `authorize()` at mint and redemption, short
   one-time entitled derivatives, proof-bound redemption, per-viewer/IP/image
   quotas, distinct-image detection, security events, and marks. A stealth
   browser with a legitimate paid session must be handled as an authorized
   viewer whose rate, catalogue breadth, size, and continued access are
   governed server-side.

2. **A bearer token should not be sufficient when copied elsewhere.**
   OAuth DPoP (RFC 9449) addresses token exfiltration by binding the token
   to a client key and requiring a fresh proof for each request. Archx v1.5
   implements a deliberately narrower DPoP-style protocol instead of a
   general JWT stack: the browser creates one ephemeral ECDSA P-256 pair per
   page with the private key non-extractable, sends only the public JWK at
   mint, and the signed v2 token carries its RFC 7638 thumbprint (`jkt`).
   Redemption requires a bounded proof over the method, exact payload path,
   SHA-256 of the access token, issued/expiry times (max two minutes), and a
   one-time proof ID. The server accepts only on-curve P-256 keys, recomputes
   the thumbprint, and claims the proof ID in a bounded TTL store. The wire
   format is intentionally small enough to audit: mint sends
   `X-Archx-Proof-Key: base64url(JSON.stringify({kty,crv,x,y}))`; redemption
   sends `X-Archx-Proof: v1.<base64url(JSON proof)>.<base64url(raw P1363
   signature)>`, where the proof contains exactly `jwk`, `jti`, millisecond
   `iat`/`exp`, `htm:'GET'`, `htu` (the payload pathname), and
   `ath: base64url(SHA-256(accessToken))`, and the ECDSA signing input is
   `v1.<base64url(JSON proof)>`. This makes
   a token copied from logs/history/proxy tooling useless in another browser
   that lacks the private key. It does **not** stop same-page XSS, a
   malicious extension, or the legitimate browser operator from asking the
   page to sign a proof and display pixels; CSP, session security, and
   authorization remain separate responsibilities.

3. **Clean token URLs create a cache-deception obligation.**
   Moving the token from `?t=` into `X-Archx-Token` keeps bearer material out
   of history, Referer, Resource Timing, and many logs, but makes the payload
   path look static. PortSwigger-style web-cache deception is therefore part
   of the threat model. Token and payload responses now send
   `Cache-Control: private, no-store`, `CDN-Cache-Control: private, no-store`,
   `Surrogate-Control: no-store`, and a `Vary` list covering Origin (when
   CORS is enabled), Cookie, Authorization, token/proof headers, and
   User-Agent. `Vary` is defence in depth, not a rescue: shared-cache support
   is inconsistent, and a CDN rule that deliberately overrides origin
   `no-store` remains an operator deployment failure that must be tested.

4. **Ambiguous security APIs are backdoor-shaped even when nobody intended a
   backdoor.** v1.5 therefore rejects unknown/misspelled server options,
   ambiguous authorization results, weak secrets without a test bypass, and
   callbacks that hang past a deadline. Public generic token-signing/
   verification exports, `handler._test`, and `handler.index` were removed.
   Client public options are deep-cloned/redacted, duplicate hosts and
   unavailable shadow roots fail closed, and debug handles remain per-instance
   opt-in. On the data path, the browser stream-caps and schema-checks token
   JSON, refuses redirects and non-allowlisted payload origins, sniffs image
   dimensions before decode where the format permits, and enforces byte/
   dimension/pixel budgets. The server passes Sharp only byte buffers,
   pre-sniffs and cross-checks metadata, and can block unneeded libvips
   loaders process-wide. These are not glamorous features; they close the
   paths by which a typo, test hook, hostile file, or compromised upstream
   response becomes a bypass.

5. **Provenance needs a second lookup when pixel marks are attacked.**
   C2PA separates provenance from access control: metadata and credentials
   can be stripped, while soft bindings (watermarks or content fingerprints)
   can rediscover a stored record. Archx now exports a 64-bit DCT perceptual
   fingerprint and comparison helpers, returns it from `scrambleImage()` only
   when ingest code opts in, prints it from `archx-protect`, and compares it
   in `archx-detect`. That gives monitoring a candidate match after resize/
   re-encode even when StegoMark is absent. Current watermark/fingerprint
   research also sets the limit: regeneration, compositing, crops, and
   adversarial perturbations can move fingerprints and remove invisible
   marks, so a soft-binding hit is investigative evidence to corroborate with
   the retained master and issuance log—not cryptographic identity and not a
   substitute for withholding the master.

### 2.13 Second enterprise review: safer defaults, demonstrated hooks, and leak tracing

The second external review was less about another viewer trick than about
whether the library would steer a competent operator toward the safe
deployment—and whether its language around the demonstrated attacks was
precise. Five conclusions drove this pass:

1. **Safe settings lose when the insecure setting is the default.**
   Query-string payload tokens were historically convenient, but bearer
   material in a URL reaches history, Referer, Resource Timing, bookmarks,
   screenshots of network panels, and ordinary access logs. The server now
   defaults `allowQueryTokens:false`; a legacy consumer must select the
   compatibility exception explicitly. `withHardenedProductionDefaults()`
   fills unset fields with POST-only minting, same-site/custom-header
   checks, required proof of possession, one-time tokens, a 120-second TTL,
   fail-closed Stego/provenance behavior, and blocking abuse detection.
   `auditArchxProductionConfig()` is deliberately a second check, not a
   synonym for startup validation: it reports expected instance count,
   query tokens, optional PoP, reusable tokens, abuse-detection
   `action:'event'` (record-only), unregistered Stego issuance, and other
   production blockers without exposing a secret.

2. **The demonstrated WebGL hook must be named as a limit, then regression
   tested.** A script already running before Archx in an attacker-controlled
   page can wrap WebGL methods and inspect the framebuffer once Archx draws
   the authorized derivative. Expanding the integrity surface to texture,
   framebuffer, shader/program, draw, and readback methods—and distinguishing
   an early first-party integrity snapshot from later mutation—makes some
   hooks observable, but it cannot turn an untrusted browser into a trusted
   display path. The regression suite therefore checks patched
   `drawArrays`/`drawElements`, verifies that invalid integrity modes fail
   closed, and records the product distinction: Fortress locks when a runtime
   hook is detected during load, while Vault can report and continue. That
   Vault continuation means a fetch hook may observe delivery traffic;
   Fortress's availability risk is false refusals when a legitimate
   extension patches the same APIs.

3. **Delivery keys are visible to their intended decrypting browser.**
   Any docs that call client-side scramble/AES keys “hidden” are misleading.
   Header transport reduces URL/log leakage; it does not conceal a token or
   key from page code, DevTools operated by the authorized viewer, or a
   compromised same-origin script. The useful controls are scope and time:
   derive keys from a short-lived, one-image token; re-authorize at
   redemption; bind proof of possession; and keep tokens/keys out of logs,
   errors, security events, delivery telemetry, provenance records, and
   browser plugin events. Tests now assert that sanitized telemetry carries
   no token/key-shaped fields while still supporting monitoring and
   operator-managed reverse-image-search queues.

4. **Per-delivery attribution needs to be a first-class transaction ID.**
   `authorize()` can now return `buyerId`, `orderId`, `deliveryId`, and
   `traceId` at both mint and redemption. The server validates and bounds
   those fields, signs a trace hash and Stego profile/version into the token,
   rechecks changed trace fields, supports visible-mark placeholders, and
   derives the Stego subject from the trace. `onStegoIssue` has the complete
   key-free registry record; `onDelivery` is metadata-only success
   telemetry; `onProvenanceIssue` is a clean issuance hook for an external
   C2PA/provenance service rather than a false claim that Archx itself signs
   Content Credentials. Registry and provenance failures deny by default,
   with explicit lower-assurance continue policies only when an operator
   chooses and can reconcile them.

5. **Robust steganography needs a larger codeword and a false-positive
   budget, not just more amplitude.** The backwards-compatible standard
   mark retains its 48-bit fingerprint + CRC-16 over 24×16 macro-cells. The
   new robust profile uses a separately keyed 20×14 layout, amplitude up to
   `min(16, 1.35 × base)`, and a 96-bit codeword containing the 48-bit
   fingerprint, one CRC over the fingerprint, a second keyed CRC over the
   first 64 bits, and fixed markers. Detection median-aggregates segments
   and votes by median per code bit, requires at least 88 observed bits and
   128 scored cells for bounded crop acceptance, then tries exact decode,
   syndrome-guided meet-in-the-middle repair, and byte-level repair. The
   important negative result shaped acceptance: on a flat synthetic 90%
   crop, aggressive repair can find a nearby wrong fingerprint that passes
   the CRC structure. Candidates needing four or five corrections therefore
   require strong mean signal and cell agreement; otherwise the detector
   returns `found:false`. At the final tuning, robust decoded direct,
   resize/JPEG, and brightness/saturation/blur/JPEG cases on the synthetic
   fixture, and direct/resize/edit plus a 90% center crop on the natural
   `aurora-valley` fixture, each with the exact fingerprint and zero
   corrections; the unmarked natural control stayed negative. Rotation,
   perspective, phone-photo, and AI-regeneration recovery remain unproven,
   and flat-graphics crop recovery is not claimed.

The same review produced narrower product hardening: a bundled atomic
Redis/Valkey state-store adapter at `./redis`; detail-destroying, visibly
marked scrambled decoys; constructable shadow stylesheets where available;
an explicit byte/Blob custom-transport source boundary (HTTP bodies are
stream-read under a cap, but AES-GCM containers are not rendered
progressively before whole-message authentication); and `fortress60`, a
deliberately harsher three-phase temporal profile with
6 px blocks, noise fill, and 20 Hz per-phase presentation on a 60 Hz target.
Multiple captures/recordings can still recombine phases. The CSP evidence
also stays specific: the tested policy avoids scripts/blob/workers, but
`style-src 'self' 'unsafe-inline'` remains the compatibility baseline until
a deployment proves a tighter style policy across its browser matrix.

### 2.14 Scale review: make the expensive derivative, then stop remaking it

The scale pass started by separating the costs. On this repository's photo
masters, the JavaScript tile scramble is only a few milliseconds even at
multi-megapixel sizes; Sharp decode/resize and especially lossy WebP encoding
of high-entropy scrambled pixels dominate a cold derivative. A warm
mint+redeem number for one already-cached image therefore says almost
nothing about a cold thousand-image catalog. The design that follows is the
ordinary image-CDN lesson applied without weakening the token boundary:

1. **Canonicalize the variant space.** Thousands of CSS box, DPR, zoom, and
   viewport combinations should land on a small ladder of widths. The
   client and server now share a 160–2560 px ladder, but the server applies
   it only inside the signed entitlement cap. Cache identity includes only
   fields that can change output bytes; adding a viewer hash unconditionally
   would quietly turn an otherwise identical public thumbnail into a
   per-viewer Sharp job.
2. **Reuse after authorization, not instead of it.** Dynamic payloads remain
   private/no-store and are not CDN-shared. After signature/proof checks,
   redemption authorization, replay claims, and quotas, the middleware may
   reuse scrambled bytes from memory, a bounded private disk cache, or a
   shared store. That ordering matters: a cache hit is a CPU optimization,
   never an entitlement.
3. **Move static catalogs to ingest time.** `archx-build` generates a few
   versioned responsive `.archx` variants and a manifest once, incrementally
   reuses unchanged variants, and lets a CDN serve immutable files. This is
   the cheapest request path because it has no per-view mint or Sharp work.
   Its trust boundary is explicit: the manifest contains the keys a browser
   needs, so a public manifest is for a deliberately public derivative;
   private catalogs must authorize/sign manifest and asset delivery and
   should keep paid/revocable views on the token server.
4. **Batch round trips, not security checks.** `POST {basePath}/tokens`
   lets a gallery page mint many images in a few HTTP requests. It does not
   batch away authorization, rate, quota, abuse, entitlement, callback, or
   signing work, and malformed/unknown items still spend token-rate budget.
   The browser starts batch enqueue before its payload/decode limiter so a
   visible pageful can coalesce while decode concurrency remains bounded.
5. **Ask for fewer, better-matched pixels.** The catalog browser profile
   uses 1× device-pixel sampling and a DPR cap of 2 for listings instead of
   the quality-first 2× oversampling used for detail views. Lazy loading
   remains below the fold; Fetch Priority is reserved for a genuine hero/LCP
   image rather than marking every thumbnail high priority.
6. **Tune Sharp as a job system.** Encoder effort/smart-subsample, resize
   kernel, PNG/JPEG settings, concurrent image jobs, and libvips threads per
   job are separate knobs. Sharp's own performance guidance also makes the
   libuv thread pool part of capacity planning on larger machines. The
   catalog defaults favor several bounded jobs with one libvips thread each;
   operators still need staging measurements on their instance type.

The resulting trade-off is intentionally tiered: precomputed public assets
for volume, shared dynamic derivatives for private browsing, and unique
per-viewer marks/keys only where attribution value justifies cold CPU on
every view.

### 2.15 Follow-up: stampedes, integrity-pinned manifests, adaptive bytes

Three smaller scale/integrity gaps remained after §2.14:

1. **Cold-cache stampedes.** Caching a derivative after its first transform
   does nothing for the burst that arrives *while* that transform runs;
   request coalescing (singleflight) is the standard fix, and CDN request
   collapsing cannot do it for Archx because token payloads are
   authorization-scoped, `private, no-store` responses rather than shared
   cacheable objects [3](https://iotdigitaltwinplm.com/cache-stampede-thundering-herd-request-coalescing-ttl-jitter-caching-patterns-2026/)
   [2](https://rednafi.com/go/request-coalescing/). The middleware already
   kept an in-flight promise per derivative identity; v1.7 makes the effect
   observable (`derivativeCache.coalesced` vs `misses`) and regression-tests
   an eight-way concurrent redemption producing exactly one Sharp transform
   and byte-identical responses.
2. **Static-path integrity.** Moving delivery to a CDN moves trust to the
   CDN/object store: whoever can replace the manifest controls keys and
   variant URLs, and whoever can replace a variant controls pixels. The
   builder already content-hashed variant filenames and recorded
   per-variant SHA-256 digests in the manifest; the browser now *verifies*
   them (`assetIntegrity`), and can pin the manifest's own SHA-256
   (`assetManifestIntegrity`, printed by `archx-build`) so a substituted
   manifest is rejected before any of its material is trusted. The
   minified browser bundle likewise ships a `sha384-…` Subresource
   Integrity value (`dist/archx.min.js.sri`). Pinning is tamper evidence,
   not confidentiality: a public manifest remains public.
3. **Adaptive delivery.** The Network Information API exposes a user's
   Save-Data preference and an effective-connection estimate, and the
   established fallback-first pattern is to degrade resource weight where
   the signal exists and keep defaults where it does not
   [1](https://botbrowser.io/en/blog/network-information-api-for-adaptive-content/)
   [4](https://web.dev/articles/adaptive-serving-based-on-network-quality).
   `networkAware` applies that pattern to derivative selection (DPR,
   oversampling, numeric quality) for both token and manifest flows, and
   `Archx.preloadAssets()` removes first-paint network latency for known
   hero assets while refusing to spend bytes on Save-Data connections.

### 2.16 Scattered-memory display and browser-enforced readback denial (v1.8)

Verified against the implementation, the browser never stores a clean,
whole image: the retained payload bytes and the decoded `ImageBitmap` are
always the keyed tile-scrambled mosaic (tiles shuffled and per-tile
mirrored, grid 2–32). Canvas2D display reassembles tiles on a private
off-DOM canvas with exact integer 1:1 copies, paints the visible canvas
once, and wipes the working copy; `splitCanvases` slices the composition
across separately poisoned tile canvases, so no single canvas holds the
picture. Vault/Fortress never reassembles in JavaScript at all — the
scrambled mosaic is a GPU texture and each output pixel is unscrambled in
the fragment shader at present time, with `preserveDrawingBuffer:false`
black readback.

For 2D modes, v1.8 adds deliberate **origin tainting**: MDN documents that
drawing a cross-origin image without CORS approval flips the canvas's
origin-clean flag, after which `getImageData`/`toBlob`/`toDataURL`/
`captureStream` throw `SecurityError`[1], and the HTML Standard shows the
flag propagating through `createImageBitmap()` and `drawImage`, so the
canvas cannot be laundered clean[11]. The middleware serves the required
constant cross-origin pixel at `{basePath}/taint.png}`; the client draws
it under the real pixels when the API is cross-origin (or `taintUrl` is
set), upgrading 2D readback denial from instance poisoning (bypassable
via prototype calls) to browser-platform enforcement. WebGL canvases also
now shadow read/record APIs to block `captureStream` recording of
animated frames[1]. Quality is measured, not asserted: the browser suite
compares the painted shield canvas to an independently unscrambled
reference at 1:1 and records mean absolute difference 0. Same-origin
deployments cannot taint (origin-clean by definition) and retain instance
poisoning; compositor/OS capture and cameras remain addressed only by
derivative caps, marks, Lens/temporal layers, and attribution.

### 2.17 Measured optimization round (v1.9)

Optimizations were admitted only with same-machine before/after evidence
(`tools/optimization-bench.mjs`, plus interleaved A/B against the v1.8
code to cancel sandbox CPU drift). Findings: the cold pipeline was
already encode-dominated (libwebp ≈ 70% of a 960 px catalog transform;
fused pad+scramble ≈ 2 ms; metadata < 1 ms), so wins came from removing
whole frame passes rather than micro-tuning JS: fusing
pad+scramble+encoder-input into one pass (byte-identical output, proven
against 21 fixture hashes and a permanent equality test), skipping EXIF
autorotate for orientation-1 masters, and dropping the synthesized
alpha band before WebP/PNG encoding of opaque masters (PNG −34% encode
time, −11% bytes; WebP encode −6%). Aggregate cold-transform gain was
~3–10% depending on size/profile, with peak RSS a few MB lower. On the
warm path, CPU profiling showed GC pressure from `filter()`-copying
sliding-window timestamp arrays on every limiter hit; in-place
front-pruning raised loopback mint+redeem throughput 859 → 915 flows/s
(6,000-request A/B). Client-side probes found per-image JS overhead
already negligible (`auditIntegrity()` ≈ 0 ms; native decode dominates),
so no client behavior changed; an es2022 bundle-target bump was measured
(−1.4 kB gzip) and rejected for its browser-floor cost.

### 2.18 Industry-standard hardening round (v1.10)

The round began by writing `docs/STANDARDS.md` — every control mapped to
the external standard it answers (OWASP API Top 10 2023, browser platform
rules, crypto/key guidance, media-processing safety, provenance, OpenSSF
supply-chain signals, accessibility, and explicit non-goals) — then
closing the gaps it exposed:

- **Untrusted-cache integrity (OWASP API10).** Derivative bytes were
  already container-validated after a cache read, but a writer with access
  to the disk/shared cache (not the server secret) could substitute a
  *different structurally valid* derivative. Cache entries now carry an
  HMAC-SHA256 tag bound to key + bytes; forged entries miss and
  regenerate (proven by a planted-container unit test).
- **Scramble seed strength.** The effective plan seed was 32-bit, so the
  permutation of an unencrypted payload could be brute-forced (trial
  unscrambling per candidate seed) in seconds. Plan v2 (cyrb128 + sfc32,
  128-bit state, header `pv:2`) removes that shortcut; v1 stays the
  byte-compatible default. This raises the offline-attack cost of the
  obfuscation layer; AES-256-GCM remains the actual secrecy mechanism.
- **Parser fuzzing paid for itself immediately.** A new seeded fuzz suite
  over the container decoder, header schema, format sniffer, scramble
  round-trips, stego detector, and live token redemption found a real
  false-attribution bug: on tiny unmarked noise, ~1 cell per code bit
  makes majority "agreement" tautological, and the CRC corrector could
  flip near-zero-reliability bits into a `found: true` at confidence
  0.82. Detection now requires dense evidence (≥3 cells/bit average, ≥2
  for every bit; repaired candidates need clearly genuine raw signal).
  Genuine marks measured in this round (≥320 px, clean + JPEG-80) sit at
  ~6 cells/bit, ≤1 correction, agreement ≥ 0.84 — and 3,000 seeded noise
  scans now yield 0 false positives with the corruption matrix intact.
- **Slow-body resource holding (OWASP API4).** Streamed batch-token
  bodies had a byte cap but no time budget; they now share
  `callbackTimeoutMs` and fail 408, with the connection destroyed first
  (an `iterator.return()` await queues behind a suspended generator, so
  the deadline must cut the socket, not ask politely).
- **AVIF, measured before admitted.** On scrambled tiles AVIF q55 is 56%
  smaller than WebP q88 but encodes 8–70× slower; it ships as an opt-in
  for precomputed catalogs, not the on-demand default.
- **Industry floor items:** TypeScript declarations with a `tsc` smoke
  test in CI, CodeQL SAST, Dependabot, an OIDC trusted-publishing
  workflow (npm provenance, no long-lived token), an ETag/304-capable
  taint pixel (still non-CORS), and shared TextEncoder/Decoder instances.
  Bench vs v1.9: payload bytes identical (default v1 outputs verified
  byte-identical against the released implementation), timings within
  noise, bundle +0.4 kB gzip.

### 2.19 External adversarial review — verification and response (v1.11)

An outside reviewer penetration-tested v1.10 and published a detailed
problem list (overall 6.8/10). Every claim was re-verified against the
code before acting; this section records what held up, what did not, and
what changed. Measured on this repo's fixtures (`neon-portrait.jpg`,
synthetic masters), Node 22 sandbox.

**Confirmed real bugs — fixed.**

- *Public StegoMark key.* `scramble-image`/`build-assets`/CLIs defaulted
  `stegoKey` to the scramble `key`, which static builds print in the
  manifest: anyone could detect/subtract/forge marks. Now a hard error
  (breaking; see CHANGELOG). The middleware fleet path was already safe
  (per-image key derived from the server secret).
- *Redis binary corruption.* `getCache` re-encoded node-redis v4's
  default UTF-8 string replies, mangling every byte ≥ 0x80. Values are
  now base64-armored (+33% at rest; ≈ ×1.37 with the HMAC tag).
- *Quota burn + counter smearing.* Minting incremented quotas before
  request-shape validation, and all dimensions unconditionally. Now
  shape-first, narrow→wide, early-exit. Related: the scrape alert
  re-fired per request (distinct-count caps at threshold+1 by design) —
  it now latches once per client per window; enforcement unchanged.
- *IPv6 /64 rotation.* Limiter/quota/distinct keys now group IPv6 by
  /64; token IP binding intentionally still uses the exact address.
- *Per-token cache pollution.* Unique-per-token derivatives previously
  filled RAM/disk/Redis caches they could never hit; reads and writes
  are now skipped for those derivatives.
- *Black padding oracle.* True and worse than framed: pad tiles were
  identifiable *with flip state* from the black strip alone (8/8 in the
  review). Padding now replicates edge pixels (server + client);
  displayed (cropped) pixels are byte-identical.
- *Confidence on negative verdicts.* `confidence` is capped at 0.49
  when `found:false`.
- *fortress60 median algebra.* The fixed temporal cycle made a 6-frame
  multiset `{c, c+d, c−d}×2` — median exactly `c`. The shader now
  re-seeds noise per presented frame, jitters amplitude, and randomizes
  sign/phase order (shuffle bag, balance-corrected). Long recordings
  still average out; the exact short-window shortcut is gone.
- *Lens center-cell accounting.* Stitching detection counted only the
  cell under the disc center. It now counts the disc's full cell union
  (8×8 grid), threshold recalibrated to the same ~72% coverage intent.
- *Unmonitored hooks.* `JSON.parse`, `attachShadow`,
  `ReadableStream.getReader` are captured, audited, and used on
  sensitive paths; the vault verifies `preserveDrawingBuffer:false`
  actually took effect. A pre-load `Proxy`/`toString` forgery still
  evades this (it always could) — the point is removing free wins.
- *Mirrored suspects.* StegoMark detection now tries the horizontally
  flipped candidate (`mirrored:true`; verified both profiles).

**Confirmed weaknesses — mitigated or consciously traded.**

- *Keyless jigsaw reassembly of unencrypted payloads* (review: 94.6%
  top-1 plain, 96.4% with the pad oracle, 0% encrypted). Agreed: a
  permutation is obfuscation and tile-edge continuity is public
  information. Mitigations: pad oracle removed; the hardened preset now
  defaults `encrypt:true`; config audit warns on unencrypted/v1
  deployments. Unencrypted mode remains available for public-catalog
  friction, labelled as such.
- *Collusion.* Averaging ≥2 copies erases the mark (any LSB/spatial
  mark), and with a shared layout key, majority voting + CRC repair can
  synthesize a phantom fingerprint. Our reproduction: 3-buyer average
  on `neon-portrait` robust → `found:false` (7 corrections, rejected by
  the v1.10 gates), but the mechanism is real and image-dependent.
  `keyScope:'viewer'` now breaks cell-by-cell alignment between
  buyers; `archx-detect` flags repaired decodes as
  corroboration-required. True anti-collusion codes (Tardos/Boneh–Shaw)
  are future work.
- *Geometric fragility.* Rotation (≥ ~1°), warp, and heavy asymmetric
  crops break the fixed-grid mark. Search widened (quarter origins,
  fine-scale ±3.5%, ±4-cell offset roam) and mirror handled, but our
  own 82% asymmetric-crop probe still fails on busy texture —
  signal/boundary-limited, not search-limited. This mark class does not
  survive arbitrary geometry; a feature/Fourier-Mellin-synchronized or
  learned mark (TrustMark/WAM-class) is the honest path and is **not**
  bundled: it would be a model dependency with its own removal/transfer
  attacks, evaluated separately rather than smuggled in.
- *Mark visibility.* Measured PSNR at strength 6: 33.4 dB (standard),
  30.4 dB (robust) — the review's ~30.7 dB is accurate; strength 3
  measures 39.4/35.9 dB with weaker survival. Default unchanged
  (changing it would silently alter every issued mark); choose per
  content with eyes open (SECURITY.md table).
- *Same-origin untainted shield/lite.* True by platform rules; the
  client now emits `archx-taint-unavailable` so the state is visible
  instead of silent. Cross-origin API/CDN deploys get full taint.
- *Cold-view latency (their 339 ms).* Not independently reproduced at
  that size on this sandbox, but the shape is right: an uncached view
  costs a full Sharp transform. The answer remains architectural
  (precomputed catalogs, width buckets, warm caches) plus this round's
  stat/KeyObject caching — worker-thread offload of the JS stages and
  A/B two-variant tile streaming were evaluated and deferred: both are
  protocol/client rewrites whose benefit concentrates at >1080p
  uncached traffic, and neither changes the security story.

**Refuted on this codebase.**

- *"41 MB of Float64 integral tables in embedStegoFingerprint."* No
  such tables exist; the embed allocates the output frame plus small
  per-code arrays. Measured embed: 18 ms @1.15 MP, 65–86 ms @4.59 MP
  (their ~68 ms/2.58 MP timing is in range; the memory claim is not).
- *"Uncapped per-image WebGL contexts."* A global budget of 8 contexts
  with 2D fallback already existed; this round adds the
  `archx-webgl-budget` event so the fallback is observable.

**Held up under their testing** (unchanged): no `<img>` elements,
closed shadow roots, decoy `toDataURL`, cross-origin taint, black
vault readback, naive-hook detection, path traversal / Fetch Metadata /
DPoP replay / width-clamp / race handling.

### 2.20 Second adversarial follow-up — verification and response (v1.12)

The same reviewer re-tested v1.11.0 and returned eight file/function-mapped
fixes, a set of compute/memory/battery optimizations, and a competitor
comparison (SmartFrame, IIIF+OpenSeadragon, IMATAG/Steg.AI/Digimarc,
Adobe TrustMark, Meta WAM). Each claim was verified against the code —
and, where the claim was about browser behavior, against a real Chromium
— before acting.

**Confirmed real — fixed.**

- *Fortress 2D downgrade on `preserveDrawingBuffer` rewrite.* True: the
  v1.11 attribute verification fell back to an untainted 2D canvas under
  exactly the conditions fortress exists to distrust, and a proxy that
  also spoofs `getContextAttributes` defeated the check entirely. The
  attribute read now goes through the captured native, and a behavioral
  canary backstops it: after the first presented frame, drawing holds
  for two frames and `readPixels` runs before the next draw — on an
  honest swapchain the buffer is clear color by then. Two empirical
  corrections to the reviewer's sketch: Chromium clears the buffer only
  after the **second** following rAF (one-frame checks false-positive),
  and a canvas that was never composited (below the fold — our
  visibility observer runs the loop 500px early) is never cleared at
  all, so the canary only judges provably presented frames and defers
  otherwise. Either signal under `integrity:'lock'` is now a hard
  blackout, not a downgrade. The browser suite includes a pre-load
  proxy that forces-true while spoofing-false; the canary catches it
  (`source:'canary'`).
- *Hookable crypto/stream primitives in the core.* True: the shared
  core called `globalThis.crypto.subtle` directly, and the client used
  live `subtle.*`, `reader.read`, `Response.text`, and fresh
  `TextDecoder`s on sensitive paths. The core now ships pure-JS
  SHA-256/HMAC-SHA256 (byte-identical to `node:crypto`, including
  >64-byte keys) and takes an injected, boot-captured WebCrypto surface
  (`useWebCrypto`) for AES-GCM and digests; raw key bytes are zeroed
  after import. Client-side, all subtle calls route through a
  receiver-correct captured-method helper (SubtleCrypto methods throw
  "Illegal invocation" on any other receiver), streaming uses the
  captured reader, and bounded-JSON parsing uses a shared captured
  fatal decoder.
- *Mirror+crop blindspot.* True for explicit profiles: only
  `auto`+geometry tried the flipped candidate, and it dropped the
  other search dimensions. `searchMirror` now defaults on for every
  profile and the flipped probe inherits offset/geometry search.
  Measured (800px, strength 6): flip + 90% center-crop recovers in
  3.6s (standard) and 9.1s (robust) — before: not found.
- *Edge-replicate row-duplication oracle.* True, and it was our own
  v1.11 padding fix that created it: replicated pad rows are exact
  duplicates, self-identifying to tile-edge solvers (100% duplicate
  rows on a gradient probe). Padding is now interior reflection with
  a deterministic ±1 dither confined to pad pixels (<5% duplicates).
  Displayed pixels and wire compatibility are unchanged (the client
  crops the pad; it never re-derives it for server payloads).
- *Paced lens stitching.* True: the 8s burst window let a slow,
  scripted sweep stay under threshold forever. The lens now keeps a
  120s last-visit ledger over the 8×8 coverage grid (≥56/64 cells ⇒
  `lens-scan`, tunable via `scanCellsCumulative`), and the disc
  radius jitters ±6% so captured discs no longer share one geometry.
- *Temporal median after the v1.11 reseed.* The reseed removed the
  exact 6-frame algebraic shortcut, but an order-independent median
  of a couple dozen frames still tracked the clean value closely.
  The shader path now adds an asymmetric-duty spatial bias
  ([+2⁄3, −1⁄3, −1⁄3] duty at 24px blocks, 0.55×strength amplitude,
  seed re-rolled every ~90 frames): the frame *mean* is exact, the
  sample *median* converges to a block-varying offset that keeps
  moving. Long-window averaging still converges to the displayed
  image. That is inherent to anything watchable and stays documented
  as a cost-raiser, not a wall.
- *IPv6 /48 rotation + limiter eviction churn.* Both true. Limits now
  apply at /64 (configured) and /48 (4×) narrow-first; the distinct-
  image abuse signal intentionally stays /64 so a big NAT /48 is not
  auto-flagged. The limiter evicts unblocked entries before blocked
  ones, so flooding the table no longer flushes the flooders' blocks.
- *Collusion framing against the StegoMark CRC.* Structurally true:
  the acceptance tag was a linear CRC whose only keying was one
  derived byte in the layout — majority hybrids correlate with the
  CRC of the majority fingerprint by construction, and detection
  under per-viewer keys degrades to an O(N) scan. **Not reproduced
  as demonstrated, though:** our replication (3-buyer pixel-average,
  800px, strength 6, 12 trials) produced zero validating phantoms
  under *either* scheme — the averaged marks erased below gate
  thresholds first. The fix is justified by the structure, not by
  reproducing their phantom: codeword v2 accepts on a 16-bit
  truncated HMAC-SHA256 of the fingerprint (shared image key, so
  detection stays O(1)); the robust profile keeps its first CRC
  strictly as a repair oracle. `tagScheme` reports which tag
  validated, legacy decodes are gated harder and CLI-warned, and
  pre-1.12 detectors cannot read new marks (upgrade detectors first).

**Optimizations shipped.** Two-stage derivatives
(`prepareDerivativeBase`/`finishDerivative`): resize/watermark once,
cache the raw base for per-token/per-viewer variants that can never
output-cache (byte-identical; base proven non-mutated by tests).
Redis binary mode when the client can return Buffers (≈33% smaller
than the `b64:` armor, which remains the fallback; HMAC entry tags
make mixed fleets self-heal). WebGL contexts are deliberately lost
on viewport unload so long galleries return slots to the browser's
context budget. Continuous temporal loops idle-throttle to 1-in-3
frames after 5s without interaction — reduced, never stopped, since
a frozen temporal frame is a free clean capture.

**Evaluated and deferred (with the competitor table).**

- *A/B tile-sheet streaming & IIIF tile pyramids* (OpenSeadragon's
  model) are the right architecture for gigapixel masters and for
  never shipping a whole frame; they are also a protocol and client
  rewrite whose benefit concentrates far above current display caps.
  The temporal-interlace engine already ships the "no single frame
  is whole" property at display resolution. Roadmap, not this round.
- *Worker-thread pool for the JS stages.* Sharp already runs libvips
  on its own thread pool; measured JS-side work (scramble/mark) is
  the minority share (§2.17) and structured-clone copies of raw
  frames would eat much of the win. Revisit with `SharedArrayBuffer`
  measurements, not on principle.
- *FFT/sync-template registration for cropped suspects.* This is the
  correct fix for the ~82% asymmetric-crop dead end — boundary cells
  vote wrong at high reliability, and no search density fixes that
  (§2.19). It requires a sync template in the mark itself: a v2 mark
  redesign, scoped as such.
- *Learned watermarks (Adobe TrustMark, Meta WAM; IMATAG/Steg.AI/
  Digimarc as services).* Different product and threat model:
  provenance/recovery at internet scale, with model weights, GPU
  inference, and (for the services) a hosted detector. Archx's
  StegoMark is a self-hostable, key-held attribution tag with known
  measured envelopes; C2PA-style provenance is complementary and
  explicitly not access control. We do not claim parity.
- *SmartFrame-style crawler/SEO previews.* Serving different bytes
  to crawlers is a hosted-service growth feature with cloaking
  policy risk; the static catalog already separates public widths
  from protected delivery for operators who want an indexable
  preview. Not built into the protection path by design.

### 2.21 Third adversarial review — verification and response (v1.13)

A third adversarial pass audited v1.12.0 end-to-end (the reviewer reports
13,081 lines read, reproduces our published dist SRI exactly, finds no
backdoors/exfiltration, and scores the release 8.1/10). It raised seven
new bug groups and seven optimization proposals (A–G). As before, every
claim was verified against the code or a measurement before acting;
confirmed items are fixed with regression tests, and the rest are
answered with evidence rather than absorbed silently.

**Confirmed real — fixed.**

- *Cross-viewer watermark leak through the derivative-base cache
  (their Bug #1, reproduced byte-for-byte).* The prepare/finish split
  cached a viewer-independent base keyed without the watermark — but
  the visible watermark was baked into that base, so the second viewer
  of a geometry received the first viewer's mark. Watermarks are now
  applied exclusively in stage 2; cached bases are clean by
  construction, so the viewer-independent key is correct. A two-viewer
  HTTP regression asserts Bob's derivative matches Bob's own reference
  rendering, not Alice's, while exactly one base is shared.
- *IPv4-mapped IPv6 split rate-limit identity (Bug #2).* `::ffff:1.2.3.4`
  and `1.2.3.4` drew separate quota/abuse buckets. Client identity is
  now canonical: v4-mapped/translated forms collapse to dotted-quad and
  all other IPv6 spellings collapse to one expanded-group form before
  token binding, quotas, and abuse accounting. Regression-tested over
  HTTP in compressed, expanded, and hex-tail spellings.
- *Geometry-search scale dedupe precision (Bug #3).* Candidate scales
  were deduplicated at 0.1 precision, discarding near-1.0 resizes the
  search exists to find; now keyed at 0.001.
- *Single-tier distinct-IP abuse threshold (Bug #4).* One global
  distinct-image ceiling either cried wolf on catalogs or slept through
  slow scrapes; detection is tiered now, and member limits are hinted
  into token responses so honest clients can self-throttle.
- *Visible watermark tiled on one axis only (#5).* Server and both
  client painters stamped one text per diagonal row, leaving most of
  the width clean — cropping the row bands erased attribution. All
  three now tile on both axes with a measured-text-width step and
  alternating row offsets.
- *32-bit stego layout and forensic sign seeds (#6).* Cell shuffles
  and block-sign sequences derived from 32-bit hashes of the key, so
  the layout space was enumerable. Layout v2 / signs v2 derive from a
  128-bit SHA-256 seed (sfc32 over four hash words), are the embed
  defaults, and dual-read: v1 marks decode bit-exactly as before
  (verified pixel-identical embeds and dual-vintage detection), and
  results report the matched vintage (`layoutVersion`,
  `signsVersion`). The payload→fingerprint map also moved to SHA-256
  for non-hex identities; `legacyStegoFingerprint()` preserves the old
  derivation for lookups against pre-1.13 marks, and the detection CLI
  accepts either derivation for `--expect`. Issued registries (which
  store the fingerprint itself) and 12-hex payloads are unaffected.
- *Cache/loader lifecycle nits (#7a–e).* `close()` now clears the base
  and indexed-output caches; master and base caches share one RAM
  budget; shared-cache integrity tags accept any keyring key; quota
  and abuse accounting run after host authorization callbacks (so
  denied viewers cost no budget); and Sharp loader policy is
  most-restrictive-wins — a later stricter `configureSharpSecurity`
  re-blocks loaders an earlier looser call unblocked
  (regression-tested by tightening AVIF away mid-process).
- *Reflection-padding palindrome seam (#10).* The v1.12 mirror padding
  left MAD(pad row, reflected edge row) ≈ 0.6 vs ≈ 17 for real
  texture — a seam oracle for keyless solvers. Padding is now a keyed
  shifted toroidal wrap (pad pixels are displaced interior texture
  plus ±3 keyed noise): displayed pixels still round-trip byte-exact,
  seam MAD now exceeds interior texture MAD, and no pad row duplicates
  an edge. The client-side local scrambler received the same
  treatment in canvas form. Pad bytes changed, so the derivative
  cache namespace moved to `v4`; unscrambling never regenerated pad
  content, so issued assets are unaffected.

**Found during verification (not in the report).** Fixing #6 changed
the fingerprint derived for one test identity, which exposed a latent
soundness flaw in the robust decoder: syndrome repair ranked
candidates by a fully *regenerated* canonical codeword, so the `mac`
pass could synthesize MAC bytes for a legacy CRC-tagged mark, "repair"
it at ~7 flips, and short-circuit the CRC fallback — mislabeling the
scheme and missing valid legacy marks whose CRC2 happened to sit
within the flip budget of its MAC. Acceptance now requires the tag
bits to be *observed* (≤2 vote-error flips in bits 64..95); costlier
repairs fall through to the exhaustive search, which pays for every
flipped tag bit from the gate-capped budget.

**Optimizations — measured, then decided.**

- *Opt A (detector hot path) — implemented and exceeded.* The
  strided-sampling vote estimator is replaced by a luma plane plus a
  Float64 summed-area table: per-cell band means are now exact
  full-population rectangle means at O(1) per query. A/B over 66
  marked/unmarked cases showed the integral estimator is a strict
  superset of the sampler (4 extra correct weak-mark recoveries, 0
  losses, 0 false positives) *and* faster, so the sampling branch was
  deleted rather than kept as an option. Around it: closure-level
  scratch-buffer reuse, an exact repair pre-gate (skips flip searches
  whose agreement ceiling is arithmetically below the acceptance
  gate), outcome-identical repair-depth caps, and a marker prefilter
  that rejects junk syndrome candidates before paying for their MAC.
  On the 800px reference image: 90%-crop+geometry detection 5.3s →
  1.5s, unmarked robust+geometry 21.6s → 5.3s, unmarked auto 32s →
  6.0s; direct detection stays ≈40ms. The Node suite itself dropped
  33s → 10s.
- *Opt D (perceptual hash) — implemented, bit-exact.* Column/row
  overlap spans are precomputed once and the DCT basis is a
  module-static table; accumulation order is unchanged, so
  fingerprints are identical to the direct form (asserted across ten
  geometries including 1×1 and sub-32px inputs) at ~1.45× the speed
  here (the reviewer measured 2.48× on their hardware).
- *Opt F (integrity-audit allocation) — implemented narrowly.* The
  reader-prototype probe no longer allocates a stream + locked reader
  per call, and the WebGL method list is a module constant. The audit
  runs at viewer init, not per frame; a deeper rewrite buys nothing.
- *Opt C (cascading resize in the asset builder) — rejected on
  measurement.* Cascading 2400→1600→1200→800→400 saved ~10% wall
  time (WebP encode, not resampling, dominates) while degrading
  derivatives to 26.9dB vs direct-from-master and coupling every
  width's bytes to the width set above it. Quality-first wins;
  builds stay direct.
- *Opt E (native KeyObject HMAC) — deferred on measurement.* Pure-JS
  HMAC was 5.6% of worst-case detect time *before* the marker
  prefilter cut 27k junk MACs per unmarked geometry search to a
  trickle; what remains does not justify a backend-registration API
  in the shared core. Revisit if profiling ever disagrees.
- *Opt G (WebP effort) — default unchanged, knob documented.* Effort
  2 vs 4 on the derivative pipeline: −24% encode time for +1.7%
  bytes. Effort 4 stays the default (bytes are served forever,
  encodes are cached); CPU-bound fleets can set
  `processing.webpEffort: 2` — the catalog preset already does.

**Verified as not reproducible or already covered.**

- *"`uTemporalOn` enabled with subset = 1 destroys the temporal
  effect" (#9) — does not map to this implementation.* `uTemporalOn`
  gates the complementary *noise* shield, which is full-frame by
  design; the subset mechanism is `uInterlaceOn` + phase test, and
  `phases` is hard-clamped to 2..4 in `normalizeTemporalInterlace`,
  so no configuration presents the full frame every phase. Their
  multi-frame median result is the known limit of complementary
  noise, already documented and mitigated (per-frame reseeding,
  asymmetric duty bias so medians converge to c − b/3 on a re-rolling
  bias), not a configuration bug.
- *Lens park signaling (#12)* already ships: burst-window and
  120-second cumulative-coverage ledgers fire `lens-scan` through
  `onAttempt`, the `archx-attempt` DOM event, telemetry, and the
  strike ladder; radius jitter ghosts stitched seams.
- *`planVersion` plumbing (#7f)* is explicit at every client call
  site; the server default stays v1 with a startup warning because
  pv-unaware cached clients would unscramble v2 payloads wrongly
  mid-migration. The hardened preset opts into v2.
- *Pre-load Proxy readback (#8)* stands as a stated residual: code
  running in a realm instrumented before the library loads is
  equivalent to a compromised browser/extension, which no page-level
  control survives. Captured natives, the presentation canary, and
  `integrity:'lock'` raise the cost and force blackouts on detection;
  we do not claim more, and SECURITY.md says so.

**Still open (unchanged, scoped).** Collusion *erasure* (averaging
k differently-marked copies destroys all marks while framing none)
and small-angle rotation remain outside StegoMark's envelope;
asymmetric deep crops still need the sync-template v2 mark design
scoped in §2.20. The reviewer's 0/400 phantom-framing collusion
result confirms the v1.12 MAC tag holds the line that matters for
attribution: marks can be destroyed, not forged onto a third party.

### 2.22 Fourth adversarial review — verification and response (v1.14)

A fourth adversarial pass audited v1.13.0 and filed thirteen problems
(P1–P13), seven server optimizations (S1–S7), and six browser
optimizations (C1–C6), each with a proposed patch. As before, no claim
was taken on faith — including the reviewer's own "zero regression"
assurances: every item was reproduced, read against the code, or
measured before acting. Two of their patches were right in spirit but
unsafe as written (one would have redefined a shipped wire format);
one optimization was already shipped; one rested on a misreading of
the shader. Everything else confirmed is fixed with regression tests.

**Packaging and public surface (P1, P2, S5, P13 subset).**

- *P1 — confirmed with a correction.* The image-processing entry
  points (`scrambleImage`, `unscrambleImage`, `inspectImageMetadata`,
  `prepareDerivativeBase`/`finishDerivative`, `configureSharpSecurity`,
  `configureSharpPerformance`, `generateKeyBase64`) existed only in
  `server/scramble-image.js`, which the exports map did not expose and
  the type declarations did not declare — unreachable through the
  documented package surface. (The README examples the reviewer cited
  in fact import only the middleware, so no shipped example was
  broken; the *capability* was nevertheless private by accident.)
  Fixed on the reviewer's preferred shape: middleware now statically
  re-exports them from `/server`, a `./server/scramble-image` subpath
  was added, and both are fully declared in `types/server.d.ts`. The
  static re-export is safe only because of S5: Sharp itself now loads
  lazily (`createRequire` on first actual image operation), so
  importing `/server` in a token-only process loads zero native
  modules — asserted in a child-process regression test via the
  require cache. Both import paths resolve to one module singleton
  (identity-asserted), so loader policy state cannot fork.
- *P2 — confirmed.* The type surface documented `{ imageId }` token
  sources and a `marketplace` preset; the runtime accepted only
  `{ id }` and threw on `preset('marketplace')` — and the type-smoke
  test exercised exactly those two dead shapes, so it compiled green
  against a runtime that would have rejected the code. The runtime now
  accepts `{ imageId }` as an alias everywhere `{ id }` works (mint
  context, batch prefetch, byte resolution), the `marketplace` preset
  exists (vault/high-quality/batch/forensic/dynamic-trace), and the
  smoke test covers both shapes plus the new `/server` functions.
- *P13 — verified subset fixed.* Every enum in `types/index.d.ts` was
  diffed against the runtime's normalization: `mode`
  (`lite` was missing; `lens`/`trace`/`catalog` were not modes),
  `qualityProfile` (declared `quality|balanced|throughput`; runtime
  implements `original|high|balanced|catalog|fast`), `onExtract`
  (declared `blank|decoy|none`; runtime implements
  `black|lowres|scrambled`), `renderLoop`, `tokenTransport`,
  `renderer`, `memory`, `strikes`, `brand`, `cacheScope`, and the
  interlace `fill` union were all stale and are now exact. One drift
  cut the other way: types had long promised `renderer: 'canvas2d'`,
  which the runtime silently treated as `auto` — the runtime now
  accepts `'canvas2d'` as an alias of `'canvas'` so existing typed
  code starts meaning what it says (browser-checked). Index
  signatures are deliberately retained: the option surface is the
  customization API, and unknown-key strictness lives server-side
  where typos are security-relevant.

**Server correctness (P3, P4, P8, P10–P12).**

- *P3 — confirmed, fixed as scoped leases.* `configureSharpSecurity`
  was eternal and narrowing-only: any caller (including two
  middleware instances of differing strictness) permanently
  intersected the process loader set, and there was no way back.
  Loader policy is now two-tier: *permanent* configurations (the old
  function, kept for hosts who mean it forever) and refcounted
  *leases* (`acquireSharpSecurityLease` → idempotent release). The
  effective block set is permanents ∩ live leases, reconciled on
  every change. Each middleware instance acquires a lease for its
  `allowedInputFormats` at construction and releases it in
  `handler.close()`, so a strict temporary handler no longer poisons
  the process. Per-request code only calls the cheap
  `ensureUntrustedSharpLoadersBlocked()` baseline. Child-process
  regression covers block-under-lease, restore-on-release,
  double-release, and middleware acquire/close wiring.
- *P4 — confirmed and extended.* v1.13's canonical IP collapsed
  v4-mapped/translated forms but left transition mechanisms as
  separate identities: every NAT64 carrier customer shared one /64
  abuse bucket (mass false-positive lockout), while one 6to4 or
  Teredo IPv4 controlled a whole /48+/32 of fresh identities (quota
  evasion). `canonicalIp` now also unwraps NAT64 `64:ff9b::/96` and
  `64:ff9b:1::/96`, 6to4 `2002::/16`, Teredo `2001:0000::/32`
  (XOR-decoded client address), and deprecated v4-compatible `::/96`,
  validates then strips `%zone` IDs, and `ipv6Groups` is strict
  (rejects bad octets and under-length uncompressed forms instead of
  `parseInt`-forgiving them). HTTP regression mints through all five
  spellings of one IPv4 and asserts a single quota bucket.
- *P8 — confirmed, and wider than reported.* The middleware rejected
  options its own types and engine implemented: not only
  `processing.avifEffort`/`avifChromaSubsampling` and
  `forensic.signsVersion`, but also stego `layoutVersion`/
  `legacyCode`. All five are now validated, plumbed (including
  `legacyCode` forwarding into the embed call, which was missing in
  `finishDerivative`), and included in output-cache identity so
  changing them cannot serve stale-vintage derivatives.
- *P10 — confirmed.* Build results omitted the typed `file` per
  variant and reported `bytes` where types promised `totalBytes`;
  both are emitted now (`bytes` kept for compatibility). While here:
  incremental build state ignored library-side derivative-byte
  changes entirely, so upgrading the package would have left stale
  pad/mark bytes on disk forever; `optionsMaterial` now carries a
  `derivativeFormatVersion` that rides the same bumps as the
  middleware cache namespace.
- *P11 — confirmed.* The server's tiled watermark repeated on a grid
  whose columns aligned every row (the client painters already
  staggered). Server rows now brick-stagger by half a step, raising
  the inpainting cost of periodic-pattern estimation.
- *P12 — confirmed.* Both CLIs omitted `avif` from the format list
  and falsely claimed the scramble key as the stego-key default (the
  engine rightly refuses that); help text now tells the truth. The
  demo static file server leaked a file descriptor per aborted
  request and had no stream error handler; the load-test tool wrote
  PNG bytes into `load.jpg`.

**Marks and padding (P5, P7).**

- *P7 — real weakness; the proposed patch was not safe to land as
  written.* v1.13's "128-bit" v2 layout/sign seeds derive four sfc32
  state words from a fast string hash (cyrb128): wide, but not a
  cryptographic KDF. The reviewer's patch *redefined v2* to a
  SHA-256 derivation, which would silently orphan every v2 mark
  embedded by 1.13. Instead v1.14 adds **layout/signs v3**:
  `sha256SeededPrng()` seeds sfc32 from the first 128 bits of
  SHA-256(key material) with 12 warm-up rounds. Embeds default to
  v3; detectors and forensic scoring triple-read v3→v2→v1 and report
  the matched vintage. v1/v2 derivations are bit-exact untouched —
  the 16-case pinned detector baseline (direct/crop/mirror/geometry
  searches over both profiles) is byte-identical before and after.
  One crop fixture that passed under v2 failed under v3-standard by
  shuffle variance (verified: v1/v2-standard and v3-robust recover
  the same crop), so that regression test now pins the layout it was
  calibrated on instead of pretending layouts are interchangeable.
- *P5 — confirmed with a fuller root cause.* v1.13's shifted wrap
  still let keyless tile solvers find boundary tiles: not (only) the
  values, but the *statistics*. Per-row phase jumps plus independent
  per-pixel noise destroyed texture coherence across the pad strip,
  and DC-only anchoring left visible seams on photographic texture.
  The core padding is rewritten: coherent toroidal wrap; a keyed
  best-match search over 24 candidate source rows/columns scored by
  mean-removed subsampled MAD (so the wrapped texture *fits* its new
  neighbours); ±16px box-mean DC anchoring; 8×8-block-coherent noise
  (texture-like, never zero); and a 3-step feather toward the true
  edge. On a real photo the strip-internal gradient ratios are
  0.45/0.85× interior and seam gradients 1.25/2.35× (v1.13:
  1.34/1.01 internal with 4.84/4.18 seams on the same image; the
  original mirror scheme measured ~9–18× seams on smooth content).
  On a deliberately ultra-smooth synthetic the seam *ratio* stays
  elevated (≈2.0 absolute MAD against a ≈0.2–0.5 interior) — with
  zero duplicated content that residual is information-theoretic:
  a flat image's pad must invent texture or confess flatness, and
  either is a (much weaker) tell. Displayed pixels remain exact by
  construction (padding is never sampled), asserted per-pixel. The
  browser's local-scramble padding gets the 2D analog (two keyed
  wraps composited at partial alpha — a near-copy of neither source
  region — plus a 3px true-edge taper, no readback).

**Temporal median (P6) — half a misreading, half a real leak.**
The reviewer claimed the interlace noise fill is symmetric around the
clean value, so a one-cycle recording's temporal median *is* the
clean pixel. The shader hash in fact re-seeds every presented frame
(`uSeed` is randomized per draw precisely to defeat short-window
statistics, and sign is randomized balance-corrected), so cycle
multisets are not the fixed `{c, c+d, c−d}` claimed. But the core
leak survives the correction: at 3 phases a 3-frame window contains
`{c, c+d₁, c+d₂}` with independent symmetric deltas, and the median
is exactly `c` whenever the deltas straddle zero — about half of all
pixels, recoverable from a <50 ms screen recording while
`fortress60`'s noise shield is off. Two reviewer corollaries were
exactly right: `fortress60` ships `noiseStrength: 0.55` into a 0.45
clamp, so the flagship profile silently ran weaker than specified
(clamp now 0.65, regression-asserted). And the fix shape is theirs,
mirroring the duty bias already used by the noise shield: a
cycle-zero-mean per-24px-block bias `b`, applied `+b·(P−1)/P` on a
cell's active phase and `−b/P` hidden (scaled by fill strength), in
both the shader (via the existing 90-frame re-seeded `biasHash`, so
long recordings chase a drifting offset) and the pre-rendered-frames
engine (where frames are static, so the bias is what moves every
cycle statistic off `c`). Cycle *mean* is unchanged — the eye sees
the same image; the median no longer does. This raises multi-frame
capture cost; it does not and cannot make displayed pixels
uncopiable (see §3).

**Server performance (S1–S7) — implemented where measured.**

- *S1 — confirmed.* Every per-token view loaded (and re-cached) the
  5–50 MB master before discovering the stage-1 base was already
  cached, evicting bases from the shared RAM pool; and N concurrent
  first-views each ran a full decode+resize because per-token output
  keys defeat output singleflight. Derivative resolution is now
  base-first (a warm base never touches disk or the master cache;
  `masterVersion` in the base key keeps replaced masters correct)
  with a `baseInFlight` singleflight around stage-1 creation,
  drained on `close()` and exposed in `stats()`. (Their S3 targeted
  the same duplicate stage-1 work; the singleflight is the
  mechanism, shipped here.) The reviewer's companion suggestion to
  hoist the singleflight entry creation was *not* taken literally:
  `loadMaster` deliberately stays outside the processing semaphore
  so disk latency doesn't consume codec slots.
- *S2 — confirmed.* `finishDerivative` copied the shared base
  unconditionally (an allocation of the full RGBA frame per
  per-viewer derivative, watermark or not). It now copy-on-writes:
  the copy happens only immediately before the first in-place
  mutation (forensic/stego embed, watermark blend);
  mark-free finishes encode straight from the shared base.
  Regression asserts byte-identical `base.data` after watermark,
  forensic, and stego finishes.
- *S4 — implemented; benefit re-scoped by measurement.* Detector
  fan-out (layouts × profiles × geometry × mirror hypotheses)
  rebuilt luma/integral planes per hypothesis. Planes are now built
  once per source buffer and threaded through the recursion
  (bit-identical results on the pinned 16-case baseline). The
  reviewer's 35–55% CPU claim did not reproduce here: on an
  800px unmarked geometry search, probe scoring dominates plane
  construction, and adding the v3 layout pass nets out to 8.4s
  auto / 7.0s robust vs 6.0s/5.3s for two layouts in 1.13. The real
  win is allocation churn (a full-size Float64 integral + luma per
  hypothesis → one per image), which is what pressure-tested
  detection workers feel. Claimed as such, not as a wall-clock cut.
- *S6 — confirmed, and the reviewer's cheaper alternative won.*
  Static-text watermarks re-parsed SVG and re-rasterized Pango text
  inside a full libvips composite per derivative (~37 ms at
  960×640 measured; ~21 ms of a ~205 ms full derivative).
  Caching a rasterized PNG overlay only halved it (20 ms — the
  composite pipeline itself dominates). The shipped path caches the
  *raw RGBA* overlay (4-entry/32 MB LRU keyed by geometry+SVG hash)
  and blends in JS (~2.3 ms, agreeing with libvips `over` to ≤1 LSB
  on opaque and translucent bases — measured, not assumed). Repeat
  watermarked derivatives now measure at parity with unwatermarked.
- *S7 — confirmed.* `withHardenedProductionDefaults` never set the
  processing defaults its catalog sibling (partly) had;
  `sharpConcurrency: 1` and `sharpCache: false` are now defaults in
  both presets, per-key overridable. (The reviewer credited the
  catalog preset with `sharpCache: false`; it didn't have it
  either — now it does.)

**Browser performance (C1–C6).**

- *C1 — confirmed for the default policy.* Every instance built a
  full-size decoy canvas at paint time although the default (and
  vault/fortress) `onExtract: 'black'` decoy needs no pixels.
  Black decoys now materialize lazily on first intercepted readback
  — most sessions never have one — saving the canvas and, on the GL
  path, a 320px unscramble per instance. Real decoys
  (`lowres`/`scrambled`) still build eagerly while clean pixels
  exist; shield can never rebuild them later by design.
- *C2 — already shipped (v1.12).* The GL upload source is zeroed
  immediately after `texImage2D` and the decoded bitmap released;
  verified in `#paintGl`, no change.
- *C3 — confirmed.* The 2D temporal frame builder allocated a fresh
  full-frame `ImageData` per phase and did two `Math.floor`
  divisions per pixel per phase. One shared scratch buffer
  (`putImageData` copies synchronously) and column lookup tables
  now serve all phases.
- *C4 — confirmed.* The GL watermark texture was a fixed 1024px
  raster regardless of a 200px tile backing; it now right-sizes to
  the current backing width (256–1024) and re-rasterizes on resize
  re-uploads as before.
- *C5 — rejected with evidence.* "Don't retain payload bytes under
  one-time tokens / claim refresh" is not actionable client-side:
  the token JSON deliberately carries no such server configuration,
  so the client cannot know; and mechanically the suggestion
  backfires — payload caching is precisely what lets a one-time
  deployment repaint on resize *without* burning a second mint.
  Hosts who want zero local retention already have
  `cachePayload: false`, which gates every write.
- *C6 — partially confirmed.* rAF loops already pause with the tab;
  the one true offender was the dynamic-trace `setInterval`
  repainting viewer text while hidden/off-screen. It now no-ops
  unless the document is visible and the instance is on-screen.

**Compatibility.** Derivative bytes change (v3 marks, new padding,
staggered rows, JS blend): middleware output-cache namespace moves
`v4`→`v5` and the asset builder stamps `derivativeFormatVersion:
'v5'`, so warm caches and incremental builds regenerate instead of
serving mixed vintages. Displayed pixels are unchanged. Detectors
older than 1.14 cannot read v3-layout marks — upgrade detection
tooling first, or pin `layoutVersion: 2` (now actually accepted by
the middleware, per P8). One behavioral note: a middleware instance
now *restores* Sharp loaders it narrowed when closed; hosts who
relied on a middleware constructor permanently blocking loaders
process-wide should call `configureSharpSecurity()` explicitly
(it remains permanent by design).

### 2.23 Fifth adversarial review — verification and response (v1.15)

Review #5 was a self-described "independent full-depth red-team audit"
of v1.14.0: five client-side attacks (C1–C5), six server/CLI/type
defects (S1–S6), four crypto/stego findings (M1–M4), a CPU/RAM
feasibility evaluation, and a verdict of "Conditional Near
Industry-Standard." As with the previous four, every claim was
reproduced against the shipped code before any fix was designed. The
report's root causes were largely real; several of its concrete
details were invented (documented below so future readers do not chase
them). Confirmed issues are fixed in 1.15.0 with regression tests;
residuals are stated plainly.

**S1 — cross-quality key reuse in `per-image` mode (CONFIRMED, fixed).**
The per-image scramble/AES keys were derived from the image id and the
deployment secret only, so every authorized viewer of an image received
the *same* key pair regardless of the quality tier their entitlement
allowed. A free-tier account could request the lossless derivative
(where `authorize` granted it to another class of viewer) or simply
hold a key that opened any derivative of that image ever served —
tiered quality was enforced per-request but not cryptographically.
Keys are now scoped to the delivered variant: `w` (canonical width),
`q` (quality), and `fmt` (format) — all of which were *already* pinned
in the signed token claims, so no token format change was needed. The
mint path derives with `variantKeyScope(w, quality, format)` and
redemption re-derives from the *claims* (never from request
parameters), and the derivative output-cache key carries the same
scope (cache namespace bumped to `v6`). A free-tier key now fails
AES-GCM authentication on the paid derivative and leaves it scrambled
even in unencrypted mode (regression test 92). Migration note:
per-image tokens minted in the last TTL window before an upgrade carry
legacy-scoped keys and will not unscramble post-upgrade derivatives;
the client recovers by re-minting. There is no reliable discriminator
for dual-derivation fallback, and silently trying two keys would halve
the protection, so the one-TTL convergence window is accepted and
documented. `per-token` mode (now also the hardened preset's explicit
choice) was unaffected by the flaw.

**S2 — X-Forwarded-For short-chain spoofing (CONFIRMED, fixed).** With
`trustedProxyHops: n`, the client IP was selected as
`chain[chain.length - n] || chain[0]`. For chains *shorter* than `n`,
the index was negative and the fallback selected `chain[0]` — the most
spoofable value in the header — letting a direct attacker mint one
fresh quota identity per invented IP. MDN's guidance (count trusted
proxies from the right; the header is untrustworthy when the origin is
directly reachable) applies with full force here. Short chains now
fall back to the canonical socket identity. A chain of exactly `n`
entries legitimately selects index 0 *under the operator's stated
trust assumption* (those entries were appended by proxies the operator
controls); deployments that cannot make that guarantee should not
enable `trustProxy` at all (regression test 93).

**S3 — authorized headless clients (CONFIRMED as a limit, not a bug).**
A scraper holding a legitimate session can request tokens and
derivatives at whatever rate the operator's `authorize` and quotas
allow. Archx constrains (sender-constrained one-time tokens, per-IP /
per-viewer quotas, abuse-pattern scoring, cache-bounded CPU) but
cannot distinguish "paying customer with a script" from "paying
customer with a browser" without becoming a bot-management product.
Operators who need that must layer a real bot/WAF product in front;
the `authorize` hook is the integration point. Documented residual.

**S4 — `BoundedTtlSet` saturation behaviour (CONFIRMED, fixed).** On
saturation the one-time-token store scanned the whole map (O(N) per
claim) and then failed *closed for everyone* — a self-DoS once
`maxEntries` unexpired JTIs accumulated under load or attack. `claim()`
now performs bounded front eviction in insertion (≈ expiry) order:
expired entries first, then the oldest live entries, within a budget of
`1024 + maxEntries/64` deletions. Evicting one near-expiry JTI re-opens
replay for that single signed, sender-constrained, re-authorized token
in its final seconds; rejecting every legitimate viewer is strictly
worse. Fail-closed remains only for pathological map disorder that the
bounded scan cannot resolve (regression test 94). The in-memory
`claimOnce` store inherits the behaviour.

**S5 — CLI argument parsing and manifest permissions (CONFIRMED, fixed).**
All three CLIs shared a parser whose flags greedily consumed the next
argument: `archx-detect --json suspect.png` treated `suspect.png` as
the *value of `--json`* and then reported on a missing file; `--x=y`
forms were unsupported. Parsers now take an explicit boolean-flag set,
support `--flag=value` (with boolean coercion for known booleans), and
never let a boolean swallow a positional path. Separately, the
build-manifest was written `0600`, which routinely 403s when the build
runs as one user and the web server reads as another; the manifest
(whose contents are public by design) is now `0644` while the build
state file stays `0600` (regression tests 97–98).

**S6 — type/runtime declaration drift (PARTLY CONFIRMED, fixed).** Real
drift: `deploymentMode` was declared `'development' | 'production'`
but the runtime accepts `'single-instance' | 'multi-instance'`;
`bindTokenTo` was typed as an array but implemented as an object map —
the runtime now *also* accepts the declared array form
(`['ip', 'ua', …]`, normalized to the same binding shape) so both
spellings work and the type is a union; stego `scope/keyScope` types
advertised `'token'`/`'global'` values the validator rejects (they
were never "silently ignored" as the report claimed — strict
validation throws); `validateWatermarkValue` was typed `string | null`
but returns `boolean` (and returns `false` for function inputs rather
than throwing, contra the report). The declared-but-unimplemented
`ttlSec` on the `authorize` result is now implemented: an integer in
[5, 900] from `authorize` overrides the minted token lifetime
(regression test 95). Invented details in the report, none of which
exist in either the types or the runtime: `deploymentMode: 'hardened'`,
a `tokenTtlSec` option, an `onAuditEvent` hook, and a server-side
`presets` option.

**C1/C2 — post-load prototype hooks on uncaptured methods (CONFIRMED,
fixed).** The render path called `gl.uniform1f/2f/1i` (and the rest of
the draw-setup family) directly, and the off-DOM unscramble used
`save/restore/translate/scale` directly. A userscript/extension that
patched `WebGL2RenderingContext.prototype.uniform1f` *after* Archx
loaded could zero the temporal/lens modulation mid-draw; a hooked
`CanvasRenderingContext2D.prototype.restore` received `this.canvas` —
the uncropped padded intermediate. Both families are now captured at
module load and every render/sensitive call goes through
`glNative()`/`ctxNative()`; the integrity audit names the new methods
too. Browser regression [8g] proves a post-load `uniform1f` hook
observes *zero* Archx calls while vault temporal rendering continues,
and a `restore` stealer never receives an off-DOM canvas. (The
report's specific uniform names — `u_traceAlpha` and friends — do not
exist in the shipped shader; the technique class was nevertheless
real.) **C3** (pre-load realm compromise: hooks installed before the
captures run are indistinguishable from natives) is an accepted
residual of any in-page defence; SRI-pinned self-hosted bundles,
extension-free kiosk browsers, and first-party-only script policy are
the mitigations. **C4** claimed the WebGL context-budget fallback was
silent; it already dispatched `archx-webgl-budget` before falling back
to Canvas2D — 1.15 additionally emits the `archx.webgl_budget`
telemetry event. **C5** (multi-frame averaging of temporal interlace by
a determined capture attacker) is the documented physics of the
feature: it raises cost and injects traceable per-viewer fingerprints,
it does not make displayed pixels unrecoverable.

**M1 — plan-v1 default (CONFIRMED, flipped).** Plan v2 (128-bit seed)
shipped in 1.10 but every producer still defaulted to the 32-bit-seed
v1, whose seed space is brute-forceable against known plaintext.
Defaults now: middleware, `scrambleImage`, `unscrambleImage`, the
static builder, and both CLIs all plan-v2 (containers remain
header-authoritative for stored assets; raw pre-1.15 v1 payloads need
explicit `planVersion: 1`). Cache/derivative namespaces bumped to `v6`
so no v1-keyed derivative is served under a v2 header. **M2**
(unencrypted payloads are one known-plaintext away from key recovery
under v1) was already warned at construction; `encrypt: false` and
explicit `scramblePlanVersion: 1` are now production-audit *blockers*,
and the hardened preset pins `scrambleKeyMode: 'per-token'`.

**M3 — detector geometry gaps (PARTLY CONFIRMED, improved).** The
report's geometry mental model (centre-shift percent) did not match
the implemented search (independent X/Y scales over explicit origin
ranges, quarter-origin refinement, sub-cell fractions), but two
concrete evasions reproduced: a *vertical* flip (only the horizontal
mirror was probed) and moderate corner crops whose scale fell between
table entries. The mirror search now probes x, y, and xy (180°)
variants and reports `mirrorAxis`; a failure-only geometry stage 2 adds
deep retained-area scales (0.65–0.75 and reciprocals), which recovers
e.g. 88% corner crops at full confidence. Deep crops (≤ 75% retained
on an axis, 1:1 reframes) and arbitrary rotation/perspective remain
outside the evidence envelope: at that point too few marked cells
survive for any search breadth to help — that requires the
sync-template mark v2 scoped in §2.20, and 1.15 does not claim it.
Forensic detection also gained `detectStegoFingerprintInWorker()` so
the multi-second worst case never runs on a request path.

**M4 — pHash DC bit (CONFIRMED, documented).** The median excludes the
DC coefficient, but the DC term participates in bit 63 and exceeds any
AC median in practice, so registries hold 63 effective bits.
Redefining the bit would orphan every stored 16-hex print for one bit
of dedup entropy; thresholds were calibrated with the constant bit
present. Documented in code, deliberately not changed.

**Feasibility notes (CONFIRMED in direction).** The report's CPU/RAM
cautions were directionally right: default `maxInputPixels` is raised
to an explicit, consistent 50 MP (middleware was 40 MP, the direct API
already 50 MP — an inconsistency worth more than the value), AVIF at
effort > 2 now warns at construction (it is an offline/batch codec
setting, not a request-path one), and `OPERATIONS.md` gained explicit
RAM sizing (`sharpConcurrency × in-flight derivatives × ~4 bytes ×
input pixels`, with the unref'd worker excluded from request paths).
Per-request AVIF encoding at high effort remains the operator's footgun
to avoid; the static builder + CDN guide is the recommended shape for
catalogues.

Nothing in this review changed the fundamental limits stated since
§2.1: displayed pixels can be photographed, client-side checks are
defence-in-depth, and attribution is probabilistic forensic evidence —
not proof on its own.

## 3. Threat model

| Adversary | Goal | Archx outcome |
|---|---|---|
| Casual visitor | save a picture they like | Finds no save path at all (A1/A2 dead-end) |
| Bookmarklet/extension user | strip a page/gallery in one click | DOM has no images; canvas grabs return decoys |
| Scraper bot operator (incl. AI training crawlers and stealth browsers) | harvest a whole catalogue | No URLs in HTML; needs JS, POST, authorization and a fresh signed token per image; bounded rate/quota/distinct-image controls make sweeps slow and visible; payloads are mosaics/ciphertext. Client fingerprint signals are not trusted because coherent stealth stacks can spoof them |
| Script/extension injector | hook web APIs or grab viewer internals wholesale | Captured natives bypass later hooks; audits can fail closed in Fortress; no host expando/public registry/debug handle exposes canvases, bitmaps, or keys |
| Token thief | replay/share a captured delivery URL or token, or inflate its derivative size | Strict v2 claims + short expiry + synchronous proof/nonce claims; redemption reauthorization and viewer/session checks; optional IP/User-Agent friction; DPoP-style proof makes a copied token unusable without the page's non-extractable private key; current entitlement can only tighten signed width/quality/format |
| Skilled fan / pirate | extract one specific premium image | Must reverse the scramble + capture session keys from their own browser; even perfect reconstruction is capped at the authorized derivative and can retain server-baked visible/forensic marks. Fortress adds strict memory lifetime and probing lockouts |
| Insider / paying customer | leak content they can legitimately view | Screenshot/camera remain possible, but the delivered pixels can carry viewer-specific visible + forensic + blind StegoMark IDs; Lens prevents one screenshot from containing the whole sharp image, and the registry can identify the issued view when the mark survives and is geometrically recovered |
| Screenshot-extension / DevTools user | capture the visible tab with browser privileges | Page JS cannot veto the capture; source/DOM still expose no file or signed URL, Vault read-back is black, and Fortress visible pixels are Lens/patterned-temporal-degraded + dynamically traced |
| Cross-device photographer | keep the site open on one device and photograph it with another | Undetectable in principle; quality is limited by the entitled derivative and screen/camera losses, with server marks, dynamic trace, checker/band opponent-colour effects, and Lens reducing resale value; StegoMark phone-photo recovery is unproven without external rectification |
| AI cleanup / regeneration operator | turn a degraded capture into a polished copy or remove invisible marks | Cannot be ruled out for visible pixels. Archx limits source information and keeps server-side entitlement/issuance evidence; regenerated detail is invented, but the business still needs monitoring/enforcement |
| Reposter denying origin | circulate a copy stripped of metadata/credit | `archx-detect` can test for the blind StegoMark, search bounded axis-aligned crop geometry, compare a registered perceptual soft binding, and map recovered evidence to the owner's issuance record; rotation/perspective/AI/fingerprint-evasion failures remain possible |
| Cache-deception attacker / misconfigured CDN | have a shared cache retain and resend one viewer's derivative | Origin responds `private,no-store` through standard, CDN, and surrogate controls with credential/token/proof-sensitive `Vary`; deployment tests must prove no edge rule overrides them |
| Hostile input/upstream operator | crash or exhaust the decoder, redirect the client, or smuggle an oversized/parser-confusing payload | Byte-only Sharp inputs, pre-decode sniffing/metadata cross-checks, loader and format allowlists, strict token JSON/origin/redirect rules, streamed byte caps, and dimension/pixel/timeouts on both sides fail closed |

Non-goals: hiding that protection exists, DRM-level guarantees, stopping a
camera pointed at a monitor, proving browser integrity on a machine the
attacker owns, defending composited frames against a compromised browser/GPU
process, claiming invisible marks survive arbitrary AI regeneration, or
compensating for masters also hosted at public URLs (that's a deployment
error — see the README checklist).

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
   `IntersectionObserver`, max-6 decode concurrency, bitmap LRU and private
   scrambled-payload retention so a once-loaded image repaints locally,
   integer-tile reassembly with a single smoothing pass (no seams, no
   per-pixel loops), server output caching, draw-on-demand WebGL for static
   stills, and a hard WebGL-context budget with automatic fallback.
   Off-screen backing-store unloading remains an opt-in memory knob, not a
   reason to remint tokens while scrolling.
7. **Server marks outrank client marks for reconstruction resistance.** A
   client-added `{session}` watermark is useful against screenshots/canvas
   grabs, but the offline reconstruction path bypasses the client renderer.
   Therefore the middleware/CLI can mark the resized derivative before
   scrambling. Header `wm`/`fx`/`sg` flags let operators verify that the
   delivered container was marked without placing the forensic seed or
   StegoMark fingerprint derivation in the payload.
8. **Entitlements are signed policy, not presentation hints.** Width — and
   now delivery quality/format — is part of the security boundary. The
   middleware accepts a browser's desired width/quality only as a request,
   clamps width by global and per-viewer `maxWidth`, lets `authorize()` set
   `quality`/`lossless`/`format`, and signs the resulting derivative policy.
   One-time/browser-bound tokens are optional because they increase token
   churn and can interact with retries, mobile IP changes, and shared
   networks.
9. **Encapsulation should be structural, not naming-based.** Calling a field
   `_canvas` is only a convention. `#private` fields and private WeakMap
   registries make internals unavailable to ordinary page script even if it
   obtains the public `ProtectedImage` object or host element. A default-off,
   per-instance debug opt-in preserves testability without shipping an
   always-available extraction handle.
10. **Per-viewer attribution deliberately costs server cacheability, not
    viewer reloads.** Per-token watermarks, forensic seeds, StegoMarks,
    scramble keys and one-time URLs reduce cross-viewer output reuse. On the
    client, however, a delivered view should be spent once: strict bitmap
    release is paired with private payload retention / texture repaint so
    scrolling and ordinary resizes do not ask for another token. The API
    exposes the granularity (`forensicPerToken`, StegoMark `perToken`, static
    CLI marks, `cachePayload`, `reloadOnResize`, normal vs strict memory,
    `lite` vs `fortress`) rather than forcing maximum paranoia onto 500
    catalogue thumbnails.
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
13. **Loaded means loaded; static means static.** A still photograph is not a
    video game. After first paint, visibility changes repaint from the
    retained bitmap/WebGL texture or decode the already-delivered scrambled
    payload locally; ordinary resizes do not remint one-time tokens; and
    WebGL presents a few frames then idles unless Lens interaction, a resize,
    a lock/risk change — or the explicitly continuous temporal shield — asks
    for more. `reload()` remains the deliberate forced-refresh API.
14. **Temporal and steganographic layers must be labelled by what they prove.**
    The temporal shield and temporal interlace prove only that one frame is
    an incomplete/noisy sample; time integration, recording, or collecting
    each interlace phase can recover more. StegoMark proves, when it decodes,
    that a suspect copy is consistent with a registered fingerprint; it does
    not prove a negative when filtering/regeneration has destroyed the
    signal. Shipping the detector, CRC/confidence output and negative
    controls matters more than calling either layer “screenshot-proof” or
    “AI-proof.”

15. **Configuration is part of the attack surface.** A missing authorization
    callback, demo secret, wildcard origin, public/master path overlap, or
    absurd processing limit is not a warning to discover after an incident.
    Startup either receives a coherent deny-by-default policy or throws;
    `allowAnonymous:true` is deliberately explicit and auditable.
16. **A signed URL is a request to re-check policy, not the policy itself.**
    Claims say what was approved at issuance; redemption asks what is true
    now. This is the only way revocation and entitlement downgrade can have
    an effect shorter than token expiry.
17. **Every security store gets a forgetting rule.** Rate windows expire,
    nonce entries expire, client maps evict, caches have byte ceilings, and
    processing queues reject predictably. “Security state” that grows forever
    becomes a denial-of-service feature for the attacker.
18. **Do not port hardware claims into browser marketing.** TPVM needs a
    synchronized viewer; anti-camera LEDs need controllable illumination;
    neural screen-shooting watermarks need learned localization/synchronization.
    Archx borrows the page-feasible signal-processing ideas (complementary
    checker/bands/chroma, literal phase-partitioned subsets, incomplete
    reveal, redundant marks) and labels the missing hardware/learning pieces
    as missing.

## 5. Evidence (this repo's measurements)

- **Unit/integration (Node, 44 tests):** scramble plans are deterministic,
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
  StegoMark tests decode the blind fingerprint with no reference image, keep
  decoding it after downscale + JPEG re-encoding, reject unmarked and
  wrong-key controls, and prove that an HTTP entitlement's lossless/PNG
  policy wins over a browser's `q=10` request while `onStegoIssue` receives
  exactly the fingerprint later recovered from the reconstructed copy.
  The v1.4 regressions additionally prove that missing `authorize()` and
  weak/short secrets fail startup, wildcard origins and unsafe processing
  numbers are rejected, master/public overlap is refused, an outside-pointing
  symlink is not indexed, every strict v2 claim mutation fails, bounded
  limiter/nonce stores expire or fail closed, an overloaded semaphore returns
  a typed busy error, malformed percent-encoding/traversal/extra segments/
  wrong methods/oversized token bodies/bad sizing/cross-site fetch metadata
  produce controlled 4xx responses, revoked or transferred sessions cannot
  redeem, a downgraded entitlement narrows the delivered width, token/image
  quotas and distinct-image denial fire with sanitized security events, and
  corrupt/oversized/format-mismatched masters produce typed Sharp-limit
  errors. Twenty parallel spends of one signed URL produce **one** 200 and
  nineteen 403s. The v1.5 regressions additionally prove that unknown server
  options, weak-secret bypass attempts, and ambiguous authorization shapes
  fail closed; public signing/verification, live-index, and test-hook surfaces
  are absent; strict sniffing/container/base64 and byte-only Sharp inputs
  reject hostile payloads before unsafe paths; required mint headers, clean
  header-token transport, query-token opt-out, callback deadlines, and
  right-side trusted-hop `X-Forwarded-For` selection behave as configured.
  A required-proof fixture rejects missing/malformed proof keys, a copied
  token without a proof, and a proof from the wrong P-256 key; the correct
  key succeeds, the exact proof cannot replay even with reusable tokens, a
  fresh proof can, and responses carry CDN/surrogate `no-store` plus
  proof-sensitive `Vary`. The soft-binding test registers a perceptual
  fingerprint during `scrambleImage()`, matches a resized/JPEG copy within
  distance 10, and separates an unrelated synthetic image. The temporal-
  interlace normalizer test proves the five named 60 Hz profiles exist
  (including three-phase `fortress60`), disabled forms normalize to `null`,
  a 4-phase request is clamped to 2 phases at 60 Hz/30 Hz minimum, the same
  request remains 4 phases at a configured 120 Hz target, and shader/frames
  plus pixel/block aliases map to the documented engines/layout defaults.
  The second-review regressions additionally prove query tokens are off by
  default while an explicit legacy opt-in works; hardened defaults fill
  only unset fields; the production audit flags query tokens, optional PoP,
  reusable tokens, record-only abuse handling, unregistered Stego issuance,
  and multi-instance memory state; buyer/order/delivery/trace fields reach
  key-free Stego, provenance, delivery, and security hooks; a provenance
  failure denies by default; and the bundled Redis adapter satisfies the
  fake-client `SET NX PX` plus single-key Lua contract. The robust
  StegoMark unit fixture recovers exactly after resize/JPEG, ordinary
  photometric editing, and a photographic center crop while the unmarked
  control remains negative. The scale regressions additionally prove that
  canonicalization never exceeds an entitlement cap, a 641 px request is
  signed for the 800 px bucket, batch minting returns independent per-item
  successes/failures, different authorized viewers receive byte-identical
  reusable catalog derivatives, a restarted handler gets a persistent disk
  hit with no new miss, the asset builder reuses every unchanged variant and
  regenerates only a damaged one, and the in-place server Stego path is
  byte-identical to the copying public API.
- **Real browser (headless Chromium, 104 checks):** a page with 7 protected
  images + 1 normal `<img>` exposes exactly **1** downloadable image (the
  normal one) — 0 canvases reachable from the document, 0 URLs in any
  protected element's HTML, closed root invisible to JS; protected hosts have
  no `__archx` expando, `Archx._instances` is absent, public option/config
  views redact secrets, instances expose no public canvas property, and
  `_debug()` is null without explicit per-instance opt-in. At native element
  resolution the latest Shield render measures **8.05 MAD and 0.87
  gradient-detail ratio** versus the ordinary `<img>` in the current
  marked/StegoMark demo configuration (the cover/quality work had moved an
  earlier failing 11.28 / 0.53 measurement to 7.03 / 0.85 before the
  additional stego layer). `toDataURL`/`toBlob`/
  `getImageData` all return decoys and fire attempt events; repeated probes
  trigger the configured strike blackout. Replacing `fetch` and patching
  WebGL `drawArrays`/`drawElements` are reported by the detailed integrity
  audit; Fortress fails closed under the demonstrated fetch-hook fixture,
  Vault reports it and continues, and invalid integrity values fail closed.
  A separate page installs a framebuffer-reading `drawArrays` wrapper with
  Puppeteer's `evaluateOnNewDocument` *before* the Archx module evaluates:
  `capturedNonNative` names both WebGL variants, Fortress gives the hook no
  non-black pixels, and Vault's monitor policy intentionally renders while
  the hook samples 256 non-black center pixels—an executable record of the
  residual risk, not a claim that the hook was prevented.
  Global/plugin telemetry is asserted to be coarse and key-free, and the
  degraded scrambled decoy for `gallery-016` differs materially from its
  clean derivative (MAD 39.60 in the latest regression). Trusted pointer
  movement positions the Lens while a synthetic untrusted event does not; the
  dynamic capture trace is active with session/time text, and a PrintScreen
  signal immediately blackouts. Strict mode reports the bitmap released and
  the GPU source scrambled. The lifecycle regression test loads a strict
  Fortress token image, cycles visibility with backing-store unloading and
  applies an ordinary resize, and observes **exactly one token request and
  one payload request total**; in the render-economy check a static Vault
  presented **0 extra frames over 450 ms**, while a temporal-shield Fortress
  presented 27. The WebGL prototype bypass returns **pure black**
  (mean RGB ≈ 0), split mode uses 9 separately poisoned canvases, guards and
  print blackout engage, and network checks confirm a marked mosaic payload,
  one-time replay rejection, and wrong-User-Agent rejection. The production
  POST-token path is exercised by the actual page loads; v1.5 additionally
  proves duplicate-host/shadow failure, hostile SVG rejection, immutable
  public option views, clean payload URLs with no bearer token in Resource
  Timing names, and real Chromium request traffic carrying both the mint
  proof key and a proof on every payload request. v1.4 also renders a
  `bands` + chroma camera shield continuously in WebGL and a `checker` +
  chroma shield as complementary Canvas2D frames, exposes their normalized
  pattern/chroma only through the debug-gated test hook, scopes their token
  cache, and verifies `Archx.clearCaches()` does not blank already-painted
  instances. Temporal-interlace checks render pixel subsets through the
  shader engine, two-phase strips and three-phase randomized blocks through
  pre-rendered Canvas2D frames, and Lens through both engines. In a retained
  black-fill strip fixture, successive real Puppeteer element screenshots
  produced a maximum opposite-phase MAD of **about 96/255** in recent runs,
  while the debug phase index advanced between captures—evidence that the
  compositor presented different incomplete phases, not merely that
  configuration state changed.
- **Performance/quality tradeoff:** 100/100 gallery images loaded+painted in
  **2.1 s** in the latest deliberately non-lazy headless run with catalog
  derivatives, 0 `<img>` tags, **2 batch mint requests and 0 single mints**;
  browser bundle **114.4 KiB minified / 37.1 KiB gzipped**. The browser
  fixture also builds two real precomputed assets, renders them through both
  the JS and custom-element manifest paths, selects the 640 px variant for a
  340×220 cover box, and proves one shared manifest request serves the page.
  In `npm run bench`, the 1408×768 master at 960 px took 144 ms/249 KiB for
  quality-first q95 versus 57 ms/170 KiB for catalog q88/effort-2. In a
  separate loopback HTTP fixture with anonymous authorization and no proof
  header, six cold canonical flows measured p50 87 ms; after a handler
  restart the same six flows were all disk-cache hits at p50 2.8 ms, and one
  50-item batch mint completed in 11.3 ms versus 59 ms for 50 parallel
  single mints. Those loopback figures deliberately exclude a real
  authorization database, TLS/network latency, Redis, and browser proof
  signing, so they are regression evidence—not a production throughput
  claim. Static/per-image server outputs remain cacheable; per-token or
  viewer-scoped marks/keys and lossless payloads intentionally trade
  bytes/cache hits for attribution and exactness, while the client spends a
  delivered payload once and then repaints locally.

- **StegoMark transform matrix (three 800 px photo masters, strength 6,
  geometry search on):** direct PNG, resize to 560 px + JPEG q70, blur 0.8 +
  JPEG q85, and brightness/saturation/contrast adjustment + JPEG q85 decoded
  in the earlier matrix. The v1.4 crop matrix decoded 90% centre-crop +
  resize (3/3), left-edge crop leaving 85% width (3/3), and top-aligned crop
  leaving 90% height (3/3), but only 2/3 at an 80% centre crop; 2° rotation +
  90% centre crop decoded 0/3. Geometry search on these files took roughly
  1.8–2.3 s per suspect on the test machine, so it is an offline forensic
  mode, not a per-page-view cost. Unmarked controls remained negative. These
  results support resize/re-encode/mild-blur/photometric and bounded
  axis-aligned-crop claims only—not rotation, perspective, screen-photo, or
  AI-regeneration attribution.

- **Robust StegoMark follow-up matrix (final 20×14 tuning):** on the
  synthetic SVG master, the robust profile recovered fingerprint
  `15b03266f7f1` exactly with 0 corrections for direct output,
  resize-to-448 + JPEG q82, and brightness 1.05/saturation 1.1/blur 0.4 +
  JPEG q80 (cell agreement 0.982/0.979/0.982). On the natural 640×420
  `aurora-valley` fixture it recovered the same exact fingerprint with 0
  corrections direct, after resize/JPEG, after the photometric edit, and
  after a 90% center crop + resize/JPEG q85 with geometry search; the
  unmarked natural control returned `found:false`. A flat synthetic 90%
  crop remained unreliable and, under overly permissive repair, could
  produce a CRC-valid wrong neighbor—hence the final high-correction
  evidence gate and the explicit decision not to claim flat-graphics crop
  recovery.
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
- ShootProof, *Introducing Screenshot Protection* (desktop blur/notice;
  mobile partially blurred, touch-shifting reveal; positioned as deterrence)
  — https://www.shootproof.com/blog/screenshot-protection/
- Steg.AI, *Watermarking Software for Secure Collaboration* (patented deep
  Light Field Messaging; vendor claims survival through common edits,
  screenshots and screen-to-camera capture; watermark → share → trace
  workflow) — https://steg.ai/watermarking-software/
- persistent.info / Mihai Parparita, *Screenshot-proof images via temporal
  dithering* (positive/negative frame proof of concept and its own
  recording/analog-hole caveats) —
  https://blog.persistent.info/2012/12/screenshot-proof-images-via-temporal.html
- Chrome, `chrome.tabs.captureVisibleTab` (extension-privileged visible-tab
  capture available to the browser, not a page-vetoable web API) —
  https://developer.chrome.com/docs/extensions/reference/api/tabs#method-captureVisibleTab
- Ilya Grishchenko et al., *Invisible Image Watermarks Are
  Provably Removable Using Generative AI* (NeurIPS 2024; regeneration attacks
  against pixel-level invisible watermarks) —
  https://arxiv.org/abs/2306.01953
- IMATAG forensic-watermarking API material (unique per-recipient invisible
  identifiers plus later detection/monitoring as the production workflow) —
  https://www.imatag.com/api/forensic-watermarking-api
- OWASP, *Authorization Cheat Sheet* and *Broken Access Control* (least
  privilege, deny by default, resource-level checks, logging/rate limits,
  short-lived stateless tokens) —
  https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
  · https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- Sharp, *Security* and *Output* documentation (treat all input as untrusted;
  warning/pixel/channel limits; metadata is removed from output by default;
  run image work under resource limits) —
  https://sharp.pixelplumbing.com/security/
  · https://sharp.pixelplumbing.com/api-output/
- Xiaolin Wu & Guangtao Zhai, *Temporal Psychovisual Modulation: a new paradigm of
  information display* (high-refresh atom frames fused through
  display-synchronized viewing devices and the human visual system) —
  https://arxiv.org/abs/1201.1601
- *Anti-camera LED Lighting* (multispectral coded illumination intended to
  create rolling-shutter colour artifacts while appearing steady to people)
  — https://dl.acm.org/doi/10.1145/3123266.3123416
- Shilin Zhu, Chi Zhang & Xinyu Zhang, *Automating Visual Privacy Protection Using a
  Smart LED* / LiShield (smart-LED waveforms exploit row-sequential camera
  exposure; custom illumination hardware is part of the system) —
  https://cacm.acm.org/magazines/2020/2/242333-automating-visual-privacy-protection-using-a-smart-led/abstract
- *Screen-Shooting Resilient Watermarking* (I-SIFT localization, repeated
  templates, and the lens/light/moiré distortion model) —
  http://home.ustc.edu.cn/~zh2991/18TIFS_Screen/Screen-Shooting%20Resilient%20Watermarking.pdf
- *ScreenMark: Watermarking Arbitrary Visual Content on Screen* and
  *Automatic Localization and Detection Applicable to Robust Image
  Watermarking Resisting Camera Shooting* (why localization/synchronization,
  not merely payload redundancy, dominates screen→camera recovery) —
  https://arxiv.org/html/2409.03487v1
  · https://arxiv.org/pdf/2304.13953
- IETF RFC 9449, *OAuth 2.0 Demonstrating Proof of Possession (DPoP)*, and
  RFC 7638, *JSON Web Key (JWK) Thumbprint* (sender-constrained tokens: a
  copied token without the corresponding private key should not redeem;
  short proof lifetimes and replay identifiers are part of the design) —
  https://www.rfc-editor.org/rfc/rfc9449.html
  · https://www.rfc-editor.org/rfc/rfc7638.html
- PortSwigger Web Security Academy, *Web cache deception* and *Web cache
  poisoning* (sensitive dynamic responses need origin `private,no-store`;
  cache rules/keys must account for credentials and request-header variance,
  and a CDN override can defeat otherwise correct headers) —
  https://portswigger.net/web-security/web-cache-deception
  · https://portswigger.net/web-security/web-cache-poisoning
- C2PA Specification and FAQ (Content Credentials are provenance, not DRM;
  durable credentials use soft bindings such as fingerprints/watermarks to
  rediscover a stored manifest after metadata separation) —
  https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html
  · https://c2pa.org/faqs/
- OWASP API Security Top 10, *Unrestricted Resource Consumption* and *Unsafe
  Consumption of APIs* (timeouts, payload/operation budgets, schema/size
  validation, and treating upstream responses/redirects as untrusted) —
  https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/
  · https://owasp.org/API-Security/editions/2023/en/0xaa-unsafe-consumption-of-apis/
- MDN, `X-Forwarded-For` (the left-most value is spoofable; security-sensitive
  client-IP selection must count trusted proxies from the right, and the
  header is untrustworthy when the origin is directly reachable) —
  https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For

- Sharp, *Performance* (libuv thread-pool sizing, per-operation libvips
  concurrency, allocator/cache tuning, and codec I/O as the throughput
  ceiling) — https://sharp.pixelplumbing.com/performance/
- MDN, *Fix your website's Largest Contentful Paint by optimizing image
  loading* (responsive candidates, modern formats, lazy loading below the
  fold, and reserving Fetch Priority for the key image) —
  https://developer.mozilla.org/en-US/blog/fix-image-lcp/
- Vercel, *Cache-Control headers* (long immutable caching only for
  versioned/content-addressed assets; personalized responses remain
  private/no-store) — https://vercel.com/docs/caching/cache-control-headers
