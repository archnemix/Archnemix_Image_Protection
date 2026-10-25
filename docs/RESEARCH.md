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

The design goal follows directly: **A1–A11, A13, A16–A20 and A24 should yield
nothing clean or reusable; A12/A14/A15/A21–A23/A25–A27 must be pushed toward at
most a server-authorized, screen-resolution, visibly/forensically marked copy
whose production is slow, noisy, and attributable; A28 should leave the owner
a testable fingerprint trail rather than screenshots and assertions.**

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
- One-time use is claimed synchronously after signature/claim/IP/UA checks
  and before the first redemption `await`. In Node's event-loop model this
  removes the check/use gap that let twenty parallel copies of one URL race;
  the regression test now expects exactly one 200 and nineteen 403s. The
  operational price is explicit: if redemption authorization, quota, or
  processing later fails, that URL is burned and the client must mint again.
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
   retain noise, checker phase, or banding. Lens still prevents one frame
   from containing the whole sharp image; dynamic traces and server marks add
   attribution. The defeats remain obvious and are documented rather than
   hidden: record and average frames, use a longer exposure, shift exposure
   phase, stitch pointer-Lens discs, denoise/regenerate, or simply accept the
   screen-resolution picture.

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

## 3. Threat model

| Adversary | Goal | Archx outcome |
|---|---|---|
| Casual visitor | save a picture they like | Finds no save path at all (A1/A2 dead-end) |
| Bookmarklet/extension user | strip a page/gallery in one click | DOM has no images; canvas grabs return decoys |
| Scraper bot operator (incl. AI training crawlers) | harvest a whole catalogue | No URLs in HTML; needs JS, POST, authorization and a fresh signed token per image; bounded rate/quota/distinct-image controls make sweeps slow and visible; payloads are mosaics/ciphertext |
| Script/extension injector | hook web APIs or grab viewer internals wholesale | Captured natives bypass later hooks; audits can fail closed in Fortress; no host expando/public registry/debug handle exposes canvases, bitmaps, or keys |
| Token thief | replay/share a captured delivery URL or inflate its derivative size | Strict v2 claims + short expiry + synchronous one-time claim; redemption reauthorization and viewer/session checks; optional IP/User-Agent friction; current entitlement can only tighten signed width/quality/format |
| Skilled fan / pirate | extract one specific premium image | Must reverse the scramble + capture session keys from their own browser; even perfect reconstruction is capped at the authorized derivative and can retain server-baked visible/forensic marks. Fortress adds strict memory lifetime and probing lockouts |
| Insider / paying customer | leak content they can legitimately view | Screenshot/camera remain possible, but the delivered pixels can carry viewer-specific visible + forensic + blind StegoMark IDs; Lens prevents one screenshot from containing the whole sharp image, and the registry can identify the issued view when the mark survives and is geometrically recovered |
| Screenshot-extension / DevTools user | capture the visible tab with browser privileges | Page JS cannot veto the capture; source/DOM still expose no file or signed URL, Vault read-back is black, and Fortress visible pixels are Lens/patterned-temporal-degraded + dynamically traced |
| Cross-device photographer | keep the site open on one device and photograph it with another | Undetectable in principle; quality is limited by the entitled derivative and screen/camera losses, with server marks, dynamic trace, checker/band opponent-colour effects, and Lens reducing resale value; StegoMark phone-photo recovery is unproven without external rectification |
| AI cleanup / regeneration operator | turn a degraded capture into a polished copy or remove invisible marks | Cannot be ruled out for visible pixels. Archx limits source information and keeps server-side entitlement/issuance evidence; regenerated detail is invented, but the business still needs monitoring/enforcement |
| Reposter denying origin | circulate a copy stripped of metadata/credit | `archx-detect` can test for the blind StegoMark, search bounded axis-aligned crop geometry, and map a recovered fingerprint to the owner's issuance record; rotation/perspective/AI failures remain possible |

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
    The temporal shield proves only that one frame is an incomplete sample;
    time integration/recording can recover more. StegoMark proves, when it
    decodes, that a suspect copy is consistent with a registered fingerprint;
    it does not prove a negative when filtering/regeneration has destroyed
    the signal. Shipping the detector, CRC/confidence output and negative
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
    checker/bands/chroma, incomplete reveal, redundant marks) and labels the
    missing hardware/learning pieces as missing.

## 5. Evidence (this repo's measurements)

- **Unit/integration (Node, 24 tests):** scramble plans are deterministic,
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
  nineteen 403s.
- **Real browser (headless Chromium, 62 checks):** a page with 7 protected
  images + 1 normal `<img>` exposes exactly **1** downloadable image (the
  normal one) — 0 canvases reachable from the document, 0 URLs in any
  protected element's HTML, closed root invisible to JS; protected hosts have
  no `__archx` expando, `Archx._instances` is absent, public option/config
  views redact secrets, instances expose no public canvas property, and
  `_debug()` is null without explicit per-instance opt-in. At native element
  resolution the Shield render measures **9.48 MAD and 0.88 gradient-detail
  ratio** versus the ordinary `<img>` in the current marked/StegoMark demo
  configuration (the cover/quality work had moved an earlier failing
  11.28 / 0.53 measurement to 7.03 / 0.85 before the additional stego layer). `toDataURL`/`toBlob`/
  `getImageData` all return decoys and fire attempt events; repeated probes
  trigger the configured strike blackout. Replacing `fetch` is both reported
  by `auditIntegrity()` and causes Fortress to fail closed. Trusted pointer
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
  POST-token path is exercised by the actual page loads; v1.4 also renders a
  `bands` + chroma camera shield continuously in WebGL and a `checker` +
  chroma shield as complementary Canvas2D frames, exposes their normalized
  pattern/chroma only through the debug-gated test hook, scopes their token
  cache, and verifies `Archx.clearCaches()` does not blank already-painted
  instances.
- **Performance/quality tradeoff:** 100/100 gallery images loaded+painted in
  about **2.9 s** in the deliberately non-lazy headless test with high-quality
  derivatives and 0 `<img>` tags; browser bundle **61.5 KiB minified / 20.7 KiB
  gzipped**. The 900 px q95 server pipeline previously measured ~147 ms
  one-time per cached variant. Static/per-image server outputs remain
  cacheable; per-token marks/keys and lossless payloads intentionally trade
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
