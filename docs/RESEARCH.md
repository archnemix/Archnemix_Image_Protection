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
  the still-image version of it into one small library + one middleware.

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

The design goal follows directly: **A1–A11 and A13 must yield nothing usable;
A12/A14 must yield at most a screen-resolution, watermarked, traceable copy.**

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

## 3. Threat model

| Adversary | Goal | Archx outcome |
|---|---|---|
| Casual visitor | save a picture they like | Finds no save path at all (A1/A2 dead-end) |
| Bookmarklet/extension user | strip a page/gallery in one click | DOM has no images; canvas grabs return decoys |
| Scraper bot operator (incl. AI training crawlers) | harvest a whole catalogue | No URLs in HTML; needs JS + fresh signed token per image, rate-limited; payloads are mosaics/ciphertext |
| Skilled fan / pirate | extract one specific premium image | Must reverse the scramble + capture session keys from their own browser; ceiling = display-size, watermarked, grain-traced copy (vault forces them down to screenshots) |
| Insider / paying customer | leak content they can legitimately view | Screenshot possible, but carries visible + forensic session watermark → attributable |

Non-goals: hiding that protection exists, DRM-level guarantees, stopping a
camera pointed at a monitor, compensating for masters also hosted at public
URLs (that's a deployment error — see the README checklist).

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

## 5. Evidence (this repo's measurements)

- **Unit/integration (Node, 10 tests):** scramble plans are deterministic,
  key-sensitive permutations; pixel scramble round-trips exactly; scrambled
  payloads are visually unrecognisable (mean absolute pixel difference vs
  master ≈ 55/255 on photo content) while un-scrambling restores them
  (MAD < 6 lossless, ≈ 5–8 through the full browser pipeline incl. watermark
  and WebP q82); encrypted payloads don't parse as images and fail closed
  under wrong keys; tokens reject tampering, expiry and id-swaps; the HTTP
  flow serves only down-scaled `.archx` containers.
- **Real browser (headless Chromium, 33 checks):** a page with 6 protected
  images + 1 normal `<img>` exposes exactly **1** downloadable image (the
  normal one) — 0 canvases reachable from the document, 0 URLs in any
  protected element's HTML, closed root invisible to JS; `toDataURL`/
  `toBlob`/`getImageData` all return decoys and fire attempt events; the
  WebGL prototype bypass returns **pure black** (mean RGB ≈ 0) while the
  same canvas screenshots as a perfectly normal photo; split mode = 9
  separately poisoned canvases; right-click and drag are intercepted;
  window-blur protection and print blackout engage; master path → 404,
  token-less image route → 403, captured payload is a mosaic.
- **Performance:** 100/100 gallery images loaded+painted in **~1.5 s** in
  headless Chromium with 0 `<img>` tags; browser bundle **11.7 kB gzipped**;
  server scramble+encode ≈ 100 ms one-time per image/width (cached
  thereafter), pixel scramble ≈ 135 MP/s, AES-GCM overhead ≈ 4 ms.

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
