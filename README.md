# 🛡 Archnemix Image Protection (`Archx`)

**Show your images. Don't give them away.**

Websites that display valuable images — portfolios, stock previews, product shots, paid content, exam papers, real-estate and art listings — face an unfair fight: a plain `<img>` tag hands every visitor the raw file (right-click → *Save*, drag-and-drop, DevTools, bulk-download extensions, AI scrapers). Most sites give up because doing anything better means stitching together ten half-techniques yourself.

**Archx is that work, done once, in one tiny library:**

```js
Archx.load.image('#hero', { id: 'aurora-valley' }, { mode: 'shield', watermark: '© My Studio' });
```

No `<img>` is ever created. There is no image URL in your HTML to copy, no file in the Network tab to save, and the picture itself is painted through a sealed, protected viewer that fights back at every step a thief normally takes. People who dig deeper get a **black card**, a **scrambled mosaic**, or a **heavily pixelated thumbnail** — your call. Your original file **never leaves the server**.

- 📦 **19.8 KiB gzipped**, zero runtime dependencies (browser)
- ⚡ Built for **hundreds of images per page** (lazy loading, decode concurrency cap, bitmap/payload caching, display-size-aware rendering) — 100-image gallery verified in tests. **Loaded images do not reload** on scroll/visibility/ordinary resize, and static WebGL images draw on demand instead of running a 60 fps GPU loop
- 🖼️ **Quality-first rendering:** quality profiles (`original` = pixel-exact lossless at display size, `high` = q95, `balanced`, `fast`), stable-layout + cover-aware derivative sizing, exact device-pixel canvas sizing where available, DPR up to 3, native/oversampled tile reassembly, and exact/supersampled WebGL sampling — protection should not make fine detail look slurry
- 🧩 Four preset modes — **lite** (galleries), **shield** (default), **vault** (WebGL), and **fortress** (Vault + anti-hook lock, strike lockouts, strict memory wiping, dynamic capture trace, temporal anti-single-frame shield, and optional pointer lens) — plus `mode:'custom'` / a direct `renderer` flag and **direct parameters for every behaviour**, so you are never locked into a preset
- 🔐 Optional server: HMAC-signed, optionally one-time and browser-bound URLs, entitlement-capped resolution **and quality/format**, tile-scrambled / AES-GCM-encrypted delivery, and visible/forensic/**blind steganographic StegoMark** fingerprints baked in **before** scrambling
- 🕵️ Hardened internals: private fields, no public instance registry or host expando, secret-redacted option views, captured native APIs, and hooked-API / automation policies

> **Honest up front:** no web technology can stop someone photographing their screen, pressing PrintScreen before page JS can react, or fully controlling their own browser — and no pixel watermark is immune to a determined AI-regeneration attack. What Archx guarantees is that your *file* is never sent, one-click and bulk theft stop working entirely, replayed delivery URLs can be made useless, single-frame captures can be degraded, and anything that leaks is capped at the resolution/quality your server authorized and can carry visible, forensic, and blind-decoding attribution marks. Full reasoning: [docs/RESEARCH.md](docs/RESEARCH.md).

---

## Try to steal it (live demo)

```bash
npm install
npm run demo:images   # generates the 100-image demo gallery
npm run build
npm run demo          # http://localhost:4173
```

The demo compares a normal `<img>` with Archx Shield, Vault, and Fortress + Lens cards, and includes an **Attack Simulator**: buttons that execute real theft techniques (DOM scanning, `canvas.toDataURL()`, prototype bypass, network capture, payload reconstruction with a stolen client key, signed-URL replay, and print) in your browser and show you the loot. Nothing is mocked. In the reconstruction attack, the important result is that the server-baked watermark is still there.

For a copy-and-run visual comparison, see [`examples/archx-showcase.html`](examples/archx-showcase.html). It shows one image as Normal → Lite → Shield → Vault → Fortress and includes a **Custom Flags Builder** (direct `renderer`, memory, forensic, Lens, temporal, split-canvas, quality, extraction, and guard flags). Put that HTML beside your test JPG and the extracted repository folder, serve the parent folder over HTTP, and open it in a browser.

## Quick start

### 1 · Script tag (no build step)

```html
<script src="/path/to/archx.min.js"></script>
<script>
  Archx.load.image('#hero', 'https://cdn.example.com/photo.jpg', { mode: 'shield' });
</script>
<div id="hero" style="aspect-ratio: 16/10"></div>
```

### 2 · npm / bundler

```bash
npm install @archnemix/image-protection
```

```js
import Archx from '@archnemix/image-protection';

// Single image — URL, File, Blob, ArrayBuffer, or a server token { id }
Archx.load.image('#hero', urlOrFile, { mode: 'vault', watermark: '© Studio · {session}' });

// Gallery — lazy, capped concurrency, cached after first paint (no reload on scroll)
Archx.load.gallery('#grid', photos.map(p => ({ id: p.id })), { mode: 'lite' });

// Preset + direct overrides (every preset is just inspectable parameters)
Archx.load.image('#product', { id: 'watch-01' },
  { ...Archx.preset('commerce'), temporalShield: false, qualityProfile: 'original' });

// Migrate an existing page: replace marked <img> tags in place
Archx.protectAll('img[data-protect]');
```

### 3 · Declarative web component

```html
<archx-image image-id="aurora-valley" preset="screenshotResistant"
             quality-profile="original" lens temporal-shield watermark="© Studio"
             token-endpoint="/archx/token/" style="aspect-ratio:16/10"></archx-image>
```

### 4 · Strongest setup: signed + scrambled server delivery (recommended for anything valuable)

Keep masters **outside** your static/public folder and let the middleware be the only door:

```js
// server (Express-compatible; plain node:http works too)
import { createArchxMiddleware } from '@archnemix/image-protection/server';

app.use(createArchxMiddleware({
  secret: process.env.ARCHX_SECRET,     // long random string, env only
  imagesDir: './masters',               // NEVER serve this folder statically
  ttlSec: 120,                          // signed URLs die after 2 minutes
  grid: 8,                              // 8×8 tile scramble
  quality: 95,                          // high-fidelity WebP; or lossless:true for exact delivered pixels
  oneTimeTokens: true,                  // a captured signed URL cannot be replayed
  bindTokenTo: { userAgent: true },     // optionally also bind to IP
  allowedOrigins: ['https://example.com'],
  serverWatermark: '© Studio · viewer {viewer}',
  forensic: true,                       // seeded block mark, also pre-scramble
  forensicPerToken: true,
  // Blind ownership fingerprint: recoverable later from a suspect screenshot
  // with archx-detect / detectStegoFingerprint(), no original needed.
  steganography: { perToken: true, strength: 6 },
  onStegoIssue: async ({ id, viewerId, fingerprint }) =>
    db.fingerprints.save({ id, viewerId, fingerprint }),
  // Let the server — never the browser — set identity, resolution AND quality:
  authorize: async (req, id) => req.session?.user
    ? {
        viewerId: req.session.user.id,
        maxWidth: req.session.user.paid ? 1600 : 800,
        quality: req.session.user.paid ? 'lossless' : 90,
      }
    : false,
  // encrypt: true,                     // + AES-GCM on the wire
}));
```

```js
// browser — the page never contains a usable image URL
Archx.config({ tokenEndpoint: '/archx/token/' });
Archx.load.image('#hero', { id: 'aurora-valley' }, {
  mode: 'fortress', lens: true, qualityProfile: 'original',
  temporalShield: { strength: 0.16, block: 2 }, // set false if flicker is unacceptable
});
```

### 5 · No server code allowed? Pre-scramble assets with the CLI

```bash
npx archx-protect photo.jpg photo.archx --key "long-random-secret" --max-width 1400 \
  --watermark "© Studio" --forensic-seed "campaign-or-batch-id" \
  --stego "ORDER-1042-or-owner-batch" --lossless
npx archx-protect ./masters ./protected --key "long-random-secret" --encrypt
```

Host the `.archx` files on any static CDN — captured copies are scrambled mosaics (or ciphertext) without the key:

```js
Archx.load.image('#hero', '/protected/photo.archx', { key: 'long-random-secret' });
```

### 6 · Prove a leaked copy is yours (StegoMark detection)

```bash
# Static/CLI marks (detector key defaults to the protect --key):
npx archx-detect suspect-screenshot.png --key "long-random-secret" --expect "ORDER-1042"

# Token-server marks (derive the same detector key from your server secret):
npx archx-detect suspect.jpg --secret "$ARCHX_SECRET" --image-id aurora-valley
```

A confident result prints a 12-hex fingerprint. With the token server, persist that value from `onStegoIssue` next to the image/user/order, then look the detected fingerprint up. StegoMark is a redundant keyed 48-bit ID + CRC with soft error correction; in tests it survives WebP/JPEG re-encoding and substantial downscaling. It is attribution evidence, **not** an AI-proof lock: aggressive denoising/diffusion regeneration, severe crops, or a wrong detector key/grid can defeat it.

## How the protection works (defence in depth)

| Theft route | What Archx does | What the thief gets |
|---|---|---|
| Right-click → *Save image / Open in new tab* | No `<img>` exists; the picture is a `<canvas>` under a shield layer inside a **closed shadow root**; context menu is intercepted on the component only | No menu, no file |
| Drag to desktop / new tab, iOS long-press save | `dragstart` blocked, `-webkit-user-drag:none`, `-webkit-touch-callout:none`, long-press blackout | Nothing |
| DevTools → Elements | Closed shadow DOM; the source URL lives in JS closures/private fields, never in attributes | An empty-looking element |
| DevTools → Network → Img | Bytes arrive via `fetch()` + `createImageBitmap()` as `application/octet-stream` — never as an image load | An opaque `data.bin` |
| Copy / share / replay the image URL | HMAC-signed URLs are bound to one image id and a short expiry; server mode can add one-time nonces plus IP and/or User-Agent binding | `403 invalid or expired token` |
| Ask for a bigger file than allowed | The browser may request a width, but middleware `maxWidthCap` and per-request `authorize()` entitlements cap it server-side | Only the resolution that viewer was entitled to receive |
| Guess the master path | Masters live outside every static route; the signer endpoint is the only reader and never returns originals | `404` |
| Decode the captured payload | Pixels are cut into an 8×8 grid, shuffled & mirrored under a key (optional AES-GCM layer) inside an `.archx` container | A meaningless mosaic / ciphertext |
| Capture payload **and** steal the client session key, then reconstruct offline | Server watermarks and forensic block marks can be applied **before tile scrambling**, so a mathematically perfect reconstruction is still marked; it also remains limited to the server-authorized web resolution | A marked, traceable web-size copy — never the master |
| `canvas.toDataURL()` · `toBlob()` · `getImageData()` · `captureStream()` (download extensions) | Read-back APIs are **poisoned per canvas instance** and report the attempt; optional strike policies escalate repeated probes to blur/blackout lockouts | Your choice: ⬛ black “PROTECTED” card · 🥔 72-px pixelated copy · 🧩 re-scrambled mosaic |
| Reach into library objects/DOM for canvases, URLs, or keys | Instance state uses JavaScript `#private` fields; host/element lookup uses module-private `WeakMap`s (no `__archx`/`_inst` expando), there is no public instance registry, option/config views redact keys, and `_debug()` is inert unless that instance was explicitly created with `debug:true` | No supported handle to internal canvases, payloads, bitmaps, or secrets |
| Monkey-patch `fetch`, `createImageBitmap`, canvas, or WebGL APIs around the viewer | Sensitive native functions are captured at module load and used internally; `auditIntegrity()` reports replacements/non-native implementations. Fortress defaults to **fail closed** when hooks are detected; other modes can monitor or lock | The cheap userscript/extension hook is bypassed or causes a lock instead of silently recording clean pixels |
| Expert move: `HTMLCanvasElement.prototype.toDataURL.call(canvas)` | **Vault/Fortress** render in WebGL with `preserveDrawingBuffer:false` — the browser clears the buffer after compositing, so even the prototype call returns black. In other modes the backing store only ever contains the display-size, watermarked copy | Vault/Fortress: black. Elsewhere: screen-size marked copy at best |
| Bulk scrapers & AI crawlers | No URLs in HTML, JS + a fresh token required per image, separate token/image rate limits, optional origin allowlist and automation tripwires | An empty or very expensive harvest |
| Inspect decoded image memory after display | Fortress defaults to strict memory handling: decoded bitmaps are released promptly, CPU-side working canvases are wiped after GPU upload, plain client-only sources can be locally scrambled before upload, and strict mode bypasses the shared bitmap cache | Far less clean decoded material left hanging around (not a defense against a fully compromised browser/process) |
| Print → PDF | `@media print` blackout + `beforeprint` reaction | Black boxes |
| Windows/macOS/Linux built-in screenshot or snipping tool | **Cannot be blocked by a web page** — the OS compositor is outside the browser. Archx reacts to signals that do reach the page (PrintScreen, common snipping shortcuts, window blur, page freeze) with blur/blackout, and caps/marks the derivative | Sometimes a blurred/black frame; otherwise at best a traceable screen-resolution copy |
| Browser screenshot extension, DevTools “Capture screenshot”, or CDP/remote capture | These use browser privileges above page JavaScript; a website cannot reliably detect installed extensions or veto a privileged visible-tab capture. View-source/Elements still reveals no master or signed URL. Fortress assumes capture and adds Lens + a drifting session/time trace | A degraded, attributable capture of what was visible — never the original file/master |
| Photographing the monitor with a phone or second device | **Physically unstoppable and undetectable from the device displaying the page.** Mitigation is value destruction: entitled resolution, server-baked visible/forensic marks, dynamic capture trace, and Fortress Lens so no single frame contains the whole sharp image | A camera copy with perspective/moiré/screen loss, mostly Lens mush outside one disc, carrying session attribution |
| Single PrintScreen / extension frame under `temporalShield` | Two complementary per-block noise frames alternate at refresh rate; eyes integrate the pair toward the image, one captured frame retains the noise. Reduced-motion users are respected by default | One noisy half-frame. A screen recording, averaged captures, or long-exposure camera can reconstruct more — layer it with Lens/marks |
| AI denoise/upscale/regeneration of a degraded capture | No web layer can honestly promise AI-proof pixels. Archx limits the source information (entitled derivative, Lens/temporal capture), keeps visible attribution, and adds evidence/control layers around it | At best a plausible regenerated approximation and a marked/attributable trail — not the withheld master pixels |
| Reposted copy — “prove it's yours” | StegoMark embeds a blind, keyed, redundant 48-bit fingerprint + CRC in delivered pixels; `archx-detect` recovers it without the original and your `onStegoIssue` registry maps it to the issued view | Attribution evidence surviving ordinary re-encode/resize paths in tests |

### Modes

| Mode | Renderer / policy | Use it for | Cost per image |
|---|---|---|---|
| `lite` | 2D canvas, poisoned read-back, guards | Galleries of 100s, listings, feeds | 1 fetch + 1 decode + 1 draw |
| `shield` *(default)* | 2D canvas + tile-unscramble, client watermark/forensic marks, integrity/automation monitoring, risk reactions (`splitCanvases` option = one canvas per tile) | Most valuable single images | + 64 `drawImage` tile copies (no per-pixel JS in the image path) |
| `vault` | WebGL2 shader un-scrambles on the GPU; read-back returns black by platform design; forensic grain | Hero / premium / paid images. Browsers allow ~8–16 GL contexts — Archx budgets 8 and falls back to shield | 1 texture upload + a few presentation frames; static images then idle (`renderLoop:'auto'`) |
| `fortress` | Vault renderer plus fail-closed integrity policy, strike lockouts, strict memory wiping, local pre-GPU scrambling for plain sources, DevTools guard on, dynamic capture trace, temporal shield, and optional trusted-pointer Lens | The small number of images where even a clean screenshot/photo is a serious loss | Vault cost + policy checks; temporal shield deliberately animates. Reserve it for hero/paid content, not grids |
| `custom` | No preset bundle: choose `renderer:'canvas'|'webgl'` and each flag (`forensic`, `memory`, `lens`, `temporalShield`, `splitCanvases`, guards, quality, extraction, caching, policies) yourself. Omitting `mode` while passing `renderer` is also treated as custom | Sites that need a precise mix—e.g. Canvas for compatibility but strict memory and Lens, or WebGL without temporal flicker | Exactly the layers you enable; nothing extra is bundled by a mode name |

Inspectable bundles live in `Archx.presets` / `Archx.preset(name, overrides)`: `gallery`, `editorial`, `commerce`, and `screenshotResistant`. They are ordinary option objects — spread one and override any key.

## API

### `Archx.load.image(target, source, options?) → ProtectedImage`

- `target`: CSS selector or element (give it a size via CSS/`aspect-ratio`, or Archx derives it from the image)
- `source`: URL string · `File`/`Blob` · `ArrayBuffer` · `{ id }` for the token server · URL of an `.archx` asset
- returns an instance immediately; `instance.ready` resolves after first paint. `instance.reload(newSource?)` is the explicit forced-refresh/source-change path; ordinary visibility/resize repainting never calls it implicitly. `instance.destroy()` releases observers, canvases, textures, and cached payload state.

### Key options

| Option | Default | Notes |
|---|---|---|
| `mode` | `'shield'` | `'lite' \| 'shield' \| 'vault' \| 'fortress' \| 'custom'` ('fortress' is a stricter Vault preset; 'custom' applies no preset bundle; explicit options always win) |
| `renderer` | `'auto'` | `'auto' \| 'canvas' \| 'webgl'`. Direct pipeline selection for custom setups: use with `mode:'custom'`, or omit `mode` and pass `renderer` plus individual flags. `'webgl'` falls back to Canvas if WebGL/context budget is unavailable |
| `watermark` | `null` | string or `{text, opacity, tile, corner, color}` — baked into the same pixels; `{session}` expands to a per-visitor id |
| `onExtract` | `'black'` | decoy for canvas grabbers: `'black' \| 'lowres' \| 'scrambled'` |
| `tokenEndpoint` | `null` | e.g. `'/archx/token/'` (id is appended) |
| `key` / `aesKey` / `grid` / `scrambled` | — | for `.archx` / statically scrambled assets |
| `fit` | `'cover'` | `'cover' \| 'contain' \| 'fill'` (like CSS `object-fit`) |
| `lazy` | `true` | shared `IntersectionObserver`, 500 px pre-load margin |
| `unloadOnExit` | `false` (including gallery) | opt-in backing-store release for truly huge grids; repaint still prefers retained bitmap/texture/cached payload over the network |
| `maxBackingWidth` / `dprCap` | `1920` / `3` | canvas backing follows modern retina/mobile DPR without exceeding the hard backing cap; exact `devicePixelContentBoxSize` is used when the browser provides it |
| `qualityProfile` / `requestQuality` | `'high'` / profile-derived | `qualityProfile`: `'original' \| 'high' \| 'balanced' \| 'fast'`. It maps to lossless/q95/q90/q82 plus sampling defaults, each directly overridable. `requestQuality` (`1..100 \| 'lossless'`) is sent as `q=` and honoured only if the server sets `allowClientQuality` (your `authorize()` entitlement still wins) |
| `sourceOversample` / `maxSourceWidth` | `2` (gallery helper: `1.5`) / `2560` | token sources wait for a stable host box, request a 2× cover-aware derivative and supersample down for detail; the server entitlement is still the real signed cap. Lower this for bandwidth-first thumbnails, raise it for zoom/lightbox hosts |
| `cacheBitmap` / `cachePayload` | `true` / `true` | session-level no-reload controls. `cacheBitmap` shares decoded results for identical non-strict sources; `cachePayload` privately retains scrambled bytes so strict-memory repaint/context recovery can decode locally instead of reminting/fetching. Explicit `reload()` bypasses both |
| `reloadOnResize` / `resizeUpscaleFactor` | `'upscale'` / `1.75` | strict-memory resize policy: `'never'` keeps the painted canvas, `'upscale'` re-resolves only after a large size jump (locally from cached payload when enabled), `'always'` is the legacy eager behaviour. Normal modes repaint from the retained bitmap |
| `renderLoop` | `'auto'` | WebGL presentation policy: `'auto'` = static images draw on demand and only temporal shield animates; `'static'` forces on-demand; `'continuous'` forces a RAF loop while visible. Lens/risk/resize changes request fresh frames automatically |
| `temporalShield` | `null`; fortress enables `{strength:0.16, block:2}` | `true` or `{ strength, block, respectReducedMotion }`. Alternates complementary noisy frames so one OS/extension/DevTools screenshot is degraded. Can flicker/eye-strain and costs continuous rendering; recordings/averaged frames/long exposures can undo it. Set `false` to opt a Fortress image out |
| `splitCanvases` / `splitGrid` | `false` / `3` | paranoid mode: no single canvas holds the whole image |
| `shadow` | `'closed'` | `'closed' \| 'open' \| 'none'` |
| `forensic` | `true` (Lite defaults it off) | client-side per-session marks; an explicit `forensic:true` enables it even with Lite/custom Canvas. Pair with server `forensic` when reconstruction-resistance matters |
| `integrity` | `'monitor'`; fortress: `'lock'` | hooked-API policy: `'off' \| 'monitor' \| 'lock'`. `monitor` reports through `onAttempt`; `lock` refuses/blackouts rather than feeding a hooked pipeline |
| `automation` | `'monitor'` | headless/bot tripwire policy: `'off' \| 'monitor' \| 'lock'`. Signals are spoofable, so don't use this as your only bot defense |
| `memory` | `'standard'`; fortress: `'strict'` | strict mode bypasses shared bitmap caching, closes decoded bitmaps promptly, and wipes CPU-side clean working canvases after use/upload |
| `localScramble` | `false`; fortress: `true` | for plain client-only sources in Vault/Fortress, tile-scramble locally before GPU upload so the texture source is not a clean image |
| `lens` | `null` | `true` or `{ radius, idlePixelate }`: in 2D and WebGL, only a disc around trusted pointer input is sharp; the rest is pixelated. Intended as an anti-single-screenshot UX tradeoff |
| `captureShield` | `null`; fortress: `true` | `true` or `{ dynamicTrace, temporalPattern, temporalDither, text, opacity, updateMs }`: a low-opacity drifting session/time trace above the image for OS/extension/DevTools/camera captures. It attributes and complicates stitching; it cannot prevent privileged or physical capture. `temporalPattern` adds a shifting phase layer; `temporalDither` is accepted as an alias when `temporalShield` is not set |
| `strikes` | `null`; fortress enables | `{ blurAt, lockAt, lockMs }` — repeated extraction attempts escalate from reporting to blur, then timed blackout |
| `debug` | `false` | **Development/tests only.** Enables that one instance's `_debug()` handle. Never enable it in production |
| `guards` | see source | `{contextMenu, drag, copy, longPress, print, blurOnBlur, screenshotKeys, devtools}` — `devtools` (blur while DevTools looks open) is opt-in; it uses a size heuristic and can false-positive |
| `onAttempt(kind, instance)` | `null` | hook analytics/logging/banning. Kinds include `contextmenu`, `drag`, `copy`, `longpress`, `extract-*`, `screenshot-key`, `integrity:*`, `automation:*`, and `lens-scan`. Also fires as a bubbling `archx-attempt` DOM event |
| `alt` | `''` | sets `role="img"` + `aria-label` for screen readers |
| `onLoad` / `onError` / `onClick` | `null` | lifecycle + genuine click forwarding (lightboxes keep working) |

### Also

- `Archx.presets` / `Archx.preset(name, overrides?)` / exported `PRESETS` + `preset()` — frozen, inspectable direct-parameter bundles (`gallery`, `editorial`, `commerce`, `screenshotResistant`)
- `Archx.config({...})` — set global defaults (endpoint, session id, brand text…). Calling it with no useful update returns a sanitized view; configured `key`/`aesKey` values are shown only as `[redacted]`
- `Archx.instanceCount` — number of live instances, without exposing the instance registry itself
- `Archx.auditIntegrity()` / `auditIntegrity()` — names of sensitive browser APIs that currently differ from the native references captured when the module loaded
- `Archx.detectAutomation()` / `detectAutomation()` — current cheap headless/automation signals (a tripwire, not a bot-proof identity check)
- `instance.options` — sanitized per-instance option view with secrets redacted
- `Archx.load.gallery(container, items, options?)` — items: URLs or `{id, alt}` objects
- `Archx.protectAll(selector?, options?)` — upgrade existing `<img data-protect>` in place
- `<archx-image>` — attributes: `src`, `image-id`, `token-endpoint`, `mode`, `preset`, `quality-profile`, `watermark`, `fit`, `grid`, `key`, `scrambled`, `lens`, `capture-shield`, `temporal-shield`, `render-loop`, `reload-on-resize`, `on-extract`, `alt` *(prefer `image-id` + tokens: a `src` attribute is visible in page source by definition)*
- Server: `createArchxMiddleware({ secret, imagesDir | imagesDirs | images, basePath, ttlSec, grid, encrypt, scrambleKeyMode: 'per-image' | 'per-token', maxWidthCap, quality: 95, lossless, format: 'webp' | 'png' | 'jpeg', allowClientQuality, authorize, rateLimitPerMinute, tokenRateLimitPerMinute, oneTimeTokens, bindTokenTo: { ip, userAgent }, allowedOrigins, serverWatermark, forensic, forensicPerToken, steganography, onStegoIssue, outputCacheMax })`. Needs `sharp` (declared as an optional peer; the browser build doesn't). Token requests include the display box (`bw`, `bh`, `fit`, optional `q`); the server uses the source aspect to sign a cover-safe derivative width before applying entitlement caps, avoiding crop-then-upscale softening.
  - `authorize(req, id)` may return `true`/`false` or an entitlement object such as `{ viewerId, maxWidth, watermark, quality, lossless, format, steganography, stegoFingerprint }`. Viewer IDs are HMAC-hashed before being used in token/cache/forensic/stego derivation; width/quality/format decisions are made before signing, so a tampered browser cannot simply ask for more. `allowClientQuality:true` only lets the browser *request* `q=` when no entitlement quality overrides it.
  - `serverWatermark` may be a string, an SVG-watermark config object, or an async function receiving `{ req, id, nonce, viewerId, exp }`. `{id}`, `{nonce}`, and `{viewer}` placeholders are expanded. It is composited before forensic marking, tile scrambling, encoding, and optional encryption.
  - `forensic: true` uses the default 32 px / delta-2 block mark; or pass `{ blockSize, delta }`. With `forensicPerToken: true` the seed changes per signed delivery (more attribution, less output-cache reuse); set it `false` for static per-image/viewer marks when gallery throughput matters more.
  - `steganography: true` or `{ strength, gridX, gridY, perToken }` enables StegoMark. The fingerprint is HMAC-derived from image + viewer hash + (nonce or `static`), never returned to the browser; `onStegoIssue({ req, id, viewerId, nonce, exp, fingerprint })` is your registry hook. `deriveStegoFingerprint()` / `deriveStegoKey()` are exported for investigations, and `embedStegoFingerprint()` / `detectStegoFingerprint()` / `stegoFingerprint()` are exported from the scramble core for custom pipelines. Direct `scrambleImage()` callers can pass `stegoPayload`, `stegoKey`, and `stegoStrength`.
  - Marked `.archx` headers carry `wm: 1`, `fx: 1`, and/or `sg: 1` flags so your pipeline can verify what was embedded without exposing the seed/text/fingerprint derivation in the payload.

## Performance

Measured on this repo's test machine (`npm run bench`, `npm run test:browser`):

- Browser bundle: **58.9 KiB minified / 19.8 KiB gzipped**, zero dependencies
- 100-image protected gallery in headless Chromium: all 100 painted with 0 `<img>` tags; the current test run measured **2.6 s** in the non-lazy path (production lazy mode streams them on scroll, and the gallery helper defaults to 1.5× oversampling)
- Steady-state cost after first paint is deliberately near zero for stills: the browser test measured **0 additional Vault frames over 450 ms** with `renderLoop:'auto'`, while a temporal-shield Fortress intentionally presented 27 frames in the same window. The no-reload browser test also verifies one token + one payload request across strict-memory visibility/resize cycles
- Server pixel scramble measured up to **~149 MP/s**; full down-scale + scramble + q95 WebP took **~147 ms at 900 px** as a one-time cached cost per distinct output variant, with AES-GCM lost in run-to-run noise at that size
- Quality: on the detailed 800 px watch benchmark, q95 reconstruction measured **41.0 dB PSNR / 1.43 MAD** versus 36.6 dB / 2.56 MAD at the old q82. `lossless:true` is exact at the delivered size (800 px test payload ~360 kB lossless WebP vs ~128 kB q95), so use it selectively for hero/product detail.
- Per image in the standard browser path: 1 fetch + 1 `createImageBitmap` decode + 64 tile copies at native/oversampled resolution + one high-quality final resample. No general per-pixel JavaScript is required to un-scramble; client forensic/noise touches are deliberately sparse/block-oriented
- Security/performance trade-offs to know: per-token server watermarks/forensics/StegoMarks and `scrambleKeyMode: 'per-token'` intentionally defeat cross-viewer output-cache reuse; Fortress strict memory bypasses the shared bitmap cache, but with the default `cachePayload:true` it can decode its privately retained scrambled bytes locally instead of reminting. Temporal shield is the one deliberately continuous renderer. Use the strongest per-viewer settings on valuable items, not every thumbnail.
- Scrambled pixels compress worse than natural images (tile edges), so payloads run larger than an equivalent plain WebP. Lower `grid` (e.g. 6) if bytes matter more than shuffle strength.

## The honest limits

1. **The analog hole is real.** Anything visible can be screenshotted or photographed at screen resolution. Only DRM *video* pipelines (Widevine/EME + HDCP output protection) can black out screenshots, and browsers offer no equivalent for still images. Archx's answer: never ship more than display resolution, bake the watermark in, trace the session.
2. **A skilled reverse-engineer controls the receiving browser.** Someone who instruments below JavaScript, patches the browser, forges native-function fingerprints before Archx loads, captures composited frames/GPU memory, or simply photographs the display can obtain some form of the visible pixels. Captured native references and audits catch ordinary post-load hooking and naive pre-hooks; they cannot create a trusted execution environment inside an attacker-owned browser.
3. **Payload + session key reconstruction is deliberately made low-value, not mathematically impossible.** The open-source decoder must run for legitimate viewers, so a determined viewer can reassemble the one web-size derivative they were sent. One-time/browser-bound entitled tokens stop replay and oversized requests; server-baked marks mean the reconstructed derivative is still watermarked/traced. They never recover the master resolution, metadata, or pixels the server withheld.
4. **Lens + capture trace + temporal shield are friction, not screenshot-proofing.** They prevent a single ordinary screenshot/photo from containing the whole sharp, unmarked frame and make scripted sweeps harder/noisier, but a patient person can move a real pointer and stitch discs, record/average temporal frames, or use a camera. Likewise, page JavaScript cannot veto the OS compositor, a screenshot extension's privileged visible-tab capture, DevTools/CDP capture, or another device's camera; shortcut/blur reactions only help when the browser exposes a signal in time. Expect attribution and delay—not impossibility.
5. **AI regeneration and invisible-mark removal are real attacks.** Research on diffusion-based regeneration shows many pixel-level invisible watermarks can be weakened/removed while preserving the scene's semantics; an upscaler can also invent plausible detail from a degraded capture. StegoMark and forensic blocks are therefore evidence layers. Your durable controls are not shipping the master, server authorization/entitlement, visible marks where appropriate, issuance logs, monitoring, and enforcement.
6. **Client-only mode is only as strong as the URL you feed it.** If the same full-resolution file is also sitting at a guessable public URL, protect the door, not the window: move masters behind the token server (or at least only ever publish down-scaled derivatives). Local scrambling before GPU upload protects the texture path, not the public network file.
7. **SEO / sharing trade-off:** protected images have no indexable `<img src>` (that's the point). Keep SEO-critical thumbnails as normal images and protect the valuable full views; use `alt` for accessibility.

## Security checklist for production

- [ ] Masters in a folder that is **not** statically served (test the direct URL → 404)
- [ ] `ARCHX_SECRET` long & random, from the environment; HTTPS everywhere (tokens/keys ride along)
- [ ] Short `ttlSec` (60–180 s), `oneTimeTokens: true` where replay matters, and an `authorize` hook that returns a server-decided `viewerId` + `maxWidth` for account/paid content
- [ ] Use `allowedOrigins` and browser binding deliberately: User-Agent binding is the low-friction option; IP binding can break mobile/VPN/network-switching users
- [ ] Server-side watermark + forensic marking on for valuable derivatives; client `{session}` watermarks alone do not survive offline payload reconstruction
- [ ] If StegoMark is enabled, persist every `onStegoIssue` fingerprint with image/user/order context and test your `archx-detect` investigation path; an unregistered fingerprint is only a number
- [ ] `debug: false` everywhere in production, and no custom code that re-exposes instances/canvases on `window` or DOM elements
- [ ] `fortress`/`vault` reserved for the few images that matter most; `lite` for bulk grids. Enable Lens/temporal shield only where their UX/accessibility trade-offs are acceptable, and keep reduced-motion honoured
- [ ] Keep full-resolution masters offline/backed-up — the server only needs web-size sources if you pre-resize

## Tests

```bash
npm test            # 17 unit/integration tests (scramble/crypto, delivery quality,
                    # cover-aware sizing, server marks, StegoMark survival,
                    # entitled quality + token flow…)
npm run test:browser  # 60 checks in real headless Chromium (encapsulation, decoys,
                      # native detail retention, WebGL black read-back,
                      # Fortress Lens/temporal shield/capture trace/strikes/integrity,
                      # no-reload lifecycle, draw-on-demand GPU, token replay,
                      # guards, print, 100-image gallery…)
npm run test:all
```

## Repository layout

```
src/         browser library (archx.js) + shared scramble/crypto core (scramble.js)
dist/        built bundles (esm / cjs / minified browser-global)
server/      token+scramble middleware, image scrambler, archx-protect + archx-detect CLIs, demo server
demo/        interactive demo + attack simulator, automated-test harness
demo-masters/  demo originals — deliberately NOT web-accessible
docs/        RESEARCH.md — how image theft works, what the big platforms do, threat model
tests/       unit + real-browser test suites
tools/       build, demo-image generator, benchmarks
```

## License

MIT © Archnemix contributors
