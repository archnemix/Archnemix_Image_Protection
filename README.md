# 🛡 Archnemix Image Protection (`Archx`)

**Show your images. Don't give them away.**

Websites that display valuable images — portfolios, stock previews, product shots, paid content, exam papers, real-estate and art listings — face an unfair fight: a plain `<img>` tag hands every visitor the raw file (right-click → *Save*, drag-and-drop, DevTools, bulk-download extensions, AI scrapers). Most sites give up because doing anything better means stitching together ten half-techniques yourself.

**Archx is that work, done once, in one tiny library:**

```js
Archx.load.image('#hero', { id: 'aurora-valley' }, { mode: 'shield', watermark: '© My Studio' });
```

No `<img>` is ever created. There is no image URL in your HTML to copy, no file in the Network tab to save, and the picture itself is painted through a protected viewer that fights back at every step a thief normally takes. People who dig deeper get a **black card**, a **scrambled mosaic**, or a **heavily pixelated thumbnail** — your call. Your original file **never leaves the server**.

- 📦 **11.7 kB gzipped**, zero runtime dependencies (browser)
- ⚡ Built for **hundreds of images per page** (lazy loading, decode concurrency cap, bitmap LRU, display-size-only rendering) — 100-image gallery verified in tests
- 🧩 Three modes: **lite** (galleries), **shield** (default), **vault** (WebGL, for premium images)
- 🔐 Optional server: HMAC-signed expiring URLs + tile-scrambled / AES-GCM-encrypted delivery + enforced down-scaling

> **Honest up front:** no web technology can stop someone photographing their screen. What Archx guarantees is that your *file* is never sent, one-click and bulk theft stop working entirely, and anything that leaks is capped at screen resolution and carries your watermark + a per-session forensic trace. Full reasoning: [docs/RESEARCH.md](docs/RESEARCH.md).

---

## Try to steal it (live demo)

```bash
npm install
npm run demo:images   # generates the 100-image demo gallery
npm run build
npm run demo          # http://localhost:4173
```

The demo puts the same photo three ways — normal `<img>`, Archx Shield, Archx Vault — and includes an **Attack Simulator**: buttons that execute real theft techniques (DOM scanning, `canvas.toDataURL()`, prototype bypass, network capture, URL replay, print) in your browser and show you the loot. Nothing is mocked.

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

// Gallery — lazy, capped concurrency, off-screen unloading
Archx.load.gallery('#grid', photos.map(p => ({ id: p.id })), { mode: 'lite' });

// Migrate an existing page: replace marked <img> tags in place
Archx.protectAll('img[data-protect]');
```

### 3 · Declarative web component

```html
<archx-image image-id="aurora-valley" mode="shield" watermark="© Studio"
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
  // encrypt: true,                     // + AES-GCM on the wire
  // authorize: async (req, id) => !!req.session?.user,  // your auth hook
}));
```

```js
// browser — the page never contains a usable image URL
Archx.config({ tokenEndpoint: '/archx/token/' });
Archx.load.image('#hero', { id: 'aurora-valley' }, { mode: 'shield' });
```

### 5 · No server code allowed? Pre-scramble assets with the CLI

```bash
npx archx-protect photo.jpg photo.archx --key "long-random-secret" --max-width 1400
npx archx-protect ./masters ./protected --key "long-random-secret" --encrypt
```

Host the `.archx` files on any static CDN — captured copies are scrambled mosaics (or ciphertext) without the key:

```js
Archx.load.image('#hero', '/protected/photo.archx', { key: 'long-random-secret' });
```

## How the protection works (defence in depth)

| Theft route | What Archx does | What the thief gets |
|---|---|---|
| Right-click → *Save image / Open in new tab* | No `<img>` exists; the picture is a `<canvas>` under a shield layer inside a **closed shadow root**; context menu is intercepted on the component only | No menu, no file |
| Drag to desktop / new tab, iOS long-press save | `dragstart` blocked, `-webkit-user-drag:none`, `-webkit-touch-callout:none`, long-press blackout | Nothing |
| DevTools → Elements | Closed shadow DOM; the source URL lives in JS closures/private fields, never in attributes | An empty-looking element |
| DevTools → Network → Img | Bytes arrive via `fetch()` + `createImageBitmap()` as `application/octet-stream` — never as an image load | An opaque `data.bin` |
| Copy / share / replay the image URL | HMAC-signed URLs bound to one image id, expiring in ~120 s (server mode) | `403 invalid or expired token` |
| Guess the master path | Masters live outside every static route; the signer endpoint is the only reader and never returns originals | `404` |
| Decode the captured payload | Pixels are cut into an 8×8 grid, shuffled & mirrored under a secret key (optional AES-GCM layer) inside an `.archx` container | A meaningless mosaic / ciphertext |
| `canvas.toDataURL()` · `toBlob()` · `getImageData()` · `captureStream()` (download extensions) | Read-back APIs are **poisoned per canvas instance** and report the attempt | Your choice: ⬛ black “PROTECTED” card · 🥔 72-px pixelated copy · 🧩 re-scrambled mosaic |
| Expert move: `HTMLCanvasElement.prototype.toDataURL.call(canvas)` | **Vault mode** renders in WebGL with `preserveDrawingBuffer:false` — the browser clears the buffer after compositing, so even the prototype call returns black. In other modes the backing store only ever contains the display-size, watermarked copy | Vault: black. Elsewhere: screen-size watermarked copy at best |
| Bulk scrapers & AI crawlers | No URLs in HTML, JS + a fresh token required per image, rate-limited signer, LRU-capped work | An empty harvest |
| Print → PDF | `@media print` blackout + `beforeprint` reaction | Black boxes |
| Screenshot / snipping tools | Cannot be fully prevented on the open web (see below). Deterred & traced: display-res cap, watermark **baked into the same pixels**, per-session forensic grain, blur-while-window-unfocused, PrintScreen reaction | A traceable screen-resolution copy |

### Modes

| Mode | Renderer | Use it for | Cost per image |
|---|---|---|---|
| `lite` | 2D canvas, poisoned read-back, guards | Galleries of 100s, listings, feeds | 1 fetch + 1 decode + 1 draw |
| `shield` *(default)* | 2D canvas + tile-unscramble, baked watermark, forensic grain, risk reactions (`splitCanvases` option = one canvas per tile) | Most valuable single images | + 64 `drawImage` tile copies (no per-pixel JS) |
| `vault` | WebGL2 shader un-scrambles on the GPU; read-back returns black by platform design; animated grain | Hero / premium / paid images. Browsers allow ~8–16 GL contexts — Archx budgets 8 and falls back to shield | 1 texture upload + per-frame draw while visible |

## API

### `Archx.load.image(target, source, options?) → ProtectedImage`

- `target`: CSS selector or element (give it a size via CSS/`aspect-ratio`, or Archx derives it from the image)
- `source`: URL string · `File`/`Blob` · `ArrayBuffer` · `{ id }` for the token server · URL of an `.archx` asset
- returns an instance immediately; `instance.ready` resolves after first paint. `instance.reload(newSource?)`, `instance.destroy()`.

### Key options

| Option | Default | Notes |
|---|---|---|
| `mode` | `'shield'` | `'lite' \| 'shield' \| 'vault'` |
| `watermark` | `null` | string or `{text, opacity, tile, corner, color}` — baked into the same pixels; `{session}` expands to a per-visitor id |
| `onExtract` | `'black'` | decoy for canvas grabbers: `'black' \| 'lowres' \| 'scrambled'` |
| `tokenEndpoint` | `null` | e.g. `'/archx/token/'` (id is appended) |
| `key` / `aesKey` / `grid` / `scrambled` | — | for `.archx` / statically scrambled assets |
| `fit` | `'cover'` | `'cover' \| 'contain' \| 'fill'` (like CSS `object-fit`) |
| `lazy` | `true` | shared `IntersectionObserver`, 500 px pre-load margin |
| `unloadOnExit` | gallery: `true` | frees backing stores of far off-screen items |
| `maxBackingWidth` / `dprCap` | `1920` / `2` | hard caps — a stolen canvas can never exceed display size |
| `splitCanvases` / `splitGrid` | `false` / `3` | paranoid mode: no single canvas holds the whole image |
| `shadow` | `'closed'` | `'closed' \| 'open' \| 'none'` |
| `forensic` | `true` (shield/vault) | sub-visible per-session pixel grain |
| `guards` | see source | `{contextMenu, drag, copy, longPress, print, blurOnBlur, screenshotKeys, devtools}` — `devtools` (blur while DevTools looks open) is opt-in; it uses a size heuristic and can false-positive |
| `onAttempt(kind, instance)` | `null` | hook analytics/logging/banning. Kinds: `contextmenu`, `drag`, `copy`, `longpress`, `extract-dataurl`, `extract-blob`, `extract-pixels`, `extract-stream`, `screenshot-key`, … Also fires as a bubbling `archx-attempt` DOM event |
| `alt` | `''` | sets `role="img"` + `aria-label` for screen readers |
| `onLoad` / `onError` / `onClick` | `null` | lifecycle + genuine click forwarding (lightboxes keep working) |

### Also

- `Archx.config({...})` — set global defaults (endpoint, session id, brand text…)
- `Archx.load.gallery(container, items, options?)` — items: URLs or `{id, alt}` objects
- `Archx.protectAll(selector?, options?)` — upgrade existing `<img data-protect>` in place
- `<archx-image>` — attributes: `src`, `image-id`, `token-endpoint`, `mode`, `watermark`, `fit`, `grid`, `key`, `scrambled`, `on-extract`, `alt` *(prefer `image-id` + tokens: a `src` attribute is visible in page source by definition)*
- Server: `createArchxMiddleware({ secret, imagesDir | imagesDirs | images, basePath, ttlSec, grid, encrypt, scrambleKeyMode: 'per-image' | 'per-token', maxWidthCap, quality, authorize, rateLimitPerMinute, outputCacheMax })`. Needs `sharp` (declared as an optional peer; the browser build doesn't).

## Performance

Measured on this repo's test machine (`npm run bench`, `npm run test:browser`):

- Browser bundle: **31.1 kB minified / 11.7 kB gzipped**, zero dependencies
- 100-image protected gallery in headless Chromium: **all 100 painted in ~1.5 s**, 0 `<img>` tags (lazy mode streams them on scroll in production)
- Server pixel scramble: **~135 MP/s** pure JS; full pipeline (down-scale + scramble + WebP) ≈ **100 ms for a 900 px image, once** — afterwards served from an in-memory cache; AES-GCM adds ≈ 4 ms (hardware-accelerated WebCrypto)
- Per image in the browser: 1 fetch + 1 `createImageBitmap` decode + 64 GPU-friendly `drawImage` calls. No per-pixel JavaScript anywhere in the hot path.
- Trade-off to know: scrambled pixels compress worse than natural images (tile edges), so payloads run larger than an equivalent plain WebP. Lower `grid` (e.g. 6) if bytes matter more than shuffle strength.

## The honest limits

1. **The analog hole is real.** Anything visible can be screenshotted or photographed at screen resolution. Only DRM *video* pipelines (Widevine/EME + HDCP output protection) can black out screenshots, and browsers offer no equivalent for still images. Archx's answer: never ship more than display resolution, bake the watermark in, trace the session.
2. **A skilled reverse-engineer** who reads this open-source code, captures a payload *and* its session keys from their own browser, can reassemble that one display-size, watermarked copy. Archx raises theft from “right-click / bulk-download everything” to “hours of work per image for a degraded copy” — which is the realistic goal every museum/stock platform (Google Arts & Culture tiles its images the same philosophical way) settles for. See [docs/RESEARCH.md](docs/RESEARCH.md).
3. **Client-only mode is only as strong as the URL you feed it.** If the same full-resolution file is also sitting at a guessable public URL, protect the door, not the window: move masters behind the token server (or at least only ever publish down-scaled derivatives).
4. **SEO / sharing trade-off:** protected images have no indexable `<img src>` (that's the point). Keep SEO-critical thumbnails as normal images and protect the valuable full views; use `alt` for accessibility.

## Security checklist for production

- [ ] Masters in a folder that is **not** statically served (test the direct URL → 404)
- [ ] `ARCHX_SECRET` long & random, from the environment; HTTPS everywhere (tokens/keys ride along)
- [ ] Short `ttlSec` (60–180 s) and an `authorize` hook if images are account-bound
- [ ] Watermark on for hero images, `{session}` included for paid content
- [ ] `vault` reserved for the few images that matter most; `lite` for bulk grids
- [ ] Keep full-resolution masters offline/backed-up — the server only needs web-size sources if you pre-resize

## Tests

```bash
npm test            # 10 unit/integration tests (scramble round-trips, crypto, tokens, HTTP flow)
npm run test:browser  # 33 checks in real headless Chromium (DOM hygiene, decoys,
                      # WebGL black read-back, guards, print, 100-image gallery…)
npm run test:all
```

## Repository layout

```
src/         browser library (archx.js) + shared scramble/crypto core (scramble.js)
dist/        built bundles (esm / cjs / minified browser-global)
server/      token+scramble middleware, image scrambler, archx-protect CLI, demo server
demo/        interactive demo + attack simulator, automated-test harness
demo-masters/  demo originals — deliberately NOT web-accessible
docs/        RESEARCH.md — how image theft works, what the big platforms do, threat model
tests/       unit + real-browser test suites
tools/       build, demo-image generator, benchmarks
```

## License

MIT © Archnemix contributors
