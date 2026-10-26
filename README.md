# 🛡 Archnemix Image Protection (`Archx`)

**Show your images. Don't give them away.**

Websites that display valuable images — portfolios, stock previews, product shots, paid content, exam papers, real-estate and art listings — face an unfair fight: a plain `<img>` tag hands every visitor the raw file (right-click → *Save*, drag-and-drop, DevTools, bulk-download extensions, AI scrapers). Most sites give up because doing anything better means stitching together ten half-techniques yourself.

**Archx is that work, done once, in one tiny library:**

```js
Archx.load.image('#hero', { id: 'aurora-valley' }, { mode: 'shield', watermark: '© My Studio' });
```

No `<img>` is ever created. There is no image URL in your HTML to copy, no file in the Network tab to save, and the picture itself is painted through a sealed, protected viewer that fights back at every step a thief normally takes. People who dig deeper get a **black card**, a **scrambled mosaic**, or a **heavily pixelated thumbnail** — your call. Your original file **never leaves the server**.

- 📦 **94.3 KiB minified / 30.9 KiB gzipped**, zero runtime dependencies (browser)
- ⚡ Built for **hundreds of images per page** (lazy loading, decode concurrency cap, bitmap/payload caching, display-size-aware rendering) — 100-image gallery verified in tests. **Loaded images do not reload** on scroll/visibility/ordinary resize, and static WebGL images draw on demand instead of running a 60 fps GPU loop
- 🖼️ **Quality-first rendering:** quality profiles (`original` = pixel-exact lossless at display size, `high` = q95, `balanced`, `fast`), stable-layout + cover-aware derivative sizing, exact device-pixel canvas sizing where available, DPR up to 3, native/oversampled tile reassembly, and exact/supersampled WebGL sampling — protection should not make fine detail look slurry
- 🧩 Four preset modes — **lite** (galleries), **shield** (default), **vault** (WebGL), and **fortress** (Vault + anti-hook lock, strike lockouts, strict memory wiping, dynamic capture trace, temporal anti-single-frame shield, and optional pointer lens) — plus `mode:'custom'` / a direct `renderer` flag and **direct parameters for every behaviour**, so you are never locked into a preset
- 🌓 Optional **temporal interlace**: assign pixel/checker/strip/block subsets to 2–4 phases so one presented frame is deliberately incomplete. Four 60 Hz-first profiles, GPU-shader or pre-rendered-frame engines, refresh-rate phase optimization, and reduced-motion respect. It is explicit opt-in because two-phase viewing on a 60 Hz monitor still flickers at 30 Hz per subset
- 🔐 Optional server: **deny-by-default authorization at both token issuance and redemption**, POST-minted HMAC v2 tokens with versioned signing-key IDs, header-carried payload tokens by default, atomic one-time claims through a local or shared state store, optional DPoP-style sender-constrained redemption with a non-extractable page key, optional IP/User-Agent/session binding, entitlement-capped resolution **and quality/format**, bounded rate/quota/abuse/processing controls, tile-scrambled / AES-GCM-obfuscated delivery, and visible/forensic/**blind steganographic StegoMark** fingerprints baked in **before** scrambling
- 🧬 Attribution fallback: an optional 64-bit perceptual **soft-binding fingerprint** can be registered at ingest and compared with a suspect copy after metadata or a pixel mark has been stripped (evidence, not access control or cryptographic proof)
- 🕵️ Hardened internals: private fields, no public instance registry or host expando, secret-redacted option views, captured native APIs, and hooked-API / automation policies

> **Honest up front:** no web technology can stop someone photographing their screen, pressing PrintScreen before page JS can react, or fully controlling their own browser — and no pixel watermark is immune to a determined AI-regeneration attack. What Archx is designed to ensure in the recommended server setup is that the **master file is never sent**, one-click theft stops working, bulk collection becomes slow/visible/rate-limited, replayed delivery URLs can be made useless, single-frame captures can be degraded, and anything that leaks is capped at the resolution/quality your server authorized and can carry visible, forensic, and blind-decoding attribution marks. Browser-delivered scrambling/encryption keys are obfuscation and transport friction—not DRM—because an authorized recipient controls the receiving browser. Full reasoning: [docs/RESEARCH.md](docs/RESEARCH.md).

> **Reviewing the code?** Start with [docs/REVIEW_GUIDE.md](docs/REVIEW_GUIDE.md) for a fresh-clone verification path, repository map, suggested review order, and the security properties that matter most. Production operators should also read [docs/OPERATIONS.md](docs/OPERATIONS.md); assurance reviewers can use [docs/COMPLIANCE.md](docs/COMPLIANCE.md) and [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md). Release changes are summarized in [CHANGELOG.md](CHANGELOG.md).

---

## Try to steal it (live demo)

```bash
npm ci
npm run demo:images   # generates the 100-image demo gallery
npm run build
npm run demo          # http://localhost:4173
```

The demo compares a normal `<img>` with Archx Shield, Vault, and Fortress + Lens cards, and includes an **Attack Simulator**: buttons that execute real theft techniques (DOM scanning, `canvas.toDataURL()`, prototype bypass, network capture, payload reconstruction with a stolen client key, signed-URL replay, and print) in your browser and show you the loot. Nothing is mocked. In the reconstruction attack, the important result is that the server-baked watermark is still there.

For a copy-and-run visual comparison, see [`examples/archx-showcase.html`](examples/archx-showcase.html). It shows one image as Normal → Lite → Shield → Vault → Fortress and includes a **Custom Flags Builder** (direct `renderer`, memory, forensic, Lens, temporal/camera-pattern, 60 Hz temporal-interlace profile/engine/layout/phase/fill controls, opponent-colour, split-canvas, quality, extraction, token/cache, and guard flags). Put that HTML beside your test JPG and the extracted repository folder, serve the parent folder over HTTP, and open it in a browser.

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
             quality-profile="original" lens camera-shield watermark="© Studio"
             token-endpoint="/archx/token/" token-method="POST" cache-scope="account-42" style="aspect-ratio:16/10"></archx-image>
```

### 4 · Strongest setup: signed + scrambled server delivery (recommended for anything valuable)

Keep masters **outside** your static/public folder and let the middleware be the only door:

```js
// server (Express-compatible; plain node:http works too)
import { createArchxMiddleware } from '@archnemix/image-protection/server';

app.use(createArchxMiddleware({
  secret: process.env.ARCHX_SECRET,     // required, random, at least 32 bytes
  imagesDir: './masters',               // NEVER serve this folder statically
  publicDirs: ['./public'],             // startup rejects overlap with masters
  ttlSec: 120,                          // signed URLs die after 2 minutes
  grid: 8,                              // 8×8 tile scramble
  quality: 95,                          // high-fidelity WebP; or lossless:true for exact delivered pixels
  tokenMethods: ['POST'],               // secure default; the client POSTs with X-Archx-Request
  requireTokenRequestHeader: true,      // default; rejects simple cross-site mint attempts
  allowQueryTokens: false,              // strongest: payload token only in X-Archx-Token, never a URL
  proofOfPossession: 'required',        // copied tokens need the page's non-extractable P-256 key too
  callbackTimeoutMs: 10000,             // hung authorize/watermark/registry callbacks fail closed
  oneTimeTokens: true,                  // a captured signed URL/token cannot be replayed
  bindTokenTo: { userAgent: true, session: true }, // friction only; authorize() is the boundary
  allowedOrigins: ['https://example.com'], // exact origins; '*' is rejected
  quotas: { perViewer: 500, perViewerImage: 20, perIp: 2000, windowMs: 3600000 },
  abuseDetection: { distinctImages: 250, windowMs: 600000, action: 'event' },
  processing: {
    maxInputBytes: 50 * 1024 * 1024,
    maxInputPixels: 40000000,
    maxInputWidth: 12000,
    maxInputHeight: 12000,
    maxOutputPixels: 16777216,
    processingTimeoutSec: 10,
    allowedInputFormats: ['jpeg', 'png', 'webp', 'avif'],
    blockUntrustedSharpLoaders: true,   // default; process-global libvips loader allowlist
  },
  processingConcurrency: 2,             // bounded Sharp work + bounded queue
  serverWatermark: '© Studio · viewer {viewer}',
  forensic: true,                       // seeded block mark, also pre-scramble
  forensicPerToken: true,
  // Blind ownership fingerprint: recoverable later from a suspect screenshot
  // with archx-detect / detectStegoFingerprint(), no original needed.
  steganography: { perToken: true, strength: 6 },
  stegoRegistryFailure: 'deny',         // do not issue an unregistered marked view
  onStegoIssue: async ({ id, viewerId, fingerprint }) =>
    db.fingerprints.save({ id, viewerId, fingerprint }),
  onSecurityEvent: async (event) => securityLog.write(event), // sanitized; no tokens/keys/headers
  // Required unless allowAnonymous:true is an intentional public-catalog choice.
  // It runs at phase:'token' AND again at phase:'image', so logout/revocation
  // or a lower current entitlement wins inside the old token's TTL.
  authorize: async (req, id, { phase, token }) => {
    const user = req.session?.user;
    if (!user || !await db.canView(user.id, id)) return false;
    return {
      viewerId: user.id,
      permissions: ['image:view'],
      maxWidth: user.paid ? 1600 : 800,
      quality: user.paid ? 'lossless' : 90,
    };
  },
  // encrypt: true,                     // + AES-GCM transport/obfuscation (not DRM)
}));
```

> **Fail-closed startup:** v1.5 throws during `createArchxMiddleware()` if the secret is missing/short/known-demo, no supported masters are indexed, origins/processing values are invalid, masters overlap declared `publicDir`/`publicDirs`, both `authorize` and explicit `allowAnonymous:true` are absent, or an unknown/misspelled top-level or nested security option is present. There is no weak-secret test bypass. Use `auditArchxServerConfig(options)` for a non-throwing, secret-free preflight report. Server-side Sharp work requires **Node ≥20.9.0** and **Sharp ^0.35.5**.

#### Upgrading older server code to the v1.5 defaults

1. Add `authorize(req, id, { phase, token })`; reserve `allowAnonymous:true` for catalogs that are deliberately public. Authorization results are normalized fail-closed: return `true`, `false`, or an explicit object such as `{ viewerId, permissions:['image:view'], maxWidth }`; ambiguous values (`{allowed:false}`, `{allow:0}`, string scopes in an array field, string widths/qualities, invalid watermarks/Stego settings) deny.
2. Rotate any short/demo secret to at least 32 random bytes and remove retired bypass/test surfaces: `allowWeakSecretForTests`, public `signToken`/`verifyToken` exports, `handler._test`, and `handler.index` are gone (use `handler.stats().images`). Claims remain strict v2, including an optional-claim allowlist and bounded watermark/binding/Stego fields.
3. Update custom token clients to `POST` with `X-Archx-Request: token` (required by default) and redeem the separate `token` in `X-Archx-Token` against `cleanUrl`. The legacy query-token `url` remains enabled for compatibility; set `allowQueryTokens:false` when all clients support header transport. The bundled browser client defaults to `proofOfPossession:'auto'`: it presents an ephemeral public P-256 key at mint and a short-lived proof at redemption, and the server's default `'optional'` policy binds the signed token to that key when one is presented. Use server `proofOfPossession:'required'` plus client `proofOfPossession:'required'` for the strongest token-theft posture; a custom client must implement the same narrow proof protocol or the server policy must remain `'optional'`. Only as a temporary legacy bridge, set server `tokenMethods:['GET','POST']` and client `tokenMethod:'GET'`.
4. Use image IDs matching `^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`; paths, dots/extensions, traversal, unknown IDs, malformed percent-encoding, simultaneous query+header tokens, and oversized URLs/bodies fail with generic controlled responses.
5. Remove `allowedOrigins:['*']`; exact origins only. When Fetch Metadata is present, only `same-origin` (or an exact allowlisted origin) may mint by default. Client IP comes from the socket unless `trustProxy:true` **and** an exact `trustedProxyHops` count are configured; X-Forwarded-For is then selected from the right. Origin/Referer/User-Agent/IP are supplemental signals, never substitutes for your session/entitlement check.

```js
// browser — the page never contains a usable image URL
Archx.config({
  tokenEndpoint: '/archx/token/',
  tokenMethod: 'POST',       // default; use GET only for a legacy bridge
  tokenTransport: 'header',  // default; keep bearer tokens out of payload URLs
  proofOfPossession: 'required', // pair with the server policy above; 'auto' is the compatible default
  cacheScope: currentUserId, // call Archx.clearCaches() on logout/account switch
});
Archx.load.image('#hero', { id: 'aurora-valley' }, {
  mode: 'fortress', lens: true, qualityProfile: 'original',
  cameraShield: { pattern: 'checker', chroma: true, strength: 0.18, block: 2 },
});
```

#### Horizontal scaling and signing-key rotation

The default state store is process-local memory. That is correct for one
Node.js process, but **not** for several processes behind a load balancer:
one-time nonce/proof claims, rate windows, quotas, and distinct-image abuse
tracking would otherwise reset per instance. Declare the deployment and
supply one shared, atomic adapter:

```js
createArchxMiddleware({
  deploymentMode: 'multi-instance', // startup rejects a missing/memory store
  stateStore: myRedisArchxStore,    // claimOnce + hitWindow + trackDistinct
  stateStoreTimeoutMs: 250,         // security-state failures return 503
  secrets: {
    '2026-01': process.env.ARCHX_SECRET_2026_01,
    '2026-02': process.env.ARCHX_SECRET_2026_02,
  },
  activeSecretId: '2026-02',        // new tokens carry kid:'2026-02'
  // imagesDir, authorize, quotas, ...
});
```

Tokens issued under `2026-01` continue to verify—and derive their scramble,
AES, viewer-binding, forensic, and StegoMark material—with the issuing key
until that key is retired after the rollover window. The store contract,
Redis/Dynamo atomicity notes, CloudFront/Cloudflare reference settings,
structured-event schema, failover rules, and load-test procedure are in
[`docs/OPERATIONS.md`](docs/OPERATIONS.md). Archx deliberately does not fall
back to local replay/quota state when a shared store times out or errors.

### 5 · No server code allowed? Pre-scramble assets with the CLI

```bash
# Keep secrets in the environment, not argv/shell history/process listings.
export ARCHX_SCRAMBLE_KEY='<long random secret>'
export ARCHX_FORENSIC_SEED='campaign-or-batch-id'
npx archx-protect photo.jpg photo.archx --max-width 1400 \
  --watermark "© Studio" \
  --stego "ORDER-1042-or-owner-batch" --lossless \
  --max-input-bytes 52428800 --max-input-pixels 40000000 --timeout-sec 10
npx archx-protect ./masters ./protected --encrypt
```

Host the `.archx` files on any static CDN — captured copies are scrambled mosaics (or ciphertext) without the key:

```js
// The browser must receive this key to display the asset, so treat it as
// obfuscation/transport friction—not as a server secret or DRM key.
Archx.load.image('#hero', '/protected/photo.archx', { key: window.__ARCHX_STATIC_KEY__ });
```

### 6 · Prove a leaked copy is yours (StegoMark detection)

```bash
# Static/CLI marks. ARCHX_STEGO_KEY should be the embed-time key (for the
# example above, the value of ARCHX_SCRAMBLE_KEY unless you set one separately).
# Geometry search is on by default; add --no-geometry for a faster uncropped-only pass:
ARCHX_STEGO_KEY="$ARCHX_SCRAMBLE_KEY" \
  npx archx-detect suspect-screenshot.png --expect "ORDER-1042"

# Token-server marks (derive the same detector key from your server secret):
ARCHX_SECRET="$ARCHX_SECRET" npx archx-detect suspect.jpg --image-id aurora-valley

# `archx-protect` also prints a non-secret perceptual soft binding. Register
# that 16-hex value at ingest, then compare a suspect even if StegoMark is gone:
npx archx-detect suspect.jpg --expect-fingerprint 0123456789abcdef --max-distance 10 --json
```

A confident result prints a 12-hex fingerprint and the recovered crop geometry. With the token server, persist that value from `onStegoIssue` next to the image/user/order, then look the detected fingerprint up. StegoMark is a redundant keyed 48-bit ID + CRC with soft error correction. In the current three-photo, 800 px matrix it survived ordinary resize/JPEG, mild blur, photometric changes, 90% center crops (3/3), 15% left-edge removal (3/3), 10% bottom removal (3/3), and 80% center crops (2/3); it failed a 2° rotation (0/3). It is attribution evidence, **not** an AI-proof lock or a promise for perspective phone photos: aggressive denoising/diffusion regeneration, severe/asymmetric geometry, or a wrong detector key/grid can defeat it. For a phone photo, first crop tightly to the displayed rectangle and correct perspective/rotation manually, then run the detector.

The perceptual soft binding is a separate 64-bit DCT fingerprint of image structure. It is useful as a C2PA-style lookup key when metadata and pixel marks are separated from a copy, and the unit suite verifies a resized/JPEG copy within the default distance threshold. It can collide or drift under crops, compositing, heavy edits, adversarial perturbation, or semantic regeneration; corroborate a match with issuance records and the original before making an ownership claim.

## How the protection works (defence in depth)

| Theft route | What Archx does | What the thief gets |
|---|---|---|
| Right-click → *Save image / Open in new tab* | No `<img>` exists; the picture is a `<canvas>` under a shield layer inside a **closed shadow root**; context menu is intercepted on the component only | No menu, no file |
| Drag to desktop / new tab, iOS long-press save | `dragstart` blocked, `-webkit-user-drag:none`, `-webkit-touch-callout:none`, long-press blackout | Nothing |
| DevTools → Elements | Closed shadow DOM; the source URL lives in JS closures/private fields, never in attributes. This blocks ordinary page JS, but browser/CDP tooling can pierce closed roots, so it is not a security boundary against the browser operator | An empty-looking element to page scripts; a CDP owner can still inspect/capture the authorized derivative |
| DevTools → Network → Img | Bytes arrive via `fetch()` + `createImageBitmap()` as `application/octet-stream` — never as an image load | An opaque `data.bin` |
| Copy / share / replay the image URL or token | Strict v2 HMAC claims bind audience/scope/image/width/quality/issued-at/expiry and, when presented, an RFC 7638 P-256 key thumbprint. Redemption verifies a short-lived proof of possession, re-runs `authorize()`, checks viewer/session + optional IP/User-Agent bindings, then—after all asynchronous checks—atomically claims the proof ID and one-time nonce through the configured local/shared state store | `403 invalid or expired token`; a token copied to another browser also lacks the non-extractable private key |
| Ask for a bigger file than allowed | The browser may request a width, but middleware `maxWidthCap` and per-request `authorize()` entitlements cap it server-side | Only the resolution that viewer was entitled to receive |
| Guess the master path | Masters live outside every static route; IDs are allowlisted, files/symlinks are realpath-contained and revalidated at redemption, configured master/public overlaps fail startup, and the middleware never returns originals | `404` |
| Decode the captured payload | Pixels are cut into an 8×8 grid, shuffled & mirrored under a key (optional AES-GCM transport/obfuscation layer) inside an `.archx` container | A meaningless mosaic / ciphertext |
| Capture payload **and** steal the client session key, then reconstruct offline | Server watermarks and forensic block marks can be applied **before tile scrambling**, so a mathematically perfect reconstruction is still marked; it also remains limited to the server-authorized web resolution | A marked, traceable web-size copy — never the master |
| `canvas.toDataURL()` · `toBlob()` · `getImageData()` · `captureStream()` (download extensions) | Read-back APIs are **poisoned per canvas instance** and report the attempt; optional strike policies escalate repeated probes to blur/blackout lockouts | Your choice: ⬛ black “PROTECTED” card · 🥔 72-px pixelated copy · 🧩 re-scrambled mosaic |
| Reach into library objects/DOM for canvases, URLs, or keys | Instance state uses JavaScript `#private` fields; host/element lookup uses module-private `WeakMap`s (no `__archx`/`_inst` expando), there is no public instance registry, option/config views redact keys, and `_debug()` is inert unless that instance was explicitly created with `debug:true` | No supported handle to internal canvases, payloads, bitmaps, or secrets |
| Monkey-patch `fetch`, `createImageBitmap`, canvas, or WebGL APIs around the viewer | Sensitive native functions are captured at module load and used internally; `auditIntegrity()` reports replacements/non-native implementations. Fortress defaults to **fail closed** when hooks are detected; other modes can monitor or lock | The cheap userscript/extension hook is bypassed or causes a lock instead of silently recording clean pixels |
| Expert move: `HTMLCanvasElement.prototype.toDataURL.call(canvas)` | **Vault/Fortress** render in WebGL with `preserveDrawingBuffer:false` — the browser clears the buffer after compositing, so even the prototype call returns black. In other modes the backing store only ever contains the display-size, watermarked copy | Vault/Fortress: black. Elsewhere: screen-size marked copy at best |
| Bulk scrapers & AI crawlers | No URLs in HTML, POST + authorization + a fresh token per view, separate bounded token/image rate windows, per-IP/viewer/image quotas, distinct-image scraping alerts/denial, exact-origin and same-site token gating, bounded caches/nonce stores, and automation tripwires | An empty or very expensive harvest |
| Stealth browser / raw CDP / coherent fingerprint spoofing | Modern stealth stacks can imitate a real browser, pierce shadow trees, and capture composited frames. Archx therefore treats client automation signals as telemetry only; the durable controls remain authenticated `authorize()`, per-viewer quotas/abuse detection, derivative caps, proof-bound one-time delivery, marks, and monitoring | It can obtain only derivatives that the authenticated session is entitled to view, at a rate/pattern your server can throttle or revoke |
| Web-cache deception through a CDN/shared cache | Token and payload responses send `Cache-Control: private, no-store`, `CDN-Cache-Control: private, no-store`, `Surrogate-Control: no-store`, and credential/token/proof-sensitive `Vary` fields. Your CDN must still be tested: a rule that overrides origin `no-store` can defeat these headers | Compliant caches do not retain or replay another viewer's derivative |
| Inspect decoded image memory after display | Fortress defaults to strict memory handling: decoded bitmaps are released promptly, CPU-side working canvases are wiped after GPU upload, plain client-only sources can be locally scrambled before upload, and strict mode bypasses the shared bitmap cache | Far less clean decoded material left hanging around (not a defense against a fully compromised browser/process) |
| Print → PDF | `@media print` blackout + `beforeprint` reaction | Black boxes |
| Windows/macOS/Linux built-in screenshot or snipping tool | **Cannot be blocked by a web page** — the OS compositor is outside the browser. Archx reacts to signals that do reach the page (PrintScreen, common snipping shortcuts, window blur, page freeze) with blur/blackout, and caps/marks the derivative | Sometimes a blurred/black frame; otherwise at best a traceable screen-resolution copy |
| Browser screenshot extension, DevTools “Capture screenshot”, or CDP/remote capture | These use browser privileges above page JavaScript; a website cannot reliably detect installed extensions or veto a privileged visible-tab capture. View-source/Elements still reveals no master or signed URL. Fortress assumes capture and adds Lens + a drifting session/time trace | A degraded, attributable capture of what was visible — never the original file/master |
| Photographing the monitor with a phone or second device | **Physically unstoppable and undetectable from the device displaying the page.** Mitigation is value destruction: entitled resolution, server-baked visible/forensic/Stego marks, dynamic capture trace, Fortress Lens, and optional checker/band opponent-colour temporal modulation designed to interact badly with Bayer sampling, rolling shutter, moiré, and short camera exposures | A camera copy with perspective/moiré/screen loss, mostly Lens mush outside one disc, carrying session attribution |
| Single PrintScreen / extension frame under `temporalShield` | Two complementary frames alternate at refresh rate: random blocks, a parity checker, or horizontal bands, optionally in opponent colour. Eyes integrate the pair toward the image; one captured frame retains noise/stripes. Reduced-motion users are respected by default | One noisy half-frame. A screen recording, averaged captures, or long-exposure camera can reconstruct more — layer it with Lens/marks |
| Single presented frame under `temporalInterlace` | Only the cells assigned to that phase retain sharp pixels; pixel-level, checker, strip, or randomized-block subsets cycle over 2–4 phases. Inactive cells get a low-detail local-colour fill by default (or dim/black/noise), and 60 Hz optimization clamps the cycle to two phases so each subset still updates at 30 Hz | One spatially incomplete frame. Capturing several presented phases, recording video, or using an integrating camera exposure can recombine most detail; interlace raises capture effort, it does not create a screenshot veto |
| AI denoise/upscale/regeneration of a degraded capture | No web layer can honestly promise AI-proof pixels. Archx limits the source information (entitled derivative, Lens/temporal capture), keeps visible attribution, and adds evidence/control layers around it | At best a plausible regenerated approximation and a marked/attributable trail — not the withheld master pixels |
| Reposted copy — “prove it's yours” | StegoMark embeds a blind, keyed, redundant 48-bit fingerprint + CRC in delivered pixels; `archx-detect` recovers it without the original and your `onStegoIssue` registry maps it to the issued view. An optional registered perceptual soft binding gives a second lookup path if metadata/marks were stripped | Attribution evidence for the measured resize/re-encode/mild-blur/photometric and bounded axis-aligned crop cases above—not rotation/perspective proof or standalone legal proof |

### Modes

| Mode | Renderer / policy | Use it for | Cost per image |
|---|---|---|---|
| `lite` | 2D canvas, poisoned read-back, guards | Galleries of 100s, listings, feeds | 1 fetch + 1 decode + 1 draw |
| `shield` *(default)* | 2D canvas + tile-unscramble, client watermark/forensic marks, integrity/automation monitoring, risk reactions (`splitCanvases` option = one canvas per tile) | Most valuable single images | + 64 `drawImage` tile copies (no per-pixel JS in the image path) |
| `vault` | WebGL2 shader un-scrambles on the GPU; read-back returns black by platform design; forensic grain | Hero / premium / paid images. Browsers allow ~8–16 GL contexts — Archx budgets 8 and falls back to shield | 1 texture upload + a few presentation frames; static images then idle (`renderLoop:'auto'`) |
| `fortress` | Vault renderer plus fail-closed integrity policy, strike lockouts, strict memory wiping, local pre-GPU scrambling for plain sources, DevTools guard on, dynamic capture trace, checker + opponent-colour camera shield, and optional trusted-pointer Lens | The small number of images where even a clean screenshot/photo is a serious loss | Vault cost + policy checks; camera/temporal shield deliberately animates. Reserve it for hero/paid content, not grids |
| `custom` | No preset bundle: choose `renderer:'canvas'|'webgl'` and each flag (`forensic`, `memory`, `lens`, `temporalShield`, `cameraShield`, `temporalInterlace`, `splitCanvases`, guards, quality, extraction, token method/cache scope, policies) yourself. Omitting `mode` while passing `renderer` is also treated as custom | Sites that need a precise mix—e.g. Canvas for compatibility but strict memory and Lens, or WebGL without temporal flicker | Exactly the layers you enable; nothing extra is bundled by a mode name |

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
| `tokenTransport` | `'header'` | `'header' \| 'query' \| 'auto'`. Header transport redeems the separate token in `X-Archx-Token` against a clean payload URL, keeping bearer material out of URLs/history/Referer/proxy logs/Resource Timing names; query transport is for legacy token servers |
| `proofOfPossession` | `'auto'` | `'auto' \| 'required' \| 'off'` (or boolean). Auto creates one ephemeral non-extractable ECDSA P-256 key pair per page when WebCrypto is available, binds minted tokens to its thumbprint, and signs a 60-second method/path/token-hash proof for each payload. Required fails closed without WebCrypto. It stops token replay in another browser; it does not stop the legitimate page/browser from displaying authorized pixels |
| `fetchTimeoutMs` / `maxResponseBytes` / `maxDecodedPixels` / `maxDecodedDimension` | `20000` / 64 MiB / 40 MP / 16384 | bounded streaming fetches and pre/post-decode budgets for token and direct sources; hostile SVG/oversized/redirected/cross-origin token responses fail closed |
| `tokenMethod` | `'POST'` | `'POST' \\| 'GET'`. POST sends `X-Archx-Request: token`, `cache:'no-store'`, and works with the server's POST-only default. GET is only a legacy bridge when the server explicitly enables it |
| `key` / `aesKey` / `grid` / `scrambled` | — | for `.archx` / statically scrambled assets |
| `fit` | `'cover'` | `'cover' \| 'contain' \| 'fill'` (like CSS `object-fit`) |
| `lazy` | `true` | shared `IntersectionObserver`, 500 px pre-load margin |
| `unloadOnExit` | `false` (including gallery) | opt-in backing-store release for truly huge grids; repaint still prefers retained bitmap/texture/cached payload over the network |
| `maxBackingWidth` / `dprCap` | `1920` / `3` | canvas backing follows modern retina/mobile DPR without exceeding the hard backing cap; exact `devicePixelContentBoxSize` is used when the browser provides it |
| `qualityProfile` / `requestQuality` | `'high'` / profile-derived | `qualityProfile`: `'original' \| 'high' \| 'balanced' \| 'fast'`. It maps to lossless/q95/q90/q82 plus sampling defaults, each directly overridable. `requestQuality` (`1..100 \| 'lossless'`) is sent as `q=` and honoured only if the server sets `allowClientQuality` (your `authorize()` entitlement still wins) |
| `sourceOversample` / `maxSourceWidth` | `2` (gallery helper: `1.5`) / `2560` | token sources wait for a stable host box, request a 2× cover-aware derivative and supersample down for detail; the server entitlement is still the real signed cap. Lower this for bandwidth-first thumbnails, raise it for zoom/lightbox hosts |
| `cacheScope` | `null` | viewer/tenant namespace included in token/bitmap cache keys. Set it for authenticated SPAs and call `Archx.clearCaches()` on logout/account switch so a new viewer cannot reuse the previous viewer's decoded bitmap |
| `cacheBitmap` / `cachePayload` | `true` / `true` | session-level no-reload controls. `cacheBitmap` shares decoded results for identical non-strict sources; `cachePayload` privately retains scrambled bytes so strict-memory repaint/context recovery can decode locally instead of reminting/fetching. Explicit `reload()` bypasses both |
| `reloadOnResize` / `resizeUpscaleFactor` | `'upscale'` / `1.75` | strict-memory resize policy: `'never'` keeps the painted canvas, `'upscale'` re-resolves only after a large size jump (locally from cached payload when enabled), `'always'` is the legacy eager behaviour. Normal modes repaint from the retained bitmap |
| `renderLoop` | `'auto'` | WebGL presentation policy: `'auto'` = static images draw on demand and only temporal shield animates; `'static'` forces on-demand; `'continuous'` forces a RAF loop while visible. Lens/risk/resize changes request fresh frames automatically |
| `temporalShield` | `null`; fortress enables checker+chroma | `true` or `{ strength, block, pattern:'blocks' \\| 'checker' \\| 'bands', chroma, engine, respectReducedMotion }`. Alternates complementary frames so one OS/extension/DevTools screenshot is degraded. Can flicker/eye-strain and costs continuous rendering; recordings/averaged frames/long exposures can undo it. Set `false` to opt a Fortress image out |
| `temporalInterlace` | `null` (never enabled by a preset) | `true`, `'balanced60' \\| 'pixels60' \\| 'strips60' \\| 'blocks60'`, or `{ profile, engine:'auto' \\| 'shader' \\| 'frames', layout:'checker' \\| 'pixels' \\| 'strips' \\| 'blocks', axis, cellSize, phases:2..4, fill:'lowres' \\| 'dim' \\| 'black' \\| 'noise', fillBlock, fillStrength, hiddenScale, activeGain, compensation, noiseStrength, chroma, refreshHz, minPhaseHz, optimizeRefresh, respectReducedMotion }`. Only the current spatial subset is sharp; other cells use the selected fill. `shader` evaluates the phase mask in WebGL; `frames` pre-renders one altered Canvas2D frame per phase; `auto` follows the effective renderer. The 60 Hz default is two phases with 2-device-pixel checker cells and a local-average fill. See the dedicated section below |
| `cameraShield` | `null` | experimental separate-device profile using the same temporal engine: e.g. `{ pattern:'checker', chroma:true }` for Bayer/opponent-colour friction or `{ pattern:'bands', chroma:true }` for rolling-shutter rows. A truthy `cameraShield` takes precedence over a preset's generic `temporalShield`. It is capture degradation—not TPVM and not camera-proof; synchronized shutters/viewers or coded room lighting would require hardware outside page JS |
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

### Temporal interlace: deliberately incomplete presented frames

`temporalInterlace` is separate from the older complementary-noise `temporalShield`. It partitions the backing image into spatial cells and assigns each cell to one phase. On each presented animation frame, only that phase's cells retain the sharp source pixels; cells assigned to other phases show a selectable fill. Visual persistence can integrate the cycle, while an ordinary one-frame screenshot or a fast camera exposure receives an incomplete partition.

```js
// 60 Hz default profile, drawn by whichever renderer is already effective.
Archx.load.image('#hero', { id: 'watch-01' }, {
  mode: 'custom',
  renderer: 'webgl',
  temporalInterlace: true,
});

// Explicit GPU fragment-shader masking with an override.
Archx.load.image('#shader', { id: 'watch-02' }, {
  mode: 'custom',
  temporalInterlace: {
    profile: 'pixels60',
    engine: 'shader',      // WebGL phase mask; falls back to frames if GL is unavailable
    phases: 4,              // optimized to 2 for refreshHz: 60 / minPhaseHz: 30
    fill: 'lowres',
  },
});

// Explicit pre-rendered Canvas2D phase frames.
Archx.load.image('#frames', { id: 'watch-03' }, {
  mode: 'custom',
  temporalInterlace: {
    profile: 'blocks60',
    engine: 'frames',       // one altered full-size canvas per phase
    layout: 'blocks',
    cellSize: 8,
    fill: 'dim',
    hiddenScale: 0.25,
  },
});
```

All four built-in profiles target a **60 Hz** display and a 30 Hz minimum per-phase rate:

| Profile | Layout | Cell size | Intended trade-off |
|---|---|---:|---|
| `balanced60` | checker-assigned square cells | 2 device px | Default for `temporalInterlace:true`; fine partition with locally averaged inactive colour |
| `pixels60` | pixel-level cells distributed by `(x + y) mod phases` for 2 phases, `(x + 2y) mod phases` for 3–4 | 1 device px | Finest shimmer, but most sensitive to scaling, sub-pixel rendering, and camera sampling |
| `strips60` | alternating row strips (`axis:'columns'` also available) | 2 device px | Easiest geometry to reason about; interacts visibly with scrolling/rolling-shutter capture |
| `blocks60` | square blocks assigned randomly per render | 8 device px | Coarser holes in a one-frame capture, but the most obvious flicker/motion texture |

Choose the drawing engine by where you want the cost:

- **`engine:'shader'`** — the fragment shader derives the cell from `gl_FragCoord`, decides whether it belongs to the current phase, and synthesizes the inactive fill. It avoids extra full-size frame canvases and composes naturally with WebGL un-scrambling and Lens. The low-detail fill costs an extra texture sample for inactive fragments, and continuous presentation still costs GPU/compositor/battery work every animation frame.
- **`engine:'frames'`** — Canvas2D builds one altered canvas per phase after the final overlays/watermark are baked, then cycles them with `drawImage`. Per-frame CPU pixel work is almost zero, but setup does one pixel pass per phase and memory is roughly one RGBA backing store per phase (about 7.9 MiB per uncompressed 1920×1080 frame before browser/compositor copies).
- **`engine:'auto'`** follows the effective renderer. In debug builds, `_debug()` reports both `temporalEngineRequested` and `temporalEngineActual`, so a WebGL-budget/context fallback to frames is visible rather than silent.

Important limits and safety defaults:

- `refreshHz` is a **planning target**, not a hardware measurement: browsers do not give page JS a portable, trustworthy physical-refresh API. With `optimizeRefresh:true`, Archx uses `floor(refreshHz / minPhaseHz)` to cap requested phases. The default `60 / 30` therefore clamps 3–4 phases to 2; at a correctly configured 120 Hz target, 4 phases are allowed. The actual cadence is still the browser's `requestAnimationFrame`/compositor cadence.
- Two-phase interlace on a real 60 Hz monitor updates each subset at 30 Hz. The default `fill:'lowres'` preserves local average colour to reduce brightness modulation, but it does **not** make a flicker pattern universally comfortable or safe. `fill:'black'` is the literal missing-subset version and is the harshest; partial active-pixel gain can also clip highlights. Keep `respectReducedMotion:true`, test with photosensitive users/content in mind, and avoid enabling interlace across a whole gallery.
- Interlace is not a screenshot veto. Screenshots from different phases, screen recordings, compositor frame extraction, and some phone-camera exposures can recombine the subsets. Long exposures may integrate a nearly complete image; short/rolling-shutter exposures may show bands. Use it with server-side authorization, resolution caps, Lens, watermarks, and attribution—not as the only layer.
- It can be combined with `temporalShield`/`cameraShield` complementary noise. Fortress does not turn literal interlace on by default, and enabling `temporalInterlace` suppresses Fortress's automatic generic `temporalShield` unless you also set that shield explicitly (`temporalInterlace:false` leaves the Fortress shield alone).
- Shader interlace is applied before the client watermark texture, so the watermark remains present in each phase. Canvas frames are built from the already-composited frame, so baked overlays remain phase-partitioned with the image. With Lens, the sharp disc is sampled from the current phase rather than bypassing interlace.

The normalized settings are inspectable before use with `Archx.normalizeTemporalInterlace(value)` (also exported as `normalizeTemporalInterlace` alongside `TEMPORAL_INTERLACE_PROFILES`). The web component accepts `temporal-interlace`, `temporal-interlace-engine`, `temporal-interlace-layout`, `temporal-interlace-phases`, `temporal-interlace-cell-size`, `temporal-interlace-fill`, and `temporal-interlace-refresh-hz` attributes.

### Also

- `Archx.presets` / `Archx.preset(name, overrides?)` / exported `PRESETS` + `preset()` — frozen, inspectable direct-parameter bundles (`gallery`, `editorial`, `commerce`, `screenshotResistant`)
- `Archx.temporalInterlaceProfiles` / `Archx.normalizeTemporalInterlace(value)` / exported `TEMPORAL_INTERLACE_PROFILES` + `normalizeTemporalInterlace()` — inspect and bound the 60 Hz-first subset-frame profiles before passing them to an image
- `Archx.clearCaches()` — clears shared decoded-bitmap/token promises and rotates the page-session scope; call it on logout, tenant switch, or entitlement downgrade. Already-painted instances keep their current private frame until reload/destroy
- `Archx.config({...})` — set global defaults (endpoint, token method, cache scope, session id, brand text…). Calling it with no useful update returns a sanitized view; configured `key`/`aesKey` values are shown only as `[redacted]`
- `Archx.instanceCount` — number of live instances, without exposing the instance registry itself
- `Archx.auditIntegrity()` / `auditIntegrity()` — names of sensitive browser APIs that currently differ from the native references captured when the module loaded
- `Archx.detectAutomation()` / `detectAutomation()` — current cheap headless/automation signals (a tripwire, not a bot-proof identity check)
- `instance.options` — sanitized per-instance option view with secrets redacted
- `Archx.load.gallery(container, items, options?)` — items: URLs or `{id, alt}` objects
- `Archx.protectAll(selector?, options?)` — upgrade existing `<img data-protect>` in place
- `<archx-image>` — attributes: `src`, `image-id`, `token-endpoint`, `token-method`, `token-transport`, `proof-of-possession`, `cache-scope`, `mode`, `preset`, `quality-profile`, `watermark`, `fit`, `grid`, `key`, `scrambled`, `lens`, `capture-shield`, `temporal-shield`, `camera-shield`, `temporal-interlace`, `temporal-interlace-engine`, `temporal-interlace-layout`, `temporal-interlace-phases`, `temporal-interlace-cell-size`, `temporal-interlace-fill`, `temporal-interlace-refresh-hz`, `render-loop`, `reload-on-resize`, `on-extract`, `alt` *(prefer `image-id` + tokens: a `src` attribute is visible in page source by definition)*
- Server: `createArchxMiddleware(options)` needs `sharp` (optional peer; pinned examples use Sharp 0.35). Important direct controls:
  - **Access:** `secret`, `authorize`, `allowAnonymous`, `imagesDir | imagesDirs | images`, `publicDir | publicDirs`, `basePath`, `ttlSec`, `tokenMethods`, `oneTimeTokens`, `bindTokenTo:{ip,userAgent,session}`, `allowedOrigins`, `requireSameSiteTokenRequests`, `requireTokenRequestHeader`, `allowQueryTokens`, `proofOfPossession:'optional'|'required'|'off'`, `callbackTimeoutMs`/`authorizeTimeoutMs`, `trustProxy`, `trustedProxyHops`.
  - **Delivery:** `grid`, `encrypt`, `scrambleKeyMode:'per-image'|'per-token'`, `maxWidthCap`, `quality`, `lossless`, `format:'webp'|'png'|'jpeg'`, `allowClientQuality`, `serverWatermark`, `forensic`, `forensicPerToken`, `steganography`, `onStegoIssue`, `stegoRegistryFailure`.
  - **Abuse/CPU/memory:** `rateLimitPerMinute`, `tokenRateLimitPerMinute`, `rateLimitMaxClients`/`maxTrackedClients`, `oneTimeTokenMaxEntries`, `quotas:{windowMs,perIp,perViewer,perIpImage,perViewerImage}`, `abuseDetection:{distinctImages,windowMs,action:'event'|'deny'}`, `onSecurityEvent` (or legacy `onAbuse`), `processing:{maxInputBytes,maxInputPixels,maxInputWidth,maxInputHeight,maxOutputPixels,processingTimeoutSec,allowedInputFormats}`, `processingConcurrency`, `processingQueueMax`, `processingQueueTimeoutMs`, `outputCacheMax`, `outputCacheMaxBytes`, `masterCacheMaxBytes`, `cacheMasters`.
  - `authorize(req, id, { phase, token })` may return `true`/`false` or `{ allow, viewerId|userId|subject|sessionId, permissions|scopes|scope, maxWidth, watermark, quality, lossless, format, steganography, stegoFingerprint }`. If scopes are supplied, one of `image:view`, `archx:image:view`, or `*` is required. It runs before minting and again before bytes are served; current entitlements can tighten width/quality/format but cannot widen signed claims. Viewer IDs are HMAC-hashed before token/cache/forensic/Stego derivation. `allowClientQuality:true` only lets the browser request `q=` when no entitlement quality overrides it.
  - Token requests include the display box (`bw`, `bh`, `fit`, optional `q`); the server validates them as strict integers/enums and uses source aspect to sign a cover-safe derivative width before entitlement caps. Responses use `Cache-Control: private,no-store`, CDN/surrogate `no-store` controls, credential/token/proof-sensitive `Vary`, `nosniff`, `Referrer-Policy:no-referrer`, same-origin/cross-origin CORP as configured, exact-origin credentialled CORS only, a sandboxed CSP on payloads, `Retry-After` on 429s, and generic error bodies that do not leak paths/stacks/decoder/token details.
  - `auditArchxServerConfig(options)` gives a frozen, secret-free preflight result. A live handler exposes only `handler.configAudit`, `handler.stats()`, and `handler.close()` for graceful shutdown/cache/limiter cleanup; there is no public live index, test hook, generic token signer, or generic token verifier. `validateImageId()`, `validateTokenClaims()`, and `computeJwkThumbprint()` are exported for host-side validation/tests.
  - `serverWatermark` may be a string, SVG-watermark config object, or async function receiving `{ req, id, nonce, viewerId, exp }`. `{id}`, `{nonce}`, and `{viewer}` placeholders are expanded. It is composited before forensic/Stego marking, tile scrambling, encoding, and optional encryption.
  - `forensic:true` uses the default 32 px / delta-2 block mark; or pass `{ blockSize, delta }`. With `forensicPerToken:true` the seed changes per signed delivery (more attribution, less output-cache reuse); set it `false` for static per-image/viewer marks when gallery throughput matters more.
  - `steganography:true` or `{ strength, gridX, gridY, perToken }` enables StegoMark. The fingerprint is HMAC-derived from image + viewer hash + (nonce or `static`), never returned to the browser; `onStegoIssue({ req, id, viewerId, nonce, exp, fingerprint })` is your registry hook. `deriveStegoFingerprint()` / `deriveStegoKey()` are exported for investigations, and `embedStegoFingerprint()` / `detectStegoFingerprint()` / `stegoFingerprint()` are exported from the scramble core. Detection accepts `searchOffsets` and `searchGeometry`. Direct `scrambleImage()` callers can pass `stegoPayload`, `stegoKey`, `stegoStrength`, plus the same processing-limit options.
  - Direct `scrambleImage()` callers can pass `contentFingerprint:true` to receive a `perceptualFingerprint` for an ingest registry; the token middleware does not compute it per request. The core exports `perceptualFingerprint()`, `normalizePerceptualFingerprint()`, `perceptualFingerprintDistance()`, and `comparePerceptualFingerprints()` for offline monitoring/takedown tooling.
  - Sharp masters are treated as untrusted: byte-only inputs, pre-decode format/dimension sniffing cross-checked against Sharp metadata, byte/pixel/width/height/output budgets, detected-format and process-global libvips-loader allowlists, rejection of multi-page and >4-channel inputs, `failOn:'warning'`, native timeouts, metadata-stripping output, and a bounded processing semaphore. Corrupt/oversized inputs become controlled 413/415/503 responses rather than stack leaks.
  - Marked `.archx` headers carry `wm:1`, `fx:1`, and/or `sg:1` flags so your pipeline can verify what was embedded without exposing seed/text/fingerprint derivation in the payload.

## Performance

Measured on this repo's test machine (`npm run bench`, `npm run test:browser`):

- Browser bundle: **94.3 KiB minified / 30.9 KiB gzipped**, zero dependencies. The v1.5 size buys strict token-response/origin validation, bounded streaming/decode budgets, header-token transport, proof-of-possession signing, fail-closed lifecycle handling, and the optional shader/pre-rendered temporal-interlace engines
- 100-image protected gallery in headless Chromium: all 100 painted with 0 `<img>` tags; recent local runs measure **about 3.7–4.0 s** in the non-lazy path (production lazy mode streams them on scroll, and the gallery helper defaults to 1.5× oversampling)
- Steady-state cost after first paint is deliberately near zero for stills: the browser test measured **0 additional Vault frames over 450 ms** with `renderLoop:'auto'`, while a temporal-shield Fortress intentionally presented 27 frames in the same window. The no-reload browser test also verifies one token + one payload request across strict-memory visibility/resize cycles
- Server pixel scramble measured **170–224 MP/s** in the latest local run (1.9 ms at 800×536, 10.1 ms at 1600×1072, 9.4 ms at 1920×1080); full down-scale + scramble + q95 WebP took **169.9 ms at 900 px** as a one-time cached cost per distinct output variant, with AES-GCM in run-to-run noise at that size. Optional perceptual-fingerprint computation is off in the request path and intended for ingest/CLI use
- Quality: on the detailed 800 px watch benchmark, q95 reconstruction measured **41.0 dB PSNR / 1.43 MAD** versus 36.6 dB / 2.56 MAD at the old q82. `lossless:true` is exact at the delivered size (800 px test payload ~360 kB lossless WebP vs ~128 kB q95), so use it selectively for hero/product detail.
- Per image in the standard browser path: 1 fetch + 1 `createImageBitmap` decode + 64 tile copies at native/oversampled resolution + one high-quality final resample. No general per-pixel JavaScript is required to un-scramble. Static WebGL requests no depth/stencil/MSAA buffers and uses a low-power preference; permanent 4xx/aborted fetches are not retried. Temporal work is the deliberate exception: shader interlace evaluates a small phase mask per fragment (plus one extra sample for inactive `lowres` fragments), while the frames engine spends one clamped-array pixel pass and one extra backing store per phase at setup, then only `drawImage`s. Either way, an interlaced image must present continuously while visible, so reserve it for selected hero/paid views rather than hundreds of thumbnails. In the Chromium interlace fixture, screenshots from opposite black-fill strip phases differed by **about 96 mean absolute channel value** in recent runs, confirming that the compositor was actually presenting materially different incomplete frames
- Server caches and security stores are entry- **and byte-bounded**, limiter clients expire, nonce claims fail closed when saturated, and image jobs pass through a bounded semaphore/queue. Trade-offs remain: per-token server watermarks/forensics/StegoMarks and `scrambleKeyMode:'per-token'` intentionally defeat cross-viewer output-cache reuse; Fortress strict memory bypasses the shared bitmap cache, but with default `cachePayload:true` it can decode privately retained scrambled bytes locally instead of reminting. Use the strongest per-viewer settings on valuable items, not every thumbnail.
- Scrambled pixels compress worse than natural images (tile edges), so payloads run larger than an equivalent plain WebP. Lower `grid` (e.g. 6) if bytes matter more than shuffle strength.

## The honest limits

1. **The analog hole is real.** Anything visible can be screenshotted or photographed at screen resolution. Only DRM *video* pipelines (Widevine/EME + HDCP output protection) can black out screenshots, and browsers offer no equivalent for still images. Archx's answer: never ship more than display resolution, bake the watermark in, trace the session.
2. **A skilled reverse-engineer controls the receiving browser.** Someone who instruments below JavaScript, patches the browser, forges native-function fingerprints before Archx loads, uses CDP/Juggler to pierce a closed shadow root, captures composited frames/GPU memory, or simply photographs the display can obtain some form of the visible pixels. Captured native references and audits catch ordinary post-load hooking and naive pre-hooks; they cannot create a trusted execution environment inside an attacker-owned browser. Stealth-automation fingerprints are likewise spoofable and must never replace authorization/quotas.
3. **Payload + session key reconstruction is deliberately made low-value, not mathematically impossible.** The open-source decoder must run for legitimate viewers, so a determined viewer can reassemble the one web-size derivative they were sent. One-time/proof-bound entitled tokens stop external replay and oversized requests; proof of possession does not stop script or a browser operator in the legitimate page from causing that page to sign and load. Server-baked marks mean the reconstructed derivative is still watermarked/traced. They never recover the master resolution, metadata, or pixels the server withheld.
4. **Lens + capture trace + temporal/camera shields/interlace are friction, not screenshot-proofing.** They prevent a single ordinary screenshot/photo from containing the whole sharp, unmarked frame and make scripted sweeps harder/noisier, but a patient person can move a real pointer and stitch discs, record/average temporal frames, capture and recombine every interlace phase, or use a camera. Likewise, page JavaScript cannot veto the OS compositor, a screenshot extension's privileged visible-tab capture, DevTools/CDP capture, or another device's camera; shortcut/blur reactions only help when the browser exposes a signal in time. Expect attribution and delay—not impossibility.
5. **AI regeneration and invisible-mark removal are real attacks.** Research on diffusion-based regeneration shows many pixel-level invisible watermarks can be weakened/removed while preserving the scene's semantics; perceptual fingerprints can also drift or be adversarially evaded, and an upscaler can invent plausible detail from a degraded capture. StegoMark, forensic blocks, C2PA-style provenance, and soft bindings are therefore evidence/discovery layers—not DRM. Your durable controls are not shipping the master, server authorization/entitlement, visible marks where appropriate, issuance logs, monitoring, and enforcement.
6. **Authorization headers are not identity.** Origin/Referer help with CORS/CSRF context; IP and User-Agent are spoofable/changeable and can cause false rejects behind NAT, VPNs, mobile network changes, or browser updates. Your authenticated session and object-level `authorize()` decision are the security boundary, and Archx checks that boundary again at redemption.
7. **One-time means a late failure can burn a token.** To close the parallel-replay race without letting a transient authorization failure spend a valid token, Archx verifies the signature/claims/proof, re-runs redemption authorization and binding checks, and only then atomically claims the proof ID and nonce through the configured state store. In a multi-instance deployment that store must be shared and atomic across every process. A later quota/processing failure can still burn that token; mint a fresh one instead of retrying it. The bundled client re-mints once after a 401/403 payload response.
8. **Client-only mode is only as strong as the URL you feed it.** If the same full-resolution file is also sitting at a guessable public URL, protect the door, not the window: move masters behind the token server (or at least only ever publish down-scaled derivatives). Local scrambling before GPU upload protects the texture path, not the public network file.
9. **SEO / sharing trade-off:** protected images have no indexable `<img src>` (that's the point). Keep SEO-critical thumbnails as normal images and protect the valuable full views; use `alt` for accessibility.

## Security checklist for production

- [ ] Masters in a folder that is **not** statically served (test the direct URL → 404)
- [ ] `ARCHX_SECRET` random and **≥32 bytes**, from the environment; run `auditArchxServerConfig()` in deployment tests and compare `handler.configAudit`/stats in staging vs production (without logging secrets)
- [ ] For more than one server process, set `deploymentMode:'multi-instance'` with a shared atomic `stateStore`; test mint-on-A/redeem-on-B/replay-on-A and confirm a store outage returns 503 rather than falling back locally
- [ ] Rotate signing keys through the `secrets` keyring + `activeSecretId`, keep the previous key only through the token rollover window, and persist StegoMark `keyId` values for later investigations
- [ ] HTTPS everywhere (tokens/keys ride along), short `ttlSec` (60–180 s), POST token minting, `oneTimeTokens:true`, and object-level `authorize(req,id,{phase})` tests for horizontal/vertical access (another user's image, revoked user, downgraded plan)
- [ ] Prefer `allowQueryTokens:false` and pair server `proofOfPossession:'required'` with client `proofOfPossession:'required'` once every supported client implements the proof protocol
- [ ] Verify every CDN/WAF/reverse-proxy rule honors origin `private,no-store`/`CDN-Cache-Control`/`Surrogate-Control`; never add a cache rule for token or payload paths based only on a static-looking URL
- [ ] Exact `allowedOrigins` only; treat Origin/Referer/User-Agent/IP as signals. Enable session binding where a stable viewer ID exists; use IP binding cautiously for mobile/VPN users. Set `trustProxy:true` only with the exact `trustedProxyHops` count behind proxies that strip/set `X-Forwarded-For`; otherwise the socket IP remains authoritative
- [ ] Tune token/image rate limits, per-viewer/IP/image quotas, distinct-image abuse alerting, `onSecurityEvent`, bounded cache/store sizes, and Sharp bytes/pixels/dimensions/formats/timeout/concurrency to your catalog and CPU budget
- [ ] Negative-test the deployed routes: direct master path, traversal/double-encoding/malformed `%`, extra path segments, wrong method, duplicate/oversized tokens, sizing abuse, replay race, revoked session, corrupt/oversized master, and quota exhaustion
- [ ] Server-side watermark + forensic marking on for valuable derivatives; client `{session}` watermarks alone do not survive offline payload reconstruction
- [ ] If StegoMark is enabled, persist every `onStegoIssue` fingerprint with image/user/order context and test your `archx-detect` investigation path; an unregistered fingerprint is only a number. Register perceptual soft bindings at ingest if you want a second discovery path, and calibrate the distance threshold on your own catalog/false-positive tolerance
- [ ] Client `debug:false`, `tokenMethod:'POST'`, a viewer/tenant `cacheScope`, and `Archx.clearCaches()` on logout/account switch; no custom code that re-exposes instances/canvases on `window` or DOM elements
- [ ] `fortress`/`vault` reserved for the few images that matter most; `lite` for bulk grids. Enable Lens/camera/interlace patterns only where flicker, GPU, accessibility, and legitimate-viewing trade-offs are acceptable; keep reduced-motion honoured and test on real 60/120 Hz displays + phone cameras before claiming camera degradation for your hardware
- [ ] Keep full-resolution masters offline/backed-up — the server only needs web-size sources if you pre-resize

## Tests

```bash
npm test            # 34 unit/integration tests (scramble/crypto, delivery quality,
                    # cover-aware sizing, server marks, StegoMark survival + crop geometry,
                    # perceptual soft bindings, strict config/claims, malformed HTTP, replay races,
                    # reauthorization, sender-constrained proofs, bounded stores/quotas/abuse,
                    # trusted-hop proxy parsing, Sharp processing limits, 60 Hz interlace normalization,
                    # cross-instance shared state, signing-key rotation, and fail-closed store errors)
npm run test:browser  # 72 checks in real headless Chromium (encapsulation, decoys,
                      # native detail retention, WebGL black read-back,
                      # Fortress Lens/camera + shader/frames temporal-interlace patterns/capture trace/strikes/integrity,
                      # POST + clean-header + proof-bound token flow, cache scopes, no-reload lifecycle,
                      # draw-on-demand GPU, token replay, guards, print, 100-image gallery…)
npm run test:all
npm run load-test -- --requests=500 --concurrency=50 --width=1200
                    # bounded local mint+redeem regression load; see docs/OPERATIONS.md
                    # before treating any staging number as a capacity result
```

## Repository layout

```
src/         browser library (archx.js) + shared scramble/crypto core (scramble.js)
dist/        committed built bundles (ESM / CJS / minified browser-global; regenerate, do not hand-edit)
server/      token+scramble middleware, image scrambler, archx-protect + archx-detect CLIs, demo server
demo/        interactive demo + attack simulator, automated-test harness
demo-masters/  three tracked demo originals — deliberately NOT web-accessible; generated gallery is ignored
docs/        reviewer guide, research, operations, compliance readiness,
             compatibility matrix, and plain-language IP-holder guide
examples/    copy-and-run protection ladder and custom-flags showcase
tests/       unit + real-browser test suites
tools/       build, demo-image generator, benchmarks, bounded load test
```

## License

MIT © Archnemix contributors
