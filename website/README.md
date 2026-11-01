# Archnemix website

The static site for **Archnemix Image Protection**. There is no build step,
analytics, demo API or application server. Three.js is vendored in `vendor/`;
Google Fonts is the only external request, with local font fallbacks if it is
blocked.

The opening film and pipeline specimens are **browser-only visual
simulations**. They make no uploads and contact no demo server. That wording
matters: they explain the shipped protection model, but they are not a hosted
instance of the library's server middleware.

## Pages and scripts

- `index.html` — begins inside the full-screen protection film, then contains
  the complete homepage pipeline: six-stage journey, measured profiles,
  "try to steal it" artifact lab and leak-identification table, followed by
  the problem, layers, measured results, use notes and license.
- `technical.html` + `technical.js` — the decision atlas: 21 engineering
  decisions (problem / chosen / alternatives rejected / pros / cons /
  evidence), searchable and tag-filtered, with five live widgets — a
  bit-exact port of the shipped scramble-plan builder (parity-verified
  against `src/core/plan.js`), a WebCrypto token explorer including the
  canonical-base64url gate, a replay-saturation sizing calculator, a BCH
  errors/erasures recovery map, and the measured watermark-survival chart.
- `limits.html` + `limits.js` — threat model: eight-attacker interactive
  matrix, measured edges, and when to choose DRM/C2PA/neural instead.
- `film.js` — "Follow one photograph": a pinned, scroll-scrubbed film in five
  acts. It opens on the photograph full-frame, docks it into the private
  frame, scrambles/fingerprints it, sends one-time fragments past an
  attacker's network tab, reassembles it inside a browser frame and rescans
  a leaked copy. Includes play mode, act rail, reduced-motion static mode and
  a 2D storyboard fallback.
- `pipeline-details.js` — the detailed homepage journey/profiles/steal/
  identify widgets. `site.js` imports it only when the section approaches the
  viewport, and derived canvases are created on first use.
- `photo.js` — the shared procedural aurora-valley "photograph"; every film
  tile, backdrop and pipeline specimen derives from it, so the site needs no
  image assets.
- `site.js` — deliberately small shared behaviour: install-command copying,
  one-time IntersectionObserver section reveals and lazy-loading the pipeline
  details. It does not replace the scrollbar or cursor and owns no perpetual
  animation loop.
- `styles.css` — warm-paper editorial theme plus the dark opening cinema.
  Native scrolling and a visible native scrollbar are intentional.
- `_redirects` — sends old `/pipeline.html` links to the homepage pipeline.
- `_headers` — static-host security/cache headers.

## Performance choices

- The previous site-wide motion layer (custom cursor, scroll progress,
  parallax, tilt, magnetic buttons and blurred orbs) was removed. Ordinary
  reading now has no always-on JavaScript frame loop.
- The film caches viewport/panel geometry on layout instead of reading DOM
  rectangles every frame, shares one material across non-fading tiles,
  reuses tile poses and noise buffers, steps down resolution if frame time
  stays high, and renders alternate frames once scroll/playback settles.
- Film depth comes from a few cheap scene elements — dim photo backdrop,
  dust points, gradient shadows, one stream path and a 36-point pulse cloud —
  rather than post-processing or additional renderers.
- Detailed pipeline artifacts are both module-lazy and artifact-lazy.

## Run it locally

```bash
npx serve website        # or: python3 -m http.server -d website 8080
```

## Host on Cloudflare Pages

Use the repository with these settings:

- Framework preset: **None**
- Build command: *(blank)*
- Build output directory: `website`

No environment variables, Functions, database, API or demo server are needed.
Cloudflare Pages will pick up `website/_headers` and `website/_redirects`
when `website/` is the output directory. The same folder also works on GitHub
Pages, Netlify, S3 or any other static file host, although the Cloudflare
control files are ignored by hosts that do not understand them.

If WebGL is unavailable, the film degrades to a storyboard; with JavaScript
disabled, the homepage keeps a semantic introduction and the explanatory
sections remain readable.
