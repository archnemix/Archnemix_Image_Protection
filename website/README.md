# Archnemix website

The static site for **Archnemix Image Protection**. No build step, no
analytics, no third-party CDNs (Three.js is vendored in `vendor/`):

- `index.html` — overview: headline, the scroll-scrubbed pipeline film,
  the problem, how it works, measured results, honest limits
  (readable with no JavaScript at all)
- `pipeline.html` + `pipeline.js` — the interactive walkthrough: the
  same film up top, then a six-stage journey rendered live per stage,
  a measured profile simulator, a "try to steal it" artifact lab, and
  the identification outcome table
- `technical.html` + `technical.js` — the decision atlas: 21 engineering
  decisions (problem / chosen / alternatives rejected / pros / cons /
  evidence), searchable and tag-filtered, with five live widgets — a
  bit-exact port of the shipped scramble-plan builder (parity-verified
  against `src/core/plan.js`), a WebCrypto token explorer including the
  canonical-base64url gate, a replay-saturation sizing calculator, a BCH
  errors/erasures recovery map, and the measured watermark-survival chart
- `limits.html` + `limits.js` — threat model: eight-attacker interactive
  matrix, measured edges, and when to choose DRM/C2PA/neural instead
- `film.js` — "Follow one photograph": a pinned, scroll-scrubbed film
  (Three.js) in five acts — private master → sliced, scrambled and
  fingerprinted tiles → one-time-token wire flight past an attacker's
  network tab → reassembly inside a browser frame with a right-click
  blackout beat → a leaked copy rescanned and attributed. Play mode,
  act rail, reduced-motion static mode, and a 2D storyboard fallback
- `photo.js` — the shared procedural "photograph" (aurora valley)
  painted on a 2D canvas; every live artifact on the site derives
  from it, so the site needs zero image assets
- `motion.js` — site-wide motion chrome: inertia-smoothed scroll
  progress, parallax depth, staggered section reveals, 3D card tilt,
  magnetic cursor, ambient orbs, progress bar and chapter dots
  (all reduced-motion/touch aware), plus the install copy button
- `styles.css` — warm-paper editorial theme shared by all pages,
  with a dark "cinema" band for the film

## Run it locally

```bash
npx serve website        # or: python3 -m http.server -d website 8080
```

## Host it

Drop the `website/` folder on any static host (GitHub Pages, Netlify,
Cloudflare Pages, an S3 bucket…). The only external request is Google
Fonts (with system-serif fallbacks); if it is blocked, the page stays
fully readable, and if WebGL is unavailable the hero degrades to a text
explanation.

The hero's tiles scramble the same way the real Archx payload does — a
seeded 8×8 permutation with per-tile mirrors — because the site should
demonstrate the product, not just describe it.
