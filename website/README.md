# Archnemix website

The static three-page site for **Archnemix Image Protection**. No build
step, no analytics, no third-party CDNs (Three.js is vendored in `vendor/`):

- `index.html` — overview: interactive 3D hero (drag-orbit, per-tile trace
  readout, 4×4–16×16 grids), pipeline, measured results, honest limits
  (readable with no JavaScript at all)
- `technical.html` + `technical.js` — the decision atlas: 21 engineering
  decisions (problem / chosen / alternatives rejected / pros / cons /
  evidence), searchable and tag-filtered, with five live widgets — a
  bit-exact port of the shipped scramble-plan builder (parity-verified
  against `src/core/plan.js`), a WebCrypto token explorer including the
  canonical-base64url gate, a replay-saturation sizing calculator, a BCH
  errors/erasures recovery map, and the measured watermark-survival chart
- `limits.html` + `limits.js` — threat model: eight-attacker interactive
  matrix, measured edges, and when to choose DRM/C2PA/neural instead
- `styles.css` — warm-paper editorial theme (shared by all three pages)
- `main.js` — the 3D tile-scramble hero (procedural painted-valley
  texture, pointer lift field, raycast tile tracing, drag orbit)

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
