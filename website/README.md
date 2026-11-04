# Archnemix website

The static four-page site for **Archnemix Image Protection**. No build
step, no analytics, no third-party CDNs (Three.js is vendored in `vendor/`,
and the Fraunces / IBM Plex Mono fonts are self-hosted OFL WOFF2 files in
`fonts/` — pages make no third-party subresource requests at all):

- `index.html` — overview: interactive 3D hero (drag-orbit, per-tile trace
  readout, 8×8–32×32 grids — the same range the product permits), how it
  works, measured results, honest limits (readable with no JavaScript at
  all)
- `docs.html` — the documentation page: install, quick starts, the three
  profiles, key options, server rules, ownership proof, FAQ. Written for
  reading (sticky on-this-page index with scroll-spy, 70ch measure) and
  fully usable with JavaScript disabled; it teaches the guided path and
  links to the complete reference on GitHub
- `technical.html` + `technical.js` — the decision atlas: 21 engineering
  decisions (problem / chosen / alternatives rejected / pros / cons /
  evidence), searchable and tag-filtered, with an animated mode/options
  delivery flowchart (a local explanation, not a server demo) and five
  local widgets — a
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
Cloudflare Pages, an S3 bucket…). There are no external requests to
worry about — fonts and Three.js are self-hosted — and if WebGL is
unavailable the hero degrades to a text explanation.

The hero's tiles scramble the same way the real Archx payload does — a
seeded 8×8 permutation with per-tile mirrors — but it remains an
illustration. This static site intentionally has no live end-to-end demo:
there is no Archx Node server here to authorize viewers, mint/spend
tokens, keep masters private, or build Sharp derivatives. Run the real
demo locally from the repository with `npm ci`, `npm run demo:images`,
`npm run build`, and `npm run demo`.
