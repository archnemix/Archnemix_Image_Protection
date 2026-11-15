# Archnemix website

The static four-page site for **Archnemix Image Protection**. No build
step, no analytics, no third-party CDNs (Three.js is vendored in `vendor/`,
and the Fraunces / IBM Plex Mono fonts are self-hosted OFL WOFF2 files in
`fonts/` — pages make no third-party subresource requests at all):

- `index.html` + `js/hero/{painting,tile-stage}.js` — overview:
  interactive 3D hero (drag-orbit, per-tile trace readout, 8×8–32×32
  grids — the same range the product permits), how it works, measured
  results, and honest limits (readable with no JavaScript at all)
- `docs.html` + `js/docs/docs-page.js` — the documentation page:
  install, quick starts, the three profiles, key options, server rules,
  ownership proof, FAQ, and the current npm release-status panel. The
  panel identifies v1.30.4 as the current published npm release. Keep it
  aligned with `../docs/RELEASE_STATUS.md`; that mutable status note is
  intentionally omitted from npm artifacts. The page remains fully usable
  without JS and links to the complete reference on GitHub.
- `technical.html` + `js/technical/` — the decision atlas: 21
  engineering decisions (problem / chosen / alternatives rejected / pros /
  cons / evidence), searchable and tag-filtered, with an animated
  mode/options delivery flowchart (`flow-widget.js`, a local explanation,
  not a server demo) and local widgets (`plan-widget.js`,
  `token-widget.js`, `saturation-widget.js`, `bch-widget.js`,
  `survival-widget.js`, orchestrated by `atlas.js` and `index.js`)
- `limits.html` + `js/limits/threat-matrix.js` — threat model:
  eight-attacker interactive matrix, measured edges, and when to choose
  DRM/C2PA/neural instead
- `js/shared/{ui,plan-port}.js` — shared UI enhancements (scroll-progress
  hairline, mobile navigation drawer, section reveal) and the verbatim
  port of `src/core/plan.js` (`cyrb128`, `sfc32`, `mulberry32`,
  `buildScramblePlan`) used by both the hero stage and the technical atlas
- `styles/{tokens,base,layout,components,pages}.css` — modular
  field-guide stylesheets: self-hosted type tokens, paper/ink palette,
  masthead & grid layout, interactive widgets/tables/callouts, and
  page-specific rules. No remote fonts, scripts, analytics, or image
  requests.

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
