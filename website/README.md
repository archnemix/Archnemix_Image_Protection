# Archnemix website

The static marketing site for **Archnemix Image Protection**. Three files,
no build step:

- `index.html` — content (readable with no JavaScript at all)
- `styles.css` — warm-paper editorial theme
- `main.js` — the interactive 3D tile-scramble hero (Three.js via CDN,
  procedural painting, no image assets)

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
