/* W0 — Animated 10-stage end-to-end delivery flowchart (local explanation, no server) */
import { buildScramblePlan } from '../shared/plan-port.js';

export function initFlowWidget() {
  const flowRoot = document.getElementById('w-flow');
  if (!flowRoot) return;

  const $ = (id) => document.getElementById(id);
  const flowCanvas = $('flowCanvas');
  const fctx = flowCanvas?.getContext('2d') || null;
  const reducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
  const activeValue = (selector, key, fallback) =>
    flowRoot.querySelector(`${selector} .is-active`)?.dataset[key] || fallback;

  const ACCENT = '#2d529e';
  const SEAL = '#b43d26';
  const INK = '#172026';
  const MUTED = '#515c5e';

  const flowState = {
    mode: activeValue('#flowModeSeg', 'mode', 'shield'),
    renderer: activeValue('#flowRendererSeg', 'renderer', 'auto'),
    extract: activeValue('#flowExtractSeg', 'extract', 'black'),
    opts: { pop: true, encrypt: true, watermark: true, serverForensic: true, stego: true },
    step: 0,
    t: reducedMotion ? 0.62 : 0,
    playing: !reducedMotion,
    last: 0,
    raf: 0,
    visible: true,
    now: 0,
    durations: [],
    routeMs: 0,
  };
  flowRoot.querySelectorAll('[data-flow-opt]').forEach((btn) => {
    flowState.opts[btn.dataset.flowOpt] = btn.classList.contains('is-active');
  });

  const FLOW_LEGACY_TOTAL_MS = 33000;
  function activeMarks() {
    const marks = [];
    if (flowState.opts.watermark) marks.push('visible watermark');
    if (flowState.opts.serverForensic) marks.push('server forensic blocks');
    if (flowState.opts.stego) marks.push('StegoMark');
    return marks;
  }
  function effectiveRenderer() {
    if (flowState.renderer !== 'auto') return flowState.renderer;
    return flowState.mode === 'vault' || flowState.mode === 'fortress' ? 'webgl' : 'canvas';
  }
  function clientForensicOn() { return flowState.mode !== 'lite'; }

  function flowStageDurations() {
    const marks = activeMarks().length;
    const renderer = effectiveRenderer();
    return [
      1700,
      flowState.opts.pop ? 2400 : 2150,
      3500,
      flowState.opts.pop ? 3900 : 3650,
      2900,
      marks ? 1300 + 550 * marks : 1500,
      2700 + (flowState.opts.encrypt ? 600 : 0),
      2400 + (flowState.opts.encrypt ? 400 : 0),
      (renderer === 'webgl' ? 3400 : 3000) + (flowState.mode === 'fortress' ? 200 : 0),
      3200,
    ];
  }
  function refreshFlowDurations() {
    flowState.durations = flowStageDurations();
    flowState.routeMs = flowState.durations.reduce((sum, ms) => sum + ms, 0);
    return flowState.durations;
  }
  function flowStageDuration(index = flowState.step) {
    if (!flowState.durations.length) refreshFlowDurations();
    return flowState.durations[index] || 2500;
  }
  const formatFlowMs = (ms) => `${(ms / 1000).toFixed(1)}s`;
  const flowPlan = buildScramblePlan(8, 'archx-flow-explainer', 2);
  const clamp01 = (v) => Math.max(0, Math.min(1, v));
  const lerp = (a, b, t) => a + (b - a) * t;
  const ease = (t) => { const x = clamp01(t); return x * x * (3 - 2 * x); };
  const phase = (t, a, b) => clamp01((t - a) / Math.max(0.001, b - a));
  const cap = (s) => (s ? s[0].toUpperCase() + s.slice(1) : s);

  function rendererFact() {
    const r = effectiveRenderer();
    const name = r === 'webgl' ? 'WebGL shader' : 'Canvas 2D';
    return flowState.renderer === 'auto'
      ? `${name} (auto from ${cap(flowState.mode)})`
      : `${name} (renderer: "${flowState.renderer}")`;
  }
  function wireFact() {
    const payload = flowState.opts.encrypt
      ? 'AES-256-GCM-encrypted .archx scrambled derivative'
      : 'Unencrypted .archx scrambled derivative';
    const token = flowState.opts.pop
      ? 'one-time token, sender-constrained to the proof key'
      : 'one-time token; no proof supplied in this illustration';
    return `${payload} · ${token} · no master`;
  }
  function extractFact() {
    const r = effectiveRenderer();
    const choice = flowState.extract;
    if (r === 'webgl') {
      if (choice === 'black') return 'Instance readback is decoyed/black; prototype GL readback sees the cleared black drawing buffer.';
      return `Instance exports return the real ${choice === 'lowres' ? 'low-res' : 'low-res scrambled'} decoy; prototype GL readback still sees cleared black.`;
    }
    let base;
    if (choice === 'black') base = 'Instance exports and getImageData return the branded black / opaque-black decoy.';
    else if (choice === 'lowres') base = 'Instance exports return a real low-res decoy; instance getImageData stays black.';
    else base = 'Instance exports return a real low-res scrambled decoy; instance getImageData stays black.';
    if (flowState.mode === 'vault' || flowState.mode === 'fortress') {
      return `${base} Forcing Canvas here skips the non-Vault origin-taint setup, so prototype-call 2D readback is not browser-blocked — Auto/WebGL is the stronger pairing.`;
    }
    return `${base} Prototype-call readback is browser-blocked only when the origin-taint pixel actually loads.`;
  }

  function modeInfo() {
    const r = effectiveRenderer();
    const branch = r === 'webgl'
      ? 'On this branch the still-scrambled bitmap becomes a GPU texture and the fragment shader maps every displayed fragment back to its source tile and mirror — no clean CPU working canvas for the static image.'
      : 'On this branch a private Canvas 2D working canvas assembles the tiles at backing-store size, paints the guarded display canvas, then is zeroed; the visible canvas necessarily holds the pixels being shown.';
    switch (flowState.mode) {
      case 'lite':
        return {
          title: 'Lite — the lightweight baseline',
          text: `Lite keeps the guarded viewer but defaults client forensic marking off, so this chart's final view carries server marks only unless a host explicitly adds forensic: true. Catalog batching and width buckets come from presets or direct flags, not from the mode name alone. ${branch}`,
        };
      case 'vault':
        return {
          title: 'Vault — shader-first viewing',
          text: `Vault chooses WebGL when the renderer is left on auto, keeping tile assembly in the shader and the drawing buffer non-preserved. ${branch}`,
        };
      case 'fortress':
        return {
          title: 'Fortress — Vault plus capture friction',
          text: `Fortress normalizes to the Vault path and adds capture shielding, strike lockout, DevTools blanking and integrity locking by default. Literal 60 Hz temporal interlace is opt-in in bare Fortress mode; the elite and maxProtection presets enable balanced60. When interlace is active, the checker shimmer in the final frames indicates that temporal split; screenshots and cameras can still capture a degraded display, and multi-frame capture can recombine it. ${branch}`,
        };
      case 'custom':
        return {
          title: 'Custom — no bundle, direct flags only',
          text: `Custom adds no mode bundle: ordinary framework defaults apply until the host's own flags override them, and the renderer selection decides whether the internal path behaves like the Canvas or WebGL branch. It is the escape hatch for hand-picking protections instead of accepting a preset personality. ${branch}`,
        };
      default:
        return {
          title: 'Shield — the default viewer',
          text: `Shield is the default mode. With the renderer on auto it takes the Canvas 2D branch; choosing WebGL here promotes the same delivery to the shader branch without changing what the server sends. ${branch}`,
        };
    }
  }

  function flowStages() {
    const r = effectiveRenderer();
    const marks = activeMarks();
    const pop = flowState.opts.pop;
    const enc = flowState.opts.encrypt;
    return [
      {
        zone: 'SERVER · PRIVATE',
        title: 'The master goes in — and stays there',
        short: 'Indexed by ID outside public roots declared to Archx; undeclared host mounts remain the operator’s responsibility.',
        body: 'The original is indexed by image ID in a masters directory outside every public root declared to Archx. Startup rejects overlap with declared roots and contains paths/symlinks; undeclared host mounts remain the operator’s responsibility, and no Archx route returns the original file.',
      },
      {
        zone: 'BROWSER → SERVER · TOKEN REQUEST',
        title: 'The browser asks first',
        short: pop
          ? 'The viewer measures its box and requests a token for that ID and size, sending the public half of its proof key. No pixels move yet.'
          : 'The viewer measures its box and requests a token for that ID and size. No pixels or master path move yet.',
        body: `The loader waits for a stable display box, derives the needed width from CSS size, device-pixel ratio and oversampling (snapped to canonical buckets only if configured), then requests a token for the image ID. ${pop ? 'In this illustrated delivery it also sends the public proof-of-possession key; the private half never leaves the browser.' : 'No proof key is supplied in this illustrated delivery.'}`,
      },
      {
        zone: 'SERVER · AUTHORIZE + SIGN',
        title: 'The server decides and signs',
        short: enc
          ? 'Authorization and entitlement caps run before the HMAC token, scramble key, grid, expiry and one-view AES key are returned.'
          : 'Authorization and entitlement caps run before the HMAC token, scramble key, grid and expiry are returned.',
        body: `Rate limits and the host's deny-by-default authorize callback run first, unless the deployment explicitly chooses public anonymous delivery. The entitlement caps width, quality and format and may bind viewer/trace and mark choices. Only then does the server HMAC-sign allowlisted claims and return a clean payload URL, token, scramble key, grid and expiry${enc ? ', plus the one-view AES key' : ''}. An authorized browser necessarily receives viewing keys — that is access control, not DRM.`,
      },
      {
        zone: 'BROWSER → SERVER · REDEEM',
        title: 'The token is redeemed and spent',
        short: pop
          ? 'The payload request carries the token and a signature from the matching private proof key; checks pass, then the one-time claim is spent.'
          : 'The payload request carries the token; signature, expiry, bindings and a second authorization run before the one-time claim is spent.',
        body: `The viewer fetches the clean payload URL with the token${pop ? ' and a fresh proof signature bound to that token, method and target' : ''}. The server verifies canonical encoding, HMAC and expiry${pop ? ', verifies the proof' : ''}, re-runs authorize for the image phase, checks viewer/trace bindings, and only then atomically spends the one-time claim. A current entitlement may tighten signed width or quality, but the exact output format is pinned in the token; a format mismatch is denied and requires a newly minted token. No current policy can widen signed claims.`,
      },
      {
        zone: 'SERVER · SHARP DERIVATIVE',
        title: 'Sharp builds only the entitled derivative',
        short: 'Cold path shown: bytes are sniffed and budget-checked, decoded, orientation-baked when needed, and resized. Validated cache hits can skip repeated work.',
        body: 'The middleware resolves the indexed master and, on the cold path shown here, Sharp validates and decodes it under byte, pixel and time budgets, bakes EXIF orientation when present, and resizes to the signed, entitled width. That is not inherently the physical display size: maxWidthFraction defaults to 1, so native-width pixels can be delivered when other caps permit. The clean derivative base stays server-side; the master file and its metadata never enter the response.',
      },
      {
        zone: 'SERVER · OPTIONAL MARKS',
        title: marks.length ? 'Server marks are baked in' : 'Optional server marks are skipped',
        short: marks.length
          ? `Applied to derivative pixels in server order: ${marks.join(' → ')}. Copy-on-write keeps the cached clean base clean.`
          : 'All three optional server-mark branches are off in this configuration, so the clean derivative passes through unchanged.',
        body: marks.length
          ? `Enabled marks are applied to the derivative pixels before scrambling, in server order: ${marks.join(' → ')}. They are baked into a per-view copy, not into the cached clean base. In the drawing, faint rust dots exaggerate StegoMark so an invisible layer is visible for teaching. If ownership claims are configured, the signed perceptual claim is also derived from these final pre-scramble pixels.`
          : 'With visible watermarking, server forensic blocks and StegoMark all off, this stage is a pass-through. That costs nothing in image quality, but a later screenshot or re-upload carries no server-baked attribution layer from this delivery.',
      },
      {
        zone: 'SERVER → WIRE · PACKAGE',
        title: 'Tiles are scrambled and packaged',
        short: enc
          ? 'Keyed padding and the 8×8 plan-v2 tile permutation are encoded, wrapped as .archx, then sealed with AES-256-GCM.'
          : 'Keyed padding and the 8×8 plan-v2 tile permutation are encoded and wrapped as .archx. Scramble alone is obfuscation, not encryption.',
        body: `A fused pass writes keyed padding and mirrored, permuted tiles; the result is image-encoded (WebP by default) and wrapped in the .archx container with its dimensions, grid and mark flags. ${enc ? 'Because encrypt is on in this illustration, the encoded payload is then sealed with AES-256-GCM.' : 'Because encrypt is off here, network confidentiality rests on HTTPS; tile obfuscation adds no secrecy, and a captured payload can be reconstructed with enough work.'} Either way, page source contains no master URL.`,
      },
      {
        zone: 'BROWSER · OPEN PAYLOAD',
        title: 'The browser opens the payload',
        short: 'Bounded fetch, strict .archx and geometry checks, optional AES-GCM decrypt, then decode — the bitmap is still a scrambled mosaic.',
        body: `The viewer fetches with size and time bounds, strictly validates the container and padded geometry${enc ? ', decrypts the sealed payload' : ''}, sniffs the encoded image before decoding, and verifies the decoded bitmap against the header. At the end of this stage the browser holds only the still-scrambled derivative bitmap and the inverse tile plan.`,
      },
      {
        zone: r === 'webgl' ? 'BROWSER · WEBGL RENDER' : 'BROWSER · CANVAS RENDER',
        title: r === 'webgl' ? 'The WebGL shader renders the view' : 'Canvas 2D assembles the view',
        short: r === 'webgl'
          ? `${cap(flowState.mode)} uploads the scrambled bitmap as a texture; the shader maps each fragment to its source tile/flip${clientForensicOn() ? ' and can add the client forensic pass' : ''}.`
          : `${cap(flowState.mode)} assembles tiles in a private working canvas${clientForensicOn() ? ', bakes configured client marks,' : ''} paints the guarded display canvas, then zeroes the work canvas.`,
        body: r === 'webgl'
          ? `The scrambled bitmap is uploaded as a texture beside a tile-map texture. The fragment shader performs the un-scramble per fragment, so the static path needs no clean CPU working canvas; the drawing buffer is presented without preservation, which is why later GL readback sees black.${flowState.mode === 'fortress' ? ' Fortress also releases the source bitmap after upload and can temporally split the presented frames.' : ''}`
          : `Canvas mode assembles the full derivative once in a private working canvas${clientForensicOn() ? ', bakes any configured client watermark/forensic blocks,' : ' (Lite leaves client forensic marking off by default),'} paints the visible guarded canvas, then zeroes the working canvas. Optional split canvases slice that one composed frame; Lens and temporal modes are the deliberate exceptions that retain a private frame.`,
      },
      {
        zone: 'OUTPUT · WHAT CAN COME OUT',
        title: 'What can come out',
        short: `The visitor sees the entitled derivative. Network capture gets ${enc ? 'encrypted scrambled' : 'scrambled'} bytes; programmatic readback gets the ${flowState.extract} result; screenshots remain possible at the server-authorized width, which may be native width.`,
        body: `The legitimate visitor sees the authorized derivative; its width is bound by server policy and may reach native width unless maxWidthFraction is below 1. Network tools and page source get ${enc ? 'AES-sealed scrambled' : 'scrambled'} payload bytes and no master. Programmatic readback follows the selected renderer and onExtract branch. A screenshot, OS capture or camera still sees what was displayed — bounded by configured server width caps (which may allow native width)${marks.length || clientForensicOn() ? ' and carrying the enabled marks for later corroborated rescanning' : ''}${flowState.mode === 'fortress' ? ', with Fortress temporal/capture friction raising effort but not preventing capture' : ''}.`,
      },
    ];
  }

  function makeFlowArt(marked, markOpts = flowState.opts) {
    const c = document.createElement('canvas');
    c.width = 320;
    c.height = 200;
    const x = c.getContext('2d');
    if (!x) return c;
    const sky = x.createLinearGradient(0, 0, 0, 132);
    sky.addColorStop(0, '#8fb8c9');
    sky.addColorStop(1, '#f0d9a8');
    x.fillStyle = sky;
    x.fillRect(0, 0, 320, 132);
    x.fillStyle = '#d9903c';
    x.beginPath();
    x.arc(254, 42, 20, 0, 6.3);
    x.fill();
    x.fillStyle = '#476b73';
    x.beginPath();
    x.moveTo(0, 126); x.lineTo(74, 62); x.lineTo(126, 108); x.lineTo(174, 50);
    x.lineTo(250, 118); x.lineTo(320, 78); x.lineTo(320, 132); x.lineTo(0, 132);
    x.closePath();
    x.fill();
    x.fillStyle = '#29484f';
    x.beginPath();
    x.moveTo(0, 132); x.lineTo(92, 86); x.lineTo(164, 124); x.lineTo(238, 82);
    x.lineTo(320, 126); x.lineTo(320, 146); x.lineTo(0, 146);
    x.closePath();
    x.fill();
    x.fillStyle = '#71854a';
    x.fillRect(0, 140, 320, 60);
    x.fillStyle = '#e8dcc0';
    x.beginPath();
    x.moveTo(138, 200); x.lineTo(166, 142); x.lineTo(184, 142); x.lineTo(196, 200);
    x.closePath();
    x.fill();
    x.fillStyle = '#223d2c';
    [34, 58, 276, 296].forEach((tx) => {
      x.fillRect(tx + 5, 150, 5, 20);
      x.beginPath();
      x.moveTo(tx - 4, 154); x.lineTo(tx + 8, 126); x.lineTo(tx + 20, 154);
      x.closePath();
      x.fill();
    });

    if (marked) {
      if (markOpts.serverForensic) {
        for (let gy = 0; gy < 5; gy++) {
          for (let gx = 0; gx < 8; gx++) {
            const v = Math.sin(gx * 12.9898 + gy * 78.233) * 43758.5453;
            x.fillStyle = (v - Math.floor(v)) > 0.5 ? 'rgba(255,253,247,.13)' : 'rgba(25,22,18,.11)';
            x.fillRect(gx * 40, gy * 40, 40, 40);
          }
        }
      }
      if (markOpts.watermark) {
        x.save();
        x.translate(160, 100);
        x.rotate(-0.32);
        x.font = '700 16px ui-monospace, monospace';
        x.fillStyle = 'rgba(255,253,247,.55)';
        x.fillText('© ARCHX · VIEW 7F3A', -132, -28);
        x.fillText('© ARCHX · VIEW 7F3A', -104, 24);
        x.fillText('© ARCHX · VIEW 7F3A', -148, 76);
        x.restore();
      }
      if (markOpts.stego) {
        x.fillStyle = 'rgba(180,61,38,.58)';
        for (let i = 0; i < 58; i++) {
          const px = 12 + ((Math.sin(i * 91.17) * 0.5 + 0.5) * 296);
          const py = 12 + ((Math.cos(i * 47.31) * 0.5 + 0.5) * 176);
          x.beginPath();
          x.arc(px, py, 1.7, 0, 6.3);
          x.fill();
        }
      }
    }
    return c;
  }

  const cleanArt = makeFlowArt(false);
  let markedArt = cleanArt;
  let markedLayerArts = [];
  function flowMarkLayers() {
    const all = [
      { key: 'watermark', label: 'visible ©' },
      { key: 'serverForensic', label: 'forensic blocks' },
      { key: 'stego', label: 'StegoMark dots' },
    ];
    return all.filter((layer) => flowState.opts[layer.key]);
  }
  function rebuildFlowArtwork() {
    markedArt = makeFlowArt(true);
    const subset = { watermark: false, serverForensic: false, stego: false };
    markedLayerArts = flowMarkLayers().map((layer) => {
      subset[layer.key] = true;
      return { ...layer, art: makeFlowArt(true, { ...subset }) };
    });
  }
  rebuildFlowArtwork();

  const lowArt = document.createElement('canvas');
  lowArt.width = 36;
  lowArt.height = 23;
  const lowCtx = lowArt.getContext('2d');

  function drawFlowLock(cx, cy, s = 1) {
    if (!fctx) return;
    fctx.save();
    fctx.translate(cx, cy);
    fctx.scale(s, s);
    fctx.fillStyle = '#e7eeff';
    fctx.strokeStyle = INK;
    fctx.lineWidth = 2;
    fctx.fillRect(-11, -2, 22, 17);
    fctx.strokeRect(-11, -2, 22, 17);
    fctx.beginPath();
    fctx.arc(0, -3, 7, Math.PI, 0);
    fctx.stroke();
    fctx.fillStyle = INK;
    fctx.beginPath();
    fctx.arc(0, 6, 3, 0, 6.3);
    fctx.fill();
    fctx.restore();
  }

  function drawFlowImage(art, x, y, w, h, o = {}) {
    if (!fctx || !art) return;
    const scramble = clamp01(o.scramble || 0);
    const encrypt = clamp01(o.encrypt || 0);
    fctx.save();
    fctx.globalAlpha = o.alpha ?? 1;
    fctx.beginPath();
    fctx.rect(x, y, w, h);
    fctx.clip();
    if (o.black) {
      fctx.fillStyle = '#090908';
      fctx.fillRect(x, y, w, h);
      fctx.fillStyle = 'rgba(236,227,208,.72)';
      fctx.font = '700 13px ui-monospace, monospace';
      fctx.textAlign = 'center';
      fctx.fillText('ARCHX', x + w / 2, y + h / 2 + 4);
      fctx.textAlign = 'left';
    } else {
      let source = art;
      if (o.pixelate && lowCtx) {
        lowCtx.clearRect(0, 0, lowArt.width, lowArt.height);
        lowCtx.drawImage(art, 0, 0, lowArt.width, lowArt.height);
        source = lowArt;
        fctx.imageSmoothingEnabled = false;
      } else {
        fctx.imageSmoothingEnabled = true;
      }
      if (scramble <= 0.001) {
        fctx.drawImage(source, x, y, w, h);
      } else {
        const g = 8;
        const sw = source.width / g;
        const sh = source.height / g;
        const dw = w / g;
        const dh = h / g;
        const e = ease(scramble);
        fctx.fillStyle = INK;
        fctx.fillRect(x, y, w, h);
        for (let orig = 0; orig < 64; orig++) {
          const dest = flowPlan.inverse[orig];
          const ox = x + (orig % g) * dw;
          const oy = y + Math.floor(orig / g) * dh;
          const tx = x + (dest % g) * dw;
          const ty = y + Math.floor(dest / g) * dh;
          const delay = (((orig * 29) % 17) / 17) * 0.2;
          const le = ease(clamp01((e - delay) / 0.8));
          let dx = lerp(ox, tx, le);
          let dy = lerp(oy, ty, le);
          const vx = tx - ox;
          const vy = ty - oy;
          const dist = Math.hypot(vx, vy);
          if (dist > 0.5) {
            const bow = Math.sin(Math.PI * le) * Math.min(15, dist * 0.13) * (orig % 2 ? 1 : -1);
            dx += (-vy / dist) * bow;
            dy += (vx / dist) * bow;
          }
          const flip = le > 0.55 ? flowPlan.flips[dest] : { fx: false, fy: false };
          const lift = 1 + Math.sin(Math.PI * le) * 0.06;
          fctx.save();
          fctx.translate(dx + dw / 2, dy + dh / 2);
          fctx.scale((flip.fx ? -1 : 1) * lift, (flip.fy ? -1 : 1) * lift);
          fctx.drawImage(source, (orig % g) * sw, Math.floor(orig / g) * sh, sw, sh, -dw / 2, -dh / 2, dw + 0.6, dh + 0.6);
          fctx.restore();
        }
      }
      if (o.client) {
        for (let gy = 0; gy < 4; gy++) {
          for (let gx = 0; gx < 6; gx++) {
            const v = Math.sin(gx * 19.19 + gy * 7.7) * 24634.63;
            fctx.fillStyle = (v - Math.floor(v)) > 0.5 ? 'rgba(255,253,247,.12)' : 'rgba(25,22,18,.10)';
            fctx.fillRect(x + (gx * w) / 6, y + (gy * h) / 4, w / 6, h / 4);
          }
        }
      }
      if (o.temporal) {
        const cell = 15;
        const ph = Math.floor(flowState.now / 480) % 2;
        fctx.fillStyle = 'rgba(25,22,18,.17)';
        for (let yy = y, iy = 0; yy < y + h; yy += cell, iy++) {
          for (let xx = x, ix = 0; xx < x + w; xx += cell, ix++) {
            if ((ix + iy + ph) % 2 === 0) fctx.fillRect(xx, yy, cell, cell);
          }
        }
      }
      if (encrypt > 0) {
        fctx.fillStyle = `rgba(11,13,19,${encrypt * 0.76})`;
        fctx.fillRect(x, y, w, h);
        for (let gy = 0; gy < 5; gy++) {
          for (let gx = 0; gx < 7; gx++) {
            const v = Math.sin(gx * 31.7 + gy * 17.3) * 12345.67;
            if ((v - Math.floor(v)) > 0.45) {
              fctx.fillStyle = `rgba(236,227,208,${encrypt * 0.13})`;
              fctx.fillRect(x + (gx * w) / 7, y + (gy * h) / 5, w / 7, h / 5);
            }
          }
        }
        if (w > 88 && encrypt > 0.25) drawFlowLock(x + w / 2, y + h / 2, 1);
      }
    }
    fctx.restore();
    fctx.strokeStyle = 'rgba(25,22,18,.78)';
    fctx.lineWidth = 1;
    fctx.strokeRect(x + 0.5, y + 0.5, w - 1, h - 1);
  }

  function flowText(txt, x, y, font = '12px ui-monospace, monospace', color = INK, align = 'left') {
    if (!fctx) return;
    fctx.font = font;
    fctx.fillStyle = color;
    fctx.textAlign = align;
    fctx.fillText(txt, x, y);
    fctx.textAlign = 'left';
  }
  function flowBadge(txt, x, y, active = true) {
    if (!fctx) return 0;
    fctx.font = '700 11px ui-monospace, monospace';
    const w = Math.ceil(fctx.measureText(txt).width) + 18;
    fctx.fillStyle = active ? INK : 'transparent';
    fctx.strokeStyle = INK;
    fctx.lineWidth = 1;
    fctx.fillRect(x, y, w, 24);
    fctx.strokeRect(x + 0.5, y + 0.5, w - 1, 23);
    flowText(txt, x + 9, y + 16, '700 11px ui-monospace, monospace', active ? '#f4f7fb' : MUTED);
    return w + 8;
  }
  function flowPacket(x, y, w, h, title, lines) {
    if (!fctx) return;
    fctx.fillStyle = '#ffffff';
    fctx.strokeStyle = INK;
    fctx.lineWidth = 1.4;
    fctx.fillRect(x, y, w, h);
    fctx.strokeRect(x + 0.5, y + 0.5, w - 1, h - 1);
    fctx.fillStyle = ACCENT;
    fctx.fillRect(x, y, w, 4);
    flowText(title, x + 10, y + 22, '700 12px ui-monospace, monospace');
    lines.forEach((line, i) => flowText(line, x + 10, y + 41 + i * 16, '11px ui-monospace, monospace', MUTED));
  }
  function flowChecks(x, y, w, title, lines, reveal) {
    if (!fctx) return;
    const h = 40 + lines.length * 22;
    fctx.fillStyle = '#ffffff';
    fctx.strokeStyle = INK;
    fctx.lineWidth = 1.3;
    fctx.fillRect(x, y, w, h);
    fctx.strokeRect(x + 0.5, y + 0.5, w - 1, h - 1);
    flowText(title, x + 11, y + 22, '700 12px ui-monospace, monospace', ACCENT);
    const shown = Math.floor(clamp01(reveal) * lines.length + 0.001);
    lines.forEach((line, i) => {
      flowText(`${i < shown ? '✓' : '·'} ${line}`, x + 11, y + 46 + i * 22, '11.5px ui-monospace, monospace', i < shown ? INK : '#8290a6');
    });
  }
  function flowEmpty(x, y, w, h, lines) {
    if (!fctx) return;
    fctx.save();
    fctx.setLineDash([6, 5]);
    fctx.strokeStyle = '#8290a6';
    fctx.lineWidth = 1.2;
    fctx.strokeRect(x, y, w, h);
    fctx.restore();
    lines.forEach((line, i) => flowText(line, x + w / 2, y + h / 2 - (lines.length - 1) * 8 + i * 17, '700 11px ui-monospace, monospace', MUTED, 'center'));
  }
  function flowArrow(x1, y, x2) {
    if (!fctx) return;
    fctx.save();
    fctx.strokeStyle = ACCENT;
    fctx.fillStyle = ACCENT;
    fctx.lineWidth = 2;
    fctx.beginPath();
    fctx.moveTo(x1, y);
    fctx.lineTo(x2, y);
    fctx.stroke();
    const dir = x2 >= x1 ? 1 : -1;
    fctx.beginPath();
    fctx.moveTo(x2, y);
    fctx.lineTo(x2 - dir * 9, y - 5);
    fctx.lineTo(x2 - dir * 9, y + 5);
    fctx.closePath();
    fctx.fill();
    fctx.restore();
  }
  function flowCurvePoint(p, tt) {
    const u = clamp01(tt);
    const v = 1 - u;
    return [
      v * v * v * p[0][0] + 3 * v * v * u * p[1][0] + 3 * v * u * u * p[2][0] + u * u * u * p[3][0],
      v * v * v * p[0][1] + 3 * v * v * u * p[1][1] + 3 * v * u * u * p[2][1] + u * u * u * p[3][1],
    ];
  }
  function flowCurve(p, progress = 1, color = ACCENT, dashed = false) {
    if (!fctx) return;
    const end = clamp01(progress);
    if (end <= 0) return;
    fctx.save();
    fctx.strokeStyle = color;
    fctx.fillStyle = color;
    fctx.lineWidth = 2;
    if (dashed) fctx.setLineDash([6, 5]);
    fctx.beginPath();
    const steps = Math.max(2, Math.round(44 * end));
    for (let i = 0; i <= steps; i++) {
      const [x, y] = flowCurvePoint(p, (i / steps) * end);
      if (i === 0) fctx.moveTo(x, y); else fctx.lineTo(x, y);
    }
    fctx.stroke();
    fctx.setLineDash([]);
    const [x2, y2] = flowCurvePoint(p, end);
    const [x1, y1] = flowCurvePoint(p, Math.max(0, end - 0.02));
    const a = Math.atan2(y2 - y1, x2 - x1);
    fctx.beginPath();
    fctx.moveTo(x2, y2);
    fctx.lineTo(x2 - 10 * Math.cos(a - 0.42), y2 - 10 * Math.sin(a - 0.42));
    fctx.lineTo(x2 - 10 * Math.cos(a + 0.42), y2 - 10 * Math.sin(a + 0.42));
    fctx.closePath();
    fctx.fill();
    fctx.restore();
  }
  function flowPulse(p, tt, color = ACCENT, r = 6) {
    if (!fctx) return;
    const [x, y] = flowCurvePoint(p, tt);
    fctx.save();
    fctx.fillStyle = '#ffffff';
    fctx.strokeStyle = color;
    fctx.lineWidth = 2;
    fctx.beginPath();
    fctx.arc(x, y, r, 0, 6.3);
    fctx.fill();
    fctx.stroke();
    fctx.fillStyle = color;
    fctx.beginPath();
    fctx.arc(x, y, Math.max(2, r - 3), 0, 6.3);
    fctx.fill();
    fctx.restore();
  }
  function flowScanFrame(x, y, w, h, p, color = ACCENT) {
    if (!fctx) return;
    const q = clamp01(p);
    const sx = x + w * q;
    fctx.save();
    fctx.fillStyle = 'rgba(180,61,38,.08)';
    fctx.fillRect(x, y, Math.max(0, sx - x), h);
    fctx.strokeStyle = color;
    fctx.lineWidth = 2;
    fctx.beginPath();
    fctx.moveTo(sx, y - 4);
    fctx.lineTo(sx, y + h + 4);
    fctx.stroke();
    const c = 14;
    fctx.beginPath();
    fctx.moveTo(x - 5, y + c); fctx.lineTo(x - 5, y - 5); fctx.lineTo(x + c, y - 5);
    fctx.moveTo(x + w - c, y - 5); fctx.lineTo(x + w + 5, y - 5); fctx.lineTo(x + w + 5, y + c);
    fctx.moveTo(x + w + 5, y + h - c); fctx.lineTo(x + w + 5, y + h + 5); fctx.lineTo(x + w - c, y + h + 5);
    fctx.moveTo(x + c, y + h + 5); fctx.lineTo(x - 5, y + h + 5); fctx.lineTo(x - 5, y + h - c);
    fctx.stroke();
    fctx.restore();
  }
  function flowGate(x, y, w, h, open) {
    if (!fctx) return;
    const q = clamp01(open);
    fctx.save();
    fctx.strokeStyle = INK;
    fctx.fillStyle = INK;
    fctx.lineWidth = 2;
    fctx.strokeRect(x + 0.5, y + 0.5, w - 1, h - 1);
    const bars = 6;
    for (let i = 0; i < bars; i++) {
      const bx = x + 10 + i * ((w - 20) / (bars - 1));
      const top = y + 8 + q * (h - 18) * (0.45 + 0.09 * i);
      fctx.beginPath();
      fctx.moveTo(bx, top);
      fctx.lineTo(bx, y + h - 8);
      fctx.stroke();
    }
    fctx.restore();
  }
  function flowSeal(cx, cy, p, label = '✓') {
    if (!fctx) return;
    const q = clamp01(p);
    if (q <= 0) return;
    fctx.save();
    fctx.globalAlpha = Math.min(1, q * 1.4);
    fctx.translate(cx, cy);
    fctx.scale(0.55 + 0.45 * ease(q), 0.55 + 0.45 * ease(q));
    fctx.fillStyle = ACCENT;
    fctx.beginPath();
    fctx.arc(0, 0, 19, 0, 6.3);
    fctx.fill();
    fctx.strokeStyle = '#ffffff';
    fctx.lineWidth = 2;
    fctx.beginPath();
    fctx.arc(0, 0, 14.5, 0, 6.3);
    fctx.stroke();
    fctx.fillStyle = '#ffffff';
    fctx.font = '700 15px ui-monospace, monospace';
    fctx.textAlign = 'center';
    fctx.fillText(label, 0, 5.5);
    fctx.restore();
  }
  function drawFlowTimeline() {
    if (!fctx || !flowState.durations.length) return;
    const x0 = 18;
    const totalW = 944;
    const y = 41;
    const total = Math.max(1, flowState.routeMs);
    let x = x0;
    fctx.save();
    fctx.fillStyle = '#ddd0ae';
    fctx.fillRect(x0, y, totalW, 3);
    flowState.durations.forEach((ms, i) => {
      const w = (totalW * ms) / total;
      if (i < flowState.step) {
        fctx.fillStyle = ACCENT;
        fctx.fillRect(x, y, w, 3);
      } else if (i === flowState.step) {
        fctx.fillStyle = INK;
        fctx.fillRect(x, y, w * clamp01(flowState.t), 3);
        fctx.fillStyle = ACCENT;
        fctx.beginPath();
        fctx.arc(x + w * clamp01(flowState.t), y + 1.5, 4, 0, 6.3);
        fctx.fill();
      }
      x += w;
      fctx.fillStyle = '#fcfaf5';
      fctx.fillRect(Math.min(961, x - 0.5), y - 2, 1, 7);
    });
    fctx.restore();
  }
  function drawFlowZones() {
    if (!fctx || !flowCanvas) return;
    fctx.clearRect(0, 0, flowCanvas.width, flowCanvas.height);
    fctx.fillStyle = '#fcfaf5';
    fctx.fillRect(0, 0, flowCanvas.width, flowCanvas.height);
    fctx.fillStyle = '#f5ede0';
    fctx.fillRect(18, 48, 492, 340);
    fctx.fillStyle = '#edf0e6';
    fctx.fillRect(594, 48, 368, 340);
    fctx.strokeStyle = INK;
    fctx.lineWidth = 1.4;
    fctx.strokeRect(18.5, 48.5, 491, 339);
    fctx.strokeRect(594.5, 48.5, 367, 339);
    fctx.save();
    fctx.setLineDash([5, 5]);
    fctx.strokeStyle = '#b9ab8b';
    fctx.strokeRect(510.5, 48.5, 83, 339);
    fctx.restore();
    flowText('SERVER · MASTERS + MIDDLEWARE + SHARP', 18, 32, '700 13px ui-monospace, monospace');
    flowText('WIRE', 552, 32, '700 13px ui-monospace, monospace', INK, 'center');
    flowText('BROWSER · ARCHX VIEWER', 594, 32, '700 13px ui-monospace, monospace');
    flowText('private master never leaves this side', 18, 410, '11px ui-monospace, monospace', MUTED);
    flowText('HTTPS', 552, 410, '11px ui-monospace, monospace', MUTED, 'center');
    flowText(rendererFact(), 962, 410, '11px ui-monospace, monospace', MUTED, 'right');
    drawFlowTimeline();
  }

  function drawFlow() {
    if (!fctx) return;
    drawFlowZones();
    const s = flowState.step;
    const t = flowState.t;
    const e = ease(t);
    const client = clientForensicOn();
    const temporal = flowState.mode === 'fortress';

    if (s === 0) {
      flowText('MASTER · PRIVATE DIRECTORY', 42, 84, '700 12px ui-monospace, monospace', ACCENT);
      drawFlowImage(cleanArt, 42, 98, 268, 168);
      flowPacket(336, 106, 148, 126, 'SERVER ONLY', ['no public route', 'read by ID', 'startup checked']);
      drawFlowLock(410, 262, 1.05);
      flowGate(42, 98, 268, 168, 1 - ease(phase(t, 0.02, 0.48)));
      flowCurve([[488, 178], [562, 92], [630, 120], [552, 220]], phase(t, 0.38, 0.9), SEAL, true);
      if (t > 0.72) {
        fctx.strokeStyle = SEAL;
        fctx.lineWidth = 3;
        fctx.beginPath();
        fctx.moveTo(540, 152); fctx.lineTo(564, 180);
        fctx.moveTo(564, 152); fctx.lineTo(540, 180);
        fctx.stroke();
      }
      flowEmpty(648, 98, 268, 168, ['NO PIXELS YET', 'no master URL']);
      flowText('Keep the master outside every public web root.', 42, 356, '600 16px Georgia, serif');
    } else if (s === 1) {
      flowText('MASTER STAYS PUT', 42, 88, '700 12px ui-monospace, monospace', ACCENT);
      drawFlowImage(cleanArt, 42, 102, 204, 128, { alpha: 0.72 });
      flowEmpty(648, 88, 268, 168, ['VIEWER BOX', 'CSS × DPR × oversample']);
      flowScanFrame(648, 88, 268, 168, phase(t, 0.02, 0.45));
      const reqPath = [[650, 282], [566, 212], [430, 350], [272, 282]];
      const reqP = ease(phase(t, 0.2, 1));
      flowCurve(reqPath, reqP, ACCENT, true);
      const [px, py] = flowCurvePoint(reqPath, reqP);
      flowPacket(px, py, 224, 68, 'TOKEN REQUEST · {id}', ['w · bw · bh · fit', flowState.opts.pop ? '+ proof public key' : 'no pixels · no path']);
      if (flowState.opts.pop) flowSeal(782, 274, phase(t, 0.08, 0.28), 'key');
      flowText('Permission and size are requested before any image bytes exist on the wire.', 42, 366, '600 15px Georgia, serif');
    } else if (s === 2) {
      drawFlowImage(cleanArt, 38, 102, 196, 123, { alpha: 0.62 });
      flowChecks(278, 84, 206, 'SERVER DECIDES', ['authorize viewer', 'cap width / quality', 'rate + quota', 'HMAC-sign claims'], phase(t, 0.08, 0.72));
      flowSeal(466, 102, phase(t, 0.64, 0.8));
      const tokPath = [[330, 292], [438, 208], [566, 336], [636, 292]];
      const tokP = ease(phase(t, 0.58, 1));
      if (t > 0.52) {
        flowCurve(tokPath, tokP, ACCENT, true);
        const [px, py] = flowCurvePoint(tokPath, tokP);
        flowPacket(px, py, 238, 68, 'TOKEN RESPONSE', ['clean URL · key · grid', flowState.opts.encrypt ? 'expiry · + AES key' : 'short expiry']);
      }
      flowEmpty(676, 96, 224, 140, t > 0.9 ? ['TOKEN HELD', 'briefly, in memory'] : ['WAITING', 'for permission']);
    } else if (s === 3) {
      drawFlowImage(cleanArt, 38, 102, 196, 123, { alpha: 0.62 });
      flowChecks(278, 78, 206, 'REDEEM GATE', ['verify HMAC + expiry', flowState.opts.pop ? 'verify proof signature' : 'no proof supplied', 'authorize again', 'check bindings', 'claimOnce → spent'], phase(t, 0.2, 0.94));
      flowGate(518, 150, 68, 118, phase(t, 0.24, 0.92));
      const getPath = [[640, 300], [562, 362], [458, 236], [340, 300]];
      const getP = ease(phase(t, 0, 0.62));
      flowCurve(getPath, getP, ACCENT, true);
      const [px, py] = flowCurvePoint(getPath, getP);
      flowPacket(px, py, 238, 64, 'GET PAYLOAD', ['X-Archx-Token', flowState.opts.pop ? '+ signed proof' : 'clean URL']);
      if (t > 0.86) {
        flowCurve([[820, 240], [700, 318], [610, 250], [586, 286]], phase(t, 0.86, 1), '#8290a6', true);
        flowText('replay ✗', 650, 374, '700 11px ui-monospace, monospace', SEAL);
      }
      if (t > 0.82) {
        fctx.save();
        fctx.translate(459, 332);
        fctx.rotate(-0.08);
        fctx.strokeStyle = ACCENT;
        fctx.lineWidth = 2;
        fctx.strokeRect(-58, -15, 116, 30);
        flowText('SPENT ONCE', 0, 5, '700 13px ui-monospace, monospace', ACCENT, 'center');
        fctx.restore();
      }
      flowEmpty(676, 96, 224, 140, ['TOKEN SENT BACK', 'for one payload']);
    } else if (s === 4) {
      flowText(t < 0.5 ? 'MASTER · SNIFF + DECODE SCAN' : 'ENTITLED DERIVATIVE · WIDTH POLICY', 105, 88, '700 12px ui-monospace, monospace', ACCENT);
      fctx.save();
      fctx.setLineDash([6, 5]);
      fctx.strokeStyle = '#8290a6';
      fctx.lineWidth = 1.2;
      fctx.strokeRect(105.5, 102.5, 299, 187);
      fctx.restore();
      const shrink = ease(phase(t, 0.45, 0.88));
      const iw = lerp(300, 218, shrink);
      const ih = lerp(188, 136, shrink);
      drawFlowImage(cleanArt, 255 - iw / 2, 196 - ih / 2, iw, ih);
      flowScanFrame(105, 102, 300, 188, phase(t, 0.05, 0.45));
      if (t > 0.45) flowText('master bounds stay behind', 255, 310, '11px ui-monospace, monospace', MUTED, 'center');
      let bx = 70;
      bx += flowBadge('sniff + budgets', bx, 324, t > 0.18);
      bx += flowBadge('decode + orient', bx, 324, t > 0.44);
      flowBadge('resize to entitlement', bx, 324, t > 0.7);
      flowText('Only the signed, entitled width is built; preview-only needs a fraction cap.', 38, 366, '600 15px Georgia, serif');
      flowEmpty(676, 102, 224, 140, ['WAITING', 'response not started']);
    } else if (s === 5) {
      flowText('DERIVATIVE PIXELS · SERVER COPY', 94, 78, '700 12px ui-monospace, monospace', ACCENT);
      drawFlowImage(cleanArt, 94, 92, 322, 201);
      const layers = markedLayerArts;
      let bx = 94;
      if (layers.length) {
        const seg = 0.72 / layers.length;
        layers.forEach((layer, i) => {
          const start = 0.12 + i * seg;
          const p = ease(phase(t, start, start + seg));
          if (p > 0) {
            const off = (1 - p) * 24;
            drawFlowImage(layer.art, 94 - off, 92 - off * 0.62, 322, 201, { alpha: 0.25 + 0.75 * p });
          }
          bx += flowBadge(layer.label, bx, 318, p > 0.82);
        });
        if (flowState.opts.stego) flowText('Rust dots exaggerate the invisible StegoMark.', 94, 368, '11px ui-monospace, monospace', MUTED);
      } else {
        flowBadge('all optional marks OFF — pass through', bx, 318, false);
        flowScanFrame(94, 92, 322, 201, phase(t, 0.1, 0.8), '#8290a6');
      }
      flowEmpty(676, 108, 224, 140, ['STILL SERVER-SIDE', 'nothing sent yet']);
    } else if (s === 6) {
      flowText('.ARCHX PACKAGE', 94, 78, '700 12px ui-monospace, monospace', ACCENT);
      drawFlowImage(markedArt, 94, 92, 322, 201, {
        scramble: phase(t, 0, 0.68),
        encrypt: flowState.opts.encrypt ? phase(t, 0.68, 1) : 0,
      });
      if (t > 0.52) {
        const closeP = ease(phase(t, 0.52, 0.8));
        const inset = lerp(14, 0, closeP);
        fctx.save();
        fctx.strokeStyle = INK;
        fctx.lineWidth = 2;
        fctx.strokeRect(94 - inset + 0.5, 92 - inset + 0.5, 322 + inset * 2 - 1, 201 + inset * 2 - 1);
        fctx.fillStyle = ACCENT;
        fctx.fillRect(94, 92, 322 * clamp01(phase(t, 0.52, 0.72)), 6);
        fctx.restore();
      }
      flowSeal(416, 92, phase(t, 0.74, 0.92), flowState.opts.encrypt ? 'AES' : '✓');
      let bx = 94;
      bx += flowBadge('8×8 plan v2 + mirrors', bx, 318, t > 0.25);
      bx += flowBadge('.archx header', bx, 318, t > 0.55);
      flowBadge(flowState.opts.encrypt ? 'AES-256-GCM' : 'no AES layer', bx, 318, flowState.opts.encrypt && t > 0.72);
      flowEmpty(676, 108, 224, 140, ['READY TO SEND', 'derivative only']);
    } else if (s === 7) {
      flowText('MASTER STAYED', 40, 292, '700 11px ui-monospace, monospace', MUTED);
      drawFlowImage(cleanArt, 40, 302, 116, 73, { alpha: 0.45 });
      const wirePath = [[72, 94], [245, 34], [455, 238], [642, 94]];
      const wireCenter = [[206, 178], [360, 96], [548, 286], [776, 178]];
      const wireP = ease(phase(t, 0, 0.78));
      flowCurve(wireCenter, wireP, ACCENT, true);
      const [px, py] = flowCurvePoint(wirePath, wireP);
      flowText(wireP < 0.98 ? 'ON THE WIRE' : 'VALIDATE · DECODED · STILL SCRAMBLED', px, Math.max(82, py - 12), '700 12px ui-monospace, monospace', ACCENT);
      drawFlowImage(markedArt, px, py, 268, 168, {
        scramble: 1,
        encrypt: flowState.opts.encrypt ? 1 - phase(t, 0.8, 1) : 0,
      });
      if (t > 0.78) flowScanFrame(642, 94, 268, 168, phase(t, 0.78, 1));
      if (t > 0.9) flowBadge('validated + decoded', 676, 292, true);
      flowText('What crossed is a bounded, scrambled derivative — never the master file.', 40, 360, '600 15px Georgia, serif');
    } else if (s === 8) {
      drawFlowImage(cleanArt, 42, 108, 178, 111, { alpha: 0.45 });
      flowText('MASTER · SERVER ONLY', 42, 242, '700 11px ui-monospace, monospace', MUTED);
      if (effectiveRenderer() === 'canvas') {
        flowText('PRIVATE CANVAS ASSEMBLY → DISPLAY', 650, 78, '700 12px ui-monospace, monospace', ACCENT);
        drawFlowImage(markedArt, 634, 82, 268, 168, { scramble: 1, alpha: 0.26 * (1 - phase(t, 0.6, 0.95)) });
        drawFlowImage(markedArt, 650, 94, 268, 168, {
          scramble: 1 - e,
          client: client && t > 0.55,
          temporal,
        });
        let bx = 650;
        bx += flowBadge(client ? 'client forensic baked' : 'client forensic off (Lite)', bx, 290, t > 0.55);
        if (t > 0.78) flowBadge('work canvas zeroed', bx, 290, true);
      } else {
        flowText('SCRAMBLED TEXTURE', 618, 76, '700 11px ui-monospace, monospace', ACCENT);
        drawFlowImage(markedArt, 618, 86, 124, 78, { scramble: 1 });
        flowArrow(746, 124, 768);
        flowText('SHADER OUTPUT', 772, 76, '700 11px ui-monospace, monospace', ACCENT);
        drawFlowImage(markedArt, 772, 86, 168, 105, { client: client && t > 0.5, temporal });
        if (t < 1) {
          fctx.fillStyle = 'rgba(252,250,245,.72)';
          fctx.fillRect(772, 86 + 105 * e, 168, 105 * (1 - e));
        }
        flowScanFrame(772, 86, 168, 105, phase(t, 0.05, 0.9));
        flowPulse([[742, 124], [750, 104], [760, 150], [772, 124]], (t * 1.6) % 1, ACCENT, 5);
        flowPacket(650, 232, 268, 66, 'FRAGMENT SHADER', ['tile map + mirrors per fragment', flowState.mode === 'fortress' && t > 0.74 ? 'source bitmap released' : 'no clean CPU work canvas']);
      }
    } else {
      flowText('NETWORK CAPTURE', 52, 86, '700 11px ui-monospace, monospace', ACCENT);
      drawFlowImage(markedArt, 52, 96, 190, 119, { scramble: 1, encrypt: flowState.opts.encrypt ? 1 : 0, alpha: ease(phase(t, 0.22, 0.48)) });
      flowScanFrame(52, 96, 190, 119, phase(t, 0.24, 0.48), '#8290a6');
      flowText('MASTER · NEVER SENT', 282, 86, '700 11px ui-monospace, monospace', MUTED);
      drawFlowImage(cleanArt, 282, 96, 174, 109, { alpha: 0.52 });
      drawFlowLock(369, 150, 0.9);
      flowText('VISITOR VIEW · ENTITLED DERIVATIVE', 650, 72, '700 11px ui-monospace, monospace', ACCENT);
      drawFlowImage(markedArt, 650, 82, 268, 150, { client, temporal, alpha: ease(phase(t, 0.02, 0.26)) });
      flowCurve([[744, 232], [730, 244], [724, 250], [716, 264]], phase(t, 0.48, 0.62), SEAL, true);
      flowCurve([[830, 232], [842, 244], [850, 250], [858, 264]], phase(t, 0.68, 0.82), ACCENT, true);
      flowText('READBACK', 650, 254, '700 11px ui-monospace, monospace', SEAL);
      drawFlowImage(markedArt, 650, 264, 132, 88, {
        black: flowState.extract === 'black',
        pixelate: flowState.extract !== 'black',
        scramble: flowState.extract === 'scrambled' ? 1 : 0,
        alpha: ease(phase(t, 0.52, 0.74)),
      });
      flowText('SCREENSHOT', 798, 254, '700 11px ui-monospace, monospace', ACCENT);
      drawFlowImage(markedArt, 798, 264, 120, 88, { client, temporal, alpha: ease(phase(t, 0.72, 0.94)) });
      flowText('Read-back may be poisoned; screenshots still capture the displayed derivative.', 52, 360, '600 15px Georgia, serif');
    }
  }

  function syncSeg(id, key, value) {
    $(id)?.querySelectorAll('button').forEach((b) => {
      const on = b.dataset[key] === value;
      b.classList.toggle('is-active', on);
      b.setAttribute('aria-pressed', String(on));
    });
  }
  function syncFlowTransport() {
    const play = $('flowPlay');
    if (play) {
      play.textContent = flowState.playing ? 'Pause' : 'Play';
      play.setAttribute('aria-pressed', String(flowState.playing));
      play.setAttribute('aria-label', flowState.playing ? 'Pause flowchart animation' : 'Play flowchart animation');
    }
    const prev = $('flowPrev');
    if (prev) prev.disabled = flowState.step === 0;
    const next = $('flowNext');
    if (next) next.disabled = flowState.step === 9;
  }
  function updateFlowText() {
    syncSeg('flowModeSeg', 'mode', flowState.mode);
    syncSeg('flowRendererSeg', 'renderer', flowState.renderer);
    syncSeg('flowExtractSeg', 'extract', flowState.extract);
    flowRoot.querySelectorAll('[data-flow-opt]').forEach((b) => {
      const on = !!flowState.opts[b.dataset.flowOpt];
      b.classList.toggle('is-active', on);
      b.setAttribute('aria-pressed', String(on));
    });
    const note = $('flowServerNote');
    if (note) {
      note.textContent = flowState.opts.pop
        ? 'One-time tokens are on by default in the middleware; this illustrated token is also sender-constrained to the browser’s proof key.'
        : 'One-time tokens are on by default in the middleware. Proof-of-possession is off in this illustration, so a stolen bearer token would need the server’s other limits and short expiry to contain it.';
    }
    const durations = refreshFlowDurations();
    const info = modeInfo();
    if ($('flowModeTitle')) $('flowModeTitle').textContent = info.title;
    if ($('flowModeText')) $('flowModeText').textContent = info.text;
    if ($('flowRendererOut')) $('flowRendererOut').textContent = rendererFact();
    if ($('flowWireOut')) $('flowWireOut').textContent = wireFact();
    if ($('flowExtractOut')) $('flowExtractOut').textContent = extractFact();

    const stages = flowStages();
    const cur = stages[flowState.step];
    if ($('flowZone')) $('flowZone').textContent = cur.zone;
    if ($('flowStageTitle')) $('flowStageTitle').textContent = `${flowState.step + 1} · ${cur.title}`;
    if ($('flowStageText')) $('flowStageText').textContent = cur.body;
    if ($('flowProgress')) {
      const delta = FLOW_LEGACY_TOTAL_MS - flowState.routeMs;
      const deltaText = delta >= 0
        ? `${formatFlowMs(delta)} shorter than the old fixed 3.3s × 10`
        : `${formatFlowMs(Math.abs(delta))} longer than the old fixed 3.3s × 10`;
      $('flowProgress').textContent = `Stage ${flowState.step + 1} of 10 · this stage ${formatFlowMs(durations[flowState.step])} · route ${formatFlowMs(flowState.routeMs)} (${deltaText})`;
    }
    flowRoot.querySelectorAll('.flow-step').forEach((btn) => {
      const idx = Number(btn.dataset.step);
      const on = idx === flowState.step;
      btn.classList.toggle('is-current', on);
      if (on) btn.setAttribute('aria-current', 'step');
      else btn.removeAttribute('aria-current');
      const strong = btn.querySelector('strong');
      if (strong) strong.textContent = stages[idx].title;
      const small = btn.querySelector('[data-flow-step-text]');
      if (small) small.textContent = `${stages[idx].short} · ${formatFlowMs(durations[idx])}`;
    });
    syncFlowTransport();
  }

  function ensureFlowLoop() {
    if (flowState.playing && !flowState.raf && flowState.visible && !document.hidden) {
      flowState.raf = requestAnimationFrame(flowFrame);
    }
  }
  function setFlowStep(step) {
    flowState.step = Math.max(0, Math.min(9, step | 0));
    flowState.t = reducedMotion ? 0.62 : 0;
    flowState.last = 0;
    updateFlowText();
    drawFlow();
    ensureFlowLoop();
  }
  function setFlowPlaying(on) {
    flowState.playing = !!on;
    flowState.last = 0;
    if (!flowState.playing && flowState.raf) {
      cancelAnimationFrame(flowState.raf);
      flowState.raf = 0;
    }
    syncFlowTransport();
    drawFlow();
    ensureFlowLoop();
  }
  function flowFrame(now) {
    flowState.raf = 0;
    if (!flowState.playing) return;
    if (!flowState.visible || document.hidden) {
      flowState.last = 0;
      return;
    }
    flowState.now = now;
    if (flowState.last) flowState.t += (now - flowState.last) / flowStageDuration();
    flowState.last = now;
    if (flowState.t >= 1) {
      if (flowState.step < 9) {
        setFlowStep(flowState.step + 1);
        return;
      }
      flowState.t = 1;
      flowState.playing = false;
      syncFlowTransport();
      drawFlow();
      return;
    }
    drawFlow();
    ensureFlowLoop();
  }

  $('flowModeSeg')?.addEventListener('click', (ev) => {
    const b = ev.target.closest('button[data-mode]');
    if (!b) return;
    flowState.mode = b.dataset.mode;
    updateFlowText();
    drawFlow();
  });
  $('flowRendererSeg')?.addEventListener('click', (ev) => {
    const b = ev.target.closest('button[data-renderer]');
    if (!b) return;
    flowState.renderer = b.dataset.renderer;
    updateFlowText();
    drawFlow();
  });
  $('flowExtractSeg')?.addEventListener('click', (ev) => {
    const b = ev.target.closest('button[data-extract]');
    if (!b) return;
    flowState.extract = b.dataset.extract;
    updateFlowText();
    drawFlow();
  });
  flowRoot.querySelectorAll('[data-flow-opt]').forEach((b) => {
    b.addEventListener('click', () => {
      const key = b.dataset.flowOpt;
      flowState.opts[key] = !flowState.opts[key];
      if (key === 'watermark' || key === 'serverForensic' || key === 'stego') rebuildFlowArtwork();
      updateFlowText();
      drawFlow();
    });
  });
  $('flowPrev')?.addEventListener('click', () => setFlowStep(flowState.step - 1));
  $('flowNext')?.addEventListener('click', () => setFlowStep(flowState.step + 1));
  $('flowRestart')?.addEventListener('click', () => {
    setFlowStep(0);
    if (!reducedMotion) setFlowPlaying(true);
  });
  $('flowPlay')?.addEventListener('click', () => {
    if (!flowState.playing && flowState.step === 9 && flowState.t >= 1) setFlowStep(0);
    setFlowPlaying(!flowState.playing);
  });
  flowRoot.querySelectorAll('.flow-step').forEach((b) => {
    b.addEventListener('click', () => setFlowStep(Number(b.dataset.step)));
  });

  if ('IntersectionObserver' in window) {
    new IntersectionObserver((entries) => {
      flowState.visible = entries.some((en) => en.isIntersecting);
      flowState.last = 0;
      if (flowState.visible) {
        drawFlow();
        ensureFlowLoop();
      }
    }, { threshold: 0.08 }).observe(flowRoot);
  }
  document.addEventListener('visibilitychange', () => {
    flowState.last = 0;
    if (!document.hidden) ensureFlowLoop();
  });

  updateFlowText();
  drawFlow();
  ensureFlowLoop();
}
