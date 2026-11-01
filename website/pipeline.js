/* Archnemix pipeline page — every artifact below is rendered live from one
 * procedurally painted "photograph", the same way the real pipeline derives
 * its artifacts from one master. No image files are loaded. */

const reducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/* The sample "photograph" (same painter as the overview page). */
function paintValley(w, h) {
  const c = document.createElement('canvas');
  c.width = w; c.height = h;
  const x = c.getContext('2d');
  const rand = mulberry32(0xa2c4e6);

  const sky = x.createLinearGradient(0, 0, 0, h * 0.72);
  sky.addColorStop(0, '#0b2620');
  sky.addColorStop(0.38, '#175144');
  sky.addColorStop(0.72, '#6d9a7e');
  sky.addColorStop(1, '#d9c9a3');
  x.fillStyle = sky;
  x.fillRect(0, 0, w, h);

  for (let i = 0; i < 220; i++) {
    const sx = rand() * w, sy = rand() * h * 0.42;
    x.fillStyle = `rgba(240,238,220,${0.12 + rand() * 0.5})`;
    x.fillRect(sx, sy, rand() < 0.12 ? 2 : 1, 1);
  }

  x.globalCompositeOperation = 'lighter';
  for (let band = 0; band < 3; band++) {
    const baseY = h * (0.13 + band * 0.085);
    const amp = h * (0.035 + band * 0.012);
    const phase = rand() * 6.28;
    for (let pass = 0; pass < 5; pass++) {
      x.beginPath();
      for (let px = -20; px <= w + 20; px += 8) {
        const py = baseY + Math.sin(px / w * 5.2 + phase) * amp + Math.sin(px / w * 13.7 + phase * 2) * amp * 0.35 + pass * 7;
        px === -20 ? x.moveTo(px, py) : x.lineTo(px, py);
      }
      x.strokeStyle = `rgba(${90 + band * 30},${220 - band * 18},${150},${0.05 + (4 - pass) * 0.012})`;
      x.lineWidth = 15 - pass * 2.4;
      x.stroke();
    }
  }
  x.globalCompositeOperation = 'source-over';

  const mx = w * 0.79, my = h * 0.2, mr = h * 0.055;
  const halo = x.createRadialGradient(mx, my, mr * 0.4, mx, my, mr * 4.2);
  halo.addColorStop(0, 'rgba(238,234,210,0.4)');
  halo.addColorStop(1, 'rgba(238,234,210,0)');
  x.fillStyle = halo;
  x.fillRect(mx - mr * 4.2, my - mr * 4.2, mr * 8.4, mr * 8.4);
  x.fillStyle = '#ece5cc';
  x.beginPath(); x.arc(mx, my, mr, 0, 6.29); x.fill();
  x.fillStyle = 'rgba(160,155,130,0.5)';
  x.beginPath(); x.arc(mx - mr * 0.3, my - mr * 0.15, mr * 0.16, 0, 6.29); x.fill();
  x.beginPath(); x.arc(mx + mr * 0.25, my + mr * 0.3, mr * 0.11, 0, 6.29); x.fill();

  const ridge = (baseY, jag, color, snow) => {
    x.beginPath();
    x.moveTo(-10, h + 10);
    let y = baseY;
    const peaks = [];
    for (let px = -10; px <= w + 10; px += 14) {
      y += (rand() - 0.5) * jag;
      y = Math.max(baseY - jag * 1.7, Math.min(baseY + jag * 0.7, y));
      x.lineTo(px, y);
      peaks.push([px, y]);
    }
    x.lineTo(w + 10, h + 10);
    x.closePath();
    x.fillStyle = color;
    x.fill();
    if (snow) {
      x.fillStyle = 'rgba(232,234,222,0.75)';
      for (const [px, py] of peaks) {
        if (py < baseY - jag * 0.75 && rand() < 0.7) {
          x.beginPath();
          x.moveTo(px - 9, py + 13); x.lineTo(px, py); x.lineTo(px + 9, py + 13);
          x.lineTo(px + 3, py + 9); x.lineTo(px, py + 13); x.lineTo(px - 4, py + 8);
          x.closePath(); x.fill();
        }
      }
    }
  };
  ridge(h * 0.56, h * 0.05, '#2a5647', true);
  ridge(h * 0.64, h * 0.045, '#1a4032', false);
  ridge(h * 0.72, h * 0.038, '#0f2c20', false);

  const lakeY = h * 0.8;
  const floor = x.createLinearGradient(0, lakeY - h * 0.06, 0, h);
  floor.addColorStop(0, '#14382a');
  floor.addColorStop(0.25, '#275c46');
  floor.addColorStop(0.55, '#173e2f');
  floor.addColorStop(1, '#08190f');
  x.fillStyle = floor;
  x.fillRect(0, lakeY - h * 0.045, w, h - lakeY + h * 0.045);
  for (let i = 0; i < 260; i++) {
    const lx = w * 0.79 + (rand() - 0.5) * w * 0.22 * (0.4 + rand());
    const ly = lakeY + rand() * (h - lakeY) * 0.92;
    x.fillStyle = `rgba(226,230,205,${0.05 + rand() * 0.22})`;
    x.fillRect(lx, ly, 3 + rand() * 16, 1.3);
  }
  for (let i = 0; i < 160; i++) {
    const lx = rand() * w, ly = lakeY + rand() * (h - lakeY) * 0.7;
    x.fillStyle = `rgba(110,210,160,${0.03 + rand() * 0.1})`;
    x.fillRect(lx, ly, 4 + rand() * 22, 1.2);
  }

  const pine = (px, ph) => {
    x.fillStyle = '#050d09';
    x.fillRect(px - 1.5, h - ph * 0.32, 3, ph * 0.32);
    for (let t = 0; t < 4; t++) {
      const tw = ph * (0.34 - t * 0.07), ty = h - ph * 0.25 - t * ph * 0.2;
      x.beginPath();
      x.moveTo(px - tw / 2, ty); x.lineTo(px, ty - ph * 0.34); x.lineTo(px + tw / 2, ty);
      x.closePath(); x.fill();
    }
  };
  for (let i = 0; i < 9; i++) pine(w * 0.02 + rand() * w * 0.1, h * (0.16 + rand() * 0.15));
  for (let i = 0; i < 8; i++) pine(w * 0.9 + rand() * w * 0.09, h * (0.14 + rand() * 0.16));
  for (let i = 0; i < 26; i++) pine(rand() * w, h * (0.045 + rand() * 0.05));

  for (let i = 0; i < 4200; i++) {
    x.fillStyle = rand() < 0.5 ? 'rgba(0,0,0,0.05)' : 'rgba(255,250,235,0.045)';
    x.fillRect(rand() * w, rand() * h, 1.3, 1.3);
  }
  const vig = x.createRadialGradient(w / 2, h / 2, h * 0.36, w / 2, h / 2, h * 0.95);
  vig.addColorStop(0, 'rgba(0,0,0,0)');
  vig.addColorStop(1, 'rgba(2,8,5,0.42)');
  x.fillStyle = vig;
  x.fillRect(0, 0, w, h);

  return c;
}

/* ---------- derived artifacts ---------- */
const W = 720, H = 405;
const master = paintValley(W, H);

function makeCanvas() {
  const c = document.createElement('canvas');
  c.width = W; c.height = H;
  return c;
}

function scrambledFrom(src, seed, tint) {
  const c = makeCanvas();
  const x = c.getContext('2d');
  const rand = mulberry32(seed);
  const cols = 8, rows = 8, tw = W / cols, th = H / rows;
  const order = Array.from({ length: cols * rows }, (_, i) => i);
  for (let i = order.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }
  for (let d = 0; d < order.length; d++) {
    const s = order[d];
    const sx = (s % cols) * tw, sy = Math.floor(s / cols) * th;
    const dx = (d % cols) * tw, dy = Math.floor(d / cols) * th;
    x.save();
    x.translate(dx + tw / 2, dy + th / 2);
    if (rand() < 0.5) x.scale(-1, 1);
    if (rand() < 0.5) x.scale(1, -1);
    x.drawImage(src, sx, sy, tw, th, -tw / 2, -th / 2, tw, th);
    x.restore();
  }
  if (tint) {
    const img = x.getImageData(0, 0, W, H);
    const d = img.data;
    for (let i = 0; i < d.length; i += 4) {
      d[i] ^= 0x3c; d[i + 1] ^= 0x5a; d[i + 2] ^= 0x27;
    }
    x.putImageData(img, 0, 0);
  }
  return c;
}

function noiseFrom(seed) {
  const c = makeCanvas();
  const x = c.getContext('2d');
  const rand = mulberry32(seed);
  const img = x.createImageData(W, H);
  const d = img.data;
  for (let i = 0; i < d.length; i += 4) {
    const v = Math.floor(rand() * 256);
    d[i] = v; d[i + 1] = Math.floor(rand() * 256); d[i + 2] = Math.floor(rand() * 256); d[i + 3] = 255;
  }
  x.putImageData(img, 0, 0);
  return c;
}

function lowResFrom(src) {
  const small = document.createElement('canvas');
  small.width = 72; small.height = 41;
  small.getContext('2d').drawImage(src, 0, 0, 72, 41);
  const c = makeCanvas();
  const x = c.getContext('2d');
  x.imageSmoothingEnabled = false;
  x.drawImage(small, 0, 0, W, H);
  return c;
}

function visitorFrom(src, label) {
  const c = makeCanvas();
  const x = c.getContext('2d');
  x.drawImage(src, 0, 0);
  x.save();
  x.translate(W / 2, H / 2);
  x.rotate(-0.32);
  x.font = '600 30px "IBM Plex Mono", monospace';
  x.textAlign = 'center';
  x.fillStyle = 'rgba(243,237,225,0.20)';
  for (let r = -2; r <= 2; r++) {
    for (let q = -1; q <= 1; q++) x.fillText(label, q * 380, r * 110);
  }
  x.restore();
  x.strokeStyle = 'rgba(243,237,225,0.35)';
  x.lineWidth = 2;
  x.strokeRect(8, 8, W - 16, H - 16);
  return c;
}

function blackWith(text) {
  const c = makeCanvas();
  const x = c.getContext('2d');
  x.fillStyle = '#0a0a09';
  x.fillRect(0, 0, W, H);
  x.font = '500 17px "IBM Plex Mono", monospace';
  x.textAlign = 'center';
  x.fillStyle = 'rgba(243,237,225,0.55)';
  x.fillText(text, W / 2, H / 2);
  return c;
}

function screenshotFrom(src) {
  const c = makeCanvas();
  const x = c.getContext('2d');
  x.drawImage(src, 0, 0);
  // temporal-interlace striping a still capture keeps, faint moiré
  x.fillStyle = 'rgba(0,0,0,0.16)';
  for (let y = 0; y < H; y += 4) x.fillRect(0, y, W, 1);
  x.save();
  x.translate(W / 2, H / 2);
  x.rotate(-0.32);
  x.font = '600 30px "IBM Plex Mono", monospace';
  x.textAlign = 'center';
  x.fillStyle = 'rgba(243,237,225,0.16)';
  for (let r = -2; r <= 2; r++) x.fillText('ARCHNEMIX · LICENSED COPY', 0, r * 110);
  x.restore();
  return c;
}

const wireCanvas = scrambledFrom(master, 0x51ab, true);
const payloadCanvas = scrambledFrom(master, 0x9e37, false);
const visitorCanvas = visitorFrom(master, 'ARCHNEMIX · PREVIEW');
const noiseCanvas = noiseFrom(0x77c1);
const lowResCanvas = lowResFrom(master);
const screenshotCanvas = screenshotFrom(master);

/* ---------- 01 · journey ---------- */
const stageFacts = [
  ['Stage 0 · your master', 'Full-resolution master on private disk, <strong>outside the web root</strong>. The web server has no route to it; nothing in any page references its path.'],
  ['Stage 1 · server processing', 'A derivative at (or below) the viewer&rsquo;s entitled width. The invisible <strong>StegoMark fingerprint</strong> for this recipient is embedded, tiles are permuted under a per-image key (plan v2), and vault modes add AES encryption.'],
  ['Stage 2 · on the wire', 'Served only against a <strong>one-time HMAC token</strong>, with <span class="mono">Cache-Control: private, no-store</span>. A captured response is permuted pieces tied to an already-spent token — replaying it returns 403.'],
  ['Stage 3 · visitor&rsquo;s screen', 'Reassembled <strong>only inside the guarded viewer</strong> (canvas or WebGL). There is no <span class="mono">&lt;img src&gt;</span> to save, and programmatic read-back is poisoned or blocked by canvas tainting.'],
  ['Stage 4 · what extraction gets', 'Scrapers harvest permuted bytes; canvas extraction returns black or a decoy; a thumbnail pipeline sees at most a low-resolution fragment. The best available copy is a <strong>display-resolution screenshot</strong> — §03 lets you try.'],
  ['Stage 5 · identification', 'The offline detector reads the fingerprint back out of a leaked copy and names the recipient it was issued to. It survives the screenshot chain; deep crops and AI regeneration defeat it — measured numbers in §04.'],
];

const journeyTag = document.getElementById('journeyTag');
const journeyFacts = document.getElementById('journeyFacts');
const journeyCtx = document.getElementById('journeyCanvas')?.getContext('2d');
let scanAnim = null;

function drawIdentify(progress) {
  if (!journeyCtx) return;
  journeyCtx.drawImage(master, 0, 0);
  const x = journeyCtx;
  x.strokeStyle = 'rgba(177,58,34,0.85)';
  x.lineWidth = 2;
  const inset = 26, len = 34;
  for (const [cx, cy, dx, dy] of [[inset, inset, 1, 1], [W - inset, inset, -1, 1], [inset, H - inset, 1, -1], [W - inset, H - inset, -1, -1]]) {
    x.beginPath();
    x.moveTo(cx + dx * len, cy); x.lineTo(cx, cy); x.lineTo(cx, cy + dy * len);
    x.stroke();
  }
  const sy = progress * H;
  const grad = x.createLinearGradient(0, sy - 46, 0, sy);
  grad.addColorStop(0, 'rgba(177,58,34,0)');
  grad.addColorStop(1, 'rgba(177,58,34,0.28)');
  x.fillStyle = grad;
  x.fillRect(inset, sy - 46, W - inset * 2, 46);
  x.fillStyle = 'rgba(255,120,80,0.95)';
  x.fillRect(inset, sy - 1, W - inset * 2, 2);
  x.font = '500 15px "IBM Plex Mono", monospace';
  x.fillStyle = 'rgba(243,237,225,0.92)';
  x.fillText(progress >= 1 ? 'fingerprint: FOUND — matches issuance #buyer-1042' : 'scanning suspect copy…', inset + 8, H - inset - 12);
}

function setStage(n) {
  if (!journeyCtx) return;
  if (scanAnim) { cancelAnimationFrame(scanAnim); scanAnim = null; }
  const renderers = [
    () => journeyCtx.drawImage(master, 0, 0),
    () => { journeyCtx.drawImage(master, 0, 0); journeyCtx.strokeStyle = 'rgba(177,58,34,0.5)'; journeyCtx.setLineDash([6, 5]); journeyCtx.lineWidth = 1.5; for (let i = 1; i < 8; i++) { journeyCtx.beginPath(); journeyCtx.moveTo((W / 8) * i, 0); journeyCtx.lineTo((W / 8) * i, H); journeyCtx.stroke(); journeyCtx.beginPath(); journeyCtx.moveTo(0, (H / 8) * i); journeyCtx.lineTo(W, (H / 8) * i); journeyCtx.stroke(); } journeyCtx.setLineDash([]); },
    () => journeyCtx.drawImage(wireCanvas, 0, 0),
    () => journeyCtx.drawImage(visitorCanvas, 0, 0),
    () => { journeyCtx.drawImage(payloadCanvas, 0, 0, W, H / 2); journeyCtx.drawImage(blackWith('canvas read-back: black'), 0, H / 2, W / 2, H / 2); journeyCtx.drawImage(lowResCanvas, W / 2, H / 2, W / 2, H / 2); },
    () => {
      if (reducedMotion) { drawIdentify(1); return; }
      const t0 = performance.now();
      const tick = (t) => {
        const p = Math.min(1, (t - t0) / 1600);
        drawIdentify(p);
        if (p < 1) scanAnim = requestAnimationFrame(tick);
      };
      scanAnim = requestAnimationFrame(tick);
    },
  ];
  renderers[n]();
  if (journeyTag) journeyTag.textContent = stageFacts[n][0];
  if (journeyFacts) journeyFacts.innerHTML = stageFacts[n][1];
  document.querySelectorAll('.pipe-stage').forEach((b) => {
    b.classList.toggle('is-active', Number(b.dataset.stage) === n);
  });
}
document.querySelectorAll('.pipe-stage').forEach((b) => {
  b.addEventListener('click', () => setStage(Number(b.dataset.stage)));
});
setStage(0);

/* ---------- 02 · profiles ---------- */
const profiles = {
  performance: {
    line: 'For image-heavy catalogs: the cheapest path that still never exposes a saveable file. Shield viewer, bounded caches, batched token mints, no per-view encryption.',
    bars: [
      ['Server encode · 960 px derivative', 55, 400, '≈55 ms (catalog effort)'],
      ['Browser time to first paint', 285, 500, '≈285 ms (shield/canvas)'],
      ['Mint 50 one-time tokens (batch)', 12, 100, '≈12 ms total'],
    ],
    layers: [
      ['One-time HMAC tokens', 1], ['Tile scramble · plan v2', 1], ['StegoMark fingerprint', 1],
      ['Payload encryption (AES)', 0], ['Visible/dynamic watermark', 0.5], ['Canvas taint fallback', 0.5],
      ['Temporal interlace (60 Hz)', 0], ['Proof-of-possession binding', 0],
    ],
  },
  balanced: {
    line: 'The catalog default: encrypted plan-v2 payloads and the full token lifecycle at catalog encoder effort — the setting most galleries should start from.',
    bars: [
      ['Server encode · 960 px derivative', 55, 400, '≈55 ms (catalog effort)'],
      ['Browser time to first paint', 285, 500, '≈285 ms (shield/canvas)'],
      ['Mint 50 one-time tokens (batch)', 12, 100, '≈12 ms total'],
    ],
    layers: [
      ['One-time HMAC tokens', 1], ['Tile scramble · plan v2', 1], ['StegoMark fingerprint', 1],
      ['Payload encryption (AES)', 1], ['Visible/dynamic watermark', 0.5], ['Canvas taint fallback', 1],
      ['Temporal interlace (60 Hz)', 0], ['Proof-of-possession binding', 0.5],
    ],
  },
  max: {
    line: 'For paid originals: vault delivery in WebGL at original quality, sender-constrained proofs, screenshot-degrading temporal interlace and per-viewer trace watermarks. Costs more CPU on both ends — deliberately.',
    bars: [
      ['Server encode · 960 px derivative', 257, 400, '≈257 ms (original-quality effort)'],
      ['Browser time to first paint', 400, 500, '≈400 ms (vault/WebGL)'],
      ['Mint 50 one-time tokens (batch)', 12, 100, '≈12 ms total'],
    ],
    layers: [
      ['One-time HMAC tokens', 1], ['Tile scramble · plan v2', 1], ['StegoMark fingerprint', 1],
      ['Payload encryption (AES)', 1], ['Visible/dynamic watermark', 1], ['Canvas taint fallback', 1],
      ['Temporal interlace (60 Hz)', 1], ['Proof-of-possession binding', 1],
    ],
  },
};

const profileLine = document.getElementById('profileLine');
const profileBars = document.getElementById('profileBars');
const profileLayers = document.getElementById('profileLayers');

function setProfile(name) {
  const p = profiles[name];
  if (!p) return;
  if (profileLine) profileLine.textContent = p.line;
  if (profileBars) {
    profileBars.innerHTML = p.bars.map(([label, v, max, note]) => `
      <div class="pipe-bar-row">
        <span class="pipe-bar-label">${label}</span>
        <span class="pipe-bar-track"><span class="pipe-bar-fill" style="width:${Math.max(3, (v / max) * 100)}%"></span></span>
        <span class="pipe-bar-note">${note}</span>
      </div>`).join('');
  }
  if (profileLayers) {
    profileLayers.innerHTML = p.layers.map(([label, on]) => {
      const mark = on === 1 ? '●' : on === 0.5 ? '◐' : '○';
      const cls = on === 1 ? 'on' : on === 0.5 ? 'half' : 'off';
      const state = on === 1 ? 'on' : on === 0.5 ? 'optional' : 'off';
      return `<li class="pipe-layer ${cls}"><span aria-hidden="true">${mark}</span> ${label} <small>(${state})</small></li>`;
    }).join('');
  }
  document.querySelectorAll('[data-profile]').forEach((b) => {
    b.classList.toggle('is-active', b.dataset.profile === name);
  });
}
document.querySelectorAll('[data-profile]').forEach((b) => {
  b.addEventListener('click', () => setProfile(b.dataset.profile));
});
setProfile('balanced');

/* ---------- 03 · try to steal it ---------- */
const stealCases = {
  save: {
    tag: 'Right-click → Save: nothing to save',
    draw: (x) => x.drawImage(blackWith('no file — read-back returns black'), 0, 0),
    verdict: '<strong>Artifact: nothing.</strong> There is no <span class="mono">&lt;img&gt;</span> element and no image file in the page. The viewer swallows save gestures, and code that tries to read the canvas gets black (or a SecurityError where tainting applies).',
  },
  source: {
    tag: 'View source: an opaque ID and a locked door',
    draw: (x) => x.drawImage(blackWith('403 · token required (and your copied one is spent)'), 0, 0),
    verdict: '<strong>Artifact: an ID.</strong> Page source contains an opaque image identifier. The payload endpoint answers only to a fresh, one-time, usually proof-bound token — a copied URL is already spent, and guessing is rate-limited.',
  },
  network: {
    tag: 'Network capture: permuted pieces',
    draw: (x) => { x.drawImage(payloadCanvas, 0, 0, W, H); x.drawImage(noiseCanvas, 0, H * 0.72, W, H * 0.28); },
    verdict: '<strong>Artifact: noise.</strong> What crosses the wire is permuted tiles (encrypted outright in vault modes), useless without the server-side plan — which is itself bound to a token that stops existing after first use.',
  },
  screenshot: {
    tag: 'Screenshot: works — at display size, and it is evidence',
    draw: (x) => x.drawImage(screenshotCanvas, 0, 0),
    verdict: '<strong>Artifact: a display-resolution copy.</strong> Screenshots cannot be prevented on an open platform — anyone promising otherwise is selling something. What Archx guarantees instead: the copy is capped at display resolution, degraded by temporal interlace in max-protection mode, and carries the invisible fingerprint that names the recipient (§04).',
  },
};

const stealCtx = document.getElementById('stealCanvas')?.getContext('2d');
const stealTag = document.getElementById('stealTag');
const stealVerdict = document.getElementById('stealVerdict');

function setSteal(name) {
  const s = stealCases[name];
  if (!s || !stealCtx) return;
  stealCtx.clearRect(0, 0, W, H);
  s.draw(stealCtx);
  if (stealTag) stealTag.textContent = s.tag;
  if (stealVerdict) stealVerdict.innerHTML = s.verdict;
  document.querySelectorAll('[data-steal]').forEach((b) => {
    b.classList.toggle('is-active', b.dataset.steal === name);
  });
}
document.querySelectorAll('[data-steal]').forEach((b) => {
  b.addEventListener('click', () => setSteal(b.dataset.steal));
});
setSteal('save');

/* ---------- hero · 3D tile field ---------- */
async function initHero() {
  const canvas = document.getElementById('glpipe');
  if (!canvas) return;
  let THREE;
  try { THREE = await import('three'); } catch { return; }

  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(38, 16 / 9, 0.1, 100);
  camera.position.set(0, 2.1, 10.8);
  camera.lookAt(0, 0, 0);

  const texture = new THREE.CanvasTexture(master);
  texture.colorSpace = THREE.SRGBColorSpace;
  const cols = 8, rows = 8, pw = 8.8, ph = 5.5;
  const group = new THREE.Group();
  const tiles = [];
  for (let r = 0; r < rows; r++) {
    for (let cIdx = 0; cIdx < cols; cIdx++) {
      const geo = new THREE.PlaneGeometry(pw / cols * 0.94, ph / rows * 0.94);
      const uv = geo.attributes.uv;
      for (let i = 0; i < uv.count; i++) {
        uv.setXY(i, (cIdx + uv.getX(i)) / cols, (rows - 1 - r + uv.getY(i)) / rows);
      }
      const mat = new THREE.MeshBasicMaterial({ map: texture, side: THREE.DoubleSide });
      const m = new THREE.Mesh(geo, mat);
      m.position.set(-pw / 2 + (cIdx + 0.5) * (pw / cols), ph / 2 - (r + 0.5) * (ph / rows), 0);
      m.userData.phase = (cIdx * 0.35 + r * 0.5);
      group.add(m);
      tiles.push(m);
    }
  }
  group.rotation.set(-0.12, -0.3, 0);
  scene.add(group);
  window.__archxPipeGlReady = true;

  let dragging = false, lastX = 0, lastY = 0, velY = 0;
  canvas.addEventListener('pointerdown', (e) => { dragging = true; lastX = e.clientX; lastY = e.clientY; canvas.setPointerCapture(e.pointerId); });
  canvas.addEventListener('pointermove', (e) => {
    if (!dragging) return;
    velY = (e.clientX - lastX) * 0.0006;
    group.rotation.y += (e.clientX - lastX) * 0.005;
    group.rotation.x += (e.clientY - lastY) * 0.004;
    group.rotation.x = Math.max(-0.8, Math.min(0.8, group.rotation.x));
    lastX = e.clientX; lastY = e.clientY;
  });
  canvas.addEventListener('pointerup', () => { dragging = false; });

  function resize() {
    const rect = canvas.parentElement.getBoundingClientRect();
    renderer.setSize(rect.width, rect.height, false);
    camera.aspect = rect.width / rect.height;
    camera.updateProjectionMatrix();
  }
  resize();
  window.addEventListener('resize', resize);

  function frame(t) {
    if (!dragging) group.rotation.y += velY + 0.0012;
    velY *= 0.95;
    if (!reducedMotion) {
      for (const m of tiles) {
        m.position.z = Math.sin(t * 0.0012 + m.userData.phase) * 0.16;
      }
    }
    renderer.render(scene, camera);
    if (!reducedMotion) requestAnimationFrame(frame);
  }
  requestAnimationFrame(frame);
}
initHero().catch(() => { /* fallback watcher in the page handles the message */ });
