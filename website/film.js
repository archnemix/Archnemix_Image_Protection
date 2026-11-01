/* Archnemix — "Follow one photograph": a scroll-scrubbed, browser-only
 * visual simulation of the protection pipeline. One procedurally
 * painted photograph is sliced into 64 tiles (Three.js), scrambled and
 * fingerprinted, streamed as one-time fragments to a browser frame,
 * reassembled inside the guarded viewer, and finally a leaked
 * screenshot is rescanned and attributed. This file makes no network
 * requests and talks to no demo server; it is a film of the model, not
 * the production delivery path itself.
 *
 * Scrolling through the tall band scrubs the timeline (inertia-
 * smoothed); ▶ plays it through automatically; the act rail seeks.
 * prefers-reduced-motion gets a static stage with act buttons. If
 * WebGL is unavailable, a 2D storyboard tells the same story.
 * Every pixel derives from website/photo.js — no external assets. */
import { paintValley, mulberry32 } from './photo.js';

const ACTS = [
  { until: 0.14, no: '01', title: 'The master stays home', body: 'The full-resolution original is never placed at a public web address. Visitors are never handed the file they came to admire.', chips: ['Original resolution', 'No public image URL', 'Private by default'] },
  { until: 0.36, no: '02', title: 'Sliced, scrambled, fingerprinted', body: 'A display-size copy is prepared for the viewer, invisibly marked for that recipient, then broken into keyed pieces whose order is meaningless on its own.', chips: ['Display-size derivative', '64 keyed tiles', 'Invisible recipient mark'] },
  { until: 0.58, no: '03', title: 'Only fragments travel — once', body: 'Delivery needs a signed one-time token. Intercept the journey and you collect permuted pieces tied to a token that no longer exists.', chips: ['One-time token', 'No-store delivery', 'Capture = fragments'] },
  { until: 0.80, no: '04', title: 'It becomes a picture only in the viewer', body: 'Tiles reassemble inside a guarded canvas/WebGL viewer. There is no ordinary file to save and read-back is poisoned; a screenshot is display-resolution at best.', chips: ['Guarded viewer', 'Poisoned read-back', 'Screenshot ≠ master'] },
  { until: 1.01, no: '05', title: 'A leak still names its source', body: 'Rescan a suspect copy and the surviving fingerprint points back to an issuance record — evidence to corroborate, not magic proof on its own.', chips: ['Offline rescan', 'Orientation-aware match', 'Evidence, not magic'] },
];
const READOUT = [
  [0.895, 'scan        : suspect-copy.jpg'],
  [0.925, 'fingerprint : FOUND'],
  [0.955, 'issuance    : buyer-1042'],
  [0.985, 'next        : verify issuance log'],
];
const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
const lerp = (a, b, t) => a + (b - a) * t;
const easeInOut = (t) => (t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2);
const smooth = (a, b, p) => { const t = clamp((p - a) / (b - a), 0, 1); return t * t * (3 - 2 * t); };
const bell = (p, a, b, c, d) => smooth(a, b, p) * (1 - smooth(c, d, p));

function buildSkeleton(mount) {
  mount.innerHTML = `
  <div class="film-viewport">
    <canvas class="film-gl" aria-hidden="true"></canvas>
    <div class="film-kicker">The journey · an in-browser visual simulation</div>
    <div class="film-framebox film-serverbox"><span class="film-frametag">Private originals · never published</span></div>
    <div class="film-browser">
      <div class="film-browser-bar"><i></i><i></i><i></i><span class="film-url">gallery.example/photo</span><span class="film-frametag film-frametag-right">Visitor&rsquo;s browser</span></div>
      <div class="film-browser-view"><div class="film-blackout"><span>right-click &rarr; nothing to save</span></div></div>
    </div>
    <div class="film-chip film-token">one-time token · spent on delivery</div>
    <div class="film-panel film-attacker">
      <div class="film-panel-head">Attacker · network tab</div>
      <canvas class="film-noise" width="240" height="104"></canvas>
      <div class="film-panel-line">Captured delivery — permuted fragments.<br>No clean image in here.</div>
    </div>
    <div class="film-panel film-scanner">
      <div class="film-panel-head">Rescan · suspect copy</div>
      <div class="film-scanner-slot"></div>
      <pre class="film-readout"></pre>
    </div>
    <div class="film-caption" aria-live="polite">
      <span class="film-caption-no"></span>
      <h3 class="film-caption-title"></h3>
      <p class="film-caption-body"></p>
      <div class="film-caption-chips" aria-hidden="true"></div>
    </div>
    <div class="film-intro">
      <p class="film-intro-kicker">Open-source image protection · 0BSD · npm install</p>
      <h1>Publish the picture.<br><em>Keep</em> the picture.</h1>
      <p class="film-intro-lede">Follow one photograph as Archnemix protects it: the master stays private, the public copy is fingerprinted and scrambled, fragments travel once, and the picture exists whole only inside a guarded viewer.</p>
      <div class="film-intro-actions">
        <button type="button" class="btn btn-rust film-intro-play">&#9654; Play the protection film</button>
        <a class="btn film-intro-journey" href="#pipeline-detail">See the full pipeline</a>
      </div>
      <p class="film-intro-note">Static browser simulation · no upload · no demo server · scroll to take control</p>
    </div>
    <div class="film-controls">
      <button type="button" class="btn btn-small film-play" aria-pressed="false">&#9654; Play the journey</button>
      <div class="film-rail" role="group" aria-label="Film acts"></div>
      <div class="film-track"><span class="film-track-fill"></span></div>
    </div>
    <div class="film-hint">Scroll to scrub the film &darr;</div>
    <div class="film-storyboard" hidden></div>
  </div>`;
  const q = (s) => mount.querySelector(s);
  const rail = q('.film-rail');
  ACTS.forEach((act, i) => {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'film-act-btn';
    b.textContent = act.no;
    b.title = act.title;
    b.setAttribute('aria-label', `Act ${act.no}: ${act.title}`);
    b.dataset.act = String(i);
    rail.appendChild(b);
  });
  return {
    viewport: q('.film-viewport'), canvas: q('.film-gl'),
    serverbox: q('.film-serverbox'), browser: q('.film-browser'),
    browserView: q('.film-browser-view'), blackout: q('.film-blackout'),
    token: q('.film-token'), attacker: q('.film-attacker'), noise: q('.film-noise'),
    scanner: q('.film-scanner'), scannerSlot: q('.film-scanner-slot'), readout: q('.film-readout'),
    caption: q('.film-caption'), capNo: q('.film-caption-no'),
    capTitle: q('.film-caption-title'), capBody: q('.film-caption-body'), capChips: q('.film-caption-chips'),
    intro: q('.film-intro'), introPlay: q('.film-intro-play'),
    play: q('.film-play'), rail, trackFill: q('.film-track-fill'),
    hint: q('.film-hint'), storyboard: q('.film-storyboard'),
    actBtns: [...rail.children],
  };
}

function drawStoryboard(els, photo) {
  // No-WebGL fallback: three stills + the five captions.
  els.viewport.classList.add('film-fallback-mode');
  if (els.intro) els.intro.hidden = true;
  els.storyboard.hidden = false;
  const rand = mulberry32(0x9e37);
  const still = (draw) => {
    const c = document.createElement('canvas');
    c.width = 480; c.height = 270;
    draw(c.getContext('2d'), c);
    return c;
  };
  const plain = still((x, c) => x.drawImage(photo, 0, 0, c.width, c.height));
  const scrambled = still((x, c) => {
    const n = 8, tw = c.width / n, th = c.height / n;
    const order = Array.from({ length: n * n }, (_, i) => i);
    for (let i = order.length - 1; i > 0; i--) { const j = Math.floor(rand() * (i + 1)); [order[i], order[j]] = [order[j], order[i]]; }
    order.forEach((sIdx, d) => {
      x.drawImage(photo, (sIdx % n) * (photo.width / n), Math.floor(sIdx / n) * (photo.height / n), photo.width / n, photo.height / n,
        (d % n) * tw, Math.floor(d / n) * th, tw, th);
    });
  });
  const strip = document.createElement('div');
  strip.className = 'film-stills';
  [plain, scrambled, plain.cloneNode()].forEach((c) => { c.getContext('2d').drawImage(c === scrambled ? c : photo, 0, 0, c.width, c.height); strip.appendChild(c); });
  els.storyboard.appendChild(strip);
  const list = document.createElement('ol');
  list.className = 'film-storylist';
  ACTS.forEach((a) => { const li = document.createElement('li'); li.innerHTML = `<strong>${a.title}.</strong> ${a.body}`; list.appendChild(li); });
  els.storyboard.appendChild(list);
}

async function initFilm(mount) {
  const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const els = buildSkeleton(mount);
  const section = mount.closest('.film-band') || mount;
  const photo = paintValley(960, 540);
  if (reduced) section.classList.add('film-static');

  let THREE;
  try { THREE = await import('three'); } catch { drawStoryboard(els, photo); return; }
  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas: els.canvas, antialias: true, alpha: true, powerPreference: 'high-performance' });
  } catch { drawStoryboard(els, photo); return; }
  // Start below the old 2x cap. The frame loop lowers this again if a
  // device cannot hold a healthy frame time; visual detail comes from
  // composition and depth, not from forcing full retina resolution.
  const maxPixelRatio = Math.min(window.devicePixelRatio || 1, window.innerWidth < 760 ? 1.2 : 1.35);
  let pixelRatio = maxPixelRatio;
  renderer.setPixelRatio(pixelRatio);

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(38, 16 / 9, 0.1, 100);
  const CAM_Z = 12;
  camera.position.set(0, 0, CAM_Z);

  const texture = new THREE.CanvasTexture(photo);
  texture.colorSpace = THREE.SRGBColorSpace;

  const COLS = 8, ROWS = 8, N = COLS * ROWS;
  const rand = mulberry32(0xa2c4e6);
  const perm = Array.from({ length: N }, (_, i) => i);
  for (let i = N - 1; i > 0; i--) { const j = Math.floor(rand() * (i + 1)); [perm[i], perm[j]] = [perm[j], perm[i]]; }
  const DIVERTED = new Set([7, 19, 28, 41, 52, 60]);

  // Ambient depth is deliberately cheap: one oversized blurred-by-scale
  // echo of the same photo, one static point field, two gradient shadows,
  // one delivery path and one small pulse cloud. No post-processing pass,
  // no per-frame texture work and no extra renderer.
  const backdrop = new THREE.Mesh(
    new THREE.PlaneGeometry(1, 1),
    new THREE.MeshBasicMaterial({ map: texture, color: 0x405047, transparent: true, opacity: 0.20, depthWrite: false }),
  );
  backdrop.position.set(0, 0, -5.6);
  backdrop.scale.set(24, 13.5, 1);
  backdrop.renderOrder = -4;
  backdrop.frustumCulled = false;
  scene.add(backdrop);

  const dustCount = 120;
  const dustPositions = new Float32Array(dustCount * 3);
  for (let i = 0; i < dustCount; i++) {
    dustPositions[i * 3] = (rand() - 0.5) * 17;
    dustPositions[i * 3 + 1] = (rand() - 0.5) * 9;
    dustPositions[i * 3 + 2] = -4.5 + rand() * 5.8;
  }
  const dustGeometry = new THREE.BufferGeometry();
  dustGeometry.setAttribute('position', new THREE.BufferAttribute(dustPositions, 3));
  const dust = new THREE.Points(dustGeometry, new THREE.PointsMaterial({
    color: 0xdcead4, size: 0.035, transparent: true, opacity: 0.48,
    blending: THREE.AdditiveBlending, depthWrite: false, sizeAttenuation: true,
  }));
  dust.frustumCulled = false;
  dust.renderOrder = -3;
  scene.add(dust);

  const shadowCanvas = document.createElement('canvas');
  shadowCanvas.width = 128; shadowCanvas.height = 64;
  const shadowCtx = shadowCanvas.getContext('2d');
  const shadowGrad = shadowCtx.createRadialGradient(64, 32, 4, 64, 32, 62);
  shadowGrad.addColorStop(0, 'rgba(0,0,0,0.62)');
  shadowGrad.addColorStop(0.55, 'rgba(0,0,0,0.28)');
  shadowGrad.addColorStop(1, 'rgba(0,0,0,0)');
  shadowCtx.fillStyle = shadowGrad;
  shadowCtx.fillRect(0, 0, 128, 64);
  const shadowTexture = new THREE.CanvasTexture(shadowCanvas);
  const makeShadow = () => {
    const mesh = new THREE.Mesh(
      new THREE.PlaneGeometry(1, 1),
      new THREE.MeshBasicMaterial({ map: shadowTexture, transparent: true, opacity: 0.34, depthWrite: false }),
    );
    mesh.frustumCulled = false;
    mesh.renderOrder = -2;
    scene.add(mesh);
    return mesh;
  };
  const masterShadow = makeShadow();
  const browserShadow = makeShadow();

  // The route the fragments take. Its geometry is rebuilt only on layout;
  // pulses reuse one small typed array during Act 3.
  const streamSegments = 56;
  const streamGeometry = new THREE.BufferGeometry();
  streamGeometry.setAttribute('position', new THREE.BufferAttribute(new Float32Array((streamSegments + 1) * 3), 3));
  const streamLine = new THREE.Line(streamGeometry, new THREE.LineBasicMaterial({
    color: 0xff8666, transparent: true, opacity: 0, depthWrite: false,
  }));
  streamLine.frustumCulled = false;
  streamLine.renderOrder = -1;
  scene.add(streamLine);

  const pulseCount = 36;
  const pulsePositions = new Float32Array(pulseCount * 3);
  const pulseGeometry = new THREE.BufferGeometry();
  pulseGeometry.setAttribute('position', new THREE.BufferAttribute(pulsePositions, 3));
  const streamPulses = new THREE.Points(pulseGeometry, new THREE.PointsMaterial({
    color: 0xffb08d, size: 0.075, transparent: true, opacity: 0,
    blending: THREE.AdditiveBlending, depthWrite: false, sizeAttenuation: true,
  }));
  streamPulses.frustumCulled = false;
  streamPulses.renderOrder = 2;
  scene.add(streamPulses);

  const tiles = [];
  const unitPlane = new THREE.PlaneGeometry(1, 1);
  const sharedTileMaterial = new THREE.MeshBasicMaterial({ map: texture, side: THREE.DoubleSide, transparent: true });
  for (let i = 0; i < N; i++) {
    const geo = unitPlane.clone();
    const c = i % COLS, r = Math.floor(i / COLS);
    const uv = geo.attributes.uv;
    for (let k = 0; k < uv.count; k++) {
      uv.setXY(k, (c + uv.getX(k)) / COLS, (ROWS - 1 - r + uv.getY(k)) / ROWS);
    }
    // Only the six diverted tiles ever fade independently; the other 58
    // share one program/material instead of allocating 64 materials.
    const mat = DIVERTED.has(i) ? sharedTileMaterial.clone() : sharedTileMaterial;
    const mesh = new THREE.Mesh(geo, mat);
    mesh.frustumCulled = false;
    scene.add(mesh);
    tiles.push({
      mesh, home: i, permuted: perm[i],
      delay: rand() * 0.45,
      flip: rand() < 0.55,
      burst: { z: -1.4 + rand() * 3.4, rz: (rand() - 0.5) * 0.9, jx: (rand() - 0.5) * 0.5, jy: (rand() - 0.5) * 0.5 },
      keys: null, pose: { x: 0, y: 0, z: 0, ry: 0, rz: 0, s: 1, o: 1 },
    });
  }
  unitPlane.dispose();

  // Screenshot "leak" plane + its scanline (child, local space).
  const leak = new THREE.Mesh(
    new THREE.PlaneGeometry(1, 1),
    new THREE.MeshBasicMaterial({ map: texture, transparent: true, opacity: 0 }),
  );
  leak.frustumCulled = false;
  leak.visible = false;
  const scan = new THREE.Mesh(
    new THREE.PlaneGeometry(1, 0.014),
    new THREE.MeshBasicMaterial({ color: 0xff7850, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }),
  );
  scan.position.z = 0.02;
  leak.add(scan);
  scene.add(leak);

  // Fingerprint shimmer sweep.
  const shimCanvas = document.createElement('canvas');
  shimCanvas.width = 128; shimCanvas.height = 8;
  const sx = shimCanvas.getContext('2d');
  const grad = sx.createLinearGradient(0, 0, 128, 0);
  grad.addColorStop(0, 'rgba(255,150,90,0)');
  grad.addColorStop(0.5, 'rgba(255,170,110,0.85)');
  grad.addColorStop(1, 'rgba(255,150,90,0)');
  sx.fillStyle = grad; sx.fillRect(0, 0, 128, 8);
  const shimmer = new THREE.Mesh(
    new THREE.PlaneGeometry(1, 1),
    new THREE.MeshBasicMaterial({ map: new THREE.CanvasTexture(shimCanvas), transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false }),
  );
  shimmer.frustumCulled = false;
  scene.add(shimmer);

  /* ---------------- layout: world rects <-> DOM frames ---------------- */
  const L = {
    halfW: 6, halfH: 3.4, portrait: false,
    opening: { cx: 0, cy: 0.15, w: 9.6, h: 5.4 },
    master: { cx: -3, cy: 0, w: 4.4, h: 2.48 },
    browser: { cx: 3, cy: 0, w: 4.4, h: 2.48 },
    stream: { a: { x: 0, y: 0 }, ctrl: { x: 0, y: 0 }, b: { x: 0, y: 0 } },
  };
  // Geometry is measured on resize/font-load only. The render loop uses
  // these cached CSS-pixel/normalized values and never asks layout for a
  // fresh rect while it is also writing styles -- the old implementation
  // forced synchronous layout several times per frame.
  const viewSize = { w: 1, h: 1 };
  const panelNorm = {
    attacker: { x: 0.5, y: 0.2 },
    scanner: { x0: 0.72, y0: 0.58, x1: 0.97, y1: 0.78 },
  };
  let chipHalf = 126;
  const attackerPt = { x: 0, y: 0 };
  const scannerTL = { x: 0, y: 0 };
  const scannerBR = { x: 0, y: 0 };
  const scannerRect = { cx: 0, cy: 0, w: 1, h: 1 };
  const v3 = new THREE.Vector3();
  function worldToPx(x, y, out = { x: 0, y: 0 }) {
    v3.set(x, y, 0).project(camera);
    out.x = (v3.x * 0.5 + 0.5) * viewSize.w;
    out.y = (-v3.y * 0.5 + 0.5) * viewSize.h;
    return out;
  }
  function normToWorld(nx, ny, out) {
    v3.set(nx * 2 - 1, -ny * 2 + 1, 0.5).unproject(camera);
    const dir = v3.sub(camera.position).normalize();
    const dist = -camera.position.z / dir.z;
    out.x = camera.position.x + dir.x * dist;
    out.y = camera.position.y + dir.y * dist;
    return out;
  }
  function cachePanelAnchors() {
    // offset* values ignore the tiny entrance transforms, which is the
    // right trade: anchors are stable to within a few pixels while all
    // layout reads move out of the animation loop.
    panelNorm.attacker.x = els.attacker.offsetLeft / viewSize.w;
    panelNorm.attacker.y = (els.attacker.offsetTop + els.attacker.offsetHeight * 0.62) / viewSize.h;
    const slotLeft = els.scanner.offsetLeft + els.scannerSlot.offsetLeft;
    const slotTop = els.scanner.offsetTop + els.scannerSlot.offsetTop;
    panelNorm.scanner.x0 = (slotLeft + els.scannerSlot.offsetWidth * 0.02) / viewSize.w;
    panelNorm.scanner.y0 = (slotTop + els.scannerSlot.offsetHeight * 0.02) / viewSize.h;
    panelNorm.scanner.x1 = (slotLeft + els.scannerSlot.offsetWidth * 0.98) / viewSize.w;
    panelNorm.scanner.y1 = (slotTop + els.scannerSlot.offsetHeight * 0.98) / viewSize.h;
    chipHalf = (els.token.offsetWidth || 240) / 2 + 6;
  }
  const frameTL = { x: 0, y: 0 };
  const frameBR = { x: 0, y: 0 };
  function placeFrame(el, rect, liftPx = 0) {
    const tl = worldToPx(rect.cx - rect.w / 2, rect.cy + rect.h / 2, frameTL);
    const br = worldToPx(rect.cx + rect.w / 2, rect.cy - rect.h / 2, frameBR);
    el.style.left = `${tl.x}px`;
    el.style.top = `${tl.y - liftPx}px`;
    el.style.width = `${br.x - tl.x}px`;
    el.style.height = `${br.y - tl.y + liftPx}px`;
  }
  function cellCenter(rect, idx) {
    const c = idx % COLS, r = Math.floor(idx / COLS);
    return {
      x: rect.cx - rect.w / 2 + ((c + 0.5) / COLS) * rect.w,
      y: rect.cy + rect.h / 2 - ((r + 0.5) / ROWS) * rect.h,
    };
  }
  function bezier(a, ctrl, b, t) {
    const u = 1 - t;
    return {
      x: u * u * a.x + 2 * u * t * ctrl.x + t * t * b.x,
      y: u * u * a.y + 2 * u * t * ctrl.y + t * t * b.y,
    };
  }

  function computeLayout() {
    const r = els.viewport.getBoundingClientRect();
    viewSize.w = Math.max(2, r.width);
    viewSize.h = Math.max(2, r.height);
    renderer.setSize(viewSize.w, viewSize.h, false);
    camera.aspect = viewSize.w / viewSize.h;
    camera.updateProjectionMatrix();
    L.halfH = Math.tan((camera.fov * Math.PI) / 360) * CAM_Z;
    L.halfW = L.halfH * camera.aspect;
    L.portrait = camera.aspect < 1.02;
    if (!L.portrait) {
      const w = Math.min(4.9, L.halfW * 0.80);
      const openingW = Math.min(L.halfW * 1.72, 12.3);
      L.opening = { cx: 0, cy: 0.12, w: openingW, h: openingW * 0.5625 };
      L.master = { cx: -L.halfW * 0.54, cy: 0.55, w, h: w * 0.5625 };
      L.browser = { cx: L.halfW * 0.54, cy: 0.55, w, h: w * 0.5625 };
    } else {
      const w = Math.min(L.halfW * 1.72, 5.4);
      // Portrait gets a cover-style crop: a 16:9 photograph small enough
      // to fit the width would be only a thin strip behind the title.
      const openingW = Math.min(L.halfW * 3.05, 7);
      L.opening = { cx: 0, cy: L.halfH * 0.10, w: openingW, h: openingW * 0.5625 };
      L.master = { cx: 0, cy: L.halfH * 0.46, w, h: w * 0.5625 };
      L.browser = { cx: 0, cy: -L.halfH * 0.26, w, h: w * 0.5625 };
    }
    backdrop.scale.set(L.halfW * 3.15, L.halfH * 3.15, 1);
    masterShadow.position.set(L.master.cx, L.master.cy - L.master.h * 0.62, -0.28);
    masterShadow.scale.set(L.master.w * 1.12, 0.62, 1);
    browserShadow.position.set(L.browser.cx, L.browser.cy - L.browser.h * 0.62, -0.28);
    browserShadow.scale.set(L.browser.w * 1.12, 0.62, 1);
    cachePanelAnchors();
    buildKeys();
  }

  function buildKeys() {
    const tw = L.master.w / COLS, th = L.master.h / ROWS;
    const aPt = { x: L.master.cx + L.master.w / 2, y: L.master.cy };
    const bPt = { x: L.browser.cx - L.browser.w / 2, y: L.browser.cy };
    const ctrl = L.portrait
      ? { x: L.halfW * 0.75, y: (L.master.cy + L.browser.cy) / 2 }
      : { x: 0, y: (L.master.cy + L.browser.cy) / 2 + 1.05 };
    if (L.portrait) { aPt.x = L.master.cx; aPt.y = L.master.cy - L.master.h / 2; bPt.x = L.browser.cx; bPt.y = L.browser.cy + L.browser.h / 2; }
    L.stream.a = aPt; L.stream.ctrl = ctrl; L.stream.b = bPt;
    const streamPos = streamGeometry.attributes.position;
    for (let i = 0; i <= streamSegments; i++) {
      const pt = bezier(aPt, ctrl, bPt, i / streamSegments);
      streamPos.setXYZ(i, pt.x, pt.y, -0.12);
    }
    streamPos.needsUpdate = true;
    for (const t of tiles) {
      const opening = cellCenter(L.opening, t.home);
      const home = cellCenter(L.master, t.home);
      const permCell = cellCenter(L.master, t.permuted);
      const burstCx = L.master.cx * 0.86;
      const burst = {
        x: burstCx + (permCell.x - L.master.cx) * 1.28 + t.burst.jx,
        y: L.master.cy + (permCell.y - L.master.cy) * 1.28 + t.burst.jy,
        z: t.burst.z, ry: t.flip ? Math.PI : 0, rz: t.burst.rz,
      };
      const sPos = bezier(aPt, ctrl, bPt, (t.permuted + 0.5) / N);
      const dest = cellCenter(L.browser, t.home);
      const base = { rx: 0 };
      const openingScale = (L.opening.w / L.master.w) * 1.012;
      t.keys = [
        { p: 0, x: opening.x, y: opening.y, z: -0.08, ry: 0, rz: 0, s: openingScale, o: 1, ...base },
        { p: 0.10, x: home.x, y: home.y, z: 0, ry: 0, rz: 0, s: 1.012, o: 1, ...base },
        { p: 0.16, x: home.x, y: home.y, z: 0, ry: 0, rz: 0, s: 1.012, o: 1, ...base },
        { p: 0.30, x: burst.x, y: burst.y, z: burst.z, ry: burst.ry, rz: burst.rz, s: 0.97, o: 1, ...base },
        { p: 0.54, x: sPos.x, y: sPos.y, z: 0.4, ry: burst.ry, rz: burst.rz * 0.4, s: 0.8, o: 1, ...base },
        { p: 0.74, x: dest.x, y: dest.y, z: 0, ry: 0, rz: 0, s: 0.992, o: 1, ...base },
        { p: 1, x: dest.x, y: dest.y, z: 0, ry: 0, rz: 0, s: 0.992, o: 1, ...base },
      ];
      t.tw = tw; t.th = th;
    }
    leak.scale.set(L.browser.w, L.browser.h, 1);
    shimmer.scale.set(L.master.w * 0.5, L.master.h * 1.15, 1);
  }

  function sampleKeys(keys, p, delay, out) {
    let a = keys[0], b = keys[keys.length - 1];
    for (let i = 0; i < keys.length - 1; i++) {
      if (p <= keys[i + 1].p) { a = keys[i]; b = keys[i + 1]; break; }
    }
    const span = Math.max(1e-6, b.p - a.p);
    const local = clamp(((p - a.p) / span - delay * 0.5) / (1 - 0.5 * 0.9), 0, 1);
    const e = easeInOut(local);
    out.x = lerp(a.x, b.x, e); out.y = lerp(a.y, b.y, e); out.z = lerp(a.z, b.z, e);
    out.ry = lerp(a.ry, b.ry, e); out.rz = lerp(a.rz, b.rz, e);
    out.s = lerp(a.s, b.s, e); out.o = lerp(a.o, b.o, e);
    return out;
  }

  /* ---------------- progress: scroll scrub + autoplay ----------------- */
  let targetP = 0, shownP = 0, playing = false, playFrom = 0, playStart = 0;
  let secTop = 0, secH = 1;
  function measureSection() {
    const r = section.getBoundingClientRect();
    secTop = r.top + window.scrollY;
    secH = section.offsetHeight;
  }
  function scrollProgress() {
    if (reduced) return targetP;
    return clamp((window.scrollY - secTop) / Math.max(1, secH - window.innerHeight), 0, 1);
  }
  window.addEventListener('scroll', () => {
    if (playing) setPlaying(false);
    targetP = scrollProgress();
  }, { passive: true });
  let layoutQueued = false;
  function queueLayout() {
    if (layoutQueued) return;
    layoutQueued = true;
    requestAnimationFrame(() => {
      layoutQueued = false;
      measureSection();
      computeLayout();
    });
  }
  window.addEventListener('resize', queueLayout, { passive: true });
  window.addEventListener('load', queueLayout, { passive: true });
  if (document.fonts?.ready) document.fonts.ready.then(queueLayout).catch(() => {});

  function setPlaying(on) {
    playing = on;
    els.play.setAttribute('aria-pressed', String(on));
    els.play.textContent = on ? '❚❚ Pause' : (targetP >= 0.999 ? '↺ Replay the journey' : '▶ Play the journey');
    if (on) { playFrom = targetP >= 0.999 ? 0 : targetP; playStart = performance.now(); if (playFrom === 0) shownP = 0; }
  }
  els.play.addEventListener('click', () => setPlaying(!playing));
  els.introPlay?.addEventListener('click', () => setPlaying(true));
  els.actBtns.forEach((b, i) => {
    b.addEventListener('click', () => {
      setPlaying(false);
      // Representative stills, not just act midpoints: Act 1 lands after
      // the opening photograph has docked into the private frame.
      const stops = [0.105, 0.245, 0.475, 0.745, 0.965];
      const mid = stops[i];
      if (reduced) { targetP = mid; shownP = mid; }
      else window.scrollTo({ top: secTop + mid * (secH - window.innerHeight), behavior: 'smooth' });
    });
  });

  /* ---------------- DOM sync helpers ----------------------------------- */
  let currentAct = -1, captionTimer = 0, shownLines = -1;
  function setAct(idx) {
    if (idx === currentAct) return;
    currentAct = idx;
    els.actBtns.forEach((b, i) => b.classList.toggle('active', i === idx));
    const act = ACTS[idx];
    els.caption.classList.add('swap');
    clearTimeout(captionTimer);
    captionTimer = setTimeout(() => {
      els.capNo.textContent = `${act.no} / 05`;
      els.capTitle.textContent = act.title;
      els.capBody.textContent = act.body;
      els.capChips.replaceChildren(...act.chips.map((chip) => {
        const span = document.createElement('span');
        span.textContent = chip;
        return span;
      }));
      els.caption.classList.remove('swap');
    }, reduced ? 0 : 160);
  }
  const noiseCtx = els.noise.getContext('2d', { alpha: false });
  const noiseImage = noiseCtx.createImageData(els.noise.width, els.noise.height);
  function drawNoise() {
    const d = noiseImage.data;
    for (let i = 0; i < d.length; i += 4) {
      const v = (Math.random() * 255) | 0;
      d[i] = v; d[i + 1] = (Math.random() * 255) | 0; d[i + 2] = (Math.random() * 255) | 0; d[i + 3] = 255;
    }
    noiseCtx.putImageData(noiseImage, 0, 0);
  }

  let visible = true;
  new IntersectionObserver((e) => { visible = e[0].isIntersecting; }, { threshold: 0.02 }).observe(els.viewport);

  measureSection();
  computeLayout();
  targetP = scrollProgress();
  shownP = targetP;
  setAct(0);

  let frame = 0;
  let lastFrameAt = 0;
  let frameTimeEma = 16.7;
  let measuredFrames = 0;
  const tokenPt = { x: 0, y: 0 };
  function tick(now) {
    requestAnimationFrame(tick);
    if (!visible && !playing) return;
    frame += 1;

    if (playing) {
      targetP = clamp(playFrom + (now - playStart) / 16000, 0, 1);
      if (targetP >= 1) setPlaying(false);
    }
    // Time-based (not frame-count-based) inertia: a 120 Hz display and a
    // struggling 20 fps device now settle over roughly the same wall-clock
    // interval instead of the slower device also getting slower scrubbing.
    const rawFrameDt = lastFrameAt ? now - lastFrameAt : 16.7;
    const frameDt = clamp(rawFrameDt, 1, 100);
    const smoothing = reduced ? 1 : 1 - Math.exp(-frameDt / 110);
    shownP = lerp(shownP, targetP, smoothing);
    if (Math.abs(shownP - targetP) < 0.0004) shownP = targetP;
    const p = shownP;

    // Adaptive resolution: sample real frame time, then step down once
    // rather than letting a weak GPU spend the whole film at a resolution
    // it cannot sustain. No layout reads are involved. Slow frames above
    // 100 ms are capped for the EMA but still counted -- otherwise the
    // devices that most need the step-down would never trigger it.
    if (lastFrameAt && rawFrameDt > 0 && rawFrameDt < 1000) {
      frameTimeEma = frameTimeEma * 0.92 + frameDt * 0.08;
      measuredFrames += 1;
    }
    lastFrameAt = now;
    if (measuredFrames >= 30) {
      if (frameTimeEma > 23 && pixelRatio > 1) {
        pixelRatio = Math.max(1, pixelRatio - (frameTimeEma > 50 ? 0.3 : 0.18));
        renderer.setPixelRatio(pixelRatio);
        renderer.setSize(viewSize.w, viewSize.h, false);
      }
      measuredFrames = 0;
    }

    // When scroll/playback has settled, ambient bobbing does not need a
    // full 60 fps scene. Render alternate frames and halve idle GPU work.
    const settled = !playing && shownP === targetP;
    if (settled && (frame & 1)) return;

    // Camera: begin square-on and slightly closer for the full-frame
    // opening, then pull into the familiar master -> browser dolly.
    camera.position.x = p < 0.14
      ? lerp(0, -0.45, smooth(0.03, 0.14, p))
      : lerp(-0.45, 0.45, smooth(0.14, 0.9, p));
    camera.position.z = CAM_Z - (1 - smooth(0, 0.14, p)) * 1.05 - Math.sin(clamp(p, 0, 1) * Math.PI) * 0.85;
    camera.position.y = Math.sin(now * 0.0004) * 0.06 * (reduced ? 0 : 1);
    camera.lookAt(0, 0, 0);
    camera.updateMatrixWorld();

    // World anchors from cached normalized DOM positions. Projection is
    // recomputed because the camera moves, but layout is not re-read.
    normToWorld(panelNorm.attacker.x, panelNorm.attacker.y, attackerPt);
    normToWorld(panelNorm.scanner.x0, panelNorm.scanner.y0, scannerTL);
    normToWorld(panelNorm.scanner.x1, panelNorm.scanner.y1, scannerBR);
    scannerRect.cx = (scannerTL.x + scannerBR.x) / 2;
    scannerRect.cy = (scannerTL.y + scannerBR.y) / 2;
    scannerRect.w = Math.abs(scannerBR.x - scannerTL.x);
    scannerRect.h = Math.abs(scannerTL.y - scannerBR.y);

    // Tiles.
    const bob = (1 - smooth(0.1, 0.16, p)) * (reduced ? 0 : Math.sin(now * 0.0012) * 0.045);
    for (const t of tiles) {
      const pose = sampleKeys(t.keys, p, t.delay, t.pose);
      let { x, y, z, ry, rz, s, o } = pose;
      if (DIVERTED.has(t.home)) {
        // Two phases with an invisible seam: fly OUT to the attacker's
        // panel while fading, stay invisible, then fade back IN at the
        // (normal) pose position — never a visible mid-flight smear.
        const divOut = smooth(0.47, 0.585, p);
        const backIn = smooth(0.665, 0.725, p);
        if (backIn > 0) {
          o = backIn;
        } else if (divOut > 0) {
          x = lerp(x, attackerPt.x, divOut); y = lerp(y, attackerPt.y, divOut); z = lerp(z, 0.6, divOut);
          o = 1 - divOut;
        }
      }
      t.mesh.position.set(x, y + bob, z);
      t.mesh.rotation.set(0, ry, rz);
      t.mesh.scale.set(t.tw * s, t.th * s, 1);
      if (DIVERTED.has(t.home)) t.mesh.material.opacity = o;
    }

    // Shimmer sweep during fingerprint embed.
    const shimT = clamp((p - 0.295) / 0.055, 0, 1);
    shimmer.material.opacity = bell(p, 0.29, 0.305, 0.34, 0.355) * 0.85;
    shimmer.position.set(
      L.master.cx + lerp(-L.master.w * 0.55, L.master.w * 0.55, shimT),
      L.master.cy, 0.9,
    );

    // Ambient depth and the visible delivery route. These are a handful
    // of transform/opacity updates plus one 36-point buffer in Act 3.
    const introReveal = smooth(0.035, 0.115, p);
    backdrop.position.x = lerp(-0.14, 0.14, p);
    backdrop.material.opacity = 0.13 + introReveal * 0.07;
    dust.rotation.z = p * 0.025;
    dust.position.x = reduced ? 0 : Math.sin(now * 0.000035) * 0.08;
    masterShadow.material.opacity = 0.05 + introReveal * 0.29;
    browserShadow.material.opacity = 0.05 + introReveal * 0.29;
    const streamOpacity = bell(p, 0.34, 0.43, 0.65, 0.72);
    streamLine.material.opacity = streamOpacity * 0.52;
    streamPulses.material.opacity = streamOpacity * 0.9;
    if (streamOpacity > 0.02) {
      const { a, ctrl, b } = L.stream;
      const flow = reduced ? 0.18 : (now * 0.000045) % 1;
      for (let i = 0; i < pulseCount; i++) {
        const tPos = (i / pulseCount + flow) % 1;
        const u = 1 - tPos;
        pulsePositions[i * 3] = u * u * a.x + 2 * u * tPos * ctrl.x + tPos * tPos * b.x;
        pulsePositions[i * 3 + 1] = u * u * a.y + 2 * u * tPos * ctrl.y + tPos * tPos * b.y;
        pulsePositions[i * 3 + 2] = 0.18;
      }
      pulseGeometry.attributes.position.needsUpdate = true;
    }

    // Leak plane: lift off the browser, fly to the scanner.
    const leakIn = smooth(0.80, 0.845, p);
    const fly = easeInOut(smooth(0.845, 0.905, p));
    leak.visible = p > 0.795;
    if (leak.visible) {
      const from = { x: L.browser.cx, y: L.browser.cy, w: L.browser.w, h: L.browser.h };
      leak.position.set(
        lerp(from.x, scannerRect.cx, fly),
        lerp(from.y, scannerRect.cy, fly) + Math.sin(fly * Math.PI) * 0.35,
        lerp(0.06, 0.04, fly) + Math.sin(fly * Math.PI) * 0.35,
      );
      leak.scale.set(lerp(from.w, scannerRect.w, fly), lerp(from.h, scannerRect.h, fly), 1);
      leak.rotation.x = -0.16 * Math.sin(fly * Math.PI);
      leak.material.opacity = leakIn;
      const scanT = smooth(0.90, 0.97, p);
      scan.position.y = lerp(0.48, -0.48, scanT);
      scan.material.opacity = bell(p, 0.895, 0.905, 0.965, 0.98);
    }

    // DOM frames tracked to the 3D world every frame (camera moves).
    placeFrame(els.serverbox, L.master, 0);
    placeFrame(els.browser, L.browser, 26);
    worldToPx(
      L.master.cx + L.master.w * (L.portrait ? 0.30 : 0.52),
      L.master.cy - L.master.h * (L.portrait ? 0.82 : 0.72),
      tokenPt,
    );
    els.token.style.left = `${clamp(tokenPt.x, chipHalf, Math.max(chipHalf, viewSize.w - chipHalf))}px`;
    els.token.style.top = `${tokenPt.y}px`;

    // Opening title hands over to the staged frames as the photograph
    // docks. The caption stays out of the title shot, then takes over.
    const introOut = smooth(0.055, 0.125, p);
    const introOpacity = 1 - introOut;
    els.intro.style.opacity = String(introOpacity);
    els.intro.style.transform = `translate(-50%, calc(-50% - ${introOut * 26}px)) scale(${1 - introOut * 0.035})`;
    els.intro.style.visibility = introOpacity <= 0.01 ? 'hidden' : 'visible';
    if ('inert' in els.intro) els.intro.inert = introOpacity < 0.35;
    els.caption.style.opacity = p < 0.14 ? String(introReveal) : '';

    // Panel + chip choreography.
    els.serverbox.style.opacity = String((0.04 + 0.96 * introReveal) * (0.35 + 0.65 * (1 - smooth(0.3, 0.42, p))));
    els.browser.style.opacity = String((0.04 + 0.96 * introReveal) * (0.35 + 0.65 * smooth(0.3, 0.5, p)));
    els.token.style.opacity = String(bell(p, 0.335, 0.385, 0.57, 0.63));
    els.token.style.transform = `translate(-50%, -50%) scale(${0.8 + 0.2 * bell(p, 0.335, 0.385, 0.57, 0.63)})`;
    const atk = bell(p, 0.43, 0.50, 0.73, 0.81);
    els.attacker.style.opacity = String(atk);
    els.attacker.style.transform = `translate(-50%, ${(1 - atk) * -14}px)`;
    if (atk > 0.03 && frame % 5 === 0) drawNoise();
    const scn = smooth(0.82, 0.885, p);
    els.scanner.style.opacity = String(scn);
    els.scanner.style.transform = `translateY(${(1 - scn) * 16}px)`;
    els.blackout.style.opacity = String(bell(p, 0.764, 0.771, 0.783, 0.791));
    els.hint.style.opacity = String(smooth(0.075, 0.12, p) * (1 - smooth(0.16, 0.23, p)) * (playing ? 0 : 1));
    els.trackFill.style.transform = `scaleX(${p.toFixed(4)})`;

    const lines = READOUT.filter(([at]) => p >= at).length;
    if (lines !== shownLines) {
      shownLines = lines;
      els.readout.textContent = READOUT.slice(0, lines).map(([, txt]) => txt).join('\n');
    }

    let actIdx = ACTS.findIndex((a) => p < a.until);
    if (actIdx < 0) actIdx = ACTS.length - 1;
    setAct(actIdx);

    renderer.render(scene, camera);
  }
  requestAnimationFrame(tick);
}

document.querySelectorAll('[data-film]').forEach((mount) => {
  initFilm(mount).catch(() => {
    try {
      const els = buildSkeleton(mount);
      drawStoryboard(els, paintValley(960, 540));
    } catch { /* mount keeps its static fallback text */ }
  });
});
