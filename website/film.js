/* Archnemix — "Follow one photograph": a scroll-scrubbed film of the
 * real pipeline. One procedurally painted photograph is sliced into
 * 64 tiles (Three.js), scrambled + fingerprinted on the "server",
 * streamed to a browser frame (while an attacker's network tab grabs
 * nothing but fragments), reassembled inside the guarded viewer, and
 * finally a leaked screenshot is rescanned and attributed.
 *
 * Scrolling through the tall band scrubs the timeline (inertia-
 * smoothed); ▶ plays it through automatically; the act rail seeks.
 * prefers-reduced-motion gets a static stage with act buttons. If
 * WebGL is unavailable, a 2D storyboard tells the same story.
 * Every pixel derives from website/photo.js — no external assets. */
import { paintValley, mulberry32 } from './photo.js';

const ACTS = [
  { until: 0.14, no: '01', title: 'The master stays home', body: 'Your original lives on private disk, outside the web root. Nothing on any page links to it, and it is never served.' },
  { until: 0.36, no: '02', title: 'Sliced, scrambled, fingerprinted', body: 'For each viewer, the server renders a display-size derivative, embeds an invisible per-recipient StegoMark, then permutes the tiles under a per-image key.' },
  { until: 0.58, no: '03', title: 'Only fragments travel — once', body: 'Delivery needs a signed one-time token. Intercept the traffic and you collect permuted pieces tied to a token that no longer exists.' },
  { until: 0.80, no: '04', title: 'It becomes a picture only in the viewer', body: 'Tiles reassemble inside a guarded canvas/WebGL viewer. There is no file to save and read-back is poisoned; a screenshot is display-resolution at best.' },
  { until: 1.01, no: '05', title: 'A leak still names its source', body: 'Rescan a suspect copy offline and the fingerprint reads back out, pointing at the issuance record — evidence you can act on.' },
];
const READOUT = [
  [0.90, '$ archx-detect suspect.jpg'],
  [0.93, '  fingerprint : FOUND — 9182736450'],
  [0.96, '  issuance    : buyer-1042 · 2026-10-30'],
  [0.99, '  verdict     : this copy names its recipient'],
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
    <div class="film-kicker">The journey · what actually happens to your photo</div>
    <div class="film-framebox film-serverbox"><span class="film-frametag">Your server · private disk</span></div>
    <div class="film-browser">
      <div class="film-browser-bar"><i></i><i></i><i></i><span class="film-url">gallery.example/photo</span><span class="film-frametag film-frametag-right">Visitor&rsquo;s browser</span></div>
      <div class="film-browser-view"><div class="film-blackout"><span>right-click &rarr; nothing to save</span></div></div>
    </div>
    <div class="film-chip film-token">one-time token · spent on delivery</div>
    <div class="film-panel film-attacker">
      <div class="film-panel-head">Attacker · network tab</div>
      <canvas class="film-noise" width="240" height="104"></canvas>
      <div class="film-panel-line">payload.bin — permuted fragments.<br>No image in here.</div>
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
    capTitle: q('.film-caption-title'), capBody: q('.film-caption-body'),
    play: q('.film-play'), rail, trackFill: q('.film-track-fill'),
    hint: q('.film-hint'), storyboard: q('.film-storyboard'),
    actBtns: [...rail.children],
  };
}

function drawStoryboard(els, photo) {
  // No-WebGL fallback: three stills + the five captions.
  els.viewport.classList.add('film-fallback-mode');
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
    renderer = new THREE.WebGLRenderer({ canvas: els.canvas, antialias: true, alpha: true });
  } catch { drawStoryboard(els, photo); return; }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));

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

  const tiles = [];
  const unitPlane = new THREE.PlaneGeometry(1, 1);
  for (let i = 0; i < N; i++) {
    const geo = unitPlane.clone();
    const c = i % COLS, r = Math.floor(i / COLS);
    const uv = geo.attributes.uv;
    for (let k = 0; k < uv.count; k++) {
      uv.setXY(k, (c + uv.getX(k)) / COLS, (ROWS - 1 - r + uv.getY(k)) / ROWS);
    }
    const mat = new THREE.MeshBasicMaterial({ map: texture, side: THREE.DoubleSide, transparent: true });
    const mesh = new THREE.Mesh(geo, mat);
    mesh.frustumCulled = false;
    scene.add(mesh);
    tiles.push({
      mesh, home: i, permuted: perm[i],
      delay: rand() * 0.45,
      flip: rand() < 0.55,
      burst: { z: -1.4 + rand() * 3.4, rz: (rand() - 0.5) * 0.9, jx: (rand() - 0.5) * 0.5, jy: (rand() - 0.5) * 0.5 },
      keys: null,
    });
  }

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
    master: { cx: -3, cy: 0, w: 4.4, h: 2.48 },
    browser: { cx: 3, cy: 0, w: 4.4, h: 2.48 },
    attacker: { x: 0, y: 2.2 },
    scanner: { cx: 3, cy: -2.2, w: 2.2, h: 1.24 },
  };
  const v3 = new THREE.Vector3();
  function worldToPx(x, y) {
    v3.set(x, y, 0).project(camera);
    const r = els.viewport.getBoundingClientRect();
    return { x: (v3.x * 0.5 + 0.5) * r.width, y: (-v3.y * 0.5 + 0.5) * r.height };
  }
  function pxToWorld(px, py) {
    const r = els.viewport.getBoundingClientRect();
    v3.set((px / r.width) * 2 - 1, -(py / r.height) * 2 + 1, 0.5).unproject(camera);
    const dir = v3.sub(camera.position).normalize();
    const dist = -camera.position.z / dir.z;
    return { x: camera.position.x + dir.x * dist, y: camera.position.y + dir.y * dist };
  }
  function placeFrame(el, rect, liftPx = 0) {
    const tl = worldToPx(rect.cx - rect.w / 2, rect.cy + rect.h / 2);
    const br = worldToPx(rect.cx + rect.w / 2, rect.cy - rect.h / 2);
    el.style.left = `${tl.x}px`;
    el.style.top = `${tl.y - liftPx}px`;
    el.style.width = `${br.x - tl.x}px`;
    el.style.height = `${br.y - tl.y + liftPx}px`;
  }
  function domAnchorWorld(el, fx = 0.5, fy = 0.5) {
    const vp = els.viewport.getBoundingClientRect();
    const r = el.getBoundingClientRect();
    return pxToWorld(r.left - vp.left + r.width * fx, r.top - vp.top + r.height * fy);
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
    renderer.setSize(Math.max(2, r.width), Math.max(2, r.height), false);
    camera.aspect = r.width / Math.max(2, r.height);
    camera.updateProjectionMatrix();
    L.halfH = Math.tan((camera.fov * Math.PI) / 360) * CAM_Z;
    L.halfW = L.halfH * camera.aspect;
    L.portrait = camera.aspect < 1.02;
    if (!L.portrait) {
      const w = Math.min(4.9, L.halfW * 0.80);
      L.master = { cx: -L.halfW * 0.54, cy: 0.55, w, h: w * 0.5625 };
      L.browser = { cx: L.halfW * 0.54, cy: 0.55, w, h: w * 0.5625 };
    } else {
      const w = Math.min(L.halfW * 1.72, 5.4);
      L.master = { cx: 0, cy: L.halfH * 0.46, w, h: w * 0.5625 };
      L.browser = { cx: 0, cy: -L.halfH * 0.26, w, h: w * 0.5625 };
    }
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
    for (const t of tiles) {
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
      t.keys = [
        { p: 0, x: home.x, y: home.y, z: 0, ry: 0, rz: 0, s: 1.012, o: 1, ...base },
        { p: 0.14, x: home.x, y: home.y, z: 0, ry: 0, rz: 0, s: 1.012, o: 1, ...base },
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

  function sampleKeys(keys, p, delay) {
    let a = keys[0], b = keys[keys.length - 1];
    for (let i = 0; i < keys.length - 1; i++) {
      if (p <= keys[i + 1].p) { a = keys[i]; b = keys[i + 1]; break; }
    }
    const span = Math.max(1e-6, b.p - a.p);
    const local = clamp(((p - a.p) / span - delay * 0.5) / (1 - 0.5 * 0.9), 0, 1);
    const e = easeInOut(local);
    return {
      x: lerp(a.x, b.x, e), y: lerp(a.y, b.y, e), z: lerp(a.z, b.z, e),
      ry: lerp(a.ry, b.ry, e), rz: lerp(a.rz, b.rz, e),
      s: lerp(a.s, b.s, e), o: lerp(a.o, b.o, e),
    };
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
  window.addEventListener('resize', () => { measureSection(); computeLayout(); }, { passive: true });
  window.addEventListener('load', () => { measureSection(); computeLayout(); }, { passive: true });
  if (document.fonts?.ready) document.fonts.ready.then(() => { measureSection(); computeLayout(); }).catch(() => {});

  function setPlaying(on) {
    playing = on;
    els.play.setAttribute('aria-pressed', String(on));
    els.play.textContent = on ? '❚❚ Pause' : (targetP >= 0.999 ? '↺ Replay the journey' : '▶ Play the journey');
    if (on) { playFrom = targetP >= 0.999 ? 0 : targetP; playStart = performance.now(); if (playFrom === 0) shownP = 0; }
  }
  els.play.addEventListener('click', () => setPlaying(!playing));
  els.actBtns.forEach((b, i) => {
    b.addEventListener('click', () => {
      setPlaying(false);
      const starts = [0, 0.14, 0.36, 0.58, 0.80];
      const mid = starts[i] + (ACTS[i].until - starts[i]) * 0.45;
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
      els.caption.classList.remove('swap');
    }, reduced ? 0 : 160);
  }
  function drawNoise() {
    const c = els.noise, x = c.getContext('2d');
    const img = x.createImageData(c.width, c.height);
    const d = img.data;
    for (let i = 0; i < d.length; i += 4) {
      const v = (Math.random() * 255) | 0;
      d[i] = v; d[i + 1] = (Math.random() * 255) | 0; d[i + 2] = (Math.random() * 255) | 0; d[i + 3] = 255;
    }
    x.putImageData(img, 0, 0);
  }

  let visible = true;
  new IntersectionObserver((e) => { visible = e[0].isIntersecting; }, { threshold: 0.02 }).observe(els.viewport);

  measureSection();
  computeLayout();
  targetP = scrollProgress();
  shownP = targetP;
  setAct(0);

  let frame = 0;
  function tick(now) {
    requestAnimationFrame(tick);
    if (!visible && !playing) return;
    frame += 1;

    if (playing) {
      targetP = clamp(playFrom + (now - playStart) / 16000, 0, 1);
      if (targetP >= 1) setPlaying(false);
    }
    shownP = reduced ? targetP : lerp(shownP, targetP, 0.14);
    if (Math.abs(shownP - targetP) < 0.0004) shownP = targetP;
    const p = shownP;

    // Camera: gentle dolly + attention shift master -> browser.
    camera.position.x = lerp(-0.45, 0.45, smooth(0.1, 0.9, p));
    camera.position.z = CAM_Z - Math.sin(clamp(p, 0, 1) * Math.PI) * 0.85;
    camera.position.y = Math.sin(now * 0.0004) * 0.06 * (reduced ? 0 : 1);
    camera.lookAt(0, 0, 0);
    camera.updateMatrixWorld();

    // Live world anchors from DOM panels (camera moves, so re-derive).
    const attackerPt = domAnchorWorld(els.attacker, 0.5, 0.62);
    const scannerTL = domAnchorWorld(els.scannerSlot, 0.02, 0.02);
    const scannerBR = domAnchorWorld(els.scannerSlot, 0.98, 0.98);
    const scannerRect = {
      cx: (scannerTL.x + scannerBR.x) / 2, cy: (scannerTL.y + scannerBR.y) / 2,
      w: Math.abs(scannerBR.x - scannerTL.x), h: Math.abs(scannerTL.y - scannerBR.y),
    };

    // Tiles.
    const bob = (1 - smooth(0.1, 0.16, p)) * (reduced ? 0 : Math.sin(now * 0.0012) * 0.045);
    for (const t of tiles) {
      const pose = sampleKeys(t.keys, p, t.delay);
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
      t.mesh.material.opacity = o;
    }

    // Shimmer sweep during fingerprint embed.
    const shimT = clamp((p - 0.295) / 0.055, 0, 1);
    shimmer.material.opacity = bell(p, 0.29, 0.305, 0.34, 0.355) * 0.85;
    shimmer.position.set(
      L.master.cx + lerp(-L.master.w * 0.55, L.master.w * 0.55, shimT),
      L.master.cy, 0.9,
    );

    // Leak plane: lift off the browser, fly to the scanner.
    const leakIn = smooth(0.80, 0.845, p);
    const fly = easeInOut(smooth(0.845, 0.905, p));
    leak.visible = p > 0.795;
    if (leak.visible) {
      const from = { x: L.browser.cx, y: L.browser.cy, w: L.browser.w, h: L.browser.h };
      leak.position.set(
        lerp(from.x, scannerRect.cx, fly),
        lerp(from.y, scannerRect.cy, fly) + Math.sin(fly * Math.PI) * 0.35,
        lerp(0.06, 0.55, leakIn * (1 - fly * 0.5)),
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
    const tokenPt = worldToPx(L.master.cx + L.master.w * 0.30, L.master.cy - L.master.h * 0.82);
    const vpW = els.viewport.clientWidth || 1;
    const chipHalf = (els.token.offsetWidth || 240) / 2 + 6;
    els.token.style.left = `${clamp(tokenPt.x, chipHalf, Math.max(chipHalf, vpW - chipHalf))}px`;
    els.token.style.top = `${tokenPt.y}px`;

    // Panel + chip choreography.
    els.serverbox.style.opacity = String(0.35 + 0.65 * (1 - smooth(0.3, 0.42, p)));
    els.browser.style.opacity = String(0.35 + 0.65 * smooth(0.3, 0.5, p));
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
    els.hint.style.opacity = String((1 - smooth(0.015, 0.07, p)) * (playing ? 0 : 1));
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
