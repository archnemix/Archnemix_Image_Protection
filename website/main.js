/* Archnemix site — hero demonstration.
 * A painting is generated in-browser, split into an 8x8 field of 3D
 * tiles, and scrambled exactly the way Archx scrambles real payloads:
 * a keyed permutation with per-tile mirrors. "Visitor's view"
 * reassembles it; "On the wire" shows what extraction collects. */

const REDUCED = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/* ---------- copy-to-clipboard ---------- */
const copyBtn = document.getElementById('copyInstall');
copyBtn?.addEventListener('click', async () => {
  const text = document.getElementById('installCmd')?.textContent?.trim() ?? '';
  try {
    await navigator.clipboard.writeText(text);
    copyBtn.textContent = 'Copied';
  } catch {
    copyBtn.textContent = 'Select & copy';
    const range = document.createRange();
    range.selectNode(document.getElementById('installCmd'));
    const sel = window.getSelection();
    sel.removeAllRanges(); sel.addRange(range);
  }
  setTimeout(() => { copyBtn.textContent = 'Copy'; }, 2200);
});

/* ---------- the painting (procedural, seeded) ---------- */
function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function paintValley(w, h) {
  const c = document.createElement('canvas');
  c.width = w; c.height = h;
  const x = c.getContext('2d');
  const rand = mulberry32(0xa2c4e6);

  // dusk sky
  const sky = x.createLinearGradient(0, 0, 0, h * 0.72);
  sky.addColorStop(0, '#0b2620');
  sky.addColorStop(0.38, '#175144');
  sky.addColorStop(0.72, '#6d9a7e');
  sky.addColorStop(1, '#d9c9a3');
  x.fillStyle = sky;
  x.fillRect(0, 0, w, h);

  // stars (upper sky)
  for (let i = 0; i < 220; i++) {
    const sx = rand() * w, sy = rand() * h * 0.42;
    x.fillStyle = `rgba(240,238,220,${0.12 + rand() * 0.5})`;
    x.fillRect(sx, sy, rand() < 0.12 ? 2 : 1, 1);
  }

  // aurora ribbons
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

  // moon
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

  // mountain layers, back to front
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

  // valley floor and lake
  const lakeY = h * 0.8;
  const floor = x.createLinearGradient(0, lakeY - h * 0.06, 0, h);
  floor.addColorStop(0, '#14382a');
  floor.addColorStop(0.25, '#275c46');
  floor.addColorStop(0.55, '#173e2f');
  floor.addColorStop(1, '#08190f');
  x.fillStyle = floor;
  x.fillRect(0, lakeY - h * 0.045, w, h - lakeY + h * 0.045);
  // moonlight + aurora shimmer on the water
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

  // foreground pines
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

  // grain + vignette
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

/* ---------- 3D tile field ---------- */
const GRID = 8;
const PLANE_W = 8.8, PLANE_H = 5.5;

async function startStage() {
  const canvas = document.getElementById('gl');
  const frame = canvas.parentElement;
  let THREE;
  try {
    THREE = await import('three');
  } catch { throw new Error('three unavailable'); }

  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: false });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.75));
  const scene = new THREE.Scene();
  scene.background = new THREE.Color(0x101410);

  const camera = new THREE.PerspectiveCamera(37, 16 / 10, 0.1, 60);
  camera.position.set(0, 0.35, 9.4);
  camera.lookAt(0, 0, 0);

  scene.add(new THREE.AmbientLight(0xfff2dd, 0.85));
  const key = new THREE.DirectionalLight(0xffe9c4, 1.5);
  key.position.set(-4, 5, 6);
  scene.add(key);
  const rim = new THREE.DirectionalLight(0x9fd8b4, 0.5);
  rim.position.set(5, -3, 4);
  scene.add(rim);

  const texture = new THREE.CanvasTexture(paintValley(1024, 640));
  texture.colorSpace = THREE.SRGBColorSpace;
  texture.anisotropy = 4;

  const group = new THREE.Group();
  scene.add(group);

  const tw = PLANE_W / GRID, th = PLANE_H / GRID;
  const geo = new THREE.BoxGeometry(tw * 0.982, th * 0.982, 0.07);
  const side = new THREE.MeshStandardMaterial({ color: 0x2b2620, roughness: 0.9 });
  const tiles = [];
  const slotPos = (i) => ({
    x: (i % GRID) * tw - PLANE_W / 2 + tw / 2,
    y: PLANE_H / 2 - th / 2 - Math.floor(i / GRID) * th,
  });

  for (let row = 0; row < GRID; row++) {
    for (let col = 0; col < GRID; col++) {
      const idx = row * GRID + col;
      const t = texture.clone();
      t.wrapS = t.wrapT = THREE.ClampToEdgeWrapping;
      t.repeat.set(1 / GRID, 1 / GRID);
      t.offset.set(col / GRID, 1 - (row + 1) / GRID);
      t.needsUpdate = true;
      const face = new THREE.MeshStandardMaterial({ map: t, roughness: 0.62, metalness: 0.02 });
      // Face material on both z faces: a pi-rotated tile reads as the
      // mirrored picture, exactly like a real fx-flipped payload tile.
      const mesh = new THREE.Mesh(geo, [side, side, side, side, face, face]);
      const home = slotPos(idx);
      mesh.position.set(home.x, home.y, 0);
      group.add(mesh);
      tiles.push({
        mesh, idx,
        tx: home.x, ty: home.y, tz: 0,        // targets
        flip: 0,                               // target rotY (0 or PI)
        lift: 0,                               // pointer lift (smoothed)
        speed: 2.6 + ((idx * 37) % 10) / 6,    // deterministic stagger
      });
    }
  }

  /* ----- state: assembled vs scrambled ----- */
  let scrambled = false;
  let round = 0;
  const tag = document.getElementById('stageTag');
  const caption = document.getElementById('stageCaption');
  const btnView = document.getElementById('btnView');
  const btnWire = document.getElementById('btnWire');

  function setScrambled(on) {
    scrambled = on;
    round++;
    const rand = mulberry32(0x5eed + round * 7919);
    const order = [...Array(GRID * GRID).keys()];
    if (on) {
      for (let i = order.length - 1; i > 0; i--) {
        const j = Math.floor(rand() * (i + 1));
        [order[i], order[j]] = [order[j], order[i]];
      }
    }
    for (const tile of tiles) {
      const dest = on ? order[tile.idx] : tile.idx;
      const p = slotPos(dest);
      tile.tx = p.x; tile.ty = p.y;
      tile.tz = on ? (rand() - 0.3) * 0.55 : 0;
      tile.flip = on && rand() < 0.42 ? Math.PI : 0;
    }
    tag.textContent = on ? 'On the wire — the payload' : 'Your visitor’s view';
    caption.innerHTML = on
      ? 'Tiles permuted and mirrored under a 128-bit-seeded plan (optionally AES-256-GCM sealed). This — at display resolution only — is all a scraper, proxy or DevTools session ever downloads.'
      : 'Reassembled, per-viewer, inside a canvas — never as an <span class="mono">&lt;img&gt;</span> with an address. Move your pointer across it; click to scatter.';
    btnView.classList.toggle('is-active', !on);
    btnWire.classList.toggle('is-active', on);
  }
  btnView.addEventListener('click', () => { poke(); setScrambled(false); });
  btnWire.addEventListener('click', () => { poke(); setScrambled(true); });
  canvas.addEventListener('click', () => { poke(); setScrambled(!scrambled); });

  /* ----- pointer presence ----- */
  const pointer = { x: 999, y: 999, active: false, parX: 0, parY: 0 };
  canvas.addEventListener('pointermove', (e) => {
    const r = canvas.getBoundingClientRect();
    pointer.x = ((e.clientX - r.left) / r.width - 0.5) * PLANE_W;
    pointer.y = -((e.clientY - r.top) / r.height - 0.5) * PLANE_H;
    pointer.parX = (e.clientX - r.left) / r.width - 0.5;
    pointer.parY = (e.clientY - r.top) / r.height - 0.5;
    pointer.active = true;
  });
  canvas.addEventListener('pointerleave', () => { pointer.active = false; });

  /* ----- auto-cycle (calm; off for reduced motion) ----- */
  let lastPoke = performance.now();
  function poke() { lastPoke = performance.now(); }
  if (!REDUCED) {
    setInterval(() => {
      if (performance.now() - lastPoke > 14000 && visible) setScrambled(!scrambled);
    }, 9000);
  }

  /* ----- resize + visibility ----- */
  function fit() {
    const w = frame.clientWidth, h = frame.clientHeight;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  fit();
  new ResizeObserver(fit).observe(frame);

  let visible = true;
  new IntersectionObserver(([en]) => { visible = en.isIntersecting; }, { threshold: 0.05 }).observe(frame);

  /* ----- render loop ----- */
  const clock = new THREE.Clock();
  const ease = REDUCED ? 1 : 0; // reduced motion: snap, no sweeps
  function tick() {
    requestAnimationFrame(tick);
    if (!visible) return;
    const dt = Math.min(clock.getDelta(), 0.05);
    const R = 1.9; // pointer influence radius (world units)
    for (const tile of tiles) {
      const m = tile.mesh;
      const k = ease === 1 ? 1 : 1 - Math.exp(-tile.speed * dt * 2.2);
      m.position.x += (tile.tx - m.position.x) * k;
      m.position.y += (tile.ty - m.position.y) * k;
      // pointer lift
      let targetLift = 0, tiltX = 0, tiltY = 0;
      if (pointer.active && !REDUCED) {
        const dx = m.position.x - pointer.x, dy = m.position.y - pointer.y;
        const d = Math.hypot(dx, dy);
        if (d < R) {
          const f = (1 - d / R) ** 2;
          targetLift = f * 0.62;
          tiltY = (dx / R) * f * 0.5;
          tiltX = -(dy / R) * f * 0.5;
        }
      }
      tile.lift += (targetLift - tile.lift) * (1 - Math.exp(-dt * 9));
      m.position.z = tile.tz + tile.lift + (m.position.z - tile.tz - tile.lift) * Math.exp(-dt * 6);
      // flip rotation (shortest path kept simple: exponential approach)
      m.rotation.y += (tile.flip + tiltY - m.rotation.y) * (1 - Math.exp(-tile.speed * dt * 1.9));
      m.rotation.x += (tiltX - m.rotation.x) * (1 - Math.exp(-dt * 9));
    }
    if (!REDUCED) {
      const gx = pointer.parY * -0.05, gy = pointer.parX * 0.07;
      group.rotation.x += (gx - group.rotation.x) * (1 - Math.exp(-dt * 3));
      group.rotation.y += (gy - group.rotation.y) * (1 - Math.exp(-dt * 3));
    }
    renderer.render(scene, camera);
  }
  tick();
  window.__archxGlReady = true;
}

startStage().catch(() => {
  document.getElementById('gl')?.remove();
  const fb = document.getElementById('stageFallback');
  if (fb) fb.hidden = false;
  const tag = document.getElementById('stageTag');
  if (tag) tag.textContent = 'The idea, in words';
});
