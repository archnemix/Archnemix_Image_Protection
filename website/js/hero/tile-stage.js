/* Archnemix overview page: shared UI + interactive 3D tile-scramble stage
   using the real plan-v2 permutation and per-tile mirror flips. */

import { initSharedUi } from '../shared/ui.js';
import { buildScramblePlan } from '../shared/plan-port.js';
import { paintValley } from './painting.js';

initSharedUi();

const REDUCED = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
const PLANE_W = 8.8;
const PLANE_H = 5.5;

async function startStage() {
  const canvas = document.getElementById('gl');
  if (!canvas) return;
  const frame = canvas.parentElement;
  const THREE = await import('three');

  const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: false });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.85));

  const scene = new THREE.Scene();
  scene.background = new THREE.Color(0x101410);

  const camera = new THREE.PerspectiveCamera(37, 16 / 10, 0.1, 60);
  camera.position.set(0, 0.32, 9.35);
  camera.lookAt(0, 0, 0);

  scene.add(new THREE.AmbientLight(0xfff2dd, 0.88));
  const keyLight = new THREE.DirectionalLight(0xffe9c4, 1.48);
  keyLight.position.set(-4, 5, 6);
  scene.add(keyLight);
  const rimLight = new THREE.DirectionalLight(0x9fd8b4, 0.52);
  rimLight.position.set(5, -3, 4);
  scene.add(rimLight);

  const texture = new THREE.CanvasTexture(paintValley(1024, 640));
  texture.colorSpace = THREE.SRGBColorSpace;
  texture.anisotropy = 4;

  const group = new THREE.Group();
  scene.add(group);
  const sideMat = new THREE.MeshStandardMaterial({ color: 0x2b2620, roughness: 0.88 });

  let gridN = 8;
  let tiles = [];
  let tileGeo = null;
  let plan = null;
  let scrambled = false;

  const slotPos = (i) => {
    const tw = PLANE_W / gridN;
    const th = PLANE_H / gridN;
    return {
      x: (i % gridN) * tw - PLANE_W / 2 + tw / 2,
      y: PLANE_H / 2 - th / 2 - Math.floor(i / gridN) * th,
    };
  };

  function buildTiles(nextGrid) {
    for (const t of tiles) {
      group.remove(t.mesh);
      const mats = Array.isArray(t.mesh.material) ? t.mesh.material : [t.mesh.material];
      for (const m of mats) {
        if (m !== sideMat) {
          m.map?.dispose();
          m.dispose();
        }
      }
    }
    tileGeo?.dispose();

    gridN = nextGrid;
    tiles = [];
    plan = buildScramblePlan(gridN, 'archx-hero-2026', 2);

    const tw = PLANE_W / gridN;
    const th = PLANE_H / gridN;
    tileGeo = new THREE.BoxGeometry(tw * 0.982, th * 0.982, 0.07);

    for (let row = 0; row < gridN; row++) {
      for (let col = 0; col < gridN; col++) {
        const idx = row * gridN + col;
        const t = texture.clone();
        t.wrapS = THREE.ClampToEdgeWrapping;
        t.wrapT = THREE.ClampToEdgeWrapping;
        t.repeat.set(1 / gridN, 1 / gridN);
        t.offset.set(col / gridN, 1 - (row + 1) / gridN);
        t.needsUpdate = true;

        const face = new THREE.MeshStandardMaterial({
          map: t,
          roughness: 0.6,
          metalness: 0.02,
        });
        const mesh = new THREE.Mesh(tileGeo, [sideMat, sideMat, sideMat, sideMat, face, face]);
        const home = slotPos(idx);
        mesh.position.set(home.x, home.y, 0);
        mesh.userData.tileIdx = idx;
        group.add(mesh);

        tiles.push({
          mesh,
          idx,
          face,
          x: home.x,
          y: home.y,
          z: 0,
          vx: 0,
          vy: 0,
          vz: 0,
          tx: home.x,
          ty: home.y,
          tz: 0,
          rotX: 0,
          rotY: 0,
          tRotX: 0,
          tRotY: 0,
          slot: idx,
          fx: false,
          fy: false,
          delay: ((row + col) / (gridN * 2)) * 0.16,
          flight: 0,
        });
      }
    }
  }

  let transitionAge = 0;
  let hoveredTile = -1;
  function applyTargets(nextScrambled) {
    scrambled = nextScrambled;
    transitionAge = 0;
    for (let i = 0; i < tiles.length; i++) {
      const tile = tiles[i];
      if (!scrambled) {
        const home = slotPos(tile.idx);
        tile.tx = home.x;
        tile.ty = home.y;
        tile.tz = 0;
        tile.tRotX = 0;
        tile.tRotY = 0;
        tile.slot = tile.idx;
        tile.fx = false;
        tile.fy = false;
      } else {
        const slot = plan.inverse[tile.idx];
        const dest = slotPos(slot);
        const f = plan.flips[slot];
        const waveZ = (((tile.idx * 29) % 13) / 13) * 0.24 - 0.12;
        tile.tx = dest.x;
        tile.ty = dest.y;
        tile.tz = waveZ;
        tile.tRotY = f.fx ? Math.PI : 0;
        tile.tRotX = f.fy ? Math.PI : 0;
        tile.slot = slot;
        tile.fx = f.fx;
        tile.fy = f.fy;
      }
      tile.flight = 1;
    }
  }

  const btnView = document.getElementById('btnView');
  const btnWire = document.getElementById('btnWire');
  const tag = document.getElementById('stageTag');
  const badgeWire = document.getElementById('stageWireBadge');
  const caption = document.getElementById('stageCaption');
  const readout = document.getElementById('stageReadout');
  const statsEl = document.getElementById('stageStats');

  function setMode(nextScrambled) {
    applyTargets(nextScrambled);
    btnView?.classList.toggle('is-active', !nextScrambled);
    btnWire?.classList.toggle('is-active', nextScrambled);
    btnView?.setAttribute('aria-pressed', String(!nextScrambled));
    btnWire?.setAttribute('aria-pressed', String(nextScrambled));

    if (tag) tag.textContent = nextScrambled ? 'On the wire · .archx payload' : "Your visitor's view";
    if (badgeWire) badgeWire.hidden = !nextScrambled;
    if (caption) {
      caption.innerHTML = nextScrambled
        ? `What DevTools or a scraper captures: ${gridN * gridN} permuted, mirrored tiles (plan v2) inside an <span class="mono">application/octet-stream</span> envelope.`
        : 'Reassembled, per-viewer, inside a canvas — never as an <span class="mono">&lt;img&gt;</span> with an address. Drag to orbit, hover a tile to trace it, press Space to toggle.';
    }
    if (!nextScrambled && readout && hoveredTile < 0) {
      readout.textContent = 'Hover a tile to trace where it travels.';
    }
  }

  buildTiles(8);
  setMode(false);

  btnView?.addEventListener('click', () => setMode(false));
  btnWire?.addEventListener('click', () => setMode(true));

  document.querySelectorAll('#gridSeg button').forEach((btn) => {
    btn.addEventListener('click', () => {
      const nextGrid = Number(btn.dataset.g);
      document.querySelectorAll('#gridSeg button').forEach((b) => {
        const active = b === btn;
        b.classList.toggle('is-active', active);
        b.setAttribute('aria-pressed', String(active));
      });
      const wasScrambled = scrambled;
      buildTiles(nextGrid);
      applyTargets(wasScrambled);
      if (statsEl) {
        statsEl.textContent = `${nextGrid * nextGrid} tiles · plan v2 · drag to orbit · hover a tile · space to toggle`;
      }
      if (readout) {
        readout.textContent = `Switched to ${nextGrid}×${nextGrid} (${nextGrid * nextGrid} tiles). Hover a tile to trace it.`;
      }
    });
  });

  // Resize cleanly with device box
  function resize() {
    const r = frame.getBoundingClientRect();
    const w = Math.max(240, Math.round(r.width));
    const h = Math.max(180, Math.round(r.height));
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  resize();
  window.addEventListener('resize', resize);

  // Orbit + hover raycast + scatter pulse
  const raycaster = new THREE.Raycaster();
  const pointer = new THREE.Vector2(-99, -99);
  let dragging = false;
  let movedDrag = false;
  let dragStartX = 0;
  let dragStartY = 0;
  let orbitY = 0;
  let orbitX = 0;
  let targetOrbitY = 0;
  let targetOrbitX = 0;

  canvas.addEventListener('pointerdown', (e) => {
    dragging = true;
    movedDrag = false;
    dragStartX = e.clientX;
    dragStartY = e.clientY;
    canvas.setPointerCapture?.(e.pointerId);
  });

  canvas.addEventListener('pointermove', (e) => {
    const rect = canvas.getBoundingClientRect();
    pointer.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
    pointer.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;
    if (dragging) {
      const dx = e.clientX - dragStartX;
      const dy = e.clientY - dragStartY;
      if (Math.abs(dx) > 3 || Math.abs(dy) > 3) movedDrag = true;
      targetOrbitY = Math.max(-0.55, Math.min(0.55, targetOrbitY + dx * 0.0042));
      targetOrbitX = Math.max(-0.35, Math.min(0.35, targetOrbitX + dy * 0.0036));
      dragStartX = e.clientX;
      dragStartY = e.clientY;
    }
  });

  canvas.addEventListener('pointerup', (e) => {
    dragging = false;
    canvas.releasePointerCapture?.(e.pointerId);
    if (!movedDrag) setMode(!scrambled);
  });

  canvas.addEventListener('pointerleave', () => {
    dragging = false;
    pointer.set(-99, -99);
    hoveredTile = -1;
  });

  canvas.addEventListener('keydown', (e) => {
    if (e.code === 'Space' || e.code === 'Enter') {
      e.preventDefault();
      setMode(!scrambled);
    } else if (e.code === 'ArrowLeft') {
      targetOrbitY = Math.max(-0.55, targetOrbitY - 0.1);
    } else if (e.code === 'ArrowRight') {
      targetOrbitY = Math.min(0.55, targetOrbitY + 0.1);
    }
  });

  let lastTime = performance.now();
  let running = true;
  document.addEventListener('visibilitychange', () => {
    running = !document.hidden;
    if (running) lastTime = performance.now();
  });

  function tick(now) {
    requestAnimationFrame(tick);
    if (!running) return;
    const dt = Math.min(0.05, Math.max(0.001, (now - lastTime) / 1000));
    lastTime = now;
    transitionAge += dt;

    // Gentle idle drift when not dragging
    const idleY = REDUCED ? 0 : Math.sin(now * 0.00055) * 0.055;
    const idleX = REDUCED ? 0 : Math.cos(now * 0.00042) * 0.025;
    orbitY += (targetOrbitY + idleY - orbitY) * Math.min(1, dt * 6);
    orbitX += (targetOrbitX + idleX - orbitX) * Math.min(1, dt * 6);
    group.rotation.y = orbitY;
    group.rotation.x = orbitX;

    // Raycast hover
    if (pointer.x > -2 && !dragging) {
      raycaster.setFromCamera(pointer, camera);
      const hits = raycaster.intersectObjects(group.children, false);
      const nextHover = hits[0]?.object?.userData?.tileIdx ?? -1;
      if (nextHover !== hoveredTile) {
        hoveredTile = nextHover;
        if (hoveredTile >= 0 && readout) {
          const tile = tiles[hoveredTile];
          const srcRow = Math.floor(tile.idx / gridN) + 1;
          const srcCol = (tile.idx % gridN) + 1;
          const slot = plan.inverse[tile.idx];
          const dstRow = Math.floor(slot / gridN) + 1;
          const dstCol = (slot % gridN) + 1;
          const f = plan.flips[slot];
          const mirrors = [f.fx ? 'H-flip' : '', f.fy ? 'V-flip' : ''].filter(Boolean).join(' + ') || 'unmirrored';
          readout.textContent = `Tile #${tile.idx} (r${srcRow}:c${srcCol}) → wire slot #${slot} (r${dstRow}:c${dstCol}) · ${mirrors}`;
        }
      }
    }

    // Spring-damped tile flight + subtle lift on hover
    const stiffness = REDUCED ? 28 : 11.5;
    for (let i = 0; i < tiles.length; i++) {
      const t = tiles[i];
      const active = transitionAge >= t.delay;
      const hoverLift = t.idx === hoveredTile ? 0.34 : 0;
      const targetZ = (active ? t.tz : t.z) + hoverLift;

      if (active) {
        const k = Math.min(1, dt * stiffness);
        const dx = t.tx - t.x;
        const dy = t.ty - t.y;
        const dist = Math.hypot(dx, dy);
        const arcZ = dist > 0.05 ? Math.min(0.85, dist * 0.18) : 0;

        t.x += dx * k;
        t.y += dy * k;
        t.z += (targetZ + arcZ - t.z) * k;
        t.rotX += (t.tRotX - t.rotX) * k;
        t.rotY += (t.tRotY - t.rotY) * k;
      } else {
        t.z += (targetZ - t.z) * Math.min(1, dt * 10);
      }

      t.mesh.position.set(t.x, t.y, t.z);
      t.mesh.rotation.set(t.rotX, t.rotY, 0);
      t.face.emissive.setHex(t.idx === hoveredTile ? 0x243b6b : 0x000000);
    }

    renderer.render(scene, camera);
  }

  window.__archxGlReady = true;
  requestAnimationFrame(tick);
}

startStage().catch(() => {
  const fb = document.getElementById('stageFallback');
  const gl = document.getElementById('gl');
  if (gl) gl.remove();
  if (fb) fb.hidden = false;
});
