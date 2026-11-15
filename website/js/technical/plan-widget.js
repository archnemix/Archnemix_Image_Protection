/* W1 — Interactive scramble plan visualizer (real shipped algorithm)
   with animated correspondence arc on tile hover. */
import { buildScramblePlan } from '../shared/plan-port.js';

export function initPlanWidget() {
  const planCanvas = document.getElementById('planCanvas');
  if (!planCanvas) return;

  const state = { grid: 8, version: 2, plan: null, hover: -1 };

  function tileColor(idx, count) {
    const t = idx / Math.max(1, count - 1);
    const hue = 95 - t * 60;
    const light = 30 + (Math.sin(idx * 12.9898) * 0.5 + 0.5) * 18;
    return `hsl(${hue} 42% ${light}%)`;
  }

  function drawPlan() {
    const key = document.getElementById('planKey')?.value ?? '';
    const plan = buildScramblePlan(state.grid, key, state.version);
    state.plan = plan;

    const ctx = planCanvas.getContext('2d');
    const W = planCanvas.width;
    const H = planCanvas.height;
    ctx.clearRect(0, 0, W, H);
    ctx.fillStyle = '#fcfaf5';
    ctx.fillRect(0, 0, W, H);

    const g = plan.grid;
    const board = Math.min(H - 56, (W - 180) / 2);
    const cell = board / g;
    const y0 = 40;
    const leftX = 30;
    const rightX = W - 30 - board;

    ctx.fillStyle = '#172026';
    ctx.font = '600 13px Georgia, serif';
    ctx.fillText('Original tiles', leftX, 22);
    ctx.fillText('On the wire (scrambled positions)', rightX, 22);

    const drawBoard = (ox, scrambledSide) => {
      for (let i = 0; i < plan.count; i++) {
        const tile = scrambledSide ? plan.order[i] : i;
        const x = ox + (i % g) * cell;
        const y = y0 + Math.floor(i / g) * cell;
        ctx.fillStyle = tileColor(tile, plan.count);
        ctx.fillRect(x + 0.5, y + 0.5, cell - 1, cell - 1);

        if (state.hover >= 0 && state.hover !== tile) {
          ctx.fillStyle = 'rgba(252,250,245,0.42)';
          ctx.fillRect(x + 0.5, y + 0.5, cell - 1, cell - 1);
        }
        if (state.hover === tile) {
          ctx.strokeStyle = '#b43d26';
          ctx.lineWidth = 3;
          ctx.strokeRect(x + 1.5, y + 1.5, cell - 3, cell - 3);
        }
        if (cell >= 17) {
          ctx.fillStyle = 'rgba(255,253,247,0.92)';
          ctx.font = `${Math.min(12, cell * 0.42)}px ui-monospace, monospace`;
          ctx.fillText(String(tile), x + 3, y + Math.min(14, cell * 0.52));
          const f = plan.flips[scrambledSide ? i : plan.inverse[tile]];
          const marks = (f.fx ? '⇋' : '') + (f.fy ? '⇅' : '');
          if (marks && scrambledSide) ctx.fillText(marks, x + 3, y + cell - 4);
        }
      }
    };

    drawBoard(leftX, false);
    drawBoard(rightX, true);

    const midY = y0 + board / 2;
    ctx.strokeStyle = '#2d529e';
    ctx.fillStyle = '#2d529e';
    ctx.lineWidth = 2.5;
    ctx.beginPath();
    ctx.moveTo(leftX + board + 18, midY);
    ctx.lineTo(rightX - 18, midY);
    ctx.stroke();
    ctx.beginPath();
    ctx.moveTo(rightX - 18, midY);
    ctx.lineTo(rightX - 30, midY - 7);
    ctx.lineTo(rightX - 30, midY + 7);
    ctx.closePath();
    ctx.fill();

    if (state.hover >= 0) {
      const tile = state.hover;
      const slot = plan.inverse[tile];
      const f = plan.flips[slot];

      const sx = leftX + (tile % g + 0.5) * cell;
      const sy = y0 + (Math.floor(tile / g) + 0.5) * cell;
      const dx = rightX + (slot % g + 0.5) * cell;
      const dy = y0 + (Math.floor(slot / g) + 0.5) * cell;
      const mx = (sx + dx) / 2;
      const my = Math.min(sy, dy) - 48;

      ctx.save();
      ctx.strokeStyle = '#b43d26';
      ctx.lineWidth = 2.2;
      ctx.setLineDash([5, 4]);
      ctx.beginPath();
      ctx.moveTo(sx, sy);
      ctx.quadraticCurveTo(mx, my, dx, dy);
      ctx.stroke();
      ctx.setLineDash([]);
      ctx.fillStyle = '#b43d26';
      ctx.beginPath();
      ctx.arc(sx, sy, 4, 0, Math.PI * 2);
      ctx.arc(dx, dy, 4, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();

      const out = document.getElementById('planOut');
      if (out) {
        out.textContent = `tile ${tile} (row ${Math.floor(tile / g) + 1}, col ${(tile % g) + 1}) → wire slot ${slot}`
          + `${f.fx ? ' · mirrored horizontally' : ''}${f.fy ? ' · mirrored vertically' : ''}${!f.fx && !f.fy ? ' · unmirrored' : ''}`
          + ` — plan v${plan.version}, grid ${g}×${g}`;
      }
    }
  }

  planCanvas.addEventListener('pointermove', (e) => {
    const r = planCanvas.getBoundingClientRect();
    const plan = state.plan;
    if (!plan) return;
    const g = plan.grid;
    const W = planCanvas.width;
    const H = planCanvas.height;
    const board = Math.min(H - 56, (W - 180) / 2);
    const cell = board / g;
    const y0 = 40;
    const leftX = 30;
    const rightX = W - 30 - board;
    const px = (e.clientX - r.left) * (W / r.width);
    const py = (e.clientY - r.top) * (H / r.height);

    const pick = (ox, scrambledSide) => {
      const cx = Math.floor((px - ox) / cell);
      const cy = Math.floor((py - y0) / cell);
      if (cx < 0 || cy < 0 || cx >= g || cy >= g) return -1;
      const pos = cy * g + cx;
      return scrambledSide ? plan.order[pos] : pos;
    };

    let tile = pick(leftX, false);
    if (tile < 0) tile = pick(rightX, true);
    if (tile !== state.hover) {
      state.hover = tile;
      drawPlan();
    }
  });

  planCanvas.addEventListener('pointerleave', () => {
    state.hover = -1;
    drawPlan();
  });

  document.getElementById('planKey')?.addEventListener('input', drawPlan);

  document.querySelectorAll('#planGridSeg button').forEach((b) => {
    b.addEventListener('click', () => {
      state.grid = Number(b.dataset.g);
      document.querySelectorAll('#planGridSeg button').forEach((x) => {
        const active = x === b;
        x.classList.toggle('is-active', active);
        x.setAttribute('aria-pressed', String(active));
      });
      drawPlan();
    });
  });

  document.querySelectorAll('#planVerSeg button').forEach((b) => {
    b.addEventListener('click', () => {
      state.version = Number(b.dataset.v);
      document.querySelectorAll('#planVerSeg button').forEach((x) => {
        const active = x === b;
        x.classList.toggle('is-active', active);
        x.setAttribute('aria-pressed', String(active));
      });
      drawPlan();
    });
  });

  document.getElementById('planRandom')?.addEventListener('click', () => {
    const input = document.getElementById('planKey');
    if (input) input.value = `key-${Math.random().toString(36).slice(2, 10)}`;
    drawPlan();
  });

  document.getElementById('d-plan-v2')?.addEventListener('decision:open', drawPlan, { once: true });
  drawPlan();
}
