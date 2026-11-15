/* W5 — Animated watermark survival chart (measured data, RESEARCH §2.28) */

export function initSurvivalWidget() {
  if (!document.getElementById('w-survival')) return;

  const REDUCED = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
  let survMode = 'class';
  let animRaf = 0;

  const SURV = {
    class: {
      title: 'Layout 4, robust profile — recovered by content class',
      bars: [
        ['Photos', 30, 33],
        ['Graphics', 33, 33],
        ['Flat / UI', 11, 11],
        ['Text-heavy', 10, 11],
        ['Adversarial periodic', 0, 11],
      ],
    },
    totals: {
      title: 'All 99 cases — layout 3 (default) vs layout 4 (opt-in)',
      bars: [
        ['Robust · L3', 85, 99],
        ['Robust · L4', 84, 99],
        ['Standard · L3', 63, 99],
        ['Standard · L4', 63, 99],
      ],
    },
  };

  function renderFrame(progress) {
    const canvas = document.getElementById('survCanvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const W = canvas.width;
    const H = canvas.height;
    ctx.clearRect(0, 0, W, H);
    ctx.fillStyle = '#fcfaf5';
    ctx.fillRect(0, 0, W, H);

    const data = SURV[survMode];
    ctx.fillStyle = '#172026';
    ctx.font = '600 14px Georgia, serif';
    ctx.fillText(data.title, 18, 24);

    const chartX = 190;
    const chartW = W - chartX - 96;
    const top = 48;
    const rowH = Math.min(44, (H - top - 16) / data.bars.length);

    data.bars.forEach(([label, got, of], i) => {
      const y = top + i * rowH;
      const t = REDUCED ? 1 : Math.max(0, Math.min(1, (progress - i * 0.08) / 0.65));
      const eased = 1 - Math.pow(1 - t, 3);
      ctx.font = '13px Georgia, serif';
      ctx.fillStyle = '#172026';
      ctx.fillText(label, 18, y + rowH * 0.62);

      ctx.fillStyle = '#e5dcc6';
      ctx.fillRect(chartX, y + 4, chartW, rowH - 16);

      ctx.fillStyle = got === 0 ? '#172026' : '#2d529e';
      ctx.fillRect(chartX, y + 4, chartW * (got / of) * eased, rowH - 16);

      ctx.fillStyle = '#172026';
      ctx.font = '600 13px ui-monospace, monospace';
      ctx.fillText(`${got}/${of} · ${Math.round((got / of) * 100)}%`, chartX + chartW + 10, y + rowH * 0.62);
    });
  }

  function updateNote() {
    const note = document.getElementById('survNote');
    if (!note) return;
    if (survMode === 'totals') {
      note.innerHTML = 'Recorded on the 1.30.2 StegoMark implementation (unchanged through 1.30.4). The one-case robust gap is why layout 3 remains the default (D-13) — the flip bar was written <em>before</em> measuring. Layout 4 wins on quality: +1.4 dB PSNR on photos. False positives: <strong>0/369</strong> wrong-key checks (95% upper bound ≈0.81%).';
    } else {
      note.innerHTML = 'Recorded on the 1.30.2 StegoMark implementation (unchanged through 1.30.4): 9 images × 11 fixed transform cases (JPEG q80/q50, resize, center/corner crop+resize, 90° rotation, flop, transpose, brightness+JPEG; no screenshot/camera captures). Robust: 85/99; standard: 63/99. False positives: <strong>0/369</strong> wrong-key checks (95% upper bound ≈0.81%). Timings and budgets are in the evidence artifact. Re-run: <span class="mono">npm run bench:stego:evidence</span>.';
    }
  }

  function animateSurvival() {
    cancelAnimationFrame(animRaf);
    updateNote();
    if (REDUCED) {
      renderFrame(1);
      return;
    }
    const start = performance.now();
    const step = (now) => {
      const p = Math.min(1, (now - start) / 620);
      renderFrame(p);
      if (p < 1) animRaf = requestAnimationFrame(step);
    };
    animRaf = requestAnimationFrame(step);
  }

  document.querySelectorAll('#survSeg button').forEach((b) => {
    b.addEventListener('click', () => {
      survMode = b.dataset.m;
      document.querySelectorAll('#survSeg button').forEach((x) => {
        const active = x === b;
        x.classList.toggle('is-active', active);
        x.setAttribute('aria-pressed', String(active));
      });
      animateSurvival();
    });
  });

  document.getElementById('d-classical')?.addEventListener('decision:open', animateSurvival, { once: true });
  renderFrame(1);
  updateNote();
}
