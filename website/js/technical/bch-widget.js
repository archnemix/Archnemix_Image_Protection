/* W4 — BCH errors/erasures recovery map (schematic) */

export function initBchWidget() {
  if (!document.getElementById('w-bch')) return;

  function drawBch() {
    const canvas = document.getElementById('bchCanvas');
    if (!canvas) return;
    const s = Number(document.getElementById('bchS')?.value ?? 69);
    const e = Number(document.getElementById('bchE')?.value ?? 13);
    document.getElementById('bchSV').textContent = s;
    document.getElementById('bchEV').textContent = e;

    const ctx = canvas.getContext('2d');
    const W = canvas.width;
    const H = canvas.height;
    ctx.clearRect(0, 0, W, H);
    ctx.fillStyle = '#fcfaf5';
    ctx.fillRect(0, 0, W, H);

    const x0 = 56;
    const y0 = 18;
    const x1 = W - 18;
    const y1 = H - 42;
    const maxS = 130;
    const maxE = 42;
    const X = (v) => x0 + (v / maxS) * (x1 - x0);
    const Y = (v) => y1 - (v / maxE) * (y1 - y0);

    ctx.fillStyle = 'rgba(180,61,38,0.10)';
    ctx.beginPath();
    ctx.moveTo(X(0), Y(0));
    ctx.lineTo(X(124), Y(0));
    ctx.lineTo(X(124), Y(0.22 * 64));
    ctx.lineTo(X(0), Y(0.22 * 188));
    ctx.closePath();
    ctx.fill();

    ctx.fillStyle = 'rgba(180,61,38,0.20)';
    ctx.beginPath();
    ctx.moveTo(X(0), Y(0));
    ctx.lineTo(X(124), Y(0));
    ctx.lineTo(X(124), Y(2));
    ctx.lineTo(X(36), Y(6));
    ctx.lineTo(X(0), Y(6));
    ctx.closePath();
    ctx.fill();

    ctx.fillStyle = 'rgba(45,82,158,0.34)';
    ctx.beginPath();
    ctx.moveTo(X(0), Y(0));
    ctx.lineTo(X(36), Y(0));
    ctx.lineTo(X(0), Y(18));
    ctx.closePath();
    ctx.fill();

    ctx.strokeStyle = '#172026';
    ctx.fillStyle = '#172026';
    ctx.lineWidth = 1.5;
    ctx.beginPath();
    ctx.moveTo(x0, y0);
    ctx.lineTo(x0, y1);
    ctx.lineTo(x1, y1);
    ctx.stroke();

    ctx.font = '12px ui-monospace, monospace';
    ctx.fillText('erasures s →', x1 - 90, H - 14);
    ctx.save();
    ctx.translate(14, y0 + 90);
    ctx.rotate(-Math.PI / 2);
    ctx.fillText('errors e →', 0, 0);
    ctx.restore();

    ctx.fillText('2e+s ≤ 36 · BM guaranteed', X(4), Y(13));
    ctx.fillText('ML erasure + OSD', X(60), Y(4.6));
    ctx.fillText('ISD (probabilistic, budgeted)', X(52), Y(26));
    ctx.fillText('beyond recovery', X(96), Y(36));

    ctx.fillStyle = '#172026';
    ctx.beginPath();
    ctx.arc(X(s), Y(e), 6, 0, Math.PI * 2);
    ctx.fill();
    ctx.strokeStyle = '#ffffff';
    ctx.lineWidth = 2;
    ctx.stroke();

    const out = document.getElementById('bchOut');
    if (out) {
      let verdict;
      if (2 * e + s <= 36) verdict = 'Berlekamp-Massey region: guaranteed correction, microseconds.';
      else if (s <= 124 && e <= 2 + Math.max(0, (36 - s) / 16)) {
        verdict = 'ML erasure solve / OSD: solvable if enough independent clean bits survive (measured: 70/188 erased recovered).';
      } else if (s <= 124 && e <= 0.22 * (188 - s)) {
        verdict = 'ISD territory: probabilistic search over information sets, gated by mismatch caps and the keyed MAC; needs budget and a bit of luck.';
      } else {
        verdict = 'Beyond the ladder: honestly reported as “not found” — never guessed (D-14).';
      }
      out.textContent = `s=${s} erasures, e=${e} errors → ${verdict}`;
    }
  }

  ['bchS', 'bchE'].forEach((id) => document.getElementById(id)?.addEventListener('input', drawBch));
  document.getElementById('d-ladder')?.addEventListener('decision:open', drawBch, { once: true });
  drawBch();
}
