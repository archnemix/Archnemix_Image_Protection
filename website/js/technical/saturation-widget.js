/* W3 — Replay-store saturation sizing calculator */

export function initSaturationWidget() {
  if (!document.getElementById('w-saturation')) return;

  let satPolicy = 'evict';

  function drawSaturation() {
    const out = document.getElementById('satOut');
    if (!out) return;
    const rps = Number(document.getElementById('satRps')?.value ?? 50);
    const ttl = Number(document.getElementById('satTtl')?.value ?? 300);
    const margin = Number(document.getElementById('satMargin')?.value ?? 2);

    document.getElementById('satRpsV').textContent = rps;
    document.getElementById('satTtlV').textContent = ttl;
    document.getElementById('satMarginV').textContent = `${margin}×`;

    const required = Math.ceil(rps * ttl * margin);
    const burstToChurn = Math.ceil(required / rps);
    out.textContent =
      `required oneTimeTokenMaxEntries ≥ ${rps}/s × ${ttl}s × ${margin} = ${required.toLocaleString()} entries\n`
      + (satPolicy === 'evict'
        ? `policy: evict — an attacker must sustain >${rps}/s redemptions for ~${burstToChurn}s to push a live claim out and re-open its replay window. Availability first; size generously.`
        : `policy: strict — at ${required.toLocaleString()} live claims the server refuses NEW redemptions (loud 429/503) rather than forgetting a spend. Integrity first; alert on saturation.`);
  }

  ['satRps', 'satTtl', 'satMargin'].forEach((id) => {
    document.getElementById(id)?.addEventListener('input', drawSaturation);
  });
  document.querySelectorAll('#satSeg button').forEach((b) => {
    b.addEventListener('click', () => {
      satPolicy = b.dataset.p;
      document.querySelectorAll('#satSeg button').forEach((x) => {
        const active = x === b;
        x.classList.toggle('is-active', active);
        x.setAttribute('aria-pressed', String(active));
      });
      drawSaturation();
    });
  });

  drawSaturation();
}
