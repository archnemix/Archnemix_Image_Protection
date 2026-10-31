/* Threat-model page: the interactive attacker matrix. Outcomes are the
 * ones documented in README/RESEARCH — no category is oversold. */

const LAYERS = [
  'Private masters', 'Resolution cap', 'Tile scramble', 'AES-256-GCM',
  'One-time tokens', 'Proof-of-possession', 'Canvas viewer', 'Poisoned readback',
  'Temporal interlace', 'StegoMark attribution', 'Quotas & rate limits', 'Issuance records',
];

const ATTACKERS = [
  {
    id: 'casual',
    name: 'The right-click saver',
    sub: 'Right-click → Save image as… / drag to desktop',
    outcome: 'Stopped.',
    detail: 'There is no image element to save and no URL to copy. The context menu offers nothing; drag-out has nothing to grab. This attacker needs no skill to stop — but most “protection” products stop only them and claim victory. For Archx this is merely the floor.',
    layers: { 'Canvas viewer': 1, 'Private masters': 1 },
    verdict: 'Walks away with: nothing.',
  },
  {
    id: 'devtools',
    name: 'The DevTools user',
    sub: 'Network tab, view-source, “open image in new tab”',
    outcome: 'Stopped at the payload.',
    detail: 'View-source shows a loader call, not a file. The network tab shows a one-time redemption returning permuted tiles (optionally AES-sealed) at display resolution; replaying the request after the single spend returns 403. Reassembling by hand is possible in principle for the screen-sized derivative — and capped at exactly that.',
    layers: { 'Private masters': 1, 'One-time tokens': 1, 'Tile scramble': 1, 'AES-256-GCM': 1, 'Resolution cap': 1 },
    verdict: 'Walks away with: scrambled tiles, or a display-resolution reconstruction after real work. Never the master.',
  },
  {
    id: 'scraper',
    name: 'The bulk scraper',
    sub: 'Scripts harvesting a whole catalog unattended',
    outcome: 'Starved and walled.',
    detail: 'Each image needs an authorized mint; mints are rate-limited (IPv6-rotation-resistant tiers), distinct-image quotas trip on catalog breadth (the 4th distinct image in our test config already gets a 429), bodies are deadline-bounded, and every payload is per-token and screen-resolution. Bulk economics invert: cost per image rises while value per image is capped.',
    layers: { 'One-time tokens': 1, 'Quotas & rate limits': 1, 'Resolution cap': 1, 'Private masters': 1 },
    verdict: 'Walks away with: a trickle of screen-size images at escalating cost — or a wall of 429s.',
  },
  {
    id: 'token-thief',
    name: 'The token thief',
    sub: 'Steals a live token from logs, a shared link, or a proxy',
    outcome: 'Mostly empty-handed.',
    detail: 'The window is the TTL (seconds-to-minutes) and exactly one spend — often already gone. With proof-of-possession enabled, the copied bearer token is useless without the victim page’s non-extractable key: bearer attempt, wrong key, wrong target, and replayed proofs all return 403 in the red-team battery.',
    layers: { 'One-time tokens': 1, 'Proof-of-possession': 1 },
    verdict: 'Walks away with: an expired or unspendable string. In bearer-only mode, possibly one rushed screen-size view inside the TTL.',
  },
  {
    id: 'screenshotter',
    name: 'The screenshotter',
    sub: 'OS capture, browser extensions, CDP screenshots',
    outcome: 'Degraded — and attributable.',
    detail: 'No web technology can veto an OS-level capture, and Archx does not claim to. What changes: the capture is display-resolution, readback paths are poisoned/black where the platform allows, temporal interlace can leave single frames incomplete, and the per-viewer StegoMark typically survives the screenshot chain — the leak names its source when you rescan it.',
    layers: { 'Resolution cap': 1, 'Poisoned readback': 1, 'Temporal interlace': 1, 'StegoMark attribution': 1 },
    verdict: 'Walks away with: a degraded screen copy that can testify about who leaked it.',
  },
  {
    id: 'buyer',
    name: 'The leaking buyer',
    sub: 'A legitimate customer redistributing what they bought access to',
    outcome: 'Identified, usually.',
    detail: 'Each delivery can carry a distinct invisible fingerprint tied to the buyer/order in your issuance records. Rescanning the leaked file recovers it (85/99 bench cases under the robust profile, 0/369 false accusations). Buyers who average multiple copies defeat the bit-level decode — the collusion assay then ranks participants for investigation instead of pretending to a verdict mathematics forbids at this payload size.',
    layers: { 'StegoMark attribution': 1, 'Issuance records': 1, 'One-time tokens': 1 },
    verdict: 'Walks away with: a copy that carries their name invisibly — and a paper trail.',
  },
  {
    id: 'camera',
    name: 'The camera',
    sub: 'A phone photographing the screen',
    outcome: 'Not preventable — by anyone.',
    detail: 'The analog hole is physics: light leaves the screen, a sensor collects it. Archx’s honest contribution is that the photograph is of a display-resolution, optionally interlaced rendering — and the fingerprint is designed to survive exactly the resampling a photo introduces, within measured limits. Any vendor claiming more is claiming magic.',
    layers: { 'Resolution cap': 1, 'Temporal interlace': 1, 'StegoMark attribution': 1 },
    verdict: 'Walks away with: a photograph of a screen. Sometimes still attributable; never the file.',
  },
  {
    id: 'regen',
    name: 'The regenerator',
    sub: 'Diffusion re-synthesis / aggressive AI “enhancement”',
    outcome: 'The mark dies; the trail may not.',
    detail: 'Regeneration destroys every tested invisible watermark — classical and neural alike (literature: ~0–13% residual decode). StegoMark will usually not survive a full re-synthesis. What can survive: perceptual-hash proximity to your registered originals, issuance records, and the mundane evidence of where the copy surfaced. Plan your response around provenance and process, not a promise no one can keep.',
    layers: { 'Issuance records': 1 },
    verdict: 'Walks away with: a re-synthesized derivative. Attribution falls back to pHash, records, and investigation.',
  },
];

const grid = document.getElementById('attackerGrid');
const detailEl = document.getElementById('attackerDetail');
let current = null;

function render(attacker) {
  current = attacker;
  grid.querySelectorAll('.attacker').forEach((b) =>
    b.classList.toggle('is-active', b.dataset.id === attacker.id));
  const pills = LAYERS.map((l) =>
    `<span class="pill ${attacker.layers[l] ? 'on' : 'off'}">${l}</span>`).join('');
  detailEl.innerHTML = `
    <h3>${attacker.name} — <em>${attacker.outcome}</em></h3>
    <div class="layer-pills" aria-label="Layers that engage">${pills}</div>
    <p>${attacker.detail}</p>
    <p class="verdict-line"><strong>${attacker.verdict}</strong></p>`;
}

if (grid && detailEl) {
  for (const a of ATTACKERS) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'attacker';
    b.dataset.id = a.id;
    b.innerHTML = `<h3>${a.name}</h3><p class="attacker-sub">${a.sub}</p>`;
    b.addEventListener('click', () => render(a));
    grid.appendChild(b);
  }
  render(ATTACKERS[1]); // start with the DevTools user — the most common real question
}
