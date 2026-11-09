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
    outcome: 'Obfuscated at the payload; reconstruction is possible.',
    detail: 'View-source shows a loader call, not a file. The network tab shows a one-time redemption returning permuted tiles (optionally AES-sealed) at the width allowed by server policy; replaying the request returns 403 while the spend record is retained; evict-on-saturation can reopen a narrow window under sustained pressure. Reassembly is possible, and the default maxWidthFraction of 1 can allow native-width pixels when other caps permit.',
    layers: { 'Private masters': 1, 'One-time tokens': 1, 'Tile scramble': 1, 'AES-256-GCM': 1, 'Resolution cap': 1 },
    verdict: 'Walks away with: scrambled tiles, or an authorized-width reconstruction after real work. The original file is not served; native-width pixels are possible unless the host caps them below the master.',
  },
  {
    id: 'scraper',
    name: 'The bulk scraper',
    sub: 'Scripts harvesting a whole catalog unattended',
    outcome: 'Throttled, not stopped.',
    detail: 'In protected deployments, each image needs an authorized mint; explicit anonymous mode can mint without a user entitlement. Mints are rate-limited (IPv6-rotation-resistant tiers), distinct-image quotas trip on catalog breadth (the 4th distinct image in our test config already gets a 429), bodies are deadline-bounded, and payload width follows configured caps, which may allow native width unless maxWidthFraction is below 1. Authorization and quotas can restrict collection, but do not make it impossible.',
    layers: { 'One-time tokens': 1, 'Quotas & rate limits': 1, 'Resolution cap': 1, 'Private masters': 1 },
    verdict: 'Walks away with: images within active caps and quotas; production policy can restrict collection, not make it impossible.',
  },
  {
    id: 'token-thief',
    name: 'The token thief',
    sub: 'Steals a live token from logs, a shared link, or a proxy',
    outcome: 'Mostly empty-handed.',
    detail: 'The window is the TTL (seconds-to-minutes); a spent claim normally blocks replay while its record is retained, but an evict-on-saturation policy can reopen a narrow window under sustained pressure. With proof-of-possession enabled, the copied bearer token is useless without the victim page’s non-extractable key: bearer attempt, wrong key, wrong target, and replayed proofs all return 403 in the red-team battery.',
    layers: { 'One-time tokens': 1, 'Proof-of-possession': 1 },
    verdict: 'Walks away with: an expired or unspendable string. In bearer-only mode, possibly one rushed view at the signed, entitled width inside the TTL.',
  },
  {
    id: 'screenshotter',
    name: 'The screenshotter',
    sub: 'OS capture, browser extensions, CDP screenshots',
    outcome: 'Degraded; sometimes attributable.',
    detail: 'No web technology can veto an OS-level capture, and Archx does not claim to. What changes: the capture is limited to the delivered derivative (which may be native width unless the host configures a stricter fraction), readback paths are poisoned/black where the platform allows, and temporal interlace can leave single frames incomplete. The 99-case single-transform bench recovered marks in 85 cases, including screenshot simulations; a miss is possible, so a recovered mark is evidence to corroborate, not a guaranteed source label.',
    layers: { 'Resolution cap': 1, 'Poisoned readback': 1, 'Temporal interlace': 1, 'StegoMark attribution': 1 },
    verdict: 'Walks away with: a degraded copy that may carry recoverable attribution evidence.',
  },
  {
    id: 'buyer',
    name: 'The leaking buyer',
    sub: 'A legitimate customer redistributing what they bought access to',
    outcome: 'Sometimes identified; recovery is not guaranteed.',
    detail: 'Each delivery can carry a distinct invisible fingerprint tied to the buyer/order in your issuance records. Rescanning the leaked file recovers it (85/99 bench cases under the robust profile, 0/369 false accusations). Buyers who average multiple copies defeat the bit-level decode — the collusion assay then ranks participants for investigation instead of pretending to a verdict mathematics forbids at this payload size.',
    layers: { 'StegoMark attribution': 1, 'Issuance records': 1, 'One-time tokens': 1 },
    verdict: 'Walks away with: a copy that may retain a buyer-linked mark and issuance evidence; recovery is not guaranteed.',
  },
  {
    id: 'camera',
    name: 'The camera',
    sub: 'A phone photographing the screen',
    outcome: 'Not preventable — by anyone.',
    detail: 'The analog hole is physics: light leaves the screen, a sensor collects it. Archx’s honest contribution is a photograph of the delivered derivative (whose width depends on server policy), optionally interlaced. There is no real-camera/phone-photo recovery corpus: synthetic affine/keystone regressions do not establish camera-photo survival, and ordinary resize/re-encode measurements do not either. Any vendor claiming more needs evidence.',
    layers: { 'Resolution cap': 1, 'Temporal interlace': 1, 'StegoMark attribution': 1 },
    verdict: 'Walks away with: a photograph of a screen. Sometimes still attributable; never the file.',
  },
  {
    id: 'regen',
    name: 'The regenerator',
    sub: 'Diffusion re-synthesis / aggressive AI “enhancement”',
    outcome: 'Marks are not a dependable defense; the trail may remain.',
    detail: 'Published diffusion attacks reduce or remove many tested invisible watermark schemes, including neural methods. Archx StegoMark has not been measured against full diffusion regeneration, so treat it as vulnerable rather than claiming a measured failure or survival rate. What may remain: perceptual-hash proximity to registered originals, issuance records, and evidence of where the copy surfaced. Plan around provenance and process, not a promise no one can keep.',
    layers: { 'Issuance records': 1 },
    verdict: 'Walks away with: a re-synthesized derivative. Attribution may rely on pHash, records, and investigation.',
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
