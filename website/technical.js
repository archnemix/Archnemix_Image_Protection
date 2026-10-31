/* Archnemix technical page: decision accordion + index + filter, and the
 * five widgets (scramble-plan visualizer, token explorer, saturation
 * calculator, BCH recovery map, survival chart). Everything runs
 * locally; nothing is sent anywhere. */

/* ------------------------------------------------------------------ */
/* Accordion, generated index, scrollspy, filter                      */
/* ------------------------------------------------------------------ */
const decisions = [...document.querySelectorAll('.decision')];
const indexNav = document.getElementById('techIndex');
if (indexNav) {
  let currentGroup = null;
  for (const card of decisions) {
    const groupEl = card.parentElement.querySelectorAll('.group-head');
    // find the preceding group-head among siblings before this card
    let g = null;
    let el = card;
    while (el && !g) { el = el.previousElementSibling; if (el?.classList?.contains('group-head')) g = el; }
    const gName = g?.querySelector('h2')?.textContent ?? '';
    if (gName && gName !== currentGroup) {
      currentGroup = gName;
      const div = document.createElement('div');
      div.className = 'idx-group';
      div.textContent = gName;
      indexNav.appendChild(div);
      void groupEl;
    }
    const a = document.createElement('a');
    a.href = `#${card.id}`;
    a.textContent = `${card.querySelector('.decision-no')?.textContent ?? ''} · ${card.querySelector('.decision-title')?.textContent ?? ''}`;
    a.dataset.for = card.id;
    indexNav.appendChild(a);
  }
  const links = [...indexNav.querySelectorAll('a')];
  const spy = new IntersectionObserver((entries) => {
    for (const en of entries) {
      if (en.isIntersecting) {
        links.forEach((l) => l.classList.toggle('is-current', l.dataset.for === en.target.id));
      }
    }
  }, { rootMargin: '-30% 0px -60% 0px' });
  decisions.forEach((d) => spy.observe(d));
}

function setOpen(card, open) {
  const body = card.querySelector('.decision-body');
  const btn = card.querySelector('.decision-toggle');
  if (!body || !btn) return;
  body.hidden = !open;
  btn.setAttribute('aria-expanded', String(open));
  btn.textContent = open ? 'Close' : 'Open';
  if (open) card.dispatchEvent(new CustomEvent('decision:open'));
}
decisions.forEach((card, i) => {
  card.querySelector('.decision-toggle')?.addEventListener('click', () => {
    setOpen(card, card.querySelector('.decision-body')?.hidden);
  });
  if (i === 0) setOpen(card, true);
});
if (location.hash) {
  const target = document.querySelector(location.hash);
  if (target?.classList?.contains('decision')) setOpen(target, true);
}

const search = document.getElementById('techSearch');
const count = document.getElementById('techCount');
let activeTag = null;
function applyFilter() {
  const q = (search?.value ?? '').trim().toLowerCase();
  let shown = 0;
  for (const card of decisions) {
    const tagOk = !activeTag || (card.dataset.tags ?? '').includes(activeTag);
    const textOk = !q || card.textContent.toLowerCase().includes(q);
    const show = tagOk && textOk;
    card.hidden = !show;
    if (show) shown++;
  }
  if (count) count.textContent = `${shown} of ${decisions.length} decisions`;
}
search?.addEventListener('input', applyFilter);
document.querySelectorAll('.tech-toolbar .chip[data-tag]').forEach((chip) => {
  chip.addEventListener('click', () => {
    const tag = chip.dataset.tag;
    activeTag = activeTag === tag ? null : tag;
    document.querySelectorAll('.tech-toolbar .chip[data-tag]').forEach((c) =>
      c.classList.toggle('is-active', c.dataset.tag === activeTag));
    applyFilter();
  });
});
applyFilter();

/* ------------------------------------------------------------------ */
/* W1 — scramble plan visualizer (the real shipped algorithm)         */
/* ------------------------------------------------------------------ */
// === PLAN PORT BEGIN === (verbatim from src/core/crypto.js + plan.js; parity-tested)
function hashSeed(str, seed = 0) {
  let h1 = 0xdeadbeef ^ seed;
  let h2 = 0x41c6ce57 ^ seed;
  const s = String(str);
  for (let i = 0, ch; i < s.length; i++) {
    ch = s.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return 4294967296 * (2097151 & h2) + (h1 >>> 0);
}
function mulberry32(seed) {
  let a = seed >>> 0;
  return function next() {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function cyrb128(str) {
  const s = String(str);
  let h1 = 1779033703, h2 = 3144134277, h3 = 1013904242, h4 = 2773480762;
  for (let i = 0, k; i < s.length; i++) {
    k = s.charCodeAt(i);
    h1 = h2 ^ Math.imul(h1 ^ k, 597399067);
    h2 = h3 ^ Math.imul(h2 ^ k, 2869860233);
    h3 = h4 ^ Math.imul(h3 ^ k, 951274213);
    h4 = h1 ^ Math.imul(h4 ^ k, 2716044179);
  }
  h1 = Math.imul(h3 ^ (h1 >>> 18), 597399067);
  h2 = Math.imul(h4 ^ (h2 >>> 22), 2869860233);
  h3 = Math.imul(h1 ^ (h3 >>> 17), 951274213);
  h4 = Math.imul(h2 ^ (h4 >>> 19), 2716044179);
  return [(h1 ^ h2 ^ h3 ^ h4) >>> 0, (h2 ^ h1) >>> 0, (h3 ^ h1) >>> 0, (h4 ^ h1) >>> 0];
}
function sfc32(a, b, c, d) {
  return function next() {
    a >>>= 0; b >>>= 0; c >>>= 0; d >>>= 0;
    let t = (a + b | 0) + d | 0;
    d = (d + 1) | 0;
    a = b ^ (b >>> 9);
    b = (c + (c << 3)) | 0;
    c = (c << 21) | (c >>> 11);
    c = (c + t) | 0;
    return (t >>> 0) / 4294967296;
  };
}
function buildScramblePlan(grid = 8, key = '', version = 2) {
  const g = Math.max(2, Math.min(32, grid | 0));
  const count = g * g;
  let rand;
  if (version === 2) {
    rand = sfc32(...cyrb128(String(key) + '::archx-grid2-' + g));
    for (let i = 0; i < 8; i++) rand();
  } else {
    rand = mulberry32(hashSeed(String(key) + '::archx-grid-' + g));
  }
  const order = Array.from({ length: count }, (_, i) => i);
  for (let i = count - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }
  const flips = Array.from({ length: count }, () => ({ fx: rand() < 0.5, fy: rand() < 0.5 }));
  const inverse = new Array(count);
  order.forEach((orig, scrambledPos) => { inverse[orig] = scrambledPos; });
  return { grid: g, count, version, order, inverse, flips };
}
// === PLAN PORT END ===

const planState = { grid: 8, version: 2, plan: null, hover: -1 };
function tileColor(idx, count) {
  const t = idx / Math.max(1, count - 1);
  const hue = 95 - t * 60;         // green -> russet-teal walk, print-like
  const light = 30 + (Math.sin(idx * 12.9898) * 0.5 + 0.5) * 18;
  return `hsl(${hue} 42% ${light}%)`;
}
function drawPlan() {
  const canvas = document.getElementById('planCanvas');
  if (!canvas) return;
  const key = document.getElementById('planKey')?.value ?? '';
  const plan = buildScramblePlan(planState.grid, key, planState.version);
  planState.plan = plan;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);
  ctx.fillStyle = '#fffdf7'; ctx.fillRect(0, 0, W, H);
  const g = plan.grid;
  const board = Math.min(H - 56, (W - 180) / 2);
  const cell = board / g;
  const y0 = 40;
  const leftX = 30, rightX = W - 30 - board;
  ctx.fillStyle = '#191612'; ctx.font = '600 13px Georgia, serif';
  ctx.fillText('Original tiles', leftX, 22);
  ctx.fillText('On the wire (scrambled positions)', rightX, 22);
  const drawBoard = (ox, scrambledSide) => {
    for (let i = 0; i < plan.count; i++) {
      // original board: tile i sits at position i; wire board: slot i
      // holds tile order[i] (order[scrambledPos] = original tile)
      const pos = i;
      const tile = scrambledSide ? plan.order[i] : i;
      const x = ox + (pos % g) * cell, y = y0 + Math.floor(pos / g) * cell;
      ctx.fillStyle = tileColor(tile, plan.count);
      ctx.fillRect(x + 0.5, y + 0.5, cell - 1, cell - 1);
      if (planState.hover === tile) {
        ctx.strokeStyle = '#b13a22'; ctx.lineWidth = 3;
        ctx.strokeRect(x + 1.5, y + 1.5, cell - 3, cell - 3);
      }
      if (cell >= 17) {
        ctx.fillStyle = 'rgba(255,253,247,.92)';
        ctx.font = `${Math.min(12, cell * 0.42)}px ui-monospace, monospace`;
        ctx.fillText(String(tile), x + 3, y + Math.min(14, cell * 0.52));
        const f = plan.flips[scrambledSide ? i : plan.inverse[tile]]; // flips are indexed by destination slot
        const marks = (f.fx ? '⇋' : '') + (f.fy ? '⇅' : '');
        if (marks && scrambledSide) ctx.fillText(marks, x + 3, y + cell - 4);
      }
    }
  };
  drawBoard(leftX, false);
  drawBoard(rightX, true);
  // center arrow
  const midY = y0 + board / 2;
  ctx.strokeStyle = '#b13a22'; ctx.fillStyle = '#b13a22'; ctx.lineWidth = 2.5;
  ctx.beginPath(); ctx.moveTo(leftX + board + 18, midY); ctx.lineTo(rightX - 18, midY); ctx.stroke();
  ctx.beginPath(); ctx.moveTo(rightX - 18, midY); ctx.lineTo(rightX - 30, midY - 7); ctx.lineTo(rightX - 30, midY + 7); ctx.closePath(); ctx.fill();
  if (planState.hover >= 0) {
    const tile = planState.hover;
    const slot = plan.inverse[tile];
    const f = plan.flips[slot];
    const out = document.getElementById('planOut');
    if (out) out.textContent = `tile ${tile} (row ${Math.floor(tile / g) + 1}, col ${(tile % g) + 1}) → wire slot ${slot}` +
      `${f.fx ? ' · mirrored horizontally' : ''}${f.fy ? ' · mirrored vertically' : ''}${!f.fx && !f.fy ? ' · unmirrored' : ''} — plan v${plan.version}, grid ${g}×${g}`;
  }
}
const planCanvas = document.getElementById('planCanvas');
if (planCanvas) {
  const onMove = (e) => {
    const r = planCanvas.getBoundingClientRect();
    const plan = planState.plan; if (!plan) return;
    const g = plan.grid;
    const W = planCanvas.width, H = planCanvas.height;
    const board = Math.min(H - 56, (W - 180) / 2);
    const cell = board / g, y0 = 40, leftX = 30, rightX = W - 30 - board;
    const px = (e.clientX - r.left) * (W / r.width), py = (e.clientY - r.top) * (H / r.height);
    let tile = -1;
    const pick = (ox, scrambledSide) => {
      const cx = Math.floor((px - ox) / cell), cy = Math.floor((py - y0) / cell);
      if (cx < 0 || cy < 0 || cx >= g || cy >= g) return -1;
      const pos = cy * g + cx;
      return scrambledSide ? plan.order[pos] : pos;
    };
    tile = pick(leftX, false);
    if (tile < 0) tile = pick(rightX, true);
    if (tile !== planState.hover) { planState.hover = tile; drawPlan(); }
  };
  planCanvas.addEventListener('pointermove', onMove);
  planCanvas.addEventListener('pointerleave', () => { planState.hover = -1; drawPlan(); });
  document.getElementById('planKey')?.addEventListener('input', drawPlan);
  document.querySelectorAll('#planGridSeg button').forEach((b) => b.addEventListener('click', () => {
    planState.grid = Number(b.dataset.g);
    document.querySelectorAll('#planGridSeg button').forEach((x) => x.classList.toggle('is-active', x === b));
    drawPlan();
  }));
  document.querySelectorAll('#planVerSeg button').forEach((b) => b.addEventListener('click', () => {
    planState.version = Number(b.dataset.v);
    document.querySelectorAll('#planVerSeg button').forEach((x) => x.classList.toggle('is-active', x === b));
    drawPlan();
  }));
  document.getElementById('planRandom')?.addEventListener('click', () => {
    const input = document.getElementById('planKey');
    if (input) input.value = 'key-' + Math.random().toString(36).slice(2, 10);
    drawPlan();
  });
  document.getElementById('d-plan-v2')?.addEventListener('decision:open', drawPlan, { once: true });
  drawPlan();
}

/* ------------------------------------------------------------------ */
/* W2 — token explorer (mirror of the server's single-secret path)    */
/* ------------------------------------------------------------------ */
const b64url = (bytes) => {
  let bin = '';
  bytes.forEach((b) => { bin += String.fromCharCode(b); });
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
};
const b64urlDecode = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
async function hmac(secret, body) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body)));
}
const CLAIM_NOTES = {
  v: 'token format version', kid: 'signing key id (rotation)', aud: 'audience: only the image service',
  scope: 'what the token may do', id: 'image id — bound, cannot be swapped', w: 'entitled width (px)',
  iat: 'issued-at (ms)', exp: 'expiry (ms)', n: 'nonce — the one-time claim key',
  jkt: 'proof-key thumbprint (sender constraining)',
};
let currentToken = '';
async function tokenMint() {
  const out = document.getElementById('tokOut');
  const secret = document.getElementById('tokSecret')?.value ?? '';
  let claims;
  try { claims = JSON.parse(document.getElementById('tokClaims')?.value ?? '{}'); }
  catch { if (out) out.textContent = 'Claims JSON does not parse — the server would never mint this either.'; return; }
  const body = b64url(new TextEncoder().encode(JSON.stringify(claims)));
  const mac = await hmac(secret, body);
  currentToken = `${body}.${b64url(mac)}`;
  await tokenVerify(currentToken, 'minted just now');
}
async function tokenVerify(token, label) {
  const out = document.getElementById('tokOut');
  const secret = document.getElementById('tokSecret')?.value ?? '';
  if (!out) return;
  const lines = [`token (${label}):`, token, ''];
  const parts = token.split('.');
  if (parts.length !== 2 || !/^[A-Za-z0-9_-]+$/.test(parts[0]) || !/^[A-Za-z0-9_-]+$/.test(parts[1])) {
    out.textContent = lines.join('\n') + '\n✗ REJECTED — structure (must be body.mac, base64url alphabet)';
    return;
  }
  const [body, mac] = parts;
  // canonical-encoding gate (v1.21): re-encoding must reproduce the string exactly
  let canonical = true;
  try {
    canonical = b64url(b64urlDecode(body)) === body && b64url(b64urlDecode(mac)) === mac;
  } catch { canonical = false; }
  if (!canonical) {
    out.textContent = lines.join('\n') + '\n✗ REJECTED — non-canonical base64url (same MAC bytes, different string). Token malleability is refused even though the signature itself is valid.';
    return;
  }
  const expected = await hmac(secret, body);
  const given = b64urlDecode(mac);
  const macOk = given.length === expected.length && given.every((b, i) => b === expected[i]);
  if (!macOk) {
    out.textContent = lines.join('\n') + '\n✗ REJECTED — HMAC mismatch (claims were changed after signing, or the secret is wrong)';
    return;
  }
  let claims;
  try { claims = JSON.parse(new TextDecoder().decode(b64urlDecode(body))); } catch {
    out.textContent = lines.join('\n') + '\n✗ REJECTED — payload is not JSON';
    return;
  }
  const problems = [];
  if (claims.aud !== 'archx:image') problems.push(`aud must be archx:image, got ${claims.aud}`);
  if (claims.scope !== 'image:view') problems.push(`scope must be image:view, got ${claims.scope}`);
  if (!Number.isFinite(claims.exp) || Date.now() > claims.exp) problems.push('expired (or exp malformed)');
  if (!Number.isInteger(claims.w) || claims.w < 1) problems.push(`w must be a positive integer, got ${JSON.stringify(claims.w)}`);
  if (typeof claims.n !== 'string' || !claims.n) problems.push('nonce n is required (one-time claim)');
  const annotated = Object.entries(claims).map(([k, v]) => `  ${k}: ${JSON.stringify(v)}${CLAIM_NOTES[k] ? `  — ${CLAIM_NOTES[k]}` : '  — (unknown claim: server refuses)'}`).join('\n');
  out.textContent = lines.join('\n') + `\nclaims:\n${annotated}\n\n` +
    (problems.length ? `✗ REJECTED — MAC valid, claims invalid:\n  · ${problems.join('\n  · ')}` : '✓ ACCEPTED — canonical, signature valid, claims valid. Redeeming would now burn nonce n forever.');
}
const tokClaimsEl = document.getElementById('tokClaims');
if (tokClaimsEl) {
  const now = Date.now();
  tokClaimsEl.value = JSON.stringify({
    v: 2, kid: 'primary', aud: 'archx:image', scope: 'image:view',
    id: 'aurora-valley', w: 240, iat: now, exp: now + 120000,
    n: 'demoNonce123456', jkt: 'present-only-with-proof-key-43-chars-xxxxxxx',
  }, null, 1);
  document.getElementById('tokMint')?.addEventListener('click', tokenMint);
  document.getElementById('tokTamper')?.addEventListener('click', async () => {
    if (!currentToken) await tokenMint();
    const [body, mac] = currentToken.split('.');
    const claims = JSON.parse(new TextDecoder().decode(b64urlDecode(body)));
    claims.w = 4000;
    const evilBody = b64url(new TextEncoder().encode(JSON.stringify(claims)));
    await tokenVerify(`${evilBody}.${mac}`, 'width edited, original MAC kept');
  });
  document.getElementById('tokVariant')?.addEventListener('click', async () => {
    if (!currentToken) await tokenMint();
    const [body, mac] = currentToken.split('.');
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const last = alphabet.indexOf(mac.at(-1));
    const variantChar = [...alphabet].find((c) => (alphabet.indexOf(c) >> 2) === (last >> 2) && c !== mac.at(-1));
    await tokenVerify(`${body}.${mac.slice(0, -1)}${variantChar}`, 'padding-variant re-encode (identical MAC bytes)');
  });
  document.getElementById('d-tokens')?.addEventListener('decision:open', () => { void tokenMint(); }, { once: true });
}

/* ------------------------------------------------------------------ */
/* W3 — saturation sizing                                             */
/* ------------------------------------------------------------------ */
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
    `required oneTimeTokenMaxEntries ≥ ${rps}/s × ${ttl}s × ${margin} = ${required.toLocaleString()} entries\n` +
    (satPolicy === 'evict'
      ? `policy: evict — an attacker must sustain >${rps}/s redemptions for ~${burstToChurn}s to push a live claim out and re-open its replay window. Availability first; size generously.`
      : `policy: strict — at ${required.toLocaleString()} live claims the server refuses NEW redemptions (loud 429/503) rather than forgetting a spend. Integrity first; alert on saturation.`);
}
if (document.getElementById('w-saturation')) {
  ['satRps', 'satTtl', 'satMargin'].forEach((id) => document.getElementById(id)?.addEventListener('input', drawSaturation));
  document.querySelectorAll('#satSeg button').forEach((b) => b.addEventListener('click', () => {
    satPolicy = b.dataset.p;
    document.querySelectorAll('#satSeg button').forEach((x) => x.classList.toggle('is-active', x === b));
    drawSaturation();
  }));
  drawSaturation();
}

/* ------------------------------------------------------------------ */
/* W4 — BCH recovery map (schematic)                                  */
/* ------------------------------------------------------------------ */
function drawBch() {
  const canvas = document.getElementById('bchCanvas');
  if (!canvas) return;
  const s = Number(document.getElementById('bchS')?.value ?? 69);
  const e = Number(document.getElementById('bchE')?.value ?? 13);
  document.getElementById('bchSV').textContent = s;
  document.getElementById('bchEV').textContent = e;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);
  ctx.fillStyle = '#fffdf7'; ctx.fillRect(0, 0, W, H);
  const x0 = 56, y0 = 18, x1 = W - 18, y1 = H - 42;
  const maxS = 130, maxE = 42;
  const X = (v) => x0 + (v / maxS) * (x1 - x0);
  const Y = (v) => y1 - (v / maxE) * (y1 - y0);
  // ISD probabilistic region (schematic): s <= 124 and e <= 0.22*(188-s)
  ctx.fillStyle = 'rgba(177,58,34,.10)';
  ctx.beginPath(); ctx.moveTo(X(0), Y(0)); ctx.lineTo(X(124), Y(0)); ctx.lineTo(X(124), Y(0.22 * 64)); ctx.lineTo(X(0), Y(0.22 * 188)); ctx.closePath(); ctx.fill();
  // ML/OSD region: s <= 124, e <= 4 + something small near axis
  ctx.fillStyle = 'rgba(177,58,34,.18)';
  ctx.beginPath(); ctx.moveTo(X(0), Y(0)); ctx.lineTo(X(124), Y(0)); ctx.lineTo(X(124), Y(2)); ctx.lineTo(X(36), Y(6)); ctx.lineTo(X(0), Y(6)); ctx.closePath(); ctx.fill();
  // BM guaranteed: 2e + s <= 36
  ctx.fillStyle = 'rgba(177,58,34,.38)';
  ctx.beginPath(); ctx.moveTo(X(0), Y(0)); ctx.lineTo(X(36), Y(0)); ctx.lineTo(X(0), Y(18)); ctx.closePath(); ctx.fill();
  // axes + labels
  ctx.strokeStyle = '#191612'; ctx.fillStyle = '#191612'; ctx.lineWidth = 1.5;
  ctx.beginPath(); ctx.moveTo(x0, y0); ctx.lineTo(x0, y1); ctx.lineTo(x1, y1); ctx.stroke();
  ctx.font = '12px ui-monospace, monospace';
  ctx.fillText('erasures s →', x1 - 90, H - 14);
  ctx.save(); ctx.translate(14, y0 + 90); ctx.rotate(-Math.PI / 2); ctx.fillText('errors e →', 0, 0); ctx.restore();
  ctx.fillText('2e+s ≤ 36 · BM guaranteed', X(4), Y(13));
  ctx.fillText('ML erasure + OSD', X(60), Y(4.6));
  ctx.fillText('ISD (probabilistic, budgeted)', X(52), Y(26));
  ctx.fillText('beyond recovery', X(96), Y(36));
  // point
  ctx.fillStyle = '#191612';
  ctx.beginPath(); ctx.arc(X(s), Y(e), 6, 0, 6.29); ctx.fill();
  ctx.strokeStyle = '#fffdf7'; ctx.lineWidth = 2; ctx.stroke();
  const out = document.getElementById('bchOut');
  if (out) {
    let verdict;
    if (2 * e + s <= 36) verdict = 'Berlekamp-Massey region: guaranteed correction, microseconds.';
    else if (s <= 124 && e <= 2 + Math.max(0, (36 - s) / 16)) verdict = 'ML erasure solve / OSD: solvable if enough independent clean bits survive (measured: 70/188 erased recovered).';
    else if (s <= 124 && e <= 0.22 * (188 - s)) verdict = 'ISD territory: probabilistic search over information sets, gated by mismatch caps and the keyed MAC; needs budget and a bit of luck.';
    else verdict = 'Beyond the ladder: honestly reported as “not found” — never guessed (D-14).';
    out.textContent = `s=${s} erasures, e=${e} errors → ${verdict}`;
  }
}
if (document.getElementById('w-bch')) {
  ['bchS', 'bchE'].forEach((id) => document.getElementById(id)?.addEventListener('input', drawBch));
  document.getElementById('d-ladder')?.addEventListener('decision:open', drawBch, { once: true });
  drawBch();
}

/* ------------------------------------------------------------------ */
/* W5 — survival chart (measured data, RESEARCH §2.28)                */
/* ------------------------------------------------------------------ */
let survMode = 'class';
const SURV = {
  class: {
    title: 'Layout 4, robust profile — recovered by content class',
    bars: [
      ['Photos', 30, 33], ['Graphics', 33, 33], ['Flat / UI', 11, 11],
      ['Text-heavy', 10, 11], ['Adversarial periodic', 0, 11],
    ],
  },
  totals: {
    title: 'All 99 cases — layout 3 (default) vs layout 4 (opt-in)',
    bars: [
      ['Robust · L3', 85, 99], ['Robust · L4', 84, 99],
      ['Standard · L3', 63, 99], ['Standard · L4', 63, 99],
    ],
  },
};
function drawSurvival() {
  const canvas = document.getElementById('survCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  ctx.clearRect(0, 0, W, H);
  ctx.fillStyle = '#fffdf7'; ctx.fillRect(0, 0, W, H);
  const data = SURV[survMode];
  ctx.fillStyle = '#191612'; ctx.font = '600 14px Georgia, serif';
  ctx.fillText(data.title, 18, 24);
  const chartX = 190, chartW = W - chartX - 90;
  const top = 48, rowH = Math.min(44, (H - top - 16) / data.bars.length);
  data.bars.forEach(([label, got, of], i) => {
    const y = top + i * rowH;
    ctx.font = '13px Georgia, serif'; ctx.fillStyle = '#191612';
    ctx.fillText(label, 18, y + rowH * 0.62);
    ctx.fillStyle = '#e5dcc6';
    ctx.fillRect(chartX, y + 4, chartW, rowH - 16);
    ctx.fillStyle = got === 0 ? '#191612' : '#b13a22';
    ctx.fillRect(chartX, y + 4, chartW * (got / of), rowH - 16);
    ctx.fillStyle = '#191612'; ctx.font = '600 13px ui-monospace, monospace';
    ctx.fillText(`${got}/${of} · ${Math.round((got / of) * 100)}%`, chartX + chartW + 10, y + rowH * 0.62);
  });
  const note = document.getElementById('survNote');
  if (note && survMode === 'totals') {
    note.innerHTML = 'The one-case robust gap is why layout 3 remains the default (D-13) — the flip bar was written <em>before</em> measuring. Layout 4 wins on quality: +1.4 dB PSNR on photos. False positives: <strong>0/369</strong>.';
  } else if (note) {
    note.innerHTML = '9 images × 11 transforms (crops, scales, JPEG/WebP rounds, screenshot chains, mirrors). False positives: <strong>0/369</strong> wrong-key checks. Re-run: <span class="mono">npm run bench:stego</span>.';
  }
}
if (document.getElementById('w-survival')) {
  document.querySelectorAll('#survSeg button').forEach((b) => b.addEventListener('click', () => {
    survMode = b.dataset.m;
    document.querySelectorAll('#survSeg button').forEach((x) => x.classList.toggle('is-active', x === b));
    drawSurvival();
  }));
  document.getElementById('d-classical')?.addEventListener('decision:open', drawSurvival, { once: true });
  drawSurvival();
}
