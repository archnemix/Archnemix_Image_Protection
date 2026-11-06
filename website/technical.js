/* Archnemix technical page: decision accordion + index + filter, an
 * animated end-to-end delivery-flow explainer, and five widgets
 * (scramble-plan visualizer, token explorer, saturation calculator,
 * BCH recovery map, survival chart). Everything runs locally; this
 * static page never contacts an Archx server. */

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
/* W2 — token explorer (local HMAC/core-claim teaching model)         */
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
  jkt: '43-character proof-key thumbprint shape (not proof verification)',
};
let currentToken = '';
const TOKEN_FIELDS = new Set(['v', 'kid', 'aud', 'scope', 'id', 'w', 'iat', 'exp', 'n', 'q', 'fmt', 'ls', 'vh', 'th', 'wm', 'sg', 'sgp', 'sgs', 'sge', 'sgv', 'sgx', 'sgy', 'sgi', 'sgk', 'nsg', 'nwm', 'b', 'jkt']);
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
  const now = Date.now();
  for (const field of Object.keys(claims)) if (!TOKEN_FIELDS.has(field)) problems.push(`unknown claim ${field} (server refuses)`);
  if (claims.v !== 2) problems.push(`v must be 2, got ${JSON.stringify(claims.v)}`);
  if (claims.aud !== 'archx:image') problems.push(`aud must be archx:image, got ${claims.aud}`);
  if (claims.scope !== 'image:view') problems.push(`scope must be image:view, got ${claims.scope}`);
  if (claims.kid !== undefined && (typeof claims.kid !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(claims.kid))) problems.push('kid must be a valid 1–64 character key id');
  if (typeof claims.id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(claims.id)) problems.push('id must be a valid image id');
  if (!Number.isSafeInteger(claims.w) || claims.w < 64 || claims.w > 1920) problems.push(`w must be an integer from 64 to 1920, got ${JSON.stringify(claims.w)}`);
  if (!Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp) || claims.iat > now + 300000 || claims.exp <= claims.iat || claims.exp - claims.iat > 1200000) problems.push('iat/exp must be safe integers in the permitted time window');
  if (!Number.isSafeInteger(claims.exp) || claims.exp <= now) problems.push('expired (or exp malformed)');
  if (typeof claims.n !== 'string' || !/^[A-Za-z0-9_-]{8,86}$/.test(claims.n)) problems.push('nonce n must be an 8–86 character base64url string');
  if (claims.jkt !== undefined && (typeof claims.jkt !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(claims.jkt))) problems.push('jkt must be a 43-character base64url thumbprint');
  const annotated = Object.entries(claims).map(([k, v]) => `  ${k}: ${JSON.stringify(v)}${CLAIM_NOTES[k] ? `  — ${CLAIM_NOTES[k]}` : TOKEN_FIELDS.has(k) ? '  — (allowlisted optional claim; value checks simplified)' : '  — (unknown claim: server refuses)'}`).join('\n');
  out.textContent = lines.join('\n') + `\nclaims:\n${annotated}\n\n` +
    (problems.length ? `✗ REJECTED — MAC valid, claims invalid:\n  · ${problems.join('\n  · ')}` : '✓ ACCEPTED BY THIS WIDGET — canonical HMAC and core v2 claims valid (optional-claim checks are simplified). Redeeming spends nonce n for its live one-time-token window.');
}
const tokClaimsEl = document.getElementById('tokClaims');
if (tokClaimsEl) {
  const now = Date.now();
  tokClaimsEl.value = JSON.stringify({
    v: 2, kid: 'primary', aud: 'archx:image', scope: 'image:view',
    id: 'aurora-valley', w: 240, iat: now, exp: now + 120000,
    n: 'demoNonce123456', jkt: 'Abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG',
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

/* ------------------------------------------------------------------ */
/* W0 — end-to-end delivery flowchart (local explainer, no server)    */
/* ------------------------------------------------------------------ */
(() => {
  const flowRoot = document.getElementById('w-flow');
  if (!flowRoot) return;

  const $ = (id) => document.getElementById(id);
  const flowCanvas = $('flowCanvas');
  const fctx = flowCanvas?.getContext('2d') || null;
  const reducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
  const activeValue = (selector, key, fallback) =>
    flowRoot.querySelector(`${selector} .is-active`)?.dataset[key] || fallback;

  const flowState = {
    mode: activeValue('#flowModeSeg', 'mode', 'shield'),
    renderer: activeValue('#flowRendererSeg', 'renderer', 'auto'),
    extract: activeValue('#flowExtractSeg', 'extract', 'black'),
    opts: { pop: true, encrypt: true, watermark: true, serverForensic: true, stego: true },
    step: 0,
    t: reducedMotion ? 0.62 : 0,
    playing: !reducedMotion,
    last: 0,
    raf: 0,
    visible: true,
    now: 0,
    durations: [],
    routeMs: 0,
  };
  flowRoot.querySelectorAll('[data-flow-opt]').forEach((btn) => {
    flowState.opts[btn.dataset.flowOpt] = btn.classList.contains('is-active');
  });

  /* Viewing-time budgets, not server runtimes. The old chart gave every stage
     the same 3.3s (33.0s total). These budgets are set by the number of
     visible beats and active branches in each stage: a static vault hold is
     short, while gate/checklist/transform stages get enough sequential time
     for each beat to land. Detailed text remains below the canvas and the
     transport can pause/step, so the animation itself only has to carry the
     title + visual gist. Sub-motions stay in the familiar ~150–600ms band. */
  const FLOW_LEGACY_TOTAL_MS = 33000;
  function flowStageDurations() {
    const marks = activeMarks().length;
    const renderer = effectiveRenderer();
    return [
      1700, // 01 vault lock + denied loop: two beats, no checklist
      flowState.opts.pop ? 2400 : 2150, // 02 measure + request (+ proof chip)
      3500, // 03 four mint checks, then the HMAC seal
      flowState.opts.pop ? 3900 : 3650, // 04 redeem gate checks + SPENT stamp
      2900, // 05 sniff/scan, resize contract, derivative settle
      marks ? 1300 + 550 * marks : 1500, // 06 one beat per baked mark layer
      2700 + (flowState.opts.encrypt ? 600 : 0), // 07 tile burst + package seal
      2400 + (flowState.opts.encrypt ? 400 : 0), // 08 wire loop + validate scan
      (renderer === 'webgl' ? 3400 : 3000) + (flowState.mode === 'fortress' ? 200 : 0),
      3200, // 10 three extraction outputs fan out one by one
    ];
  }
  function refreshFlowDurations() {
    flowState.durations = flowStageDurations();
    flowState.routeMs = flowState.durations.reduce((sum, ms) => sum + ms, 0);
    return flowState.durations;
  }
  function flowStageDuration(index = flowState.step) {
    if (!flowState.durations.length) refreshFlowDurations();
    return flowState.durations[index] || 2500;
  }
  function formatFlowMs(ms) {
    return `${(ms / 1000).toFixed(1)}s`;
  }
  const flowPlan = buildScramblePlan(8, 'archx-flow-explainer', 2);
  const clamp01 = (v) => Math.max(0, Math.min(1, v));
  const lerp = (a, b, t) => a + (b - a) * t;
  const ease = (t) => { const x = clamp01(t); return x * x * (3 - 2 * x); };
  const phase = (t, a, b) => clamp01((t - a) / Math.max(0.001, b - a));
  const cap = (s) => s ? s[0].toUpperCase() + s.slice(1) : s;

  function effectiveRenderer() {
    if (flowState.renderer !== 'auto') return flowState.renderer;
    return flowState.mode === 'vault' || flowState.mode === 'fortress' ? 'webgl' : 'canvas';
  }
  function clientForensicOn() {
    // Framework default is on; Lite is the one mode that turns it off by default.
    return flowState.mode !== 'lite';
  }
  function rendererFact() {
    const r = effectiveRenderer();
    const name = r === 'webgl' ? 'WebGL shader' : 'Canvas 2D';
    return flowState.renderer === 'auto'
      ? `${name} (auto from ${cap(flowState.mode)})`
      : `${name} (renderer: "${flowState.renderer}")`;
  }
  function wireFact() {
    const payload = flowState.opts.encrypt
      ? 'AES-256-GCM-encrypted .archx scrambled derivative'
      : 'Unencrypted .archx scrambled derivative';
    const token = flowState.opts.pop
      ? 'one-time token, sender-constrained to the proof key'
      : 'one-time token; no proof supplied in this illustration';
    return `${payload} · ${token} · no master`;
  }
  function extractFact() {
    const r = effectiveRenderer();
    const choice = flowState.extract;
    if (r === 'webgl') {
      if (choice === 'black') return 'Instance readback is decoyed/black; prototype GL readback sees the cleared black drawing buffer.';
      return `Instance exports return the real ${choice === 'lowres' ? 'low-res' : 'low-res scrambled'} decoy; prototype GL readback still sees cleared black.`;
    }
    let base;
    if (choice === 'black') base = 'Instance exports and getImageData return the branded black / opaque-black decoy.';
    else if (choice === 'lowres') base = 'Instance exports return a real low-res decoy; instance getImageData stays black.';
    else base = 'Instance exports return a real low-res scrambled decoy; instance getImageData stays black.';
    if (flowState.mode === 'vault' || flowState.mode === 'fortress') {
      return `${base} Forcing Canvas here skips the non-Vault origin-taint setup, so prototype-call 2D readback is not browser-blocked — Auto/WebGL is the stronger pairing.`;
    }
    return `${base} Prototype-call readback is browser-blocked only when the origin-taint pixel actually loads.`;
  }
  function activeMarks() {
    const marks = [];
    if (flowState.opts.watermark) marks.push('visible watermark');
    if (flowState.opts.serverForensic) marks.push('server forensic blocks');
    if (flowState.opts.stego) marks.push('StegoMark');
    return marks;
  }
  function modeInfo() {
    const r = effectiveRenderer();
    const branch = r === 'webgl'
      ? 'On this branch the still-scrambled bitmap becomes a GPU texture and the fragment shader maps every displayed fragment back to its source tile and mirror — no clean CPU working canvas for the static image.'
      : 'On this branch a private Canvas 2D working canvas assembles the tiles at backing-store size, paints the guarded display canvas, then is zeroed; the visible canvas necessarily holds the pixels being shown.';
    switch (flowState.mode) {
      case 'lite':
        return {
          title: 'Lite — the lightweight baseline',
          text: `Lite keeps the guarded viewer but defaults client forensic marking off, so this chart's final view carries server marks only unless a host explicitly adds forensic: true. Catalog batching and width buckets come from presets or direct flags, not from the mode name alone. ${branch}`,
        };
      case 'vault':
        return {
          title: 'Vault — shader-first viewing',
          text: `Vault chooses WebGL when the renderer is left on auto, keeping tile assembly in the shader and the drawing buffer non-preserved. ${branch}`,
        };
      case 'fortress':
        return {
          title: 'Fortress — Vault plus capture friction',
          text: `Fortress normalizes to the Vault path and adds capture shielding, 60 Hz temporal interlace, strike lockout, DevTools blanking and integrity locking by default. The checker shimmer in the final frames only indicates that temporal split; screenshots and cameras can still capture a degraded display, and multi-frame capture can recombine it. ${branch}`,
        };
      case 'custom':
        return {
          title: 'Custom — no bundle, direct flags only',
          text: `Custom adds no mode bundle: ordinary framework defaults apply until the host's own flags override them, and the renderer selection decides whether the internal path behaves like the Canvas or WebGL branch. It is the escape hatch for hand-picking protections instead of accepting a preset personality. ${branch}`,
        };
      default:
        return {
          title: 'Shield — the default viewer',
          text: `Shield is the default mode. With the renderer on auto it takes the Canvas 2D branch; choosing WebGL here promotes the same delivery to the shader branch without changing what the server sends. ${branch}`,
        };
    }
  }
  function flowStages() {
    const r = effectiveRenderer();
    const marks = activeMarks();
    const pop = flowState.opts.pop;
    const enc = flowState.opts.encrypt;
    return [
      {
        zone: 'SERVER · PRIVATE',
        title: 'The master goes in — and stays there',
        short: 'Indexed by ID outside public roots declared to Archx; undeclared host mounts remain the operator’s responsibility.',
        body: 'The original is indexed by image ID in a masters directory outside every public root declared to Archx. Startup rejects overlap with declared roots and contains paths/symlinks; undeclared host mounts remain the operator’s responsibility, and no Archx route returns the original file.',
      },
      {
        zone: 'BROWSER → SERVER · TOKEN REQUEST',
        title: 'The browser asks first',
        short: pop
          ? 'The viewer measures its box and requests a token for that ID and size, sending the public half of its proof key. No pixels move yet.'
          : 'The viewer measures its box and requests a token for that ID and size. No pixels or master path move yet.',
        body: `The loader waits for a stable display box, derives the needed width from CSS size, device-pixel ratio and oversampling (snapped to canonical buckets only if configured), then requests a token for the image ID. ${pop ? 'In this illustrated delivery it also sends the public proof-of-possession key; the private half never leaves the browser.' : 'No proof key is supplied in this illustrated delivery.'}`,
      },
      {
        zone: 'SERVER · AUTHORIZE + SIGN',
        title: 'The server decides and signs',
        short: enc
          ? 'Authorization and entitlement caps run before the HMAC token, scramble key, grid, expiry and one-view AES key are returned.'
          : 'Authorization and entitlement caps run before the HMAC token, scramble key, grid and expiry are returned.',
        body: `Rate limits and the host's deny-by-default authorize callback run first, unless the deployment explicitly chooses public anonymous delivery. The entitlement caps width, quality and format and may bind viewer/trace and mark choices. Only then does the server HMAC-sign allowlisted claims and return a clean payload URL, token, scramble key, grid and expiry${enc ? ', plus the one-view AES key' : ''}. An authorized browser necessarily receives viewing keys — that is access control, not DRM.`,
      },
      {
        zone: 'BROWSER → SERVER · REDEEM',
        title: 'The token is redeemed and spent',
        short: pop
          ? 'The payload request carries the token and a signature from the matching private proof key; checks pass, then the one-time claim is spent.'
          : 'The payload request carries the token; signature, expiry, bindings and a second authorization run before the one-time claim is spent.',
        body: `The viewer fetches the clean payload URL with the token${pop ? ' and a fresh proof signature bound to that token, method and target' : ''}. The server verifies canonical encoding, HMAC and expiry${pop ? ', verifies the proof' : ''}, re-runs authorize for the image phase, checks viewer/trace bindings, and only then atomically spends the one-time claim. A current entitlement may tighten the signed width, quality or format — never widen it.`,
      },
      {
        zone: 'SERVER · SHARP DERIVATIVE',
        title: 'Sharp builds only the entitled derivative',
        short: 'Cold path shown: bytes are sniffed and budget-checked, decoded, orientation-baked when needed, and resized. Validated cache hits can skip repeated work.',
        body: 'The middleware resolves the indexed master and, on the cold path shown here, Sharp validates and decodes it under byte, pixel and time budgets, bakes EXIF orientation when present, and resizes to the signed, entitled width. That is not inherently the physical display size: maxWidthFraction defaults to 1, so native-width pixels can be delivered when other caps permit. The clean derivative base stays server-side; the master file and its metadata never enter the response.',
      },
      {
        zone: 'SERVER · OPTIONAL MARKS',
        title: marks.length ? 'Server marks are baked in' : 'Optional server marks are skipped',
        short: marks.length
          ? `Applied to derivative pixels in server order: ${marks.join(' → ')}. Copy-on-write keeps the cached clean base clean.`
          : 'All three optional server-mark branches are off in this configuration, so the clean derivative passes through unchanged.',
        body: marks.length
          ? `Enabled marks are applied to the derivative pixels before scrambling, in server order: ${marks.join(' → ')}. They are baked into a per-view copy, not into the cached clean base. In the drawing, faint rust dots exaggerate StegoMark so an invisible layer is visible for teaching. If ownership claims are configured, the signed perceptual claim is also derived from these final pre-scramble pixels.`
          : 'With visible watermarking, server forensic blocks and StegoMark all off, this stage is a pass-through. That costs nothing in image quality, but a later screenshot or re-upload carries no server-baked attribution layer from this delivery.',
      },
      {
        zone: 'SERVER → WIRE · PACKAGE',
        title: 'Tiles are scrambled and packaged',
        short: enc
          ? 'Keyed padding and the 8×8 plan-v2 tile permutation are encoded, wrapped as .archx, then sealed with AES-256-GCM.'
          : 'Keyed padding and the 8×8 plan-v2 tile permutation are encoded and wrapped as .archx. Scramble alone is obfuscation, not encryption.',
        body: `A fused pass writes keyed padding and mirrored, permuted tiles; the result is image-encoded (WebP by default) and wrapped in the .archx container with its dimensions, grid and mark flags. ${enc ? 'Because encrypt is on in this illustration, the encoded payload is then sealed with AES-256-GCM.' : 'Because encrypt is off here, network confidentiality rests on HTTPS; tile obfuscation adds no secrecy, and a captured payload can be reconstructed with enough work.'} Either way, page source contains no master URL.`,
      },
      {
        zone: 'BROWSER · OPEN PAYLOAD',
        title: 'The browser opens the payload',
        short: enc
          ? 'Bounded fetch, strict .archx and geometry checks, AES-GCM decrypt, then decode — the bitmap is still a scrambled mosaic.'
          : 'Bounded fetch, strict .archx and geometry checks, then decode — the bitmap is still a scrambled mosaic.',
        body: `The viewer fetches with size and time bounds, strictly validates the container and padded geometry${enc ? ', decrypts the sealed payload' : ''}, sniffs the encoded image before decoding, and verifies the decoded bitmap against the header. At the end of this stage the browser holds only the still-scrambled derivative bitmap and the inverse tile plan.`,
      },
      {
        zone: r === 'webgl' ? 'BROWSER · WEBGL RENDER' : 'BROWSER · CANVAS RENDER',
        title: r === 'webgl' ? 'The WebGL shader renders the view' : 'Canvas 2D assembles the view',
        short: r === 'webgl'
          ? `${cap(flowState.mode)} uploads the scrambled bitmap as a texture; the shader maps each fragment to its source tile/flip${clientForensicOn() ? ' and can add the client forensic pass' : ''}.`
          : `${cap(flowState.mode)} assembles tiles in a private working canvas${clientForensicOn() ? ', bakes configured client marks,' : ''} paints the guarded display canvas, then zeroes the work canvas.`,
        body: r === 'webgl'
          ? `The scrambled bitmap is uploaded as a texture beside a tile-map texture. The fragment shader performs the un-scramble per fragment, so the static path needs no clean CPU working canvas; the drawing buffer is presented without preservation, which is why later GL readback sees black.${flowState.mode === 'fortress' ? ' Fortress also releases the source bitmap after upload and can temporally split the presented frames.' : ''}`
          : `Canvas mode assembles the full derivative once in a private working canvas${clientForensicOn() ? ', bakes any configured client watermark/forensic blocks,' : ' (Lite leaves client forensic marking off by default),'} paints the visible guarded canvas, then zeroes the working canvas. Optional split canvases slice that one composed frame; Lens and temporal modes are the deliberate exceptions that retain a private frame.`,
      },
      {
        zone: 'OUTPUT · WHAT CAN COME OUT',
        title: 'What can come out',
        short: `The visitor sees the entitled derivative. Network capture gets ${enc ? 'encrypted scrambled' : 'scrambled'} bytes; programmatic readback gets the ${flowState.extract} result; screenshots remain possible at the server-authorized width, which may be native width.`,
        body: `The legitimate visitor sees the authorized derivative; its width is bound by server policy and may reach native width unless maxWidthFraction is below 1. Network tools and page source get ${enc ? 'AES-sealed scrambled' : 'scrambled'} payload bytes and no master. Programmatic readback follows the selected renderer and onExtract branch. A screenshot, OS capture or camera still sees what was displayed — bounded by configured server width caps (which may allow native width)${marks.length || clientForensicOn() ? ' and carrying the enabled marks for later corroborated rescanning' : ''}${flowState.mode === 'fortress' ? ', with Fortress temporal/capture friction raising effort but not preventing capture' : ''}.`,
      },
    ];
  }

  /* ----- generated artwork for the canvas animation ----- */
  function makeFlowArt(marked, markOpts = flowState.opts) {
    const c = document.createElement('canvas');
    c.width = 320; c.height = 200;
    const x = c.getContext('2d');
    if (!x) return c;
    const sky = x.createLinearGradient(0, 0, 0, 132);
    sky.addColorStop(0, '#8fb8c9'); sky.addColorStop(1, '#f0d9a8');
    x.fillStyle = sky; x.fillRect(0, 0, 320, 132);
    x.fillStyle = '#d9903c'; x.beginPath(); x.arc(254, 42, 20, 0, 6.3); x.fill();
    x.fillStyle = '#476b73';
    x.beginPath(); x.moveTo(0, 126); x.lineTo(74, 62); x.lineTo(126, 108); x.lineTo(174, 50); x.lineTo(250, 118); x.lineTo(320, 78); x.lineTo(320, 132); x.lineTo(0, 132); x.closePath(); x.fill();
    x.fillStyle = '#29484f';
    x.beginPath(); x.moveTo(0, 132); x.lineTo(92, 86); x.lineTo(164, 124); x.lineTo(238, 82); x.lineTo(320, 126); x.lineTo(320, 146); x.lineTo(0, 146); x.closePath(); x.fill();
    x.fillStyle = '#71854a'; x.fillRect(0, 140, 320, 60);
    x.fillStyle = '#e8dcc0';
    x.beginPath(); x.moveTo(138, 200); x.lineTo(166, 142); x.lineTo(184, 142); x.lineTo(196, 200); x.closePath(); x.fill();
    x.fillStyle = '#223d2c';
    [34, 58, 276, 296].forEach((tx) => {
      x.fillRect(tx + 5, 150, 5, 20);
      x.beginPath(); x.moveTo(tx - 4, 154); x.lineTo(tx + 8, 126); x.lineTo(tx + 20, 154); x.closePath(); x.fill();
    });
    if (marked) {
      if (markOpts.serverForensic) {
        for (let gy = 0; gy < 5; gy++) for (let gx = 0; gx < 8; gx++) {
          const v = Math.sin(gx * 12.9898 + gy * 78.233) * 43758.5453;
          x.fillStyle = (v - Math.floor(v)) > 0.5 ? 'rgba(255,253,247,.13)' : 'rgba(25,22,18,.11)';
          x.fillRect(gx * 40, gy * 40, 40, 40);
        }
      }
      if (markOpts.watermark) {
        x.save(); x.translate(160, 100); x.rotate(-0.32);
        x.font = '700 16px ui-monospace, monospace'; x.fillStyle = 'rgba(255,253,247,.55)';
        x.fillText('© ARCHX · VIEW 7F3A', -132, -28);
        x.fillText('© ARCHX · VIEW 7F3A', -104, 24);
        x.fillText('© ARCHX · VIEW 7F3A', -148, 76);
        x.restore();
      }
      if (markOpts.stego) {
        x.fillStyle = 'rgba(177,58,34,.58)';
        for (let i = 0; i < 58; i++) {
          const px = 12 + ((Math.sin(i * 91.17) * 0.5 + 0.5) * 296);
          const py = 12 + ((Math.cos(i * 47.31) * 0.5 + 0.5) * 176);
          x.beginPath(); x.arc(px, py, 1.7, 0, 6.3); x.fill();
        }
      }
    }
    return c;
  }
  const cleanArt = makeFlowArt(false);
  let markedArt = cleanArt;
  let markedLayerArts = [];
  function flowMarkLayers() {
    const all = [
      { key: 'watermark', label: 'visible ©' },
      { key: 'serverForensic', label: 'forensic blocks' },
      { key: 'stego', label: 'StegoMark dots' },
    ];
    return all.filter((layer) => flowState.opts[layer.key]);
  }
  function rebuildFlowArtwork() {
    markedArt = makeFlowArt(true);
    const subset = { watermark: false, serverForensic: false, stego: false };
    markedLayerArts = flowMarkLayers().map((layer) => {
      subset[layer.key] = true;
      return { ...layer, art: makeFlowArt(true, { ...subset }) };
    });
  }
  rebuildFlowArtwork();
  const lowArt = document.createElement('canvas');
  lowArt.width = 36; lowArt.height = 23;
  const lowCtx = lowArt.getContext('2d');

  function drawFlowLock(cx, cy, s = 1) {
    if (!fctx) return;
    fctx.save(); fctx.translate(cx, cy); fctx.scale(s, s);
    fctx.fillStyle = '#ece3d0'; fctx.strokeStyle = '#191612'; fctx.lineWidth = 2;
    fctx.fillRect(-11, -2, 22, 17); fctx.strokeRect(-11, -2, 22, 17);
    fctx.beginPath(); fctx.arc(0, -3, 7, Math.PI, 0); fctx.stroke();
    fctx.fillStyle = '#191612'; fctx.beginPath(); fctx.arc(0, 6, 3, 0, 6.3); fctx.fill();
    fctx.restore();
  }
  function drawFlowImage(art, x, y, w, h, o = {}) {
    if (!fctx || !art) return;
    const scramble = clamp01(o.scramble || 0);
    const encrypt = clamp01(o.encrypt || 0);
    fctx.save();
    fctx.globalAlpha = o.alpha ?? 1;
    fctx.beginPath(); fctx.rect(x, y, w, h); fctx.clip();
    if (o.black) {
      fctx.fillStyle = '#090908'; fctx.fillRect(x, y, w, h);
      fctx.fillStyle = 'rgba(236,227,208,.72)';
      fctx.font = '700 13px ui-monospace, monospace'; fctx.textAlign = 'center';
      fctx.fillText('ARCHX', x + w / 2, y + h / 2 + 4);
      fctx.textAlign = 'left';
    } else {
      let source = art;
      if (o.pixelate && lowCtx) {
        lowCtx.clearRect(0, 0, lowArt.width, lowArt.height);
        lowCtx.drawImage(art, 0, 0, lowArt.width, lowArt.height);
        source = lowArt;
        fctx.imageSmoothingEnabled = false;
      } else {
        fctx.imageSmoothingEnabled = true;
      }
      if (scramble <= 0.001) {
        fctx.drawImage(source, x, y, w, h);
      } else {
        const g = 8;
        const sw = source.width / g, sh = source.height / g;
        const dw = w / g, dh = h / g;
        const e = ease(scramble);
        fctx.fillStyle = '#191612'; fctx.fillRect(x, y, w, h);
        for (let orig = 0; orig < 64; orig++) {
          const dest = flowPlan.inverse[orig];
          const ox = x + (orig % g) * dw, oy = y + Math.floor(orig / g) * dh;
          const tx = x + (dest % g) * dw, ty = y + Math.floor(dest / g) * dh;
          /* Stagger the tiles and bow their paths: a scramble should read as
             many small pieces swapping places, not one picture sliding. The
             endpoints are untouched, so scramble 0 and 1 stay exact. */
          const delay = ((orig * 29) % 17) / 17 * 0.2;
          const le = ease(clamp01((e - delay) / 0.8));
          let dx = lerp(ox, tx, le);
          let dy = lerp(oy, ty, le);
          const vx = tx - ox, vy = ty - oy;
          const dist = Math.hypot(vx, vy);
          if (dist > 0.5) {
            const bow = Math.sin(Math.PI * le) * Math.min(15, dist * 0.13) * (orig % 2 ? 1 : -1);
            dx += (-vy / dist) * bow;
            dy += (vx / dist) * bow;
          }
          const flip = le > 0.55 ? flowPlan.flips[dest] : { fx: false, fy: false };
          const lift = 1 + Math.sin(Math.PI * le) * 0.06;
          fctx.save();
          fctx.translate(dx + dw / 2, dy + dh / 2);
          fctx.scale((flip.fx ? -1 : 1) * lift, (flip.fy ? -1 : 1) * lift);
          fctx.drawImage(source, (orig % g) * sw, Math.floor(orig / g) * sh, sw, sh, -dw / 2, -dh / 2, dw + 0.6, dh + 0.6);
          fctx.restore();
        }
      }
      if (o.client) {
        for (let gy = 0; gy < 4; gy++) for (let gx = 0; gx < 6; gx++) {
          const v = Math.sin(gx * 19.19 + gy * 7.7) * 24634.63;
          fctx.fillStyle = (v - Math.floor(v)) > 0.5 ? 'rgba(255,253,247,.12)' : 'rgba(25,22,18,.10)';
          fctx.fillRect(x + gx * w / 6, y + gy * h / 4, w / 6, h / 4);
        }
      }
      if (o.temporal) {
        const cell = 15;
        const ph = Math.floor(flowState.now / 480) % 2;
        fctx.fillStyle = 'rgba(25,22,18,.17)';
        for (let yy = y, iy = 0; yy < y + h; yy += cell, iy++) {
          for (let xx = x, ix = 0; xx < x + w; xx += cell, ix++) {
            if ((ix + iy + ph) % 2 === 0) fctx.fillRect(xx, yy, cell, cell);
          }
        }
      }
      if (encrypt > 0) {
        fctx.fillStyle = `rgba(11,13,19,${encrypt * 0.76})`;
        fctx.fillRect(x, y, w, h);
        for (let gy = 0; gy < 5; gy++) for (let gx = 0; gx < 7; gx++) {
          const v = Math.sin(gx * 31.7 + gy * 17.3) * 12345.67;
          if ((v - Math.floor(v)) > 0.45) {
            fctx.fillStyle = `rgba(236,227,208,${encrypt * 0.13})`;
            fctx.fillRect(x + gx * w / 7, y + gy * h / 5, w / 7, h / 5);
          }
        }
        if (w > 88 && encrypt > 0.25) drawFlowLock(x + w / 2, y + h / 2, 1);
      }
    }
    fctx.restore();
    fctx.strokeStyle = 'rgba(25,22,18,.78)'; fctx.lineWidth = 1;
    fctx.strokeRect(x + 0.5, y + 0.5, w - 1, h - 1);
  }
  function flowText(txt, x, y, font = '12px ui-monospace, monospace', color = '#191612', align = 'left') {
    if (!fctx) return;
    fctx.font = font; fctx.fillStyle = color; fctx.textAlign = align;
    fctx.fillText(txt, x, y); fctx.textAlign = 'left';
  }
  function flowBadge(txt, x, y, active = true) {
    if (!fctx) return 0;
    fctx.font = '700 11px ui-monospace, monospace';
    const w = Math.ceil(fctx.measureText(txt).width) + 18;
    fctx.fillStyle = active ? '#191612' : 'transparent';
    fctx.strokeStyle = '#191612'; fctx.lineWidth = 1;
    fctx.fillRect(x, y, w, 24); fctx.strokeRect(x + 0.5, y + 0.5, w - 1, 23);
    flowText(txt, x + 9, y + 16, '700 11px ui-monospace, monospace', active ? '#f3ede1' : '#4a453a');
    return w + 8;
  }
  function flowPacket(x, y, w, h, title, lines) {
    if (!fctx) return;
    fctx.fillStyle = '#fffdf7'; fctx.strokeStyle = '#191612'; fctx.lineWidth = 1.4;
    fctx.fillRect(x, y, w, h); fctx.strokeRect(x + 0.5, y + 0.5, w - 1, h - 1);
    fctx.fillStyle = '#b13a22'; fctx.fillRect(x, y, w, 4);
    flowText(title, x + 10, y + 22, '700 12px ui-monospace, monospace');
    lines.forEach((line, i) => flowText(line, x + 10, y + 41 + i * 16, '11px ui-monospace, monospace', '#4a453a'));
  }
  function flowChecks(x, y, w, title, lines, reveal) {
    if (!fctx) return;
    const h = 40 + lines.length * 22;
    fctx.fillStyle = '#fffdf7'; fctx.strokeStyle = '#191612'; fctx.lineWidth = 1.3;
    fctx.fillRect(x, y, w, h); fctx.strokeRect(x + 0.5, y + 0.5, w - 1, h - 1);
    flowText(title, x + 11, y + 22, '700 12px ui-monospace, monospace', '#b13a22');
    const shown = Math.floor(clamp01(reveal) * lines.length + 0.001);
    lines.forEach((line, i) => {
      flowText(`${i < shown ? '✓' : '·'} ${line}`, x + 11, y + 46 + i * 22, '11.5px ui-monospace, monospace', i < shown ? '#191612' : '#8a8170');
    });
  }
  function flowEmpty(x, y, w, h, lines) {
    if (!fctx) return;
    fctx.save(); fctx.setLineDash([6, 5]);
    fctx.strokeStyle = '#8a8170'; fctx.lineWidth = 1.2;
    fctx.strokeRect(x, y, w, h); fctx.restore();
    lines.forEach((line, i) => flowText(line, x + w / 2, y + h / 2 - (lines.length - 1) * 8 + i * 17, '700 11px ui-monospace, monospace', '#6b6352', 'center'));
  }
  function flowArrow(x1, y, x2) {
    if (!fctx) return;
    fctx.save(); fctx.strokeStyle = '#b13a22'; fctx.fillStyle = '#b13a22'; fctx.lineWidth = 2;
    fctx.beginPath(); fctx.moveTo(x1, y); fctx.lineTo(x2, y); fctx.stroke();
    const dir = x2 >= x1 ? 1 : -1;
    fctx.beginPath(); fctx.moveTo(x2, y); fctx.lineTo(x2 - dir * 9, y - 5); fctx.lineTo(x2 - dir * 9, y + 5); fctx.closePath(); fctx.fill();
    fctx.restore();
  }
  function flowCurvePoint(p, tt) {
    const u = clamp01(tt), v = 1 - u;
    return [
      v * v * v * p[0][0] + 3 * v * v * u * p[1][0] + 3 * v * u * u * p[2][0] + u * u * u * p[3][0],
      v * v * v * p[0][1] + 3 * v * v * u * p[1][1] + 3 * v * u * u * p[2][1] + u * u * u * p[3][1],
    ];
  }
  function flowCurve(p, progress = 1, color = '#b13a22', dashed = false) {
    if (!fctx) return;
    const end = clamp01(progress);
    if (end <= 0) return;
    fctx.save();
    fctx.strokeStyle = color; fctx.fillStyle = color; fctx.lineWidth = 2;
    if (dashed) fctx.setLineDash([6, 5]);
    fctx.beginPath();
    const steps = Math.max(2, Math.round(44 * end));
    for (let i = 0; i <= steps; i++) {
      const [x, y] = flowCurvePoint(p, (i / steps) * end);
      if (i === 0) fctx.moveTo(x, y); else fctx.lineTo(x, y);
    }
    fctx.stroke();
    fctx.setLineDash([]);
    const [x2, y2] = flowCurvePoint(p, end);
    const [x1, y1] = flowCurvePoint(p, Math.max(0, end - 0.02));
    const a = Math.atan2(y2 - y1, x2 - x1);
    fctx.beginPath();
    fctx.moveTo(x2, y2);
    fctx.lineTo(x2 - 10 * Math.cos(a - 0.42), y2 - 10 * Math.sin(a - 0.42));
    fctx.lineTo(x2 - 10 * Math.cos(a + 0.42), y2 - 10 * Math.sin(a + 0.42));
    fctx.closePath(); fctx.fill();
    fctx.restore();
  }
  function flowPulse(p, tt, color = '#b13a22', r = 6) {
    if (!fctx) return;
    const [x, y] = flowCurvePoint(p, tt);
    fctx.save();
    fctx.fillStyle = '#fffdf7'; fctx.strokeStyle = color; fctx.lineWidth = 2;
    fctx.beginPath(); fctx.arc(x, y, r, 0, 6.3); fctx.fill(); fctx.stroke();
    fctx.fillStyle = color;
    fctx.beginPath(); fctx.arc(x, y, Math.max(2, r - 3), 0, 6.3); fctx.fill();
    fctx.restore();
  }
  function flowScanFrame(x, y, w, h, p, color = '#b13a22') {
    if (!fctx) return;
    const q = clamp01(p);
    const sx = x + w * q;
    fctx.save();
    fctx.fillStyle = 'rgba(177,58,34,.08)';
    fctx.fillRect(x, y, Math.max(0, sx - x), h);
    fctx.strokeStyle = color; fctx.lineWidth = 2;
    fctx.beginPath(); fctx.moveTo(sx, y - 4); fctx.lineTo(sx, y + h + 4); fctx.stroke();
    const c = 14;
    fctx.beginPath();
    fctx.moveTo(x - 5, y + c); fctx.lineTo(x - 5, y - 5); fctx.lineTo(x + c, y - 5);
    fctx.moveTo(x + w - c, y - 5); fctx.lineTo(x + w + 5, y - 5); fctx.lineTo(x + w + 5, y + c);
    fctx.moveTo(x + w + 5, y + h - c); fctx.lineTo(x + w + 5, y + h + 5); fctx.lineTo(x + w - c, y + h + 5);
    fctx.moveTo(x + c, y + h + 5); fctx.lineTo(x - 5, y + h + 5); fctx.lineTo(x - 5, y + h - c);
    fctx.stroke();
    fctx.restore();
  }
  function flowGate(x, y, w, h, open) {
    if (!fctx) return;
    const q = clamp01(open);
    fctx.save();
    fctx.strokeStyle = '#191612'; fctx.fillStyle = '#191612'; fctx.lineWidth = 2;
    fctx.strokeRect(x + 0.5, y + 0.5, w - 1, h - 1);
    const bars = 6;
    for (let i = 0; i < bars; i++) {
      const bx = x + 10 + i * ((w - 20) / (bars - 1));
      const top = y + 8 + q * (h - 18) * (0.45 + 0.09 * i);
      fctx.beginPath(); fctx.moveTo(bx, top); fctx.lineTo(bx, y + h - 8); fctx.stroke();
    }
    fctx.restore();
  }
  function flowSeal(cx, cy, p, label = '✓') {
    if (!fctx) return;
    const q = clamp01(p);
    if (q <= 0) return;
    fctx.save();
    fctx.globalAlpha = Math.min(1, q * 1.4);
    fctx.translate(cx, cy); fctx.scale(0.55 + 0.45 * ease(q), 0.55 + 0.45 * ease(q));
    fctx.fillStyle = '#b13a22';
    fctx.beginPath(); fctx.arc(0, 0, 19, 0, 6.3); fctx.fill();
    fctx.strokeStyle = '#fffdf7'; fctx.lineWidth = 2;
    fctx.beginPath(); fctx.arc(0, 0, 14.5, 0, 6.3); fctx.stroke();
    fctx.fillStyle = '#fffdf7'; fctx.font = '700 15px ui-monospace, monospace'; fctx.textAlign = 'center';
    fctx.fillText(label, 0, 5.5);
    fctx.restore();
  }
  function drawFlowTimeline() {
    if (!fctx || !flowState.durations.length) return;
    const x0 = 18, totalW = 944, y = 41;
    const total = Math.max(1, flowState.routeMs);
    let x = x0;
    fctx.save();
    fctx.fillStyle = '#ddd0ae'; fctx.fillRect(x0, y, totalW, 3);
    flowState.durations.forEach((ms, i) => {
      const w = totalW * ms / total;
      if (i < flowState.step) {
        fctx.fillStyle = '#b13a22'; fctx.fillRect(x, y, w, 3);
      } else if (i === flowState.step) {
        fctx.fillStyle = '#191612'; fctx.fillRect(x, y, w * clamp01(flowState.t), 3);
        fctx.fillStyle = '#b13a22';
        fctx.beginPath(); fctx.arc(x + w * clamp01(flowState.t), y + 1.5, 4, 0, 6.3); fctx.fill();
      }
      x += w;
      fctx.fillStyle = '#fffdf7'; fctx.fillRect(Math.min(961, x - 0.5), y - 2, 1, 7);
    });
    fctx.restore();
  }
  function drawFlowZones() {
    if (!fctx || !flowCanvas) return;
    fctx.clearRect(0, 0, flowCanvas.width, flowCanvas.height);
    fctx.fillStyle = '#fffdf7'; fctx.fillRect(0, 0, flowCanvas.width, flowCanvas.height);
    fctx.fillStyle = '#f7efdd'; fctx.fillRect(18, 48, 492, 340);
    fctx.fillStyle = '#eef0e3'; fctx.fillRect(594, 48, 368, 340);
    fctx.strokeStyle = '#191612'; fctx.lineWidth = 1.4;
    fctx.strokeRect(18.5, 48.5, 491, 339); fctx.strokeRect(594.5, 48.5, 367, 339);
    fctx.save(); fctx.setLineDash([5, 5]); fctx.strokeStyle = '#b9ab8b';
    fctx.strokeRect(510.5, 48.5, 83, 339); fctx.restore();
    flowText('SERVER · MASTERS + MIDDLEWARE + SHARP', 18, 32, '700 13px ui-monospace, monospace');
    flowText('WIRE', 552, 32, '700 13px ui-monospace, monospace', '#191612', 'center');
    flowText('BROWSER · ARCHX VIEWER', 594, 32, '700 13px ui-monospace, monospace');
    flowText('private master never leaves this side', 18, 410, '11px ui-monospace, monospace', '#6b6352');
    flowText('HTTPS', 552, 410, '11px ui-monospace, monospace', '#6b6352', 'center');
    flowText(rendererFact(), 962, 410, '11px ui-monospace, monospace', '#6b6352', 'right');
    drawFlowTimeline();
  }
  function drawFlow() {
    if (!fctx) return;
    drawFlowZones();
    const s = flowState.step;
    const t = flowState.t;
    const e = ease(t);
    const client = clientForensicOn();
    const temporal = flowState.mode === 'fortress';

    if (s === 0) {
      flowText('MASTER · PRIVATE DIRECTORY', 42, 84, '700 12px ui-monospace, monospace', '#b13a22');
      drawFlowImage(cleanArt, 42, 98, 268, 168);
      flowPacket(336, 106, 148, 126, 'SERVER ONLY', ['no public route', 'read by ID', 'startup checked']);
      drawFlowLock(410, 262, 1.05);
      /* The vault bars close over the master, then a direct grab is turned
         back on itself — denial is a loop, not a slide. */
      flowGate(42, 98, 268, 168, 1 - ease(phase(t, 0.02, 0.48)));
      const denied = [[488, 178], [562, 92], [630, 120], [552, 220]];
      flowCurve(denied, phase(t, 0.38, 0.9), '#b13a22', true);
      if (t > 0.72 && fctx) {
        fctx.strokeStyle = '#b13a22'; fctx.lineWidth = 3;
        fctx.beginPath(); fctx.moveTo(540, 152); fctx.lineTo(564, 180); fctx.moveTo(564, 152); fctx.lineTo(540, 180); fctx.stroke();
      }
      flowEmpty(648, 98, 268, 168, ['NO PIXELS YET', 'no master URL']);
      flowText('Keep the master outside every public web root.', 42, 356, '600 16px Georgia, serif');
    } else if (s === 1) {
      flowText('MASTER STAYS PUT', 42, 88, '700 12px ui-monospace, monospace', '#b13a22');
      drawFlowImage(cleanArt, 42, 102, 204, 128, { alpha: 0.72 });
      flowEmpty(648, 88, 268, 168, ['VIEWER BOX', 'CSS × DPR × oversample']);
      /* First the box is measured in place; only then does the little request
         card loop up and drop into the server inbox. */
      flowScanFrame(648, 88, 268, 168, phase(t, 0.02, 0.45));
      const reqPath = [[650, 282], [566, 212], [430, 350], [272, 282]];
      const reqP = ease(phase(t, 0.2, 1));
      flowCurve(reqPath, reqP, '#b13a22', true);
      const [px, py] = flowCurvePoint(reqPath, reqP);
      flowPacket(px, py, 224, 68, 'TOKEN REQUEST · {id}', ['w · bw · bh · fit', flowState.opts.pop ? '+ proof public key' : 'no pixels · no path']);
      if (flowState.opts.pop) flowSeal(782, 274, phase(t, 0.08, 0.28), 'key');
      flowText('Permission and size are requested before any image bytes exist on the wire.', 42, 366, '600 15px Georgia, serif');
    } else if (s === 2) {
      drawFlowImage(cleanArt, 38, 102, 196, 123, { alpha: 0.62 });
      flowChecks(278, 84, 206, 'SERVER DECIDES', ['authorize viewer', 'cap width / quality', 'rate + quota', 'HMAC-sign claims'], phase(t, 0.08, 0.72));
      /* The decision happens at the checklist; the seal stamps in place and
         only the finished token arcs out to the browser. */
      flowSeal(466, 102, phase(t, 0.64, 0.8));
      const tokPath = [[330, 292], [438, 208], [566, 336], [636, 292]];
      const tokP = ease(phase(t, 0.58, 1));
      if (t > 0.52) {
        flowCurve(tokPath, tokP, '#b13a22', true);
        const [px, py] = flowCurvePoint(tokPath, tokP);
        flowPacket(px, py, 238, 68, 'TOKEN RESPONSE', ['clean URL · key · grid', flowState.opts.encrypt ? 'expiry · + AES key' : 'short expiry']);
      }
      flowEmpty(676, 96, 224, 140, t > 0.9 ? ['TOKEN HELD', 'briefly, in memory'] : ['WAITING', 'for permission']);
    } else if (s === 3) {
      drawFlowImage(cleanArt, 38, 102, 196, 123, { alpha: 0.62 });
      flowChecks(278, 78, 206, 'REDEEM GATE', ['verify HMAC + expiry', flowState.opts.pop ? 'verify proof signature' : 'no proof supplied', 'authorize again', 'check bindings', 'claimOnce → spent'], phase(t, 0.2, 0.94));
      /* The payload request drops through the redeem gate on a lower arc;
         the gate bars lift one check at a time as the list fills. */
      flowGate(518, 150, 68, 118, phase(t, 0.24, 0.92));
      const getPath = [[640, 300], [562, 362], [458, 236], [340, 300]];
      const getP = ease(phase(t, 0, 0.62));
      flowCurve(getPath, getP, '#b13a22', true);
      const [px, py] = flowCurvePoint(getPath, getP);
      flowPacket(px, py, 238, 64, 'GET PAYLOAD', ['X-Archx-Token', flowState.opts.pop ? '+ signed proof' : 'clean URL']);
      if (t > 0.86) {
        const replay = [[820, 240], [700, 318], [610, 250], [586, 286]];
        flowCurve(replay, phase(t, 0.86, 1), '#8a8170', true);
        flowText('replay ✗', 650, 374, '700 11px ui-monospace, monospace', '#8a8170');
      }
      if (t > 0.82 && fctx) {
        fctx.save(); fctx.translate(459, 332); fctx.rotate(-0.08);
        fctx.strokeStyle = '#b13a22'; fctx.lineWidth = 2; fctx.strokeRect(-58, -15, 116, 30);
        flowText('SPENT ONCE', 0, 5, '700 13px ui-monospace, monospace', '#b13a22', 'center');
        fctx.restore();
      }
      flowEmpty(676, 96, 224, 140, ['TOKEN SENT BACK', 'for one payload']);
    } else if (s === 4) {
      /* Sharp works in place: the master is scanned inside its own dashed
         bounds, then the frame contracts to the entitled derivative size. */
      flowText(t < 0.5 ? 'MASTER · SNIFF + DECODE SCAN' : 'ENTITLED DERIVATIVE · WIDTH POLICY', 105, 88, '700 12px ui-monospace, monospace', '#b13a22');
      if (fctx) {
        fctx.save(); fctx.setLineDash([6, 5]); fctx.strokeStyle = '#8a8170'; fctx.lineWidth = 1.2;
        fctx.strokeRect(105.5, 102.5, 299, 187); fctx.restore();
      }
      const shrink = ease(phase(t, 0.45, 0.88));
      const iw = lerp(300, 218, shrink), ih = lerp(188, 136, shrink);
      drawFlowImage(cleanArt, 255 - iw / 2, 196 - ih / 2, iw, ih);
      flowScanFrame(105, 102, 300, 188, phase(t, 0.05, 0.45));
      if (t > 0.45) flowText('master bounds stay behind', 255, 310, '11px ui-monospace, monospace', '#6b6352', 'center');
      let bx = 70;
      bx += flowBadge('sniff + budgets', bx, 324, t > 0.18);
      bx += flowBadge('decode + orient', bx, 324, t > 0.44);
      flowBadge('resize to entitlement', bx, 324, t > 0.7);
      flowText('Only the signed, entitled width is built; preview-only needs a fraction cap.', 38, 366, '600 15px Georgia, serif');
      flowEmpty(676, 102, 224, 140, ['WAITING', 'response not started']);
    } else if (s === 5) {
      flowText('DERIVATIVE PIXELS · SERVER COPY', 94, 78, '700 12px ui-monospace, monospace', '#b13a22');
      drawFlowImage(cleanArt, 94, 92, 322, 201);
      /* Each enabled mark arrives as its own translucent sheet and fuses
         into the pixels in server order — cumulative art, one beat each. */
      const layers = markedLayerArts;
      let bx = 94;
      if (layers.length) {
        const seg = 0.72 / layers.length;
        layers.forEach((layer, i) => {
          const start = 0.12 + i * seg;
          const p = ease(phase(t, start, start + seg));
          if (p > 0) {
            const off = (1 - p) * 24;
            drawFlowImage(layer.art, 94 - off, 92 - off * 0.62, 322, 201, { alpha: 0.25 + 0.75 * p });
          }
          bx += flowBadge(layer.label, bx, 318, p > 0.82);
        });
        if (flowState.opts.stego) flowText('Rust dots exaggerate the invisible StegoMark.', 94, 368, '11px ui-monospace, monospace', '#6b6352');
      } else {
        flowBadge('all optional marks OFF — pass through', bx, 318, false);
        flowScanFrame(94, 92, 322, 201, phase(t, 0.1, 0.8), '#8a8170');
      }
      flowEmpty(676, 108, 224, 140, ['STILL SERVER-SIDE', 'nothing sent yet']);
    } else if (s === 6) {
      flowText('.ARCHX PACKAGE', 94, 78, '700 12px ui-monospace, monospace', '#b13a22');
      drawFlowImage(markedArt, 94, 92, 322, 201, {
        scramble: phase(t, 0, 0.68),
        encrypt: flowState.opts.encrypt ? phase(t, 0.68, 1) : 0,
      });
      /* Then the container closes around the scrambled tiles: header strip
         first, border second, seal last. */
      if (fctx && t > 0.52) {
        const closeP = ease(phase(t, 0.52, 0.8));
        const inset = lerp(14, 0, closeP);
        fctx.save();
        fctx.strokeStyle = '#191612'; fctx.lineWidth = 2;
        fctx.strokeRect(94 - inset + 0.5, 92 - inset + 0.5, 322 + inset * 2 - 1, 201 + inset * 2 - 1);
        fctx.fillStyle = '#b13a22';
        fctx.fillRect(94, 92, 322 * clamp01(phase(t, 0.52, 0.72)), 6);
        fctx.restore();
      }
      flowSeal(416, 92, phase(t, 0.74, 0.92), flowState.opts.encrypt ? 'AES' : '✓');
      let bx = 94;
      bx += flowBadge('8×8 plan v2 + mirrors', bx, 318, t > 0.25);
      bx += flowBadge('.archx header', bx, 318, t > 0.55);
      flowBadge(flowState.opts.encrypt ? 'AES-256-GCM' : 'no AES layer', bx, 318, flowState.opts.encrypt && t > 0.72);
      flowEmpty(676, 108, 224, 140, ['READY TO SEND', 'derivative only']);
    } else if (s === 7) {
      flowText('MASTER STAYED', 40, 292, '700 11px ui-monospace, monospace', '#6b6352');
      drawFlowImage(cleanArt, 40, 302, 116, 73, { alpha: 0.45 });
      /* The payload rides an S-loop through the wire, then stops at the
         browser validation ring instead of sliding straight across. */
      const wirePath = [[72, 94], [245, 34], [455, 238], [642, 94]];
      const wireCenter = [[206, 178], [360, 96], [548, 286], [776, 178]];
      const wireP = ease(phase(t, 0, 0.78));
      flowCurve(wireCenter, wireP, '#b13a22', true);
      const [px, py] = flowCurvePoint(wirePath, wireP);
      flowText(wireP < 0.98 ? 'ON THE WIRE' : 'VALIDATE · DECODED · STILL SCRAMBLED', px, Math.max(82, py - 12), '700 12px ui-monospace, monospace', '#b13a22');
      drawFlowImage(markedArt, px, py, 268, 168, {
        scramble: 1,
        encrypt: flowState.opts.encrypt ? 1 - phase(t, 0.8, 1) : 0,
      });
      if (t > 0.78) flowScanFrame(642, 94, 268, 168, phase(t, 0.78, 1));
      if (t > 0.9) flowBadge('validated + decoded', 676, 292, true);
      flowText('What crossed is a bounded, scrambled derivative — never the master file.', 40, 360, '600 15px Georgia, serif');
    } else if (s === 8) {
      drawFlowImage(cleanArt, 42, 108, 178, 111, { alpha: 0.45 });
      flowText('MASTER · SERVER ONLY', 42, 242, '700 11px ui-monospace, monospace', '#6b6352');
      if (effectiveRenderer() === 'canvas') {
        flowText('PRIVATE CANVAS ASSEMBLY → DISPLAY', 650, 78, '700 12px ui-monospace, monospace', '#b13a22');
        /* Ghost = the private work canvas behind the display. It fades and
           collapses as the visible canvas takes over, then is zeroed. */
        drawFlowImage(markedArt, 634, 82, 268, 168, { scramble: 1, alpha: 0.26 * (1 - phase(t, 0.6, 0.95)) });
        drawFlowImage(markedArt, 650, 94, 268, 168, {
          scramble: 1 - e,
          client: client && t > 0.55,
          temporal,
        });
        let bx = 650;
        bx += flowBadge(client ? 'client forensic baked' : 'client forensic off (Lite)', bx, 290, t > 0.55);
        if (t > 0.78) flowBadge('work canvas zeroed', bx, 290, true);
      } else {
        flowText('SCRAMBLED TEXTURE', 618, 76, '700 11px ui-monospace, monospace', '#b13a22');
        drawFlowImage(markedArt, 618, 86, 124, 78, { scramble: 1 });
        flowArrow(746, 124, 768);
        flowText('SHADER OUTPUT', 772, 76, '700 11px ui-monospace, monospace', '#b13a22');
        drawFlowImage(markedArt, 772, 86, 168, 105, { client: client && t > 0.5, temporal });
        if (fctx && t < 1) {
          fctx.fillStyle = 'rgba(255,253,247,.72)';
          fctx.fillRect(772, 86 + 105 * e, 168, 105 * (1 - e));
        }
        /* Column sweeps stand in for per-fragment tile mapping: the texture
           stays scrambled while the shader resolves the output. */
        flowScanFrame(772, 86, 168, 105, phase(t, 0.05, 0.9));
        flowPulse([[742, 124], [750, 104], [760, 150], [772, 124]], (t * 1.6) % 1, '#b13a22', 5);
        flowPacket(650, 232, 268, 66, 'FRAGMENT SHADER', ['tile map + mirrors per fragment', flowState.mode === 'fortress' && t > 0.74 ? 'source bitmap released' : 'no clean CPU work canvas']);
      }
    } else {
      flowText('NETWORK CAPTURE', 52, 86, '700 11px ui-monospace, monospace', '#b13a22');
      drawFlowImage(markedArt, 52, 96, 190, 119, { scramble: 1, encrypt: flowState.opts.encrypt ? 1 : 0, alpha: ease(phase(t, 0.22, 0.48)) });
      flowScanFrame(52, 96, 190, 119, phase(t, 0.24, 0.48), '#8a8170');
      flowText('MASTER · NEVER SENT', 282, 86, '700 11px ui-monospace, monospace', '#6b6352');
      drawFlowImage(cleanArt, 282, 96, 174, 109, { alpha: 0.52 });
      drawFlowLock(369, 150, 0.9);
      flowText('VISITOR VIEW · ENTITLED DERIVATIVE', 650, 72, '700 11px ui-monospace, monospace', '#b13a22');
      drawFlowImage(markedArt, 650, 82, 268, 150, { client, temporal, alpha: ease(phase(t, 0.02, 0.26)) });
      /* Extraction attempts branch downward out of the one legitimate view,
         one sink at a time. */
      flowCurve([[744, 232], [730, 244], [724, 250], [716, 264]], phase(t, 0.48, 0.62), '#b13a22', true);
      flowCurve([[830, 232], [842, 244], [850, 250], [858, 264]], phase(t, 0.68, 0.82), '#b13a22', true);
      flowText('READBACK', 650, 254, '700 11px ui-monospace, monospace', '#b13a22');
      drawFlowImage(markedArt, 650, 264, 132, 88, {
        black: flowState.extract === 'black',
        pixelate: flowState.extract !== 'black',
        scramble: flowState.extract === 'scrambled' ? 1 : 0,
        alpha: ease(phase(t, 0.52, 0.74)),
      });
      flowText('SCREENSHOT', 798, 254, '700 11px ui-monospace, monospace', '#b13a22');
      drawFlowImage(markedArt, 798, 264, 120, 88, { client, temporal, alpha: ease(phase(t, 0.72, 0.94)) });
      flowText('Read-back may be poisoned; screenshots still capture the displayed derivative.', 52, 360, '600 15px Georgia, serif');
    }
  }

  /* ----- DOM state / transport ----- */
  function syncSeg(id, key, value) {
    $(id)?.querySelectorAll('button').forEach((b) => {
      const on = b.dataset[key] === value;
      b.classList.toggle('is-active', on);
      b.setAttribute('aria-pressed', String(on));
    });
  }
  function syncFlowTransport() {
    const play = $('flowPlay');
    if (play) {
      play.textContent = flowState.playing ? 'Pause' : 'Play';
      play.setAttribute('aria-pressed', String(flowState.playing));
      play.setAttribute('aria-label', flowState.playing ? 'Pause flowchart animation' : 'Play flowchart animation');
    }
    const prev = $('flowPrev'); if (prev) prev.disabled = flowState.step === 0;
    const next = $('flowNext'); if (next) next.disabled = flowState.step === 9;
  }
  function updateFlowText() {
    syncSeg('flowModeSeg', 'mode', flowState.mode);
    syncSeg('flowRendererSeg', 'renderer', flowState.renderer);
    syncSeg('flowExtractSeg', 'extract', flowState.extract);
    flowRoot.querySelectorAll('[data-flow-opt]').forEach((b) => {
      const on = !!flowState.opts[b.dataset.flowOpt];
      b.classList.toggle('is-active', on);
      b.setAttribute('aria-pressed', String(on));
    });
    const note = $('flowServerNote');
    if (note) {
      note.textContent = flowState.opts.pop
        ? 'One-time tokens are on by default in the middleware; this illustrated token is also sender-constrained to the browser’s proof key.'
        : 'One-time tokens are on by default in the middleware. Proof-of-possession is off in this illustration, so a stolen bearer token would need the server’s other limits and short expiry to contain it.';
    }
    const durations = refreshFlowDurations();
    const info = modeInfo();
    if ($('flowModeTitle')) $('flowModeTitle').textContent = info.title;
    if ($('flowModeText')) $('flowModeText').textContent = info.text;
    if ($('flowRendererOut')) $('flowRendererOut').textContent = rendererFact();
    if ($('flowWireOut')) $('flowWireOut').textContent = wireFact();
    if ($('flowExtractOut')) $('flowExtractOut').textContent = extractFact();

    const stages = flowStages();
    const cur = stages[flowState.step];
    if ($('flowZone')) $('flowZone').textContent = cur.zone;
    if ($('flowStageTitle')) $('flowStageTitle').textContent = `${flowState.step + 1} · ${cur.title}`;
    if ($('flowStageText')) $('flowStageText').textContent = cur.body;
    if ($('flowProgress')) {
      const delta = FLOW_LEGACY_TOTAL_MS - flowState.routeMs;
      const deltaText = delta >= 0
        ? `${formatFlowMs(delta)} shorter than the old fixed 3.3s × 10`
        : `${formatFlowMs(Math.abs(delta))} longer than the old fixed 3.3s × 10`;
      $('flowProgress').textContent = `Stage ${flowState.step + 1} of 10 · this stage ${formatFlowMs(durations[flowState.step])} · route ${formatFlowMs(flowState.routeMs)} (${deltaText})`;
    }
    flowRoot.querySelectorAll('.flow-step').forEach((btn) => {
      const idx = Number(btn.dataset.step);
      const on = idx === flowState.step;
      btn.classList.toggle('is-current', on);
      if (on) btn.setAttribute('aria-current', 'step'); else btn.removeAttribute('aria-current');
      const strong = btn.querySelector('strong');
      if (strong) strong.textContent = stages[idx].title;
      const small = btn.querySelector('[data-flow-step-text]');
      if (small) small.textContent = `${stages[idx].short} · ${formatFlowMs(durations[idx])}`;
    });
    syncFlowTransport();
  }
  function ensureFlowLoop() {
    if (flowState.playing && !flowState.raf && flowState.visible && !document.hidden) {
      flowState.raf = requestAnimationFrame(flowFrame);
    }
  }
  function setFlowStep(step) {
    flowState.step = Math.max(0, Math.min(9, step | 0));
    flowState.t = reducedMotion ? 0.62 : 0;
    flowState.last = 0;
    updateFlowText();
    drawFlow();
    ensureFlowLoop();
  }
  function setFlowPlaying(on) {
    flowState.playing = !!on;
    flowState.last = 0;
    if (!flowState.playing && flowState.raf) {
      cancelAnimationFrame(flowState.raf);
      flowState.raf = 0;
    }
    syncFlowTransport();
    drawFlow();
    ensureFlowLoop();
  }
  function flowFrame(now) {
    flowState.raf = 0;
    if (!flowState.playing) return;
    if (!flowState.visible || document.hidden) { flowState.last = 0; return; }
    flowState.now = now;
    if (flowState.last) flowState.t += (now - flowState.last) / flowStageDuration();
    flowState.last = now;
    if (flowState.t >= 1) {
      if (flowState.step < 9) {
        setFlowStep(flowState.step + 1);
        return;
      }
      flowState.t = 1;
      flowState.playing = false;
      syncFlowTransport();
      drawFlow();
      return;
    }
    drawFlow();
    ensureFlowLoop();
  }

  $('flowModeSeg')?.addEventListener('click', (ev) => {
    const b = ev.target.closest('button[data-mode]'); if (!b) return;
    flowState.mode = b.dataset.mode; updateFlowText(); drawFlow();
  });
  $('flowRendererSeg')?.addEventListener('click', (ev) => {
    const b = ev.target.closest('button[data-renderer]'); if (!b) return;
    flowState.renderer = b.dataset.renderer; updateFlowText(); drawFlow();
  });
  $('flowExtractSeg')?.addEventListener('click', (ev) => {
    const b = ev.target.closest('button[data-extract]'); if (!b) return;
    flowState.extract = b.dataset.extract; updateFlowText(); drawFlow();
  });
  flowRoot.querySelectorAll('[data-flow-opt]').forEach((b) => {
    b.addEventListener('click', () => {
      const key = b.dataset.flowOpt;
      flowState.opts[key] = !flowState.opts[key];
      if (key === 'watermark' || key === 'serverForensic' || key === 'stego') rebuildFlowArtwork();
      updateFlowText(); drawFlow();
    });
  });
  $('flowPrev')?.addEventListener('click', () => setFlowStep(flowState.step - 1));
  $('flowNext')?.addEventListener('click', () => setFlowStep(flowState.step + 1));
  $('flowRestart')?.addEventListener('click', () => {
    setFlowStep(0);
    if (!reducedMotion) setFlowPlaying(true);
  });
  $('flowPlay')?.addEventListener('click', () => {
    if (!flowState.playing && flowState.step === 9 && flowState.t >= 1) setFlowStep(0);
    setFlowPlaying(!flowState.playing);
  });
  flowRoot.querySelectorAll('.flow-step').forEach((b) => {
    b.addEventListener('click', () => setFlowStep(Number(b.dataset.step)));
  });
  if ('IntersectionObserver' in window) {
    new IntersectionObserver((entries) => {
      flowState.visible = entries.some((en) => en.isIntersecting);
      flowState.last = 0;
      if (flowState.visible) { drawFlow(); ensureFlowLoop(); }
    }, { threshold: 0.08 }).observe(flowRoot);
  }
  document.addEventListener('visibilitychange', () => {
    flowState.last = 0;
    if (!document.hidden) ensureFlowLoop();
  });

  updateFlowText();
  drawFlow();
  ensureFlowLoop();
})();
