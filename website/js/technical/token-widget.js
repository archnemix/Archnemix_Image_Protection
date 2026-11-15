/* W2 — Token explorer (local WebCrypto HMAC-SHA256 + canonical base64url gate) */

export function initTokenWidget() {
  const tokClaimsEl = document.getElementById('tokClaims');
  if (!tokClaimsEl) return;

  const b64url = (bytes) => {
    let bin = '';
    bytes.forEach((b) => { bin += String.fromCharCode(b); });
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  };
  const b64urlDecode = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));

  async function hmac(secret, body) {
    const key = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    return new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(body)));
  }

  const CLAIM_NOTES = {
    v: 'token format version',
    kid: 'signing key id (rotation)',
    aud: 'audience: only the image service',
    scope: 'what the token may do',
    id: 'image id — bound, cannot be swapped',
    w: 'entitled width (px)',
    iat: 'issued-at (ms)',
    exp: 'expiry (ms)',
    n: 'nonce — the one-time claim key',
    jkt: '43-character proof-key thumbprint shape (not proof verification)',
  };

  const TOKEN_FIELDS = new Set([
    'v', 'kid', 'aud', 'scope', 'id', 'w', 'iat', 'exp', 'n', 'q', 'fmt', 'ls',
    'vh', 'th', 'wm', 'sg', 'sgp', 'sgs', 'sge', 'sgv', 'sgx', 'sgy', 'sgi', 'sgk',
    'nsg', 'nwm', 'b', 'jkt',
  ]);

  let currentToken = '';

  async function tokenVerify(token, label) {
    const out = document.getElementById('tokOut');
    const secret = document.getElementById('tokSecret')?.value ?? '';
    if (!out) return;

    const lines = [`token (${label}):`, token, ''];
    const parts = token.split('.');
    if (parts.length !== 2 || !/^[A-Za-z0-9_-]+$/.test(parts[0]) || !/^[A-Za-z0-9_-]+$/.test(parts[1])) {
      out.textContent = `${lines.join('\n')}\n✗ REJECTED — structure (must be body.mac, base64url alphabet)`;
      return;
    }

    const [body, mac] = parts;
    let canonical = true;
    try {
      canonical = b64url(b64urlDecode(body)) === body && b64url(b64urlDecode(mac)) === mac;
    } catch { canonical = false; }

    if (!canonical) {
      out.textContent = `${lines.join('\n')}\n✗ REJECTED — non-canonical base64url (same MAC bytes, different string). Token malleability is refused even though the signature itself is valid.`;
      return;
    }

    const expected = await hmac(secret, body);
    const given = b64urlDecode(mac);
    const macOk = given.length === expected.length && given.every((b, i) => b === expected[i]);
    if (!macOk) {
      out.textContent = `${lines.join('\n')}\n✗ REJECTED — HMAC mismatch (claims were changed after signing, or the secret is wrong)`;
      return;
    }

    let claims;
    try {
      claims = JSON.parse(new TextDecoder().decode(b64urlDecode(body)));
    } catch {
      out.textContent = `${lines.join('\n')}\n✗ REJECTED — payload is not JSON`;
      return;
    }

    const problems = [];
    const now = Date.now();
    for (const field of Object.keys(claims)) {
      if (!TOKEN_FIELDS.has(field)) problems.push(`unknown claim ${field} (server refuses)`);
    }
    if (claims.v !== 2) problems.push(`v must be 2, got ${JSON.stringify(claims.v)}`);
    if (claims.aud !== 'archx:image') problems.push(`aud must be archx:image, got ${claims.aud}`);
    if (claims.scope !== 'image:view') problems.push(`scope must be image:view, got ${claims.scope}`);
    if (claims.kid !== undefined && (typeof claims.kid !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(claims.kid))) {
      problems.push('kid must be a valid 1–64 character key id');
    }
    if (typeof claims.id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(claims.id)) {
      problems.push('id must be a valid image id');
    }
    if (!Number.isSafeInteger(claims.w) || claims.w < 64 || claims.w > 1920) {
      problems.push(`w must be an integer from 64 to 1920, got ${JSON.stringify(claims.w)}`);
    }
    if (!Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp) ||
        claims.iat > now + 300000 || claims.exp <= claims.iat || claims.exp - claims.iat > 1200000) {
      problems.push('iat/exp must be safe integers in the permitted time window');
    }
    if (!Number.isSafeInteger(claims.exp) || claims.exp <= now) problems.push('expired (or exp malformed)');
    if (typeof claims.n !== 'string' || !/^[A-Za-z0-9_-]{8,86}$/.test(claims.n)) {
      problems.push('nonce n must be an 8–86 character base64url string');
    }
    if (claims.jkt !== undefined && (typeof claims.jkt !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(claims.jkt))) {
      problems.push('jkt must be a 43-character base64url thumbprint');
    }

    const annotated = Object.entries(claims).map(([k, v]) =>
      `  ${k}: ${JSON.stringify(v)}${CLAIM_NOTES[k] ? `  — ${CLAIM_NOTES[k]}` : TOKEN_FIELDS.has(k) ? '  — (allowlisted optional claim; value checks simplified)' : '  — (unknown claim: server refuses)'}`,
    ).join('\n');

    out.textContent = `${lines.join('\n')}\nclaims:\n${annotated}\n\n` + (
      problems.length
        ? `✗ REJECTED — MAC valid, claims invalid:\n  · ${problems.join('\n  · ')}`
        : '✓ ACCEPTED BY THIS WIDGET — canonical HMAC and core v2 claims valid (optional-claim checks are simplified). Redeeming spends nonce n for its live one-time-token window.'
    );
  }

  async function tokenMint() {
    const out = document.getElementById('tokOut');
    const secret = document.getElementById('tokSecret')?.value ?? '';
    let claims;
    try {
      claims = JSON.parse(tokClaimsEl.value ?? '{}');
    } catch {
      if (out) out.textContent = 'Claims JSON does not parse — the server would never mint this either.';
      return;
    }
    const body = b64url(new TextEncoder().encode(JSON.stringify(claims)));
    const mac = await hmac(secret, body);
    currentToken = `${body}.${b64url(mac)}`;
    await tokenVerify(currentToken, 'minted just now');
  }

  const now = Date.now();
  tokClaimsEl.value = JSON.stringify({
    v: 2,
    kid: 'primary',
    aud: 'archx:image',
    scope: 'image:view',
    id: 'aurora-valley',
    w: 240,
    iat: now,
    exp: now + 120000,
    n: 'demoNonce123456',
    jkt: 'Abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG',
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
