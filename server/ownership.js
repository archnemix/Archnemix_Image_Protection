/**
 * Signed ownership claims for delivered derivatives (v1.18).
 *
 * Three evidence layers, weakest to strongest:
 *  1. DECLARATIVE METADATA — an Ed25519-signed claim token
 *     (`ARCHX1.<payload>.<sig>`) written into EXIF/XMP alongside
 *     human-readable Copyright/Artist. Instantly checkable by
 *     anyone with the owner's PUBLIC key, but metadata is trivially
 *     stripped by re-encoding — its absence proves nothing.
 *  2. PERCEPTUAL SOFT BINDING — the claim carries the derivative's
 *     perceptual fingerprint, so a leaked, metadata-stripped copy
 *     can be re-scanned and matched back to the signed claim by
 *     content similarity (the C2PA "soft binding" idea; this is NOT
 *     a C2PA implementation and makes no conformance claim).
 *  3. STEGOMARK — the claim also carries the (non-secret) stego
 *     fingerprint hex; the keyed in-pixel mark survives screenshots
 *     and re-encodes within its documented envelope, and its
 *     detection under the private key is the strongest layer.
 *
 * `verifyOwnership()` combines the layers into one evidence report;
 * no single layer — and no combination — is cryptographic proof of
 * legal ownership on its own. Treat the report as investigative
 * evidence tied to your issuance registry.
 */
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import {
  perceptualFingerprint, perceptualFingerprintDistance, detectStegoFingerprint,
} from '../src/scramble.js';

const require_ = createRequire(import.meta.url);
let sharpSingleton = null;
function getSharp() {
  if (!sharpSingleton) sharpSingleton = require_('sharp');
  return sharpSingleton;
}

const CLAIM_PREFIX = 'ARCHX1.';
const CLAIM_RE = /ARCHX1\.([A-Za-z0-9_-]{10,2000})\.([A-Za-z0-9_-]{40,120})/;

export function generateOwnershipKeyPair() {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  return Object.freeze({
    privateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKey: publicKey.export({ type: 'spki', format: 'pem' }),
  });
}

function assertEd25519(keyObject, kind) {
  if (keyObject.asymmetricKeyType !== 'ed25519') {
    throw new TypeError(`Archx ownership: ${kind} key must be Ed25519`);
  }
}

export function loadOwnershipPrivateKey(pem) {
  const key = crypto.createPrivateKey(String(pem));
  assertEd25519(key, 'private');
  return key;
}

export function loadOwnershipPublicKey(pem) {
  const key = crypto.createPublicKey(String(pem));
  assertEd25519(key, 'public');
  return key;
}

export function ownershipPublicKeyFingerprint(publicKey) {
  const key = typeof publicKey === 'string' ? loadOwnershipPublicKey(publicKey) : publicKey;
  const der = key.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex').slice(0, 32);
}

const b64url = (buf) => Buffer.from(buf).toString('base64url');

/**
 * Sign an ownership claim. Claims are DERIVATIVE-scoped and carry no
 * timestamp on purpose: identical derivative => identical token, so
 * finished-derivative caching stays sound. Issuance time belongs in
 * the operator's registry, next to this token.
 */
export function signOwnershipClaim({ owner, imageId, perceptualHash, stegoFingerprint }, privateKey) {
  if (typeof owner !== 'string' || !owner || owner.length > 128) {
    throw new TypeError('Archx ownership: owner must be a non-empty string of at most 128 chars');
  }
  const key = typeof privateKey === 'string' ? loadOwnershipPrivateKey(privateKey) : privateKey;
  assertEd25519(key, 'private');
  const payload = {
    v: 1,
    own: owner,
    img: String(imageId ?? '').slice(0, 128),
    ph: perceptualHash ? String(perceptualHash).slice(0, 64) : null,
    sfp: stegoFingerprint ? String(stegoFingerprint).slice(0, 32) : null,
  };
  const segment = b64url(Buffer.from(JSON.stringify(payload), 'utf8'));
  const signature = crypto.sign(null, Buffer.from(segment, 'ascii'), key);
  return `${CLAIM_PREFIX}${segment}.${b64url(signature)}`;
}

export function parseOwnershipClaim(token) {
  const match = CLAIM_RE.exec(String(token || ''));
  if (!match) return null;
  try {
    const payload = JSON.parse(Buffer.from(match[1], 'base64url').toString('utf8'));
    if (!payload || payload.v !== 1 || typeof payload.own !== 'string') return null;
    return { payload, segment: match[1], signature: Buffer.from(match[2], 'base64url') };
  } catch { return null; }
}

export function verifyOwnershipClaim(token, publicKey) {
  const parsed = parseOwnershipClaim(token);
  if (!parsed) return { valid: false, claim: null, reason: 'unparseable-claim' };
  const key = typeof publicKey === 'string' ? loadOwnershipPublicKey(publicKey) : publicKey;
  assertEd25519(key, 'public');
  const valid = crypto.verify(null, Buffer.from(parsed.segment, 'ascii'), key, parsed.signature);
  return { valid, claim: parsed.payload, reason: valid ? null : 'signature-mismatch' };
}

/** Scan encoded image bytes for an embedded claim token (EXIF/XMP store it as ASCII). */
export function extractOwnershipClaim(imageBytes) {
  if (!imageBytes || typeof imageBytes.length !== 'number') return null;
  const text = Buffer.from(imageBytes).toString('latin1');
  const match = CLAIM_RE.exec(text);
  return match ? match[0] : null;
}

function xmpPacket({ owner, copyright, token }) {
  const esc = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const rights = esc(copyright || `© ${owner}`);
  return [
    '<x:xmpmeta xmlns:x="adobe:ns:meta/">',
    '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">',
    '<rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:xmp="http://ns.adobe.com/xap/1.0/">',
    `<dc:rights><rdf:Alt><rdf:li xml:lang="x-default">${rights}</rdf:li></rdf:Alt></dc:rights>`,
    `<dc:creator><rdf:Seq><rdf:li>${esc(owner)}</rdf:li></rdf:Seq></dc:creator>`,
    token ? `<dc:description><rdf:Alt><rdf:li xml:lang="x-default">${esc(token)}</rdf:li></rdf:Alt></dc:description>` : '',
    '</rdf:Description></rdf:RDF></x:xmpmeta>',
  ].join('');
}

/** Apply ownership metadata to a Sharp pipeline (before toBuffer). */
export function applyOwnershipMetadata(pipeline, { owner, copyright, artist, token } = {}) {
  const rights = copyright || (owner ? `© ${owner}` : null);
  const exif = { IFD0: {} };
  if (rights) exif.IFD0.Copyright = String(rights).slice(0, 256);
  if (artist || owner) exif.IFD0.Artist = String(artist || owner).slice(0, 128);
  if (token) exif.IFD0.ImageDescription = String(token);
  let out = pipeline.withExif(exif);
  if (typeof out.withXmp === 'function' && (rights || token)) {
    out = out.withXmp(xmpPacket({ owner: owner || artist || '', copyright: rights, token }));
  }
  return out;
}

/** Embed ownership metadata into already-encoded image bytes. */
export async function embedOwnershipMetadata(imageBytes, metadata) {
  return applyOwnershipMetadata(getSharp()(imageBytes), metadata).toBuffer();
}

/**
 * Full rescan verification of a suspect image (encoded bytes):
 * metadata claim -> signature -> perceptual soft binding -> stego.
 * `publicKey` verifies the claim; `stegoKey` (optional) enables the
 * in-pixel layer. Returns a JSON-safe evidence report.
 */
export async function verifyOwnership(imageBytes, {
  publicKey,
  stegoKey,
  claim: externalClaim = null,
  maxPhDistance = 10,
  detectOptions = {},
} = {}) {
  const sharp = getSharp();
  const bytes = Buffer.isBuffer(imageBytes) ? imageBytes : Buffer.from(imageBytes);
  const { data, info } = await sharp(bytes, { failOn: 'warning', limitInputPixels: 100_000_000 })
    .rotate().ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const rgba = new Uint8Array(data);

  const token = externalClaim || extractOwnershipClaim(bytes);
  const report = {
    claimFound: !!token,
    claimSource: externalClaim ? 'external' : (token ? 'metadata' : null),
    signatureValid: false,
    owner: null,
    imageId: null,
    perceptual: { hash: null, distanceToClaim: null, matchesClaim: false },
    stego: null,
    verdict: 'no-evidence',
  };

  const ph = perceptualFingerprint(rgba, info.width, info.height);
  report.perceptual.hash = ph;

  let claimPayload = null;
  if (token && publicKey) {
    const checked = verifyOwnershipClaim(token, publicKey);
    report.signatureValid = checked.valid;
    claimPayload = checked.claim;
  } else if (token) {
    claimPayload = parseOwnershipClaim(token)?.payload ?? null;
  }
  if (claimPayload) {
    report.owner = claimPayload.own;
    report.imageId = claimPayload.img || null;
    if (claimPayload.ph) {
      const distance = perceptualFingerprintDistance(ph, claimPayload.ph);
      report.perceptual.distanceToClaim = distance;
      report.perceptual.matchesClaim = distance !== null && distance <= maxPhDistance;
    }
  }

  if (stegoKey !== undefined && stegoKey !== null) {
    const hit = detectStegoFingerprint(rgba, info.width, info.height, {
      key: stegoKey, profile: 'auto', searchGeometry: true, ...detectOptions,
    });
    report.stego = {
      found: hit.found,
      fingerprint: hit.found ? hit.fingerprint : null,
      matchesClaim: !!(hit.found && claimPayload?.sfp && hit.fingerprint === claimPayload.sfp),
      erasureDecoded: !!hit.erasureDecoded,
      corrections: hit.corrections ?? 0,
      timedOut: !!hit.timedOut,
    };
  }

  if (report.signatureValid && (report.perceptual.matchesClaim || report.stego?.matchesClaim)) {
    report.verdict = 'verified'; // signed claim + content layer agree
  } else if (report.signatureValid) {
    report.verdict = 'claim-only'; // authentic claim, content layers inconclusive
  } else if (report.stego?.found || (claimPayload && report.perceptual.matchesClaim)) {
    report.verdict = 'content-match'; // pixels match, claim signature unverified/absent
  }
  return report;
}
