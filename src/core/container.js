/**
 * The .archx container: magic + bounded JSON header + payload bytes,
 * with strict header validation. The wire content-type is
 * application/octet-stream — DevTools does not classify it as an image.
 */
import { asBytes, utf8Encode, utf8DecodeFatal, base64ToBytes } from './bytes.js';
import { paddedSize } from './plan.js';

export const ARCHX_MAGIC = 'ARCHX1';

/**
 * Layout:  "ARCHX1" | uint32BE headerLen | header JSON (utf8) | payload
 * Header:  { v, w, h, pw, ph, grid, mime, scrambled, encrypted, iv? }
 * Payload: image file bytes (scrambled pixels), optionally AES-GCM encrypted.
 * The content-type on the wire is application/octet-stream — DevTools does
 * not classify it as an image at all.
 */
export const MAX_ARCHX_HEADER_BYTES = 16384;
const ARCHX_MAGIC_BYTES = Object.freeze([...ARCHX_MAGIC].map((c) => c.charCodeAt(0)));
const ARCHX_HEADER_FIELDS = new Set([
  'v', 'w', 'h', 'pw', 'ph', 'grid', 'mime', 'scrambled', 'encrypted', 'iv', 'wm', 'fx', 'sg', 'pv',
]);
const ARCHX_MIME_FORMATS = Object.freeze({
  'image/webp': 'webp', 'image/png': 'png', 'image/jpeg': 'jpeg', 'image/avif': 'avif',
});

/** Validate the version-1 .archx header before any payload bytes are decoded. */
export function validateArchxHeader(header) {
  const fail = (message) => { throw new Error(`Archx: invalid .archx header (${message})`); };
  if (!header || typeof header !== 'object' || Array.isArray(header)) fail('not an object');
  for (const field of Object.keys(header)) if (!ARCHX_HEADER_FIELDS.has(field)) fail(`unknown field ${field}`);
  if (header.v !== 1) fail('unsupported version');
  for (const field of ['w', 'h', 'pw', 'ph']) {
    if (!Number.isSafeInteger(header[field]) || header[field] < 1 || header[field] > 65536) fail(`bad ${field}`);
  }
  if (!Number.isInteger(header.grid) || header.grid < 2 || header.grid > 32) fail('bad grid');
  if (header.pv !== undefined && header.pv !== 1 && header.pv !== 2) fail('bad plan version');
  const padded = paddedSize(header.w, header.h, header.grid);
  if (header.pw !== padded.pw || header.ph !== padded.ph) fail('padded dimensions do not match');
  if (!ARCHX_MIME_FORMATS[header.mime]) fail('unsupported MIME type');
  if (typeof header.scrambled !== 'boolean' || typeof header.encrypted !== 'boolean') fail('bad flags');
  for (const field of ['wm', 'fx', 'sg']) {
    if (header[field] !== undefined && header[field] !== 0 && header[field] !== 1 && header[field] !== true && header[field] !== false) {
      fail(`bad ${field} flag`);
    }
  }
  if (header.encrypted) {
    if (typeof header.iv !== 'string') fail('missing IV');
    try { if (base64ToBytes(header.iv).length !== 12) fail('bad IV length'); }
    catch (err) { if (/invalid \.archx header/.test(err.message)) throw err; fail('bad IV encoding'); }
  } else if (header.iv !== undefined) fail('unexpected IV');
  return header;
}

export function encodeContainer(header, payload) {
  validateArchxHeader(header);
  const headerBytes = utf8Encode(JSON.stringify(header));
  if (headerBytes.length > MAX_ARCHX_HEADER_BYTES) throw new Error('Archx: .archx header is too large');
  const body = asBytes(payload);
  if (!body.length) throw new Error('Archx: .archx payload is empty');
  const out = new Uint8Array(6 + 4 + headerBytes.length + body.length);
  out.set(ARCHX_MAGIC_BYTES, 0);
  new DataView(out.buffer, out.byteOffset, out.byteLength).setUint32(6, headerBytes.length, false);
  out.set(headerBytes, 10);
  out.set(body, 10 + headerBytes.length);
  return out;
}

export function isArchxContainer(bytes) {
  if (!bytes) return false;
  const u8 = asBytes(bytes);
  return u8.length >= 10 && ARCHX_MAGIC_BYTES.every((c, i) => u8[i] === c);
}

let coreJsonParse = null;
/**
 * Supply the JSON parser used for container headers (which carry the
 * per-response AES key for encrypted containers). The browser client passes
 * its load-time-captured native JSON.parse so a JSON.parse hook installed
 * later cannot skim keys; Node/library use can leave the default. Passing a
 * non-function resets to the ambient JSON.parse.
 */
export function useJsonParser(fn) {
  coreJsonParse = typeof fn === 'function' ? fn : null;
}

export function decodeContainer(bytes) {
  const u8 = asBytes(bytes);
  if (!isArchxContainer(u8)) throw new Error('Archx: not an .archx container');
  const headerLen = new DataView(u8.buffer, u8.byteOffset, u8.byteLength).getUint32(6, false);
  if (!Number.isSafeInteger(headerLen) || headerLen < 2 || headerLen > MAX_ARCHX_HEADER_BYTES ||
      10 + headerLen >= u8.length) {
    throw new Error('Archx: invalid .archx header length');
  }
  let header;
  try {
    header = (coreJsonParse || JSON.parse)(utf8DecodeFatal(u8.subarray(10, 10 + headerLen)));
  } catch { throw new Error('Archx: invalid .archx header encoding'); }
  validateArchxHeader(header);
  const payload = u8.subarray(10 + headerLen);
  if (!payload.length) throw new Error('Archx: invalid .archx payload');
  return { header, payload };
}

