/**
 * Byte/codec primitives shared by every core module. The captured
 * TextEncoder/TextDecoder methods are called with explicit receivers
 * so prototype hooks installed after load cannot skim container
 * headers or token JSON in the browser bundle.
 */


export function asBytes(bytes) {
  if (bytes instanceof Uint8Array) return bytes;
  if (bytes instanceof ArrayBuffer) return new Uint8Array(bytes);
  if (ArrayBuffer.isView(bytes)) return new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return new Uint8Array(bytes || []);
}

// Shared codec instances: constructing these per call is measurable churn
// on the per-image path (sniff + container decode) and entirely avoidable.
const utf8Encoder = new TextEncoder();
const utf8Fatal = new TextDecoder('utf-8', { fatal: true });
export const utf8Lenient = new TextDecoder('utf-8', { fatal: false });
// Methods captured at module evaluation and called with explicit receivers,
// so a TextDecoder/TextEncoder prototype hook installed after this module
// loads cannot skim container headers or token JSON in the browser bundle.
const textDecodeCall = TextDecoder.prototype.decode;
const textEncodeCall = TextEncoder.prototype.encode;
export function utf8Encode(str) { return textEncodeCall.call(utf8Encoder, str); }
export function utf8DecodeFatal(bytes) { return textDecodeCall.call(utf8Fatal, bytes); }


/* ------------------------------------------------------------------ */
/* Base64 helpers (browser + Node)                                      */
/* ------------------------------------------------------------------ */

export function bytesToBase64(bytes) {
  const u8 = asBytes(bytes);
  if (typeof Buffer !== 'undefined') return Buffer.from(u8.buffer, u8.byteOffset, u8.byteLength).toString('base64');
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < u8.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, u8.subarray(i, i + CHUNK));
  }
  return btoa(bin);
}

export function base64ToBytes(b64) {
  if (typeof b64 !== 'string') throw new TypeError('Archx: base64 value must be a string');
  let normalized = b64.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  const padding = normalized.endsWith('==') ? 2 : normalized.endsWith('=') ? 1 : 0;
  if (normalized.includes('=') && normalized.indexOf('=') !== normalized.length - padding) {
    throw new Error('Archx: invalid base64 value');
  }
  if (normalized.length % 4 === 1 || !/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
    throw new Error('Archx: invalid base64 value');
  }
  if (normalized.length % 4) normalized += '='.repeat(4 - (normalized.length % 4));
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(normalized, 'base64'));
  const bin = atob(normalized);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/* ------------------------------------------------------------------ */
/* .archx container format                                              */
/* ------------------------------------------------------------------ */
