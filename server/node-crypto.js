/**
 * Server-side synchronous crypto acceleration for src/scramble.js.
 *
 * The shared scramble/stego core ships portable pure-JS SHA-256/HMAC
 * (it must run identically in browsers), but on Node the detector's
 * bit-repair loop alone verifies up to ~20k HMACs per probe. Every
 * server entry point imports this module once so hardware-backed
 * node:crypto serves those primitives instead (~3x on the repair
 * shape, byte-identical outputs — verified by the FIPS/RFC
 * known-answer tests running against the injected path).
 */
import crypto from 'node:crypto';
import { useSyncCrypto } from '../src/scramble.js';

useSyncCrypto(Object.freeze({
  sha256: (bytes) => crypto.createHash('sha256').update(bytes).digest(),
  hmacSha256: (key, message) => crypto.createHmac('sha256', key).update(message).digest(),
}));
