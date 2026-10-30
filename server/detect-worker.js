/**
 * Worker-thread host for StegoMark forensic detection.
 *
 * A full auto/geometry search over an UNMARKED image is seconds of
 * synchronous CPU (thousands of layout/scale/origin hypotheses). That
 * is fine offline and fatal on an HTTP server's event loop, so the
 * supported way to run detection inside a server process is through
 * this worker (`detectStegoFingerprintInWorker()` /
 * `batchDetectStegoInWorker()` in scramble-image.js) or a job queue —
 * never inline per request.
 *
 * Batch jobs screen many keys against one suspect: planes (luma +
 * summed-area table) are built once per buffer and shared across
 * keys via the detector's internal plane cache, each key first gets
 * a cheap native screen, and only keys with signal escalate to the
 * full search the caller asked for.
 */
import { parentPort } from 'node:worker_threads';
import './node-crypto.js'; // hardware SHA/HMAC for the shared stego core
import { detectStegoFingerprint } from '../src/scramble.js';

parentPort.on('message', (msg) => {
  const { id, kind, rgba, w, h, options } = msg || {};
  try {
    const bytes = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
    if (kind === 'batch') {
      const planes = new Map();
      const keys = msg.keys || [];
      // Phase 1: native screen per key (shared planes). Mark ENERGY
      // is key-independent, so absolute signal thresholds cannot
      // prune wrong keys — but vote consistency (agreement) ranks
      // them: under the right key, cells sharing a codeword bit
      // vote together; under wrong keys the polarity correction is
      // random and consistency collapses toward chance.
      const screened = keys.map((key) => ({
        key,
        escalated: false,
        result: detectStegoFingerprint(bytes, w, h, {
          ...(options || {}), key,
          searchOffsets: false, searchGeometry: false,
          searchMirror: false, searchRotation: false, searchTilt: false,
          _planes: planes,
        }),
      }));
      // Phase 2: escalate only the top-ranked unfound keys to the
      // full caller-requested search (bounded: escalateTop, default
      // 2), so a 512-key sweep costs ~512 screens + 2 full searches
      // instead of 512 full searches. Screening assumes a roughly
      // registered suspect; heavily transformed suspects should be
      // detected per key.
      const escalateTop = Number.isSafeInteger(msg.escalateTop) && msg.escalateTop >= 0
        ? Math.min(msg.escalateTop, 32) : 2;
      const rank = (r) => (r.result?.agreement ?? 0) * Math.min(8, r.result?.meanSignal ?? 0);
      const candidates = screened
        .filter((r) => !r.result?.found)
        .sort((a, b) => rank(b) - rank(a))
        .slice(0, escalateTop);
      for (const entry of candidates) {
        entry.result = detectStegoFingerprint(bytes, w, h, {
          ...(options || {}), key: entry.key, _planes: planes,
        });
        entry.escalated = true;
      }
      parentPort.postMessage({ id, ok: true, result: screened });
      return;
    }
    const result = detectStegoFingerprint(bytes, w, h, options || {});
    parentPort.postMessage({ id, ok: true, result });
  } catch (err) {
    parentPort.postMessage({ id, ok: false, error: String((err && err.message) || err) });
  }
});
