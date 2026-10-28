/**
 * Worker-thread host for StegoMark forensic detection.
 *
 * A full auto/geometry search over an UNMARKED image is seconds of
 * synchronous CPU (thousands of layout/scale/origin hypotheses). That
 * is fine offline and fatal on an HTTP server's event loop, so the
 * supported way to run detection inside a server process is through
 * this worker (`detectStegoFingerprintInWorker()` in
 * scramble-image.js) or a job queue — never inline per request.
 */
import { parentPort } from 'node:worker_threads';
import { detectStegoFingerprint } from '../src/scramble.js';

parentPort.on('message', (msg) => {
  const { id, rgba, w, h, options } = msg || {};
  try {
    const bytes = rgba instanceof Uint8Array ? rgba : new Uint8Array(rgba);
    const result = detectStegoFingerprint(bytes, w, h, options || {});
    parentPort.postMessage({ id, ok: true, result });
  } catch (err) {
    parentPort.postMessage({ id, ok: false, error: String((err && err.message) || err) });
  }
});
