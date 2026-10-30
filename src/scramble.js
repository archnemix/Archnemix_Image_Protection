/**
 * Archnemix Image Protection — shared scramble / container / crypto core.
 *
 * This module is isomorphic: the exact same code runs in the browser
 * (to un-scramble while painting) and in Node (to scramble on the server).
 * Keeping one implementation guarantees both sides agree on the permutation.
 *
 * Scramble scheme (v1)
 * --------------------
 * The (padded) image is cut into a `grid x grid` matrix of equal tiles.
 * A key-seeded PRNG produces:
 *   - `order[]`  : order[scrambledPos] = originalPos   (Fisher-Yates shuffle)
 *   - `flips[]`  : per scrambled-position { fx, fy } mirror flags
 * Mirrors are their own inverse, so un-scrambling applies the same flags.
 * 0/180-degree rotations are covered because fx+fy together == 180-degree rotation.
 * 90-degree rotations are intentionally not used: tiles are not square in
 * general, and a 90-degree turn would change a tile's aspect ratio.
 *
 * The scrambled payload is still a *valid* image file (WebP/PNG/JPEG) —
 * it just looks like a shuffled mosaic. Anyone who captures it from the
 * Network tab gets garbage unless they also obtain the key *and* re-implement
 * this exact un-shuffle. That stops bulk scrapers, download extensions and
 * casual DevTools theft cold. (A determined reverser who reads this file can
 * un-shuffle one image at web resolution — see docs/RESEARCH.md for why no
 * web-only scheme can do better than "very expensive to steal".)
 *
 * Implementation lives in src/core/ (one responsibility per module);
 * this barrel is the stable public surface — see docs/ARCHITECTURE.md.
 */
export {
  hashSeed, mulberry32, cyrb128, sfc32, sha256SeededPrng,
  sha256Bytes, hmacSha256Bytes, useSyncCrypto, useWebCrypto,
  generateKeyBase64, encryptPayload, decryptPayload,
} from './core/crypto.js';
export { bytesToBase64, base64ToBytes } from './core/bytes.js';
export {
  DEFAULT_GRID, buildScramblePlan, tileRect, paddedSize,
  scramblePixels, scramblePixelsPadded,
} from './core/plan.js';
export { sniffImageInfo, sniffImageFormat, decodeBmpImage } from './core/sniff.js';
export {
  ARCHX_MAGIC, MAX_ARCHX_HEADER_BYTES, validateArchxHeader,
  encodeContainer, isArchxContainer, useJsonParser, decodeContainer,
} from './core/container.js';
export { forensicBlockSigns, applyForensicBlocks, forensicScore } from './core/forensic.js';
export { stegoFingerprint, legacyStegoFingerprint } from './core/stego-code.js';
export { embedStegoFingerprint } from './core/stego-embed.js';
export { detectStegoFingerprint, assayStegoCollusion } from './core/stego-detect.js';
export { assayStegoEmbed } from './core/stego-assay.js';
export {
  perceptualFingerprint, normalizePerceptualFingerprint,
  perceptualFingerprintDistance, comparePerceptualFingerprints,
} from './core/perceptual.js';
