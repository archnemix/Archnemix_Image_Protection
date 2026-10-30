/**
 * Archx core primitives: tile scrambling, the `.archx` container, AES-GCM
 * payload encryption, forensic block marks, StegoMark fingerprints, and
 * perceptual fingerprints. Environment-agnostic (browser + Node).
 */

export const ARCHX_MAGIC: 'ARCHX1';
export const DEFAULT_GRID: 8;
export const MAX_ARCHX_HEADER_BYTES: 16384;

export type ArchxBytes = Uint8Array | ArrayBuffer | ArrayBufferView;

export function hashSeed(str: string, seed?: number): number;
export function mulberry32(seed: number): () => number;
export function cyrb128(str: string): [number, number, number, number];
export function sfc32(a: number, b: number, c: number, d: number): () => number;
/** PRNG seeded from SHA-256(key material): the v3 stego-layout/forensic-sign seed. */
export function sha256SeededPrng(material: string | Uint8Array): () => number;

export interface ScramblePlan {
  grid: number;
  count: number;
  /** Plan derivation version (1 = legacy 32-bit seed, 2 = 128-bit seed). */
  version: 1 | 2;
  /** order[scrambledPos] = originalPos */
  order: number[];
  /** inverse[originalPos] = scrambledPos */
  inverse: number[];
  flips: Array<{ fx: boolean; fy: boolean }>;
}

/**
 * Build the deterministic tile-scramble plan for a key.
 * `version` 2 derives the permutation from a 128-bit seed (cyrb128 + sfc32);
 * version 1 is kept for payload compatibility with deployed clients.
 */
export function buildScramblePlan(grid?: number, key?: string, version?: 1 | 2): ScramblePlan;

export function tileRect(index: number, grid: number, tw: number, th: number):
  { x: number; y: number; w: number; h: number };
export function paddedSize(w: number, h: number, grid: number):
  { tw: number; th: number; pw: number; ph: number };

export interface SniffedImageInfo {
  format: 'png' | 'jpeg' | 'webp' | 'avif' | 'gif' | 'bmp' | 'tiff' | 'svg';
  mime: string;
  width: number | null;
  height: number | null;
}
export function sniffImageInfo(bytes: ArchxBytes): SniffedImageInfo | null;
export function sniffImageFormat(bytes: ArchxBytes): SniffedImageInfo['format'] | null;
export function decodeBmpImage(bytes: ArchxBytes, options?: { maxPixels?: number }):
  { data: Uint8Array; width: number; height: number; channels: 4 };

export function bytesToBase64(bytes: ArchxBytes): string;
export function base64ToBytes(b64: string): Uint8Array;

export interface ArchxHeader {
  v: 1;
  /** Original (display) size. */
  w: number;
  h: number;
  /** Padded raster size (divisible by `grid`). */
  pw: number;
  ph: number;
  grid: number;
  mime: 'image/webp' | 'image/png' | 'image/jpeg' | 'image/avif';
  scrambled: boolean;
  encrypted: boolean;
  /** Scramble plan version; omitted (undefined) means 1. */
  pv?: 1 | 2;
  iv?: string;
  wm?: 1;
  fx?: 1;
  sg?: 1;
}

export function validateArchxHeader<T = ArchxHeader>(header: T): T;
export function encodeContainer(header: ArchxHeader, payload: Uint8Array): Uint8Array;
export function isArchxContainer(bytes: ArchxBytes): boolean;
export function decodeContainer(bytes: ArchxBytes): { header: ArchxHeader; payload: Uint8Array };
/** Supply the JSON parser used for container headers (the browser client passes its captured native). */
export function useJsonParser(fn: ((text: string) => unknown) | null): void;

/** Pure-JS SHA-256 (identical output to node:crypto). Anchor-independent of any page hooks. */
export function sha256Bytes(message: ArchxBytes): Uint8Array;
/** Pure-JS HMAC-SHA256 over byte inputs (keys longer than 64 bytes are hashed first, per RFC 2104). */
export function hmacSha256Bytes(key: ArchxBytes, message: ArchxBytes): Uint8Array;

/**
 * Captured WebCrypto primitives injected by the client runtime so the
 * shared core never calls page-visible `crypto.subtle.*` references that
 * a pre-loaded script may have replaced. Server/Node consumers do not
 * need this; pass `null` to clear.
 */
export interface InjectedWebCrypto {
  subtle: object;
  importKey?: ((...args: any[]) => Promise<any>) | null;
  encrypt?: ((...args: any[]) => Promise<any>) | null;
  decrypt?: ((...args: any[]) => Promise<any>) | null;
  digest?: ((...args: any[]) => Promise<any>) | null;
  getRandomValues?: ((array: Uint8Array) => Uint8Array) | null;
  cryptoObj?: object | null;
}
/** Inject exact synchronous SHA-256/HMAC-SHA256 (Node: node:crypto). Null restores built-ins. */
export function useSyncCrypto(impl: {
  sha256: (bytes: Uint8Array) => Uint8Array;
  hmacSha256: (key: Uint8Array, message: Uint8Array) => Uint8Array;
} | null): void;
export function useWebCrypto(injected: InjectedWebCrypto | null): void;

export function generateKeyBase64(): string;
export function encryptPayload(plainBytes: ArchxBytes, keyBase64: string):
  Promise<{ cipher: Uint8Array; iv: string }>;
export function decryptPayload(cipherBytes: ArchxBytes, keyBase64: string, ivBase64: string):
  Promise<Uint8Array>;

export function forensicBlockSigns(seed: string, count: number, signsVersion?: 1 | 2 | 3): Int8Array;
export function applyForensicBlocks(
  rgba: Uint8Array | Uint8ClampedArray, w: number, h: number, seed: string,
  options?: {
    blockSize?: number;
    delta?: number;
    /**
     * Sign-sequence derivation: 2 (default, 128-bit SHA-256 seed) or 1
     * (legacy 32-bit seed, for reproducing pre-v1.13 marks). Scoring
     * always dual-reads both vintages.
     */
    signsVersion?: 1 | 2 | 3;
  },
): Uint8Array;
export function forensicScore(
  candidate: Uint8Array | Uint8ClampedArray, reference: Uint8Array | Uint8ClampedArray,
  w: number, h: number, seed: string, options?: { blockSize?: number },
): { score: number; matched: number; total: number; signsVersion: 1 | 2 | 3 };

export function stegoFingerprint(value: string): string;
/** Pre-1.13 payload->fingerprint derivation, for identity lookups against older marks. */
export function legacyStegoFingerprint(value: string): string;

export interface StegoEmbedOptions {
  key?: string;
  strength?: number;
  gridX?: number;
  gridY?: number;
  profile?: 'standard' | 'robust';
  inPlace?: boolean;
  /**
   * Write a pre-v1.12 codeword whose acceptance tag is the linear keyed
   * CRC instead of the default keyed HMAC-16 (codeword v2). Only for
   * reproducing marks that old detectors must read: CRC-tagged hybrids
   * can survive multi-buyer collusion averaging, MAC-tagged ones cannot
   * validate under a foreign fingerprint.
   */
  legacyCode?: boolean;
  /**
   * Codeword layout: 3 (default, SHA-256-seeded repetition code),
   * 2/1 legacy seed spaces (for reproducing pre-v1.14 marks), or 4
   * (v1.20 BCH(188,64) error correction over the v3 layout —
   * needs a v1.20+ detector). Detectors read all vintages by default.
   */
  layoutVersion?: 1 | 2 | 3 | 4;
}
export function embedStegoFingerprint(
  rgba: Uint8Array | Uint8ClampedArray, w: number, h: number, payload: string,
  options?: StegoEmbedOptions,
): Uint8Array;

export interface StegoDetectOptions {
  key?: string;
  gridX?: number;
  gridY?: number;
  profile?: 'standard' | 'robust' | 'auto';
  searchOffsets?: boolean;
  searchGeometry?: boolean;
  /** Also probe a horizontally flipped copy of the suspect (default true, all profiles). */
  searchMirror?: boolean;
  /** Probe 90°/270°-rotated variants of the suspect (default true). */
  searchRotation?: boolean;
  /** Small-angle deskew search, ±6° (default false; forensic opt-in). */
  searchTilt?: boolean;
  /** Wall-clock budget for the whole search in ms (0 = unlimited).
   *  On expiry the best-so-far candidate returns with `timedOut`. */
  maxTimeMs?: number;
  /**
   * Restrict detection to one codeword layout (1/2 legacy seed
   * spaces, 3 = SHA-256-seeded, 4 = BCH). Default 'auto' tries
   * 3, 4, 2, 1; the result's `layoutVersion` reports the match.
   */
  layoutVersion?: 1 | 2 | 3 | 4 | 'auto';
}
export interface StegoDetection {
  found: boolean;
  fingerprint: string;
  profile: 'standard' | 'robust';
  /**
   * Which acceptance tag validated the decode: 'mac' (codeword v2,
   * keyed HMAC-16 — collusion hybrids cannot forge it), 'crc' (legacy
   * pre-v1.12 codeword — corroborate before attribution), or null when
   * no tag validated.
   */
  tagScheme: 'mac' | 'crc' | null;
  /** Codeword layout that matched (0 when no layout was concrete). */
  layoutVersion: 0 | 1 | 2 | 3 | 4;
  observedBits: number;
  minBitRepetitions: number;
  /** Acceptance tag validated (MAC-16 for codeword v2, keyed CRC for legacy). Name kept for compatibility; see `tagScheme`. */
  crcValid: boolean;
  corrections: number;
  /** Capped at 0.49 whenever `found` is false — never present a negative verdict as near-certain. */
  confidence: number;
  /** True when the mark was recovered from a horizontally flipped suspect (mirror probe, all profiles). */
  mirrored?: boolean;
  mirrorAxis?: 'x' | 'y' | 'xy';
  /** Degrees the suspect was rotated clockwise from the marked original. */
  rotated?: 90 | 270;
  /** Which diagonal reflection (EXIF 5/7) was undone, if any. */
  transposed?: 'main' | 'anti';
  /** Estimated clockwise tilt removed by the deskew search, in degrees. */
  deskewed?: number;
  /** True when maxTimeMs cut the search short; `found:false` is then
   *  "not found yet", not "not present". */
  timedOut?: boolean;
  /** True when unobserved (erased) code bits were recovered algebraically
   *  (robust: payload-erasure enumeration; standard: bounded assist). */
  erasureDecoded?: boolean;
  /** Code bits with zero surviving cell votes in the accepted geometry. */
  erasedBits?: number;
  agreement: number;
  meanSignal: number;
  cells: number;
  offset: { x: number; y: number };
  geometry: { scaleX: number; scaleY: number; originX: number; originY: number };
  grid: { x: number; y: number };
}
/** Measured pre-flight for a planned embed: real PSNR, content class, optional self-verified strength. */
export function assayStegoEmbed(
  rgba: Uint8Array, w: number, h: number,
  options?: { key?: string; profile?: 'standard' | 'robust'; strength?: number; gridX?: number; gridY?: number; verify?: boolean; layoutVersion?: 1 | 2 | 3 | 4 },
): Readonly<{
  profile: string; strength: number; layoutVersion: number; grid: { x: number; y: number };
  psnr: number; maxChannelDelta: number;
  smoothFraction: number; binaryFraction: number;
  contentClass: 'binary-graphic' | 'flat-minimal' | 'photo-textured';
  verifiedAtStrength: number | null; recommendedStrength: number;
  warnings: string[];
}>;
export function detectStegoFingerprint(
  rgba: Uint8Array | Uint8ClampedArray, w: number, h: number, options?: StegoDetectOptions,
): StegoDetection;

export interface StegoCollusionCandidate {
  id?: string | null;
  payload: string;
  /** Per-candidate embed key when marks were embedded viewer-scoped. */
  key?: string;
}
export interface StegoCollusionScore {
  id: string | null;
  fingerprint: string;
  /** Mean soft agreement (signed amplitude units) over discriminative bits. */
  score: number;
  /** Comparative z-score within the candidate set; ranking aid, never proof. */
  zScore: number;
  cellAgreement: number;
  cells: number;
  bits: number;
}
export interface StegoCollusionAssay {
  results: StegoCollusionScore[];
  cells: number;
  geometry: { scaleX: number; scaleY: number; originX: number; originY: number };
  profile: 'robust' | 'standard';
}
/**
 * Rank candidate recipients by soft-evidence support in a suspect
 * image (collusion-averaging investigations). Investigative aid
 * only — not a Tardos accusation code and never proof on its own.
 */
export function assayStegoCollusion(
  rgba: Uint8Array | Uint8ClampedArray, w: number, h: number,
  candidates: StegoCollusionCandidate[],
  options?: {
    key?: string; profile?: 'standard' | 'robust';
    gridX?: number; gridY?: number; layoutVersion?: 1 | 2 | 3 | 4;
    geometry?: { scaleX?: number; scaleY?: number; originX?: number; originY?: number } | null;
  },
): StegoCollusionAssay;

export function scramblePixels(
  rgba: Uint8Array | Uint8ClampedArray, pw: number, ph: number, plan: ScramblePlan,
  direction?: 'scramble' | 'unscramble',
): Uint8Array;
export function scramblePixelsPadded(
  rgba: Uint8Array | Uint8ClampedArray, w: number, h: number, plan: ScramblePlan,
  out?: Uint8Array | null,
): Uint8Array;

export function perceptualFingerprint(rgba: Uint8Array | Uint8ClampedArray, w: number, h: number): string;
export function normalizePerceptualFingerprint(value: unknown): string | null;
export function perceptualFingerprintDistance(a: string, b: string): number;
export function comparePerceptualFingerprints(
  a: string, b: string, options?: { maxDistance?: number },
): { distance: number; similarity: number; match: boolean };
