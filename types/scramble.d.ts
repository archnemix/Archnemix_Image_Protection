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

export function generateKeyBase64(): string;
export function encryptPayload(plainBytes: ArchxBytes, keyBase64: string):
  Promise<{ cipher: Uint8Array; iv: string }>;
export function decryptPayload(cipherBytes: ArchxBytes, keyBase64: string, ivBase64: string):
  Promise<Uint8Array>;

export function forensicBlockSigns(seed: string, count: number): Int8Array;
export function applyForensicBlocks(
  rgba: Uint8Array | Uint8ClampedArray, w: number, h: number, seed: string,
  options?: { blockSize?: number; delta?: number },
): Uint8Array;
export function forensicScore(
  candidate: Uint8Array | Uint8ClampedArray, reference: Uint8Array | Uint8ClampedArray,
  w: number, h: number, seed: string, options?: { blockSize?: number },
): { score: number; matched: number; total: number };

export function stegoFingerprint(value: string): string;

export interface StegoEmbedOptions {
  key?: string;
  strength?: number;
  gridX?: number;
  gridY?: number;
  profile?: 'standard' | 'robust';
  inPlace?: boolean;
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
}
export interface StegoDetection {
  found: boolean;
  fingerprint: string;
  profile: 'standard' | 'robust';
  observedBits: number;
  minBitRepetitions: number;
  crcValid: boolean;
  corrections: number;
  confidence: number;
  agreement: number;
  meanSignal: number;
  cells: number;
  offset: { x: number; y: number };
  geometry: { scaleX: number; scaleY: number; originX: number; originY: number };
  grid: { x: number; y: number };
}
export function detectStegoFingerprint(
  rgba: Uint8Array | Uint8ClampedArray, w: number, h: number, options?: StegoDetectOptions,
): StegoDetection;

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
