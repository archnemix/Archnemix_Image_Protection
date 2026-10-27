/**
 * Archx browser client: render-only protected image viewing.
 *
 * `Archx.load.image(el, source, options)` mounts a protected viewer with no
 * saveable image URL, scrambled/encrypted delivery where configured, and
 * readback resistance. See README.md for the security model and honest limits.
 */
import type { ArchxHeader } from './scramble.js';

export * from './scramble.js';

export const VERSION: string;
export const DEFAULT_SOURCE_WIDTH_BUCKETS: readonly number[];

export type ArchxMode =
  | 'shield' | 'vault' | 'fortress' | 'lens' | 'trace' | 'catalog' | 'custom';

export type ArchxSource =
  | string
  | Blob
  | ArrayBuffer
  | Uint8Array
  | HTMLCanvasElement
  | ImageBitmap
  | { imageId: string }
  | { assetId: string }
  | { src: string };

export interface ArchxTemporalInterlace {
  targetHz?: number;
  engine?: 'shader' | 'frames' | 'auto';
  layout?: 'pixels' | 'strips' | 'blocks' | 'checker';
  phases?: 2 | 3 | 4;
  cellSize?: number;
  fill?: 'black' | 'dim' | 'color' | string;
  [key: string]: unknown;
}

export interface ArchxClientEvent {
  type: string;
  reason?: string;
  count?: number;
  [key: string]: unknown;
}

export interface ArchxLoadOptions {
  mode?: ArchxMode;
  renderer?: 'auto' | 'webgl' | 'canvas2d';
  preset?: string;
  fit?: 'cover' | 'contain' | 'fill' | 'none';
  lazy?: boolean;
  rootMargin?: string;
  unloadOnExit?: boolean;
  shadow?: boolean | 'open' | 'closed';
  grid?: number;
  scrambled?: boolean;
  /** Scramble plan derivation for container-less sources; `.archx` headers win. */
  planVersion?: 1 | 2;
  key?: string;
  aesKey?: string;
  tokenEndpoint?: string;
  tokenMethod?: 'POST' | 'GET';
  tokenTransport?: 'header' | 'query' | 'header+proof';
  tokenBatch?: boolean;
  tokenBatchEndpoint?: string;
  tokenBatchSize?: number;
  tokenBatchDelayMs?: number;
  tokenBatchMaxDelayMs?: number;
  assetManifest?: string | Record<string, unknown>;
  assetManifestMaxBytes?: number;
  assetHttpCache?: 'immutable' | 'no-store';
  assetIntegrity?: string;
  assetManifestIntegrity?: string;
  httpCache?: string;
  fetchPriority?: 'high' | 'low' | 'auto';
  proofOfPossession?: 'auto' | 'required' | 'off';
  allowedTokenOrigins?: string[] | ((url: URL) => boolean);
  fetchTimeoutMs?: number;
  maxResponseBytes?: number;
  maxDecodedPixels?: number;
  maxDecodedDimension?: number;
  onExtract?: 'blank' | 'decoy' | 'none';
  /** Origin-taint 2D display canvases so prototype-call readbacks throw. */
  taintReadback?: 'auto' | 'off';
  /** Taint pixel URL override (default: same-origin `{basePath}/taint.png`). */
  taintUrl?: string;
  splitCanvases?: boolean;
  splitGrid?: number;
  maxBackingWidth?: number;
  dprCap?: number;
  sourceOversample?: number;
  maxSourceWidth?: number;
  sourceWidthBuckets?: number[];
  qualityProfile?: 'quality' | 'balanced' | 'throughput';
  requestQuality?: number | 'lossless';
  networkAware?: boolean;
  cacheBitmap?: boolean;
  bitmapCacheMaxEntries?: number;
  bitmapCacheMaxBytes?: number;
  cachePayload?: boolean;
  cacheScope?: 'session' | 'origin';
  reloadOnResize?: 'never' | 'upscale' | 'always';
  resizeUpscaleFactor?: number;
  renderLoop?: boolean | 'auto';
  temporalShield?: boolean | Record<string, unknown>;
  temporalInterlace?: boolean | ArchxTemporalInterlace;
  cameraShield?: boolean | Record<string, unknown>;
  watermark?: string | Record<string, unknown> | null;
  forensic?: boolean | Record<string, unknown>;
  sessionId?: string;
  brand?: boolean;
  retries?: number;
  credentials?: RequestCredentials;
  integrity?: string;
  automation?: 'allow' | 'degrade' | 'block';
  memory?: Record<string, unknown>;
  localScramble?: boolean;
  lens?: boolean | Record<string, unknown>;
  captureShield?: boolean | Record<string, unknown>;
  strikes?: number;
  debug?: boolean;
  guards?: Record<string, boolean>;
  onAttempt?: (event: ArchxClientEvent) => void;
  onLoad?: (info: Record<string, unknown>) => void;
  onError?: (error: Error) => void;
  onClick?: (event: Event) => void;
  onEvent?: (event: ArchxClientEvent) => void;
  alt?: string;
  [key: string]: unknown;
}

export class ProtectedImage {
  constructor(target: Element | string, source?: ArchxSource, options?: ArchxLoadOptions);
  readonly ready: Promise<ProtectedImage>;
  readonly element: Element;
  reload(source?: ArchxSource): Promise<void>;
  destroy(): void;
}

export interface ArchxPreset {
  [key: string]: unknown;
}
export const PRESETS: Readonly<Record<string, ArchxPreset>>;
export function preset(name?: string, overrides?: ArchxLoadOptions): ArchxLoadOptions;

export interface TemporalInterlaceProfile {
  engine: 'shader' | 'frames';
  layout: 'pixels' | 'strips' | 'blocks' | 'checker';
  phases: number;
  cellSize: number;
  targetHz: number;
  [key: string]: unknown;
}
export const TEMPORAL_INTERLACE_PROFILES: Readonly<Record<string, TemporalInterlaceProfile>>;
export function normalizeTemporalInterlace(
  raw: boolean | string | ArchxTemporalInterlace | undefined,
): TemporalInterlaceProfile | null;

export function auditIntegrity(): string[];
export function auditIntegrityDetails(): Array<{ api: string; ok: boolean; detail?: string }>;
export function captureEarlyIntegritySnapshot(): unknown;
export function verifyEarlyIntegritySnapshot(snapshot: unknown): string[];
export function detectAutomation(): string[];

export function onClientEvent(listener: (event: ArchxClientEvent) => void): () => void;
export function offClientEvent(listener: (event: ArchxClientEvent) => void): void;

export interface ArchxPlugin {
  name: string;
  install?: (archx: typeof Archx) => void;
  [key: string]: unknown;
}
export function usePlugin(plugin: ArchxPlugin): void;
export function listPlugins(): string[];

export function preloadAssets(
  assetIds: string[],
  options?: ArchxLoadOptions,
): Promise<{ preloaded: string[]; failed: Array<{ id: string; error: string }> }>;

export interface ArchxStatic {
  version: string;
  ProtectedImage: typeof ProtectedImage;
  presets: typeof PRESETS;
  preset: typeof preset;
  sourceWidthBuckets: readonly number[];
  temporalInterlaceProfiles: typeof TEMPORAL_INTERLACE_PROFILES;
  normalizeTemporalInterlace: typeof normalizeTemporalInterlace;
  /** Set global defaults; returns the sanitized view (never echoes secrets). */
  config(partial?: ArchxLoadOptions): Record<string, unknown>;
  load: {
    image(target: Element | string, source?: ArchxSource, options?: ArchxLoadOptions): ProtectedImage;
    gallery(
      container: Element | string,
      items: Array<ArchxSource | { source: ArchxSource; options?: ArchxLoadOptions }>,
      options?: ArchxLoadOptions,
    ): ProtectedImage[];
  };
  image(target: Element | string, source?: ArchxSource, options?: ArchxLoadOptions): ProtectedImage;
  gallery(
    container: Element | string,
    items: Array<ArchxSource | { source: ArchxSource; options?: ArchxLoadOptions }>,
    options?: ArchxLoadOptions,
  ): ProtectedImage[];
  protectAll(selectorOrNodes?: string | Iterable<Element>, options?: ArchxLoadOptions): ProtectedImage[];
  preloadAssets: typeof preloadAssets;
  defineElement(name?: string): void;
  readonly instanceCount: number;
  clearCaches(): void;
  auditIntegrity: typeof auditIntegrity;
  auditIntegrityDetails: typeof auditIntegrityDetails;
  captureEarlyIntegritySnapshot: typeof captureEarlyIntegritySnapshot;
  verifyEarlyIntegritySnapshot: typeof verifyEarlyIntegritySnapshot;
  on: typeof onClientEvent;
  off: typeof offClientEvent;
  use: typeof usePlugin;
  plugins: typeof listPlugins;
  detectAutomation: typeof detectAutomation;
}

declare const Archx: ArchxStatic;
export default Archx;

export type { ArchxHeader };
