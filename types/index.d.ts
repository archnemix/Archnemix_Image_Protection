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

export type ArchxMode = 'lite' | 'shield' | 'vault' | 'fortress' | 'custom';

export type ArchxSource =
  | string
  | Blob
  | ArrayBuffer
  | Uint8Array
  | HTMLCanvasElement
  | ImageBitmap
  | { id: string }
  | { imageId: string }
  | { assetId: string }
  | { asset: string }
  | { src: string };

export interface ArchxTemporalInterlace {
  targetHz?: number;
  engine?: 'shader' | 'frames' | 'auto';
  layout?: 'pixels' | 'strips' | 'blocks' | 'checker';
  phases?: 2 | 3 | 4;
  cellSize?: number;
  fill?: 'lowres' | 'dim' | 'black' | 'noise';
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
  renderer?: 'auto' | 'webgl' | 'canvas' | 'canvas2d';
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
  tokenTransport?: 'header' | 'query' | 'auto';
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
  onExtract?: 'black' | 'lowres' | 'scrambled';
  /** Origin-taint 2D display canvases so prototype-call readbacks throw. */
  taintReadback?: 'auto' | 'off';
  /** Taint pixel URL override (default: same-origin `{basePath}/taint.png`). */
  taintUrl?: string;
  /** When no cross-origin taint pixel is available in a 2D mode: 'warn' surfaces telemetry + one console warning, 'webgl' promotes the instance to the WebGL renderer, 'off' stays silent. */
  taintFallback?: 'warn' | 'webgl' | 'off';
  splitCanvases?: boolean;
  splitGrid?: number;
  maxBackingWidth?: number;
  dprCap?: number;
  sourceOversample?: number;
  maxSourceWidth?: number;
  sourceWidthBuckets?: number[];
  qualityProfile?: 'original' | 'high' | 'balanced' | 'catalog' | 'fast';
  requestQuality?: number | 'lossless';
  networkAware?: boolean;
  cacheBitmap?: boolean;
  bitmapCacheMaxEntries?: number;
  bitmapCacheMaxBytes?: number;
  cachePayload?: boolean;
  cacheScope?: string;
  reloadOnResize?: 'never' | 'upscale' | 'always';
  resizeUpscaleFactor?: number;
  renderLoop?: 'auto' | 'static' | 'continuous';
  temporalShield?: boolean | Record<string, unknown>;
  temporalInterlace?: boolean | ArchxTemporalInterlace;
  cameraShield?: boolean | Record<string, unknown>;
  watermark?: string | Record<string, unknown> | null;
  forensic?: boolean | Record<string, unknown>;
  sessionId?: string;
  brand?: string;
  aspectRatio?: string;
  retries?: number;
  credentials?: RequestCredentials;
  integrity?: string;
  /**
   * Headless/automation tripwire policy (signals are spoofable; this
   * is friction, not identity): 'off' ignores, 'monitor' (default)
   * reports via onAttempt, 'lock' refuses to load. Legacy aliases
   * 'allow'|'warn'|'degrade'|'block' are normalized at runtime.
   */
  automation?: 'off' | 'monitor' | 'lock';
  memory?: 'strict' | 'standard';
  localScramble?: boolean;
  lens?: boolean | Record<string, unknown>;
  captureShield?: boolean | Record<string, unknown>;
  strikes?: false | { blurAt?: number; lockAt?: number; lockMs?: number };
  debug?: boolean;
  guards?: Record<string, boolean>;
  onAttempt?: (event: ArchxClientEvent) => void;
  /**
   * Server step-up challenge hook: when a mint is answered with
   * `x-archx-challenge: required`, return a proof token (e.g. a
   * Turnstile token) and the mint retries once with it.
   */
  onChallenge?: (ctx: { id: string; reason: string }) => Promise<string | null> | string | null;
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
/** One gallery entry: a plain source, or a source-shaped object with per-item options. */
export type ArchxGalleryItem =
  | ArchxSource
  | ({ src?: string; id?: string; assetId?: string; asset?: unknown; alt?: string; options?: ArchxLoadOptions } & Record<string, unknown>);
export interface ArchxGalleryResult {
  instances: ProtectedImage[];
  ready: Promise<Array<PromiseSettledResult<unknown>>>;
}

export interface ArchxIntegrityDetails {
  ok: boolean;
  issues: readonly string[];
  /** Captured at module load but already non-native (pre-load hooks). */
  capturedNonNative: readonly string[];
  /** Replaced after module load (post-load hooks). */
  changedSinceLoad: readonly string[];
  checked: readonly string[];
  note: string;
}
export function auditIntegrityDetails(): ArchxIntegrityDetails;
export function captureEarlyIntegritySnapshot(): unknown;
export function verifyEarlyIntegritySnapshot(snapshot: unknown): {
  ok: boolean;
  issues: readonly string[];
  snapshotAt: number | string | null;
};
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
      items: readonly ArchxGalleryItem[],
      options?: ArchxLoadOptions & { itemClass?: string },
    ): ArchxGalleryResult;
  };
  image(target: Element | string, source?: ArchxSource, options?: ArchxLoadOptions): ProtectedImage;
  gallery(
    container: Element | string,
    items: readonly ArchxGalleryItem[],
    options?: ArchxLoadOptions & { itemClass?: string },
  ): ArchxGalleryResult;
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

/**
 * The package root also re-exports the scramble/container/stego
 * primitives documented in `@archnemix/image-protection/scramble`.
 */
export * from './scramble.js';
