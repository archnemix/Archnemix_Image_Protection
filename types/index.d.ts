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
  | 'lite' | 'shield' | 'vault' | 'fortress' | 'custom'
  /** 1.28 profile-modes: 'performance' = balanced shield pipeline; 'elite' = fortress bundle + proof-of-possession required. */
  | 'performance' | 'elite';

/** The three canonical profile bundles (1.28). Applied UNDER explicit options via the `profile` option or Archx.preset(). */
export type ArchxProfile = 'lite' | 'performance' | 'elite';

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

/**
 * Frozen, sanitized telemetry event delivered to `Archx.on()` listeners,
 * plugins, and the per-instance `onEvent` option. Never carries tokens,
 * keys, proofs, source objects, pixels, canvases, or raw errors.
 */
export interface ArchxClientEvent {
  schemaVersion: 1;
  service: 'archx-client';
  type: string;
  /** ISO-8601 timestamp. */
  at: string;
  mode: string | null;
  kind: string | null;
  reason: string | null;
  outcome: string | null;
  issues: readonly string[] | null;
}

/* ---------- bubbling DOM events dispatched on the host element ---------- */

/** `archx-attempt`: an extraction/interaction attempt was detected. */
export interface ArchxAttemptEventDetail { kind: string; }
/** `archx-error`: the load failed or was blocked by policy. */
export interface ArchxErrorEventDetail { error: Error; }
/** `archx-taint-unavailable`: no cross-origin taint pixel, so a 2D mode is
 *  relying on instance poisoning alone (or was promoted to WebGL). */
export interface ArchxTaintUnavailableEventDetail {
  mode: string;
  reason: 'no-cross-origin-taint-source' | 'taint-load-failed';
  promoted: boolean;
}
/** `archx-integrity`: a page script rewrote a WebGL readback safeguard. */
export interface ArchxIntegrityEventDetail {
  issue: 'preserveDrawingBuffer-rewritten';
  source: string;
}
/** `archx-webgl-budget`: the shared WebGL context budget is exhausted, so
 *  this instance fell back to the Canvas2D renderer. */
export interface ArchxWebglBudgetEventDetail { inUse: number; budget: number; }

/** Map of the bubbling CustomEvents a protected host element dispatches.
 *  (`archx-load` is dispatched with no detail right after the first frame
 *  is rendered, just before `onLoad` runs; the `ready` promise settles
 *  after the following paint.) */
export interface ArchxElementEventMap {
  'archx-load': CustomEvent<null>;
  'archx-attempt': CustomEvent<ArchxAttemptEventDetail>;
  'archx-error': CustomEvent<ArchxErrorEventDetail>;
  'archx-taint-unavailable': CustomEvent<ArchxTaintUnavailableEventDetail>;
  'archx-integrity': CustomEvent<ArchxIntegrityEventDetail>;
  'archx-webgl-budget': CustomEvent<ArchxWebglBudgetEventDetail>;
}

declare global {
  interface HTMLElementEventMap extends ArchxElementEventMap {}
  interface HTMLElementTagNameMap {
    'archx-image': ArchxImageElement;
  }
}

/** The `<archx-image>` custom element registered by `Archx.defineElement()`. */
export interface ArchxImageElement extends HTMLElement {
  /** The backing viewer once connected, else null. */
  inst: ProtectedImage | null;
  /** Mirrors the backing viewer's first-paint `ready` promise once connected. */
  ready: Promise<ProtectedImage> | null;
}

export interface ArchxLoadOptions {
  mode?: ArchxMode;
  /** 1.28: canonical profile bundle applied under explicit options; unknown values throw. */
  profile?: ArchxProfile | null;
  renderer?: 'auto' | 'webgl' | 'canvas' | 'canvas2d';
  preset?: string;
  fit?: 'cover' | 'contain' | 'fill' | 'none';
  lazy?: boolean;
  rootMargin?: string;
  unloadOnExit?: boolean;
  shadow?: boolean | 'open' | 'closed';
  grid?: number;
  scrambled?: boolean;
  /** Scramble plan derivation for container-less scrambled sources
   *  (default 1 = legacy 32-bit seed, for header-less payloads only);
   *  `.archx` container headers carry their own `pv` and win. */
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
  /** Taint pixel URL override (default: `{basePath}/taint.png` derived from a cross-origin token endpoint; a same-origin URL cannot taint). */
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
  /** Extraction/interaction attempt hook: `(kind, instance)`. Kinds include
   *  `contextmenu`, `drag`, `copy`, `longpress`, `extract-*`, `screenshot-key`,
   *  `integrity:*`, `automation:*`, and `lens-scan`. */
  onAttempt?: (kind: string, instance: ProtectedImage) => void;
  /**
   * Server step-up challenge hook: when a mint is answered with
   * `x-archx-challenge: required`, return a proof token (e.g. a
   * Turnstile token) and the mint retries once with it.
   */
  onChallenge?: (ctx: { id: string; reason: string }) => Promise<string | null> | string | null;
  /** Called with the instance after the first frame renders (also after each successful reload). */
  onLoad?: (instance: ProtectedImage) => void;
  /** Called as `(error, instance)` when a load fails. */
  onError?: (error: Error, instance: ProtectedImage) => void;
  /** Genuine-click forwarding: `(event, instance)` (e.g. to open a lightbox). */
  onClick?: (event: MouseEvent, instance: ProtectedImage) => void;
  /** Sanitized telemetry for this instance: `(event, instance)`. */
  onEvent?: (event: ArchxClientEvent, instance: ProtectedImage) => void;
  alt?: string;
  [key: string]: unknown;
}

export class ProtectedImage {
  constructor(target: Element | string, source?: ArchxSource, options?: ArchxLoadOptions);
  /**
   * Resolves with this instance after the first frame has actually been
   * painted (two animation frames after the render that follows
   * `archx-load`/`onLoad`). Under the default lazy loading it stays
   * pending while the host is below the fold (and in background tabs,
   * where animation frames pause). Rejects when the first load fails,
   * is blocked by the integrity/automation/lockout policy, or the
   * instance is destroyed before painting.
   */
  readonly ready: Promise<ProtectedImage>;
  readonly element: Element;
  /** True once the current source has rendered. */
  readonly loaded: boolean;
  /** Sanitized, secret-free view of the effective options. */
  readonly options: Readonly<Record<string, unknown>>;
  reload(source?: ArchxSource): Promise<ProtectedImage>;
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
  /** Settles (never rejects) once every instance's `ready` has settled —
   *  with lazy loading, below-fold items settle as they scroll into view. */
  ready: Promise<Array<PromiseSettledResult<ProtectedImage>>>;
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

export type ArchxClientEventListener = (
  event: ArchxClientEvent,
  instance: ProtectedImage | null,
) => void | Promise<void>;
export function onClientEvent(listener: ArchxClientEventListener): () => void;
export function offClientEvent(listener: ArchxClientEventListener): boolean;

/** Restricted API handed to a plugin's `setup()` — no instance internals. */
export interface ArchxPluginApi {
  on: typeof onClientEvent;
  off: typeof offClientEvent;
  version: string;
}
export interface ArchxPlugin {
  name?: string;
  setup?: (api: ArchxPluginApi) => void;
  onEvent?: ArchxClientEventListener;
  teardown?: () => void;
}
/** Handle returned by `Archx.use()` / `usePlugin()`. */
export interface ArchxPluginHandle {
  readonly name: string;
  remove(): boolean;
}
export function usePlugin(plugin: ArchxPlugin): ArchxPluginHandle;
export function listPlugins(): readonly string[];

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
  /** Registers the fixed `<archx-image>` custom element (idempotent; the
   *  tag name is not configurable). Also called automatically on load. */
  defineElement(): void;
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
