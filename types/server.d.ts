/**
 * Archx server middleware: authenticated, token-gated protected delivery.
 * Deny-by-default — `authorize` is required unless `allowAnonymous` is set.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';

export type ArchxFormat = 'webp' | 'png' | 'jpeg' | 'avif';

export interface ArchxAuthorizeContext {
  phase: 'token' | 'image';
  token?: Record<string, unknown>;
  ref?: string;
}

export interface ArchxAuthorizeResult {
  allow?: boolean;
  viewerId?: string;
  maxWidth?: number;
  quality?: number | 'lossless';
  format?: ArchxFormat;
  permissions?: string[];
  watermark?: string | null;
  ttlSec?: number;
  [key: string]: unknown;
}

export type ArchxAuthorize = (
  req: IncomingMessage,
  id: string,
  context: ArchxAuthorizeContext,
) => boolean | ArchxAuthorizeResult | Promise<boolean | ArchxAuthorizeResult>;

/**
 * Optional ordinary-image endpoint for verified search crawlers. The verifier
 * must authenticate crawler identity from a trusted signal (for example,
 * verified source IP data); a User-Agent check alone is not verification.
 * Unverified requests receive no image. Output is always resized and visibly
 * watermarked, and is never shared-cacheable.
 */
export interface ArchxSeoCrawlerOptions {
  verify: (req: IncomingMessage, id: string) => boolean | Promise<boolean>;
  /** Visible site/owner label included in the server-baked PREVIEW ONLY mark. */
  watermark: string;
  /** Maximum preview width, hard-capped at 640 pixels (default 320). */
  maxWidth?: number;
  /** Maximum fraction of the master's width (0.05–0.9; default 0.5). */
  maxWidthFraction?: number;
  /** Lossy output quality, hard-capped at 75 (default 55). */
  quality?: number;
  /** Standard-image output format (default webp). */
  format?: 'webp' | 'jpeg';
}

export interface ArchxSecurityEvent {
  type: string;
  reason?: string;
  id?: string;
  phase?: string;
  count?: number;
  [key: string]: unknown;
}

export interface ArchxStateStore {
  kind?: string;
  /** Atomically claim a one-time key; resolves true only for the first caller. */
  claimOnce(key: string, ttlMs: number, now?: number): Promise<boolean>;
  hitWindow(
    key: string,
    options: { limit: number; windowMs?: number; now?: number },
  ): Promise<{ limited: boolean; retryAfterSec: number; count: number }>;
  trackDistinct(
    key: string,
    member: string,
    options?: Record<string, unknown>,
  ): Promise<unknown>;
  getCache(key: string, now?: number): Promise<Uint8Array | null>;
  setCache(key: string, bytes: Uint8Array, options?: { ttlMs?: number; now?: number }): Promise<void>;
  stats?(): Record<string, unknown>;
  close?(): void;
  [key: string]: unknown;
}

/**
 * Image-processing budgets and encoder settings. This interface mirrors
 * the server's strict allowlist exactly (v1.29): unknown keys are
 * rejected at startup by the middleware, so they are now also rejected
 * by tsc instead of silently doing nothing. The same keys may also be
 * supplied at the top level of the server options.
 */
export interface ArchxProcessingOptions {
  /** Hard input cap in bytes, checked before decode (1024 … 500 MiB). */
  maxInputBytes?: number;
  /** Hard input pixel cap (10000 … 268402689). */
  maxInputPixels?: number;
  /** Hard input width cap (64 … 65536). */
  maxInputWidth?: number;
  /** Hard input height cap (64 … 65536). */
  maxInputHeight?: number;
  /** Hard output pixel cap (10000 … 268402689). */
  maxOutputPixels?: number;
  /** Per-job Sharp timeout in seconds (1 … 120). */
  processingTimeoutSec?: number;
  /** Alias for processingTimeoutSec. */
  timeoutSec?: number;
  /** Decodable input formats (default jpeg, png, webp, avif). */
  allowedInputFormats?: string[];
  /** Parallel Sharp jobs (1 … 64). */
  processingConcurrency?: number;
  /** Alias for processingConcurrency. */
  maxConcurrentProcessing?: number;
  /** Bounded wait-queue length for processing jobs (0 … 10000). */
  processingQueueMax?: number;
  /** Max milliseconds a job may wait for a processing slot (0 … 120000). */
  processingQueueTimeoutMs?: number;
  /** Refuse Sharp loaders for untrusted formats (default true). */
  blockUntrustedSharpLoaders?: boolean;
  webpEffort?: number;
  /** Alias for webpEffort. */
  encoderEffort?: number;
  webpSmartSubsample?: boolean;
  /** Alias for webpSmartSubsample. */
  smartSubsample?: boolean;
  avifEffort?: number;
  /** Permit request-path AVIF effort > 2 (otherwise clamped to 2; pre-build offline instead). */
  allowSlowRequestAvif?: boolean;
  avifChromaSubsampling?: '4:2:0' | '4:4:4';
  resizeKernel?: 'nearest' | 'cubic' | 'mitchell' | 'lanczos2' | 'lanczos3' | 'mks2013' | 'mks2021';
  pngCompressionLevel?: number;
  jpegChromaSubsampling?: '4:2:0' | '4:4:4';
  sharpConcurrency?: number;
  sharpCache?: boolean;
}

/**
 * Delivery quotas. Mirrors the server's strict allowlist (v1.29) so a
 * typo'd key fails in tsc instead of silently leaving a quota unset.
 * `null`/absent = that dimension unlimited; `quotas: false` disables all.
 */
export interface ArchxQuotas {
  windowMs?: number;
  perIp?: number | null;
  perViewer?: number | null;
  perIpImage?: number | null;
  perViewerImage?: number | null;
}

export interface ArchxForensicOptions {
  blockSize?: number;
  delta?: number;
  /** Sign-derivation vintage: 1 = legacy hashSeed, 2 = 128-bit cyrb128, 3 = SHA-256-seeded (default). */
  signsVersion?: 1 | 2 | 3;
}

export interface ArchxStegoOptions {
  perToken?: boolean;
  scope?: 'image' | 'viewer';
  keyScope?: 'image' | 'viewer';
  profile?: 'standard' | 'robust';
  strength?: number;
  gridX?: number;
  gridY?: number;
  /** Codeword layout: 1 = legacy 32-bit, 2 = 128-bit cyrb128, 3 = SHA-256-seeded (default), 4 = BCH error correction (v1.20+, needs a v1.20+ detector). */
  layoutVersion?: 1 | 2 | 3 | 4;
  /** Keep the pre-1.12 CRC tag instead of the keyed MAC tag. */
  legacyCode?: boolean;
}

export interface ArchxOwnershipOptions {
  /** Public owner identity recorded in the signed claim. */
  owner: string;
  /** Logical image identifier recorded in the claim (<=128 chars). */
  imageId?: string;
  /** Ed25519 private key: KeyObject or PKCS#8 PEM/DER. Never browser-delivered. */
  privateKey: import('node:crypto').KeyObject | string | Uint8Array;
  /** Human-readable EXIF/XMP copyright string (default: copyright <owner>). */
  copyright?: string;
  /** Human-readable EXIF Artist string (default: <owner>). */
  artist?: string;
}

export interface ArchxServerOptions {
  /** HMAC/signing secret (>= 32 chars or bytes). Falls back to ARCHX_SECRET. */
  secret?: string | Uint8Array;
  secretId?: string;
  secrets?: Record<string, string | Uint8Array>;
  activeSecretId?: string;
  authorize?: ArchxAuthorize;
  allowAnonymous?: boolean;
  imagesDir?: string;
  imagesDirs?: Record<string, string> | string[];
  images?: Record<string, string | Uint8Array | { file?: string; bytes?: Uint8Array; version?: string }>;
  publicDir?: string;
  publicDirs?: string[];
  /** Base route prefix (default `/archx`). */
  basePath?: string;
  deploymentMode?: 'single-instance' | 'multi-instance';
  ttlSec?: number;
  tokenMethods?: Array<'POST' | 'GET'>;
  requireSameSiteTokenRequests?: boolean;
  requireTokenRequestHeader?: boolean;
  allowedOrigins?: string[];
  /** Disabled unless explicitly configured; adds GET/HEAD {basePath}/seo/:id. */
  seoCrawler?: ArchxSeoCrawlerOptions | false;
  allowQueryTokens?: boolean;
  bindTokenTo?:
    | {
        ip?: boolean | string | ((req: IncomingMessage) => string | Promise<string>);
        userAgent?: boolean | string | ((req: IncomingMessage) => string | Promise<string>);
        session?: boolean | string | ((req: IncomingMessage) => string | Promise<string>);
      }
    | Array<'ip' | 'userAgent' | 'ua' | 'user-agent' | 'session'>;
  oneTimeTokens?: boolean;
  oneTimeTokenMaxEntries?: number;
  /** Scale bounded-store defaults for small containers ('compact') or normal hosts ('standard', default). */
  memoryProfile?: 'standard' | 'compact';
  proofOfPossession?: 'off' | 'optional' | 'required';
  /** Scramble tiles per side for NEW payloads: integer 8–32 (default 8).
   *  Payloads already built with legacy 2–7 grids remain decodable. */
  grid?: number;
  /** 1 = legacy 32-bit plan seed, 2 = 128-bit seed (default since 1.15).
   *  Clients older than v1.10 cannot read `pv:2` payloads. */
  scramblePlanVersion?: 1 | 2;
  scrambleKeyMode?: 'per-image' | 'per-token';
  encrypt?: boolean;
  format?: ArchxFormat;
  quality?: number | 'lossless';
  lossless?: boolean;
  allowClientQuality?: boolean;
  maxWidthCap?: number;
  /**
   * Hard ceiling on delivered width as a fraction (0.05-1) of each
   * master's own width, enforced at mint and redemption. Values < 1
   * make "preview, never full-resolution pixels" server-enforceable.
   */
  maxWidthFraction?: number;
  /**
   * Replay-store pressure policy: 'evict' (default, availability —
   * oldest live claims dropped, archx.replay_store_evicted emitted)
   * or 'strict' (never drops a live claim; new redemptions rejected
   * while saturated).
   */
  replaySaturation?: 'evict' | 'strict';
  /** Embed a signed ownership claim in every derivative (see ArchxOwnershipOptions). */
  ownership?: ArchxOwnershipOptions;
  widthBuckets?: number[];
  /** Serve the non-CORS 1x1 taint pixel at `{basePath}/taint.png` (default on). */
  taintImage?: boolean;
  serverWatermark?: string | null;
  forensic?: boolean | ArchxForensicOptions;
  forensicPerToken?: boolean;
  forensicScope?: string;
  steganography?: boolean | ArchxStegoOptions;
  stegoRegistryFailure?: 'allow' | 'deny';
  onStegoIssue?: (event: ArchxSecurityEvent) => void;
  provenanceFailure?: 'allow' | 'deny';
  onProvenanceIssue?: (event: ArchxSecurityEvent) => void;
  onSecurityEvent?: (event: ArchxSecurityEvent) => void;
  onDelivery?: (event: ArchxSecurityEvent) => void;
  onAbuse?: (event: ArchxSecurityEvent) => void;
  abuseDetection?: {
    distinctImages?: number;
    windowMs?: number;
    /** 'event' (default) reports; 'deny' blocks 429; 'challenge' demands a step-up proof (requires challenge.verify). */
    action?: 'event' | 'deny' | 'challenge';
  } | false;
  /**
   * Step-up challenge verifier for abuseDetection.action 'challenge'.
   * verify() receives the raw proof header value (e.g. forward it to
   * Turnstile siteverify or check a WebAuthn assertion host-side)
   * and returns true / { ok: true, ttlSec? } to clear the subject.
   */
  challenge?: {
    verify: (req: IncomingMessage, proof: string) => Promise<boolean | { ok: boolean; ttlSec?: number }> | boolean | { ok: boolean; ttlSec?: number };
    header?: string;
    clearanceTtlSec?: number;
  };
  quotas?: ArchxQuotas | false;
  rateLimitPerMinute?: number;
  tokenRateLimitPerMinute?: number;
  rateLimitMaxClients?: number;
  maxTrackedClients?: number;
  trustProxy?: boolean;
  trustedProxyHops?: number;
  batchTokenMaxItems?: number;
  batchTokenMaxBytes?: number;
  callbackTimeoutMs?: number;
  authorizeTimeoutMs?: number;
  stateStore?: ArchxStateStore;
  stateStoreTimeoutMs?: number;
  sharedCacheTtlMs?: number;
  outputCacheMax?: number;
  outputCacheMaxBytes?: number;
  outputCacheDir?: string | null;
  outputCacheDiskMaxBytes?: number;
  outputCacheDiskMaxEntries?: number;
  outputCacheDiskTtlMs?: number;
  cacheMasters?: boolean;
  masterCacheMaxBytes?: number;
  processing?: ArchxProcessingOptions;
  processingConcurrency?: number;
  maxConcurrentProcessing?: number;
  processingQueueMax?: number;
  processingQueueTimeoutMs?: number;
  processingTimeoutSec?: number;
  timeoutSec?: number;
  maxInputBytes?: number;
  maxInputPixels?: number;
  maxInputWidth?: number;
  maxInputHeight?: number;
  maxOutputPixels?: number;
  allowedInputFormats?: string[];
  blockUntrustedSharpLoaders?: boolean;
  [key: string]: unknown;
}

export interface ArchxHandlerStats {
  images: number;
  deploymentMode: string;
  stateStore: string;
  stateStoreShared: boolean;
  activeSecretId: string;
  signingKeyCount: number;
  /** Resized-base derivative cache (uncacheable per-token/per-viewer variants). */
  baseCacheEntries?: number;
  baseCacheBytes?: number;
  [key: string]: unknown;
}

export interface ArchxConfigAudit {
  /**
   * True when the configuration is internally valid and the middleware
   * will accept it. This is NOT a production ship gate — a valid config
   * can still be far from the hardened baseline. Gate releases on
   * `auditArchxProductionConfig(...).ready`.
   */
  ok: boolean;
  /** Same value as `ok`, named for what it means (configuration valid). */
  configOk: boolean;
  /** Blocking configuration problems (named `issues` at runtime). */
  issues: readonly string[];
  warnings: readonly string[];
  /** Sanitized effective-configuration summary (never contains secrets), or null when invalid. */
  summary: Readonly<Record<string, unknown>> | null;
}

export interface ArchxProductionAudit {
  /**
   * Since v1.27 this means the same as `ready` (zero blockers). Before
   * v1.27 it mirrored the base audit's "configuration accepted" bit and
   * could be true with live blockers — do not backport that reading.
   */
  ok: boolean;
  /** The production ship gate: true only when `blockers` is empty. */
  ready: boolean;
  /** Base configuration validity (what `ArchxConfigAudit.ok` reports). */
  configOk: boolean;
  /** Everything that must change before this config matches the hardened baseline (includes base `issues`). */
  blockers: readonly string[];
  /** Non-blocking hardening/operational advice. */
  recommendations: readonly string[];
  warnings: readonly string[];
  /** Sanitized effective-configuration summary (never contains secrets), or null when invalid. */
  summary: Readonly<Record<string, unknown>> | null;
}

export interface ArchxRequestHandler {
  (req: IncomingMessage, res: ServerResponse): Promise<boolean>;
  configAudit: ArchxConfigAudit;
  stats(): ArchxHandlerStats;
  close(): void;
}

export function createArchxMiddleware(options?: ArchxServerOptions): ArchxRequestHandler;

/* ---------- operations helpers (server/ops.js, v1.29) ---------- */

/** Render handler.stats() as Prometheus text exposition for your scraper route. */
export function formatPrometheusMetrics(
  stats: ArchxHandlerStats,
  options?: { prefix?: string },
): string;
/** GET/HEAD health+readiness endpoint: 200 when the startup config audit passes, else 503. Body carries counts only; mount internally. */
export function createArchxHealthHandler(
  handler: ArchxRequestHandler,
): (req: IncomingMessage, res: ServerResponse) => void;
/** Wire SIGTERM/SIGINT graceful shutdown (drain server, handler.close(), exit). Returns an uninstaller. */
export function installArchxShutdown(options: {
  server: { close: (callback: () => void) => void };
  handler: ArchxRequestHandler;
  timeoutMs?: number;
  signals?: string[];
  onShutdown?: () => void;
}): () => void;
/** JSON-lines logger for the onSecurityEvent/onDelivery hooks; drops raw ip/viewerId unless includeRawActor. */
export function createJsonEventLogger(
  write: (line: string) => void,
  options?: { service?: string; includeRawActor?: boolean },
): Readonly<{
  onSecurityEvent: (event: unknown) => void;
  onDelivery: (event: unknown) => void;
}>;

/* ---------- image-processing entry points (server/scramble-image.js) ----------
 * Re-exported from the /server entry; Sharp loads lazily on first actual
 * image operation, so importing these declarations' module in a token-only
 * process does not require libvips to be installed/loaded. */

export interface ArchxDerivativeResult {
  bytes: Buffer;
  header: string;
  stegoFingerprint: string | null;
  perceptualFingerprint?: unknown;
  /** Signed ownership claim token embedded in the derivative, when configured. Log it in your issuance registry. */
  ownershipToken?: string | null;
}

/** Opaque stage-1 result of prepareDerivativeBase(); pass to finishDerivative(). */
export interface ArchxDerivativeBase {
  data: Uint8Array;
  w: number;
  h: number;
  hasAlpha: boolean;
  watermarked: boolean;
}

export interface ArchxScrambleImageOptions {
  /** Scramble tiles per side for NEW payloads: integer 8–32 (default 8). */
  grid?: number;
  key?: string;
  planVersion?: 1 | 2;
  maxWidth?: number;
  quality?: number | 'lossless';
  lossless?: boolean;
  format?: ArchxFormat;
  encrypt?: boolean;
  aesKey?: string | Uint8Array;
  /** string/object/function to mark; `false` or `null` opts this view out of the global serverWatermark. */
  watermark?: string | { text?: string; opacity?: number; color?: string; [key: string]: unknown } | null | false;
  forensic?: boolean | ArchxForensicOptions;
  forensicSeed?: string;
  /** Embed an Ed25519-signed ownership claim (EXIF/XMP) in the derivative. */
  ownership?: ArchxOwnershipOptions;
  stegoPayload?: string;
  stegoKey?: string;
  steganography?: ArchxStegoOptions & { key?: string };
  stegoLayoutVersion?: 1 | 2 | 3 | 4;
  stegoLegacyCode?: boolean;
  processing?: ArchxProcessingOptions;
  [key: string]: unknown;
}

export function scrambleImage(
  input: Uint8Array | ArrayBuffer,
  options?: ArchxScrambleImageOptions,
): Promise<ArchxDerivativeResult>;
/** Decode a scrambled payload. `grid` here accepts the full historical
 *  2–32 range so pre-v1.27 payloads remain recoverable. */
export function unscrambleImage(
  scrambledBytes: Uint8Array | ArrayBuffer,
  options?: { grid?: number; key?: string; w?: number; h?: number; planVersion?: 1 | 2; [key: string]: unknown },
): Promise<Buffer>;
export function prepareDerivativeBase(
  input: Uint8Array | ArrayBuffer,
  options?: ArchxScrambleImageOptions,
): Promise<ArchxDerivativeBase>;
export function finishDerivative(
  base: ArchxDerivativeBase,
  options?: ArchxScrambleImageOptions,
): Promise<ArchxDerivativeResult>;
export function inspectImageMetadata(
  input: Uint8Array | ArrayBuffer,
  options?: { processing?: ArchxProcessingOptions & Record<string, unknown>; [key: string]: unknown },
): Promise<{ format: string; width: number; height: number; [key: string]: unknown }>;
export function configureSharpSecurity(allowedFormats?: readonly string[]): void;
export function configureSharpPerformance(options?: { concurrency?: number; cache?: boolean }): void;
/** Refcounted scoped libvips loader policy; returns an idempotent release fn. */
export function acquireSharpSecurityLease(allowedFormats?: readonly string[]): () => void;
export function ensureUntrustedSharpLoadersBlocked(): boolean;
export function generateKeyBase64(bytes?: number): string;
/**
 * Run StegoMark forensic detection in a worker thread. The synchronous
 * core detector blocks for seconds on unmarked images under
 * auto/geometry search; never call it on an HTTP request path.
 */
export function detectStegoFingerprintInWorker(
  rgba: Uint8Array,
  w: number,
  h: number,
  options?: Record<string, unknown> & { timeoutMs?: number },
): Promise<Record<string, unknown>>;
/** Bound the forensic worker queue (default 64 pending) and per-job timeout (default 120s). */
export function configureStegoDetectWorker(options?: {
  maxPending?: number; timeoutMs?: number;
  /** Cap on total RGBA bytes held by active + queued jobs (default 512 MiB). */
  maxQueuedBytes?: number;
  /** Per-suspect pixel cap (default 50 MP). */
  maxPixels?: number;
  /** Reject a job that waited in queue longer than this (default 300s; 0 disables). */
  queueTimeoutMs?: number;
  /** Worker-thread pool size (default 1; raise for multi-core forensic batch hosts). */
  maxWorkers?: number;
}): { maxPending: number; timeoutMs: number; maxQueuedBytes: number; maxPixels: number; queueTimeoutMs: number; maxWorkers: number; pending: number; queuedBytes: number; workers: number };
/**
 * Screen one suspect against many keys in a single worker job:
 * shared planes, cheap native screen per key, full search only for
 * the top-ranked keys (escalateTop, default 2).
 */
export function batchDetectStegoInWorker(
  rgba: Uint8Array,
  w: number,
  h: number,
  keys: string[],
  options?: Record<string, unknown> & { timeoutMs?: number; escalateTop?: number },
): Promise<Array<{ key: string; escalated: boolean; result: Record<string, unknown> }>>;
export function closeStegoDetectWorker(): void;
export default createArchxMiddleware;

export const DEFAULT_WIDTH_BUCKETS: readonly number[];
export function canonicalDerivativeWidth(
  requestedWidth: number, widthCap: number, buckets?: readonly number[],
): number;
export function validateImageId(id: unknown): boolean;

export class SlidingWindowLimiter {
  constructor(options?: { windowMs?: number; maxClients?: number; cleanupIntervalMs?: number });
  readonly size: number;
  hit(key: string, max: number, now?: number): { limited: boolean; retryAfterSec: number; count: number };
  close(): void;
}
export class BoundedTtlSet {
  constructor(options?: { maxEntries?: number; cleanupIntervalMs?: number });
  readonly size: number;
  cleanup(now?: number): void;
  claim(key: string, expiresAtMs: number, now?: number): boolean;
  close(): void;
}
export class AsyncSemaphore {
  constructor(options?: { maxConcurrent?: number; maxQueue?: number; queueTimeoutMs?: number });
  run<T>(task: () => Promise<T>): Promise<T>;
  readonly active: number;
  readonly queued: number;
}

export function createMemoryStateStore(options?: {
  maxClients?: number;
  maxEntries?: number;
  maxCacheEntries?: number;
  [key: string]: unknown;
}): ArchxStateStore;

export function validateWatermarkValue(value: unknown): boolean;
export function validateTokenClaims(
  payload: unknown,
  options?: {
    id?: string;
    maxWidthCap?: number;
    maxTtlMs?: number;
    now?: number;
    clockSkewMs?: number;
  },
): boolean;
export function computeJwkThumbprint(value: unknown): string | null;
export function normalizeAuthorizationResult(auth: unknown): ArchxAuthorizeResult | null;

export function auditArchxServerConfig(options?: ArchxServerOptions): ArchxConfigAudit;
export function auditArchxProductionConfig(
  options?: ArchxServerOptions,
  context?: { expectedInstances?: number },
): ArchxProductionAudit;
export function withHardenedProductionDefaults(
  options?: ArchxServerOptions,
): ArchxServerOptions;
export function withCatalogThroughputDefaults(
  options?: ArchxServerOptions,
): ArchxServerOptions;
/** Lite profile (v1.28): CPU/RAM/speed first (catalog throughput + compact stores). */
export function withLiteDefaults(
  options?: ArchxServerOptions,
): ArchxServerOptions;
/** Performance profile (rebalanced in v1.28): catalog sharing economics at quality 90 with full-effort WebP. The v1.23–1.27 CPU-first composition moved to withLiteDefaults(). */
export function withPerformanceDefaults(
  options?: ArchxServerOptions,
): ArchxServerOptions;
/** Elite profile (v1.28): security first — max-protection composition plus maxWidthFraction 0.6 by default. */
export function withEliteDefaults(
  options?: ArchxServerOptions,
): ArchxServerOptions;
export function withMaxProtectionDefaults(
  options?: ArchxServerOptions,
): ArchxServerOptions;

export function deriveStegoFingerprint(args: {
  id: string;
  nonce?: string;
  viewerHash?: string;
  secret: string | Uint8Array;
  perToken?: boolean;
}): string;
export function deriveStegoKey(id: string, secret: string | Uint8Array): string;

export interface ArchxOwnershipClaimPayload {
  v: 1;
  own: string;
  img: string;
  /** 16-hex perceptual fingerprint of the unscrambled derivative, or null. */
  ph: string | null;
  /** 12-hex per-image stego fingerprint, or null when unmarked. */
  sfp: string | null;
}
/** Generate a fresh Ed25519 ownership key pair (PEM strings). */
export function generateOwnershipKeyPair(): Readonly<{ privateKey: string; publicKey: string }>;
/** Load an Ed25519 private key from PEM (throws for other key types). */
export function loadOwnershipPrivateKey(pem: string): import('node:crypto').KeyObject;
/** Load an Ed25519 public key from PEM (throws for other key types). */
export function loadOwnershipPublicKey(pem: string): import('node:crypto').KeyObject;
/** SHA-256 of the SPKI DER encoding, first 32 hex chars — publish alongside the key. */
export function ownershipPublicKeyFingerprint(
  publicKey: import('node:crypto').KeyObject | string,
): string;
/**
 * Sign a deterministic ownership claim token (ARCHX1.<b64url>.<sig>).
 * No timestamp: identical derivative => identical token.
 */
export function signOwnershipClaim(
  claim: { owner: string; imageId?: string; perceptualHash?: string | null; stegoFingerprint?: string | null },
  privateKey: import('node:crypto').KeyObject | string,
): string;
/**
 * Structural decode + strict field validation only — NO signature
 * check. Returns null for anything malformed.
 */
export function parseOwnershipClaim(token: string): {
  payload: ArchxOwnershipClaimPayload;
  segment: string;
  signature: Buffer;
} | null;
/** Verify the Ed25519 signature over a claim token. */
export function verifyOwnershipClaim(
  token: string,
  publicKey: import('node:crypto').KeyObject | string,
): { valid: boolean; claim: ArchxOwnershipClaimPayload | null; reason: string | null };
/** First claim token found in encoded image bytes (EXIF/XMP scan). */
export function extractOwnershipClaim(imageBytes: Uint8Array): string | null;
/** All claim-token candidates in encoded bytes (bounded; decoy-resistant evidence should prefer this). */
export function extractOwnershipClaims(imageBytes: Uint8Array, maxCandidates?: number): string[];
/** Embed ownership metadata into already-encoded image bytes. */
export function embedOwnershipMetadata(
  imageBytes: Uint8Array | ArrayBuffer,
  metadata: { owner?: string; copyright?: string; artist?: string; token?: string },
): Promise<Buffer>;
export interface ArchxOwnershipVerification {
  claimFound: boolean;
  claimSource: 'external' | 'metadata' | null;
  claimCandidates: number;
  signatureChecked: boolean;
  signatureValid: boolean;
  /** Claim payload may drive evidence (signature-valid or operator-supplied). */
  claimTrusted: boolean;
  /** Some layer an attacker cannot fabricate agreed — safe to act on. */
  contentTrusted: boolean;
  /** Set ONLY from a trusted claim; suspect-supplied strings go to unverifiedClaim. */
  owner: string | null;
  imageId: string | null;
  unverifiedClaim: { owner: string; imageId: string | null } | null;
  perceptual: { hash: string | null; distanceToClaim: number | null; matchesClaim: boolean };
  stego: {
    found: boolean;
    fingerprint: string | null;
    matchesClaim: boolean;
    erasureDecoded: boolean;
    corrections: number;
    timedOut: boolean;
  } | null;
  verdict: 'verified' | 'claim-only' | 'content-match' | 'no-evidence';
}
/**
 * Layered ownership rescan (runs in-process; stego detection is
 * time-bounded by default). Verdicts: verified / claim-only /
 * content-match / no-evidence — evidence, not legal proof.
 */
export function verifyOwnership(
  imageBytes: Uint8Array | ArrayBuffer,
  options?: {
    publicKey?: import('node:crypto').KeyObject | string;
    stegoKey?: string | null;
    /** Operator-supplied claim token from your issuance registry. */
    claim?: string | null;
    maxPhDistance?: number;
    detectOptions?: Record<string, unknown>;
  },
): Promise<ArchxOwnershipVerification>;

export interface ArchxIssuanceEntry {
  seq: number;
  ts: string;
  record: Record<string, unknown>;
  prev: string;
  mac: string;
}
export interface ArchxIssuanceLog {
  append(record: Record<string, unknown>): Readonly<ArchxIssuanceEntry>;
  entries(): Array<Readonly<ArchxIssuanceEntry>>;
  head(): string;
  verify(): { ok: boolean; badIndex: number; reason: string | null; head?: string };
  readonly size: number;
}
/** Tamper-evident hash-chained issuance registry (see docs/IP_HOLDER_GUIDE.md). */
export function createIssuanceLog(options: {
  secret: string | Buffer;
  entries?: ArchxIssuanceEntry[];
  allowBroken?: boolean;
  now?: () => string;
}): ArchxIssuanceLog;
/** Verify a serialized issuance chain without constructing a log. */
export function verifyIssuanceChain(
  entries: ArchxIssuanceEntry[],
  secret: string | Buffer,
): { ok: boolean; badIndex: number; reason: string | null; head?: string };
