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

export interface ArchxProcessingOptions {
  webpEffort?: number;
  webpSmartSubsample?: boolean;
  avifEffort?: number;
  avifChromaSubsampling?: '4:2:0' | '4:4:4';
  resizeKernel?: 'nearest' | 'cubic' | 'mitchell' | 'lanczos2' | 'lanczos3' | 'mks2013' | 'mks2021';
  pngCompressionLevel?: number;
  jpegChromaSubsampling?: '4:2:0' | '4:4:4';
  sharpConcurrency?: number;
  sharpCache?: boolean;
  [key: string]: unknown;
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
  deploymentMode?: 'development' | 'production';
  ttlSec?: number;
  tokenMethods?: Array<'POST' | 'GET'>;
  requireSameSiteTokenRequests?: boolean;
  requireTokenRequestHeader?: boolean;
  allowedOrigins?: string[];
  allowQueryTokens?: boolean;
  bindTokenTo?: Array<'ip' | 'user-agent' | 'session' | string> | false;
  oneTimeTokens?: boolean;
  oneTimeTokenMaxEntries?: number;
  proofOfPossession?: 'off' | 'optional' | 'required';
  grid?: number;
  /** 1 = legacy 32-bit plan seed (default), 2 = 128-bit seed. Clients must
   *  support `pv:2` (v1.10+) before enabling. */
  scramblePlanVersion?: 1 | 2;
  scrambleKeyMode?: 'per-image' | 'per-token';
  encrypt?: boolean;
  format?: ArchxFormat;
  quality?: number | 'lossless';
  lossless?: boolean;
  allowClientQuality?: boolean;
  maxWidthCap?: number;
  widthBuckets?: number[];
  /** Serve the non-CORS 1x1 taint pixel at `{basePath}/taint.png` (default on). */
  taintImage?: boolean;
  serverWatermark?: string | null;
  forensic?: boolean | Record<string, unknown>;
  forensicPerToken?: boolean;
  forensicScope?: string;
  steganography?: boolean | Record<string, unknown>;
  stegoRegistryFailure?: 'allow' | 'deny';
  onStegoIssue?: (event: ArchxSecurityEvent) => void;
  provenanceFailure?: 'allow' | 'deny';
  onProvenanceIssue?: (event: ArchxSecurityEvent) => void;
  onSecurityEvent?: (event: ArchxSecurityEvent) => void;
  onDelivery?: (event: ArchxSecurityEvent) => void;
  onAbuse?: (event: ArchxSecurityEvent) => void;
  abuseDetection?: Record<string, unknown> | false;
  quotas?: Record<string, unknown> | false;
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
  ok: boolean;
  errors: string[];
  warnings: string[];
  recommendations?: string[];
  [key: string]: unknown;
}

export interface ArchxRequestHandler {
  (req: IncomingMessage, res: ServerResponse): Promise<boolean>;
  configAudit: ArchxConfigAudit;
  stats(): ArchxHandlerStats;
  close(): void;
}

export function createArchxMiddleware(options?: ArchxServerOptions): ArchxRequestHandler;
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

export function validateWatermarkValue(value: unknown): string | null;
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
): ArchxConfigAudit;
export function withHardenedProductionDefaults(
  options?: ArchxServerOptions,
): ArchxServerOptions;
export function withCatalogThroughputDefaults(
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
