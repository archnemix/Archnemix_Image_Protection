/**
 * Compile-time smoke test for the shipped type declarations.
 * Checked by `npm run test:types` (tsc --noEmit); never executed.
 */
import http from 'node:http';
import Archx, {
  buildScramblePlan, decodeContainer, detectStegoFingerprint, preset,
  type ArchxLoadOptions, type ProtectedImage,
} from '../types/index.js';
import {
  createArchxMiddleware, withHardenedProductionDefaults,
  withLiteDefaults, withPerformanceDefaults, withEliteDefaults,
  formatPrometheusMetrics, createArchxHealthHandler, installArchxShutdown, createJsonEventLogger,
  type ArchxServerOptions,
  auditArchxProductionConfig, auditArchxServerConfig,
  scrambleImage, inspectImageMetadata, configureSharpSecurity, acquireSharpSecurityLease,
  validateWatermarkValue, detectStegoFingerprintInWorker, closeStegoDetectWorker,
  signOwnershipClaim, verifyOwnership, ownershipPublicKeyFingerprint,
  type ArchxDerivativeResult, type ArchxProductionAudit,
} from '../types/server.js';
import { buildArchxAssets } from '../types/build.js';
import { createRedisStateStore } from '../types/redis.js';
import {
  scramblePixelsPadded, useJsonParser,
  sha256Bytes, hmacSha256Bytes, useWebCrypto, embedStegoFingerprint,
} from '../types/scramble.js';

// --- client ---
const options: ArchxLoadOptions = {
  mode: 'fortress',
  profile: 'elite',
  planVersion: 2,
  taintReadback: 'auto',
  tokenEndpoint: '/archx/token/',
  temporalInterlace: { engine: 'shader', layout: 'pixels', phases: 2, targetHz: 60 },
};
declare const el: HTMLElement;
const view: ProtectedImage = Archx.load.image(el, { id: 'cat' }, options);
void Archx.load.image(el, { imageId: 'cat-alias' }, options); // documented alias, accepted since 1.14
void view.ready.then(() => view.destroy());
Archx.config(preset('marketplace', { fetchPriority: 'high' }));

// --- core ---
const plan = buildScramblePlan(8, 'key', 2);
const scrambled: Uint8Array = scramblePixelsPadded(new Uint8Array(4), 1, 1, plan);
void scrambled;
declare const bytes: Uint8Array;
const { header } = decodeContainer(bytes);
const pv: 1 | 2 | undefined = header.pv;
void pv;
const detection = detectStegoFingerprint(bytes, 8, 8, { profile: 'auto', searchGeometry: true, searchMirror: true, layoutVersion: 'auto' });
const layoutVintage: 0 | 1 | 2 | 3 | 4 = detection.layoutVersion;
void layoutVintage;
const found: boolean = detection.found;
const mirrored: boolean | undefined = detection.mirrored;
const mirrorAxis: 'x' | 'y' | 'xy' | undefined = detection.mirrorAxis;
void mirrorAxis;
const tagScheme: 'mac' | 'crc' | null = detection.tagScheme;
void found; void mirrored; void tagScheme;
useJsonParser(JSON.parse);

// v1.12 core additions
const digest: Uint8Array = sha256Bytes(bytes);
const mac: Uint8Array = hmacSha256Bytes(bytes, digest);
void mac;
useWebCrypto(null);
useWebCrypto({ subtle: {}, getRandomValues: (a: Uint8Array) => a });
const marked: Uint8Array = embedStegoFingerprint(bytes, 8, 8, 'buyer-42', { key: 'k', legacyCode: true, layoutVersion: 3 });
void marked;

// --- server ---
// Profile helpers (v1.28) accept and return server options.
const liteOptions = withLiteDefaults({ secret: 's', imagesDir: '/srv/masters' });
const balancedOptions = withPerformanceDefaults({ secret: 's', imagesDir: '/srv/masters' });
const eliteOptions = withEliteDefaults({ secret: 's', imagesDir: '/srv/masters' });
void liteOptions; void balancedOptions; void eliteOptions;

const handler = createArchxMiddleware(withHardenedProductionDefaults({
  secret: 'x'.repeat(40),
  imagesDir: '/srv/masters',
  scramblePlanVersion: 2,
  format: 'avif',
  steganography: { scope: 'viewer', keyScope: 'viewer', profile: 'robust', layoutVersion: 3, legacyCode: false },
  forensic: { blockSize: 32, delta: 2, signsVersion: 3 },
  processing: {
    avifEffort: 2, avifChromaSubsampling: '4:4:4',
    // DoS caps are fully typed since v1.29 (server allowlist mirrored).
    maxInputBytes: 50 * 1024 * 1024, maxInputPixels: 50_000_000,
    maxInputWidth: 12000, maxInputHeight: 12000, maxOutputPixels: 16_777_216,
    processingTimeoutSec: 10, allowedInputFormats: ['jpeg', 'png', 'webp'],
    processingConcurrency: 4, processingQueueMax: 100, processingQueueTimeoutMs: 5000,
    blockUntrustedSharpLoaders: true, encoderEffort: 4, smartSubsample: true,
  },
  quotas: { windowMs: 3_600_000, perIp: 10_000, perViewer: 2_000, perIpImage: 500, perViewerImage: 100 },
  deploymentMode: 'single-instance',
  bindTokenTo: ['ip', 'ua'],
  authorize: async (_req, _id, { phase }) => phase === 'token',
}));
const server = http.createServer((req, res) => { void handler(req, res); });

// Typo'd quota/processing keys must now fail compilation (v1.29):
const _typoChecks: ArchxServerOptions = {
  // @ts-expect-error perViewer is the real key; perviewer silently did nothing before v1.29
  quotas: { perviewer: 500 },
  // @ts-expect-error maxInputBytes is the real key; maxInputByte silently did nothing before v1.29
  processing: { maxInputByte: 1024 },
};
void _typoChecks;

// Operations helpers (v1.29).
const _metrics: string = formatPrometheusMetrics(handler.stats());
const _health = createArchxHealthHandler(handler);
const _uninstallShutdown = installArchxShutdown({ server, handler, timeoutMs: 5000 });
const _log = createJsonEventLogger((_line: string) => {}, { service: 'archx' });
void _metrics; void _health; void _uninstallShutdown; void _log;
void server;
const auditOk: boolean = handler.configAudit.ok;
void auditOk;
const baseCacheEntries: number | undefined = handler.stats().baseCacheEntries;
void baseCacheEntries;

// --- scramble-image entry points (re-exported via /server since 1.14) ---
const derivative: Promise<ArchxDerivativeResult> = scrambleImage(bytes, { key: 'k', format: 'webp' });
void derivative;
void inspectImageMetadata(bytes);
configureSharpSecurity(['jpeg', 'png']);
const releaseLease: () => void = acquireSharpSecurityLease(['png']);
releaseLease();
const wmOk: boolean = validateWatermarkValue('CONFIDENTIAL');
void wmOk;
void detectStegoFingerprintInWorker(bytes, 8, 8, { key: 'k' });
closeStegoDetectWorker();

// --- builder + redis ---
void buildArchxAssets({
  inputDir: '/srv/masters', outputDir: '/srv/public/archx',
  key: 'k', planVersion: 2, format: 'avif',
});
void createRedisStateStore({ client: { eval: async () => 1 } });

// v1.18: strict replay saturation, fraction ceiling, ownership claims.
const claimToken: string = signOwnershipClaim(
  { owner: 'Type Smoke', imageId: 'img-1', perceptualHash: '0123456789abcdef', stegoFingerprint: '0123456789ab' },
  'not-a-real-key',
);
const verificationPromise = verifyOwnership(new Uint8Array(4), { claim: claimToken, detectOptions: { maxTimeMs: 5000 } });
const keyFingerprint: string = ownershipPublicKeyFingerprint('not-a-real-key');
void [claimToken, verificationPromise, keyFingerprint];

// v1.27: the documented deployment gate must compile. `production.ready`
// (not the base audit's config-validity `ok`) is the ship decision.
const production: ArchxProductionAudit = auditArchxProductionConfig({
  secret: 'x'.repeat(40),
  imagesDir: '/srv/masters',
});
const shipIt: boolean = production.ready;
const configValid: boolean = production.configOk;
const blockers: readonly string[] = production.blockers;
const recommendations: readonly string[] = production.recommendations;
if (!shipIt) throw new Error(`Archx production blockers: ${blockers.join('; ')}`);
void configValid; void recommendations;
const baseConfigOk: boolean = auditArchxServerConfig({ secret: 'x'.repeat(40), imagesDir: '/srv/masters' }).configOk;
void baseConfigOk;

// v1.27: lifecycle callbacks take (value, instance), and the bubbling DOM
// events + plugin surface are typed as the runtime actually dispatches them.
const wired: ArchxLoadOptions = {
  onAttempt: (kind, instance) => { void kind.startsWith('extract'); void instance.loaded; },
  onLoad: (instance) => { void instance.element; },
  onError: (error, instance) => { void error.message; void instance.destroy; },
  onClick: (event, _instance) => { void event.clientX; },
  onEvent: (event, _instance) => { void event.schemaVersion; void event.outcome; },
};
void wired;
el.addEventListener('archx-attempt', (event) => { void event.detail.kind; });
el.addEventListener('archx-error', (event) => { void event.detail.error.message; });
el.addEventListener('archx-taint-unavailable', (event) => { void event.detail.promoted; });
el.addEventListener('archx-integrity', (event) => { void event.detail.issue; });
el.addEventListener('archx-webgl-budget', (event) => { void event.detail.budget; });
const pluginHandle = Archx.use({
  name: 'smoke',
  setup: (api) => { void api.version; void api.on((event, instance) => { void event.type; void instance; }); },
  onEvent: (event, _instance) => { void event.at; },
  teardown: () => {},
});
const removed: boolean = pluginHandle.remove();
void removed;
const pluginNames: readonly string[] = Archx.plugins();
void pluginNames;
Archx.defineElement(); // fixed <archx-image> tag; takes no name argument
const customEl = document.querySelector('archx-image');
if (customEl) {
  const backing: ProtectedImage | null = customEl.inst;
  void backing;
  void customEl.ready?.then((instance) => instance.reload());
}
