/**
 * Compile-time smoke test for the shipped type declarations.
 * Checked by `npm run test:types` (tsc --noEmit); never executed.
 */
import http from 'node:http';
import Archx, {
  buildScramblePlan, decodeContainer, detectStegoFingerprint, preset,
  type ArchxLoadOptions, type ProtectedImage,
} from '../types/index.js';
import { createArchxMiddleware, withHardenedProductionDefaults } from '../types/server.js';
import { buildArchxAssets } from '../types/build.js';
import { createRedisStateStore } from '../types/redis.js';
import {
  scramblePixelsPadded, useJsonParser,
  sha256Bytes, hmacSha256Bytes, useWebCrypto, embedStegoFingerprint,
} from '../types/scramble.js';

// --- client ---
const options: ArchxLoadOptions = {
  mode: 'fortress',
  planVersion: 2,
  taintReadback: 'auto',
  tokenEndpoint: '/archx/token/',
  temporalInterlace: { engine: 'shader', layout: 'pixels', phases: 2, targetHz: 60 },
};
declare const el: HTMLElement;
const view: ProtectedImage = Archx.load.image(el, { imageId: 'cat' }, options);
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
const layoutVintage: 0 | 1 | 2 = detection.layoutVersion;
void layoutVintage;
const found: boolean = detection.found;
const mirrored: boolean | undefined = detection.mirrored;
const tagScheme: 'mac' | 'crc' | null = detection.tagScheme;
void found; void mirrored; void tagScheme;
useJsonParser(JSON.parse);

// v1.12 core additions
const digest: Uint8Array = sha256Bytes(bytes);
const mac: Uint8Array = hmacSha256Bytes(bytes, digest);
void mac;
useWebCrypto(null);
useWebCrypto({ subtle: {}, getRandomValues: (a: Uint8Array) => a });
const marked: Uint8Array = embedStegoFingerprint(bytes, 8, 8, 'buyer-42', { key: 'k', legacyCode: true, layoutVersion: 1 });
void marked;

// --- server ---
const handler = createArchxMiddleware(withHardenedProductionDefaults({
  secret: 'x'.repeat(40),
  imagesDir: '/srv/masters',
  scramblePlanVersion: 2,
  format: 'avif',
  steganography: { scope: 'viewer', keyScope: 'viewer', profile: 'robust' },
  authorize: async (_req, _id, { phase }) => phase === 'token',
}));
const server = http.createServer((req, res) => { void handler(req, res); });
void server;
const auditOk: boolean = handler.configAudit.ok;
void auditOk;
const baseCacheEntries: number | undefined = handler.stats().baseCacheEntries;
void baseCacheEntries;

// --- builder + redis ---
void buildArchxAssets({
  inputDir: '/srv/masters', outputDir: '/srv/public/archx',
  key: 'k', planVersion: 2, format: 'avif',
});
void createRedisStateStore({ client: { eval: async () => 1 } });
