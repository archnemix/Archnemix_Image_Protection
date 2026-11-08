# Public JavaScript exports

This table is the inventory for the package's declared `exports` map in
`package.json`. Runtime behavior and option semantics are documented in the
[README](../README.md), [server operations guide](OPERATIONS.md), and the
individual API sections below. Internal `src/core/*` modules are not stable
package entry points unless explicitly re-exported here.

## `@archnemix/image-protection`

Default export: `Archx`. Named exports: `ProtectedImage`, `VERSION`, `PRESETS`,
`preset`, `DEFAULT_SOURCE_WIDTH_BUCKETS`, `TEMPORAL_INTERLACE_PROFILES`,
`normalizeTemporalInterlace`, `auditIntegrity`, `auditIntegrityDetails`,
`captureEarlyIntegritySnapshot`, `verifyEarlyIntegritySnapshot`,
`onClientEvent`, `offClientEvent`, `usePlugin`, `listPlugins`,
`detectAutomation`, and `preloadAssets`.

The root also re-exports the complete `./scramble` surface listed below.

## `@archnemix/image-protection/scramble`

Default export: none. Named exports:

- **Crypto/encoding:** `hashSeed`, `mulberry32`, `cyrb128`, `sfc32`,
  `sha256SeededPrng`, `sha256Bytes`, `hmacSha256Bytes`, `useSyncCrypto`,
  `useWebCrypto`, `generateKeyBase64`, `encryptPayload`, `decryptPayload`,
  `bytesToBase64`, `base64ToBytes`.
- **Image/container:** `DEFAULT_GRID`, `buildScramblePlan`, `tileRect`,
  `paddedSize`, `scramblePixels`, `scramblePixelsPadded`, `sniffImageInfo`,
  `sniffImageFormat`, `decodeBmpImage`, `ARCHX_MAGIC`,
  `MAX_ARCHX_HEADER_BYTES`, `validateArchxHeader`, `encodeContainer`,
  `isArchxContainer`, `useJsonParser`, `decodeContainer`.
- **Marks and forensic helpers:** `forensicBlockSigns`, `applyForensicBlocks`,
  `forensicScore`, `stegoFingerprint`, `legacyStegoFingerprint`,
  `embedStegoFingerprint`, `detectStegoFingerprint`, `assayStegoCollusion`,
  `assayStegoEmbed`.
- **Perceptual fingerprint:** `perceptualFingerprint`,
  `normalizePerceptualFingerprint`, `perceptualFingerprintDistance`,
  `comparePerceptualFingerprints`, `matchPerceptualFingerprint`.

## `@archnemix/image-protection/server`

Default export: `createArchxMiddleware`. Named exports:

`createArchxMiddleware`, `AsyncSemaphore`, `BoundedTtlSet`,
`SlidingWindowLimiter`, `createMemoryStateStore`, `DEFAULT_WIDTH_BUCKETS`,
`auditArchxProductionConfig`, `auditArchxServerConfig`,
`canonicalDerivativeWidth`, `normalizeAuthorizationResult`, `validateImageId`,
`validateWatermarkValue`, `withCatalogThroughputDefaults`,
`withHardenedProductionDefaults`, `withLiteDefaults`,
`withPerformanceDefaults`, `withEliteDefaults`, `withMaxProtectionDefaults`,
`computeJwkThumbprint`, `deriveStegoFingerprint`, `deriveStegoKey`,
`validateTokenClaims`, `formatPrometheusMetrics`,
`createArchxHealthHandler`, `installArchxShutdown`, `createJsonEventLogger`,
`scrambleImage`, `unscrambleImage`, `inspectImageMetadata`,
`prepareDerivativeBase`, `finishDerivative`, `configureSharpSecurity`,
`configureSharpPerformance`, `generateKeyBase64`,
`acquireSharpSecurityLease`, `ensureUntrustedSharpLoadersBlocked`,
`detectStegoFingerprintInWorker`, `closeStegoDetectWorker`,
`batchDetectStegoInWorker`, `configureStegoDetectWorker`,
`generateOwnershipKeyPair`, `signOwnershipClaim`, `verifyOwnershipClaim`,
`parseOwnershipClaim`, `extractOwnershipClaim`, `extractOwnershipClaims`,
`embedOwnershipMetadata`, `verifyOwnership`,
`ownershipPublicKeyFingerprint`, `loadOwnershipPrivateKey`,
`loadOwnershipPublicKey`, `createIssuanceLog`, and `verifyIssuanceChain`.

## Other declared subpaths

| Subpath | Default export | Named exports |
|---|---|---|
| `@archnemix/image-protection/server/scramble-image` | none | `generateKeyBase64`, `configureSharpSecurity`, `acquireSharpSecurityLease`, `ensureUntrustedSharpLoadersBlocked`, `configureSharpPerformance`, `inspectImageMetadata`, `prepareDerivativeBase`, `finishDerivative`, `scrambleImage`, `unscrambleImage`, `configureStegoDetectWorker`, `detectStegoFingerprintInWorker`, `batchDetectStegoInWorker`, `closeStegoDetectWorker` |
| `@archnemix/image-protection/build` | `buildArchxAssets` | `DEFAULT_ASSET_WIDTHS`, `buildArchxAssets` |
| `@archnemix/image-protection/redis` | `createRedisStateStore` | `REDIS_STATE_STORE_SCRIPTS`, `createRedisStateStore` |

The installed executables are `archx-protect`, `archx-build`, and
`archx-detect`; see the README and CLI help for their command-line interfaces.

## Declaration files

The TypeScript declaration entry points mirror the root, `server`, `build`,
`redis`, and `scramble` subpaths (`types/index.d.ts`, `types/server.d.ts`,
`types/build.d.ts`, `types/redis.d.ts`, and `types/scramble.d.ts`). These are
emitted from the typed API source under `types-src/` by `npm run types:generate`;
`npm run types:check` catches stale generated output. Edit the source declarations,
not `types/*.d.ts`. Type-only exports are not runtime JavaScript exports; their
interfaces and aliases are listed in those generated files.
