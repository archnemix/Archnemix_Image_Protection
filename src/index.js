/** ESM entry point: re-exports the public Archx API (default export
 * plus named exports) from archx.js for bundlers and `import` users. */
import Archx, {
  ProtectedImage,
  VERSION,
  PRESETS,
  preset,
  DEFAULT_SOURCE_WIDTH_BUCKETS,
  TEMPORAL_INTERLACE_PROFILES,
  normalizeTemporalInterlace,
  auditIntegrity,
  auditIntegrityDetails,
  captureEarlyIntegritySnapshot,
  verifyEarlyIntegritySnapshot,
  onClientEvent,
  offClientEvent,
  usePlugin,
  listPlugins,
  detectAutomation,
  preloadAssets,
} from './archx.js';
export {
  ProtectedImage,
  VERSION,
  PRESETS,
  preset,
  DEFAULT_SOURCE_WIDTH_BUCKETS,
  TEMPORAL_INTERLACE_PROFILES,
  normalizeTemporalInterlace,
  auditIntegrity,
  auditIntegrityDetails,
  captureEarlyIntegritySnapshot,
  verifyEarlyIntegritySnapshot,
  onClientEvent,
  offClientEvent,
  usePlugin,
  listPlugins,
  detectAutomation,
  preloadAssets,
};
export * from './scramble.js';
export default Archx;
