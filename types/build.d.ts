/**
 * Archx static asset builder: precompute scrambled (optionally encrypted)
 * `.archx` derivatives + a hash-pinnable manifest for CDN hosting.
 */
import type { ArchxFormat, ArchxProcessingOptions } from './server.js';

export const DEFAULT_ASSET_WIDTHS: readonly number[];

export interface ArchxAssetVariant {
  file: string;
  url?: string;
  width: number;
  sha256?: string | null;
  mime?: string | null;
}

export interface ArchxAssetEntry {
  id: string;
  width: number;
  height: number;
  key: string;
  grid: number;
  /** Present only when built with planVersion: 2. */
  planVersion?: 2;
  aesKey?: string;
  perceptualFingerprint?: string;
  variants: ArchxAssetVariant[];
}

export interface ArchxAssetManifest {
  version: 1;
  assets: Record<string, ArchxAssetEntry>;
}

export interface ArchxBuildContext {
  id: string;
  width: number;
  sourceWidth: number;
  sourceHeight: number;
}

export type ArchxDynamicValue<T> = T | ((context: ArchxBuildContext) => T | Promise<T>);

export interface ArchxBuildOptions {
  inputDir: string;
  outputDir: string;
  manifestPath?: string;
  statePath?: string;
  baseUrl?: string;
  widths?: number[];
  maxWidth?: number;
  grid?: number;
  /** 1 = legacy 32-bit plan seed, 2 = 128-bit seed (needs a pv-aware client). */
  planVersion?: 1 | 2;
  key: string;
  aesKey?: string | null;
  quality?: number | 'lossless';
  lossless?: boolean;
  format?: ArchxFormat;
  jobs?: number;
  clean?: boolean;
  watermark?: ArchxDynamicValue<string | null>;
  forensicSeed?: ArchxDynamicValue<string | null>;
  forensic?: Record<string, unknown>;
  stegoPayload?: ArchxDynamicValue<string | null>;
  stegoKey?: string;
  stegoStrength?: number;
  stegoProfile?: 'standard' | 'robust';
  steganography?: Record<string, unknown> | null;
  contentFingerprint?: boolean;
  processing?: ArchxProcessingOptions;
  [key: string]: unknown;
}

export interface ArchxBuildSummary {
  manifest: ArchxAssetManifest;
  /** SHA-256 of the exact manifest bytes; pin client-side via `assetManifestIntegrity`. */
  manifestSha256: string;
  manifestPath: string;
  statePath: string;
  assets: number;
  variants: number;
  generated: number;
  skipped: number;
  removed: number;
  totalBytes: number;
}

export function buildArchxAssets(options: ArchxBuildOptions): Promise<ArchxBuildSummary>;
export default buildArchxAssets;
