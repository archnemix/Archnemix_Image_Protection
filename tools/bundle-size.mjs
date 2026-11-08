#!/usr/bin/env node
/** Reproducible browser artifact measurement: pure-JS fflate, fixed gzip level 9. */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'fflate';

export const GZIP_LEVEL = 9;
export const GZIP_BUDGET_BYTES = 52 * 1024;

export function measureBrowserBundle(file = path.resolve('dist/archx.min.js')) {
  const bytes = fs.readFileSync(file);
  const gzipped = gzipSync(bytes, { level: GZIP_LEVEL, mtime: 0 });
  return Object.freeze({
    minifiedBytes: bytes.length,
    gzippedBytes: gzipped.length,
    minifiedKiB: (bytes.length / 1024).toFixed(1),
    gzippedKiB: (gzipped.length / 1024).toFixed(1),
    gzipLevel: GZIP_LEVEL,
    budgetBytes: GZIP_BUDGET_BYTES,
    withinBudget: gzipped.length <= GZIP_BUDGET_BYTES,
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = measureBrowserBundle();
  console.log(`Browser bundle: ${result.minifiedBytes} bytes (${result.minifiedKiB} KiB) minified; ${result.gzippedBytes} bytes (${result.gzippedKiB} KiB) gzip level ${result.gzipLevel} via pinned fflate; budget ${result.budgetBytes} bytes.`);
  if (!result.withinBudget) process.exitCode = 1;
}
