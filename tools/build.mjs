#!/usr/bin/env node
/** Build dist bundles with esbuild: ESM, CJS, and a minified browser-global build. */
import { build } from 'esbuild';
import fs from 'node:fs';

fs.mkdirSync('dist', { recursive: true });

const common = {
  entryPoints: ['src/index.js'],
  bundle: true,
  sourcemap: true,
  target: ['es2020'],
  logLevel: 'info',
};

await build({ ...common, format: 'esm', outfile: 'dist/archx.esm.js' });
await build({ ...common, format: 'cjs', outfile: 'dist/archx.cjs' });
await build({
  entryPoints: ['src/browser-global.js'],
  bundle: true,
  format: 'iife',
  globalName: 'ArchxGlobal',
  minify: true,
  sourcemap: true,
  target: ['es2020'],
  outfile: 'dist/archx.min.js',
});
const size = fs.statSync('dist/archx.min.js').size;
// Keep stdout clean so lifecycle consumers such as `npm pack --json` remain machine-readable.
console.error(`\n✔ dist/archx.min.js  ${(size / 1024).toFixed(1)} kB minified`);
