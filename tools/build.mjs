#!/usr/bin/env node
/** Build dist bundles with esbuild: ESM, CJS, and a minified browser-global build. */
import { build } from 'esbuild';
import crypto from 'node:crypto';
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
// Read the bundle once: size and SRI both describe these exact bytes.
const minified = fs.readFileSync('dist/archx.min.js');
// Keep stdout clean so lifecycle consumers such as `npm pack --json` remain machine-readable.
console.error(`\n✔ dist/archx.min.js  ${(minified.length / 1024).toFixed(1)} kB minified`);
// Subresource Integrity pin for sites that serve the browser bundle from a
// CDN: <script src="…/archx.min.js" integrity="sha384-…" crossorigin="anonymous">
const sri = `sha384-${crypto.createHash('sha384').update(minified).digest('base64')}`;
fs.writeFileSync('dist/archx.min.js.sri', `${sri}\n`);
console.error(`✔ dist/archx.min.js.sri  ${sri}`);
