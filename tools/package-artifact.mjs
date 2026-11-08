#!/usr/bin/env node
/** Temporarily strip repository-only npm scripts from the packed artifact.
 * `npm pack` runs postpack to restore the exact checkout manifest afterward.
 */
import fs from 'node:fs';

const manifestPath = new URL('../package.json', import.meta.url);
const backupPath = new URL('../.archx-package-artifact-backup', import.meta.url);
const action = process.argv[2];
if (action === 'sanitize') {
  if (fs.existsSync(backupPath)) {
    fs.copyFileSync(backupPath, manifestPath);
    fs.rmSync(backupPath, { force: true });
  }
  const original = fs.readFileSync(manifestPath);
  fs.writeFileSync(backupPath, original, { flag: 'wx' });
  const manifest = JSON.parse(original.toString('utf8'));
  manifest.scripts = {};
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
} else if (action === 'restore') {
  if (fs.existsSync(backupPath)) {
    fs.copyFileSync(backupPath, manifestPath);
    fs.rmSync(backupPath, { force: true });
  }
} else {
  console.error('Usage: node tools/package-artifact.mjs <sanitize|restore>');
  process.exitCode = 2;
}
