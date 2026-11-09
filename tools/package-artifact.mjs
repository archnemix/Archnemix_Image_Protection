#!/usr/bin/env node
/** Temporarily strip repository-only npm scripts from the packed artifact.
 * `npm pack` runs postpack to restore the exact checkout manifest afterward.
 */
import fs from 'node:fs';

const manifestPath = new URL('../package.json', import.meta.url);
const backupPath = new URL('../.archx-package-artifact-backup', import.meta.url);
function restoreManifestIfBackedUp() {
  let fd;
  try {
    const noFollow = fs.constants.O_NOFOLLOW ?? 0;
    fd = fs.openSync(backupPath, fs.constants.O_RDONLY | noFollow);
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
  let original;
  try {
    if (!fs.fstatSync(fd).isFile()) throw new Error('package artifact backup is not a regular file');
    original = fs.readFileSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.writeFileSync(manifestPath, original);
  fs.rmSync(backupPath, { force: true });
  return true;
}

const action = process.argv[2];
if (action === 'sanitize') {
  restoreManifestIfBackedUp();
  const original = fs.readFileSync(manifestPath);
  fs.writeFileSync(backupPath, original, { flag: 'wx', mode: 0o600 });
  const manifest = JSON.parse(original.toString('utf8'));
  manifest.scripts = {};
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
} else if (action === 'restore') {
  restoreManifestIfBackedUp();
} else {
  console.error('Usage: node tools/package-artifact.mjs <sanitize|restore>');
  process.exitCode = 2;
}
