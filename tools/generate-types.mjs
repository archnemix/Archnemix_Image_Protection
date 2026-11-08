#!/usr/bin/env node
/** Generate package declaration files from the typed API source in types-src/. */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const check = process.argv.includes('--check');
const temp = check ? fs.mkdtempSync(path.join(os.tmpdir(), 'archx-types-')) : null;
const outputDir = temp || path.join(root, 'types');
const tsc = path.join(root, 'node_modules', 'typescript', 'bin', 'tsc');
const result = spawnSync(process.execPath, [tsc, '-p', path.join(root, 'tsconfig.types.json'), '--outDir', outputDir], {
  cwd: root, encoding: 'utf8', stdio: 'pipe',
});
if (result.status !== 0) {
  if (result.stdout) process.stderr.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  process.exit(result.status ?? 1);
}
const generated = fs.readdirSync(outputDir).filter((name) => name.endsWith('.d.ts')).sort();
if (!generated.length) throw new Error('TypeScript emitted no declaration files');
if (check) {
  const currentDir = path.join(root, 'types');
  const current = fs.readdirSync(currentDir).filter((name) => name.endsWith('.d.ts')).sort();
  const mismatches = [...new Set([...generated, ...current])].filter((name) =>
    !generated.includes(name) || !current.includes(name) ||
    fs.readFileSync(path.join(outputDir, name), 'utf8') !== fs.readFileSync(path.join(currentDir, name), 'utf8'));
  fs.rmSync(temp, { recursive: true, force: true });
  if (mismatches.length) {
    console.error(`Generated declarations are stale: ${mismatches.join(', ')}. Run npm run types:generate.`);
    process.exit(1);
  }
  console.log(`Generated declarations current (${generated.length} files).`);
} else {
  console.log(`Generated ${generated.length} declaration files from types-src/.`);
}
