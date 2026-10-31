#!/usr/bin/env node
/**
 * Fast syntax gate: run `node --check` over every shipped and test source
 * file. Catches quoting/escaping damage from scripted edits in seconds,
 * before the full unit/browser suites run. No style rules — syntax only.
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const files = [];
function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory() && entry.name === 'vendor') continue; // third-party, as-shipped
    if (entry.isDirectory()) walk(full);
    else if (entry.isFile() && /\.(?:js|mjs|cjs)$/.test(entry.name)) files.push(full);
  }
}
for (const dir of ['src', 'server', 'tools', 'tests', 'website']) {
  const abs = path.join(root, dir);
  if (fs.existsSync(abs)) walk(abs);
}

const failures = [];
for (const file of files.sort()) {
  try {
    execFileSync(process.execPath, ['--check', file], { stdio: 'pipe' });
  } catch (err) {
    failures.push({ file: path.relative(root, file), message: String(err.stderr || err.message) });
  }
}

if (failures.length) {
  for (const failure of failures) {
    console.error(`\n✘ ${failure.file}\n${failure.message.trim()}`);
  }
  console.error(`\nSyntax check failed for ${failures.length}/${files.length} file(s).`);
  process.exit(1);
}
console.log(`✔ syntax OK (${files.length} files)`);
