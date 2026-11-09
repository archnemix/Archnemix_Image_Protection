#!/usr/bin/env node
/** Run the complete Node test suite and surface TAP failures as GitHub annotations. */
import { spawn } from 'node:child_process';

const child = spawn(process.execPath, ['--test', 'tests/unit.test.mjs', 'tests/fuzz.test.mjs'], {
  stdio: ['inherit', 'pipe', 'pipe'],
});
let output = '';
for (const stream of [child.stdout, child.stderr]) {
  stream.setEncoding('utf8');
  stream.on('data', (chunk) => {
    output += chunk;
    if (output.length > 4_000_000) output = output.slice(-2_000_000);
    (stream === child.stdout ? process.stdout : process.stderr).write(chunk);
  });
}

const code = await new Promise((resolve, reject) => {
  child.once('error', reject);
  child.once('close', (exitCode, signal) => resolve(exitCode ?? (signal ? 1 : 0)));
});
if (code !== 0) {
  const lines = output.split(/\r?\n/);
  const failureIndexes = lines.flatMap((line, i) => /^not ok \d+ - /.test(line) ? [i] : []);
  const failureBlocks = failureIndexes.map((start, index) => {
    const next = failureIndexes[index + 1] ?? lines.length;
    const end = lines.slice(start + 1, next).findIndex((line) => /^# Subtest: /.test(line));
    return lines.slice(start, end < 0 ? next : start + 1 + end).join('\n');
  });
  if (failureBlocks.length) {
    const message = failureBlocks.join('\n---\n').slice(-8000)
      .replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
    process.stdout.write(`::error title=Node test failure details::${message}\n`);
  }
}
process.exitCode = code;
