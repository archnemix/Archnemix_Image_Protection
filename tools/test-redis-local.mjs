#!/usr/bin/env node
/**
 * Run the real-Redis integration suite against an isolated local server.
 * Requires Redis Server >= 6.0 installed on PATH, or REDIS_SERVER_BIN set.
 * The temporary server binds only to 127.0.0.1 and disables persistence.
 */
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const redisBin = process.env.REDIS_SERVER_BIN || 'redis-server';
const probe = spawnSync(redisBin, ['--version'], { encoding: 'utf8' });
if (probe.error || probe.status !== 0) {
  console.error(`Could not run "${redisBin} --version". Install Redis Server >= 6.0, or set REDIS_SERVER_BIN to its executable path.`);
  process.exit(1);
}
const versionText = `${probe.stdout || ''} ${probe.stderr || ''}`;
const version = versionText.match(/\bv=(\d+)\.(\d+)(?:\.(\d+))?/);
if (!version || Number(version[1]) < 6) {
  console.error(`Redis Server >= 6.0 is required for the ioredis 6 protocol test; detected: ${versionText.trim() || 'unknown version'}`);
  process.exit(1);
}

function reservePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

function tcpReady(port) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    const finish = (ready) => { socket.destroy(); resolve(ready); };
    socket.setTimeout(400, () => finish(false));
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
  });
}

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'archx-redis-test-'));
let redis;
let testExit = 1;
try {
  const port = await reservePort();
  const url = `redis://127.0.0.1:${port}`;
  redis = spawn(redisBin, [
    '--bind', '127.0.0.1',
    '--port', String(port),
    '--protected-mode', 'yes',
    '--save', '',
    '--appendonly', 'no',
    '--daemonize', 'no',
    '--loglevel', 'warning',
    '--dir', tempDir,
  ], { stdio: 'ignore' });
  redis.once('error', (error) => console.error(`Could not start local Redis server: ${error.message}`));

  const deadline = Date.now() + 15000;
  let ready = false;
  while (Date.now() < deadline) {
    if (redis.exitCode !== null) throw new Error(`redis-server exited during startup (code ${redis.exitCode})`);
    if (await tcpReady(port)) { ready = true; break; }
    await wait(100);
  }
  if (!ready) throw new Error('redis-server did not accept a loopback connection within 15 seconds');

  console.log(`Running the real-Redis integration test against Redis ${version[1]}.${version[2]} at ${url}`);
  const test = spawn(process.execPath, ['--test', 'tests/redis-integration.test.mjs'], {
    cwd: root,
    env: { ...process.env, ARCHX_TEST_REDIS_URL: url },
    stdio: 'inherit',
  });
  testExit = await new Promise((resolve, reject) => {
    test.once('error', reject);
    test.once('exit', (code, signal) => resolve(code ?? (signal ? 1 : 0)));
  });
} catch (error) {
  console.error(`Local Redis integration setup failed: ${error.message}`);
} finally {
  if (redis && redis.exitCode === null) {
    redis.kill('SIGTERM');
    await Promise.race([
      new Promise((resolve) => redis.once('exit', resolve)),
      wait(3000),
    ]);
    if (redis.exitCode === null) {
      redis.kill('SIGKILL');
      await new Promise((resolve) => redis.once('exit', resolve));
    }
  }
  fs.rmSync(tempDir, { recursive: true, force: true });
}
process.exitCode = testExit;
