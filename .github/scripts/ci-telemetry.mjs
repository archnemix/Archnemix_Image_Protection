#!/usr/bin/env node
import { spawnSync } from 'node:child_process';
import os from 'node:os';

const label = process.argv[2] || 'step';
const cmdArgs = process.argv.slice(3);
if (!cmdArgs.length) {
  console.error('Usage: node .github/scripts/ci-telemetry.mjs <label> <command...>');
  process.exit(2);
}

function cpuTotals() {
  const cpus = os.cpus();
  let idle = 0;
  let total = 0;
  for (const cpu of cpus) {
    idle += cpu.times.idle;
    total += cpu.times.user + cpu.times.nice + cpu.times.sys + cpu.times.irq + cpu.times.idle;
  }
  return { idle, total, count: cpus.length, model: cpus[0]?.model?.trim() || 'unknown' };
}

const beforeCpu = cpuTotals();
const beforeFreeMb = Math.round(os.freemem() / (1024 * 1024));
const totalMemMb = Math.round(os.totalmem() / (1024 * 1024));
const t0 = performance.now();

let exitCode = 1;
let childRusage = null;

if (process.platform !== 'win32') {
  const py = [
    'import json, os, resource, subprocess, sys',
    'p = subprocess.run(sys.argv[1:])',
    'ru = resource.getrusage(resource.RUSAGE_CHILDREN)',
    'sys.stderr.write("__ARCHX_RU__" + json.dumps({"user": ru.ru_utime, "sys": ru.ru_stime, "maxRssKb": ru.ru_maxrss}) + "\\n")',
    'sys.exit(p.returncode)',
  ].join('\n');
  const res = spawnSync('python3', ['-c', py, ...cmdArgs], { stdio: ['inherit', 'inherit', 'pipe'], encoding: 'utf8' });
  if (res.error) {
    const fallback = spawnSync(cmdArgs[0], cmdArgs.slice(1), { stdio: 'inherit', shell: true });
    exitCode = fallback.status ?? 1;
  } else {
    const lines = (res.stderr || '').split(/\r?\n/);
    const filtered = [];
    for (const line of lines) {
      if (line.startsWith('__ARCHX_RU__')) {
        try { childRusage = JSON.parse(line.slice('__ARCHX_RU__'.length)); } catch {}
      } else if (line) {
        filtered.push(line);
      }
    }
    if (filtered.length) process.stderr.write(filtered.join('\n') + '\n');
    exitCode = res.status ?? 1;
  }
} else {
  const res = spawnSync(cmdArgs.join(' '), { stdio: 'inherit', shell: true });
  exitCode = res.status ?? 1;
}

const wallSec = (performance.now() - t0) / 1000;
const afterCpu = cpuTotals();
const afterFreeMb = Math.round(os.freemem() / (1024 * 1024));
const dTotal = Math.max(1, afterCpu.total - beforeCpu.total);
const dIdle = Math.max(0, afterCpu.idle - beforeCpu.idle);
const hostCpuPct = ((1 - dIdle / dTotal) * 100).toFixed(1);

const parts = [
  `step=${label}`,
  `os=${process.platform}/${process.arch}(${os.release()})`,
  `node=${process.version}`,
  `cpu="${beforeCpu.model}"x${beforeCpu.count}`,
  `ram=${totalMemMb}MiB(free:${beforeFreeMb}->${afterFreeMb}MiB)`,
  `wall=${wallSec.toFixed(2)}s`,
  `hostCpu=${hostCpuPct}%`,
];
if (childRusage) {
  const procPct = wallSec > 0 ? (((childRusage.user + childRusage.sys) / wallSec) * 100).toFixed(1) : '0.0';
  parts.push(`user=${childRusage.user.toFixed(2)}s`, `sys=${childRusage.sys.toFixed(2)}s`, `procCpu=${procPct}%`, `maxRss=${(childRusage.maxRssKb / 1024).toFixed(1)}MiB`);
}
parts.push(`exit=${exitCode}`);
const summary = parts.join(' | ');
console.log(`\n[CI telemetry] ${summary}`);
console.log(`::notice title=CI Telemetry (${label})::${summary}`);
process.exit(exitCode);
