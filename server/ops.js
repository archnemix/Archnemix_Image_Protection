/**
 * Operations surface (v1.29): the deployment plumbing enterprise
 * reviewers look for, as small opt-in helpers the host mounts where it
 * wants — Prometheus metrics from handler.stats(), a health/readiness
 * endpoint, graceful SIGTERM/SIGINT shutdown, and a JSON-lines event
 * logger for the onSecurityEvent/onDelivery hooks.
 *
 * Everything here is dependency-free and off the request hot path.
 * None of it exposes secrets: metrics are counters/gauges only, health
 * reports issue *counts* (mount it on an internal listener anyway),
 * and the logger drops raw IPs/viewer ids by default.
 */
import { VERSION } from '../src/client/version.js';

const isNum = (v) => typeof v === 'number' && Number.isFinite(v);
const snake = (s) => String(s).replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
const escLabel = (v) => String(v ?? '').replace(/\\|"/g, (c) => `\\${c}`).replace(/\n/g, '\\n').slice(0, 128);

// stats() fields that accumulate monotonically and are therefore
// Prometheus counters; everything else numeric is a gauge.
const COUNTER_KEYS = new Set([
  'consumedTokens', 'consumedProofs',
  'memoryHits', 'diskHits', 'sharedHits', 'misses', 'coalesced',
  'diskWrites', 'sharedWrites', 'diskPrunes', 'diskErrors',
]);

/**
 * Render handler.stats() as Prometheus text exposition. Point your
 * scraper at an authenticated route that returns this string, e.g.
 *   app.get('/metrics', requireInternal, (req, res) =>
 *     res.type('text/plain').send(formatPrometheusMetrics(handler.stats())));
 */
export function formatPrometheusMetrics(stats, { prefix = 'archx_' } = {}) {
  if (!stats || typeof stats !== 'object') throw new TypeError('Archx metrics: stats must be the object returned by handler.stats()');
  const lines = [];
  const emit = (name, value, type, help) => {
    lines.push(`# HELP ${prefix}${name} ${help}`);
    lines.push(`# TYPE ${prefix}${name} ${type}`);
    lines.push(`${prefix}${name} ${String(Math.floor(value))}`);
  };
  lines.push(`# HELP ${prefix}info Archx build/deployment info`);
  lines.push(`# TYPE ${prefix}info gauge`);
  lines.push(`${prefix}info{version="${escLabel(VERSION)}",deployment_mode="${escLabel(stats.deploymentMode)}",state_store="${escLabel(stats.stateStore)}",state_store_shared="${stats.stateStoreShared ? 'true' : 'false'}"} 1`);
  for (const [key, value] of Object.entries(stats)) {
    if (key === 'derivativeCache' || key === 'replaySets') continue;
    if (isNum(value)) emit(snake(key), value, COUNTER_KEYS.has(key) ? 'counter' : 'gauge', `handler.stats().${key}`);
  }
  const dc = stats.derivativeCache;
  if (dc && typeof dc === 'object') {
    for (const [key, value] of Object.entries(dc)) {
      if (isNum(value)) emit(`derivative_cache_${snake(key)}`, value, COUNTER_KEYS.has(key) ? 'counter' : 'gauge', `handler.stats().derivativeCache.${key}`);
    }
  }
  return lines.join('\n') + '\n';
}

/**
 * Health/readiness handler for the middleware instance. Readiness is
 * the startup config audit (secret-free): 200 when the configuration
 * is acceptable, 503 otherwise. Body exposes counts only — keep the
 * detailed audit server-side, and mount this on an internal listener.
 *   app.get('/healthz', createArchxHealthHandler(handler));
 */
export function createArchxHealthHandler(handler) {
  if (!handler || typeof handler.stats !== 'function' || !handler.configAudit) {
    throw new TypeError('Archx health: pass the handler returned by createArchxMiddleware()');
  }
  const startedAt = Date.now();
  return function archxHealthHandler(req, res) {
    const method = (req.method || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD') {
      res.writeHead(405, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', allow: 'GET, HEAD' });
      res.end(JSON.stringify({ status: 'method-not-allowed' }));
      return;
    }
    let stats = null;
    try { stats = handler.stats(); } catch { /* stats are diagnostic only */ }
    const audit = handler.configAudit || { ok: false, issues: ['audit unavailable'] };
    const ready = audit.ok === true;
    const body = {
      status: ready ? 'ok' : 'misconfigured',
      ready,
      version: VERSION,
      uptimeSeconds: Math.max(0, Math.floor((Date.now() - startedAt) / 1000)),
      configIssues: Array.isArray(audit.issues) ? audit.issues.length : 0,
      images: stats && isNum(stats.images) ? stats.images : null,
      processingActive: stats && isNum(stats.processingActive) ? stats.processingActive : null,
      processingQueued: stats && isNum(stats.processingQueued) ? stats.processingQueued : null,
    };
    res.writeHead(ready ? 200 : 503, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
    res.end(method === 'HEAD' ? undefined : JSON.stringify(body));
  };
}

/**
 * Wire graceful shutdown: on SIGTERM/SIGINT close the HTTP server (stop
 * accepting, drain in-flight), release Archx state via handler.close(),
 * then exit. A second signal — or the drain timeout — forces exit.
 * Returns an uninstall function (tests, embedded hosts).
 *   installArchxShutdown({ server, handler });
 */
export function installArchxShutdown({
  server,
  handler,
  timeoutMs = 10_000,
  signals = ['SIGTERM', 'SIGINT'],
  emitter = process,
  exit = (code) => process.exit(code),
  onShutdown = null,
} = {}) {
  if (!server || typeof server.close !== 'function') throw new TypeError('Archx shutdown: server with .close(cb) is required');
  if (!handler || typeof handler.close !== 'function') throw new TypeError('Archx shutdown: handler with .close() is required');
  let shuttingDown = false;
  const onSignal = () => {
    if (shuttingDown) { exit(1); return; }
    shuttingDown = true;
    const force = setTimeout(() => exit(1), Math.max(100, timeoutMs | 0));
    force.unref?.();
    const finish = () => { clearTimeout(force); exit(0); };
    try { onShutdown?.(); } catch { /* host hook must not block shutdown */ }
    try {
      server.close(() => {
        try { handler.close(); } catch { /* best effort */ }
        finish();
      });
    } catch {
      try { handler.close(); } catch { /* best effort */ }
      finish();
    }
  };
  for (const sig of signals) emitter.on(sig, onSignal);
  return function uninstallArchxShutdown() {
    for (const sig of signals) emitter.removeListener?.(sig, onSignal);
  };
}

const MAX_FIELD = 256;
function logSafeValue(value, depth = 0) {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value.length > MAX_FIELD ? `${value.slice(0, MAX_FIELD)}…` : value;
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.slice(0, 16).map((v) => logSafeValue(v, depth + 1));
  if (typeof value === 'object' && depth < 2) {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (typeof v === 'function' || typeof v === 'symbol') continue;
      out[k] = logSafeValue(v, depth + 1);
    }
    return out;
  }
  return String(value).slice(0, MAX_FIELD);
}

/**
 * JSON-lines structured logger for the middleware event hooks:
 *   const log = createJsonEventLogger((line) => process.stdout.write(line + '\n'));
 *   createArchxMiddleware({ ..., onSecurityEvent: log.onSecurityEvent, onDelivery: log.onDelivery });
 * Archx events are already metadata-only (never tokens/keys/paths);
 * by default this additionally drops the raw `ip`/`viewerId` fields
 * (the one-way viewerHash is kept) so log aggregation stays
 * privacy-friendlier. Never throws into the request path.
 */
export function createJsonEventLogger(write, { service = 'archx', includeRawActor = false } = {}) {
  if (typeof write !== 'function') throw new TypeError('Archx logger: write(line) function is required');
  const emit = (level, kind, event) => {
    try {
      const safe = {};
      for (const [k, v] of Object.entries(event && typeof event === 'object' ? event : {})) {
        if (!includeRawActor && (k === 'ip' || k === 'viewerId')) continue;
        if (!includeRawActor && k === 'actor' && v && typeof v === 'object') {
          const { ip: _actorIp, ...actorRest } = v;
          safe[k] = logSafeValue(actorRest);
          continue;
        }
        safe[k] = logSafeValue(v);
      }
      write(JSON.stringify({ ts: new Date().toISOString(), level, service, kind, ...safe }));
    } catch { /* logging must never alter request handling */ }
  };
  return Object.freeze({
    onSecurityEvent: (event) => emit('warn', 'security', event),
    onDelivery: (event) => emit('info', 'delivery', event),
  });
}
