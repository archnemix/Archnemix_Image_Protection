/**
 * Sanitized monitoring/plugin event bus. Events never carry tokens, keys, pixels, or raw errors.
 */
/*
 * Monitoring/plugin extension points.
 *
 * Plugins and global listeners receive only a frozen, sanitized event:
 * event type, timestamp, mode, and coarse outcome/reason. They never receive
 * a token response, token, scramble key, AES key, proof, source object,
 * canvas, bitmap, image bytes, or raw error object. This makes the hook safe
 * to forward to analytics/monitoring/reverse-image-search workflows without
 * creating a new key-leak channel. Listener failures are swallowed so a
 * monitoring bug cannot change image authorization or rendering policy.
 */
export const globalEventListeners = new Set();
export const installedPlugins = new Map();

export function sanitizeClientEvent(type, details = {}, instance = null) {
  let mode = null;
  try { mode = instance?.options?.requestedMode || instance?.options?.mode || null; } catch {}
  const cleanText = (value, max = 160) => {
    if (value == null) return null;
    const text = String(value).replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, max);
    return text || null;
  };
  return Object.freeze({
    schemaVersion: 1,
    service: 'archx-client',
    type: cleanText(type, 80) || 'archx.event',
    at: new Date().toISOString(),
    mode: cleanText(mode, 32),
    kind: cleanText(details.kind, 120),
    reason: cleanText(details.reason, 160),
    outcome: cleanText(details.outcome, 48),
    issues: Array.isArray(details.issues)
      ? Object.freeze(details.issues.slice(0, 40).map((issue) => cleanText(issue, 120)).filter(Boolean))
      : null,
  });
}

export function emitClientEvent(type, details = {}, instance = null) {
  const event = sanitizeClientEvent(type, details, instance);
  const invoke = (listener) => {
    try {
      const result = listener(event, instance);
      if (result && typeof result.catch === 'function') result.catch(() => {});
    } catch { /* monitoring must never alter rendering/authorization */ }
  };
  for (const listener of [...globalEventListeners]) invoke(listener);
  for (const plugin of installedPlugins.values()) {
    if (typeof plugin.onEvent === 'function') invoke(plugin.onEvent);
  }
  try {
    const perInstance = instance?.options?.onEvent;
    if (typeof perInstance === 'function') invoke(perInstance);
  } catch {}
  return event;
}

/** Subscribe to sanitized client telemetry. Returns an unsubscribe function. */
export function onClientEvent(listener) {
  if (typeof listener !== 'function') throw new TypeError('Archx.on: listener must be a function');
  globalEventListeners.add(listener);
  return () => { globalEventListeners.delete(listener); };
}

/** Remove a global sanitized-telemetry listener previously passed to Archx.on(). */
export function offClientEvent(listener) {
  return globalEventListeners.delete(listener);
}

/**
 * Install a monitoring/integration plugin. Supported plugin surface:
 * `{ name, onEvent(event, instance), setup(api), teardown() }`.
 * `setup` receives only { on, off, version }—not instance internals.
 */
export function usePlugin(plugin) {
  if (!plugin || typeof plugin !== 'object') throw new TypeError('Archx.use: plugin must be an object');
  const name = typeof plugin.name === 'string' && plugin.name.trim()
    ? plugin.name.trim().slice(0, 80)
    : `plugin-${installedPlugins.size + 1}`;
  if (plugin.onEvent !== undefined && typeof plugin.onEvent !== 'function') {
    throw new TypeError('Archx.use: plugin.onEvent must be a function when supplied');
  }
  if (plugin.setup !== undefined && typeof plugin.setup !== 'function') {
    throw new TypeError('Archx.use: plugin.setup must be a function when supplied');
  }
  if (plugin.teardown !== undefined && typeof plugin.teardown !== 'function') {
    throw new TypeError('Archx.use: plugin.teardown must be a function when supplied');
  }
  const previous = installedPlugins.get(name);
  if (previous?.teardown) {
    try { previous.teardown(); } catch {}
  }
  const record = Object.freeze({ name, onEvent: plugin.onEvent || null, teardown: plugin.teardown || null });
  installedPlugins.set(name, record);
  if (typeof plugin.setup === 'function') {
    try {
      plugin.setup(Object.freeze({ on: onClientEvent, off: offClientEvent, version: VERSION }));
    } catch {
      installedPlugins.delete(name);
      throw new Error(`Archx.use: plugin "${name}" setup failed`);
    }
  }
  emitClientEvent('archx.plugin_installed', { kind: name, outcome: 'installed' });
  return Object.freeze({
    name,
    remove() {
      const current = installedPlugins.get(name);
      if (!current) return false;
      installedPlugins.delete(name);
      try { current.teardown?.(); } catch {}
      return true;
    },
  });
}

export function listPlugins() {
  return Object.freeze([...installedPlugins.keys()]);
}
