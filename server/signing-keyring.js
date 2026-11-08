/**
 * Mutable signing-key state for scheduled rotations. The middleware calls
 * refreshSigningKey at request/mint boundaries so every instance observes
 * the same configured UTC transition without relying on process timers.
 */
export function createSigningKeyring({ signingKeys: configuredKeys, activeSecretId, schedule }) {
  const signingKeys = { ...configuredKeys };
  let activeId = activeSecretId;
  let activeSecret = signingKeys[activeId];
  let cacheTagKeys = [...new Set([activeSecret, ...Object.values(signingKeys)])].slice(0, 17);

  const refreshSigningKey = (now = Date.now()) => {
    if (!schedule) return;
    if (now >= schedule.activateAtMs) {
      activeId = schedule.activateSecretId;
      activeSecret = signingKeys[activeId];
    }
    if (now >= schedule.retireAtMs && schedule.retireSecretId !== activeId &&
        Object.hasOwn(signingKeys, schedule.retireSecretId)) {
      delete signingKeys[schedule.retireSecretId];
      cacheTagKeys = Object.values(signingKeys).slice(0, 16);
    }
  };

  return Object.freeze({
    signingKeys,
    refreshSigningKey,
    get activeSecretId() { return activeId; },
    get secret() { return activeSecret; },
    get cacheTagSecrets() { return cacheTagKeys; },
  });
}
