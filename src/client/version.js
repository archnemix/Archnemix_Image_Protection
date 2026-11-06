/**
 * Single source of the client version string. Kept in its own module so
 * low-level client modules (events/plugins) can report it without an
 * import cycle through the public assembly (src/archx.js).
 * Must equal package.json's version — enforced by a unit test + pack-smoke.
 */
export const VERSION = '1.30.1';
