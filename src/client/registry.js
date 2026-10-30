/**
 * Live-instance registry (WeakMap host lookup — no public DOM expando) (the page-session id lives in options.js, next to the config it reads).
 */

/* Host -> instance lookup WITHOUT stamping an expando on a public DOM node:
 * `element.__archx` would hand any page script/extension a direct handle to
 * our internals. A module-private WeakMap gives no such handle. */
export const instances = new Set();
export const hostToInstance = new WeakMap();
