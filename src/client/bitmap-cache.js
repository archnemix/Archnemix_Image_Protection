/**
 * Shared decoded-bitmap cache with byte/entry budgets and lease-based eviction (gallery memory discipline).
 */
import { DEFAULTS } from './options.js';

export let bitmapCacheBytes = 0;

export function bitmapEstimatedBytes(result) {
  const bitmap = result?.bitmap;
  const w = bitmap?.width || bitmap?.naturalWidth || result?.meta?.padW || 0;
  const h = bitmap?.height || bitmap?.naturalHeight || result?.meta?.padH || 0;
  const bytes = w * h * 4;
  return Number.isFinite(bytes) && bytes > 0 ? Math.ceil(bytes) : 0;
}

export function closeBitmapQuietly(bitmap) {
  try { bitmap?.close?.(); } catch {}
}

export function evictBitmapEntry(key, entry) {
  if (bitmapCache.get(key) === entry) bitmapCache.delete(key);
  if (entry.settled && entry.bytes) {
    bitmapCacheBytes = Math.max(0, bitmapCacheBytes - entry.bytes);
    entry.bytes = 0;
  }
  if (entry.refs <= 0 && entry.result?.bitmap) closeBitmapQuietly(entry.result.bitmap);
}

export function trimBitmapCache(maxEntries = DEFAULTS.bitmapCacheMaxEntries, maxBytes = DEFAULTS.bitmapCacheMaxBytes) {
  const entryLimit = Math.max(0, Math.floor(Number(maxEntries) || 0));
  const byteLimit = Math.max(0, Math.floor(Number(maxBytes) || 0));
  while (bitmapCache.size > entryLimit || (byteLimit > 0 && bitmapCacheBytes > byteLimit)) {
    const oldest = bitmapCache.keys().next().value;
    if (oldest === undefined) break;
    evictBitmapEntry(oldest, bitmapCache.get(oldest));
  }
}

export function cachePut(key, promise, opts = {}) {
  const existing = bitmapCache.get(key);
  if (existing?.promise === promise) return existing;
  if (existing) evictBitmapEntry(key, existing);
  const entry = { key, promise, result: null, refs: 1, bytes: 0, settled: false };
  bitmapCache.set(key, entry);
  promise.then((result) => {
    entry.result = result;
    entry.settled = true;
    entry.bytes = bitmapEstimatedBytes(result);
    if (bitmapCache.get(key) === entry) {
      bitmapCacheBytes += entry.bytes;
      trimBitmapCache(opts.bitmapCacheMaxEntries, opts.bitmapCacheMaxBytes);
    } else if (entry.refs <= 0) closeBitmapQuietly(result?.bitmap);
  }, () => {
    entry.settled = true;
    entry.refs = 0;
    if (bitmapCache.get(key) === entry) bitmapCache.delete(key);
  });
  trimBitmapCache(opts.bitmapCacheMaxEntries, opts.bitmapCacheMaxBytes);
  return entry;
}

export function cacheGetEntry(key, { acquire = false } = {}) {
  const entry = bitmapCache.get(key);
  if (!entry) return null;
  bitmapCache.delete(key); bitmapCache.set(key, entry);
  if (acquire) entry.refs++;
  return entry;
}

export function cacheReleaseEntry(entry) {
  if (!entry) return;
  entry.refs = Math.max(0, entry.refs - 1);
  if (entry.refs <= 0 && bitmapCache.get(entry.key) !== entry && entry.result?.bitmap) {
    closeBitmapQuietly(entry.result.bitmap);
  }
}

export function clearBitmapCache() {
  for (const [key, entry] of [...bitmapCache]) evictBitmapEntry(key, entry);
  bitmapCache.clear();
  bitmapCacheBytes = 0;
}

/* ---------- shared observers */
export const bitmapCache = new Map(); // digest -> { promise, result, refs, bytes, settled }
