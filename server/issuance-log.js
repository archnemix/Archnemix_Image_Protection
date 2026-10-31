/**
 * Tamper-evident issuance log (v1.19).
 *
 * Attribution is only as strong as the registry that maps a detected
 * fingerprint back to a delivery. A plain database table can be
 * edited after the fact ("we never issued that copy to them") — by
 * an insider, a compromised host, or an honest mistake. This log
 * hash-chains every issuance record:
 *
 *   mac[i] = HMAC-SHA256(secret, mac[i-1] || canonical(entry[i]))
 *
 * Editing, deleting, or reordering any historical entry breaks the
 * chain at that point and is detectable by anyone holding the log
 * secret (kept separately from the database, like the token secret).
 * It is NOT a blockchain and proves nothing about wall-clock time;
 * anchor periodic heads externally (email, git commit, timestamping
 * service) if you need time evidence. Pair it with the record schema
 * in docs/IP_HOLDER_GUIDE.md.
 */
import crypto from 'node:crypto';

const GENESIS = 'archx-issuance-genesis:v1';
const MAX_RECORD_BYTES = 16 * 1024;

function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
}

function entryMac(secret, prev, seq, ts, record) {
  return crypto.createHmac('sha256', secret)
    .update(prev)
    .update('\n')
    .update(canonicalize({ seq, ts, record }))
    .digest('hex');
}

function assertSecret(secret) {
  const bytes = Buffer.isBuffer(secret) ? secret
    : typeof secret === 'string' ? Buffer.byteLength(secret, 'utf8') : 0;
  if (!bytes || bytes < 16) {
    throw new TypeError('Archx issuance log: secret must be at least 16 bytes (store it separately from the log data)');
  }
}

/**
 * Create an append-only issuance log. Persistence is the host's job:
 * store `entries()` wherever you keep records, reload with
 * `createIssuanceLog({ secret, entries })` (the chain is verified on
 * load and a broken chain throws unless `allowBroken: true`).
 */
export function createIssuanceLog({ secret, entries = [], allowBroken = false, now = () => new Date().toISOString() } = {}) {
  assertSecret(secret);
  if (!Array.isArray(entries)) throw new TypeError('Archx issuance log: entries must be an array');
  const chain = entries.map((entry) => Object.freeze({ ...entry }));
  const check = verifyIssuanceChain(chain, secret);
  if (!check.ok && !allowBroken) {
    throw new Error(`Archx issuance log: chain verification failed at entry ${check.badIndex} (${check.reason})`);
  }
  return Object.freeze({
    append(record) {
      if (!record || typeof record !== 'object' || Array.isArray(record)) {
        throw new TypeError('Archx issuance log: record must be a plain object');
      }
      const encoded = canonicalize(record);
      if (Buffer.byteLength(encoded, 'utf8') > MAX_RECORD_BYTES) {
        throw new TypeError(`Archx issuance log: record exceeds ${MAX_RECORD_BYTES} bytes when canonicalized`);
      }
      const seq = chain.length;
      const prev = seq ? chain[seq - 1].mac : GENESIS;
      const ts = now();
      const entry = Object.freeze({ seq, ts, record: JSON.parse(encoded), prev, mac: entryMac(secret, prev, seq, ts, record) });
      chain.push(entry);
      return entry;
    },
    entries() { return [...chain]; },
    head() { return chain.length ? chain[chain.length - 1].mac : GENESIS; },
    verify() { return verifyIssuanceChain(chain, secret); },
    get size() { return chain.length; },
  });
}

/** Verify a serialized chain without constructing a log. */
export function verifyIssuanceChain(entries, secret) {
  assertSecret(secret);
  if (!Array.isArray(entries)) return { ok: false, badIndex: 0, reason: 'not-an-array' };
  let prev = GENESIS;
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    if (!entry || entry.seq !== i || entry.prev !== prev || typeof entry.mac !== 'string') {
      return { ok: false, badIndex: i, reason: 'sequence-or-link-mismatch' };
    }
    const expected = entryMac(secret, prev, entry.seq, entry.ts, entry.record);
    const given = Buffer.from(entry.mac, 'hex');
    const want = Buffer.from(expected, 'hex');
    if (given.length !== want.length || !crypto.timingSafeEqual(given, want)) {
      return { ok: false, badIndex: i, reason: 'mac-mismatch' };
    }
    prev = entry.mac;
  }
  return { ok: true, badIndex: -1, reason: null, head: prev };
}
