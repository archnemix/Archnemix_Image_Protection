/**
 * StegoMark code layer: fingerprints, CRC/MAC-tagged codewords, and
 * the keyed cell layouts shared verbatim by embedder and detector.
 * SHIPPED BIT FORMATS ARE FROZEN — new layouts get new versions.
 */
import { utf8Encode } from './bytes.js';
import { bchEncode64, bchDecode188, bchSolveObserved, bchOsdSolve, bchIsdSolve, BCH_CODE_BITS } from './bch.js';
import { sha256Bytes, hmacSha256Bytes, hashSeed, mulberry32, cyrb128, sfc32, sha256SeededPrng } from './crypto.js';

/**
 * Archx StegoMark: a keyed, redundant, *blindly decodable* payload hidden in
 * delivered pixels. It complements (not replaces) the reference-based
 * forensic blocks above: the owner can feed a suspect screenshot/export to
 * `detectStegoFingerprint()` / `archx-detect` and recover a 48-bit
 * fingerprint identifying the image / viewer / token — no original needed.
 *
 * Scheme: the image is divided into a macro-cell grid (default 24×16).
 * A 64-bit codeword (48-bit fingerprint + CRC-16) is assigned to cells via a
 * keyed permutation, so every code bit is repeated across several cells and
 * survives local cropping/damage. Each cell encodes its bit as a 4-band
 * alternating luminance pattern (+−+− vs −+−+), sign-flipped by a keyed
 * per-cell polarity and broken into four short row segments with keyed signs
 * so the mark does not form long, visible vertical stripes. Detection uses a
 * third-difference of each segment's band means, which cancels smooth image
 * content (gradients) while responding to the embedded alternation, then
 * soft-votes across repetitions and checks CRC.
 *
 * Honest limits: this is classical spread-spectrum-style marking, not a
 * neural Light Field Messaging system. It is designed to survive ordinary
 * re-encoding, mild resizing and screenshots well enough to *attribute*
 * copies; determined denoising / diffusion regeneration can weaken or
 * remove it. Treat a positive decode as evidence, not as DRM.
 */
export function stegoFingerprint(value) {
  const s = String(value ?? '');
  if (/^[0-9a-fA-F]{12}$/.test(s)) return s.toLowerCase();
  // SHA-256 (first 6 bytes), not the cyrb53 pair used before 1.13: the
  // payload->ID map gets full avalanche, so near-identical payloads no
  // longer land in correlated ID neighborhoods. Only NEW embeds see new
  // IDs for non-hex payloads — bits already in pixels are extracted
  // as-is at detection, so issued registries stay valid.
  const digest = sha256Bytes(utf8Encode('archx-stego-fp-v2:' + s));
  let hex = '';
  for (let i = 0; i < 6; i++) hex += digest[i].toString(16).padStart(2, '0');
  return hex;
}

/**
 * Pre-1.13 payload→fingerprint derivation (paired cyrb53 hashes), kept
 * so identity-string lookups against marks embedded before 1.13 still
 * resolve. Registries that stored the issued fingerprint never need
 * this; 12-hex payloads pass through identically in both derivations.
 */
export function legacyStegoFingerprint(value) {
  const s = String(value ?? '');
  if (/^[0-9a-fA-F]{12}$/.test(s)) return s.toLowerCase();
  const a = hashSeed('archx-stego:' + s, 0x51ab);
  const b = hashSeed('archx-stego:' + s, 0x9e37);
  const lo = Math.floor(a % 0x1000000).toString(16).padStart(6, '0');
  const hi = Math.floor(b % 0x1000000).toString(16).padStart(6, '0');
  return lo + hi;
}

const STEGO_CRC16_TABLE = (() => {
  const table = new Uint16Array(256);
  for (let byte = 0; byte < 256; byte++) {
    let crc = byte << 8;
    for (let i = 0; i < 8; i++) {
      crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
    table[byte] = crc;
  }
  return table;
})();

export function stegoCrc16(bytes) {
  let crc = 0xffff;
  for (const byte of bytes) {
    crc = ((crc << 8) ^ STEGO_CRC16_TABLE[((crc >> 8) ^ byte) & 255]) & 0xffff;
  }
  return crc;
}

// Codeword v2 acceptance tag: the first 16 bits of HMAC-SHA256 over the
// 48-bit fingerprint under the (secret) stego key. CRC-16 is linear, so
// the bitwise majority of several buyers' codewords sits close to another
// valid codeword and blind repair can "find" a third party's fingerprint
// in a collusion average (phantom framing). A keyed MAC avalanches:
// MAC(majority) agrees with majority(MACs) only at chance (~50%/bit), so
// hybrids fall outside any sane repair budget, while detection stays a
// single O(1) pass under one shared per-image key — no per-viewer keys
// or registry-sized search needed. CRC-16 remains as the *repair*
// oracle in the robust profile (its syndrome algebra is what makes
// bounded correction fast) and as the legacy-v1 acceptance predicate.
const STEGO_MAC_DOMAIN = utf8Encode('archx-stego-v2:');
export function stegoMac16(key, payloadBytes) {
  const msg = new Uint8Array(STEGO_MAC_DOMAIN.length + payloadBytes.length);
  msg.set(STEGO_MAC_DOMAIN, 0);
  msg.set(payloadBytes, STEGO_MAC_DOMAIN.length);
  const mac = hmacSha256Bytes(utf8Encode(String(key ?? '')), msg);
  return (mac[0] << 8) | mac[1];
}

export function stegoBytesToBits(bytes) {
  const bits = new Uint8Array(bytes.length * 8);
  bytes.forEach((byte, i) => {
    for (let b = 0; b < 8; b++) bits[i * 8 + b] = (byte >> (7 - b)) & 1;
  });
  return bits;
}

// Robust profile codeword: the same public 48-bit fingerprint and CRC-16,
// followed by a second keyed CRC over the payload+CRC and a short marker.
// The detector uses the extra redundancy only after the ordinary CRC has
// identified a plausible partially damaged vector. This is still a heuristic
// forensic mark—not an unremovable or guaranteed identifier.
function robustLegacyKeyedCrc(first8, key) {
  const keyByte = Math.floor(hashSeed('archx-stego-robust:' + String(key ?? ''), 0x51ab) % 256);
  const keyed = new Uint8Array(9);
  keyed.set(first8, 0);
  keyed[8] = keyByte;
  return stegoCrc16(keyed);
}

// Trailing sync marker of the robust codeword, as bits (bytes 10-11).
export const ROBUST_MARKER_BITS = stegoBytesToBits(new Uint8Array([0xa5, 0x5a]));

export function robustStegoCodeBits(fingerprint, key, tag = 'mac') {
  const payload = new Uint8Array(6);
  for (let i = 0; i < 6; i++) payload[i] = parseInt(fingerprint.slice(i * 2, i * 2 + 2), 16);
  const crc = stegoCrc16(payload);
  const first = [...payload, (crc >> 8) & 255, crc & 255];
  // v2: bytes 8-9 are the keyed MAC acceptance tag (avalanche) instead of
  // the legacy one-key-byte CRC (linear, so collusion majorities could
  // stay within repair distance of a phantom fingerprint).
  const check = tag === 'crc' ? robustLegacyKeyedCrc(first, key) : stegoMac16(key, payload);
  return stegoBytesToBits(new Uint8Array([
    ...first,
    (check >> 8) & 255,
    check & 255,
    0xa5,
    0x5a,
  ]));
}

export function robustStegoBytesValid(bytes, key, tag = 'mac') {
  if (!bytes || bytes.length !== 12) return false;
  // Order matters for the exhaustive repair search: the marker and the
  // linear CRC reject ~all random candidates before any HMAC runs.
  if (bytes[10] !== 0xa5 || bytes[11] !== 0x5a) return false;
  if (stegoCrc16(bytes.subarray(0, 6)) !== ((bytes[6] << 8) | bytes[7])) return false;
  const expected = tag === 'crc'
    ? robustLegacyKeyedCrc(bytes.subarray(0, 8), key)
    : stegoMac16(key, bytes.subarray(0, 6));
  return expected === ((bytes[8] << 8) | bytes[9]);
}

export function robustStegoBitsValid(bits, key, tag = 'mac') {
  if (!bits || bits.length !== 96) return false;
  const bytes = new Uint8Array(12);
  for (let i = 0; i < 12; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = (byte << 1) | bits[i * 8 + b];
    bytes[i] = byte;
  }
  return robustStegoBytesValid(bytes, key, tag);
}

export function robustStegoFingerprintFromBits(bits) {
  let fingerprint = '';
  for (let i = 0; i < 6; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = (byte << 1) | bits[i * 8 + b];
    fingerprint += byte.toString(16).padStart(2, '0');
  }
  return fingerprint;
}

export function stegoCodeBits(fingerprint, key, tag = 'mac') {
  const bytes = new Uint8Array(6);
  for (let i = 0; i < 6; i++) bytes[i] = parseInt(fingerprint.slice(i * 2, i * 2 + 2), 16);
  const check = tag === 'crc' ? stegoCrc16(bytes) : stegoMac16(key, bytes);
  const all = [...bytes, (check >> 8) & 255, check & 255];
  const bits = new Uint8Array(64);
  all.forEach((byte, i) => {
    for (let b = 0; b < 8; b++) bits[i * 8 + b] = (byte >> (7 - b)) & 1;
  });
  return bits;
}

export function stegoBitsToBytes(bits) {
  const bytes = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = (byte << 1) | bits[i * 8 + b];
    bytes[i] = byte;
  }
  return bytes;
}

export function stegoCrcValid(bits) {
  const bytes = stegoBitsToBytes(bits);
  return stegoCrc16(bytes.subarray(0, 6)) === ((bytes[6] << 8) | bytes[7]);
}

export function stegoMacValid(bits, key) {
  const bytes = stegoBitsToBytes(bits);
  return stegoMac16(key, bytes.subarray(0, 6)) === ((bytes[6] << 8) | bytes[7]);
}

/**
 * Soft-decision repair: if the voted codeword fails its tag, try flipping
 * the least-reliable bits (singles, pairs, triples). Real marks usually
 * need 0–2 repairs after re-encoding; random images are still rejected by
 * the caller's signal/agreement thresholds, not by the tag alone. The MAC
 * predicate runs first; the legacy CRC predicate is a flagged fallback so
 * pre-v1.12 marks stay detectable (under stricter caller gates).
 */
export function correctStegoBits(bits, reliability, key, maxDepth = 3) {
  const macCache = new Map();
  const macOf = (candidate) => {
    const bytes = stegoBitsToBytes(candidate);
    const cacheKey = ((bytes[0] << 16) | (bytes[1] << 8) | bytes[2]) + ':' +
      ((bytes[3] << 16) | (bytes[4] << 8) | bytes[5]);
    let mac = macCache.get(cacheKey);
    if (mac === undefined) {
      mac = stegoMac16(key, bytes.subarray(0, 6));
      macCache.set(cacheKey, mac);
    }
    return mac === ((bytes[6] << 8) | bytes[7]);
  };
  const search = (valid, depthCap) => {
    if (valid(bits)) return { bits, corrections: 0 };
    const weakest = [...bits.keys()]
      .sort((a, b) => reliability[a] - reliability[b])
      .slice(0, 20);
    let best = null;
    const visit = (start, chosen) => {
      if (chosen.length) {
        const candidate = new Uint8Array(bits);
        let cost = 0;
        for (const i of chosen) { candidate[i] ^= 1; cost += reliability[i]; }
        if (valid(candidate) && (!best || cost < best.cost)) {
          best = { bits: candidate, corrections: chosen.length, cost };
        }
      }
      if (chosen.length >= depthCap) return;
      for (let i = start; i < weakest.length; i++) visit(i + 1, [...chosen, weakest[i]]);
    };
    visit(0, []);
    return best;
  };
  const macBest = search(macOf, maxDepth);
  if (macBest) return { ...macBest, tagScheme: 'mac' };
  // Legacy standard candidates are gated to <=1 correction downstream, so
  // a deeper CRC search could only manufacture rejected candidates.
  const crcBest = search(stegoCrcValid, Math.min(1, maxDepth));
  if (crcBest) return { ...crcBest, tagScheme: 'crc' };
  return { bits, corrections: -1, tagScheme: null };
}

export const STEGO_ROW_SEGMENTS = 4;

// Layout seeds: v3 (1.14+) seeds sfc32 from SHA-256 with warm-up; v2
// (1.13) seeds through cyrb128+sfc32 (128-bit state). The pre-1.13
// layouts seeded mulberry32 with hashSeed(...) >>> 0, truncating every
// stego key — however strong — to a 2^32 layout space
// (GPU-brute-forceable from a known clean/marked pair). v1 and v2
// below reproduce their sequences bit-exactly so existing marks keep
// detecting; detection tries v3, v2, then v1 ("auto").
function layoutRand(seedString, version, legacyHashSeedArg) {
  if (version === 1) return mulberry32(hashSeed(seedString, legacyHashSeedArg));
  if (version === 2) return sfc32(...cyrb128(seedString));
  return sha256SeededPrng(seedString);
}

// Layout derivation is a pure function of (kind, cellCount, version,
// key) but costs a SHA-256-seeded shuffle plus ~5 PRNG draws per cell.
// One auto-detect rebuilds it per layout x profile x orientation
// probe, and batch screening repeats that per suspect under the same
// key. Cache the master arrays (bounded, same policy as the v4
// interleave cache below) and hand out copies, so callers keep the
// fresh-arrays contract and can never poison the cache by mutating
// a returned layout. Absurdly long keys skip the cache.
const _layoutCache = new Map();
function layoutCacheCopy(cacheKey) {
  if (cacheKey.length > 2048) return null;
  const hit = _layoutCache.get(cacheKey);
  if (!hit) return null;
  return {
    order: hit.order.slice(),
    polarity: new Int8Array(hit.polarity),
    segmentPolarity: new Int8Array(hit.segmentPolarity),
  };
}
function layoutCacheStore(cacheKey, layout) {
  if (cacheKey.length > 2048) return layout;
  if (_layoutCache.size >= 64) _layoutCache.clear();
  _layoutCache.set(cacheKey, layout);
  return layoutCacheCopy(cacheKey);
}

export function stegoLayout(cellCount, key, version = 2) {
  const seedString = String(key) + '::archx-stego-layout';
  const cacheKey = `std|${cellCount}|${version}|${seedString}`;
  const cached = layoutCacheCopy(cacheKey);
  if (cached) return cached;
  const rand = layoutRand(seedString, version);
  const order = Array.from({ length: cellCount }, (_, i) => i);
  for (let i = cellCount - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }
  const polarity = new Int8Array(cellCount);
  for (let i = 0; i < cellCount; i++) polarity[i] = rand() < 0.5 ? -1 : 1;
  const segmentPolarity = new Int8Array(cellCount * STEGO_ROW_SEGMENTS);
  for (let i = 0; i < segmentPolarity.length; i++) segmentPolarity[i] = rand() < 0.5 ? -1 : 1;
  return layoutCacheStore(cacheKey, { order, polarity, segmentPolarity });
}

export function stegoGrid(w, h, gridX, gridY) {
  let gx = Math.max(4, Math.min(64, Math.round(gridX || 24)));
  let gy = Math.max(4, Math.min(64, Math.round(gridY || 16)));
  gx = Math.min(gx, Math.max(4, Math.floor(w / 8)));
  gy = Math.min(gy, Math.max(4, Math.floor(h / 8)));
  while (gx * gy < 64 && (gx < Math.floor(w / 4) || gy < Math.floor(h / 4))) {
    if (gx <= gy && gx < Math.floor(w / 4)) gx++; else gy++;
  }
  return { gx, gy };
}

export function robustStegoLayout(cellCount, key, version = 2) {
  const seedString = 'archx-stego-robust-layout:' + String(key ?? '');
  const cacheKey = `rob|${cellCount}|${version}|${seedString}`;
  const cached = layoutCacheCopy(cacheKey);
  if (cached) return cached;
  const order = Array.from({ length: cellCount }, (_, i) => i);
  const polarity = new Int8Array(cellCount);
  const segmentPolarity = new Int8Array(cellCount * STEGO_ROW_SEGMENTS);
  const rand = layoutRand(seedString, version, 0x51ab);
  for (let i = cellCount - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [order[i], order[j]] = [order[j], order[i]];
  }
  for (let i = 0; i < cellCount; i++) {
    polarity[i] = rand() > 0.5 ? 1 : -1;
    for (let segment = 0; segment < STEGO_ROW_SEGMENTS; segment++) {
      segmentPolarity[i * STEGO_ROW_SEGMENTS + segment] = rand() > 0.5 ? 1 : -1;
    }
  }
  return layoutCacheStore(cacheKey, { order, polarity, segmentPolarity });
}

/* ---------- Layout v4: BCH error correction (v1.20) ---------- */

/**
 * Layout v4 keeps the v3 cell layout (grid, third-difference
 * statistic, keyed polarities) and replaces the repetition+tag
 * codeword with a shortened binary BCH(188,64) code: the same
 * 48-bit fingerprint + keyed MAC-16 payload, protected by 124
 * parity bits correcting any 2e+s <= 36 errors+erasures, then
 * keyed-interleaved across the cell grid so spatially clustered
 * damage (crops, overlays, scratches) lands on scattered codeword
 * positions instead of concentrated ones. Detector "auto" tries v4
 * alongside the shipped v1-v3 layouts; older detectors simply do
 * not see v4 marks (forward compatibility is one-directional, as
 * with every prior layout step).
 */
export const STEGO_V4_CODE_BITS = BCH_CODE_BITS;

// Keyed bit interleaver. wire[i] = plain[perm[i]]. Cached per key:
// the detector may attempt thousands of decodes under one key and a
// SHA-256-seeded shuffle per attempt dominated its geometry search.
const _v4PermCache = new Map();
export function stegoV4InterleaveOrder(key) {
  const cacheKey = String(key ?? '');
  let perm = _v4PermCache.get(cacheKey);
  if (perm) return perm;
  const rand = sha256SeededPrng('archx-stego-v4-interleave:' + cacheKey);
  perm = Array.from({ length: BCH_CODE_BITS }, (_, i) => i);
  for (let i = perm.length - 1; i > 0; i--) {
    const j = Math.floor(rand() * (i + 1));
    [perm[i], perm[j]] = [perm[j], perm[i]];
  }
  if (_v4PermCache.size >= 64) _v4PermCache.clear();
  _v4PermCache.set(cacheKey, perm);
  return perm;
}

/** 188-bit interleaved BCH codeword for a 12-hex fingerprint. */
export function bchStegoCodeBits(fingerprint, key) {
  const payload = new Uint8Array(6);
  for (let i = 0; i < 6; i++) payload[i] = parseInt(fingerprint.slice(i * 2, i * 2 + 2), 16);
  const mac = stegoMac16(key, payload);
  const data = stegoBytesToBits(new Uint8Array([...payload, (mac >> 8) & 255, mac & 255]));
  const code = bchEncode64(data);
  const perm = stegoV4InterleaveOrder(key);
  const wire = new Uint8Array(BCH_CODE_BITS);
  for (let i = 0; i < BCH_CODE_BITS; i++) wire[i] = code[perm[i]];
  return wire;
}

/**
 * Decode voted v4 bits (interleaved domain). `erasures` are
 * interleaved-domain indices with no/weak votes. On success returns
 * { fingerprint, bits (corrected, interleaved domain), errors,
 * erasures }; the embedded MAC-16 must verify, so a BCH
 * miscorrection onto a neighbouring codeword is still rejected.
 */
export function bchStegoDecode(wireBits, erasures, key) {
  if (!wireBits || wireBits.length !== BCH_CODE_BITS) return null;
  const perm = stegoV4InterleaveOrder(key);
  const plain = new Uint8Array(BCH_CODE_BITS);
  for (let i = 0; i < BCH_CODE_BITS; i++) plain[perm[i]] = wireBits[i] ? 1 : 0;
  const plainErasures = (erasures || []).map((i) => perm[i]).filter((i) => i !== undefined);
  const decoded = bchDecode188(plain, plainErasures);
  if (!decoded) return null;
  const bytes = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = (byte << 1) | decoded.data[i * 8 + b];
    bytes[i] = byte;
  }
  if (stegoMac16(key, bytes.subarray(0, 6)) !== ((bytes[6] << 8) | bytes[7])) return null;
  const code = bchEncode64(decoded.data);
  const bits = new Uint8Array(BCH_CODE_BITS);
  for (let i = 0; i < BCH_CODE_BITS; i++) bits[i] = code[perm[i]];
  let fingerprint = '';
  for (let i = 0; i < 6; i++) fingerprint += bytes[i].toString(16).padStart(2, '0');
  return { fingerprint, bits, errors: decoded.errors, erasures: decoded.erasures };
}


/**
 * Deep-crop fallback for v4: ML erasure solve over the observed
 * (voted) bits in reliability order. Recovers when crops erase far
 * more than the 36-erasure bounded-distance radius, as long as 64+
 * independent observed bits survive. Acceptance evidence is the
 * caller's mismatch accounting + the embedded MAC verified here.
 */
export function bchStegoSolveObserved(wireBits, observedOrderWire, key, { maxMismatches = Infinity, osd = true, isdTrials = 0, seedSalt = 0 } = {}) {
  if (!wireBits || wireBits.length !== BCH_CODE_BITS) return null;
  if (!observedOrderWire || observedOrderWire.length < 65) return null;
  // Defensive cap clamp. The payload MAC is 16 bits: with OSD+ISD
  // testing thousands of candidate words per suspect, a loose
  // mismatch cap becomes a MAC lottery — measured: cap 40 at 119
  // observed bits produced a WRONG MAC-valid fingerprint within
  // ~8000 trials (24 mismatches vs the votes; noise solves sit at
  // ~59). The detector's operative cap is 0.30*(observed-64),
  // ~8 sigma from the noise mean; this clamp keeps any future
  // caller from widening past 0.34 by accident.
  const capLimit = Math.max(3, Math.floor((observedOrderWire.length - 64) * 0.34));
  if (maxMismatches > capLimit) maxMismatches = capLimit;
  const perm = stegoV4InterleaveOrder(key);
  const plain = new Uint8Array(BCH_CODE_BITS);
  for (let i = 0; i < BCH_CODE_BITS; i++) plain[perm[i]] = wireBits[i] ? 1 : 0;
  const plainOrder = observedOrderWire.map((i) => perm[i]).filter((i) => i !== undefined);
  // MAC verification shared by the direct solve and every OSD retry.
  const macOk = (dataBits) => {
    let mac = 0;
    const fpBytes = new Uint8Array(6);
    for (let i = 0; i < 6; i++) {
      let byte = 0;
      for (let b = 0; b < 8; b++) byte = (byte << 1) | dataBits[i * 8 + b];
      fpBytes[i] = byte;
    }
    for (let b = 0; b < 16; b++) mac = (mac << 1) | dataBits[48 + b];
    return stegoMac16(key, fpBytes) === mac;
  };
  let solved = osd
    ? bchOsdSolve(plain, plainOrder, { maxMismatches, verify: macOk })
    : (() => { const d = bchSolveObserved(plain, plainOrder); return d && macOk(d.data) ? d : null; })();
  if (!solved && isdTrials > 0) {
    solved = bchIsdSolve(plain, plainOrder, { maxMismatches, verify: macOk, trials: isdTrials, seedSalt });
  }
  if (!solved) return null;
  const bytes = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    let byte = 0;
    for (let b = 0; b < 8; b++) byte = (byte << 1) | solved.data[i * 8 + b];
    bytes[i] = byte;
  }
  if (stegoMac16(key, bytes.subarray(0, 6)) !== ((bytes[6] << 8) | bytes[7])) return null;
  const code = bchEncode64(solved.data);
  const bits = new Uint8Array(BCH_CODE_BITS);
  for (let i = 0; i < BCH_CODE_BITS; i++) bits[i] = code[perm[i]];
  let fingerprint = '';
  for (let i = 0; i < 6; i++) fingerprint += bytes[i].toString(16).padStart(2, '0');
  return {
    fingerprint, bits,
    mismatches: solved.mismatches,
    erasures: BCH_CODE_BITS - plainOrder.length,
  };
}
