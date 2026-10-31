/**
 * Binary BCH error correction for StegoMark layout v4 (v1.20).
 *
 * Primitive BCH(255, 131) over GF(2^8) with designed distance 37
 * (corrects any 2e + s <= 36 errors+erasures), shortened to
 * (188, 64): 64 data bits (48-bit fingerprint + 16-bit MAC) become
 * 188 transmitted bits. This replaces the v1-v3 repetition+tag code,
 * whose repair budget (~5 voted-bit flips) wastes most of the
 * channel: BCH+repetition is the classical industry construction
 * (and measured best in the 2026 ECC-watermark comparisons).
 *
 * Conventions: a codeword array c[0..254] holds coefficients of
 * x^254 .. x^0 (c[i] is the coefficient of x^(254-i)). An error at
 * index i has locator X = alpha^(254-i); syndromes S_j = sum X^j.
 * Shortening: 67 leading zero message bits are dropped on the wire
 * and re-inserted by the decoder.
 */

const GF_POLY = 0x11d; // x^8 + x^4 + x^3 + x^2 + 1
const N = 255;
const K = 131;
const T = 18; // error-correction radius: 2t = 36 syndromes
const DATA_BITS = 64;
const PAD = K - DATA_BITS; // 67 shortened zero bits
export const BCH_CODE_BITS = N - PAD; // 188 transmitted bits
export const BCH_DATA_BITS = DATA_BITS;
export const BCH_MAX_2E_PLUS_S = 2 * T;

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
{
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= GF_POLY;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
}
const gfMul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);
const gfDiv = (a, b) => (a ? EXP[LOG[a] - LOG[b] + 255] : 0);
const gfPow = (a, p) => (a ? EXP[(LOG[a] * p) % 255] : 0);

// Generator polynomial g(x) = prod_{j=1..36} (x + alpha^j), computed
// over GF(256); for a binary BCH code every coefficient lands in
// GF(2). Stored as bits, gBits[i] = coefficient of x^(124-i).
const GENERATOR = (() => {
  // Polynomial in ascending-coefficient form over GF(256).
  let g = [1];
  for (let j = 1; j <= 2 * T; j++) {
    const root = EXP[j]; // alpha^j; factor (x + root) since char 2
    const next = new Array(g.length + 1).fill(0);
    for (let i = 0; i < g.length; i++) {
      next[i] ^= gfMul(g[i], root);
      next[i + 1] ^= g[i];
    }
    g = next;
  }
  // g now has degree 36 in this naive product ONLY if every factor is
  // distinct-degree-1; the true generator is the product of MINIMAL
  // polynomials, i.e. the same product with conjugate duplicates
  // removed. Recompute properly: collect cyclotomic cosets of
  // 1..36 mod 255 and take one representative root per coset, then
  // the minimal polynomial of alpha^r is prod over its conjugates.
  const seen = new Set();
  let gen = [1];
  for (let j = 1; j <= 2 * T; j++) {
    if (seen.has(j)) continue;
    // coset of j: { j*2^m mod 255 }
    const coset = [];
    let c = j;
    while (!seen.has(c)) { seen.add(c); coset.push(c); c = (c * 2) % 255; }
    for (const member of coset) {
      const root = EXP[member];
      const next = new Array(gen.length + 1).fill(0);
      for (let i = 0; i < gen.length; i++) {
        next[i] ^= gfMul(gen[i], root);
        next[i + 1] ^= gen[i];
      }
      gen = next;
    }
  }
  const degree = gen.length - 1;
  const bits = new Uint8Array(degree + 1);
  for (let i = 0; i <= degree; i++) {
    const coef = gen[degree - i]; // flip to descending (x^degree first)
    if (coef !== 0 && coef !== 1) throw new Error('Archx BCH: generator is not binary');
    bits[i] = coef;
  }
  if (degree !== N - K) throw new Error(`Archx BCH: generator degree ${degree}, expected ${N - K}`);
  return bits;
})();

function syndromes(codeword) {
  const out = new Uint8Array(2 * T);
  for (let j = 1; j <= 2 * T; j++) {
    let s = 0;
    for (let i = 0; i < N; i++) {
      if (!codeword[i]) continue;
      // (alpha^j)^(254-i) = alpha^(j*(254-i) mod 255)
      s ^= EXP[(j * (254 - i)) % 255];
    }
    out[j - 1] = s;
  }
  return out;
}

/** Systematic encode: 64 data bits -> 188 transmitted bits. */
export function bchEncode64(dataBits) {
  if (!dataBits || dataBits.length !== DATA_BITS) {
    throw new Error(`Archx BCH: data must be exactly ${DATA_BITS} bits`);
  }
  // Full message polynomial: PAD zero bits, then the 64 data bits,
  // then 124 parity slots (binary long division by g(x)).
  const work = new Uint8Array(N);
  work.set(dataBits, PAD);
  for (let i = 0; i < K; i++) {
    if (!work[i]) continue;
    for (let j = 0; j <= N - K; j++) work[i + j] ^= GENERATOR[j];
  }
  const out = new Uint8Array(BCH_CODE_BITS);
  out.set(dataBits, 0);
  out.set(work.subarray(K), DATA_BITS);
  return out;
}

// Berlekamp-Massey over GF(256): minimal connection polynomial
// C(x) = 1 + c1 x + ... + cL x^L generating the syndrome sequence.
function berlekampMassey(seq) {
  let C = [1];
  let B = [1];
  let L = 0;
  let m = 1;
  let b = 1;
  for (let n = 0; n < seq.length; n++) {
    let d = seq[n];
    for (let i = 1; i <= L; i++) d ^= gfMul(C[i] || 0, seq[n - i]);
    if (d === 0) { m++; continue; }
    const prevC = C.slice();
    const scale = gfDiv(d, b);
    while (C.length < B.length + m) C.push(0);
    for (let i = 0; i < B.length; i++) C[i + m] ^= gfMul(scale, B[i]);
    if (2 * L <= n) { L = n + 1 - L; B = prevC; b = d; m = 1; } else { m++; }
  }
  C.length = L + 1;
  return C;
}

function evalPolyAscending(coefs, x) {
  let acc = 0;
  for (let i = coefs.length - 1; i >= 0; i--) acc = gfMul(acc, x) ^ (coefs[i] || 0);
  return acc;
}

/**
 * Errors+erasures decode of a 188-bit received word.
 * `erasures` lists transmitted-domain indices (0..187) known to be
 * unreliable (zero-vote or near-zero-reliability bits). Returns
 * { data: Uint8Array(64), errors, erasures } or null when the word
 * is beyond the correction radius or inconsistent. A returned
 * result is a true codeword within the radius; callers still verify
 * the embedded MAC (bounded-distance decoding can miscorrect onto
 * a neighbouring codeword under >t corruption).
 */
export function bchDecode188(received, erasures = []) {
  if (!received || received.length !== BCH_CODE_BITS) return null;
  const erasureList = [...new Set(erasures)].filter((i) => i >= 0 && i < BCH_CODE_BITS);
  if (erasureList.length > 2 * T) return null;
  const full = new Uint8Array(N);
  full.set(received, PAD);
  const syn = syndromes(full);
  const s = erasureList.length;
  if (syn.every((v) => v === 0)) {
    // Already a codeword (any declared erasures happened to hold
    // the right values, or their true values are the received ones).
    return { data: Uint8Array.from(full.subarray(PAD, PAD + DATA_BITS)), errors: 0, erasures: s };
  }
  // Erasure locator Gamma(x) = prod (1 + X_l x), X_l = alpha^(254-i).
  let gamma = [1];
  for (const ti of erasureList) {
    const X = EXP[(254 - (ti + PAD)) % 255];
    const next = new Array(gamma.length + 1).fill(0);
    for (let i = 0; i < gamma.length; i++) {
      next[i] ^= gamma[i];
      next[i + 1] ^= gfMul(gamma[i], X);
    }
    gamma = next;
  }
  // Forney syndromes: coefficients s..35 of S(x)·Gamma(x) mod x^36,
  // where S(x) = S_1 + S_2 x + ... (syn[] above is S_1..S_36).
  const fsyn = [];
  for (let i = s; i < 2 * T; i++) {
    let acc = 0;
    for (let j = 0; j <= Math.min(i, gamma.length - 1); j++) {
      acc ^= gfMul(gamma[j], syn[i - j]);
    }
    fsyn.push(acc);
  }
  const errLoc = berlekampMassey(fsyn);
  const errDeg = errLoc.length - 1;
  if (2 * errDeg + s > 2 * T) return null;
  // Combined locator Lambda = errLoc · Gamma.
  const lambda = new Array(errLoc.length + gamma.length - 1).fill(0);
  for (let i = 0; i < errLoc.length; i++) {
    for (let j = 0; j < gamma.length; j++) lambda[i + j] ^= gfMul(errLoc[i], gamma[j]);
  }
  const lambdaDeg = lambda.length - 1;
  // Chien search: index i is an error/erasure iff Lambda(alpha^(i+1)) == 0
  // (since alpha^-(254-i) = alpha^(i+1) in GF(256)* cyclic order).
  const positions = [];
  for (let i = 0; i < N; i++) {
    if (evalPolyAscending(lambda, EXP[(i + 1) % 255]) === 0) positions.push(i);
  }
  if (positions.length !== lambdaDeg) return null;
  // Error magnitudes: an erasure position may already hold the right
  // bit, so flipping every located position (correct for errors-only
  // binary decoding) is wrong with erasures. Solve the syndrome
  // equations S_j = sum_l Y_l * X_l^j (j = 1..lambdaDeg) for the
  // magnitudes Y_l by Gaussian elimination over GF(256) — equivalent
  // to Forney's formula without its convention pitfalls, and cheap
  // at degree <= 36.
  const deg = lambdaDeg;
  const locators = positions.map((pos) => EXP[(254 - pos) % 255]);
  const rows = [];
  for (let j = 0; j < deg; j++) {
    const row = new Array(deg + 1);
    for (let l = 0; l < deg; l++) row[l] = gfPow(locators[l], j + 1);
    row[deg] = syn[j];
    rows.push(row);
  }
  for (let col = 0, row = 0; col < deg && row < deg; col++) {
    let pivot = -1;
    for (let r = row; r < deg; r++) if (rows[r][col] !== 0) { pivot = r; break; }
    if (pivot < 0) return null;
    [rows[row], rows[pivot]] = [rows[pivot], rows[row]];
    const inv = gfDiv(1, rows[row][col]);
    for (let c = col; c <= deg; c++) rows[row][c] = gfMul(rows[row][c], inv);
    for (let r = 0; r < deg; r++) {
      if (r === row || rows[r][col] === 0) continue;
      const factor = rows[r][col];
      for (let c = col; c <= deg; c++) rows[r][c] ^= gfMul(factor, rows[row][c]);
    }
    row++;
  }
  const erasureSet = new Set(erasureList.map((ti) => ti + PAD));
  let errors = 0;
  for (let l = 0; l < deg; l++) {
    const Y = rows[l][deg];
    if (Y !== 0 && Y !== 1) return null; // not a binary error pattern
    const pos = positions[l];
    if (!erasureSet.has(pos)) {
      if (Y !== 1) return null; // spurious locator root
      errors++;
    }
    if (Y === 1) full[pos] ^= 1;
  }
  if (2 * errors + s > 2 * T) return null;
  if (!syndromes(full).every((v) => v === 0)) return null;
  // The shortened prefix must still be zero after correction.
  for (let i = 0; i < PAD; i++) if (full[i]) return null;
  return { data: Uint8Array.from(full.subarray(PAD, PAD + DATA_BITS)), errors, erasures: s };
}

/* ---------- ML erasure solving (deep-crop fallback) ---------- */

// Generator rows in the transmitted (plain, pre-interleave) domain:
// GEN_ROWS[j] is a 64-bit mask of the data bits whose XOR produces
// transmitted bit j. Built once by encoding the 64 unit vectors.
function highestBit(mask) {
  const hi = Number(mask >> 32n);
  return hi ? 63 - Math.clz32(hi) : 31 - Math.clz32(Number(mask & 0xffffffffn));
}

const GEN_ROWS = (() => {
  const rows = new Array(BCH_CODE_BITS).fill(0n);
  for (let i = 0; i < DATA_BITS; i++) {
    const unit = new Uint8Array(DATA_BITS);
    unit[i] = 1;
    const code = bchEncode64(unit);
    for (let j = 0; j < BCH_CODE_BITS; j++) if (code[j]) rows[j] |= (1n << BigInt(i));
  }
  return rows;
})();

/**
 * Maximum-likelihood erasure solve: recover the 64 data bits from
 * whichever transmitted bits were observed, by GF(2) Gaussian
 * elimination over the generator matrix. Bounded-distance BCH
 * decoding stops at 36 erasures; this solves from ANY 64+
 * independent observed positions (deep crops erase 40-90 bits but
 * leave the rest nearly clean), which is why it exists: crop
 * damage is erasure-shaped, not error-shaped.
 *
 * `observedOrder` lists transmitted indices by descending
 * reliability — the elimination builds its basis from the most
 * reliable equations first, so a few wrong observed bits land in
 * the check set (counted as mismatches) instead of poisoning the
 * basis. Returns { data, mismatches } where mismatches counts
 * observed bits disagreeing with the solved codeword, or null
 * when the observed set does not span the data. Callers MUST
 * verify the embedded MAC: solving always produces a candidate,
 * so mismatches + MAC are the acceptance evidence.
 */
export function bchSolveObserved(received, observedOrder) {
  if (!received || received.length !== BCH_CODE_BITS) return null;
  const basis = new Array(DATA_BITS).fill(null); // pivot col -> {mask, value}
  let rank = 0;
  const used = [];
  for (const j of observedOrder) {
    if (rank === DATA_BITS) break;
    if (j < 0 || j >= BCH_CODE_BITS) continue;
    let mask = GEN_ROWS[j];
    let value = received[j] ? 1 : 0;
    // Reduce against existing basis (highest set bit = pivot).
    while (mask !== 0n) {
      const pivot = highestBit(mask);
      if (!basis[pivot]) { basis[pivot] = { mask, value }; rank++; used.push(j); mask = 0n; break; }
      mask ^= basis[pivot].mask;
      value ^= basis[pivot].value;
    }
  }
  if (rank < DATA_BITS) return null;
  // Back-substitution: basis rows are in row-echelon form by pivot.
  const data = new Uint8Array(DATA_BITS);
  for (let col = 0; col < DATA_BITS; col++) {
    const row = basis[col];
    if (!row) return null;
    let v = row.value;
    let mask = row.mask & ~(1n << BigInt(col));
    while (mask !== 0n) {
      const bit = highestBit(mask);
      v ^= data[bit] & 1;
      mask &= ~(1n << BigInt(bit));
    }
    data[col] = v;
  }
  const code = bchEncode64(data);
  let mismatches = 0;
  for (const j of observedOrder) {
    if (j >= 0 && j < BCH_CODE_BITS && (code[j] ? 1 : 0) !== (received[j] ? 1 : 0)) mismatches++;
  }
  return { data, mismatches, basis: used };
}

/**
 * Ordered-statistics reprocessing (OSD-1 + bounded OSD-2) around
 * bchSolveObserved.
 *
 * The plain ML erasure solve is brittle exactly where real damage
 * lives: observed bits are not just erased, some are WRONG, and a
 * handful of wrong bits inside the 64-bit solve basis poison the
 * whole solution. OSD retries the solve with the least-reliable
 * basis bits flipped — singly, then in pairs — until a candidate
 * satisfies BOTH the caller's mismatch cap (counted against the
 * original received word over the observed positions) and the
 * caller's verifier (the keyed MAC, in stego-code). Errors
 * concentrate in low-reliability positions by construction, so the
 * weakest ~24 basis bits are where reprocessing pays.
 *
 * Cost: <= 70 solves (~0.03 ms each) in the worst case; callers
 * gate invocation to coherent candidates and budget escalations.
 */
/**
 * Information-set decoding (ISD) escalation: randomized,
 * reliability-biased basis resampling around bchSolveObserved.
 *
 * OSD flips <=2 basis bits; real crop/resample damage measured
 * 13 voted-bit errors with ~5 inside the most-reliable 64-bit
 * basis — beyond OSD, trivial for ISD: errors concentrate in the
 * reliability tail (none in the top 27 in the measured case), so
 * reshuffling the mid/tail order produces a clean 64-bit
 * information set within a few dozen trials. Every candidate
 * must still pass the caller's mismatch cap AND verifier (keyed
 * MAC). The PRNG is seeded deterministically from the input (plus
 * a caller salt), so detection stays reproducible: same suspect,
 * same options, same verdict.
 */
export function bchIsdSolve(received, observedOrder, { maxMismatches = Infinity, verify = null, trials = 400, seedSalt = 0 } = {}) {
  if (!received || received.length !== BCH_CODE_BITS) return null;
  if (!observedOrder || observedOrder.length < DATA_BITS + 8) return null;
  let seed = 0x811c9dc5 ^ Math.imul(seedSalt + 1, 0x9e3779b9);
  for (let i = 0; i < observedOrder.length; i++) {
    seed ^= (observedOrder[i] + 1) * 257 + (received[observedOrder[i]] ? 1 : 0);
    seed = Math.imul(seed, 0x01000193);
  }
  const rnd = () => {
    seed |= 0; seed = (seed + 0x6D2B79F5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const score = (sol) => {
    if (!sol) return null;
    const code = bchEncode64(sol.data);
    let mismatches = 0;
    for (const j of observedOrder) {
      if (j >= 0 && j < BCH_CODE_BITS && (code[j] ? 1 : 0) !== (received[j] ? 1 : 0)) mismatches++;
    }
    if (mismatches > maxMismatches) return null;
    if (verify && !verify(sol.data)) return null;
    return { data: sol.data, mismatches };
  };
  // Fresh copy of the reliability order EVERY trial: the whole
  // advantage comes from errors concentrating in the tail, and
  // reshuffling one working array in place permanently scatters
  // that prior after the first full-window shuffle (measured:
  // in-place ISD failed 2000 trials on a case the fresh-copy
  // prototype solved in 19). Every 10th trial shuffles from
  // rank 0 as insurance against a wrong bit in the trusted top.
  // (Parameter cycling across blocks was also measured and
  // rejected: it halved the per-salt success rate, 20/24 -> 11/24,
  // by spending most trials at worse parameters.)
  const keepTop = Math.min(24, Math.max(0, observedOrder.length - DATA_BITS));
  const shuffleTo = Math.min(observedOrder.length, 110);
  for (let t = 0; t < trials; t++) {
    const order = [...observedOrder];
    const lo = t % 10 === 9 ? 0 : keepTop;
    for (let i = shuffleTo - 1; i > lo; i--) {
      const j = lo + Math.floor(rnd() * (i - lo + 1));
      const tmp = order[i]; order[i] = order[j]; order[j] = tmp;
    }
    const hit = score(bchSolveObserved(received, order));
    if (hit) return { ...hit, isdTrials: t + 1 };
  }
  return null;
}

export function bchOsdSolve(received, observedOrder, { maxMismatches = Infinity, verify = null } = {}) {
  if (!received || received.length !== BCH_CODE_BITS) return null;
  const score = (sol) => {
    if (!sol) return null;
    const code = bchEncode64(sol.data);
    let mismatches = 0;
    for (const j of observedOrder) {
      if (j >= 0 && j < BCH_CODE_BITS && (code[j] ? 1 : 0) !== (received[j] ? 1 : 0)) mismatches++;
    }
    if (mismatches > maxMismatches) return null;
    if (verify && !verify(sol.data)) return null;
    return { data: sol.data, mismatches };
  };
  const s0 = bchSolveObserved(received, observedOrder);
  const direct = score(s0);
  if (direct) return { ...direct, osdFlips: 0 };
  if (!s0 || !s0.basis || s0.basis.length < DATA_BITS) return null;
  // Basis entries arrive in reliability order; the tail is weakest.
  const weakest = s0.basis.slice(-24);
  const rx = Uint8Array.from(received);
  const trial = (positions) => {
    for (const p of positions) rx[p] ^= 1;
    const out = score(bchSolveObserved(rx, observedOrder));
    for (const p of positions) rx[p] ^= 1;
    return out;
  };
  for (const p of weakest) {
    const hit = trial([p]);
    if (hit) return { ...hit, osdFlips: 1 };
  }
  const pairZone = weakest.slice(-10);
  for (let i = 0; i < pairZone.length; i++) {
    for (let j = i + 1; j < pairZone.length; j++) {
      const hit = trial([pairZone[i], pairZone[j]]);
      if (hit) return { ...hit, osdFlips: 2 };
    }
  }
  return null;
}
