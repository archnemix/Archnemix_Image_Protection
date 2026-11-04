# Research registry — papers, standards, and primary docs behind Archx decisions

Every entry: **name** (authors/venue/year where applicable) — the main point
in one or two lines — and what it changed (or confirmed) in Archx. Entries
marked *(audit)* are the ones a profile/strategy decision in v1.28 cites
directly. This file is the "read it, name it, save the point" ledger; the
narrative lives in `docs/RESEARCH.md`.

## A. Scramble/permutation security — why scrambling is never secrecy

1. **Jolfaei, Wu, Muthukkumarasamy — "On the security of permutation-only
   image encryption schemes", IEEE TIFS 11(2), 2016.** Chosen-plaintext
   attack recovers the complete permutation of *any* permutation-only
   cipher with ⌈log_L(MN)⌉ chosen images, O(n·MN) time. → Permutation is a
   transport/obfuscation layer only; secrecy requires AES-GCM
   (`encrypt:true`). *(audit)*
2. **Chengqing Li et al. — "Cryptanalyzing an Image-Scrambling Encryption
   Algorithm of Pixel Bits", IEEE Multimedia / arXiv:1607.01642, 2016.**
   Correlation left inside a scrambled image leaks visual information
   ciphertext-only; the scrambling domain enables efficient known/chosen
   plaintext attacks. → Never market scrambling as encryption; keep
   per-token keys available so one view's key material is useless for
   another view's payload.
3. **"Recovering the Block-wise Relationship in an
   Encryption-Then-Compression System", arXiv:2305.04543, 2023.** An
   elaborate jigsaw solver recovers visual content from block-permuted
   cipher-images ciphertext-only, even after lossy OSN re-compression;
   correlation among blocks survives the encryption. → Grid floor (v1.27)
   is friction, not a security boundary; the boundary is AES +
   authorization. *(audit)*
4. **"Security Evaluation of Compressible Image Encryption … against
   Ciphertext-Only Attacks", arXiv:2207.08109, 2022.** With few blocks,
   jigsaw + feature-reconstruction attacks restore content; independently
   keyed extended schemes resist better. → Small grids are the worst
   case; supports the grid-8 creation floor and per-image/per-token key
   separation.
5. **Survey of image-encryption cryptanalysis, arXiv:1903.11764.**
   Ciphertext-only attack on blockwise permutation reduces to solving a
   jigsaw puzzle. → Same conclusion as A1–A4; cited in the v1.27 grid
   floor rationale.
6. **Moussa — "Jigsopu: Square Jigsaw Puzzle Solver with Pieces of
   Unknown Orientation", IJACSA 6(3).** Edge-matching solvers reassemble
   unordered square tiles (unknown orientation) without prior knowledge
   of the image. → Mirrored/rotated tiles do not save a coarse grid.
7. **Baluja Shumeet — genetic-algorithm jigsaw solver, 2012.** Large square
   puzzles are machine-solvable to near-completion. → Solver capability
   is a decade old and public; assume it in the threat model.

## B. Watermarks vs AI regeneration — why marks are evidence, not armor

8. **Zhao et al. — "Invisible Image Watermarks Are Provably Removable
   Using Generative AI", NeurIPS 2024.** Regeneration (noise → denoise)
   provably destroys pixel-level invisible watermarks while preserving
   content; detection drops to chance across four schemes. Semantic
   watermarks (e.g. Tree-Ring) are the more resilient direction. →
   StegoMark is positioned as attribution evidence layered with
   authorization/entitlement — never as copy prevention. *(audit)*
9. **Yunyi Ni et al. — "Diffusion-Based Image Editing for Breaking Robust
   Watermarks", arXiv:2510.05978, 2025.** Guided diffusion (decoder inside
   the sampling loop) drives StegaStamp/TrustMark/VINE recovery to
   near-zero at high visual fidelity; mutual information with the payload
   provably vanishes. → Do not chase "AI-proof" invisible marks; invest
   in issuance logs, visible marks, and server-side withholding.
10. **"Diffusion-Based Image Editing: An Unforeseen Adversary to Robust
    Invisible Watermarks", arXiv:2511.05598, 2025.** Formal version of
    the same result; even unguided regeneration erases state-of-the-art
    marks. → Honest-limits docs stay as written.
11. **Mareen, De Meulenaere, Lambert, Van Wallendael — "Diffusion
    Denoising Watermark Removal Models to Attack Invisible Image
    Watermarks", ICSPCS 2024.** Off-the-shelf diffusion denoisers remove
    marks embedded by schemes benchmarked only against classical
    distortions. → Our stego bench measures classical transforms and
    says so; no regeneration-survival claim is made anywhere.
12. **TrustMark / SynthID (product literature, DeepMind/Google).** Neural
    marks need trained encoder/decoder networks — infeasible in a
    dependency-free JS library, and still regeneration-vulnerable (B8/B9).
    → Neural watermarking stays deferred; documented as such.
13. **Cox, Kilian, Leighton, Shamoon — "Secure spread spectrum
    watermarking for multimedia", IEEE TIP 1997 (foundational).**
    Spread-spectrum embedding in perceptually significant coefficients
    trades capacity for robustness. → The design space StegoMark's
    redundant macro-cell layout descends from.
14. **Boneh–Shaw (1995) / Tardos (2003) collusion-secure fingerprinting
    (foundational).** Collusion-resistant codes need code lengths
    quadratic in the colluder bound. → Archx's 96-bit channel cannot be
    collusion-proof; collusion averaging is red-teamed and documented,
    not claimed away.

## C. Tokens, replay, and API abuse — why delivery is sender-constrained

15. **RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP),
    Fett et al., 2023.** Bind tokens to a client key; require a fresh
    proof per use; track `jti` to kill proof replay. → The model for
    Archx's sender-constrained one-time redemption (ES256/P-256 proof,
    exact claim sets, short lifetimes). *(audit)*
16. **OWASP API Security Top 10 (2023).** BOLA/IDOR is the #1 API risk;
    unrestricted resource consumption (API4) demands timeouts, payload
    caps, and rate limits; unrestricted access to sensitive business
    flows (API6) is the scraping pattern. → Object-level `authorize()`
    at mint *and* redemption, quotas, bounded Sharp budgets, strict
    claim allowlists. *(audit)*
17. **OWASP Web Security Testing Guide (WSTG).** Checklist source for
    prototype pollution, parameter pollution, cache deception, host
    header injection, error disclosure. → The red-team v2 section
    structure.
18. **Kettle — "HTTP Desync Attacks: Request Smuggling Reborn",
    PortSwigger, 2019.** Parser differentials between front/back ends
    desynchronize request boundaries. → Reject ambiguous requests at the
    edges we control (strict methods, no duplicate ambiguous params).
19. **Kettle — "HTTP/1.1 Must Die: The Desync Endgame", Black Hat/DEF
    CON 2025 (PortSwigger).** HTTP/1.1 request-boundary ambiguity is
    indefensible by patching; ~24M sites still downgrade to 1.1 behind
    the edge. → OPERATIONS guidance: terminate with a strict front end,
    prefer HTTP/2 upstream where the host controls the chain; red-team
    includes duplicate/ambiguous-header probes. *(audit)*
20. **Omer Gil — "Web Cache Deception Attack", 2017.** Appending a static
    extension tricks shared caches into storing private responses. →
    `private,no-store` + CDN/surrogate no-store on token/payload
    responses; path-confusion cases belong in the red team.
21. **Berto et al. — "A Methodology for Web Cache Deception Vulnerability
    Discovery", CLOSER 2024.** Path confusion generalizes: encoded
    delimiters and path parameters split cache vs origin parsing. →
    New red-team v2 §G cases replay exactly these shapes against the
    payload route. *(audit)*
22. **Doyhenard — "Gotta cache 'em all", 2024.** Per-vendor normalization
    differences turn deception into static-resource poisoning. → Never
    let cacheability depend on the URL's static-looking suffix; headers
    are authoritative.
23. **PortSwigger Web Security Academy — Web cache poisoning/deception
    references, 2024.** Taxonomy of unkeyed inputs and the conditions
    both cache and origin must meet. → Red-team case design.
24. **npm trusted publishing / provenance docs + OpenSSF Scorecard.**
    OIDC-based provenance, pinned actions, SAST (CodeQL), fuzzing,
    signed releases as supply-chain baseline. → CI shape (CodeQL,
    SBOM, audit gate) and the pack-smoke equivalence test.

## D. Image formats & server processing — why WebP + libvips by default

25. **Sharp performance documentation (sharp.pixelplumbing.com).**
    libuv's pool bounds parallel image jobs (default 4); libvips threads
    per image follow cores; one chained pipeline per output. → Existing
    tuning (`sharpConcurrency`, cache off, sequential reads,
    `UV_THREADPOOL_SIZE` guidance) already matches; nothing to swap.
    *(audit)*
26. **Toolkiya — "WebP vs AVIF vs JPEG XL: 2026 comparison".** AVIF
    encodes 2–5 s (12 MP, fast preset) vs WebP well under a second; AVIF
    decode stutter on low-end mobile with many images. → WebP stays the
    request-path default; AVIF stays precomputed-opt-in. *(audit)*
27. **ImageRobo — "JPEG vs WebP vs AVIF performance comparison", 2025.**
    1920×1080 encode medians: JPEG 45 ms, WebP 127 ms, AVIF 892 ms. →
    Same conclusion; AVIF on the request path is rented CPU.
28. **Kalyna — "AVIF in 2026" (libvips production notes).** Real libvips
    stack: AVIF −61% bytes vs JPEG but 1–2 s/image with libaom. →
    Confirms our own bench (AVIF −56% bytes, 8–70× encode time).
29. **Billion-laughs / decompression-bomb class (decoder resource
    exhaustion, CWE-400 family).** Pixel/dimension bombs exhaust memory
    before any application logic runs. → Pre-decode sniff + Sharp
    metadata gate, `limitInputPixels`, byte/pixel/dimension budgets,
    `failOn:'warning'` — already the implementation.
30. **MDN — `createImageBitmap`.** Baseline widely available since 2021;
    asynchronous decode to an `ImageBitmap`. → Default client decode
    path. *(audit)*
31. **MDN — `ImageDecoder` (WebCodecs).** Limited availability, not
    Baseline; Safari Technology Preview only, nothing on iOS. → Not the
    default; revisit only behind an Archx-run cross-browser benchmark.
    *(audit)*
32. **Broadside issue #373 — measured platform decode matrix (2026-10,
    BCD+source).** Chrome decodes off-thread; Firefox
    `createImageBitmap(Blob)` decodes on the main thread; Safari defers
    to first draw. → Keep one well-understood path; profile budgets are
    sized from our own bench, not vendor claims.
33. **Loopdesk — WebCodecs support survey (caniuse 2026-09).**
    ImageDecoder: Chrome 94+, Firefox 133+, Safari preview-only. →
    Same decision as D31.
34. **web.dev — Image performance (Learn Performance).** Deliver
    display-sized images accounting for layout × DPR; lazy-load below
    the fold, never the LCP image. → Canonical width buckets + the
    documented hero exception (`lazy:false`, `fetchPriority:'high'`).

## E. Browser platform — readback, paint, and capture truths

35. **MDN — `requestAnimationFrame`.** Callbacks run before the next
    repaint, aligned to the refresh cycle. → The v1.27 double-rAF
    first-paint settlement for `ready`.
36. **HTML canvas origin-clean flag (WHATWG HTML Standard).** Drawing a
    cross-origin image taints the canvas; every readback API then throws
    `SecurityError`, prototype calls included. → The taint-pixel layer
    for 2D modes (browser-enforced, unhookable from page JS).
37. **WebGL `preserveDrawingBuffer:false` (Khronos spec behavior).** The
    drawing buffer is cleared after compositing, so later readback is
    black. → Vault/Elite black-by-construction readback.
38. **W3C WCAG 2.2 — Pause, Stop, Hide; Animation from Interactions.**
    Motion over 5 s needs controls; honor `prefers-reduced-motion`. →
    Temporal features default off, respect reduced motion, and the
    website animation keeps pause controls.
39. **Brysbaert — "How many words do we read per minute?", J. Memory &
    Language 2019.** Silent nonfiction ≈238 wpm average. → Website
    explainer stage budgets.
40. **Mayer's CTML segmenting principle (PMC review, 2022).** Short,
    user-paced segments beat one continuous animation for comprehension.
    → Per-stage flowchart timing instead of one fixed duration.
41. **Material Design motion duration tokens.** Durations scale with
    travel distance/area (75–350 ms micro-motion). → Micro-motion inside
    the Technical explainer stages.

## F. Fingerprinting & provenance — what identification can and cannot do

42. **Yang et al. — "CertPHasH: Towards Certified Perceptual Hashing via
    Robust Training", USENIX Security 2025.** Deployed PHash systems
    (PDQ, NeuralHash, PhotoDNA) fall to evasion *and* collision
    perturbations; certified robustness needs adversarial training.
    → Archx's perceptual fingerprint is a soft-binding lookup aid with
    operator-calibrated thresholds — never an accusation by itself.
    *(audit)*
43. **Roy — "Adversarial Robustness of Perceptual Hashing Systems"
    (thesis).** All six tested algorithms evaded white-box; pHash-64
    near-collision success 99.4% at T=0.10. → Threshold choice is an
    operational risk decision; docs say calibrate on your own catalog.
44. **C2PA / Content Credentials explainers (Layer3Labs guide; TextSight
    2026 guide).** Credentials are tamper-evident but strippable by
    re-save/screenshot/platform upload; absence proves nothing. → Archx
    keeps the "not C2PA" stance: optional external provenance hook,
    content-layer marks for identification. *(audit)*
45. **Sammapix — "What Are Content Credentials (C2PA)?", 2026.** C2PA is
    a signed metadata manifest, distinct from pixel watermarks (SynthID
    class); removal is trivial, forgery of a valid signature is not. →
    Same layered-evidence framing in our docs.

## G. Human factors & the analog hole

46. **The analog hole (long-standing DRM literature/industry consensus).**
    Anything rendered for perception can be re-captured at presentation
    quality. → The product's core honesty constraint: withhold
    resolution, mark, trace — never promise un-copyable pixels.
47. **Critical flicker fusion (vision science, standard references).**
    Flicker above ~50–60 Hz fuses for most viewers; subset-frame
    integration depends on refresh alignment and fill. → Temporal
    interlace targets 60 Hz with per-phase subsets ≥30 Hz, and is
    opt-in + reduced-motion aware.
48. **Self-hosted vs CDN web fonts (web-performance consensus,
    cache-partitioning era).** Partitions killed the shared-cache
    argument for font CDNs; self-hosting removes third-party origins and
    IP exposure. → v1.27 font self-hosting on the website.

## H. Process rigor — how the above is kept true

49. **OWASP ASVS (Application Security Verification Standard).** Control
    families for authZ, session, crypto, and error handling map onto the
    middleware's fail-closed defaults. → Production-audit blocker list
    is reviewed against it each round.
50. **NIST SP 800-38D (GCM) & SP 800-56A-era KDF guidance / RFC 5869
    (HKDF).** Authenticated encryption + proper key derivation are the
    primitives; nonce uniqueness is the GCM hard rule. → AES-256-GCM
    payload encryption with per-payload IVs; HMAC/HKDF derivations for
    keys and fingerprints.
51. **Node.js crypto guidance — `timingSafeEqual` + length checks,
    canonical encodings.** Compare MACs in constant time on canonical
    bytes; authenticate before parsing where one secret exists. →
    Token verification order (MAC → parse on the single-secret path).
52. **GitHub CodeQL query suites (`js/insecure-temporary-file` et al.).**
    Static taint tracking catches temp-file races and injection classes
    unit tests miss. → CodeQL is a required gate; alerts are fixed at
    the source pattern, not suppressed (see the v1.27 atomic-write
    hardening).
