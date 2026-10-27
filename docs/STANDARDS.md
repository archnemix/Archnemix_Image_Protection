# Industry-standards checklist

This is the bar Archx holds itself to, mapped to public frameworks so a
reviewer can verify each claim instead of trusting adjectives. Status
meanings: **Met** (implemented + tested), **Operator** (the control
belongs to the deploying site; Archx provides the hook/mechanism),
**N/A** (documented why it does not apply). Anything not listed as Met is
called out as a gap with its disposition.

## A. API security — OWASP API Security Top 10 (2023)

| Risk | Requirement | Status / evidence |
|---|---|---|
| API1 Broken Object Level Authorization | Authorization checked per image ID on mint **and** redemption | Met — `authorize()` runs at both phases; deny-by-default (missing `authorize` fails startup in production modes) |
| API2 Broken Authentication | Short-lived, signed, sender-constrained tokens | Met — HMAC-SHA256 v2 claims (audience/scope/expiry/one-time nonce), RFC 7638 key thumbprint + RFC 9449-style proof of possession, `timingSafeEqual` verification |
| API3 Broken Object Property Level Authorization | Clients cannot widen width/quality/format beyond entitlement; no mass assignment | Met — signed claims are ceilings; request params strictly validated; token claims use a field allowlist |
| API4 Unrestricted Resource Consumption | Rate/concurrency/size/time budgets everywhere | Met — separate token/image rate windows, quotas, bounded stores, Sharp pixel/byte/time budgets, processing semaphore + queue timeout, batch body byte cap **and read deadline** |
| API5 Broken Function Level Authorization | No unauthenticated privileged functions | Met — no admin/debug endpoints exist; the only public route is the constant `taint.png` pixel |
| API6 Sensitive Business Flows | Bulk-view/scraping friction | Met — distinct-image abuse detection, per-viewer/image quotas, one-time tokens, batch still per-item authorized |
| API7 SSRF | Server must not fetch attacker URLs | Met — masters are local files only; IDs are allowlisted and realpath-contained; Sharp string-path inputs are rejected |
| API8 Security Misconfiguration | Secure defaults + startup validation | Met — strict unknown-option rejection, production config audit, hardened presets, generic errors |
| API9 Improper Inventory | One versioned API surface | Met — routes are `{basePath}/token/:id`, `/tokens`, `/i/:id`, `/taint.png`; methods allowlisted (405 otherwise) |
| API10 Unsafe Consumption | Treat upstream/store data as untrusted | Met — cached derivatives are container-validated **and HMAC-tagged**; Redis adapter validates value shapes; manifests schema-checked + optional SHA-256 pin |

## B. Browser platform & delivery

| Control | Status / evidence |
|---|---|
| Masters never web-accessible; derivative-only delivery | Met — contained masters dir, overlap rejected at startup |
| Cache safety (RFC 9111) | Met — dynamic responses `private, no-store` + CDN/surrogate controls + credential-sensitive `Vary`; only content-hashed static variants and the constant taint pixel are immutable (taint pixel also carries ETag/304) |
| Security headers | Met — `nosniff`, `Referrer-Policy: no-referrer`, CORP, sandboxed CSP on payloads, exact-origin CORS only (no `*` with credentials) |
| Fetch Metadata / CSRF friction | Met — POST + `X-Archx-Request` header required by default; same-site token gating option |
| Readback resistance | Met (layered, honestly bounded) — instance-poisoned decoys; browser-enforced `SecurityError` via origin tainting on cross-origin deployments; WebGL non-preserved black readback; documented residual: privileged capture (OS/CDP/camera) |
| Scramble strength | Met — plan v1 (32-bit seed, legacy compat) and **plan v2 (128-bit seed)** selectable per deployment; scramble is documented obfuscation, AES-256-GCM is the encryption layer |
| CSP friendliness | Met — no eval/inline-script needs; constructable stylesheets in shadow DOM (documented fallback caveat) |

## C. Cryptography & key management

| Control | Status / evidence |
|---|---|
| Authenticated encryption for payloads (opt-in) | Met — AES-256-GCM, random 96-bit IV per payload |
| Token integrity | Met — HMAC-SHA256, keyring with `kid` rotation, ≥32-byte secrets enforced |
| Timing safety | Met — `crypto.timingSafeEqual` on token MACs, cache tags, proof hashes |
| Key derivation hygiene | Met — per-purpose HMAC labels for scramble/AES/forensic/Stego material; viewer/trace IDs HMAC-hashed before use in keys/caches/events |
| Secrets in logs/events | Met — security events/telemetry are hash-only; options views redact key material |

## D. Media processing safety

| Control | Status / evidence |
|---|---|
| Untrusted-input discipline | Met — magic-byte sniffing cross-checked with decoder metadata, format allowlist (SVG excluded by default), `failOn:'warning'`, animated/multi-page rejection |
| Resource budgets (CWE-400) | Met — input bytes/pixels/dimensions, output pixels, decoder timeout, libvips loader blocklist option |
| Output hygiene | Met — masters' metadata never copied to derivatives; EXIF orientation baked, then dropped |

## E. Provenance & attribution

| Control | Status / evidence |
|---|---|
| Visible + forensic marks | Met — server-baked pre-scramble watermark, block forensic mark, per-viewer/token scoping |
| Steganographic fingerprint | Met with measured limits — blind detection CLI; survival claims limited to benchmarked resize/re-encode/blur/bounded-crop cases; rotation/phone-photo recovery explicitly unproven |
| C2PA | Operator — `onProvenanceIssue` hook emits a key-free issuance record for an external C2PA signer; Archx does not claim built-in Content Credentials |

## F. Supply chain & release engineering (OpenSSF-aligned)

| Control | Status / evidence |
|---|---|
| SECURITY.md policy | Met — reporting path + supported versions |
| CI tests on PR/push, 2 Node majors | Met — lint/build/unit/browser/audit workflow |
| SAST | Met — CodeQL workflow (javascript-typescript, security-extended queries); first run's 7 alerts (4 fs check-then-use races, 3 HMAC-blind bypass flags) were fixed or restructured away — 0 open alerts |
| Least-privilege CI tokens | Met — workflows declare minimal `permissions:` |
| Dependency updates + vuln gate | Met — Dependabot (npm + Actions), `npm audit` in verify/CI |
| SBOM | Met — CycloneDX generated in CI |
| Artifact integrity for script-tag users | Met — `dist/archx.min.js.sri` SHA-384 sidecar per build |
| Signed/provenanced releases | Operator-ready — `publish.yml` uses npm trusted publishing (OIDC, automatic provenance); requires the maintainer to configure the npm trusted publisher once |
| Lockfile committed | Met — `package-lock.json`; CI uses `npm ci` |

## G. Testing & quality gates

| Control | Status / evidence |
|---|---|
| Unit/integration tests | Met — Node test suite (auth, crypto, processing, abuse, caches, builders) |
| Real-browser tests | Met — headless Chromium with production web security enabled (no `--disable-web-security`) |
| Parser robustness / fuzzing | Met — `tests/fuzz.test.mjs`: deterministic seeded mutations over the container decoder, header schema, format sniffer, scramble round-trips, stego detector, and live token redemption (runs inside `npm test`; `ARCHX_FUZZ_MULTIPLIER` scales campaigns) |
| Load/perf regression | Met — `tools/load-test.mjs`, `tools/benchmark.mjs`, `tools/optimization-bench.mjs` with baseline/after JSON comparison |
| Type safety for consumers | Met — shipped TypeScript declarations with a `tsc --noEmit` smoke test in CI |

## H. Privacy, accessibility, compatibility

| Control | Status / evidence |
|---|---|
| No third-party requests / no phone-home | Met — client talks only to configured endpoints; telemetry is local events |
| Data minimization | Met — hashed viewer/trace identifiers; no fingerprint collection (automation signals are access-control inputs only, never stored identifiers) |
| Accessibility | Met (basic) — `alt` drives `role="img"`/`aria-label`, canvas is `aria-hidden`, `prefers-reduced-motion` disables flicker features by default; see COMPATIBILITY.md |
| Compatibility honesty | Met — COMPATIBILITY.md lists tested vs untested surfaces and per-feature fallbacks |

## Explicit non-goals (so nobody has to guess)

- **Not DRM** and not screenshot prevention: no web technology can veto
  OS-level capture or a camera. Archx removes programmatic routes and
  degrades/attributes privileged ones.
- **Not an identity provider**: `authorize()` is the host's session/
  entitlement system; Archx consumes its verdict.
- **Not independently audited / certified**: no SOC 2, ISO 27001, or
  third-party penetration-test claim is made. This checklist maps
  controls to public frameworks; it is not a certification.
