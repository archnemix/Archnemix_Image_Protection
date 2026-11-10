# Security policy

## Supported versions

Security fixes target the current supported 1.x release line and may ship
as patch or minor releases, depending on scope. There is no long-term-support
branch, and older minor lines do not receive backports. Pin a version only together
with an upgrade cadence, especially because image decoding depends on
current Sharp/libvips security fixes. State your exact version in
every report so applicability can be judged.

## Reporting a vulnerability

Please do not open a public issue for an exploitable vulnerability. Use
GitHub's private vulnerability reporting / security advisory flow for this
repository when available. Include:

- affected Archx, Node, Sharp, browser, and deployment versions;
- the smallest reproducible configuration you can share;
- whether the issue exposes a master image, bypasses `authorize()`, replays a
  token, escapes a configured directory, crashes the process, or exhausts
  CPU/memory;
- suggested mitigations, if known.

Do not include production secrets, real bearer tokens, private master images,
or third-party user data in a report.

There is currently no funded public bug-bounty program. Private reporting
through the process above is the supported disclosure path. Do not test a
third party's Archx deployment without that operator's written authorization.

## Security model and limits

Archx is a layered theft-friction and attribution system, not DRM. The
server must keep masters outside public web roots and enforce a real
`authorize(req, id, { phase })` callback at both token minting and image
redemption. Client-delivered scramble/AES keys can always be recovered by a
sufficiently determined authorized recipient, and displayed pixels can be
screenshotted or photographed. Treat screenshots, external cameras, complete
authorized-derivative reconstruction, and AI regeneration as residual risks;
use resolution caps, visible/forensic marks, quotas, monitoring, and your
normal legal/commercial enforcement process alongside Archx.

For more than one middleware process, use `deploymentMode:'multi-instance'`
with a shared, atomic `stateStore`; process-local quota state behind a load
balancer is outside the supported security model. When one-time tokens or
proof-of-possession replay checks are enabled (the default), tokens issued
with the built-in memory store are signed with a random store-generation claim. A
handler created with a different memory store (including after a process
restart) rejects those tokens rather than treating them as unspent. This is
fail-closed invalidation, not persistence: restart loses local counters and
clients must mint fresh tokens. Deploying this generation check also rejects
pre-generation tokens presented to a memory store. The bundled
`@archnemix/image-protection/redis` adapter still requires the host to own,
secure, monitor, and integration-test its Redis/Valkey client and deployment.
Rotate signing keys with the versioned keyring described in
`docs/OPERATIONS.md`, verify that the CDN bypasses shared caching for
token/payload routes and the optional SEO-preview route when enabled, and treat a state-store outage as a fail-closed `503`
rather than weakening replay controls.

An explicit `authorize()` denial is a policy result and returns `403`. If the
callback throws, the request still fails closed with a generic `500`; if it
exceeds `callbackTimeoutMs`, it fails closed with `503`. Both emit a separate
`archx.authorization_error` event, without returning callback exception
details through Archx. Treat these as host-application failures, not user
denials.

Derivative caches and precomputed assets do not change that boundary. A
memory/disk/shared derivative cache is consulted only for scrambled bytes
after the dynamic token, proof, authorization, replay, and quota checks; keep
any disk cache private, bounded, outside public roots, and outside the master
tree. An `archx-build` manifest contains browser scramble/AES delivery keys,
so a public manifest is appropriate only for a deliberately public capped
derivative. Private static catalogs must authorize or sign manifest/asset
delivery, and build state and masters must never be deployed.

Payload tokens belong in `X-Archx-Token` by default. Enabling
`allowQueryTokens` is a legacy compatibility exception, not an equivalent
posture. Never log a complete token response: its token, scramble key, and
optional AES key are intentionally visible to the authorized browser that
must redeem and decode the derivative. Run
`auditArchxProductionConfig(options, { expectedInstances })` in deployment
tests and treat its blockers as release failures unless a documented,
reviewed exception exists.

Client integrity checks are tripwires. Fortress may refuse an image when a
browser extension has patched fetch, canvas, or WebGL APIs; Vault's monitor
policy can continue while reporting the same signal. Neither result proves
that an attacker-owned browser is clean or compromised. Two v1.12
refinements matter operationally: sensitive primitives (SubtleCrypto,
stream readers, text decoding, core AES/HMAC) are executed through
boot-captured or page-independent implementations so naive prototype
replacement does not silently redirect them; and a rewritten
`preserveDrawingBuffer` — including one hidden by a spoofed
`getContextAttributes` — makes fortress fail closed (blackout) instead
of downgrading to a readable 2D canvas. A native-looking pre-load
forgery still evades all of this; that residual is unchanged.

## StegoMark keying and attribution discipline (v1.12)

The StegoMark layout key (`stegoKey`) must be a dedicated secret, never
the scramble key — the scramble key is public wherever browsers
unscramble (static manifests publish it). Before v1.11, the library/CLI
paths defaulted one to the other; those deployments' marks are
effectively unkeyed and should be re-issued. Detection confidence is
capped at 0.49 whenever `found` is false. A decode with
`corrections > 0` is a *repaired* decode: corroborate with the issuance
registry, the perceptual soft binding, and delivery logs before acting
on it — multi-buyer collusion averaging can erase marks, and with a
shared layout key it can synthesize a third party's fingerprint.
`steganography.keyScope: 'viewer'` removes that alignment at the cost
of per-viewer derivatives. Measured mark visibility (neon-portrait,
800 px): strength 6 ≈ 33.4 dB PSNR (standard) / 30.4 dB (robust);
strength 3 ≈ 39.4 / 35.9 dB with weaker survival. Pick deliberately;
StegoMark is an attribution aid, not proof.

Since v1.12 the acceptance tag is a keyed 16-bit truncated HMAC-SHA256
of the fingerprint (codeword v2), not the previous linear keyed CRC.
A majority hybrid of several buyers' marks can correlate with a CRC of
itself by construction; it cannot validate under a MAC it was never
issued, and detection stays O(1) per suspect under the shared image
key (no `keyScope:'viewer'` scan required). `detect` reports
`tagScheme: 'mac' | 'crc' | null`. A `'crc'` result is a legacy
pre-1.12 codeword: gates for it are deliberately tighter, the CLI
warns, and it must be corroborated before attribution — or the mark
re-issued under v2. Detectors older than v1.12 cannot read v2 marks
and may report spurious repaired decodes against them; upgrade
detection tooling before relying on new marks. The cell layout is
versioned the same way: v1.13 introduced the 128-bit-seeded
`layoutVersion: 2`; **since v1.14, embeds default to the
SHA-256-seeded `layoutVersion: 3`**, v1.20 added the opt-in
error-correcting `layoutVersion: 4` (BCH), and v1.30 added the
experimental opt-in `layoutVersion: 5` (BCH plus a keyed registration
pilot lattice). Detectors dual-read supported layouts and report the
vintage as `layoutVersion`; a detector older than the layout cannot
read it. Layout 5 is not the default. Its deterministic synthetic
asymmetric-crop and affine/keystone fixtures are regression coverage,
not a real-photo corpus or general survival guarantee. The operators' rule is
unchanged — upgrade detection tooling first, embed with an older
`layoutVersion` only where an unupgraded detector must read new
marks, and prefer re-issuance. `layoutVersion: 3` remains the default.

Two deliberate, configurable trade-offs deserve explicit operator
choices rather than defaults discovered by accident:

- **Replay-store saturation.** One-time claims live in a bounded
  store. `replaySaturation: 'evict'` (default) favors availability by
  evicting the oldest LIVE claims under sustained mint pressure
  (emitting `archx.replay_store_evicted`); `'strict'` preserves
  one-time semantics absolutely and instead rejects new redemptions
  while saturated. Size `oneTimeTokenMaxEntries` for
  peak-claims-per-second × token TTL × margin in either mode.
- **Full-resolution pixels.** The master file and its metadata are
  never served, but an entitlement whose caps reach the master's own
  dimensions receives full-resolution PIXELS. `maxWidthFraction < 1`
  makes "preview only" a server-enforced property.
