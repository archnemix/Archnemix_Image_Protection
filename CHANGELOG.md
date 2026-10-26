# Changelog

All notable changes to Archnemix Image Protection (`Archx`) are documented
here. The project follows semantic versioning once a version is released.

## [1.5.0] — Unreleased

### Added

- Configurable 60 Hz-first temporal interlace with checker, pixel, strip,
  and randomized-block phase layouts.
- Selectable temporal-interlace drawing engines: WebGL fragment shader or
  pre-rendered Canvas2D phase frames, plus an automatic mode.
- Sender-constrained token redemption using an ephemeral, non-extractable
  browser P-256 proof key.
- Header-carried payload tokens against clean payload URLs by default.
- Optional 64-bit perceptual soft-binding fingerprints for offline
  attribution workflows.
- Strict BMP screenshot decoding in the `archx-detect` investigation path.
- Security policy, Dependabot configuration, Node 20/22 CI, and a dedicated
  reviewer guide.
- Pluggable state-store interface for atomic one-time claims, rate windows,
  quotas, distinct-image tracking, and an optional shared derivative cache;
  declared multi-instance deployments fail startup without shared state.
- Versioned signing-key rotation with token `kid`, an active/previous
  keyring, and issuing-key derivations during rollover.
- Versioned structured security-event fields for SIEM forwarding while
  retaining the existing event types and top-level compatibility fields.
- Operations, compliance-readiness, compatibility, and plain-language
  IP-holder guides, plus a bounded mint+redeem load-test tool.

### Changed

- Server requirements are Node.js `>=20.9.0` and Sharp `^0.35.5`.
- Server configuration and authorization results are validated strictly and
  fail closed when ambiguous, misspelled, weak, or unsafe.
- Token, payload, image-container, response, and decoded-image handling now
  enforce explicit byte, dimension, pixel, channel, output, and time
  budgets.
- Proxy IP handling uses the socket address unless an exact trusted-hop
  configuration selects an `X-Forwarded-For` value from the trusted side.
- Cache-deception controls now cover standard, CDN, and surrogate cache
  headers for token and payload responses.

### Removed

- Public generic token signing/verification helpers.
- `handler._test` and the live `handler.index` surface.
- Weak-secret test bypasses and other fail-open compatibility paths.

### Security notes

Archx remains layered theft friction and attribution, not DRM. The server
must keep masters outside public roots and enforce `authorize()` at both
token minting and redemption. Displayed pixels can still be captured by an
authorized recipient, operating system, browser-privileged tool, or camera;
see `SECURITY.md` and `docs/RESEARCH.md` for the full model.
