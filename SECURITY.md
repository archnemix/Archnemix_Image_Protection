# Security policy

## Supported versions

Security fixes target the latest 1.5.x release and the current development
branch. Older releases should be upgraded, especially because image decoding
depends on current Sharp/libvips security fixes.

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
