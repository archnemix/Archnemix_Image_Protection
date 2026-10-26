# Compliance and assurance readiness

## Status

This document is a **self-assessment and audit-readiness map**. It is not an
OWASP ASVS certification, SOC 2 report, penetration-test result, legal
opinion, or customer security sign-off.

As of this revision:

- no independent third-party security audit of Archx is claimed;
- no SOC 2 examination of Archx or its maintainer is claimed;
- no funded public bug bounty is active;
- automated tests cover the behaviors described in the repository, but they
  do not replace an independent review of a production deployment.

A customer can use this map to scope their own review. The deploying
organization remains responsible for identity, authorization data, cloud
configuration, CDN rules, secret management, monitoring, incident response,
privacy retention, and contractual commitments.

## Shared-responsibility model

| Area | Archx provides | Deployer must provide |
| --- | --- | --- |
| Identity and sessions | Calls `authorize()` at token mint and redemption | Authentication, session security, account lifecycle, MFA/admin controls |
| Object authorization | Deny-by-default callback contract and entitlement tightening | Correct image/viewer/order entitlement logic and tests |
| Token replay | One-time claims through a local or shared store | Correct multi-instance store, consistency, TLS, and operations |
| Secrets | Keyring/`kid` rotation and weak-secret rejection | KMS/secret manager, generation, distribution, rotation records |
| Image processing | Sharp budgets, format checks, timeouts, bounded queues | Current Node/Sharp/libvips, malware/content policy for masters, resource isolation |
| Network/CDN | Private/no-store origin headers and runbook | CDN bypass rules, WAF/TLS, log redaction, deployed verification |
| Monitoring | Versioned security events and handler stats | SIEM ingestion, alert ownership, retention, incident response |
| Availability | Fail-closed state-store behavior and load-test tool | Capacity, redundancy, backups, regional failover exercises |
| Watermark evidence | StegoMark/forensic issuance hooks and detector tooling | Durable registry, chain of custody, investigation/legal process |
| Compliance evidence | Source, tests, CI, SBOM process, this map | Organization policies, audits, vendor review, customer contracts |

## OWASP ASVS-oriented self-assessment

The mapping below is intentionally at control-family level. It does not
assert a formal ASVS level. "Implemented" means the mechanism exists in this
repository; it still requires correct deployment and testing.

| ASVS family | Status | Evidence / notes |
| --- | --- | --- |
| V1 Architecture, design, threat modeling | Partial | `docs/RESEARCH.md`, this file, and `docs/OPERATIONS.md` describe trust boundaries and residual risks. A deployment-specific threat model is still required. |
| V2 Authentication | Host responsibility | Archx does not authenticate users. It requires an `authorize()` callback unless a catalog is explicitly anonymous. |
| V3 Session management | Host responsibility | Session cookies/tokens belong to the host app. Archx can bind a short token to viewer/session context and re-authorizes redemption. |
| V4 Access control | Implemented framework | Deny-by-default mint+redeem authorization, strict entitlement normalization, current entitlement can tighten but not widen signed width/quality. Host must test object-level authorization. |
| V5 Validation, sanitization, encoding | Implemented | Strict image IDs, paths, token claim allowlists, URL/body budgets, origin values, callback results, and image signatures/dimensions. |
| V6 Stored cryptography | Implemented with limits | HMAC-SHA-256 tokens, versioned key IDs/keyring, optional AES-GCM payload obfuscation, WebCrypto proof keys. Client-delivered keys are not DRM. Host owns key custody. |
| V7 Error handling and logging | Implemented framework | Generic client errors and versioned security events without token/proof material. Host owns SIEM retention/alerts and must protect raw viewer/IP fields. |
| V8 Data protection | Partial | Masters remain outside public roots, derivatives are capped/scrambled/marked, responses are private/no-store. Host owns storage encryption, backups, CDN rules, and privacy classification. |
| V9 Communications | Host responsibility | HTTPS, TLS certificates, HSTS, and proxy trust belong to the deployment. Header-token transport is available and recommended. |
| V10 Malicious code | Partial | Lockfile, CI, dependency audit, Dependabot, and SBOM process. No claim of malware scanning for uploaded masters. |
| V11 Business logic | Implemented framework | Short token TTLs, one-time claims, proof replay claims, quotas, distinct-image detection, entitlement re-checks, and state-store fail-closed behavior. |
| V12 Files and resources | Implemented | Indexed masters only, real-path containment, symlink/public-dir checks, byte/pixel/dimension/format/time/concurrency budgets. |
| V13 API and web service | Implemented | Exact routes/methods, token request header, Fetch Metadata checks, exact CORS origins, bounded stores/queues, rate limits. |
| V14 Configuration | Implemented framework | Strict unknown-option rejection, secret/deployed-mode checks, non-throwing secret-free config audit. Host must run it in deployment tests. |

## SOC 2 readiness map

SOC 2 examines an organization's controls over a period of time. Archx can
support technical controls in a larger system; the library alone cannot be
"SOC 2 compliant."

| Criteria area | How Archx can support it | Organization evidence still needed |
| --- | --- | --- |
| CC6.1 logical access | Deny-by-default authorization hooks, short-lived scoped tokens | Identity lifecycle, least-privilege cloud/KMS access, access reviews |
| CC6.6 boundary protection | Master containment, CDN no-store guidance, exact origins | Network architecture, WAF/CDN change records, penetration tests |
| CC6.7 data transmission/disposal | Header tokens, no-store responses, derivative-only delivery | TLS standards, retention/deletion procedures, backup handling |
| CC7.2 system monitoring | Structured events, stats, suspicious-scraping signals | SIEM dashboards, alert runbooks, on-call records |
| CC7.3 incident evaluation | Replay/quota/state-store event reasons and key-rotation runbook | Incident policy, ticketing, post-incident reviews |
| CC7.4 recovery | Fail-closed store behavior and active/passive guidance | Backups, restore tests, failover exercises, RTO/RPO |
| CC8.1 change management | Git history, CI checks, lockfile, changelog | Approval workflow, segregation of duties, production release records |
| A1 availability/capacity | Processing bounds and load-test tool | Capacity forecasts, load-test reports, autoscaling and SLOs |
| C1 confidentiality | Never serves masters through the protected route; keyed marks/tokens | Data classification, encryption at rest, vendor/subprocessor management |
| P privacy criteria (if selected) | Viewer hashes in structured events; no tokens in event route | Privacy notices, lawful basis, IP/viewer retention and deletion process |

## Independent-audit readiness package

Before engaging an auditor or penetration tester, provide:

1. The exact Git commit, package lockfile, SBOM, Node/Sharp versions, and
   build provenance available from your release pipeline.
2. A data-flow diagram for browser, CDN/WAF, application, `authorize()`,
   state store, master storage, Stego registry, logs/SIEM, and secret manager.
3. Production-like configuration with secrets redacted, including
   `handler.configAudit` output and CDN rules.
4. Test accounts representing anonymous, free, paid, revoked, downgraded,
   and cross-tenant users.
5. Test cases for direct-master access, traversal/symlinks, token tampering,
   replay across instances, proof theft/replay, authorization changes inside
   the TTL, quota bypass, malformed/oversized images, Sharp resource limits,
   CDN shared-cache behavior, state-store outage/failover, and key retirement.
6. Load-test results and the environment details listed in
   `docs/OPERATIONS.md`.
7. A list of accepted residual risks: screenshots/cameras, authorized-user
   reconstruction, browser/CDP capture, AI regeneration, watermark removal,
   and client-key extraction.

Audit scope should explicitly state whether the target is only this library,
a complete customer deployment, or both. Findings should be tracked to
remediation/retest; publishing an auditor's name or report requires that
auditor's permission.

## Supply-chain process

Recommended release process for maintainers and enterprise consumers:

1. Install with `npm ci` from the committed lockfile; do not use floating
   installs for a reviewed build.
2. Run `npm run verify` and `npm audit --audit-level=high` in CI.
3. Generate an SBOM for the exact release tree:

   ```bash
   npm sbom --sbom-format cyclonedx > sbom.cdx.json
   ```

4. Review Dependabot updates with the changelog and test output. Sharp
   bundles/prebuilds native image libraries such as libvips; treat Sharp and
   platform package updates as security-relevant even when Archx code does
   not change.
5. Pin or record the Node, npm, Sharp, operating-system, and container image
   versions used in production.
6. Verify package signatures/provenance if your registry and release process
   provide them. Provenance helps establish origin; it does not prove code
   is safe.
7. Keep generated SBOMs and audit output with release evidence rather than
   treating a one-time SBOM in source control as permanently current.

Suggested internal response targets—**not a contractual SLA unless your
organization adopts one**—are: triage critical reachable dependency issues
within one business day, ship or mitigate high-severity reachable issues
within seven days, and review routine dependency updates monthly. Adjust
these targets to the support you actually staff.

## Vulnerability reporting and bug-bounty status

There is currently **no funded public bug-bounty program**. Please use the
private reporting process in `SECURITY.md`. Do not test a third party's
deployment without that operator's written authorization.

If a bounty is launched later, publish a separate program page defining:

- in-scope repositories, versions, and test deployments;
- out-of-scope reports (for example, the documented screenshot/analog hole
  without an additional authorization or master-exposure impact);
- safe-harbor language and prohibited actions;
- severity/reward ranges and duplicate policy;
- response targets and disclosure timeline;
- a dedicated test environment and test data.

Until that page exists, researchers should not infer permission to test any
production site merely because it uses Archx.
