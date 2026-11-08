# Archx operations guide

This guide covers deployment topologies that the code itself cannot prove:
shared state, key rotation, CDN behavior, observability, regional failover,
and capacity testing. It is an operator runbook, not a certification or a
claim that a particular third-party service has been configured correctly.

## 1. Deployment modes

| Topology | Configuration | Security-state location | Acceptable use |
| --- | --- | --- | --- |
| One Node.js process | `deploymentMode: 'single-instance'` (default) | Built-in process-local memory store | Small deployments and local development |
| Several processes/machines behind a load balancer | `deploymentMode: 'multi-instance'` plus a host-supplied `stateStore` | One shared, atomic backend | Horizontally scaled production |
| Active/passive regions | Multi-instance settings in both regions, with a reviewed state-replication/failover design | Primary or globally consistent store | Regional recovery |
| Active/active regions | Only with a globally atomic claim design | One logical claim authority | Advanced deployments after failure testing |

The middleware refuses to start a declared `multi-instance` deployment with
no store, or with the built-in memory store. That guard prevents the most
dangerous silent failure: a token being replayed against every instance
because each process only remembers the claims it handled itself.

State that must agree across instances:

- one-time token nonce claims;
- one-time proof-of-possession proof IDs;
- token/image rate-limit windows and a separate SEO-preview window when that optional route is enabled;
- viewer/IP/image quotas;
- distinct-image scraping detection.

Master-file caches, processed-output L1 caches, dimension caches, and Sharp
semaphores may remain process-local. They affect performance, not the
one-time-use security invariant. Derivative reuse can add two more layers
after authorization: a persistent, private on-disk L2 (`outputCacheDir`) and
an optional shared state-store cache. Neither layer is an authorization or
replay record, and neither may be placed in a public web root.

Run both non-throwing audits in deployment tests or a readiness check:

```js
import {
  auditArchxProductionConfig,
  auditArchxServerConfig,
} from '@archnemix/image-protection/server';

const audit = auditArchxServerConfig(options);
const production = auditArchxProductionConfig(options, {
  expectedInstances: Number(process.env.ARCHX_EXPECTED_INSTANCES || 1),
});
// Gate the release on production.ready — and only on production.ready.
// audit.ok (== audit.configOk == production.configOk) merely proves the
// configuration is internally valid; a valid configuration can still carry
// live production blockers. (On the production audit itself, `ok` has meant
// the same as `ready` since v1.27.) Neither audit summary contains a secret.
if (!production.ready) {
  throw new Error(`Archx production blockers:\n- ${production.blockers.join('\n- ')}`);
}
void audit; // keep for diagnostics: audit.issues/warnings are inside blockers
```

`auditArchxServerConfig()` answers whether the middleware accepts the
configuration. `auditArchxProductionConfig()` additionally reports
blockers for anonymous catalogues without recalibrated controls, query
tokens, missing/optional proof of possession, reusable delivery tokens,
long token TTLs, unregistered StegoMark issuance, and process-local state
behind more than one instance. Keep its secret-free summary with release
evidence. For a new production configuration, start from
`withHardenedProductionDefaults(options)` (or, since 1.28, the named
profiles: `withLiteDefaults()` for CPU/RAM-first catalogs,
`withPerformanceDefaults()` for the balanced default, and
`withEliteDefaults()` for security-first delivery — hardened baseline
plus `maxWidthFraction: 0.6` so previews withhold native resolution by
default) and make any relaxation explicit,
owned, and tested rather than accidental.

## 2. Shared `stateStore` contract

The package now ships a framework-neutral Redis/Valkey adapter at
`@archnemix/image-protection/redis`. It accepts an ioredis- or
node-redis-compatible client supplied and operated by the host; the host
still owns credentials, TLS, persistence/eviction, failover, and latency.
For DynamoDB/Upstash HTTP/another backend, supply an adapter with this
shape:

```js
const stateStore = {
  kind: 'redis', // diagnostic label only; must not be 'memory' in multi-instance mode

  // Return true only to the first caller until ttlMs expires.
  async claimOnce(key, ttlMs) {},

  // Atomically add one hit if `limit` would not be exceeded in the sliding
  // window. Return retry timing when limited.
  async hitWindow(key, { limit, windowMs, now }) {
    return { limited: false, retryAfterSec: 0, count: 1 };
  },

  // Atomically record `member` in a bounded sliding set.
  async trackDistinct(key, member, { windowMs, maxMembers, now }) {
    return { distinct: 1, isNew: true };
  },

  // Optional shared derivative cache.
  async getCache(key) { return null; },
  async setCache(key, bytes, { ttlMs }) {},

  // Optional diagnostics/lifecycle hooks.
  stats() { return {}; },
  async close() {},
};
```

Contract requirements:

1. `claimOnce`, `hitWindow`, and `trackDistinct` must be atomic. A separate
   read followed by a write is not acceptable.
2. Keys are already namespaced by the middleware (`nonce:`, `proof:`,
   `rate:`, `quota:`, `distinct:`, and `cache:`). Prefix them again with your
   environment and tenant/deployment name in the adapter. Rate/quota/
   distinct keys can contain an IP address and image ID; protect the store as
   operational personal data, use short TTLs, and have the adapter apply a
   consistent keyed hash if raw IPs must not be visible to store operators.
3. Return the exact result types above. Malformed results are treated as a
   store outage and the request fails closed.
4. Errors and operations slower than `stateStoreTimeoutMs` produce a generic
   `503 service unavailable`; the middleware never falls back to process-local
   replay/quota state after a shared-store failure. The 250 ms default is a
   starting point for a same-region store—measure p99 latency and set a
   bounded value that fits your request budget.
5. Optional cache failures are non-fatal because the request can be
   re-authorized and reprocessed. Never use the cache as an authorization or
   replay record. Set `sharedCacheTtlMs: 0` to disable shared derivative
   caching while still using the store for security state.
6. A supplied store is host-owned. `handler.close()` does not close it,
   because several handlers may share it; close it during application
   shutdown.
7. **Eviction policy is a security setting (v1.18).** Redis/Valkey with
   an LRU/LFU `maxmemory-policy` can silently evict `nonce:`/`proof:`
   keys under pressure — that replays tokens exactly like local-store
   saturation. Run security state on an instance (or logical DB in a
   dedicated fleet) with `maxmemory-policy noeviction`, size memory
   for peak claim rate × TTL, and alert on used-memory headroom. The
   in-memory store makes the same trade-off explicit instead:
   `replaySaturation: 'evict' | 'strict'` plus live counters in
   `handler.stats().replaySets` and the `archx.replay_store_evicted`
   event. **Decide this one deliberately** (v1.20): the general library
   default stays `'evict'` for compatibility, `withHardenedProductionDefaults`
   sets `'strict'`, and the production audit now blocks `'evict'` whenever
   one-time tokens are enabled. Strict mode is required for the hardened
   production baseline; the default is not a production recommendation:

   | Policy | When the store is full of live claims | Failure you accept |
   | --- | --- | --- |
   | `'evict'` (library default) | Oldest live JTI is dropped; new redemption proceeds | A narrow replay window reopens for that one already-redeemed token until its expiry — still signed, still re-authorized at redemption, still PoP-bound where configured |
   | `'strict'` (hardened preset) | New claims are rejected until entries expire | Legitimate redemptions fail under sustained mint pressure (availability incident) |

   Sizing makes either safe: `oneTimeTokenMaxEntries` >= peak redemptions/sec ×
   token TTL seconds × 4 (burst + clock-skew margin); the production
   audit blocks < 10,000 entries.

Bundled Redis example:

```js
import Redis from 'ioredis';
import { createRedisStateStore } from '@archnemix/image-protection/redis';

const redis = new Redis(process.env.REDIS_URL, {
  enableReadyCheck: true,
  maxRetriesPerRequest: 1,
});
const stateStore = createRedisStateStore({
  client: redis,
  prefix: 'archx:prod',
  clientFlavor: 'ioredis',
});

app.use(createArchxMiddleware({
  secrets: {
    '2026-01': process.env.ARCHX_SECRET_2026_01,
    '2026-02': process.env.ARCHX_SECRET_2026_02,
  },
  activeSecretId: '2026-02',
  deploymentMode: 'multi-instance',
  stateStore,
  stateStoreTimeoutMs: 250,
  sharedCacheTtlMs: 3600000,
  // imagesDir, authorize, quotas, processing limits, ...
}));
```

### Redis/Valkey implementation notes

Use a private, authenticated TLS endpoint. The bundled adapter performs
each operation below against one Redis key, so it does not rely on
cross-key transactions and can work with Cluster:

- `claimOnce`: `SET key 1 NX PX ttlMs`; return `true` only for `OK`.
- `hitWindow`: use a Lua script over a sorted set. In one script, remove
  entries at or before `now - windowMs`, count the remainder, return
  `limited` plus the retry delay from the oldest entry when full, or add a
  globally unique member (for example `now:UUID`), refresh `PEXPIRE`, and
  return the new count.
- `trackDistinct`: use a Lua script over a sorted set. In one script, evict
  expired members, determine whether the member already exists, add/update
  it, trim oldest members above `maxMembers`, refresh `PEXPIRE`, and return
  `{ distinct, isNew }`.
- `getCache`/`setCache`: shared cache values are stored as ASCII `b64:`-prefixed base64, then decoded back to the original bytes. This avoids binary GET differences between ioredis and node-redis versions at the cost of about 33% extra cache storage/bandwidth. Consider a separate cache cluster/database so large derivative values cannot evict short-lived replay claims. Scrambled/encrypted derivatives are still access-controlled data; encrypt transport and restrict network access.

The shipped adapter signature is
`createRedisStateStore({ client, prefix, clientFlavor, closeClient })`.
`clientFlavor` defaults to `'auto'` and may be pinned to `'ioredis'`,
`'node-redis'`, or `'generic'`; `closeClient` defaults to `false` because the
host owns the client. Keys are `prefix + ':' + middlewareKey` and can expose
the operational IP/image components described above—protect Redis access and
TTL/retention accordingly rather than assuming key names are anonymized.
Middleware cache byte/entry limits still bound what Archx asks the adapter
to store. Its `stats()` deliberately does not scan the keyspace. Configure
Redis eviction so memory pressure cannot silently delete replay/quota keys;
keep `noeviction` or a reviewed equivalent for security state, alert before
capacity pressure, and treat command errors as an outage rather than
expecting a fallback.

Redis replication deserves an explicit decision. With asynchronous
replication, a newly promoted replica might miss a very recent claim. For a
strict one-time-use invariant, use durable/synchronous settings appropriate
to your provider, fail closed during failover, or choose a conditional-write
store whose consistency model you can prove. Test replica promotion while
replaying tokens; do not infer safety from the word "cluster."

### DynamoDB-style implementation notes

A single table can use the store key as the partition key plus a TTL
attribute:

- `claimOnce`: conditional `PutItem` with `attribute_not_exists(pk)` (also
  account for expired-but-not-yet-deleted TTL rows in the condition).
- Windows/distinct sets: use transactions or an atomic update design with
  bounded item sizes. A naïve read-modify-write can race.
- Pay attention to DynamoDB's 400 KB item limit for windows/distinct sets and
  do not store full derivative bytes in the same table unless each value is
  safely below service limits. Object storage is a better optional L2 cache,
  provided every read remains behind middleware authorization and replay
  checks.

Whatever backend is chosen, add an integration test equivalent to the unit
suite's shared-store test: mint on instance A, redeem on B, then prove replay
on A is `403`; also prove quotas continue across A/B and a store outage is
`503`, not `200`.

## 3. Signing-key rotation

Tokens now carry a non-secret `kid`. New tokens are signed only with
`activeSecretId`; tokens already issued under a previous key verify with that
key and use it for token-bound viewer hashes, bindings, scramble/AES keys,
forensic seeds, StegoMark fingerprints/keys, and cache partitioning.

Normal rotation:

The repository includes a rotation helper. It creates a fresh 256-bit
secret and an executable UTC activation/retirement schedule. After importing
the two secrets on every instance, pass the schedule to middleware as
`signingKeySchedule`; the middleware switches the signing key at activation
and drops the old key from verification at retirement on the first request
boundary at or after each instant. It does not deploy secret material to your
secret manager:

```sh
npm run key:rotation-plan -- --current-id signing-2026a --ttl-sec 900 \
  --activate-at 2026-11-14T00:00:00Z --output /secure/archx-rotation.json
```

The output file is created exclusively with mode `0600` and contains secret
material. Import the generated key into your secret manager, make it available
to every serving instance as `secrets[newSecretId]`, then securely remove the
local file. Never check it in, attach it to a ticket, or forward it in
logs/chat. Supply the emitted `schedule` object as `signingKeySchedule`, with
`activeSecretId` still set to `currentSecretId`. Every instance evaluates the
same UTC timestamps on request boundaries; keep clocks synchronized. For
example:

```js
createArchxMiddleware({
  secrets: { [currentSecretId]: oldSecret, [newSecretId]: newSecret },
  activeSecretId: currentSecretId,
  signingKeySchedule: handoff.schedule,
  // other production options…
});
```

1. Stage old and new secrets on every instance and deploy the same schedule.
   The runtime audit reports IDs/timestamps/counts only, never secret values.
2. Before `activateAt`, tokens continue to use the old key. At the first mint
   after `activateAt`, all nodes sign with `newSecretId`; the old key remains
   verifiable during the grace window.
3. At `retireAt` (which validation requires to be at least the API maximum
   token TTL of 900 seconds plus grace after activation), the first request
   on each node removes the old key from token verification and disk-cache tag
   verification. Old tokens
   then fail closed. Monitor each node's `handler.stats().activeSecretId` to
   confirm activation; configure a release/runbook alert for nodes that do not
   receive traffic around the timestamps.
4. Record the rotation time, key IDs, operator, approval/change ticket, and
   confirmation that all instances activated and retired as scheduled.
   Static investigations may need an old StegoMark detector secret much
   longer; retain that separately in the evidence vault, not on serving nodes.

The middleware schedules transitions deterministically, but importing and
staging secrets remains a secret-manager/deployment action. Test the exact
schedule in staging and verify both activation and retirement before
production rollout. If rollback is needed before retirement, redeploy a
corrected schedule while both secrets remain present; after retirement, a
retired key must be re-added explicitly before it can verify old tokens.

For suspected compromise, remove the compromised key immediately. Existing
tokens under it will fail and clients must mint fresh tokens, which is the
correct failure mode. Then rotate related credentials, inspect issuance and
security-event logs, invalidate application sessions if appropriate, and
treat any derivative issued under the compromised period as potentially
reproducible by the attacker. The master is still not exposed merely by a
signing-key compromise if authorization and file-system boundaries held, but
an attacker who can also pass `authorize()` could mint valid derivatives.

When StegoMark is enabled, `onStegoIssue` receives `keyId`, `profile`, the
bounded grid/strength, fingerprint, image, viewer, buyer, order, delivery,
trace hash, nonce, derivative dimensions/quality, and times. Persist those
fields transactionally so investigators know which retired secret and
profile derive the detector key. The record intentionally contains no
signing secret, access token, scramble key, or AES key.

## 4. CDN and reverse-proxy configuration

The origin sends private/no-store cache controls, CDN/surrogate controls,
`Vary`, `nosniff`, and related headers for token and payload responses. A CDN
rule must not override those controls. Protected token and payload routes
should bypass shared caching entirely. If the opt-in `seoCrawler` route is
configured, `{basePath}/seo/*` also sends `private, no-store`; bypass shared
caching there too, even though the process may reuse a bounded in-memory
watermarked derivative after re-running crawler verification on each request. SEO
requests use a separate rate-limit namespace with the configured general
`rateLimitPerMinute` ceiling, so preview traffic cannot consume the protected
`/i/:id` route's rate budget.

The SEO route is not the protected `/i/:id` route: `GET`/`HEAD /seo/:id`
serves an ordinary WebP/JPEG only after the host's `seoCrawler.verify(req,id)`
returns exactly `true`. The callback must authenticate the crawler from a
trusted signal such as verified source-IP data; `User-Agent` matching alone
is spoofable and is not sufficient. Forwarded client IP headers are trusted
only when requests can arrive exclusively from the configured proxy and the
proxy overwrites those headers. A false result is a non-disclosing 404; a
callback error/timeout is fail-closed. The image is capped to at most 640 px,
no more than the configured fraction of the master width, lossy quality at
most 75, and a server-baked visible `PREVIEW ONLY` watermark. Do not map
`/seo/*` back to master files or allow a CDN image optimizer to replace the
response.

### CloudFront reference behavior

Create behaviors for `/archx/token/*`, the exact batch route `/archx/tokens`, `/archx/i/*`, and (only when enabled) `/archx/seo/*` (adjust `basePath`):

- Viewer protocol: redirect HTTP to HTTPS or HTTPS only.
- Allowed methods: token behavior must allow the configured token methods
  and `OPTIONS`; image behavior allows `GET` and `OPTIONS`; the optional SEO
  behavior allows `GET` and `HEAD` only.
- Cache policy: `Managed-CachingDisabled`.
- Origin request policy: forward only what your `authorize()` needs, plus
  `X-Archx-Request`, `X-Archx-Proof-Key`, `X-Archx-Token`, `X-Archx-Proof`,
  `Origin`, `Referer`, `Sec-Fetch-Site`, `User-Agent`, and your chosen
  session cookie/authorization header.
- Response-headers policy: do not set or replace `Cache-Control`,
  `CDN-Cache-Control`, or `Surrogate-Control` for these behaviors.
- Do not enable a function/edge rule that strips query strings, normalizes
  duplicate headers, converts the payload to an image, or creates a shared
  cache key.
- Keep compression behavior consistent between viewers; the payload is an
  opaque `.archx`/`application/octet-stream` response, not a transformable
  image.

### Cloudflare reference rule

Create a Cache Rule for the token and payload paths (and the SEO path when enabled):

- Expression based on URI path, for example:
  `(starts_with(http.request.uri.path, "/archx/token/")) or (http.request.uri.path eq "/archx/tokens") or (starts_with(http.request.uri.path, "/archx/i/")) or (starts_with(http.request.uri.path, "/archx/seo/"))`
- Cache eligibility: **Bypass cache**.
- Do not apply "Cache Everything", APO, Cache Reserve, Polish, Mirage, image
  resizing, or a Worker cache to these paths.
- Ensure Transform Rules/Workers preserve all `X-Archx-*` headers and do not
  add a permissive `Cache-Control` response header.
- Disable any generic rule that caches based on file extension or a
  static-looking URL for these routes.

### Origin-taint pixel

`{basePath}/taint.png` is a constant 68-byte transparent PNG with immutable
caching and deliberately **no** CORS headers; it exists so cross-origin
pages can origin-taint 2D canvas readback (see the README's memory model).
Keep it reachable cross-origin, never behind authentication, and never
redirect it to the page's own origin — a same-origin load is origin-clean
and the layer silently disappears. Set `taintImage:false` if you serve
your own pixel through the client's `taintUrl` instead.

### Precomputed static assets are a separate behavior

Versioned files produced by `archx-build` are not dynamic token payloads.
When the catalog is intentionally public, serve the immutable
`{id}-{width}w-{version}.archx` files through the CDN with a long cache
lifetime (for example `public, max-age=31536000, immutable`) and an opaque
content type. Do not run image resizing/optimization on them. The manifest
needs a different policy: version it per deploy or use short/revalidating
cache headers, and put it behind your normal signed-URL/authorization layer
for a private catalog because it contains the browser scramble key (and AES
key when enabled). Never publish masters or `.archx-build-state.json`.

Deploy order matters when browsers pin the manifest with
`assetManifestIntegrity`: upload the new versioned variants first, then the
new manifest, then the page/config carrying the new `sha256-…` pin (the
value `archx-build` prints as `Manifest SHA-256`). Reversing that order
makes correctly-pinned browsers reject the not-yet-deployed manifest.
Keep `assetIntegrity: 'auto'` (or `'require'`) so a corrupted or
substituted variant object fails its manifest SHA-256 check in the browser
instead of rendering garbage or attacker-chosen pixels.

### Post-deployment CDN verification

With an authorized test account and a disposable image:

1. Mint one token through the public CDN hostname using the header-token
   flow. Keep `allowQueryTokens:false` (the default) and do not place the
   token in a URL.
2. Redeem it once and confirm `200` plus origin `private, no-store` headers.
3. Redeem the exact same token again. It must be `403`, never a cached `200`.
4. Check CDN diagnostics: Cloudflare should show `BYPASS` or `DYNAMIC` (not
   `HIT`); CloudFront should not show a shared-cache hit for either route.
5. Repeat token minting as a different viewer/entitlement and confirm the
   second viewer cannot receive the first viewer's size, watermark, or
   forensic/Stego derivative from a shared cache.
6. Confirm an unauthenticated request cannot retrieve a previous payload by
   replaying only the clean image URL.
7. Inspect access logs to verify bearer tokens are not in URLs and custom
   token/proof headers are not logged.

If any check fails, remove the CDN behavior or bypass the hostname until it
passes. Origin headers are a seat belt; an explicit bypass rule and the
replay test are the verification.

## 5. Structured security events and SIEM forwarding

`onSecurityEvent` errors never alter authorization. Events have
`schemaVersion: 1` and retain the older top-level fields for compatibility:

| Field | Meaning |
| --- | --- |
| `eventId` | Random UUID for deduplication/correlation |
| `service` | Always `archx` |
| `severity` | `notice`, `warning`, or `error` |
| `outcome` | `denied`, `detected`, `completed`, or `error` |
| `type` | Existing event type, such as `archx.denied` |
| `at` | ISO-8601 UTC timestamp |
| `imageId` / `id` | Validated image ID when available |
| `phase` | `token`, `image`, or `null` |
| `status` | HTTP status when known |
| `actor.ip` | Socket or correctly trusted-hop-derived IP |
| `actor.viewerHash` | Keyed viewer hash suitable for correlation |
| `request.method` | HTTP method |
| `request.route` | Route template; no token or query string |
| `reason` | Bounded internal reason such as `token-replay` |
| `keyId` / `previousKeyId` / `activeKeyId` | Key IDs only on scheduled signing-key lifecycle events; never secret values |

Scheduled key rotation emits `archx.signing_key_activated` and
`archx.signing_key_retired` once per transition through `onSecurityEvent`, with
`outcome: completed`. Events contain key IDs only. They are emitted when a
request boundary first observes the configured UTC transition, so each
instance reports its own transition; deploy a shared schedule to all instances
and monitor that every instance reports activation and retirement.

Step-up challenges (v1.19) emit `archx.challenge_required` (403,
`reason: challenge-required`) and `archx.challenge_passed` events in the
same schema; alert on required-but-never-passed subjects, not on the gate
itself — a healthy shared-NAT office will trip it occasionally.

The legacy raw `viewerId` remains at top level because the host supplied it
and existing consumers may use it. For SIEM export, prefer dropping raw
`viewerId` and using `actor.viewerHash`; apply your IP-retention policy to
`actor.ip`/`ip`. Never add tokens, proof headers, cookies, authorization
headers, scramble keys, or master paths to the event sink.

Generic structured forwarding:

```js
onSecurityEvent: async (event) => {
  const { viewerId, ...exported } = event;
  process.stdout.write(JSON.stringify({
    ...exported,
    env: process.env.NODE_ENV,
    deployment: process.env.ARCHX_DEPLOYMENT,
  }) + '\n');
},
```

- **Datadog:** collect the JSON lines with the Agent or a log forwarder; set
  `service: archx`, environment/source tags, and index `type`, `reason`,
  `severity`, `imageId`, and `actor.viewerHash` as facets.
- **Splunk:** send the same JSON object to HEC as the event body with a
  dedicated index and sourcetype such as `archx:security`; extract the
  schema fields above rather than parsing free text.
- **CloudWatch:** write JSON lines to stdout in Lambda/ECS/Fargate or use the
  CloudWatch agent; create metric filters on `reason` and `severity`.

Suggested starting alerts (tune to real traffic):

- any `state-store-unavailable` event;
- `archx.suspicious_scraping` above baseline;
- spikes in `token-replay`, `proof-replay`, `viewer-binding`, or proof errors;
- repeated quota exhaustion by one `actor.viewerHash` or IP;
- `archx.stego_registry_failed` above zero;
- `archx.provenance_issue_failed` above zero;
- sustained processing errors/timeouts or Sharp queue saturation.

### StegoMark registry, delivery telemetry, and provenance

Return stable `buyerId`, `orderId`, `deliveryId`, and, when useful,
`traceId` from `authorize()`. Viewer IDs are accepted up to 512 JavaScript
`String.length` code units; each trace ID is accepted up to 256 code units.
Archx validates and HMAC-binds
the full values using an unambiguous field encoding, uses them for
`{buyer}`/`{order}`/`{delivery}`/`{trace}` visible-mark text and trace-derived
StegoMark subjects, and rechecks the complete trace context at redemption;
removing or changing a previously supplied field denies delivery.
Persist the complete `onStegoIssue` record before considering issuance
successful. With `stegoRegistryFailure:'deny'` (the default and production
expectation), a failed or timed-out registry write returns `503`, spends the
one-time token/proof, and emits `archx.stego_registry_failed`; require a
fresh mint after recovery rather than silently delivering an untraceable
derivative. `'allow'` is an explicit availability-over-attribution policy,
not equivalent protection.

Successful deliveries can be forwarded with `onDelivery` to product
analytics, a monitoring queue, or an operator-managed reverse-image-search
workflow. The frozen record contains image/viewer/buyer/order/delivery
context, key ID, trace hash, width/quality/format, cache/result metadata,
and completion time only—never an access token, proof, scramble key, AES
key, payload bytes, or master path. Callback failures cannot revoke an
already-completed response, so queue/retry inside the host sink if loss is
unacceptable.

`onProvenanceIssue` is the external C2PA/provenance extension point. It is
awaited at token issuance with the same key-free actor/order/trace context
and may create or reserve a manifest record in the host's signing service.
It does not receive derivative bytes and therefore does not itself sign or
embed C2PA. `provenanceFailure:'deny'` (default) blocks issuance and emits
`archx.provenance_issue_failed`; `'allow'` continues token issuance and
must be reconciled by the operator. Never add the full token response to a
provenance manifest: it is short-lived delivery material, not public
provenance evidence.

Expose `handler.stats()` only on an authenticated private operations route.
It contains operational counts and key IDs, not secret values.

### 5.1 Health, metrics, logging, graceful shutdown (v1.29)

The deployment plumbing ships as opt-in helpers (dependency-free, off
the request hot path) so the host mounts each piece where its platform
expects it:

```js
import { createArchxHealthHandler, formatPrometheusMetrics, installArchxShutdown, createJsonEventLogger } from '@archnemix/image-protection/server';

app.get('/healthz', internalOnly, createArchxHealthHandler(handler)); // 200/503, JSON, counts only
app.get('/metrics', internalOnly, (req, res) =>
  res.type('text/plain').send(formatPrometheusMetrics(handler.stats())));

const log = createJsonEventLogger((line) => process.stdout.write(line + '\n'));
// pass log.onSecurityEvent / log.onDelivery when constructing the middleware

installArchxShutdown({ server, handler }); // SIGTERM/SIGINT → drain, handler.close(), exit
```

- **Health vs readiness.** The handler answers 200 when the
  construction-time config audit passed and 503 otherwise; the body
  carries version, uptime, issue *count*, and queue gauges — never
  issue text or config values. Keep it on an internal listener; run
  `auditArchxProductionConfig()` in deployment tests for the detailed,
  still secret-free, blocker list.
- **Metrics.** `formatPrometheusMetrics` renders `handler.stats()` as
  Prometheus text (live one-time-token/proof occupancy gauges and
  derivative-cache hit/miss counters; cache sizes, queue depth, and
  in-flight gauges; an `archx_info` series with version/deployment-mode/store
  labels). Scrape it like any app metrics route; nothing per-viewer or
  secret-bearing exists in the output.
- **Logging.** Events were already structured and metadata-only;
  `createJsonEventLogger` writes one JSON line per event for your
  aggregator and, by default, drops raw IPs and viewer ids (keeping
  the keyed `viewerHash`) so log stores stay privacy-friendlier. It
  never throws into request handling.
- **Shutdown.** `installArchxShutdown` closes the HTTP server first
  (draining in-flight delivery), then `handler.close()` releases
  caches/state; a second signal or the drain timeout (default
  10 s) forces exit. Pair it with your platform's termination grace
  period (e.g. Kubernetes `terminationGracePeriodSeconds` ≥ drain
  timeout + margin).

What remains deliberately host-owned: durable log/metric storage and
retention, alerting rules, KMS/HSM secret custody, and any
certification/SLA posture (see docs/STANDARDS.md — none is claimed).

## 6. Multi-region and failover expectations

Regional independence is easy to claim and hard to make safe for one-time
claims. The default recommendation is active/passive:

1. Serve Archx token and image routes from one primary region.
2. Replicate immutable masters and configuration to the standby region.
3. Use the same key IDs and keyring in both regions; synchronize clocks with
   NTP and monitor skew.
4. Replicate state with a documented consistency/lag policy. During a
   failover where claim replication cannot be proven current, either keep
   returning `503` until it is current or accept that already-issued tokens
   expire before promotion. Do not silently start an empty memory store.
5. Health checks must test the state store and master index, not merely
   return `200` from an unrelated route.
6. Test failover with in-flight tokens, replay attempts, quotas, and an old
   signing key still inside its rollover window.

Active/active service requires one logical authority for `claimOnce` or a
partitioning scheme that guarantees mint and redemption for a token reach
the same authority. Archx tokens do not currently encode a home region, so
independent regional stores behind global anycast routing are **not** a
valid active/active design: a token could be redeemed once in each region.

Master files should be immutable, versioned objects promoted atomically.
The local output-cache key includes file version metadata; if replicated
files have different timestamps/inodes, regional L1/shared-cache efficiency
may drop, but authorization remains per-request. A changed master must not
reuse an ambiguous in-place path during a rolling deployment.

## 7. Image-heavy capacity architecture and load testing

Choose the delivery tier per image class instead of paying the strongest
per-viewer cost for every thumbnail:

| Tier | Request-path work | Use for |
| --- | --- | --- |
| Precomputed `archx-build` + manifest | Static/CDN file fetch; no mint and no Sharp per view | Large public catalogs, listings, feeds, and other upload-time-known derivatives |
| Dynamic catalog token server | Authorization/token work per view; Sharp only on a canonical derivative-cache miss | Private/revocable catalogs where most views can share image-scoped derivatives |
| Dynamic per-viewer token server | Authorization plus potentially unique watermark/forensic/Stego/scramble material per view | Paid detail views, client proofs, licensed downloads/previews, and leak tracing |

For the dynamic catalog tier, use canonical `widthBuckets`, static or
image-scoped baked marks, a persistent non-public `outputCacheDir`, and/or a
shared derivative cache. `withCatalogThroughputDefaults()` is a starting
point, not a capacity proof. Keep `processingConcurrency` (concurrent Sharp
jobs admitted by Archx) separate from `processing.sharpConcurrency`
(libvips threads per job, process-global and last-call-wins). A common
starting point is several single-threaded jobs rather than every job fanning
out across all cores; benchmark on the actual instance type. If the host has
more than four physical cores, evaluate setting `UV_THREADPOOL_SIZE` before
Node starts, because Sharp operations also use libuv work. Disk-cache
capacity/TTL and cache-hit ratio are capacity controls: alert on
`handler.stats().derivativeCache` misses, disk errors/prunes, shared-cache
errors, Sharp queue depth/timeouts, and authorization/state-store latency.
Concurrent cold requests for the same derivative are coalesced by a
singleflight promise (one Sharp job per derivative per process, even during
a viral stampede); the `coalesced` counter shows how much duplicate work
that absorbed. Coalescing is per-process, so the worst case across N
instances is N cold transforms per derivative—another reason to prefer the
shared/persistent derivative cache or `archx-build` at fleet scale.

Batch minting (`POST {basePath}/tokens`) reduces HTTP round trips for a page
of thumbnails, but it intentionally does not skip per-item authorization,
rate, quota, abuse, entitlement, callback, or signing work. Size the token
rate and quotas for items, not batch envelopes. A slow authorization database
will still dominate a 100-item page; index/cache entitlement lookups in the
host application without weakening redemption-time reauthorization.

### RAM and worst-case sizing

Budget request-path memory as approximately
`processingConcurrency × 4 bytes × maxInputPixels` for decoded RGBA working
buffers, plus the libvips operation cache (`processing.cacheMb`, default
100 MB) and Node/V8 overhead. With the unified 50 MP `maxInputPixels`
default, one in-flight maximum-size derivative can transiently hold
~200 MB of raw pixels (plus a padded copy), so a 512 MB container should
keep `processingConcurrency: 1` and lower `maxInputPixels` to match its
real masters; a 2 GB instance at concurrency 4 is comfortable for
≤ 12 MP masters. Derivative/disk-cache buffers are additional and
bounded by their own byte caps. Keep AVIF (`processing.avifEffort > 2`
warns at construction) on the offline `archx-build` path: at high effort
it is seconds-per-image CPU that no cache-hit ratio fixes on a cold tier.
Forensic detection is several seconds of single-core CPU on unmarked
images under auto/geometry search (~7 s typical photos, up to ~30 s
worst case on noise-like suspects since the 1.16 rotation/reframe/
erasure stages; roughly resolution-independent) — run it offline via
`detectStegoFingerprintInWorker()` or the `archx-detect` CLI, never in a
request handler.

### Load-test procedure

The repository includes a bounded mint+redeem load tool:

```bash
# Local synthetic regression run (single process only)
npm run load-test -- --requests=500 --concurrency=50 --width=1200

# Authorized staging deployment, JSON output. Repeat --header for a test
# account's cookie/authorization header and adjust --base-path if needed;
# keep those credentials out of shared shell history and result files.
npm run load-test -- \
  --base-url=https://staging.example.test \
  --image-id=catalog-001 \
  --requests=5000 --concurrency=100 --width=1600 \
  --confirm-load-test --json
```

Record with every result: Git commit, image dimensions/formats, derivative
width/quality, canonical bucket count, proof mode, single versus batch
minting, watermark/Stego scope/profile and registry latency, instance count
and CPU, Sharp job/thread concurrency and queue settings, authorization
database latency, state-store type/region/latency, derivative-cache state
(cold memory, cold process with warm disk/shared cache, warm memory, or
precomputed CDN), CDN behavior, and error counts. Test at least:

- warm output cache, cold-process/warm-disk derivatives, and cold/unique derivatives;
- a realistic catalog page that measures batch-mint latency separately from payload bytes;
- precomputed manifest/variant CDN hit ratio and manifest invalidation behavior, when using `archx-build`;
- many viewers versus one viewer (quota behavior differs);
- token mint and redemption routed to different instances;
- state-store latency, timeout, and failover;
- corrupt/oversized masters and queue saturation;
- key rollover during load;
- regional failover with unexpired tokens.

Set your own SLOs before the run—for example maximum p95/p99 latency, error
budget, CPU per 1,000 derivatives, and store operation latency. A local
in-process number is only a regression signal; it is not a capacity claim
for a load-balanced or multi-region service.

## 8. Incident runbooks

### State store unavailable

Expected behavior is `503`. Keep it that way. Check network/TLS/auth,
backend latency, connection limits, and failover status. Do not restart into
single-instance memory mode behind a load balancer as a workaround.

### StegoMark registry or provenance hook unavailable

The fail-closed defaults intentionally produce generic `503` responses. Do
not temporarily switch a valuable licensed catalogue to
`stegoRegistryFailure:'allow'` or `provenanceFailure:'allow'` without an
approved exception and a reconciliation queue: the delivered derivative may
be impossible to connect back to a buyer/order. Restore the sink, reconcile
any explicitly allowed deliveries from `onDelivery`, and mint fresh tokens
for affected viewers. Investigate sink timeouts against
`securityEventTimeoutMs`, database locks, and network latency.

### Suspected CDN shared-cache leak

Immediately bypass or remove the affected CDN behavior, purge only if your
provider can prove the protected paths are purged, rotate signing keys if
tokens or per-viewer derivatives may have been exposed, and inspect logs for
cross-viewer payload delivery. Re-run every verification step in section 4.

### Signing-key compromise

Remove the key from all serving keyrings, deploy a new active key, expire or
invalidate application sessions as appropriate, review issuance records and
Stego registry entries, and notify affected customers under your incident
policy. Keep the compromised key only in an offline evidence vault if needed
to investigate previously issued marks.


## 9. Design note: deep-zoom tile delivery (not shipped)

Sketch only — no v1.17 code implements this. For gigapixel-style
viewing (maps, gigapixel product zoom), the current single-derivative
delivery forces a choice between capping zoom resolution and shipping
one very large payload. A future tile mode would:

- Split each authorized derivative into a fixed tile grid (e.g.
  512×512 display pixels, aligned to the width-bucket discipline so
  tile variants stay canonical and cacheable).
- Issue one short-lived token per tile *set*; each tile is an
  ordinary `.archx` payload whose key/scope derives from
  (image, tile coordinates, zoom bucket) through the existing
  variant-scope machinery — no new token format.
- Render tiles into the same protected viewer surface; off-viewport
  tiles are never requested (bandwidth and exposure both scale with
  what is actually viewed), and eviction reuses the viewport-unload
  lifecycle so a full-resolution composite never persists in memory
  longer than needed.
- Embed steganographic marks per *derivative* (unchanged: marks are
  embedded before tiling, so a stitched screenshot still carries
  them; tile boundaries must not align to macro-cell boundaries).

Alignment note (v1.19): this mirrors the IIIF Image API 3.0 pattern
(tiles/scale factors served behind authorization handled outside the
image API itself; tiered, resolution-capped access is the established
museum/archive approach). If built, Archx tiles should stay `.archx`
payloads as sketched above rather than becoming a general IIIF
endpoint, and zoom tiers must respect `maxWidthFraction` against the
master, not against the requested tile size.

Open questions before building: tile-edge scramble seams, prefetch
policy under quotas, per-tile PoP cost, and whether zoom beyond the
master's delivered cap should ever be authorized. Recorded here so
the design starts from the threat model rather than from a map
library's defaults.

## 10. Ownership claims: keys, custody, and verification (v1.18)

Generate a dedicated signing key pair per catalog/brand:

```bash
npx archx-protect --gen-ownership-key   # prints both PEMs once
```

Store `ARCHX_OWNERSHIP_PRIVATE_KEY` like the server `secret` (secret
manager, never in the repo, never shipped to browsers). Publish
`ARCHX_OWNERSHIP_PUBLIC_KEY` wherever investigators need it (it is
safe to embed in runbooks and demand letters). Server config:

```js
ownership: { owner: 'Studio Example', privateKey: process.env.ARCHX_OWNERSHIP_PRIVATE_KEY }
```

Derivatives then carry an Ed25519-signed claim in EXIF/XMP. Custody
rules that matter more than the cryptography:

- **Log the claim at issuance.** `finishDerivative()` returns
  `ownershipToken`; store it in the same registry row as the stego
  fingerprint (see the record schema in `docs/IP_HOLDER_GUIDE.md`).
  A metadata-stripped leak can then be checked against the *known*
  claim (`--claim`) via its perceptual hash + stego fingerprint.
- **Rotation:** mint a new key pair, keep old PUBLIC keys published
  forever (old copies verify against them), retire old private keys
  offline. Never reuse one key pair across unrelated catalogs.
- **Verification workflow:**
  `ARCHX_OWNERSHIP_PUBLIC_KEY=... npx archx-detect suspect.jpg --verify-ownership --json`.
  `verified` requires signature + a content layer to agree;
  `content-match` means pixels match a claim whose signature you did
  not (or could not) verify; `claim-only` means authentic metadata
  on inconclusive pixels. Cite the layer breakdown in any report —
  never "the tool proved ownership."

Forensic worker capacity: `configureStegoDetectWorker()` bounds job
count AND total queued RGBA bytes (`maxQueuedBytes`, 512 MiB
default), per-suspect pixels (`maxPixels`, 50 MP), queue wait
(`queueTimeoutMs`), and per-job time (`timeoutMs`). If detection is
exposed to untrusted callers, those bounds plus the detector's own
`maxTimeMs` are the contract; verify them in staging before launch.
Since v1.19 the pool size is configurable (`maxWorkers`, 1–16, default
1): per-slot crash isolation means a hostile suspect can kill at most
one worker; the byte/pixel/time budgets stay shared across the pool,
so raise `maxQueuedBytes` deliberately when raising workers.

**Issuance-log custody (v1.19).** `createIssuanceLog({ secret })`
HMAC-chains issuance records so registry tampering is detectable.
Keep the log secret in the secret manager (like `secret`, but a
*different* value), persist `entries()` wherever you keep issuance
rows, verify on load, and anchor the daily `head()` externally
(email/git/timestamping service) if you need time evidence. A broken
chain means: freeze attribution decisions from that registry, restore
from backup, and re-verify — `verifyIssuanceChain` names the first
bad index.

**Pre-flight assay (v1.19).** Before enabling StegoMark on a new
catalog, run `archx-protect <sample> --assay` on representative
images (photos, flat graphics, UI/slides). It measures the real
embed PSNR at your settings, classifies content, and reports the
minimum self-verifying strength (exit 2 = none; near-binary periodic
graphics are the known weak class — prefer visible marks there).
Record the assay output with the catalog's protection settings so a
future "the watermark was invisible/destructive" dispute is settled
by a number, not an adjective.
