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
- token/image rate-limit windows;
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
// Gate the release on audit.ok and production.ready.
// Neither audit summary contains a secret value.
```

`auditArchxServerConfig()` answers whether the middleware accepts the
configuration. `auditArchxProductionConfig()` additionally reports
blockers for anonymous catalogues without recalibrated controls, query
tokens, missing/optional proof of possession, reusable delivery tokens,
long token TTLs, unregistered StegoMark issuance, and process-local state
behind more than one instance. Keep its secret-free summary with release
evidence. For a new production configuration, start from
`withHardenedProductionDefaults(options)` and make any relaxation explicit,
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
- `getCache`/`setCache`: binary `GET` and `SET ... PX ttlMs`. Consider a
  separate cache cluster/database so large derivative values cannot evict
  short-lived replay claims. Scrambled/encrypted derivatives are still
  access-controlled data; encrypt transport and restrict network access.

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

1. Generate at least 32 random bytes in your secret manager/KMS. Never put
   secrets in source control, images, logs, or client configuration.
2. Deploy every instance with both old and new keys, initially leaving the
   active ID on the old key. Confirm `handler.configAudit.summary` reports
   the expected active ID and key count (the audit exposes IDs/counts only,
   never values).
3. Change `activeSecretId` to the new key on every instance. A mixed fleet
   is safe during this step because all instances can verify both IDs.
4. Wait at least the configured `ttlSec` plus clock-skew/retry allowance. A
   conservative minimum is `ttlSec + 300` seconds. Static investigations may
   need an old StegoMark detector secret for much longer; retain it offline
   in the evidence vault even after removing it from serving nodes.
5. Remove the old key from every serving keyring and redeploy/restart.
6. Record the rotation time, key IDs, operator, approval/change ticket, and
   the time the old key was retired.

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
should bypass shared caching entirely.

### CloudFront reference behavior

Create behaviors for `/archx/token/*`, the exact batch route `/archx/tokens`, and `/archx/i/*` (adjust `basePath`):

- Viewer protocol: redirect HTTP to HTTPS or HTTPS only.
- Allowed methods: token behavior must allow the configured token methods
  and `OPTIONS`; image behavior allows `GET` and `OPTIONS`.
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

Create a Cache Rule for the token and payload paths:

- Expression based on URI path, for example:
  `(starts_with(http.request.uri.path, "/archx/token/")) or (http.request.uri.path eq "/archx/tokens") or (starts_with(http.request.uri.path, "/archx/i/"))`
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
| `outcome` | `denied`, `detected`, or `error` |
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
`traceId` from `authorize()`. Archx turns those values into a signed trace
hash, uses them for `{buyer}`/`{order}`/`{delivery}`/`{trace}` visible-mark
text and trace-derived StegoMark subjects, and rechecks them at redemption.
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
