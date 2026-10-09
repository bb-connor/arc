# Receipt Query API

The receipt query API provides multi-filter, cursor-paginated access to the kernel's signed tool receipt log. It is available both as an HTTP endpoint served by the trust-control server and as a CLI subcommand.

The trust-control server answers receipt reads from an authenticated query
snapshot: a process-owned projection of the receipt log that is authenticated
once, extended by authenticating only what was appended, and recertified on a
schedule. Every answer names the snapshot version it came from. See
[Authenticated Query Snapshots](#authenticated-query-snapshots) for the as-of
semantics, freshness rules, typed errors and limits.

## HTTP Endpoint

```
GET /v1/receipts/query
```

All parameters are query string parameters. All filters are combined with AND semantics. The server requires a `Bearer` token in the `Authorization` header.

### Filter Parameters

All parameters are optional. Omitting a parameter disables that filter.

| Parameter | Type | Description |
|-----------|------|-------------|
| `capabilityId` | string | Exact match on capability ID |
| `toolServer` | string | Exact match on tool server name (`server_id`) |
| `toolName` | string | Exact match on tool name |
| `outcome` | string | Decision outcome: `"allow"`, `"deny"`, `"cancelled"`, or `"incomplete"` |
| `since` | u64 | Include only receipts with `timestamp >= since` (Unix seconds, inclusive) |
| `until` | u64 | Include only receipts with `timestamp <= until` (Unix seconds, inclusive) |
| `minCost` | u64 | Include only receipts with `cost_charged >= minCost` (minor units). Receipts without financial metadata are excluded when this filter is set. |
| `maxCost` | u64 | Include only receipts with `cost_charged <= maxCost` (minor units). Receipts without financial metadata are excluded when this filter is set. |
| `costCurrency` | string | Exact three-letter uppercase currency for cost filtering. Required with `minCost` or `maxCost`. |
| `agentSubject` | string | Filter by agent subject public key (hex-encoded Ed25519). Resolved from receipt attribution metadata when present and otherwise through the capability lineage table. |
| `cursor` | u64 | Pagination cursor: return only receipts with `seq > cursor` (exclusive). |
| `limit` | usize | Maximum results per page. Clamped server-side to 1 through `MAX_QUERY_LIMIT` (200). Default: 50. |

The parameter names follow `camelCase` in the HTTP query string (matching the `ReceiptQueryHttpQuery` struct's `serde(rename_all = "camelCase")` attribute).

`minCost` and `maxCost` span the full unsigned 64-bit domain and are interpreted
as minor units in `costCurrency`. Supplying a bound without `costCurrency`, a
currency other than three uppercase ASCII letters, or `minCost > maxCost`
returns `400 Bad Request`.

### Response Body

```json
{
  "snapshot": {
    "id": "01929a7c3f4e7d2a8b1c5e6f7a8b9c0d:42",
    "throughEntrySeq": 120345,
    "checkpointSeq": 1203,
    "observedAt": 1760000000123,
    "recertifiedAt": 1759996400456
  },
  "totalCount": 1024,
  "nextCursor": 47,
  "receipts": [ ...ChioReceipt objects... ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `snapshot` | object, optional | The authenticated snapshot version that answered this request. See [Snapshot Object](#snapshot-object). |
| `totalCount` | u64 | Number of receipts matching the filters in that snapshot version, independent of `limit` and `cursor`. |
| `nextCursor` | u64 or `null` | Cursor for the next page, or `null` when no page follows. |
| `receipts` | array | `ChioReceipt` objects ordered by `seq` ascending. |

`totalCount` is exact for the snapshot version named by `snapshot.id`: the
receipts and the count come from the same version. It can be used to show
"N total" in a UI without fetching all pages. It can change between pages,
because each page is answered by the version that is current when that page is
requested.

`nextCursor` is the `seq` value of the last receipt in this page. Pass it as `cursor` on the next request to get the following page. When `nextCursor` is `null` (or absent), this is the last page.

### Snapshot Object

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Opaque version identifier, for diagnostics and log correlation. It is never a request parameter and never a cursor. Do not parse it. |
| `throughEntrySeq` | u64 | Every claim-log entry at or below this sequence is included in the answer, and none above it. |
| `checkpointSeq` | u64 or `null` | Newest verified receipt checkpoint in this version. `null` before the store's first checkpoint. Entries above that checkpoint's range are authenticated by their signatures only until a later checkpoint covers them. |
| `observedAt` | u64, Unix milliseconds | Observation time of the newest receipt log head this version fully covers. This is the as-of time of the answer. |
| `recertifiedAt` | u64, Unix milliseconds | Completion time of the last full authentication of the whole history (the initial build or a recertification pass). |

A server that answers from an authenticated snapshot includes `snapshot` on
every successful response of `GET /v1/receipts/query`,
`GET /v1/agents/{subject_key}/receipts` and `GET /v1/receipts/tools`. Clients
must treat an absent `snapshot` as unknown provenance, so they keep working
against servers that predate it.

### Cursor-Based Pagination

The cursor is the `seq` column value from the last receipt in a page. Pagination is forward-only.

There is no version-pinned cursor. Each page is answered by the snapshot
version that is current when it is requested and carries its own `snapshot`.
A newer version only adds receipts, and every added receipt has a higher `seq`
than the receipts already held, so forward pagination across versions neither
repeats a receipt nor misses one that an earlier version held. One exception
affects `agentSubject` only: a receipt whose agent
subject was unresolved can later gain one from the capability lineage table.
Such a receipt can then match an `agentSubject` query below a cursor already
passed. Continued pagination does not return it, but `totalCount` counts it.

A page can hold fewer than `limit` receipts while `nextCursor` is non-null. A
page stops before the receipt that would take it above 16 MiB of stored
receipt JSON, and always carries at least one receipt. No receipt is ever
truncated. Clients must continue until `nextCursor` is `null`, and must not
treat a page shorter than `limit` as the last page.

A page that holds exactly `limit` receipts always carries a `nextCursor`, even
when no receipt follows; the next page is then empty with `nextCursor: null`.
A `cursor` above 9223372036854775807 (the largest signed 64-bit integer)
returns no receipts, while `totalCount` still reports the full filtered set.

```
# Page 1
GET /v1/receipts/query?toolServer=shell&limit=50

# Response includes nextCursor: 147

# Page 2
GET /v1/receipts/query?toolServer=shell&limit=50&cursor=147
```

When `nextCursor` is `null` or absent in the response, all matching receipts have been fetched.

### Example Request and Response

```
GET /v1/receipts/query?outcome=deny&since=1700000000&limit=2
Authorization: Bearer my-service-token
```

```json
{
  "snapshot": {
    "id": "01929a7c3f4e7d2a8b1c5e6f7a8b9c0d:42",
    "throughEntrySeq": 120345,
    "checkpointSeq": 1203,
    "observedAt": 1760000000123,
    "recertifiedAt": 1759996400456
  },
  "totalCount": 8,
  "nextCursor": 23,
  "receipts": [
    {
      "id": "receipt-001",
      "timestamp": 1700000100,
      "capability_id": "cap-abc",
      "tool_server": "filesystem",
      "tool_name": "write_file",
      "decision": { "deny": { "reason": "path outside allowed prefix", "guard": "path_allowlist" } },
      "content_hash": "...",
      "policy_hash": "...",
      "evidence": [],
      "signature": "..."
    },
    {
      "id": "receipt-002",
      "timestamp": 1700000250,
      "capability_id": "cap-abc",
      "tool_server": "shell",
      "tool_name": "exec",
      "decision": { "deny": { "reason": "budget exhausted", "guard": "monetary_budget" } },
      "metadata": {
        "attribution": {
          "subject_key": "ed25519-subject-hex",
          "issuer_key": "ed25519-issuer-hex",
          "delegation_depth": 0,
          "grant_index": 0
        },
        "financial": {
          "grant_index": 0,
          "cost_charged": 0,
          "currency": "USD",
          "budget_remaining": 0,
          "budget_total": 10000,
          "delegation_depth": 0,
          "root_budget_holder": "agent-root",
          "settlement_status": "not_applicable",
          "attempted_cost": 500
        }
      },
      "content_hash": "...",
      "policy_hash": "...",
      "evidence": [],
      "signature": "..."
    }
  ]
}
```

### Agent-Scoped Convenience Endpoint

A shorter URL is also available for per-agent receipt lookup:

```
GET /v1/agents/{subject_key}/receipts?limit=50&cursor=0
```

This is equivalent to calling `/v1/receipts/query?agentSubject={subject_key}`. It accepts only `limit` and `cursor` query parameters. Its response has the same shape, including `snapshot`.

### Tool Receipt List and Point Read

```
GET /v1/receipts/tools?toolServer=shell&decision=deny&limit=50
GET /v1/receipts/tools?receiptId=receipt-001
```

The list form accepts `capabilityId`, `toolServer`, `toolName`, `decision` and
`limit` (1 through 200, default 50) and returns one page without a cursor. The
`receiptId` form loads exactly one receipt and requires the admin service
token; a tenant read token gets `403`. Both forms return:

```json
{
  "snapshot": { "...": "same snapshot object as /v1/receipts/query" },
  "configured": true,
  "backend": "sqlite",
  "kind": "tool",
  "count": 1,
  "filters": { "receiptId": "receipt-001" },
  "receipts": [ ...ChioReceipt objects... ]
}
```

A point read that finds the receipt returns it from the current snapshot
version. A point read that finds nothing answers only after the snapshot has
reached the receipt log head read when the request started, so an empty
`receipts` array covers every receipt committed before the request. If the
snapshot cannot reach that head within 2 seconds, the request returns `503`
with code `receipt_query_snapshot_stale`.

## Authenticated Query Snapshots

The snapshot serves `GET /v1/receipts/query`,
`GET /v1/agents/{subject_key}/receipts` and `GET /v1/receipts/tools`. Child
receipts (`/v1/receipts/children`), `/v1/receipts/analytics`, the
`/v1/reports/*` endpoints and `POST /v1/evidence/export` read the receipt
store directly and carry no `snapshot` field.

### As-Of Semantics

An answer is the authenticated state of the receipt log at its snapshot
version. Within one response:

- The receipts and `totalCount` come from the same version. `totalCount` is
  exact for that version, including empty results: a filter value the version
  has never seen matches nothing, and the count is `0`.
- Every claim-log entry at or below `snapshot.throughEntrySeq` is included,
  and none above it.
- Every returned receipt is re-read from the receipt store in the request that
  returns it, its signature is verified, and its canonical leaf hash must equal
  the leaf the snapshot authenticated. A mismatch fails the request with
  `receipt_query_snapshot_invalid` and invalidates the snapshot.

Receipts a response does not return are not re-read on each request. The whole
history is authenticated when the snapshot is built and again by each
recertification pass. A pass starts every hour and re-authenticates every
claim-log entry up to the head it targets, comparing the result with the
snapshot; any difference invalidates the snapshot. A change to a stored
receipt that no response returns is therefore detected within one
recertification interval plus one pass duration, about 1 hour plus the pass
duration with the default schedule. Until then no answer reflects the change,
because answers come from the authenticated projection, but the change is not
reported either. This is as-of semantics, not immediate detection of tampering
anywhere in the database. `recertifiedAt` on each response gives the
completion time of the last full pass, and `lastRecertificationMs` on
[`/health`](#health) gives its duration.

### Freshness

The snapshot is extended in the background as receipts are appended. A read
does not silently serve an arbitrarily old version:

- **Pages** (`/v1/receipts/query`, the agent endpoint, the tool receipt list).
  The server reads the receipt log head when the request starts and waits up
  to 2 seconds for the snapshot to reach it. If the snapshot does not reach it
  in time, the page is served from the current version only when that version
  covered an observed head within the last 30 seconds. Otherwise the request
  returns `receipt_query_snapshot_stale`.
- **Point reads that find nothing** must reach the head read at request start
  within 2 seconds, with no 30-second allowance. Otherwise they return
  `receipt_query_snapshot_stale`.

Staleness depends on the append rate compared with the snapshot's extension
throughput, never on the size of the history.

### Lifecycle

| `/health` state | Read outcome |
|-----------------|--------------|
| `waiting_for_writer_seed` | `503` `receipt_query_snapshot_building`. The receipt writer has not yet seeded its verified head. |
| `building` | `503` `receipt_query_snapshot_building`. The message and `/health` report authenticated and target entry counts. |
| `ready` | Served, subject to the freshness rules. |
| `invalid` | `500` `receipt_query_snapshot_invalid`. |
| `unavailable` | `503` `receipt_query_snapshot_unavailable`. |
| `stopped` | `503` `receipt_query_snapshot_unavailable`. |

- **Restart.** The snapshot is not persisted. Every start of the service
  builds it from the receipt database, and receipt reads return
  `receipt_query_snapshot_building` until the first build completes. There is
  no startup deadline; build time grows linearly with the retained history.
  Readiness probes that need receipt reads should wait for
  `receiptQuerySnapshot.state` to be `ready` on `/health`.
- **Invalid.** A version that failed authentication is never served again. The
  service builds a new snapshot, with a new `snapshot.id`, after a backoff that
  starts at 5 minutes and doubles after each integrity failure, up to 1 hour.
  If the receipt writer fails to seed a verified head, or its head is
  poisoned, the snapshot stays invalid and is not rebuilt until an operator
  repair reseeds the writer.
- **Unavailable.** These are resource outcomes, not integrity failures. When
  the snapshot quota is exhausted, or a stored receipt exceeds the 128 MiB
  per-receipt limit, the snapshot stops serving and stays unavailable until the
  service restarts, for example with a larger
  `--receipt-query-snapshot-quota-bytes`. A snapshot step that exhausts its
  work budget or meets a busy receipt store is retried by the service after 30
  seconds.
- **Storage backends.** On Linux the snapshot database is backed by a single
  private file (mode `0600`) in a private directory (mode `0700`) that the
  service creates under `/tmp` and removes when the snapshot is released; it
  uses an in-memory rollback journal and no WAL. If `/tmp` is a `tmpfs`, that
  file occupies system memory rather than disk. On every other platform the
  snapshot database is held in process memory. In both cases the snapshot
  quota bounds the database's size; see
  [Limits and Operator Configuration](#limits-and-operator-configuration).
- **Cluster.** Each trust-control node builds its own snapshot from its own
  receipt database. `snapshot` describes the node that answered.

### Errors

Snapshot outcomes carry a stable `code`, and the body is
`{"error": string, "code": string}`. `Retry-After` is an integer number of
seconds.

| `code` | Status | `Retry-After` | Retry | Meaning |
|--------|--------|---------------|-------|---------|
| `receipt_query_snapshot_building` | `503` | `5` | yes | The snapshot is being built (startup, or a rebuild after an integrity failure). |
| `receipt_query_snapshot_stale` | `503` | `2` | yes | The snapshot did not reach the receipt log head under the freshness rules, or the version that served the read was replaced by a newer build while the read ran. |
| `receipt_query_busy` | `503` | `1` | yes | No admission permit was free. Admission never queues; see [Admission](#admission). |
| `receipt_query_snapshot_unavailable` | `503` | absent | no | A resource outcome: snapshot quota exhausted, a receipt above the per-receipt limit, a read whose payload fetch or head read exhausted its SQL work budget, an I/O failure of the snapshot's private storage, or a snapshot service that is not running. Not an integrity failure. Quota and per-receipt outcomes need operator action. |
| `receipt_query_snapshot_invalid` | `500` | absent | no | Integrity failure: a returned receipt no longer matches what the snapshot authenticated, the build or a recertification pass found a difference or a regressed receipt log, the snapshot's private storage failed its custody checks, or the receipt writer head is poisoned. |
| `receipt_query_work_budget_exhausted` | `422` | absent | no | The selection and count exceeded 10,000,000 SQLite VM steps. No rows and no count are returned. Narrow the query, for example with an equality filter or a tighter time window. |

Clients retry only `receipt_query_snapshot_building`,
`receipt_query_snapshot_stale` and `receipt_query_busy`, after the
`Retry-After` delay. They do not retry `422`, `500`, the `unavailable` code, or
a `503` without one of the three retryable codes.

Every other error keeps the `{"error": string}` body without a `code`:

| Status | Cause |
|--------|-------|
| `400` | Cost bound without `costCurrency`, a currency other than three uppercase ASCII letters, or `minCost > maxCost`. |
| `401` | Missing or invalid bearer token. Authentication runs before admission, so an unauthenticated request never takes a permit. |
| `403` | Point read by `receiptId` with a tenant read token. |
| `409` | The service was started without `--receipt-db`. |
| `500` | Any other store error, including an `outcome` value other than `allow`, `deny`, `cancelled` or `incomplete`. |

### Admission

Receipt reads are admitted in two layers. Neither layer queues: a request that
finds no free permit is refused at once with `503`
`receipt_query_busy` and `Retry-After: 1`.

1. **HTTP read lane.** The trust-control server holds 4 permits shared by
   `/v1/receipts/query`, the agent endpoint, `/v1/receipts/tools` and the
   snapshot summary on `/health`. A request takes a permit after
   authentication and before its work enters the blocking thread pool, and the
   permit moves into the blocking task. A request whose client disconnects, or
   whose HTTP future is cancelled, keeps its permit until the blocking work
   stops. This layer bounds the blocking threads receipt reads can occupy.
2. **Snapshot service read permits.** The snapshot service takes its own
   permit on every read (`max_concurrent_reads`, 4). This layer bounds every
   consumer of the snapshot, including callers that do not come through HTTP.

`POST /v1/evidence/export` has a separate lane with 1 permit. Exports never
take read permits, and reads never take the export permit. A second
concurrent export returns `503` `receipt_query_busy` with `Retry-After: 1`.
The export permit is taken before the export enters the blocking thread pool
and covers the whole export, through validation and response finalization; a
cancelled export keeps it until that work stops. Evidence export does not use
the snapshot: it authenticates the retained corpus on every call, so one
export costs work proportional to the retained history.

### Health

`GET /health` includes a `receiptQuerySnapshot` object. The HTTP status and
the top-level `ok` field do not depend on it.

```json
"receiptQuerySnapshot": {
  "configured": true,
  "state": "ready",
  "reason": null,
  "progress": null,
  "watermark": {
    "id": "01929a7c3f4e7d2a8b1c5e6f7a8b9c0d:42",
    "throughEntrySeq": 120345,
    "checkpointSeq": 1203,
    "observedAt": 1760000000123,
    "recertifiedAt": 1759996400456
  },
  "usedBytes": 52428800,
  "quotaBytes": 2147483648,
  "toolReceipts": 120000,
  "dimensions": 5321,
  "dimensionBytes": 401223,
  "lastRecertificationMs": 84211
}
```

| Field | Description |
|-------|-------------|
| `configured` | Whether the service has a receipt database. |
| `state` | `waiting_for_writer_seed`, `building`, `ready`, `invalid`, `unavailable` or `stopped`, as in [Lifecycle](#lifecycle). Three states carry only `configured` and `state`: `unconfigured` (no receipt database), `busy` (every HTTP read lane permit is taken) and `unavailable` when the snapshot service is not running. |
| `reason` | Why the snapshot is `invalid` or `unavailable`, otherwise `null`. |
| `progress` | While `building`: `{"authenticatedEntries": u64, "targetEntries": u64}`. Otherwise `null`. |
| `watermark` | The current snapshot object while `ready`, otherwise `null`. |
| `usedBytes` | Bytes of snapshot storage in use while `ready`, otherwise `0`. |
| `quotaBytes` | The quota actually enforced while `ready`, otherwise the configured quota, in bytes. |
| `toolReceipts` | Tool receipts held while `ready`, otherwise `0`. |
| `dimensions`, `dimensionBytes` | Distinct filter values held, and their total bytes, while `ready`, otherwise `0`. |
| `lastRecertificationMs` | Duration in milliseconds of the last completed full pass (the build or a recertification), or `null` before the first. |

### Limits and Operator Configuration

The snapshot quota is the one operator setting:

| Setting | Value |
|---------|-------|
| Flag | `chio trust serve --receipt-query-snapshot-quota-bytes <BYTES>` |
| Config field | `TrustServiceConfig.receipt_query_snapshot_quota_bytes: u64` |
| Environment variable | None. The quota is set only by the flag or the config field. |
| Default | `2147483648` (2 GiB) |
| Unit | Bytes, as a plain unsigned decimal integer. Unit suffixes such as `2GiB` are rejected. |
| Bounds | At least `1048576` (1 MiB), at most `18446744073709551615`. A smaller value is refused when the arguments are parsed and again when the service configuration is validated, so the service does not start. |

The quota is enforced as a SQLite page limit on the snapshot database: it is
rounded down to a whole number of database pages and capped at SQLite's own
maximum page count. `quotaBytes` on `/health` reports the enforced value while
the snapshot is `ready`. Exhausting it makes the snapshot `unavailable`; no
truncated or partial version is ever published.

The quota bounds the snapshot database's pages and nothing else. On Linux
that is the size of the private backing file; on other platforms it is the
database's share of process memory. It is not a limit on total process memory
(RSS). Outside the quota are:

- an in-process index of the distinct filter values the snapshot holds
  (reported as `dimensions` and `dimensionBytes` on `/health`);
- SQLite's page cache and statement memory;
- the snapshot builder's per-step copy buffer, up to 16 MiB, or one receipt of
  up to 128 MiB when a single receipt is larger;
- the receipts each admitted read assembles, up to 16 MiB of stored receipt
  JSON per page;
- everything else in the trust-control process.

Every other limit is fixed in this release:

| Limit | Value | When reached |
|-------|-------|--------------|
| HTTP read lane | 4 permits, non-queued | `503` `receipt_query_busy` |
| Snapshot service reads (`max_concurrent_reads`) | 4 permits, non-queued | `503` `receipt_query_busy` |
| Evidence export lane | 1 permit, non-queued | `503` `receipt_query_busy` |
| Selection and count work | 10,000,000 SQLite VM steps per request | `422` `receipt_query_work_budget_exhausted` |
| Payload fetch work | 1,000,000 SQLite VM steps per fetch, and per head read | `503` `receipt_query_snapshot_unavailable` |
| Page size | `limit` receipts (1 through 200) and at most 16 MiB of stored receipt JSON, always at least one receipt | Short page with a non-null `nextCursor` |
| Receipt size | 128 MiB per stored receipt | While building, extending or recertifying: `unavailable`. On a read: `invalid`, because the receipt the snapshot authenticated was within the limit. |
| Head wait | 2 seconds | Falls through to the 30-second staleness allowance (pages) or `stale` (point reads that find nothing) |
| Staleness allowance | 30 seconds | `503` `receipt_query_snapshot_stale` |
| Extension interval | 250 milliseconds between extension cycles when no read is waiting | None |
| Recertification interval | 1 hour between the starts of full passes | None |
| Rebuild backoff after an integrity failure | 5 minutes, doubling up to 1 hour | None |

## Receipt Analytics Endpoint

The trust-control service also exposes aggregate analytics over the same receipt corpus:

```
GET /v1/receipts/analytics
```

It uses the same authentication model as `/v1/receipts/query` and accepts these optional query parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `capabilityId` | string | Restrict analytics to one capability ID |
| `agentSubject` | string | Restrict analytics to one agent subject key |
| `toolServer` | string | Restrict analytics to one tool server |
| `toolName` | string | Restrict analytics to one tool |
| `since` | u64 | Include only receipts with `timestamp >= since` |
| `until` | u64 | Include only receipts with `timestamp <= until` |
| `groupLimit` | usize | Maximum rows returned for each grouped dimension. Default: 50, capped server-side at 200. |
| `timeBucket` | string | Time aggregation width: `hour` or `day`. Default: `day`. |

Response shape:

```json
{
  "summary": {
    "totalReceipts": 12,
    "allowCount": 9,
    "denyCount": 1,
    "cancelledCount": 1,
    "incompleteCount": 1,
    "totalCostCharged": 750,
    "totalAttemptedCost": 500,
    "reliabilityScore": 0.8181818182,
    "complianceRate": 0.9166666667,
    "budgetUtilizationRate": 0.6
  },
  "byAgent": [
    {
      "subjectKey": "ed25519-subject-hex",
      "metrics": { "...": "same metric object as summary" }
    }
  ],
  "byTool": [
    {
      "toolServer": "shell",
      "toolName": "bash",
      "metrics": { "...": "same metric object as summary" }
    }
  ],
  "byTime": [
    {
      "bucketStart": 1700000000,
      "bucketEnd": 1700086400,
      "metrics": { "...": "same metric object as summary" }
    }
  ]
}
```

The analytics API is backend-side aggregation. It complements, but is distinct from, any client-side dashboard summaries.

## Local Receipt Operations CLI

Receipt write operations are local SQLite operator commands in this release.
They require `--receipt-db <path>`. Remote `--control-url` receipt
health, flush, and checkpoint operations fail with:

```text
requires local --receipt-db; remote receipt write operations are not supported in this release
```

The JSON response is always an envelope:

```json
{
  "schema": "chio.cli.receipt.health.v1",
  "report": {}
}
```

Supported envelope schemas:

| Command | Schema |
|---------|--------|
| `chio receipt health` | `chio.cli.receipt.health.v1` |
| `chio receipt flush` | `chio.cli.receipt.flush.v1` |
| `chio receipt checkpoint status` | `chio.cli.receipt.checkpoint_status.v1` |
| `chio receipt checkpoint create` | `chio.cli.receipt.checkpoint_create.v1` |
| `chio receipt checkpoint verify` | `chio.cli.receipt.checkpoint_verify.v1` |

`chio receipt flush --timeout-ms <n>` treats the timeout as the receipt writer
flush-barrier timeout. It is not a whole-command timeout. A timeout means the
operator cannot prove all writes accepted before the barrier are committed.

`chio receipt checkpoint create --kernel-seed-file <path> --max-batch <n>`
creates the next checkpoint through the receipt store. SQLite chooses the next
contiguous `claim_receipt_log_entries.entry_seq` range, loads canonical bytes,
loads the predecessor checkpoint, builds and signs the checkpoint, inserts it,
and validates the checkpoint projections in one `IMMEDIATE` transaction.

`chio receipt checkpoint status` and `chio receipt checkpoint verify` return a
non-zero exit status when checkpoint chain or projection integrity fails.

## Operator Report Endpoint

The trust-control service also exposes a composed operator report:

```
GET /v1/reports/operator
```

It uses the same Bearer authentication model as the other receipt endpoints and accepts the same corpus filters as the analytics API, plus:

| Parameter | Type | Description |
|-----------|------|-------------|
| `attributionLimit` | usize | Maximum detailed rows returned in the nested cost-attribution slice. Default: 100. |
| `budgetLimit` | usize | Maximum budget-utilization rows returned. Default: 50, capped server-side at 200. |

Response shape:

```json
{
  "generatedAt": 1700000000,
  "filters": {
    "agentSubject": "ed25519-subject-hex",
    "toolServer": "shell",
    "toolName": "bash"
  },
  "activity": { "...": "same shape as /v1/receipts/analytics" },
  "costAttribution": { "...": "same shape as /v1/reports/cost-attribution" },
  "budgetUtilization": {
    "summary": {
      "matchingGrants": 3,
      "nearLimitCount": 1,
      "exhaustedCount": 0
    },
    "rows": [
      {
        "capabilityId": "cap-123",
        "grantIndex": 0,
        "subjectKey": "ed25519-subject-hex",
        "toolServer": "shell",
        "toolName": "bash",
        "invocationCount": 12,
        "maxInvocations": 20,
        "totalCostCharged": 850,
        "maxTotalCostUnits": 1000,
        "remainingCostUnits": 150,
        "nearLimit": true,
        "exhausted": false,
        "scopeResolved": true
      }
    ]
  },
  "compliance": {
    "matchingReceipts": 12,
    "evidenceReadyReceipts": 11,
    "uncheckpointedReceipts": 1,
    "checkpointCoverageRate": 0.9166666667,
    "lineageCoveredReceipts": 12,
    "lineageGapReceipts": 0,
    "directEvidenceExportSupported": false,
    "childReceiptScope": "omitted_no_join_path",
    "proofsComplete": false,
    "exportQuery": {
      "agentSubject": "ed25519-subject-hex"
    },
    "exportScopeNote": "tool filters narrow the operator report only; direct evidence export can scope by capability, agent, and time window."
  }
}
```

This endpoint is the stable operator workflow surface. It packages the existing analytics, cost-attribution, and evidence-export substrate into one response so dashboards and back-office tooling do not need to reconstruct the report client-side.

## Comptroller Surface Endpoint

The trust-control service exposes the unified spend and exposure surface for cross-language consumers:

```
GET /v1/reports/comptroller-surface
```

It uses the same Bearer authentication model as the other report endpoints.

The response envelope schema identifier is `chio.comptroller.surface-report.v1`. Every response carries this identifier in the top-level `schema` field so consumers can reject unknown schema versions fail-closed before parsing the body.

### Response Shape

```json
{
  "schema": "chio.comptroller.surface-report.v1",
  "generatedAt": 1700000000,
  "filters": {},
  "exposurePositions": [
    {
      "currency": "USD",
      "governedMaxExposureUnits": 10000,
      "reservedUnits": 1000,
      "settledUnits": 8500,
      "pendingUnits": 200,
      "failedUnits": 0,
      "provisionalLossUnits": 0,
      "recoveredUnits": 0,
      "quotedPremiumUnits": 0,
      "activeQuotedPremiumUnits": 0
    }
  ],
  "decisionSummary": {
    "allowCount": 38,
    "denyCount": 4,
    "cancelledCount": 0,
    "incompleteCount": 0
  },
  "settlementReconciliation": {
    "matchingReceipts": 42,
    "returnedReceipts": 0,
    "pendingReceipts": 1,
    "failedReceipts": 0,
    "actionableReceipts": 1,
    "reconciledReceipts": 37,
    "truncated": false
  },
  "budgetUtilization": {
    "matchingGrants": 5,
    "returnedGrants": 0,
    "distinctCapabilities": 2,
    "distinctSubjects": 1,
    "totalInvocations": 42,
    "totalCostCharged": 8500,
    "nearLimitCount": 1,
    "exhaustedCount": 0,
    "rowsMissingScope": 0,
    "rowsMissingLineage": 0,
    "truncated": false
  },
  "sourceRefs": {}
}
```

Note: `executionNonceRef` and `holdRef` are omitted from the JSON response when absent or null. They appear only when a specific governed invocation or pre-authorization hold context is supplied.

### Field Reference

| Field | Type | Description |
|-------|------|-------------|
| `schema` | string | Always `chio.comptroller.surface-report.v1`. Consumers must reject unknown values fail-closed. |
| `generatedAt` | integer (Unix seconds) | Epoch timestamp when this report was produced. |
| `filters` | object | The corpus filters applied to this snapshot (mirrors the request parameters). |
| `exposurePositions` | array | Per-currency credit-exposure rows (`ExposurePosition`). Fields: `currency`, `governedMaxExposureUnits`, `reservedUnits`, `settledUnits`, `pendingUnits`, `failedUnits`, `provisionalLossUnits`, `recoveredUnits`, `quotedPremiumUnits`, `activeQuotedPremiumUnits`. Positions are never netted across currencies. |
| `decisionSummary` | object | Aggregate allow/deny/cancelled/incomplete decision counts: `allowCount`, `denyCount`, `cancelledCount`, `incompleteCount`. |
| `settlementReconciliation` | object | Settlement backlog summary: `matchingReceipts`, `returnedReceipts`, `pendingReceipts`, `failedReceipts`, `actionableReceipts`, `reconciledReceipts`, `truncated`. |
| `budgetUtilization` | object | Active grant utilization summary: `matchingGrants`, `returnedGrants`, `distinctCapabilities`, `distinctSubjects`, `totalInvocations`, `totalCostCharged`, `nearLimitCount`, `exhaustedCount`, `rowsMissingScope`, `rowsMissingLineage`, `truncated`. |
| `sourceRefs` | object | Optional provenance anchors. All sub-fields are optional strings: `operatorReportRef`, `exposureLedgerRef`, `riskComptrollerReportRef`. The object is present but may be empty `{}`. |
| `executionNonceRef` | string (optional) | Reserved. Identifies the execution nonce when this surface is attached to a specific governed invocation. Omitted when not applicable. |
| `holdRef` | string (optional) | Reserved. Identifies an open pre-authorization hold when the surface is polled mid-execution. Omitted when not applicable. |

The projection implies no fund movement. The surface report is a read-only snapshot of canonical receipt, settlement, and budget truth as of `generatedAt`.

### Schema Governance

The canonical JSON Schema for `chio.comptroller.surface-report.v1` is
`spec/schemas/chio-comptroller/v1/surface-report.schema.json` in this repository.
The TypeScript binding at `src/generated/comptroller-surface.ts` is generated
from that schema and must not be hand-edited. Any shape change requires a schema
version bump. Out-of-repo consumers must pin to the published schema SHA tracked
in `spec/schemas/chio-comptroller/v1/`.

## CLI Usage: chio receipt list

The `chio receipt list` subcommand wraps the HTTP endpoint.

```
chio receipt list [OPTIONS]

Options:
  --capability <ID>      Filter by capability ID
  --tool-server <NAME>   Filter by tool server name
  --tool-name <NAME>     Filter by tool name
  --outcome <OUTCOME>    Filter by outcome (allow/deny/cancelled/incomplete)
  --since <UNIX_SECS>    Filter by minimum timestamp (inclusive)
  --until <UNIX_SECS>    Filter by maximum timestamp (inclusive)
  --min-cost <UNITS>     Minimum cost in minor currency units
  --max-cost <UNITS>     Maximum cost in minor currency units
  --cost-currency <CODE> Three-letter uppercase currency for cost filters
  --limit <N>            Page size (default: 50)
  --cursor <SEQ>         Pagination cursor (seq value)
  --tenant <ID>          Strict tenant read boundary (local mode);
                         required for local --receipt-db reads unless
                         --admin-all is set.
  --admin-all            Explicit local-operator read across all tenants
                         (local mode); required unless --tenant is set.
  --control-url <URL>    Trust-control server URL
  --control-token <TOK>  Bearer token for the trust-control server
  --receipt-db <PATH>    Path to receipt SQLite file (local mode)
```

Local `--receipt-db` reads require an explicit read boundary. The CLI does
not silently default to admin-all reads across all tenants. Pass either
`--tenant <id>` to scope output to a single tenant or `--admin-all` to
read across tenants as a documented operator action. Remote
`--control-url` reads derive the read boundary from the control token.
`--min-cost` and `--max-cost` require `--cost-currency`.

Local `--receipt-db` reads open the receipt database directly and authenticate
the retained corpus on every call; they use no snapshot. Remote
`--control-url` reads are answered from the trust-control server's
authenticated snapshot, so the as-of semantics, freshness rules and typed
errors above apply.

Each matching receipt is printed as a JSON object on its own line (NDJSON). Example:

```bash
# Local mode, scoped to one tenant.
chio --receipt-db ./receipts.sqlite receipt list \
  --tenant my-tenant \
  --outcome deny \
  --since 1700000000

# Remote control plane.
chio receipt list \
  --outcome deny \
  --since 1700000000 \
  --control-url http://localhost:7391 \
  --control-token my-token
```

To paginate programmatically, capture `nextCursor` from the HTTP response and pass it as `--cursor` on the next invocation.

Financial `budget_total` and `budget_remaining` are both `null` for uncapped
grants. Capped values describe the cumulative grant balance, including on denial
and reconciliation receipts. Consumers must preserve this distinction.
