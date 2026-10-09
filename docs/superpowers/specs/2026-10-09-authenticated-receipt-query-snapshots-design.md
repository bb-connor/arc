# Authenticated receipt query snapshots

Status: design for Root review (finding V25, PR #1160). No storage or API code
lands before acceptance.
Base: a457a89c75.
Prerequisite: V25-PRE, one persistent trust-control receipt store with writer
readiness awaited at startup (authorized 2026-10-09T05:16:44Z, claimed as
`fix/pr1160-claude-v25`).
Decision: Connor chose authenticated immutable query snapshots before #1160
lands (2026-10-09T05:22:20Z through Claude's question tool; confirmed in Root's
conversation, Codex 05:31:57Z). The alternative, strict synchronous budgets that
permanently refuse healthy stores of roughly 60-80k receipts, was rejected.
Inputs: Codex mailbox entries 04:44:55Z, 05:01:59Z, 05:11:06Z, 05:16:44Z,
05:21:30Z, 05:23:00Z and 05:27:43Z. Evidence: `claude-pr1160-evidence/vfix/v25/`.
Plan: [implementation plan](../plans/2026-10-09-authenticated-receipt-query-snapshots.md).

## 1. Problem

At a457 every receipt query page authenticates the whole retained corpus before
it reads one row:

- `SqliteReceiptStore::query_receipts` calls `with_retained_snapshot`
  (`chio-store-sqlite/src/receipt_query.rs:24`).
- `with_retained_connection_snapshot` (`receipt_store/retained_read.rs:52-77`)
  opens the archive and authenticates its whole prefix
  (`support/store_impl.rs:51-72`, `support/checkpoint_validate.rs:576-614`),
  re-verifies the whole checkpoint chain with a Merkle rebuild over every live
  claim above the watermark W (`checkpoint_validate.rs:661-734`, `:682-683`), and
  then streams every archived claim again in `retained_projection::validate`
  (`retained_projection.rs:38-171`).
- The control plane calls this from `GET /v1/receipts`, `GET /v1/receipts/query`
  and `GET /v1/agents/{subject}/receipts` for any principal, tenant-scoped ones
  included (`trust_control/receipt_handlers.rs:86`, `:293`, `:968`), and it opens
  a fresh store per request (`policy_support.rs:955-965`), so the writer seed
  (`receipt_store.rs:1288-1293`, `:2574-2586`) adds another O(N) per request.

Measured at a457 (`vfix/v25/f1f2-evidence.txt`): one 10-row tenant page over 200
archived plus 200 live receipts costs 1,220 signature verifications, linear in
the corpus. A 1M live plus 5M archived store costs about 11M verifications per
page. There is no row, byte, step or concurrency bound.

## 2. Acceptance points

| Id | Requirement (source) | Met in |
|---|---|---|
| A1 | No undetected interior tamper or count drift in answers; no silent weakening of what reads accept today (04:44, 05:01) | 5.3, 5.5, 8 |
| A2 | No permanent denial for healthy large stores; history growth alone never disables reads (05:01, 05:27) | 7.2, 10 |
| A3 | Own the authenticated bytes and projection; a pinned transaction is not authentication; account for raw in-place edits (05:16) | 4.2, 6.4 |
| A4 | Adversary boundary; disk changes during construction and after publication (05:23) | 3, 5.5 |
| A5 | Rows and total_count bind to one version, including empty results, every filter, and uncheckpointed live rows (05:23) | 4.4, 6.2, 6.3 |
| A6 | No authority for signed-but-unlogged source rows (05:23) | 5.1, 8 |
| A7 | Writer seed is asynchronous and read checkout ignores a poisoned head (05:11) | 7.3, 9 |
| A8 | Archive projections validated at build; startup does not do it today (05:11) | 5.1 |
| A9 | Unbounded checkpoint batch size and linear counts: real CPU, row, byte and concurrency bounds (05:11, 05:27) | 5.4, 6.6 |
| A10 | A covering checkpoint needs proven trusted-chain membership (05:11) | 5.1, 5.2 |
| A11 | Bounded build memory and concurrency, coalesced rebuilds, cancellation, bounded WAL retention and rotation interference, progress under continuing appends (05:23) | 5.4, 9 |
| A12 | Freshness bound never recreates permanent refusal; explicit building, stale and invalid states; never revive a superseded or poisoned snapshot (05:23) | 7 |
| A13 | Real per-request bound on COUNT and filters through indexes or maintained cardinalities; an expensive unsupported filter gets a typed refusal, never a partial count; sparse tenants work (05:23, 05:27) | 6.2, 6.3, 6.6 |
| A14 | Freshness is an API change across kernel, control plane, SDK and spec; smallest defensible change; old and new SDK behavior documented (05:11, 05:23) | 11 |
| A15 | Tested supported capacity and storage and memory policy; no infinite history in bounded RAM (05:27) | 10 |
| A16 | Existing primitives and dependencies, narrow APIs, complete results for every accepted query (05:27) | 4, 6, 11 |
| A17 | No hard seed timeout cutoff; initializing distinct from failed; one owner; stated shutdown semantics (05:21) | 9 |

## 3. Adversary and trust boundary

The adversary can:

- run arbitrary SQL against the receipt database and its archive, including with
  triggers disabled per connection, and commit at any time;
- edit the database, WAL, shared-memory and archive files in place by path,
  including byte edits that preserve SQLite's change counter;
- replace or swap those files by path.

The adversary cannot forge Ed25519 signatures under the kernel receipt key or the
checkpoint key, and cannot read or write the trust-control process's memory or
its open file descriptors (equivalently, cannot ptrace it). This is the same
boundary a457 already assumes for its in-memory verification state. An attacker
with ptrace access owns the process and is out of scope for any read path.

The snapshot service is inside the boundary. The receipt database, archive and
everything SQLite reads from them are outside it. Unsigned inputs that a457
already trusts stay explicitly listed in section 8.

## 4. The snapshot

### 4.1 What it is

A query snapshot is a process-owned, authenticated projection of every tool
receipt in the claim log through one claim-log entry E (the watermark). It is
the only source of filter, count and page-selection answers. It holds no
authority of its own: every row in it was derived from a receipt whose signature
was verified, whose claim entry is in the contiguous claim log, and, once a
checkpoint covers it, whose leaf is bound to a signed checkpoint that is a
proven member of the checkpoint chain.

### 4.2 Storage and integrity binding

The snapshot lives in a private SQLite temporary database: a connection opened
with an empty filename, owned by the snapshot service. Properties, all existing
SQLite behavior under the bundled build (`rusqlite 0.39`, `libsqlite3-sys
0.37.0`, which sets no `SQLITE_TEMP_STORE` on Linux):

- pages live in the connection's page cache (`cache_size` bounded, 64 MiB
  default) and spill to a temporary file;
- the unix VFS unlinks that file immediately after creating it, so it has no
  path; only this connection's descriptor reaches it;
- it is never shared with another connection or process and disappears when the
  connection closes.

The integrity binding is therefore the trust boundary itself: nothing outside the
process can change snapshot pages. Bytes the snapshot does not hold (receipt
JSON) are bound by a per-row RFC 6962 leaf hash (`chio_core::merkle::leaf_hash`
over the canonical receipt bytes, `chio-core-types/src/merkle.rs:4-5`), which is
exactly what checkpoints commit to. A page re-reads the receipt from the mutable
database and accepts it only if its signature verifies and its leaf equals the
owned leaf (6.4). Owned storage plus leaf binding means the snapshot never trusts
a mutable SQLite handle for any answer.

A pinned read transaction on the receipt database is not used for serving. It
would not authenticate raw in-place edits (Codex 05:16).

Temporary-file placement follows SQLite's rule (`SQLITE_TMPDIR`, `TMPDIR`,
`/var/tmp`, `/usr/tmp`, `/tmp`). Deployments set `SQLITE_TMPDIR` to a private
volume (systemd `PrivateTmp=` or a dedicated directory). The service checks free
space there before it builds (10).

### 4.3 Schema

All string dimensions are interned to integers. Interning is per snapshot.

- `snapshot_dim(id, kind, value)`, unique on `(kind, value)`. Kinds: tenant,
  capability, tool_server, tool_name, tool (server and name pair), subject,
  currency. Id 0 means "absent" (no tenant, no subject, no cost).
- `snapshot_tool_receipt`: `seq` (source seq, the API cursor, primary key),
  `entry_seq` (unique), `leaf_hash` (32 bytes), `receipt_id` (unique), `ts`,
  `tenant`, `capability`, `tool_server`, `tool_name`, `tool`, `decision`
  (allow, deny, cancelled, incomplete), `subject`, `subject_signed`,
  `cost_currency`, `cost_charged` (8-byte big-endian, as `cost_charged_be` today).
- Secondary indexes, each ending in `seq` so pages walk in cursor order:
  `(tenant, seq)`; `(tenant, D, seq)` and `(D, seq)` for each equality dimension
  D in {capability, tool_server, tool_name, tool, decision, subject};
  `(tenant, ts, seq)` and `(ts, seq)`; `(tenant, cost_currency, cost_charged)`
  and `(cost_currency, cost_charged)`.
- `snapshot_count(scope, dim, value, n, min_seq, max_seq)`, primary key
  `(scope, dim, value)`. Scope is a tenant id or the all-tenants marker. Rows
  exist for the scope total, for every equality dimension value, and for every
  hour bucket (`ts / 3600`). These are the maintained cardinalities.
- `snapshot_checkpoint(seq, batch_start, batch_end, tree_size, merkle_root,
  kernel_key)`: the verified chain, owned.
- `snapshot_pending_leaf(entry_seq, kind, leaf_hash)`: leaves of entries above
  the newest verified checkpoint (the uncheckpointed tail), both kinds.
- `snapshot_child_cursor(source_seq, entry_seq)`: child receipt cursors, with
  `source_seq` as the primary key. They are kept only to enforce the cursor
  uniqueness rule that `retained_projection.rs:16-24` enforces today, and for
  the final-phase source-row bijection.

Outside SQLite, the service holds the newest verified `KernelCheckpoint`, its
`CheckpointChainFrontier` (`chio-kernel/src/checkpoint.rs:412-480`), E, the
lineage rowid high-water mark, and the state machine (7).

### 4.4 What a snapshot version is

A version is identified by `snapshotId = <lineage>:<generation>`. The lineage is
a random 128-bit value drawn when a build starts; the generation increases by one
on every committed change. A version's content is fixed. Version g+1 differs from
g only by:

- rows for entries in (E_g, E_g+1], which always carry higher `seq` than every
  existing row (AUTOINCREMENT, `bootstrap/open.rs:621-623`), so a cursor obtained
  at g stays valid at g+1;
- newly verified checkpoints;
- lineage refreshes that fill a previously absent unsigned subject (5.2).

A query evaluates selection and total_count on one version inside one snapshot
transaction, and the response names that version (11). Empty results are
complete: an unknown filter value has no `snapshot_dim` id, and dimensions are
inserted in the same transaction as the rows that use them.

## 5. Construction: one authentication walker

One walker authenticates receipts from the mutable database. It has three modes:
build (insert), extension (append), and recertification (compare). All three
reuse the existing verification primitives:

- `parse_persisted_checkpoint_row` (`checkpoint_validate.rs:290-296`);
- `validate_checkpoint_base` and `validate_checkpoint_predecessor`, and the
  `chain_root` frontier check (`checkpoint_validate.rs:661-734`);
- `validate_checkpoint_projection_rows` (`checkpoint_validate.rs:1472`);
- `ArchiveCheckpointReader` (`support/checkpoint_read.rs:4-72`);
- `decode_verified_chio_receipt` and `decode_verified_child_receipt`
  (`support/receipt_verify.rs:123-163`), the signer binding of
  `load_checkpoint_claim_tree_canonical_bytes_range`
  (`support/checkpoint_projection.rs:707-748`), and the projection rule of
  `retained_projection.rs:84-133`, factored into one shared function so live and
  archived rows obey one rule.

The full-chain loop at `checkpoint_validate.rs:661-734` is refactored into a
per-checkpoint step plus a driver. The existing per-call path keeps calling the
driver, with unchanged behavior.

### 5.1 Build

A build runs at startup, and after an Invalid state (7.3). It targets E_target,
the claim-log head when the build starts, and proceeds in bounded steps (5.4):

1. **Chain phase.** Read `kernel_checkpoints` in pages of at most 1,024 rows, in
   `checkpoint_seq` order. For each row: verify the signature and columns; verify
   the base or predecessor link against the previous verified checkpoint held in
   memory; check `chain_root` against the running `CheckpointChainFrontier`;
   validate its projection rows; and for checkpoints at or below the live
   watermark W, require the archived row to equal the live row. Append the row to
   `snapshot_checkpoint`. Projection id-set completeness is checked in step 4 by
   count and maximum, not with in-memory sets, so memory stays O(1) in the number
   of checkpoints.
2. **Tail phase.** Read the claim entries above the newest verified checkpoint's
   `batch_end` through E_target. Require contiguous `entry_seq`. Signature-verify
   each entry and store its leaf in `snapshot_pending_leaf`. For tool entries,
   derive the projection from the signed receipt and insert the snapshot row.
   Each entry's source row is checked as in step 3.
3. **Batch phase, newest checkpoint first.** For each verified checkpoint, read
   its claim range in steps from wherever it physically lives: the live claim
   log if it is above the W read in that step's transaction, else the archive.
   For each entry:
   - enforce the per-row byte cap;
   - verify the signature;
   - require the signer to equal the checkpoint key;
   - append its leaf to a streaming RFC 6962 frontier (O(log B) memory,
     whatever the batch size B);
   - for tool entries, derive the projection and insert the row; for child
     entries, insert the cursor;
   - check the source row, using exactly the rule `retained_projection.rs`
     applies to archived rows today. The source row exists once, its `raw_json`
     equals the claim's, and its columns equal the signed projection. An
     archived source seq must not exist live and must not exceed the live
     `sqlite_sequence` ceiling. Live entries get the same check. That is new on
     the read path; today only the writer seed compares live claims with their
     source rows.

   At the end of the batch, the frontier root must equal the signed
   `merkle_root` and the entry count must equal `tree_size`. Batches are
   processed newest first, so recent receipts become available to point reads
   early (6.5).
4. **Final phase.** This runs inside the last catch-up step's transaction, so
   the live head, W and the counts are one consistent read:
   - live tool and child source-row counts equal the snapshot tool rows and
     child cursors located live (entry_seq above W). Together with per-entry
     existence this is a bijection,
     so a live source row with no claim entry fails the build (A6);
   - each checkpoint projection table (tree heads, predecessor witnesses,
     publication metadata) holds exactly the expected id set. The chain phase
     checked each expected row exists, so a count and maximum comparison here
     completes set equality, as `validate_checkpoint_projection_id_sets`
     (`checkpoint_validate.rs:1541`) does with in-memory sets;
   - every archived source seq is unique, enforced by the snapshot primary keys.

   Maintained counts are computed with one `GROUP BY` pass over the snapshot,
   the state becomes Ready, and the version is published.

After E_target the walker switches to extension until it reaches the live head,
and then publishes. A build never restarts because new receipts arrive.

Each checkpoint is accepted only as a member of the chain walked from seq 1,
and every claim range is accepted only against such a checkpoint, so covering
batch membership is proven (A10). Archived claims and archived projections are
authenticated at build (A8).

### 5.2 Extension

The service extends a Ready snapshot when the writer commits (a notification
from the store's commit path, coalesced) and on a 250 ms tick, which catches
other processes writing the same database. One extension step:

1. Reads the claim entries in (E, min(H, E + K)], where H is the live head.
   Each entry is signature-verified, its leaf is pending, and tool rows are
   inserted.
2. Accepts each new checkpoint with `batch_end` at most the new E, in sequence.
   Its seq must be the owned head's seq plus one; its predecessor link and
   `chain_root` are checked against the owned head and frontier; its Merkle root
   is recomputed from the owned pending leaves, which are then deleted. The
   mutable database is not re-read for this. If an uncheckpointed entry was
   swapped on disk after the snapshot ingested it, the writer's checkpoint
   commits the swapped bytes and the owned root differs, so the snapshot becomes
   Invalid.
3. Reads `capability_lineage` rows above the lineage rowid high-water mark.
   Lineage only ever inserts a row or upgrades its signed token and provenance
   (`capability_lineage.rs:207-220`), never its subject. A row whose unsigned
   subject was absent therefore takes the lineage subject, and its counts move.
   A row whose existing unsigned subject would change is drift, and the snapshot
   becomes Invalid.
4. Commits the inserts, counts and meta changes in one snapshot transaction,
   which publishes generation g+1.

Extension costs O(delta) and never re-reads authenticated history. An old row
tampered on disk after authentication cannot change any answer, because answers
come from owned state. That tamper is caught by recertification, or by the leaf
check if a page fetches the row.

### 5.3 Recertification

While Ready, the walker repeats the build's chain, batch and final phases in
compare mode over entries up to the E it started at. Extension keeps running.
Every entry's leaf, projection and presence, and every checkpoint row, must equal
the owned snapshot. Any difference makes the snapshot Invalid. Completion stamps
`recertifiedAt`.

The cadence is set by `recertify_interval` (default 1 hour between pass starts).
The rate is limited to the walker's one thread. This is the same work a457
performs on every page, done once per interval instead.

### 5.4 Step bounds, WAL and rotation

- **Step size.** A step covers at most K = 4,096 entries or 64 MiB of `raw_json`,
  and always at least one entry. Row sizes are read with
  `length(CAST(raw_json AS BLOB))` before the text, the pattern
  `session_certificate_read` uses. A row above `max_receipt_bytes` (default
  128 MiB, the trust-control ingress cap at `json_ingress.rs:137`) moves the
  service to Unavailable with the exact reason. That is a configured resource
  limit, not tamper evidence.
- **Transactions.** Each step is one short read transaction on a pooled live
  connection, plus one on a read-only archive connection when the step's range
  lies at or below W. The target is at most 100 ms. No read transaction spans
  steps, so WAL checkpoints proceed between steps, and the WAL is retained no
  longer than one step.
- **Rotation** runs on the writer connection: it attaches the archive, copies,
  deletes the live prefix and records W (`evidence_retention.rs:681`,
  `:1444-1455`). Its busy timeout is 5,000 ms (`bootstrap/open.rs:47`), far above
  one step, so a step can delay rotation by at most one step and never fail it.
  The walker re-reads W in every step and reads each range from wherever it
  lives. Physical location does not matter, because content is bound by the
  signed root.
- **Memory.** One step buffer (at most 64 MiB plus one row up to
  `max_receipt_bytes`), the snapshot page cache (64 MiB), an O(log B) batch
  frontier, and the owned head. Nothing scales with N.
- **CPU and concurrency.**
  - One walker thread per store, plus `verify_threads` (default 1) verification
    workers.
  - Only one of build or recertification is active at a time. Extension
    interleaves with priority.
  - Rebuild requests coalesce into one flag.
- **Snapshot locking.** Signature verification runs outside the snapshot
  connection mutex. Inserts hold it for at most 512 rows (about 10 ms).
- **Cancellation.**
  - A shutdown flag is checked between steps and every 512 rows inside a step,
    so shutdown waits at most one step.
  - A panic inside a step is caught and moves the state to Invalid(internal).
    The snapshot is not reused afterwards.

### 5.5 Disk changes during construction and after publication

- **During build.** Ranges are read in separate short transactions, so an edit
  between steps is possible. Every checkpointed range is accepted only if its
  streamed root equals the signed root, and the chain binds every root. An edit
  to any checkpointed entry, a projection, or a checkpoint row before it is read
  fails the build. An edit after it is read cannot enter the snapshot, which
  already owns the authenticated value. Uncheckpointed tail entries are
  signature-only, as at a457. A later checkpoint is verified against the owned
  leaves (5.2).
- **After publication.**
  - SQL commits and raw edits to any receipt file cannot change snapshot answers.
  - Edits to a row a page returns are refused at fetch by the leaf and signature
    check (6.4). The snapshot then becomes Invalid.
  - Edits to unreturned rows are detected by the next recertification pass.
  - Edits to the uncheckpointed tail are detected by the next checkpoint's
    verification.

## 6. Serving

### 6.1 Request flow

1. The handler takes a non-queued permit from `receipt_query_lane`
   (default 4). If none is free, it returns 503 `receipt_query_busy`.
2. On Tokio's blocking pool, the service validates the query exactly as today:
   outcome values, cost-currency rules, and `effective_read_scope`
   (`chio-kernel/src/receipt_query.rs:200-250`). The same errors are returned.
3. Freshness wait (7.2).
4. Selection and count run in one snapshot transaction under the
   `SqlWorkBudget` progress handler (`reports/analytics/work_budget.rs:11-65`),
   with a fixed plan.
5. The rows are fetched and leaf-verified outside the snapshot mutex (6.4).
6. The response carries the version watermark.

### 6.2 Query shapes and plans

Filter values are resolved to dimension ids first. A missing id returns an
exact empty page with `total_count` 0. Plans are chosen by fixed rules, using
`INDEXED BY` so that work is analyzable:

| Shape | Page | Count |
|---|---|---|
| S1 scope only | `(tenant, seq)` or primary key from the cursor: O(log N + L) | maintained total: O(1) |
| S2 scope plus one equality filter (capabilityId, toolServer, toolName, toolServer and toolName together, outcome, agentSubject, costCurrency without bounds) | `(tenant, D, seq)` from the cursor: O(log N + L) | maintained `(scope, D, value)`: O(1) |
| S3 scope plus a time window (since, until or both) | seq window [s_lo, s_hi] from hour buckets (below), then a `(tenant, seq)` scan with a ts check: O(log N + hours + L + out-of-order rows) | sum of whole-hour counts plus two boundary-hour index ranges: O(hours + boundary-hour rows) |
| S4 point read by receipt id | unique `receipt_id`: O(log N) | none |
| S5 any other combination, including cost bounds | the equality filter with the smallest maintained count supplies the index, clipped to the S3 seq window if one exists; with no equality filter, the S3 window or the `(tenant, cost_currency, cost_charged)` range; other predicates are checked per row | the same index range |

For S3, s_lo is the smallest seq with ts at or above `since`. It is the minimum
of `min_seq` over every hour bucket after hour(since), and an index scan of the
boundary hour. s_hi is computed the same way from `max_seq`. Every matching row
lies in [s_lo, s_hi], so the window is exact, not an estimate. Rows inside the
window whose ts falls outside the range ("out-of-order rows") are scanned and
skipped. With the kernel's clock they are a few seconds' worth at each edge.

### 6.3 Counts

`total_count` is always exact over the version the page was selected from:
- S1, S2: a maintained cardinality.
- S3: maintained hour counts plus boundary index counts.
- S5: a counted index range.

Maintained counts are written in the same snapshot transaction as the rows they
count. Recertification recomputes them with `GROUP BY` and compares, which
detects implementation drift.

An S5 count, or an S3 page with pathological timestamp disorder, that exceeds the
per-request step budget is refused with `receipt_query_work_budget_exhausted`.
The page and the count are both withheld, never partial (A13). S1 through S4 are
bounded independently of the corpus apart from log factors, so a sparse tenant
in a 10M-row corpus costs microseconds (10).

### 6.4 Pages, fetch and the leaf binding

Selection yields at most L = `min(limit, 200)` tuples of (seq, entry_seq,
leaf_hash). For each tuple, in one short live read transaction (plus the archive
when the entry is at or below that transaction's W):

1. read the claim entry's `raw_json` by `entry_seq` (primary key), enforcing the
   per-row byte cap;
2. decode and verify it (`decode_verified_chio_receipt`, Ed25519);
3. recompute the canonical bytes and the leaf, and require it to equal the owned
   leaf;
4. apply the tenant check exactly as `read.rs:204-210` does today.

If the row is absent from both live and archive, the read is retried once in
fresh transactions, because rotation may have moved it in between. Then a
missing row, or any mismatch, fails the request closed with
`receipt_query_snapshot_invalid` and moves the service to Invalid.

Pages also obey a 64 MiB response byte cap. A page stops early when the next row
would cross the cap, but always returns at least one row. `next_cursor` is the
last returned seq whenever more selected rows remain or the page is full,
exactly as today when the cap is not hit. Today's paginators already continue on
a short page that carries a non-null cursor
(`sdks/typescript/chio-ts/src/receipt_query_client.ts:64-88`,
`sdks/python/chio-py/src/chio/receipt_query.py:73-104`).

### 6.5 Point reads

`load_chio_receipt_with_context` looks up `receipt_id` in the snapshot, fetches
the receipt, and leaf-verifies it.

On a miss, the request waits for the snapshot to reach the head observed at
request start (7.2), so a negative answer covers every commit that completed
before the request. If the snapshot cannot catch up within the wait, the request
returns 503 `receipt_query_snapshot_stale`. It never returns an unproven
negative.

While Building, a hit at or above the authenticated suffix floor (5.1, newest
first) is served. Anything else returns 503 `receipt_query_snapshot_building`.
This keeps the kernel's governed-chain point load
(`receipt_handlers.rs:33-68`) available for recent receipts soon after a restart.

### 6.6 Per-request bounds

| Resource | Bound |
|---|---|
| Concurrency | `receipt_query_lane` permits (default 4), non-queued; snapshot SQL serialized on one connection |
| Snapshot SQL | `query_sql_steps` VM steps (default 10,000,000, about 0.13-0.5 s on the reference host), enforced by `SqlWorkBudget` |
| Signature work | at most L (200) Ed25519 verifications plus L SHA-256 leaf hashes |
| Receipt-database reads | at most two short read transactions (live, archive), at most L primary-key reads |
| Bytes | 64 MiB per page (at least one row), each row at most `max_receipt_bytes` |
| Wait | `head_wait` (default 2 s) of blocking wait, no CPU |

## 7. States and freshness

### 7.1 State machine

`Building { authenticated_entries, target_entries, floor }`, `Ready`,
`Invalid { reason, since }` and `Unavailable { reason }`, plus `Stopped`. A
Ready snapshot has a staleness computed per request.

- Start goes to Building.
- Building becomes Ready on success. An authentication failure makes it Invalid;
  a storage or row-cap limit makes it Unavailable.
- Ready advances its generation on each extension and recertification.
  Extension or recertification failure, a leaf-check failure, a poisoned writer
  head, or a walker panic makes it Invalid.
- Invalid stays put until a scheduled rebuild. Rebuilds back off exponentially
  from `invalid_retry_backoff` (default 5 min) up to 1 hour and run only while
  the writer head is not poisoned. A rebuild starts a new lineage in a new
  temporary database; the invalid snapshot is dropped and is never served again.
- Unavailable is rechecked after the operator changes configuration or frees
  space, and on restart.
- Superseded versions are not retained, and no API republishes one.

### 7.2 Freshness contract

- **Head wait.** Each request reads the claim-log head H0 (`MAX(entry_seq)`, a
  primary-key read, or W when the live log is empty after a full rotation) and
  waits up to `head_wait` (default 2 s) for the snapshot's
  E to reach H0. H0 is a wait target only, never authority. An inflated head
  makes the request time out into the rule below, and makes the walker fail to
  authenticate the bogus entry.
- **Serving after the wait.**
  - If the snapshot reached H0, the request is served.
  - If it did not, the request is still served from the current version when
    `observedAt` (the last time the snapshot equalled the live head) is within
    `max_staleness` (default 30 s).
  - Otherwise it returns 503 `receipt_query_snapshot_stale` with Retry-After.
- **Why this never strands a healthy store.** Staleness depends only on
  extension throughput against the append rate. It is independent of corpus
  size, because extension is O(delta) and full passes never gate freshness. A
  large healthy store is never refused for its size. The first build after a
  restart reports Building with progress until it completes (10 gives the
  measured rate). Building always terminates for a healthy store: it has a
  fixed target and finite steps.

### 7.3 Poisoned writer, superseded and invalid snapshots

The service reads a new crate-internal accessor for the writer's
`head_poisoned` flag (`receipt_store.rs:645-656`) at every extension and request.
A poisoned head means the writer's own seed or resync found an integrity
failure. The service then moves to Invalid(writer_head_poisoned), stops
extending, and refuses reads until an operator repair and restart reseed the
writer. A writer that is down but not poisoned does not block reads, because
extension reads the database independently. Its freshness is reported normally.
At startup the service starts only after V25-PRE has awaited writer readiness,
so the writer seed completes, or fails startup, before any snapshot is built.

## 8. Integrity compared with a457

| Property | a457, every page | Snapshot |
|---|---|---|
| Checkpoint chain coherence and membership | re-verified | verified at build, per new checkpoint against the owned head, and again each recertification |
| Checkpointed live and archived claims authenticate | re-verified | at build and each recertification; returned rows on every page (signature plus leaf) |
| Archive source projections | re-verified | at build and each recertification |
| Live source projections (for example, an edited `tool_name` column) | not checked; filters read unsigned columns, so a row silently leaves a filter | filters use signed content; drift is detected at build and recertification |
| Signed but unlogged live source row | served | never served; detected at build and recertification |
| Returned row replaced by a different validly signed receipt after verification | returned; only the row's own signature and tenant are checked | refused by the leaf check |
| Tamper of an unreturned row after authentication | next page refuses | answers unaffected; detected within `recertify_interval` plus one pass, or at fetch |
| Uncheckpointed tail | signature only | signature only, then bound to the owned leaves by the next checkpoint |
| Unsigned lineage subject fallback | trusted | trusted (unchanged), pinned per version, subject changes are drift |
| Work per page | O(N + 2M) signatures, unbounded SQL | at most 200 signatures, bounded SQL |

The one place the snapshot detects later than a457 is the seventh row: tamper of
rows a page does not return. a457 refuses on the next page. The snapshot keeps
serving the authenticated pre-tamper answers until the next recertification
completes, then refuses. Answers never reflect tampered data, counts cannot
drift, and `recertifiedAt` in every response states the detection horizon. Every
other row is equal or stronger. No read that a457 refuses on integrity grounds is
accepted after detection, so this is not a silent weakening. It is an explicit,
bounded detection latency, accepted by the owner's ruling for bounded reads, and
listed as open question Q1.

## 9. Lifecycle and ownership

- **Crate.** The snapshot service lives in `chio-store-sqlite`, because it needs
  crate-internal verification helpers. Its public surface is
  `ReceiptQuerySnapshots::start(Arc<SqliteReceiptStore>, config, clock)`,
  `query_receipts`, `load_receipt`, `status` and `shutdown`. The store's
  existing `query_receipts` and `load_chio_receipt_with_context` keep their full
  per-call authentication for local operator tools (`chio receipt list` local
  mode, evidence export internals, tests). Network handlers must use the
  snapshot service, and a source gate enforces that (plan, Task 6).
- **Owner.** `TrustServiceState` gains `receipt_query_snapshots:
  Option<Arc<ReceiptQuerySnapshots>>` and `receipt_query_lane: Arc<Semaphore>`.
  The service is started once in `serve_async_inner`, after V25-PRE's single
  store has passed `wait_for_writer_ready` (`bootstrap/open.rs:335-348`). One
  owner per database per process; no handler ever starts a writer or a walker.
- **Startup.** The HTTP server starts immediately. Receipt query routes return
  503 Building until Ready. There is no startup timeout, so Initializing
  (Building) and Failed (Invalid or Unavailable) stay distinct. `/health` reports
  the state, progress, `throughEntrySeq`, `observedAt` and `recertifiedAt`.
- **Shutdown.**
  1. The server stops accepting requests.
  2. `ReceiptQuerySnapshots::shutdown` runs in `spawn_blocking`. It sets the
     cancel flag, wakes the walker, and joins it within one step.
  3. The state, and with it the store, is dropped as V25-PRE specifies.

  If the service is dropped without `shutdown` (a panic path), it sets the cancel
  flag and detaches. The walker thread holds its own `Arc` of the store, so the
  store's blocking writer join (`receipt_store.rs:821-836`) then runs on that
  plain thread, never on a Tokio worker.
- **Cluster.** Each node builds its own snapshot over its own database.
  Replicated receipts are appended there and picked up by extension.

## 10. Capacity and resource policy

Measured on this workstation with SQLite 3.50.4, using 1,000,000 synthetic
projected rows, 2,000 tenants with the largest owning 40% of rows, one sparse
tenant with 3 rows, and the index set of 4.3 without the tool-pair and
count tables. Scripts and logs are in `claude-pr1160-evidence/vfix/v25/snapexp/`;
the plan's fixture re-measures with the production schema.

- storage: 111 B/row in the table, 398 B/row with indexes;
- sparse tenant: page and count under 0.1 ms;
- largest tenant (400k rows): mid-cursor page 0.5 ms, 1,000 VM steps;
- single-filter index count: about 3 VM steps per row (17 ms for 400k rows);
- range plus sort: about 7 steps per row;
- index plus table check: about 6.5 steps per row.

Fixed plans matter. On the largest tenant, SQLite's own plan for a "last 1% of
time" page took 1,979,000 steps (134 ms). For a 10% window, a `(tenant, ts)`
range plus sort took 280,000 steps, and the S3 seq-window scan took 2,000 steps
(0.3 ms).

Policy:

| Item | Value |
|---|---|
| Supported capacity (qualified by the plan's fixture) | 10,000,000 tool receipts in one store (live plus archived, any split), up to 10,000 tenants, any single-tenant share; sparse tenant of at most 10 receipts |
| Snapshot storage | at most 600 B per tool receipt, reserved before a build (6 GB at 10M) on SQLite's temp directory; insufficient space makes the service Unavailable(capacity), with the required bytes reported |
| Snapshot RAM | 64 MiB page cache plus the walker step buffer (at most 64 MiB plus one row) plus O(log B) |
| Build time | N divided by the measured walker rate. Each entry is verified once. The fixture measures 1,000,000 signed receipts and reports entries per second per verify thread. The build is linear, with constant per-entry work asserted by counters. |
| Per-request work | 6.6 |
| Above capacity | nothing is disabled because of history size. S1 to S4 stay O(log N). S5 refusals become more likely. Storage is the only hard requirement, and it is checked, never assumed. |

The snapshot does not claim unbounded history in bounded RAM. RAM is fixed;
storage grows at most 600 B per receipt on a disk the operator chooses.

## 11. API, spec and SDK changes

**Kernel** (`chio-kernel/src/receipt_query.rs`, `receipt_store.rs`):

- New `ReceiptSnapshotWatermark { snapshot_id, through_entry_seq,
  checkpoint_seq: Option<u64>, observed_at_unix_ms, recertified_at_unix_ms:
  Option<u64> }`.
- `ReceiptQueryResult` gains `snapshot: Option<ReceiptSnapshotWatermark>`. It is
  `None` on the per-call authenticated path.
- `ReceiptStoreError::QuerySnapshot(ReceiptQuerySnapshotError)` with variants
  `Building`, `Stale`, `Invalid`, `Unavailable`, `Busy` and
  `WorkBudgetExhausted`. Each has a stable `code()`.

**HTTP** (`service_types/requests.rs:519-526`, `responses.rs:269`):

- `ReceiptQueryResponse` and `ReceiptListResponse` gain an optional `snapshot`
  object: `{ "id", "throughEntrySeq", "checkpointSeq", "observedAt",
  "recertifiedAt" }`. This covers `/v1/receipts/query`,
  `/v1/agents/{subject}/receipts` and `/v1/receipts`, including point reads.
- The error body becomes `{ "error", "code" }`, where `code` is an addition to
  today's `plain_http_error` shape (`policy_support.rs:995-997`). Codes and
  statuses:

| Code | Status | Retry-After |
|---|---|---|
| `receipt_query_snapshot_building` | 503 | yes |
| `receipt_query_snapshot_stale` | 503 | yes |
| `receipt_query_busy` | 503 | yes |
| `receipt_query_snapshot_unavailable` | 503 | no |
| `receipt_query_snapshot_invalid` | 500 | no; same status a457 returns for integrity failures |
| `receipt_query_work_budget_exhausted` | 422 | no; narrow the filter |

**Request side.** No new request parameters. Cursor semantics are unchanged:
seq, forward-only, stable across versions. Clarified: a page may hold fewer than
`limit` receipts while `nextCursor` is non-null.

**Spec and docs:**

- `spec/WIRE_PROTOCOL.md` section 4.3 (`:394-425`) gains the response field,
  freshness semantics, the error codes and the short-page clarification.
- `spec/PROTOCOL.md` section 9 (`:2956`) gains one paragraph stating that
  receipt query reads are served from an authenticated snapshot with a
  watermark.
- `docs/reference/RECEIPT_QUERY_API.md` gets the same changes.

**SDKs:**

| Client | Old behavior against the new server | New behavior |
|---|---|---|
| TypeScript `ReceiptQueryClient` | ignores `snapshot`. 503 and 422 throw `QueryError(status)`, as any non-2xx does today. `paginate` handles short pages. | `snapshot?` typed. `QueryError.code` parsed. `paginate` retries `building`, `stale` and `busy`, honoring Retry-After, up to a configurable total wait (default 30 s). |
| Python `ReceiptQueryClient` | same as TypeScript (`TypedDict total=False`) | same as TypeScript |
| C++ client | returns the raw body; 503 and 422 surface as status errors | no change required; the code is passed through |
| Rust control-plane client (`service_runtime/client/operations.rs:527`) and `chio receipt list --remote` | deserializes without `deny_unknown_fields` | field added with `#[serde(default)]` |
| Dashboard (`chio-cli/dashboard/src/api.ts`) | ignores the field | type only |

Old clients keep working. The only behavioral differences they see are 503
during Building after a restart and 422 for expensive S5 filters. Both are
errors they already surface.

## 12. Formal, xtask and gate impact

- `formal/` and `xtask/`: none. No formal model or xtask mirror references
  retained reads, receipt query or the projection rule (searched at a457).
- `docs/security/trust-boundary-inventory.json` (`scripts/check-trust-boundaries.py`):
  - new shared-reader entries for the walker and fetch path (`:19543-19586`
    hold today's `query_receipts` reader entries);
  - new decode sites;
  - the moved projection rule (`:3819-3841`).
- `scripts/security-clock-inventory.json` (`scripts/check-security-clocks.py`):
  `observedAt`, `recertifiedAt`, the recertification schedule and the retry
  backoff read time through the store's injected clock, and each consumer is
  registered.
- `scripts/check-rust-file-hygiene.py`: each new file stays under its base
  limit.
- `scripts/check-negative-assertions.py`: new tests use exact error variants
  and codes.
- `docs/security/landing-ledger.json`: Root links this spec and plan.

## 13. Risks and open questions

- **Q1. Detection latency.** Tamper of unreturned rows is detected within
  `recertify_interval` plus one pass, not on the next page (section 8). Accept
  it with the 1 hour default? Options: a shorter interval, or sampled fetches of
  unreturned rows per request. Sampling detects mass tamper fast but single-row
  tamper only with probability k/N.
- **Q2. Serialized snapshot SQL.** One connection serializes snapshot SQL. A
  cheap query can wait behind one expensive S5 query, up to about 0.5 s at the
  default budget. A multi-connection snapshot needs a named file and weakens the
  boundary of 3, so it is not proposed.
- **Q3. Evidence export.** `POST /v1/evidence/export` stays on the per-call
  authenticated path. It is O(corpus) by contract and tenant-reachable. Proposal:
  run it behind a dedicated one-permit, non-queued lane now, and move its
  selection onto the snapshot as follow-up work. Alternatively, restrict it to
  admin principals.
- **Q4. Restart availability.** After a restart, receipt queries are
  unavailable until the first build completes, roughly N divided by the walker
  rate. Point reads for recent receipts come back early (6.5). Is a
  `verify_threads` default above 1 at startup acceptable?
- **Q5. Unsigned lineage subjects.** The lineage subject fallback stays as
  trusted as it is today. Should a later change bind it to the signed capability
  token held in `signed_capability_json`?
- **Q6. Capacity claim.** 10M rows for query bounds and storage is qualified with
  synthetic projected rows. Build throughput is qualified at 1M signed receipts
  and extrapolated linearly. Is a 10M signed-receipt build required before
  landing, or is it a scheduled qualification run?
- **Risk: temp-directory capacity.** A deployment with a small temp directory
  becomes Unavailable(capacity) instead of serving. The operator must set
  `SQLITE_TMPDIR`. This is the one size-related refusal, and it is reported
  exactly.
