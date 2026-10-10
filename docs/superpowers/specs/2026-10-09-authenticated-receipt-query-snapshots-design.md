# Authenticated receipt query snapshots

- **Status.** Revision 5 reconciles the implemented V25 snapshot design with
  FINAL-F04/F09 recovery and health contracts. The original V25 stage was
  `557d396c30` plus Root's HTTP wiring; `d9e3359e3a` supplies bounded resource
  retries, explicit owner quota growth and sampled telemetry. The public
  disclosure restriction is a final-review follow-up and remains subject to
  its source-bound acceptance record. The Linux private-file backend remains
  the production backend on Linux (4.2).
- **Base.** a457a89c75.
- **Prerequisite.** V25-PRE: one persistent trust-control receipt store, owned
  by `TrustServiceState`. Section 9 lists what this design needs from it.
- **Decision.** Connor chose authenticated query snapshots before #1160 lands.
  He gave that answer at 2026-10-09T05:22:20Z through Claude's question tool,
  and Codex confirmed it in Root's conversation at 05:31:57Z. He rejected
  strict synchronous budgets that refuse healthy stores of roughly 60-80k
  receipts.
- **Inputs.** Codex mailbox entries 04:44:55Z, 05:01:59Z, 05:11:06Z, 05:16:44Z,
  05:21:30Z, 05:23:00Z, 05:27:43Z, 05:55:09Z and 06:09:22Z (the rulings this
  revision folds in).
- **Evidence.** `claude-pr1160-evidence/vfix/v25/`.
- **Plan.** [implementation plan](../plans/2026-10-09-authenticated-receipt-query-snapshots.md).

## 1. Problem

At a457, every receipt query page authenticates the whole retained corpus
before it reads a single row:

- `SqliteReceiptStore::query_receipts` calls `with_retained_snapshot`
  (`crates/platform/chio-store-sqlite/src/receipt_query.rs:24`). The same holds
  for point reads through `load_chio_receipt_with_context`
  (`receipt_store/support/store_impl.rs:6-17`).
- `with_retained_connection_snapshot` (`receipt_store/retained_read.rs:52-77`)
  then does three full passes:
  1. authenticates the archive prefix (`support/store_impl.rs:51-72`,
     `support/checkpoint_validate.rs:576-614`);
  2. re-verifies the whole checkpoint chain, including a Merkle rebuild over
     every live claim above the watermark W (`checkpoint_validate.rs:661-734`);
  3. streams every archived claim again (`retained_projection.rs:38-171`).
- The control plane reaches this path from `GET /v1/receipts/tools`,
  `GET /v1/receipts/query` and `GET /v1/agents/{subject}/receipts` for any
  principal (`trust_control/receipt_handlers.rs:86`, `:293`, `:968`).

Measured at a457: one 10-row tenant page over 200 archived and 200 live
receipts verifies 1,220 signatures, and the count grows linearly with the
corpus (`vfix/v25/f1f2-evidence.txt`).

## 2. Acceptance points and rulings

| Id | Requirement | Section |
|---|---|---|
| A1 | No answer reflects interior tamper or count drift. No silent weakening of what reads accept. | 5.5, 8 |
| A2 | Large healthy stores are never permanently refused because history grew. | 7, 10 |
| A3 | The snapshot owns the authenticated projection and binds every payload byte. A pinned transaction is not authentication. | 4, 6.4 |
| A4 | The adversary boundary is defined, including disk changes during build and after publication. | 3, 5.5 |
| A5 | Rows and total_count bind to one version: every filter, empty results, and the uncheckpointed tail. | 4.4, 6 |
| A6 | Signed but unlogged source rows grant no authority. | 5.2 |
| A7 | A poisoned writer head is observed. | 7.3, 9 |
| A8 | Archive projections are validated at build. | 5.2 |
| A9, A13 | Enforceable CPU, row, byte and concurrency limits. Typed refusal, never a partial count. Sparse tenants work. | 5.1, 6 |
| A10 | Every covering checkpoint is a proven member of the chain. Signer binding holds. | 5.2, 5.3 |
| A11 | Bounded build memory and steps. Coalescing, cancellation, WAL and rotation behavior. Progress under appends. | 5 |
| A12 | Explicit building, stale and invalid states. No revival. No freshness cutoff on corpus size. | 7 |
| A14 | The smallest defensible API change. Old and new SDK behavior. | 11 |
| A15 | Capacity evidence, labeled. Storage and memory policy. | 10 |
| A16 | Existing primitives. Narrow APIs. Complete results for every accepted query. | throughout |
| A17 | No hard seed cutoff. Initializing is distinct from failed. One owner. Stated shutdown semantics. | 9 |

Root rulings applied:

- **Q1. As-of semantics.** Recertification starts once an hour by default. Lag
  is reported honestly as the interval plus the pass duration. No sampling.
  This timing claim is historical: sections 5.4 and 8 supersede it, and give
  no wall-clock detection bound.
- **Q2.** One snapshot connection, with every hold bounded and no unbounded
  queue.
- **Q3. Evidence export.** It keeps its authorization and its full per-call
  authentication, behind a dedicated non-queued permit (section 12).
- **Q4.** One verification worker. No configurable worker pool.
- **Q5.** The unsigned-lineage trust boundary is unchanged.
- **Q6.** Capacity evidence comes from 10M synthetic projected rows plus a
  1M-receipt signed build, labeled distinctly. There is no extrapolated 10M
  cryptographic claim.

Runtime rulings recorded against the implementation:

- **Lease re-check.** A read lease is refused as `invalid` only after an actual
  invalidation. A rebuild, a resource outcome or a stop keeps its own class.
- **Capacity and row-cap recovery.** Bounded exponential retry preserves the
  finite quota. An explicit trusted-owner quota increase wakes the walker and
  takes effect in-process; source repairs or restored backing space recover
  through the same retry path. No request silently raises the budget.
- **Point reads while building.** They return the retryable `building` outcome.
- **Request order.** State and head readiness may precede query validation. HTTP
  authentication and tenant authorization always precede snapshot admission.
- **Health.** The public snapshot summary reads nonblocking process telemetry
  and discloses only configuration and readiness. It never takes HTTP read
  admission or a database hold. Detailed resource and integrity diagnostics
  remain in the trusted owner status API.
- **Extension trigger.** A fixed 250 ms poll plus a read-triggered wake replaces
  the coalesced writer-commit signal of the earlier plan. It keeps the explicit
  head wait and staleness refusal with no writer-notification dependency, at
  the cost of bounded idle polling and a tick of delay when no read is waiting.
  An append is not guaranteed to be visible within one tick: extension work and
  contention can take longer.

## 3. Adversary and trust boundary

The adversary can:

- run arbitrary SQL against the receipt database and its archive, including with
  triggers disabled per connection, at any time;
- edit those files, or their WAL and shm files, in place by path, including
  edits that preserve SQLite's change counter;
- replace or swap those files by path.

The adversary cannot:

- forge Ed25519 signatures under the receipt or checkpoint keys;
- read or write the trust-control process's memory or open descriptors
  (ptrace-level access to the process is out of scope for any read path);
- write the Linux backend's private custody directory (4.2).

Inside the boundary: process memory, the snapshot connection and its custody
storage. Everything SQLite reads from the receipt database and its archive is
outside it.

## 4. Snapshot storage

### 4.1 Contents

The snapshot is a projection of every tool receipt whose claim-log entry is at
or below a watermark E. Every row was derived from a receipt that meets three
conditions:

- its signature verified;
- its claim entry is in the contiguous claim log;
- once a checkpoint covers it, its leaf is bound to a signed checkpoint proven
  to be a chain member.

The snapshot answers filters, counts and page selection. It does not hold
receipt JSON. Each row carries the receipt's RFC 6962 leaf
(`chio-core-types/src/merkle.rs:4-5`), and fetched bytes must match it (6.4).

Every string value is interned verbatim and never truncated. The tables are:

- `snapshot_dim(id, kind, value)`. Kinds are tenant, capability, tool_server,
  tool_name, tool (the server and name pair), subject and currency. Id 0 means
  absent.
- `snapshot_signer(id, kernel_key)`.
- `snapshot_tool_receipt`. Columns: `seq` (the source seq and API cursor; the
  primary key), `entry_seq` (unique), `leaf_hash`, `signer`, `receipt_id`
  (unique), `ts`, `tenant`, `capability`, `tool_server`, `tool_name`, `tool`,
  `decision`, `subject`, `subject_signed`, `cost_currency` and `cost_charged`
  (8-byte big-endian). Secondary indexes:
  - `(tenant, seq)`;
  - `(tenant, D, seq)` and `(D, seq)` for each equality dimension D;
  - `(tenant, ts, seq)` and `(ts, seq)`;
  - `(tenant, cost_currency, cost_charged)` and
    `(cost_currency, cost_charged)`.
- `snapshot_count(scope, dim, value, n, min_seq, max_seq)`. These are the
  maintained cardinalities, held per scope (a tenant or all tenants) for each
  total, each equality value and each hour bucket (`ts / 3600`).
- `snapshot_checkpoint(seq, batch_start, batch_end, tree_size, merkle_root,
  kernel_key)`, the verified chain.
- `snapshot_pending_leaf(entry_seq, kind, leaf_hash, signer)`, the leaves of
  entries above the newest verified checkpoint.
- `snapshot_child_cursor(source_seq, entry_seq, signer)`, which enforces the
  cursor-uniqueness rule (`retained_projection.rs:16-24`) and supports the
  source bijection check.

Kept outside SQLite: the newest verified `KernelCheckpoint` and its
`CheckpointChainFrontier` (`chio-kernel/src/checkpoint.rs:412-480`), E, the
lineage rowid mark, and the state.

### 4.2 Backends and custody

The backend is chosen by platform (`SnapshotDb::open_private`,
`receipt_query_snapshot/db/storage.rs`). Both backends take the same quota
(4.3), and exhausting it is a typed capacity refusal that never implies support
for unlimited history. Default Linux, macOS and Windows deployments (release
targets at `.github/workflows/release-binaries.yml:49-70`) need no new
prerequisite.

**Linux: private file backing (production).** `SnapshotFileBacking`
(`receipt_query_snapshot_backing.rs`) was delivered under the constraints of
the 06:09:22Z ruling, with its location amended as the first item states:
- **Location (amends the 06:09:22Z fixed-`/tmp` clause).** Snapshot
  directories live in one versioned private parent,
  `chio-receipt-snapshots-v2` (mode `0700`, owned by the effective user),
  inside the receipt store's own data directory: the directory of its main
  database file, as SQLite resolved it. Only a store without a data directory
  (in memory) falls back to `/tmp/chio-receipt-snapshots-v2-<euid>`. There is
  no operator setting and no `SQLITE_TMPDIR` prerequisite. The data directory
  itself may also be group-writable (a setgid volume root, for example); every
  ancestor keeps the strict rule. Group writers can rename or remove the data
  directory or the parent, which denies service as their access to the
  receipt store already can, but a replacement fails the held identity checks
  and is never used;
- one private directory (mode `0700`) per snapshot, named by a UUIDv7, whose
  owner holds an exclusive `flock` on it for the custody's lifetime;
- a dedicated named snapshot database (single link, mode `0600`) under that
  directory, opened without `CREATE` or URI interpretation, with no WAL, an
  in-memory rollback journal and in-memory temp store;
- the actual SQLite descriptor bound to the held file and directory
  identities, rechecked on every checked borrow of the connection, so each
  snapshot hold re-validates custody before it runs SQL;
- negative controls that replace the parent or the path;
- cleanup of the directory when the backing is dropped, and reclamation of the
  directories of owners that died without unwinding (below);
- no mutation of process-global SQLite temp settings, no custom VFS, and reuse
  of the repository's file primitives (`chio-sqlite-file-identity`, `rustix`).

**Reclamation.** The kernel releases an owner's `flock` however the owner
dies, so an unlocked directory in the parent has no live owner. Provisioning
takes a non-blocking exclusive lock on the parent before it publishes a
directory and keeps it until that directory's own lock is held; reclamation
takes the same lock, so it never observes a live directory unlocked. Under the
lock, each provisioning first reclaims one bounded window (at most 256 entries
read and 16 snapshot directories examined) and records where the next attempt
resumes in `reclaim-cursor`, an 8-byte private file created before any
snapshot directory and rewritten in place; only then does it publish its own
directory. Reclaimed space is freed before the cursor is rewritten. An
in-place rewrite needs no new block on a filesystem that overwrites in place,
but can on a copy-on-write one (btrfs, ZFS); a failed rewrite refuses that
attempt as `Unavailable`. The walker also reclaims before it
waits for the writer seed, and again every 30 seconds of the store clock while
that wait lasts. Reclamation examines only UUIDv7-named, owner-only `0700`
directories, checks each identity through held descriptors without following
links, unlinks only the known snapshot leaves and then the empty directory, and
never recurses. Directories of earlier builds
(`/tmp/chio-receipt-snapshot-<uuid>`) carry no liveness lock and are never
examined.

A custody refusal (a substituted directory, file, leaf or descriptor, a
sidecar, or changed journal settings) is an integrity outcome: the read or step
fails `Invalid`. A filesystem I/O error is a resource outcome: `Unavailable`.
So are the location refusals raised before a snapshot is admitted: a contended
parent lock, or a parent or cursor that is not a private entry of this user.
They leave the refused entries untouched. Under the stated trust boundary (3),
the private directory is part of the process's custody. The snapshot shares
the receipt store's filesystem. For an in-memory store, if `/tmp` is a
`tmpfs`, the file occupies system memory, and a local user who pre-creates the
fixed fallback parent denies the fallback with an operational refusal.

**Other platforms, and tests: `memory`.** The snapshot connection is a private
`:memory:` database. Custody is process memory, and no file exists.

### 4.3 Quota, accounting and SQLite memory

- **Hard limit.** `PRAGMA max_page_count` is set to `quota_bytes / page_size`.
  SQLite returns `SQLITE_FULL` when a write would exceed it.
- **Exhaustion.**
  - The step's snapshot transaction rolls back.
  - The state becomes `Unavailable(capacity { quota_bytes, used_bytes })`.
  - Reads get a typed 503.
  - No value is truncated, and no partial version is published.
  - SQLite FULL can also mean transient backing-storage exhaustion. A failed
    transaction can roll back below the page ceiling, so usage alone cannot
    identify which resource was exhausted. The diagnostic reports both possible
    causes, with quota and usage, without calling either an integrity failure.
  - Capacity and per-row-limit failures retry with exponential backoff (initial
    configured retry interval capped at 30 seconds, maximum one hour). Busy,
    other temporary unavailability and SQL work-budget outcomes keep the existing
    fixed retry interval capped at 30 seconds. Quotas never grow automatically.
    Cancellation interrupts either wait.
- **Accounting.** The trusted owner `status()` and sampled `health_status()` APIs report:
  - `quota_bytes`;
  - `used_bytes` (`page_count * page_size`);
  - row count;
  - distinct dimension count;
  - dimension value bytes.
  The inspecting `status()` API checks owned storage. The sampled
  `health_status()` API reads a coherent walker-maintained sample with
  nonblocking memory locks. Its watermark identifies the sampled version; it
  is not a fresh payload integrity check. Public `/health` discloses only the
  configuration and readiness state, omitting the detailed sample.
- **Default quota and operator setting.** The quota defaults to 2 GiB
  (2147483648 bytes) on both backends. Operators set it with
  `chio trust serve --receipt-query-snapshot-quota-bytes <BYTES>`
  (`TrustServiceConfig.receipt_query_snapshot_quota_bytes: u64`), explicit
  bytes only, minimum 1 MiB (1048576), with no environment variable. Every
  other snapshot limit is a fixed default. The applied quota is rounded down to
  whole pages and capped at SQLite's maximum page count; `status()` reports the
  applied value. How many receipts fit is an estimate that depends on value
  lengths (10).
  Embedded service owners may call `ReceiptQuerySnapshots::request_recovery`
  with an optional larger quota. The deployed node exposes the same operation at
  `POST /v1/receipts/query/snapshot/recovery`, using service-token authentication
  before its strict 256-byte JSON body is read. Tenant read tokens are refused.
  `{}` requests a retry; `{"quotaBytes": N}` also raises the runtime quota.
  Decreases are refused, and a healthy projection is not rebuilt. The response
  reports `scheduled` with a retry epoch (202) or `serving` (200), not completed
  recovery. Requests act only on the addressed node and are never forwarded.
  An unchanged-quota retry wakes only resource backoff; an explicit increase
  can wake either backoff. Every rebuild retains all authentication checks.
  Runtime increases are lost on restart unless the deployment's
  `--receipt-query-snapshot-quota-bytes` setting is changed too.
- **What the quota is not.** It bounds snapshot database pages only (the file
  on Linux, process memory elsewhere). It is not a limit on process RSS (10).
- **SQLite heap outside the page quota.** The page quota does not cap other
  SQLite heap allocations, so the plans are written to avoid them:
  - Every fixed query plan walks an index in cursor order, so no plan uses a
    sorter. Cost bounds are checked per row on the currency index.
  - No plan uses a temporary b-tree for `ORDER BY`, `DISTINCT` or `GROUP BY`.
  - Control C18 asserts this from `EXPLAIN QUERY PLAN` for every traced
    plan.
  - The capacity fixture measures process memory, so statement allocations
    are counted.
- **Per-row resource limit.** A receipt row larger than `max_receipt_bytes`
  (default 128 MiB, the ingress cap at `json_ingress.rs:137`) is outside the
  walker's resource limit. It yields `Unavailable(row_cap { entry_seq, bytes })`.
  This is a resource boundary, not tamper evidence.

### 4.4 Versions, read lease and cursors

- **Version id.** A version is identified by `<lineage>:<generation>`. The
  lineage is random and drawn per build. The generation increases on every
  committed change: new entries, new checkpoints, and lineage refreshes (5.3).
  Rows never change except for the refresh.
- **Selection and count.** Both run in one snapshot transaction on one version,
  and that version's watermark is returned. Empty results are complete. An
  unknown filter value has no dimension id, and dimensions are committed with
  the rows that use them.
- **Read lease.** When a request is admitted to a Ready version it records the
  phase epoch, which advances on every phase transition except build progress.
  Before it returns, after fetch, it re-checks the lease
  (`receipt_query_snapshot/service.rs` `recheck_lease`):
  1. A poisoned writer head invalidates the lineage first.
  2. If the epoch is unchanged, the request returns its own version. A newer
     generation of the same lineage does not change the epoch.
  3. If an Invalid transition happened after the lease was taken, the request
     returns `receipt_query_snapshot_invalid`.
  4. Otherwise the request returns the typed outcome of the current phase:
     `building` (Waiting or Building), `unavailable` (Unavailable or Stopped),
     or `stale` when a replacement lineage is already Ready. These are
     availability outcomes, so a read that only lost its version to a resource
     outcome or a rebuild is never reported as an integrity failure.
- **No version-pinned cursors.** No request starts on a version older than the
  current one. Once invalidated, a version is never served again.
- **What `snapshot.id` is.** It is informational. It is not accepted as a
  request parameter, and there is no version-pinned multi-page cursor.
  Multi-page iteration uses today's seq cursor. A new generation only adds rows
  with higher seq (AUTOINCREMENT, `bootstrap/open.rs:621-623`), plus the
  subject refresh of 5.3. So `total_count` may change between pages, as it does
  today.

## 5. Walker

One thread per store authenticates receipts from the mutable database, with
one verification worker (Q4). It reuses existing primitives:

- `parse_persisted_checkpoint_row` (`checkpoint_validate.rs:290-296`);
- `validate_checkpoint_base` and `validate_checkpoint_predecessor`, and the
  `chain_root` frontier step (`checkpoint_validate.rs:661-734`, refactored into
  a per-checkpoint step that the existing loop keeps calling);
- `validate_checkpoint_projection_rows` (`:1472`);
- `ArchiveCheckpointReader` (`support/checkpoint_read.rs:4-72`);
- `decode_verified_chio_receipt` and `decode_verified_child_receipt`
  (`support/receipt_verify.rs:123-163`);
- the signer rule of `load_checkpoint_claim_tree_canonical_bytes_range`
  (`support/checkpoint_projection.rs:707-748`);
- the source-projection rule of `retained_projection.rs:84-133`, factored into
  one function that both callers use;
- `SqlWorkBudget` (`receipt_store/reports/analytics/work_budget.rs`, imported as
  `crate::receipt_store::support::SqlWorkBudget`).

### 5.1 Step contract

Each step has four phases. Every limit below is enforced, not a timing target.

1. **Copy.** One short read transaction on a pooled live connection, plus the
   read-only archive connection when the range is at or below the W read in
   that transaction. It only selects claim rows by `entry_seq` range, and it is
   bounded by:
   - `step_rows` (default 1,024);
   - `step_bytes` (default 16 MiB, but at least one row);
   - `walker_sql_steps` VM steps (default 50,000,000), the one budget every
     walker read transaction takes.

   Each row's length is read with `length(CAST(raw_json AS BLOB))` before its
   text. A single row may exceed `step_bytes` up to `max_receipt_bytes`. A row
   above that is the row-cap resource boundary of 4.3. The rows are copied into
   owned memory, and the transaction ends.
2. **Authenticate.** No transaction or lock is held. Each entry gets its
   signature, signer, canonical leaf, projection, and frontier append.
   Cancellation is checked every 64 entries.
3. **Check.** One short read transaction, bounded by `step_rows` lookups and
   `walker_sql_steps`. It reads each source row by seq (live, else archive) and
   returns its projection columns and `raw_json = ?` equality. The comparison
   happens after the transaction.
4. **Insert.** Holds the snapshot connection for at most `insert_rows` (default
   256) rows and `hold_sql_steps` per hold.

Further rules for every step:

- **Fresh reads for full passes.** The build and every recertification read
  through a fresh read-only connection, so a page cache cannot hide an
  in-place edit made on disk. Extension and fetch use pooled connections.
- **Cancellation.** Each `SqlWorkBudget` progress handler also checks the
  cancel flag, so it interrupts SQL at its next progress callback (every 1,000
  VM steps). Shutdown sets the flag and waits for the current phase to stop.
  A phase blocked inside an uninterruptible filesystem call stops only when
  that call returns. Cancellation ends in `Stopped`; it is not an integrity
  outcome.
- **Budget exhaustion.** When a walker SQL budget runs out, the step ends
  without effect and the state becomes `Unavailable(walker_budget)`. The walker
  rebuilds after `min(invalid_retry_backoff, 30 s)`. This is a resource
  outcome, not evidence of tamper.
- **Contention.** A busy error from SQLite ends the step without effect, and the
  walker retries with backoff. The state is unchanged.
- **Durations.** Elapsed time is measured and reported (10), never promised.
- **Integrity.** Only an authentication or comparison failure makes the state
  Invalid.

### 5.2 Build

A build runs at start, after Invalid with backoff, and after a walker-budget or
busy-store Unavailable outcome (7.1). It pins its target in one
starting observation, a single read transaction that records:

- T0 = `MAX(entry_seq)`, or W0 when the live log is empty;
- the initial watermark W0;
- c0, the newest checkpoint whose `batch_end` is at most T0;
- the observation time t0.

It then runs three phases, in steps:

1. **Chain.** Checkpoint rows with seq at most c0, in `checkpoint_seq` order.
   Checkpoints appended during the build, and any checkpoint whose `batch_end`
   exceeds T0, belong to extension after publication. For each:
   - signature and columns;
   - the base, or the predecessor link to the previous verified checkpoint;
   - `chain_root` against the running frontier;
   - projection rows;
   - for rows at or below W, equality with the archived row.

   Rows are appended to `snapshot_checkpoint`. Projection id-set completeness
   is checked in the final step by count and maximum, since every expected row
   was already checked.
2. **Batches, in ascending order.** For each verified checkpoint, the claim
   range is copied in steps from wherever it lives. For each entry:
   - every signer must equal `checkpoint.kernel_key`, so a mixed signer or a
     different key fails with the a457 errors;
   - the leaf is appended to a streaming RFC 6962 frontier (O(log B) memory for
     any batch size B);
   - for tool entries, a row is inserted; for child entries, a cursor;
   - the source row is checked with the retained projection rule: it exists
     once, its `raw_json` is equal, and its columns equal the signed
     projection. An archived seq must not be live and must not exceed the live
     `sqlite_sequence` ceiling. The rule now applies to live entries too.

   At the end of each batch, the frontier root must equal `merkle_root` and the
   count must equal `tree_size`.
3. **Tail.** Entries in (`batch_end(c0)`, T0]. They must be contiguous. Each is signature-only, as at a457. Its leaf and signer go to
   `snapshot_pending_leaf`, and its row and source check proceed as above.

A final step runs in one read transaction:

- Live tool and child source counts must equal the snapshot rows and cursors
  located above W. The source rows counted are those with seq at most the
  snapshot's maximum tool or child seq. W is read in the same transaction.
  Later appends always get higher seq (AUTOINCREMENT), so they are excluded.
  Combined with per-entry existence, this is a bijection, so an unlogged source
  row fails the build. One added after T0 is caught by the next
  recertification.
- The projection id sets must be complete.

Maintained counts are updated in each insert transaction, together with the
rows they count. No phase runs a whole-table `GROUP BY`. The build then
publishes version 1, with `E = T0`, the head checkpoint c0, and
`observedAt = t0`.

- **Fixed target.** The target (T0, W0, c0) never moves, so the build ends after
  a finite number of steps whatever the append rate. Appends and checkpoints
  that arrive during the build are handled by extension after publication.
  Control C11b appends a checkpoint during the build. Version 1 must stop at T0
  and c0, and the next extension must accept the new checkpoint.
- **Membership and archive projections.** Every checkpoint is accepted only as
  part of the walk from seq 1, and every claim range only against such a
  checkpoint (A10). Archive projections are validated here (A8).
- **Building reads.** While Building, every read returns 503 `building`,
  including point reads. That covers an early row in a batch whose later row is
  corrupt (control C8b).

### 5.3 Extension

A cycle starts on the `extension_tick` (default 250 ms), or at once when a read
is waiting for the head (7.2) or an invalidation wakes the walker. There is no
writer commit signal.

1. **Target.** In one observation, sample T = `MAX(entry_seq)` (or W when
   the live log is empty), the newest checkpoint whose `batch_end` is at most
   T, and the lineage rowid high-water mark, at time t.
   - If T < E, or W is lower than the W last seen, the head or watermark has
     regressed. The state becomes `Invalid(regressed)`, and `observedAt` is not
     refreshed.
2. **Checkpoint-covered entries.** Process each checkpoint in the target in
   order. Authenticate its signature, projection, predecessor link and
   `chain_root`. Before publishing any new row in its covered range:
   - authenticate claim entries in bounded steps and stage only their leaf
     hashes and signers, without changing visible rows, counts or E;
   - recompute the checkpoint root from those owned leaves and any previously
     published pending tail leaves. Require contiguous entries, the exact
     `tree_size`, and `signer == checkpoint.kernel_key` for every entry;
   - after the root matches, re-read and authenticate the new entries, check
     their source rows, and require each leaf and signer to match the owned
     leaf that the root verified. Publish rows and their maintained counts in
     bounded holds;
   - accept the checkpoint as the owned head, then delete its pending leaves
     in bounded holds. If a cycle is interrupted, retain the leaves of already
     published entries; discard and stage again only those beyond E.

   Previously authenticated rows remain visible during staging. A validly
   signed substitute that disagrees with an already observed covering root
   must never become a visible page, point result or count contribution.
3. **Uncheckpointed tail.** Process the remaining entries through T in steps
   as in the build's tail phase. Publish rows and their pending leaves together.
   These entries remain signature-only until a later checkpoint authenticates
   the owned leaves. No newly observed covering checkpoint may be treated as
   absent merely to publish its rows early.
4. **Lineage refresh.** For capability lineage rows up to the sampled rowid
   mark, apply the canonical local-read provenance validation before using the
   subject. Preserve the existing unsigned `LegacyProjection` contract;
   `SignedToken` and `SyntheticAnchor` must satisfy their own validation rules.
   Lineage only inserts rows or upgrades their signed token and provenance
   (`capability_lineage.rs:207-220`). An absent unsigned subject is filled in,
   and its counts move. A changed existing subject is drift, and the state
   becomes Invalid.
5. **Freshness.** When E >= T, `observedAt` becomes t: the observation time of
   the target, not the completion time.

Each cycle has a fixed target, so it ends in finitely many steps. Freshness
holds only while the sustained append rate stays below the measured walker
throughput (section 10). Above that rate, `observedAt` ages, and reads follow
section 7.2. No freshness or termination is promised for an unbounded append
rate.

### 5.4 Recertification

A pass is scheduled no sooner than `recertify_interval` (default 1 hour) after
the previous pass started. It starts only when no pass is running and the
version has covered an observed head to target, so an active pass, a lagging
extension or contention can delay it further. It repeats the build's chain,
batch and tail checks in compare mode, over entries up to the E fixed when the
pass starts. Extension keeps running alongside it.

- **Per step.** The pass copies and authenticates as in 5.1. Then, in one
  bounded hold, it reads the snapshot rows for the same `entry_seq` range and
  compares leaf, signer, projection and presence. Any difference makes the
  state Invalid, with one exception. A subject that a lineage refresh filled in
  after the pass derived it as absent is accepted, because that direction is
  the refresh rule of 5.3.
- **Counters.** A pass re-verifies rows, not counts, and never runs a
  whole-table `GROUP BY` on the serving connection after publication.
  - **Why counts are safe.** Maintained counts are owned state. They change only
    inside the snapshot transaction that changes the rows they summarize, so no
    database mutation can alter them. A wrong count could come only from a
    defect in this code.
  - **How correctness is tested.** A differential property test compares every
    maintained count with `GROUP BY` after each generation of randomized
    appends, refreshes and invalidations. The capacity fixture checks all counts
    after its run.
- **Reporting.** `recertifiedAt` (pass completion) and the last pass duration
  are reported. A source mutation of a row no page returns is detected only by
  a later pass. The delay is at least on the order of `recertify_interval`,
  grows with pass duration, active passes and contention, and has no
  wall-clock bound. No answer reflects the mutation in the meantime. This is
  as-of semantics, not immediate whole-database tamper detection, and the API
  docs say so (section 11).

### 5.5 Disk changes during build and after publication

- **During the build or a pass.** Ranges are copied in separate short
  transactions, so an edit can land between them. Every checkpointed range is
  accepted only if its streamed root equals the signed root, and the chain
  binds the roots. An edit made before a range is copied fails the build or the
  pass. An edit made after cannot enter the snapshot. Tail entries are
  signature-only until the next checkpoint is checked against the owned leaves.
- **After publication.** No database change alters a snapshot answer.
  - A returned row that was edited or substituted fails the leaf check (6.4),
    and the state becomes Invalid.
  - An unreturned edit is caught by the next recertification.
  - A tail edit is caught by the next checkpoint.
  - A regressed head is caught by extension.

### 5.6 Rotation and WAL

- **Live database.** Walker transactions are short reads in WAL mode, so they
  do not block the writer, and checkpoints of the WAL proceed between steps.
- **Archive.** A reader can delay rotation's archive commit, and rotation waits
  up to its `busy_timeout` (`bootstrap/open.rs:47`). A rotation that still
  fails is recorded through `record_retention_rotation_outcome` and retried on
  the next maintenance run, as today (`support/store_impl.rs:855-860`). A
  control exercises rotation under walker contention.
- **Location.** The walker reads W in every copy transaction and reads each
  range from wherever it lives. Content is bound by the signed roots.

## 6. Serving

### 6.1 Request flow

1. **Two-layer admission.** Both layers are non-queued; without a permit, the
   request returns 503 `busy`.
   - The control plane takes an HTTP permit before `spawn_blocking`, and moves
     it into the closure so a cancelled request holds it until the work stops.
   - The core service then takes one of its own read permits
     (`max_concurrent_reads`, default 4). This bounds every consumer,
     including the ones that do not come through HTTP.
   Before admission the handler authenticates the caller (401, 403), validates
   the cost bounds and currency (400) and requires a configured store (409),
   so none of those take a permit.
2. The control plane calls the service on the blocking pool.
3. Check the state and take the lease (4.4). Any state other than Ready
   returns its typed outcome (7.1).
4. Apply the freshness rule (7.2).
5. Validate exactly as today, inside the selection: outcome, currency rules
   and `effective_read_scope` (`chio-kernel/src/receipt_query.rs:200-250`).
   Selection and count then run in one snapshot transaction under
   `SqlWorkBudget`.
6. Fetch the selected rows and check their leaves.
7. Re-check the lease (4.4) and return the version watermark to the control
   plane's blocking adapter. That adapter converts and serializes the response
   while it still owns the HTTP admission permit. Request cancellation does
   not release the permit before the worker and response materialization end.

### 6.2 Shapes and plans

Filter values resolve to dimension ids. A missing id gives an exact empty page
with `total_count` 0. Plans are fixed with `INDEXED BY`.

| Shape | Page | Count |
|---|---|---|
| S1 scope only | `(tenant, seq)` or the primary key, from the cursor | maintained total |
| S2 scope plus one equality filter: capabilityId, toolServer, toolName, the toolServer and toolName pair, outcome, agentSubject, or costCurrency without bounds | `(tenant, D, seq)` from the cursor | maintained `(scope, D, value)` |
| S3 scope plus a time window | a seq window [s_lo, s_hi] from hour buckets, then a `(tenant, seq)` scan with a ts check | whole-hour sums plus two boundary-hour index counts |
| S4 point read | unique `receipt_id` | none |
| S5 everything else | the index of the equality filter with the smallest maintained count, clipped to the S3 window if present; cost bounds always come with a currency filter and are checked per row | the same range |

How S3 builds its window:

- s_lo is the minimum of `min_seq` over the hour buckets after hour(since),
  together with the boundary hour's index scan.
- s_hi is built the same way from `max_seq`.
- Every matching row lies in [s_lo, s_hi], so the window is exact.
- Rows in the window whose ts falls outside the range are scanned and skipped.

### 6.3 Counts

`total_count` is exact for the version that was selected. It comes from three
sources:

- S1 and S2 use the maintained counts, written in the same snapshot transaction
  as their rows;
- S3 adds whole-hour counts to two boundary-hour index counts;
- S5 counts its index range.

Any shape that exceeds `query_sql_steps` returns 422
`receipt_query_work_budget_exhausted`. Both rows and count are withheld; the
response is never partial.

### 6.4 Fetch and leaf binding

Selection returns up to L = `min(limit, 200)` tuples of `(seq, entry_seq,
leaf_hash)`. Their raw rows are copied in one short read transaction on the
live database, plus the archive for entries at or below that transaction's W.
Steps 2 to 4 run after the transaction ends, outside any lock.

1. Copy `raw_json` by `entry_seq`, under the per-row byte check and
   `fetch_sql_steps`.
2. Decode it and verify the signature.
3. Recompute the canonical leaf, which must equal the owned leaf.
4. Apply today's tenant check (`receipt_query/read.rs:204-210`): a scoped read
   requires the signed tenant to equal the scope's tenant.

A row absent from both the live database and the archive is retried once in
fresh transactions, because rotation may have moved it. If it is still absent,
or any check fails (kind, the `max_receipt_bytes` size check, signature, leaf,
or the tenant check), the request returns `receipt_query_snapshot_invalid` and
the lineage is latched Invalid: it is never served again, and every read
holding a lease on it refuses `invalid` at its re-check (4.4). A tenant
projection mismatch is an integrity outcome like a leaf mismatch, because the
authenticated projection disagrees with the signed body.

A page stops before the row that would exceed `page_bytes` (default 16 MiB),
but always returns at least one row. `next_cursor` is then the last returned
seq. No receipt is ever truncated. Existing SDK paginators continue across such
a short page (`receipt_query_client.ts:64-88`, `receipt_query.py:73-104`).

### 6.5 Point reads

- **Positive answers.** A Ready version that holds the id is fetched and its
  leaf checked as in 6.4.
- **Positive answers do not wait.** A version that holds the id answers at
  once, with no head wait.
- **Negative answers.** The snapshot must reach H0, the head read when the
  request starts. Reaching H0 within `head_wait` gives a negative bound to every
  commit made before the request. Otherwise the read returns 503 `stale`; there
  is no `max_staleness` allowance for a negative answer.
- **While Waiting or Building.** Point reads return 503 `building` with
  `Retry-After: 5`, the same as every other read (5.2). Clients retry them.

### 6.6 Per-request limits

All limits are enforced, and each has a typed outcome.

| Limit | Default | Outcome |
|---|---|---|
| HTTP receipt read lane permits, non-queued (public health does not use this lane) | 4 | 503 `busy` |
| Core service read permits (`max_concurrent_reads`), non-queued | 4 | 503 `busy` |
| `query_sql_steps` (snapshot) | 10,000,000 | 422 |
| L signature checks and leaf hashes | at most 200 | none |
| `fetch_sql_steps`, for the payload fetch and for the head read | 1,000,000 | 503 `unavailable` (fetch or head budget); a resource outcome, not tamper |
| `page_bytes` | 16 MiB, at least one row | short page with a cursor |
| `max_receipt_bytes` per row | 128 MiB | Invalid: the authenticated row was within the cap, so a larger row differs from it, the same outcome as a leaf mismatch |
| `head_wait` (blocking wait holding a permit) | 2 s | falls through to 7.2 |
| `max_staleness` | 30 s | 503 `stale` |

Each walker hold is bounded by `hold_sql_steps`. Before each hold the walker
checks a count of requests waiting for the connection, and it yields while that
count is nonzero. A request therefore waits for at most one walker hold plus at
most three requests ahead of it, each bounded by its own budget. Query work
while a recertification runs is covered by control C14.

## 7. States and freshness

### 7.1 States

The states are `ReceiptQuerySnapshotState` in
`receipt_query_snapshot/service.rs`, reported on `/health` under the names in
brackets.

- **`WaitingForWriterSeed` (`waiting_for_writer_seed`).** The walker waits,
  without a deadline, for the writer to seed a verified head. Reads get 503
  `building` (0 of 0 entries) with `Retry-After: 5`.
- **`Building { authenticated_entries, target_entries }` (`building`).** One
  state for the whole build, reported with that progress; the chain, batch,
  tail and final steps of 5.2 are not exposed as separate phases. Reads get 503
  `building` with `Retry-After: 5`.
- **`Ready` (`ready`).** Reads are served subject to the freshness rule (7.2).
- **`Invalid { reason }` (`invalid`).** `reason` is the failure message (tamper,
  regression, a poisoned or unseeded writer head, a leaf or tenant mismatch, a
  custody refusal, or an internal error); no timestamp is kept. Reads get 500
  `invalid`. A rebuild starts a new lineage on a fresh connection after
  exponential backoff: `invalid_retry_backoff` (default 5 minutes), doubling to
  at most 1 hour, and reset to the initial value after a successful
  publication. A rebuild starts only while the writer head is not poisoned.
- **`Unavailable { reason }` (`unavailable`).** Resource outcomes, never
  integrity ones. Reads get 503 `unavailable` without `Retry-After`.
  - `walker_budget` and a busy store end the lineage, and the walker rebuilds
    after `min(invalid_retry_backoff, 30 s)`.
  - `capacity` and `row_cap` retry after exponential backoff, starting at
    `min(invalid_retry_backoff, 30 s)` and capped at one hour. Successful
    publication resets the backoff. An explicit owner recovery request wakes
    the walker, including a retry with unchanged quota. The node-local HTTP
    operator route described above exposes this operation to the service token.
    Quotas never grow automatically; the CLI option sets the startup quota.
- **`Stopped` (`stopped`).** Entered after cancellation. Reads get 503
  `unavailable`.

`/health` also reports `unconfigured` without a receipt store, and `unavailable`
when the service was not started or a telemetry lock is temporarily held. It
never borrows HTTP receipt admission and never exposes raw failure reasons.

An invalid or superseded snapshot is dropped. It is never published again.

### 7.2 Freshness

1. A page request reads H0 and waits up to `head_wait` for E >= H0.
2. If E still falls short, the request is served from the current version only
   when `now - observedAt` is at most `max_staleness` (default 30 s).
3. Otherwise it returns 503 `stale` with Retry-After.

Staleness depends on the append rate measured against walker throughput, never
on corpus size. Building ends after finitely many steps, because its target is
fixed.

### 7.3 Writer poison

The service reads a new crate-internal accessor for the writer's `head_poisoned`
flag (`receipt_store.rs:645-656`) at three points: each extension cycle, each
selection, and each lease re-check. A poisoned head moves the state to
`Invalid(writer_head_poisoned)`, and reads are refused until an operator repair
reseeds the writer. A writer thread that is down but not poisoned does not block
reads, because extension reads the database directly.

## 8. Integrity compared with a457

| Property | a457, every page | Snapshot |
|---|---|---|
| Chain coherence and membership | re-verified | at build, for each new checkpoint against the owned head, and each recertification |
| Claim authentication, live and archived | re-verified | at build and each recertification; returned rows on every page (signature and leaf) |
| Archive projections | re-verified | at build and each recertification |
| Live source projections | not checked; filters read unsigned columns | filters read signed content; drift detected at build and recertification |
| Signed but unlogged live row | served | never served; detected at build and recertification |
| Returned row replaced by another validly signed receipt | returned | refused by the leaf check |
| Mutation of an unreturned row | the next page refuses | answers unchanged; detected by a later recertification pass, no sooner than `recertify_interval` and with no wall-clock bound (5.4) |
| Uncheckpointed tail | signature only | signature only, then bound to the owned leaves by the next checkpoint |
| Unsigned lineage subject | trusted | trusted, and pinned per version (Q5) |

The snapshot uses as-of semantics. An answer is the authenticated state at its
watermark. The difference from a457 is that mutation of unreturned rows is
detected at the recertification cadence rather than on the next page (Q1).

## 9. Lifecycle and ownership

- **Ownership with V25-PRE.**
  - V25-PRE owns opening the store, writer readiness, `join_writer_on_reaper`,
    and dropping the store at shutdown.
  - V25-PRE's unanchored startup may serve while the writer is still Seeding.
    Its anchored startup must meet the same no-hard-cutoff rule (Codex 05:21).
    Both are V25-PRE's to implement.
  - This design adds `TrustServiceState.receipt_query_snapshots:
    Option<Arc<ReceiptQuerySnapshots>>`. It starts the service once after the
    store exists and stops it before the store is dropped.
  - Read admission has two layers (6.1): an outer, non-queued HTTP permit
    taken before `spawn_blocking`, and the core service's own non-queued read
    permit. Task 6 implements the outer layer as
    `TrustServiceState.receipt_query_lane` (4 permits) in
    `trust_control/receipt_query_service.rs`, with
    `evidence_export_lane` (1 permit) beside it (12).
  - `chio trust serve` passes `receipt_query_snapshot_quota_bytes` into the
    service configuration (4.3); every other limit is the default.
- **Start, asynchronously.**
  - `ReceiptQuerySnapshots::start` validates the configuration and returns at
    once in `WaitingForWriterSeed`. An invalid configuration fails service
    startup.
  - The walker thread polls writer readiness with its cancel flag and no
    deadline, using the same classification V25-PRE uses. If the writer closes
    serving without seeding a verified head (a poisoned seed included), the
    state becomes `Invalid("receipt writer failed to seed a verified head")`.
    Otherwise the build starts.
  - HTTP serves from the beginning and reports the state.
  - `/health` carries `receiptQuerySnapshot` with only `configured` and
    `state` (7.1). The sampled observation is read without receipt admission
    or database work. Counts, resource use, progress, watermarks and error
    details are omitted. The snapshot summary alone does not determine the
    top-level HTTP status or `ok`; other service readiness checks still apply.
- **Shutdown.**
  1. The server drains.
  2. `shutdown()` runs in `spawn_blocking`. It sets the cancel flag, wakes the
     walker, and waits for the current phase to stop (5.1). A phase blocked in
     an uninterruptible filesystem call stops only when that call returns.
  3. V25-PRE drops the store.

  If the service is dropped without `shutdown()`, it sets the cancel flag and
  detaches. The walker holds an `Arc` to the store, so any blocking writer join
  (`receipt_store.rs:821-836`) happens on that plain thread.
- **Local operator paths.** `SqliteReceiptStore::query_receipts` and
  `load_chio_receipt_with_context` keep full per-call authentication for local
  operator tools. A source gate keeps them out of trust-control handlers.
- **Cluster.** Each node builds its snapshot from its own database.

## 10. Capacity evidence and resource policy

Measured on this workstation with system SQLite 3.50.4 (the production build
bundles 3.51.3). The data was 1,000,000 synthetic projected rows with short
values, using the 4.1 index set minus the tool-pair column and the count
tables. Scripts and logs are in `vfix/v25/snapexp/`.

| Measurement | Result |
|---|---|
| Storage | 398 B/row with indexes |
| Sparse-tenant page and count | about 0 progress-handler steps |
| Largest tenant (400,000 rows), mid-cursor page | 1,000 steps |
| Single-filter index count | about 3 steps/row |
| SQLite's own plan for a recent-window page | 1,979,000 steps |
| Seq-window scan for a 10% window | 2,000 steps |

These are fixture measurements, not bounds. Per-row storage grows with value
lengths.

Capacity evidence that must exist before landing (plan Task 8), labeled
distinctly:

- **Projection capacity, synthetic.** 10,000,000 projected rows, with a
  large-field slice (long receipt ids, tool names and subjects). It records
  bytes per row, per-shape VM steps, the typed refusal of an over-budget S5
  shape, and quota exhaustion giving `Unavailable(capacity)`.
- **Build capacity, signed.** 1,000,000 signed receipts, half archived and half
  live, including one large batch. It records walker throughput with one
  worker, peak walker memory, step durations, and WAL growth during the build.
  The supported append rate is stated as "below the measured throughput". No
  10M signed-build claim is made.

Resource policy:

- **Storage.** The snapshot database, up to the quota (default 2 GiB,
  reported): a private file in the receipt store's data directory on Linux,
  on that filesystem (under `/tmp` only for an in-memory store), process
  memory on other platforms (4.2). Files left by owners that died are
  reclaimed (4.2).
- **RAM outside the quota.** The quota is not a process RSS limit. Outside it:
  - the in-process intern maps of every distinct dimension value and signer
    (reported as `dimensions` and `dimensionBytes`);
  - SQLite's page cache and statement memory, with sorter memory avoided by
    the fixed plans (4.3);
  - one walker step buffer: at most `step_bytes`, or one row of at most
    `max_receipt_bytes` when a single row is larger;
  - each admitted read's fetched page, up to `page_bytes` of receipt JSON;
  - O(log B) frontier state.
- **Receipts per quota.** An estimate. The fixture records it; at the measured
  short-value size it is about 2 GiB / 400-500 B. Long values lower it.
- Nothing is disabled because history grew. The limits that can refuse are the
  configured quota and the per-row cap, both typed and reported.

## 11. API, spec and SDK changes

**Kernel.**

- New `ReceiptSnapshotWatermark { snapshot_id: String, through_entry_seq: u64,
  checkpoint_seq: Option<u64>, observed_at_unix_ms: u64,
  recertified_at_unix_ms: u64 }`.
- New `ReceiptQueryResult.snapshot: Option<_>`. It is `None` on the per-call
  path.
- New `ReceiptStoreError::QuerySnapshot(ReceiptQuerySnapshotError)`. Variants:
  `Building`, `Stale`, `Invalid`, `Unavailable`, `Busy` and
  `WorkBudgetExhausted`, each with a stable `code()`.

**HTTP wire contract.** This is the exact shape Root builds the SDKs against.

The `snapshot` object is added as an optional field on three response bodies:

- `ReceiptQueryResponse`, returned by `GET /v1/receipts/query` and
  `GET /v1/agents/{subject}/receipts`;
- `ReceiptListResponse`, returned by `GET /v1/receipts/tools`, including point
  reads by `receiptId`. Child receipts (`GET /v1/receipts/children`) share the
  type but are not served from the snapshot, and omit the field.

Servers with this change always include it on those routes. Clients must treat
an absent field as "unknown" so they keep working against older servers.

```json
"snapshot": {
  "id": "5f0c...e1:42",
  "throughEntrySeq": 120345,
  "checkpointSeq": 1203,
  "observedAt": 1760000000123,
  "recertifiedAt": 1759996400456
}
```

| Field | JSON type | Meaning |
|---|---|---|
| `id` | string | Opaque version id. Informational only: never a request parameter and never a cursor |
| `throughEntrySeq` | integer, unsigned 64-bit | Every claim-log entry at or below this is included, and none above |
| `checkpointSeq` | integer, unsigned 64-bit, or `null` | Newest verified checkpoint in this version; `null` when the store has none. Entries above its range are signature-only |
| `observedAt` | integer, Unix milliseconds | Observation time of the newest head target this version fully covers (the as-of time) |
| `recertifiedAt` | integer, Unix milliseconds | Completion time of the last full authentication pass, build or recertification. Rows a response does not return may have been mutated since, undetected until the next pass, but that never alters an answer |

**Typed errors.** Only the new snapshot outcomes carry `code`. Their body is
`{"error": string, "code": string}`. Every existing error (400, 401, 403, 409,
500) keeps today's `{"error": string}` body unchanged; an `outcome` value
outside the four accepted values remains a plain 500, as at a457.
`Retry-After` is an integer number of seconds.

| `code` | HTTP status | `Retry-After` | Client action |
|---|---|---|---|
| `receipt_query_snapshot_building` | 503 | 5 | retry (also returned while waiting for the writer seed, and to point reads) |
| `receipt_query_snapshot_stale` | 503 | 2 | retry (also returned when a replacement lineage became Ready during the read, 4.4) |
| `receipt_query_busy` | 503 | 1 | retry (either admission layer, or the export lane) |
| `receipt_query_snapshot_unavailable` | 503 | absent | do not retry; resource outcome: capacity or row cap (restart with operator action), walker budget or busy store (the service rebuilds on its own), fetch or head budget, custody I/O, not started, stopped |
| `receipt_query_snapshot_invalid` | 500 | absent | do not retry; integrity failure (same status a457 returns) |
| `receipt_query_work_budget_exhausted` | 422 | absent | do not retry; narrow the filter |

**Request side.**

- No new request parameters.
- `cursor` keeps today's semantics: forward-only, by seq.
- A page may hold fewer than `limit` receipts while `nextCursor` is non-null.
  Clients continue until `nextCursor` is null.
- `totalCount` is exact for the version named by `snapshot.id`. It may change
  between pages, as it does today.

**New SDK retry contract** (Codex 06:17Z):
- Bounded retry lives in the query call itself, and `paginate` delegates to
  it, so direct query callers recover too.
- The default 30 s is a retry budget per query call, which means per page. It
  is not a budget for a whole pagination, which may be unbounded.
- Only `building`, `stale` and `busy` are retried, each after the server's
  `Retry-After`.
- There is no retry on 422, on 500, on `unavailable`, or on a 503 without a
  known code.
- TypeScript keeps its local `code = query_error` and exposes the server's code
  as `serverCode`. Python exposes it as `server_code`.
- `snapshot` is typed as optional, and `checkpointSeq` is null before the
  store's first checkpoint.

**Spec and docs.**

- `spec/WIRE_PROTOCOL.md` section 4.3 (`:394-425`): the response field, codes,
  freshness, the as-of statement and short pages.
- `spec/PROTOCOL.md` section 9 (`:2956`): one paragraph.
- `docs/reference/RECEIPT_QUERY_API.md`: the same content.

**SDKs.**

Root owns the TypeScript and Python clients and the dashboard types
(coordinator, 06:12Z).

| Client | Old SDK against the new server | New SDK |
|---|---|---|
| TypeScript `ReceiptQueryClient`, Python `ReceiptQueryClient` | `snapshot` is ignored; 503, 422 and 500 throw the existing status error with no retry; `paginate` already continues on a short page with a non-null `nextCursor` | see the retry contract above |
| C++ client | raw body; status errors | unchanged |
| Rust control-plane client (`service_runtime/client/operations.rs:527`) | no `deny_unknown_fields` | `snapshot` added with `#[serde(default)]` |
| Dashboard (`chio-cli/dashboard/src/api.ts`) | ignores the field | optional type only |

## 12. Evidence export (Q3)

`POST /v1/evidence/export` keeps today's authorization and full per-call
authentication. Changes:

- It runs under a dedicated non-queued `evidence_export_lane` with 1 permit,
  returning 503 `busy` when taken. The work runs in `spawn_blocking` with the
  permit moved into the closure, so a cancelled HTTP request holds the permit
  until the work stops. The permit covers the whole export: the bundle build,
  requirement validation and response finalization (`IntoResponse`, including
  JSON serialization) all run inside the same blocking task. Exports never
  take receipt read permits.
- The API docs state that a full export costs O(retained corpus).

V25 does not remove every lifetime-cost endpoint. Reports keep their own
budgets, and export is bounded only in concurrency.

## 13. Gate impact

- **`formal/` and `xtask/`.** No impact. Nothing in them references retained
  reads or receipt query.
- **`scripts/check-trust-boundaries.py`.** New shared-reader entries and decode
  sites, and the moved projection rule, are registered in
  `docs/security/trust-boundary-inventory.json` (existing entries at
  `:3819-3841` and `:19543-19586`).
- **`scripts/check-security-clocks.py`.** `observedAt`, `recertifiedAt`, the
  schedules and the backoff read time through the injected store clock. They
  are registered in `scripts/security-clock-inventory.json`.
- **`scripts/check-rust-file-hygiene.py` and
  `scripts/check-negative-assertions.py`.** New files stay within their limits,
  and tests assert exact variants and codes.

## 14. Remaining risks

- **Restart.** Receipt reads are unavailable after a restart until the first
  build completes, at a duration that grows linearly with history (measured in
  Task 8).
- **Snapshot connection contention.** One snapshot connection means requests
  can wait behind bounded holds.
- **Snapshot capacity.** Linux uses the private file backend in the receipt
  store's data directory; other platforms use `memory`. On either backend a store larger than the quota
  becomes `Unavailable(capacity)`. The service retries without removing its
  resource bound. Transient backing pressure can recover without restart;
  genuine page-budget exhaustion requires an explicit larger owner budget.
  An embedded owner can request the increase in process, while a CLI deployment
  restarts with a larger `--receipt-query-snapshot-quota-bytes`. Repeated failed
  rebuilds back off rather than permanently latching or repeatedly allocating
  a larger projection. These limits remain typed and reported.

### Public health disclosure boundary

The unauthenticated snapshot health response contains only `configured` and
`state`. It does not publish sampled receipt or dimension counts, resource usage,
watermarks, raw error reasons, paths or host details. The trusted owner status
API retains the detailed, source-bound observation for diagnosis. Public polling
continues to use nonblocking telemetry and never acquires receipt admission or
a snapshot database hold.
