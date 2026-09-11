# chio-store-sqlite

SQLite-backed persistence for the Chio protocol kernel. This crate is the
concrete backend for the kernel's receipt log and every other durable store
trait the kernel depends on: budgets, human approvals, capability revocation,
execution-nonce replay guards, signing-key custody, encrypted blobs, memory
provenance, IOU envelopes, and dead letters. The store traits themselves are
defined in `chio-kernel` (and, for a few economic types, `chio-credit` and
`chio-settle`); this crate implements them against SQLite and owns no
protocol-level behavior of its own.

Reader-heavy receipt queries run against an 8-connection reader pool
(`DEFAULT_READER_POOL_MAX_SIZE`); writes serialize through a single
group-commit actor onto one writer connection (`DEFAULT_WRITER_POOL_MAX_SIZE
= 1`).

## Responsibilities

- **Receipt store** (`receipt_store`, `SqliteReceiptStore`): implements
  `chio_kernel::ReceiptStore`. Appends receipts through a group-commit writer
  actor, maintains an incrementally verified head, builds and validates
  signed checkpoints, enforces checkpoint-aligned evidence retention, and
  persists capability, session, request, and receipt lineage.
- **Receipt query** (`receipt_query`): `SqliteReceiptStore::query_receipts`,
  multi-filter, cursor-paginated tool-receipt search.
- **Operator reports** (`receipt_store/reports/*`): ten report families on
  `SqliteReceiptStore` - analytics, authorization, behavioral, billing,
  compliance, cost attribution, economic, reconciliation, settlement, and
  shared evidence.
- **Liability and underwriting persistence**
  (`receipt_store::{liability_claims, liability_market, underwriting_credit}`):
  the claim lifecycle (claim, response, dispute, adjudication, payout,
  settlement), the provider/quote/placement market, and underwriting
  decisions, appeals, credit facilities, credit bonds, and credit-loss
  lifecycle events.
- **Evidence export and federation** (`evidence_export`,
  `receipt_store::bootstrap::federated`): assembles self-contained,
  Merkle-proof-backed evidence bundles, and imports and queries signed
  evidence shares from partner Chio instances.
- **Budget store** (`budget_store`, `SqliteBudgetStore`): implements
  `chio_kernel::BudgetStore`. Per-grant invocation and cost limits with a
  two-phase authorize-then-settle model, plus replication sequencing and
  ack-head bookkeeping for multi-node budget sync.
- **Approval stores** (`approval_store`, `batch_approval_store`): implement
  `chio_kernel::ApprovalStore` and `BatchApprovalStore`. Durable
  human-in-the-loop approval requests and resolutions, and standing batch
  approvals matched by pattern, call count, and spend cap.
- **Governed approval replay** (`governed_approval_replay_store`): durable,
  subject-scoped replay reservations with retained clock and capacity state.
  Explicit exact-expected source sealing permanently freezes all retained
  markers and installs persistent SQL write barriers for migration. A sealed
  reopen is read-only and ignores requested capacity. The typed migration-only
  `SqliteGovernedApprovalReplaySource` also preserves an unsealed inventory on
  reopen, without legacy startup pruning or metadata adoption. The qualified
  admission store can independently pin a source and atomically import its
  complete history as inactive tombstones with global audit commitments.
  Explicit v23 activation checks the actual authority clock against imported
  high-water and prune history. Operation-fenced claim and release ports retain
  canonical token commitments and original request/grant ownership. Expiry
  is checked by normal kernel acquisition before budget authorization when the
  activated source is explicitly configured. Nonce reservation/capture accepts
  physically verified single-approval custody without substituting it for any
  retained threshold proposal or approval set. An oversized proposal fails closed.
  Expiry cannot release committed dispatch custody; exact history remains readable for
  recovery. Complete combined runtime/credential interruption and independent-process
  qualification remain open.
  Import is not activation, an operation claim, a dispatch permit or an
  independent antirollback guarantee; see
  the [credential migration boundary](../../../docs/superpowers/specs/2026-09-07-caller-dispatch-commitment-design.md#governed-approval-legacy-source-retirement).
- **DPoP source migration** (`SqliteAdmissionOperationStore`): v24 ports pin the
  actual process-local source instance, seal and verify it outside destination
  locks, then atomically import its complete canonical history with global
  audit commitments. Local and signed retention clocks
  and historical owners are preserved without turning process-relative deadlines
  into portable expiry. Missing or replaced sources deny import and retry;
  decoding a stored snapshot cannot reconstruct the live source. Schema v25
  adds explicit activation of a signed v2 domain with immutable destination,
  authority, source generation and freshness policy. First activation verifies
  the exact imported live source and a conservative source wall-clock floor;
  the descriptor, activation event and global audit commitment are atomic.
  Exact activation readback/retry survives later source loss without source
  callbacks. A pending or imported-inactive source cannot use this recovery
  path. Upgrade preserves v24 import digests and never activates automatically.
  The migration record and activation descriptor remain evidence, not operation
  custody or dispatch permission. Unknown prior history is not restored, and
  v1 proofs cannot enter the v2 domain. Schema v26 adds operation-fenced v2
  claim/release/history ports with atomic local/global commitments, retained
  invocation/grant binding and immutable resource projections. Fresh budget
  authorization, nonce preflight and dispatch require unexpired live custody;
  exact committed results remain recoverable after expiry. Dispatch permanently
  prevents release. Proof signatures are not retained. Live v2 capacity uses
  the imported source's limits but is separate from legacy-domain tombstones;
  expiry frees live capacity, not spent identity or historical evidence.
  Configured kernel acquisition consumes verified evidence before budget on
  normal/nested/strict-nonce preflight routes, with exact episode rollback and
  startup recovery after source loss. Selection requires this already activated
  domain and never activates or recreates the source. Full caller security
  custody and combined interruption/process qualification remain open; see the
  [configured DPoP kernel checkpoint](../../../docs/security/launch-plan.md#configured-dpop-kernel-acquisition-and-recovery).
- **Revocation, nonce, and authority** (`revocation_store`,
  `execution_nonce_store`, `authority`): implement
  `chio_kernel::RevocationStore`, `ExecutionNonceStore`, and
  `CapabilityAuthority`. A monotonic capability revocation list, one-time
  execution-nonce reservation, and kernel signing-key custody with rotation
  and cluster-leader fencing.
- **Encrypted blobs and memory provenance** (`encrypted_blob`,
  `memory_provenance_store`): tenant-scoped ChaCha20-Poly1305 blob storage,
  and a hash-chained audit trail of agent-memory writes.
- **Settlement support** (`iou_store`, `dead_letters`): persists
  `chio_credit::IouEnvelope`s and permanently failed settlement receipts
  (`chio_settle::DeadLetterRecord`).
- **Schema governance** (`schema_version`): a shared open-path gate every
  store above calls, refusing a foreign, mismatched, or too-new database file
  before any write.
- **Security-state deadlines** (`SqliteSecurityStateStore`): trusted time is
  sampled inside a database transaction after lock and snapshot acquisition.
  Egress and scheduler validators retain a coherent read snapshot. These lease
  and fence checks reject expiry during a lock wait. Exact committed egress
  replay remains evidence, not new authority.
- **Transaction-owned security mutations** (internal): flow and declassification
  use/outbox mutations can share one outer SQLite transaction. Errors and drop
  cancellation roll back uncommitted work; public legacy methods still commit
  independently. Fresh one-shot consumption checks the independent store clock;
  exact retained replay remains historical. This is not activated operation
  custody, and does not reverse previously committed taint during compensation.
- **Security participant source retirement** (`security_state`): the explicit
  `SqliteSecurityParticipantSource` migration handle previews and permanently
  seals a quiesced legacy flow/declassification source. An exact bounded
  fingerprint binds all fourteen critical tables to the actual SQLite main file;
  one transaction installs seal evidence and 48 persistent write barriers,
  followed by exact readback. Normal typed security-store handles then refuse
  service, including handles opened before retirement. This is not destination
  import, activation, an operation-owned participant or a backup/rollback
  mechanism. Unrelated active-defense tables are not claimed transferred. Do not
  retire a serving source before all its consumers have a qualified migration.
  See the [source boundary and limits](../../../docs/superpowers/specs/2026-09-07-caller-dispatch-commitment-design.md#flow-and-declassification-source-retirement).
- **Inactive security participant import** (`SqliteAdmissionOperationStore`):
  schema v27 pins the exact source under the real destination serving fence,
  then imports every canonical critical-table row after verified retirement.
  Immutable local history is linked one-to-one with global authority commits;
  reads rehash actual retained bytes. Source I/O occurs outside destination locks.
  Pending pins reserve capacity (16 sources, 65,536 rows, 64 MiB total), before
  any source is sealed. This archive is not an active security store, a recovered
  operation owner or permission to execute. Activation, mutable fenced custody
  and all affected consumer migrations remain required before serving adoption.
- **Retained security-row decoding** (internal): source inventory and destination
  readback enforce the compiled predecessor's SQLite cell layout. The bounded v1
  decoder preserves full-width integers, blobs, text and null without coercion.
  Live and retained egress paths share complete fence/commitment validation.
  Decoded rows and valid historical fences do not establish activation or custody.
- **Native security-state hydration** (`SqliteAdmissionOperationStore`): schema
  v28 adds authority-scoped relational projections of the fourteen archived
  tables. `hydrate_security_participant_state` restores only an exact imported
  generation, verifies actual native rows against every source fingerprint, and
  anchors an immutable initialization in the same outer transaction. Every key,
  uniqueness constraint and cross-table reference includes the security authority.
  `load_security_participant_state` returns opaque initialization history, not a
  mutable store. Schema v29 preserves v28 initialization bytes and their original
  catalog digest. Admission schema v30 retains that native catalog and adds a
  separate egress journal. Hydrated state remains inactive for serving; only
  the operation-owned monotone join and egress writers below may change their
  respective native rows.
  The kernel's final dispatch gate rejects a native selection before legacy
  lifecycle callbacks. That requirement is retained with original admission;
  removing the live hook or selecting optional policy cannot erase it. A join
  acknowledgement is not native egress or declassification custody.
- **Operation-owned native flow joins** (`SqliteAdmissionOperationStore`):
  `join_security_participant_flow` checks the actual current admission operation
  and recovery lease, original retained security identity and authority selection,
  independently verified initialization, transition ownership and fresh
  flow-generation observation. The trusted host selects a data-only
  `NativeSecurityAuthorityBindingV1` from initialization history before kernel
  admission. Retained request v4 includes the existing v3 commitment to the
  destination UUID, authority identifier and original initialization digest,
  plus an explicit original runtime/approval/DPoP authority profile. New claims
  compare their authority and generation with that profile inside the operation
  lease transaction. A first native join requires both the native selection and
  this profile; older requests cannot acquire missing authority retroactively.
  Older records and exact native join retries remain historical data,
  without rewriting their bytes or changing the physical v29 schema. Serving
  owner rotation does not change the original initialization selection.
  The portable `AdmissionOperationStore` join/history ports connect this writer
  to a kernel-created `NativeSecurityFlowJoinAuthority` before dispatch budget
  capture. History readback returns the current operation and complete command,
  selected initialization, mutation digest and historical result in one fenced
  snapshot. The forwarding write resolves the initialization independently and
  the physical transaction rechecks it with the actual operation lease.
  An affine internal authorization permits exactly the prepared join. The owned
  transaction captures bounded before/after row images, retains original lease
  evidence and result, and appends the mutation to the global authority anchor.
  Live capture and journal readback share semantic row checks: tenant and
  affected-cohort scope, immutable identity/evidence cells, nonregressing positive
  generations, canonical label hashes and monotone label restriction. Nested
  SQL effects cannot turn a join into declassification. The returned snapshot
  must also match actual post-mutation rows before the transaction can commit.
  Errors roll back the transaction; uncertain committed outcomes require owner
  recovery. Exact retries return historical results, not fresh observations.
  `load_security_participant_flow_join` returns opaque historical readback under
  the current serving fence without reacquiring the original operation lease.
  Current rows verify against the immutable import plus the complete mutation
  chain without re-executing historical commands. Fresh writes do not replay the
  growing mutable history. A command permits at most 4,096 row changes and 8 MiB
  of row images; canonical records are bounded to 16 MiB and each authority's
  journal to 65,536 records and 64 MiB. Capacity exhaustion denies without pruning
  history. These are storage bounds, not throughput qualification.
  Kernel-coupled native egress, declassification consumption/outcomes,
  dispatch-ledger binding, general participant recovery and explicit activation
  remain required. No live adapter or imported historical obligation is released.
- **Classified native input joins** (`AdmissionOperationStore`):
  `join_native_security_input` retains an explicit original input intent and
  resolves it under the same actual operation lease and write transaction.
  It joins input plus all actual principal, global lineage and session labels
  into each row, including inherited state before an exact epoch exists.
  The existing affine writer, SQL allowlist, row capture, bounds, commit chain
  and crash cutpoints are shared with raw joins. The internal canonical event
  is `chio.native-security-flow-join.v2`; raw events retain byte-identical v1
  shape and independent-label semantics. No SQL migration or old-record rewrite
  is required. `load_native_security_input_join` returns original intent and
  resolved history together; raw/input retries cannot adopt the other family.
  Neither readback nor a committed input join grants dispatch authority.
- **Operation-owned native egress custody** (`SqliteAdmissionOperationStore`):
  `acquire_security_participant_egress` and `commit_security_participant_egress`
  require an actual tool operation in `CapturePending`, its current recovery
  lease, original native selection and authority profile, same-operation join,
  trusted flow key and fresh generation. Stable live request material must match
  the original admission. A separate canonical hash of the complete live request
  binds transient credentials across acquisition, commitment and exact retries;
  the journal does not retain raw transient credentials. This equality is not
  credential verification or permission to invoke a tool.
  A distinct affine egress owner permits only one exact pending-fence insertion
  or the owned pending-to-committed update. It cannot change labels, delete rows,
  adopt imported fences, alter fence fields or mutate another authority. The
  actual post-write row is independently checked before journal append. Both
  phases retain canonical command/result, original lease evidence and captured
  row images in an immutable egress journal anchored by the global commit chain.
  Commit references its own acquisition digest. Join-v1 bytes, counters and
  eight-table mutation policy remain unchanged. Recovery folds both journal
  families in global commit order while checking their independent sequences,
  hash chains, time order and exact current rows. Combined history retains the
  existing 65,536-record/64-MiB bound, not one allowance per family.
  The portable `AdmissionOperationStore` acquire/commit ports forward into these
  same writers after resolving the exact selected initialization. Each write
  independently rechecks that read and actual operation custody in its own
  transaction. `load_native_security_egress` returns the current operation and
  both egress phases from one fenced, anchored snapshot. A missing operation is
  distinct from an operation with no acquisition. Later commitment retains the
  acquisition's fence and digest plus the exact predecessor reference. Expired
  history is readable without renewing the operation lease or egress fence.
  `load_security_participant_egress` returns opaque historical custody under the
  current serving fence. Readback and exact retries neither renew expired fences
  nor restore a stale generation. Schema v30 migration rejects partial future
  catalogs and preserves prior initialization, join and global history; missing
  current barriers are never repaired automatically. These SQLite APIs are not
  yet wired into the kernel's native dispatch lifecycle. Native dispatch still
  denies, and native nonce, declassification, dispatch-ledger coupling, explicit
  activation and production resolver support remain open.
- **Fresh native flow observations** (`SqliteAdmissionOperationStore`):
  `observe_security_participant_flow`, also available through the portable
  `observe_native_security_flow` port, reads current labels and the exact context
  row generation in one deferred transaction. It checks the current serving
  fence, independently observed time, global anchor, full native row/history
  coverage and selected initialization. Missing or mismatched initialization is
  an error; a valid unjoined context is a successful observation with no stored
  generation. Effective inherited labels may still exist for that context.
  This distinction lets first admission use absence while retaining inherited
  taint. Subsequent admissions require a freshly observed stored generation.
  Reads create no rows, anchors, operations, leases or activation and remain
  separate from historical join readback. Integrity verification is bounded but
  history-dependent; this API is not a throughput or retention qualification.
  The control-plane native resolver implements classified input and fresh
  post-join policy. Full lifecycle coupling and activation remain unimplemented.
- **Scoped flow mutation engine** (internal): one domain implementation uses a
  closed catalog of explicit legacy/native queries for joins, generations,
  isolation transitions and egress fences. Native parameters include authority
  in every lookup, conflict key, cohort update and nested source selection.
  Read-only inspection cannot construct a writer. Native monotone joins require
  the opaque admission authorization and rollback-owning transaction above.
  Native egress requires its distinct fence-only owner; other production
  mutations still require the legacy owner. Both native owners install a
  transaction-scoped SQL authorizer that rejects writes outside the command's
  native table set, including nested changes to unrelated operation claims.
  Row capture additionally enforces exact authority and row contents. The
  authorizer is removed before journal append and during error unwinding;
  rollback remains allowed if removal fails. The operation lease is rechecked
  after domain execution. Hydration checks
  scoped semantics and later readback verifies anchored row history. Test-only
  native writers remain isolated SQL-semantic fixtures, not activation authority.
  Both scopes reject nonpositive stored generations as corrupt history.
- **Scoped declassification engine** (internal): consumption, terminal evidence,
  lifecycle, acknowledgement/retry, pending/stranded scans and compaction use the
  same checked SQL binder with explicit authority-scoped queries. Permanent
  evidence identities and complete receipt-pair bindings are verified before
  compaction. Legacy readiness and candidate reads hold one SQLite snapshot;
  all mutations remain inside the outer rollback-owning transaction. Native
  tests cover authority collisions, retained-cell parity and inactive barriers.
  This is data-engine reuse, not operation custody, activation or a native public
  declassification port. Operation-owned declassification mutations and consumer
  migration remain required.

## Public API

Re-exported at the crate root (`chio_store_sqlite::*`):

| Item | Implements / provides |
|------|------------------------|
| `SqliteReceiptStore`, `BackgroundCheckpointSigner` | `chio_kernel::ReceiptStore`; background checkpoint signing |
| `SqliteBudgetStore` | `chio_kernel::BudgetStore` |
| `SqliteApprovalStore` | `chio_kernel::ApprovalStore` |
| `SqliteBatchApprovalStore` | `chio_kernel::BatchApprovalStore` |
| `SqliteRevocationStore` | `chio_kernel::RevocationStore` |
| `SqliteExecutionNonceStore`, `SqliteExecutionNonceStoreError` | `chio_kernel::ExecutionNonceStore` |
| `SqliteCapabilityAuthority` | `chio_kernel::CapabilityAuthority` |
| `SqliteMemoryProvenanceStore`, `SqliteMemoryProvenanceStoreError` | `chio_kernel::MemoryProvenanceStore` |
| `SqliteIouEnvelopeStore`, `IOU_ENVELOPE_MIGRATION` | `chio_credit::IouEnvelopeStore` |
| `SqliteEncryptedBlobStore`, `BlobHandle`, `EncryptedBlob`, `TenantId`, `TenantKey`, `encrypt_blob`, `decrypt_blob`, `BlobStoreError`, `EncryptError`, `DecryptError` | tenant-scoped encrypted-blob storage |
| `check_schema_version`, `stamp_schema_version`, `SchemaVersionError`, `CHIO_SQLITE_APPLICATION_ID` | shared schema/anchor-table gate |
| `SqlitePoolConfig`, `SqliteStoreOptions`, `DEFAULT_READER_POOL_MAX_SIZE`, `DEFAULT_WRITER_POOL_MAX_SIZE`, `is_in_memory_sqlite_path` | pool sizing and in-memory-path detection |

`SqliteReceiptStore`'s method surface is larger than `receipt_store.rs`
itself: capability lineage (`src/capability_lineage.rs`), evidence export
(`src/evidence_export.rs`), liability and underwriting persistence, and the
ten report families all add inherent methods to the same struct from
separate files under `src/receipt_store/`.

Not re-exported at the crate root:

- `dead_letters::SqliteDeadLetterStore` - opened with `open_with_pool` or
  `open_alongside(&SqliteReceiptStore)`; there is no standalone `open(path)`.
- `lineage_cte::{forward_receipt_lineage, reverse_receipt_lineage}` -
  recursive-CTE lineage walks, behind the `lineage` feature.

## Feature flags

| Flag | Effect |
|------|--------|
| `pq` | Forwards to the aliased `chio-core` (`chio-core-types`) and `chio-kernel` `pq` features (post-quantum signing support). |
| `lineage` | Enables `lineage_cte`, recursive-CTE forward/reverse walks over `receipt_lineage_statements`. Off by default; the receipt store's own delegation-chain and lineage-statement paths work without it. |
| `admission-test-support` | Default-off cross-crate tests can install four fixed, fail-only native journal abort points on the serving-owner connection. Temporary triggers disappear on close; no arbitrary SQL, data replacement or verification bypass is exposed. Do not enable in production builds. |

## Testing

```
cargo test -p chio-store-sqlite
cargo test -p chio-store-sqlite --features lineage
RUSTFLAGS="--cfg chio_store_sqlite_loom" cargo test -p chio-store-sqlite --test loom_receipt_writer --release
cargo bench -p chio-store-sqlite --bench store_receipt_write_throughput
```

The loom test models the receipt-commit actor's channel accounting (pre-send
inflight increment, unconditional dequeue decrement, bounded fail-closed
queue), since loom cannot execute SQLite directly.

## See also

- `chio-kernel` - defines the store traits this crate implements (`ReceiptStore`, `BudgetStore`, `ApprovalStore`, `RevocationStore`, `ExecutionNonceStore`, `CapabilityAuthority`, `MemoryProvenanceStore`).
- `chio-core-types` - protocol types persisted here (receipts, capabilities, sessions); depended on as `chio-core` in this crate's `Cargo.toml`.
- `chio-credit`, `chio-settle` - the IOU envelope store trait and dead-letter record type this crate persists.
- `chio-supervisor` - the supervised-thread runtime the receipt-commit writer actor runs under.
