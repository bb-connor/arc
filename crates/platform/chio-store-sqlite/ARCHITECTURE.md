# chio-store-sqlite architecture

## Responsibility and boundary

This crate owns SQLite implementations of Chio store contracts and local
operator queries. `SqliteReceiptStore` implements `ReceiptStore` and
`IndexedSecurityEvidenceStore`; `SqliteBudgetStore`, `SqliteApprovalStore`,
`SqliteRevocationStore`, and `SqliteExecutionNonceStore` implement the
corresponding kernel traits. `SqliteCapabilityAuthority` implements
`CapabilityAuthority`. `SqliteMemoryProvenanceStore` implements
`MemoryProvenanceStore`, and `SqliteIouEnvelopeStore` implements
`chio_credit::IouEnvelopeStore`.

`SqliteSecurityStateStore` implements security ports including `FlowStateStore`
and `DeclassificationEvidenceCommitStore`. The joint
`SqliteAdmissionOperationStore` implements the kernel's admission-operation
contract and receipt projections. Obtain it from a serving
`SqliteAuthorityStore`; its connection and owner are shared with that store.
The feature-gated standalone security admission store has a separate type and
implementation. Applications select the backend and supply authenticated
identities, clocks, read contexts, and signed artifacts.

## Structure

`receipt_store.rs` owns the receipt writer actor and health state.
`receipt_store/bootstrap/open.rs` initializes schema and connection pools;
`receipt_store/support` validates receipt readback, checkpoints, and claim-log
projections. `receipt_query`, `receipt_query_snapshot`, and `evidence_export`
handle paginated reads, retained snapshots, and proof-bearing export.
`receipt_store/reports` contains operator report families.

`budget_store/store` opens the standalone connection and performs invocation
increments. Other budget modules handle composite holds, replication,
snapshots, and reconciliation. `approval_store`, `revocation_store`, and
`execution_nonce_store` own their respective tables and mutation paths.
`schema_version` implements shared application-ID and keyed revision checks.

`serving_owner` provisions the joint authority database, owns process fencing,
and verifies the global commit chain and rollback anchor.
`admission_operation_store` retains operations, participant history, recovery
leases, and terminal projections. `authority/custody` handles signing-seed file
custody. `security_state` contains flow, declassification, response, scheduler,
and source-retirement logic. Encrypted blobs, provenance, settlement, finding
markets, FROST state, and fiscal state have dedicated modules.

## Construction and migrations

`check_schema_version` inspects `PRAGMA application_id` and store-specific
anchor tables. A database with application ID zero is stamped as Chio only
when it has no user tables; a populated one is refused as foreign. A stamped
populated file must still carry an accepted anchor. `check_current_schema` adds
the single-schema contract: any recorded revision other than the current one is
refused. Revisions live in
`chio_store_schema_versions`, keyed by store, so co-located stores have
independent revisions. The helper validates provenance and returns a revision;
the constructor owns migration and the later `stamp_schema_version` call.

Receipt creation performs schema work in an immediate transaction and stamps
the revision before commit. Its `open_existing` path requires the current
schema and uses read/write flags without creation. It still configures
connection pragmas and transparency guards. Approval co-location explicitly
accepts the receipt anchor; ordinary approval opens use their own anchor set.
These checks apply to the constructors that invoke them. Security-state
migrations and joint serving-owner initialization have their own gates.

`SqliteSecurityStateStore::open` accepts a plain filesystem path. On Unix it
opens and binds an unaliased main file before migration, initializes encrypted
blob tables, and retains the identity for later connection checks. Its default
isolation-epoch verifier denies new evidence; callers can supply an explicit
verifier through `open_with_isolation_epoch_verifier`.

## Data and control flow

A standalone budget increment takes the connection mutex, starts an immediate
transaction, validates the grant index and retained history, reads the counter,
and records the decision and replication sequence. An allowed increment writes
the updated usage before commit. Rejected increments retain a denial event.
Supplying an event ID enables the path's exact replay checks.

Receipt opens create a reader pool of eight connections and a writer pool of
one by default. The actor seeds a verified durable head before processing
queued commands. `wait_for_writer_ready` provides a bounded readiness barrier.
Receipt appends and critical settlement projections use the writer handle;
reader queries borrow pooled connections. Every pooled receipt connection
configures and verifies WAL, FULL synchronization, foreign keys, and busy timeout.

`query_receipts` uses a retained snapshot and authenticates archive history;
`query_live_receipts` is the live-store diagnostic path. Query contracts require
an explicit `ReceiptReadContext`; remote adapters must authenticate credentials
before choosing it. Low-level local list/count helpers also exist, so adapters
must select the API that enforces their intended read boundary.

## Transactions and concurrency

Standalone budget state uses one `StoreConnection` behind a mutex. SQLite's
immediate transaction acquires the writer lock before reading the counter.
Independent connections and processes still contend through SQLite locking;
the mutex and receipt actor serialize work only within their owning instances.
Pool sizes and busy timeouts are operational choices, with contention errors
returned to callers.

Internal `SecurityStateWriteTransaction` consumes and returns ownership when
composing selected flow and declassification mutations. It requires a write
transaction, sets rollback-on-drop, and checks legacy source writability.
`ScopedMutation` borrows an owner and exposes a closed query catalog with exact
numbered parameter arity. Native queries prepend the security authority.
Domain methods cannot commit or obtain the underlying connection through this
wrapper. Legacy public methods create and commit their own transactions.

Native scoped mutation constructors require an admission-owned flow or egress
owner; an authority-scoped reader cannot construct those owners. Trusted security time
is sampled after the transaction has acquired its snapshot/lock and checked
source retirement. Exact retained replay follows its separate historical path.
These composition rules cover those security mutations, with each unrelated
store method retaining its own commit boundary.

## Trust, custody, and restart

Linux `AuthorityCustody::prepare` validates directories and database sidecars
before signing-seed writes. The immediate parent must belong to the effective
user with mode 0700; database and sidecars must be owned, regular, single-link
files with mode 0600. Retained directory handles and main-file identity checks
detect path replacement. Non-Linux signing-authority custody returns refusal.
The seed is stored in plaintext under this filesystem boundary.

`SqliteAuthorityStore::provision` and `open_serving` require Unix support,
validate database/lock identities, and retain an exclusive serving lock.
Joint admission writes verify the active owner, mutation fence, and authority
anchor inside an immediate transaction. Commit precedes external anchor sync;
an uncertain commit or anchor mismatch requires owner recovery. Reopening
validates retained state and reconciles the anchor according to that path.

`StoreConnection` distinguishes transaction-only and anchored connections.
After a poisoned mutex, it explicitly rolls back an open transaction, checks
autocommit, and invokes the configured consistency check. Any failure
permanently fences that handle until reopen. This recovery helper is used by
selected mutex-backed stores; receipt actor health uses its own lifecycle.

Finding-pool receipt opens add descriptor custody and an independent rollback
anchor on another device. Ordinary receipt opens omit that qualification.
Successful file-backed commits rely on SQLite synchronization and the backing
storage; memory stores disappear with their process. A receipt page-count cap
limits main-file growth while WAL space still needs checkpoint progress.

Security participant migration retains `Expected` and `ImportedInactive`
history. Source preview/import I/O runs outside destination locks; bounded
history and global commits are checked under the serving fence. Imported rows
require the typed hydration and operation-owned serving paths before mutation.

## Dependencies

`rusqlite` uses the workspace's bundled SQLite; `r2d2` and `r2d2_sqlite` provide
receipt and other read pools. `chio-sqlite-file-identity` inspects SQLite's main
descriptor for custody callers. `rustix`, `nix`, and standard file locks support
filesystem validation and serving exclusion. Core types supply canonical JSON,
receipt verification, keys, and hashes; kernel and security types supply traits
and fences. `chacha20poly1305` and `zeroize` support encrypted blob handling.
Credit, settlement, finding, and fiscal dependencies supply their typed records.

## Verification

`receipt_store/tests/bootstrap.rs` covers reopen persistence and main-file page
bounds; `receipt_store/tests/insert.rs` checks sequence persistence and
authorization-consumption replay. `tests/integration_smoke.rs` exercises budget
limits, revocation ordering, and budget hold/idempotency reopen behavior.
`tests/authority_custody.rs` exercises permissions, aliases, replacement, URI
refusal, and seed-write boundaries. Security open-path tests check alias and
permission handling; `security_state/deadline_tests.rs` advances the clock
after real database lock waits. `store_connection.rs` tests panic rollback,
anchor checks, and fenced recovery. Serving-owner tests exercise its provisioning
and relocation paths. Receipt-throughput and authorization benchmarks measure
populated local database workloads.

Run `cargo test -p chio-store-sqlite` for the local crate suites and
`cargo test -p chio-store-sqlite --features lineage` for lineage-enabled tests.
Use `cargo bench -p chio-store-sqlite --bench store_receipt_write_throughput`
to measure the receipt append workload on the target storage.
