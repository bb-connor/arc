# chio-store-sqlite

SQLite persistence for Chio receipts, capability budgets, approvals,
revocations, replay reservations, signing authority, security state, and
economic records. Kernel and security-port traits define the contracts;
this crate implements database validation, transactions, queries, and recovery.

## Usage

This example consumes a local invocation allowance and checks that its limit
survives reopening. It creates only a temporary database.

```rust
use chio_kernel::BudgetStore;
use chio_store_sqlite::SqliteBudgetStore;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("budget.sqlite3");
    let store = SqliteBudgetStore::open(&path)?;
    assert!(store.try_increment("local-capability", 0, Some(1))?);
    assert!(!store.try_increment("local-capability", 0, Some(1))?);
    drop(store);

    let reopened = SqliteBudgetStore::open(&path)?;
    assert!(!reopened.try_increment("local-capability", 0, Some(1))?);
    Ok(())
}
```

The example uses the crate's `tempfile` development dependency. The caller
supplies the capability identity, grant index, and limit after authorization.

## Constructors and custody

| Entry point | Scope and caller duties |
| --- | --- |
| `SqliteReceiptStore::open` | Creates parents and initializes an empty database or validates the current receipt catalog; default pools have eight readers and one writer connection. Protect the database and its sidecars. |
| `SqliteReceiptStore::open_existing` | Requires the complete current receipt catalog; opens read/write and configures connection pragmas without repairing schema or projections. |
| `SqliteBudgetStore::open` | Opens standalone budget state on one mutex-protected connection. A provisioned serving-authority file requires its joint owner. |
| `SqliteApprovalStore::open_colocated_with_receipt_store` | Opens a declared receipt/approval database created by `initialize_receipt_approval_database`. Approval operations retain their own transaction boundaries. |
| `SqliteAuthorityStore::provision` / `open_serving` | Provisions and opens joint authority state with file identity, an exclusive serving lock, epochs, and a rollback anchor. Requires Unix and a secure lock root. |
| `SqliteCapabilityAuthority::open` | Establishes Linux file custody before storing the plaintext signing seed. Requires a private owned parent and private single-link database/sidecars. |
| `SqliteSecurityStateStore::open` | Rejects empty, memory, URI, query, and fragment paths; Unix opens bind an unaliased main-file identity before schema creation or validation. Isolation-epoch evidence defaults to refusal. |

`SqliteAuthorityStore::admission_operation_store` returns the joint
`SqliteAdmissionOperationStore`. The separate
`SqliteSecurityAdmissionOperationStore` is a test-support export.
`SqliteReceiptStore::open_for_finding_pool` additionally requires a private
rollback-anchor root on a different filesystem device. Preserve that anchor
with the database's recovery procedure. Ordinary receipt opens have no
qualified durable sink identity.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Enabled | Empty feature set. |
| `pq` | Off | Enables `chio-core/pq` and `chio-kernel/pq`. |
| `lineage` | Off | Exports recursive-CTE lineage query helpers. |
| `cognition-market-test-support` | Off | Exposes helpers for seeding verified cognition-market test records. |
| `admission-test-support` | Off | Exposes fail-only admission fault controls. |
| `security-admission-test-support` | Off | Compiles and exports the standalone security admission store for tests and benchmarks. |
| `chaos-test-hooks` | Off | Enables environment-controlled receipt pause points for process fault tests. |
| `fuzz` | Off | Exports store byte-decoder fuzz entry points. |

## Guarantees

- `inspect_schema` reads application identity and exact declared v1 namespaces.
  `SchemaTransaction` creates metadata, identity and namespace stamps atomically
  from an empty catalog. Constructors validate their complete catalogs on reopen;
  missing namespaces and non-v1 revisions refuse without repair. Composite
  creators declare receipt/approval, seller, security/blob and serving layouts.
- Receipt connection initialization verifies WAL, FULL synchronization,
  foreign keys, and a busy timeout of at least five seconds on every pooled
  connection. `wait_for_writer_ready` waits for the writer's verified seed.
- `SqliteBudgetStore::try_increment_with_event_id` checks and updates its
  counter and mutation event inside one immediate transaction. Budget hold
  authorization, capture, release, and settlement have separate typed methods.
- Internal `SecurityStateWriteTransaction` and `ScopedMutation` compose
  selected flow and declassification mutations inside one owned transaction;
  failed mutations drop that owner and roll back its uncommitted work.
  Public methods such as `FlowStateStore::join` commit independently.
- Joint admission writes check the serving owner and rollback anchor inside
  their transaction, then synchronize the external anchor after commit.
  Uncertain commit outcomes require recovery through the serving owner.
- `StoreConnection` explicitly rolls back an interrupted transaction after
  mutex poisoning and verifies any configured anchor. Failed recovery fences
  that connection until reopen.

File-backed persistence depends on successful commits, the selected store's
sync configuration, and filesystem/storage behavior. In-memory constructors
provide process-local state. `SqlitePoolConfig::max_page_count` bounds the
receipt database's main file; operators must also budget WAL space and
checkpoint progress. The kernel remains responsible for capability checks,
trusted read contexts, signed input construction, and dispatch authorization.

## Status

Implemented backends include `ReceiptStore`, `BudgetStore`, `ApprovalStore`,
`RevocationStore`, `ExecutionNonceStore`, `CapabilityAuthority`,
`MemoryProvenanceStore`, and `IouEnvelopeStore`. Security ports include flow
state and declassification evidence. Admission source-import records can
retain inactive history. Serving adoption requires independently established
authority and the corresponding operation-owned mutation path. Test-support features expose
additional fixtures and faults. The listed tests cover local persistence,
custody refusal, concurrency, migration, and recovery paths.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [Receipt contract](../../../spec/PROTOCOL.md#6-receipt-contract)
- [SQLite file identity](../chio-sqlite-file-identity/README.md)
- [Kernel store contracts](../../kernel/chio-kernel/README.md)

License: [Apache-2.0](../../../LICENSE).
