# chio-store-sqlite

SQLite persistence for Chio receipts, capability budgets, approvals,
revocations, replay reservations, signing authority, security state, and
economic records. Kernel and security-port traits define the contracts;
this crate implements database validation, transactions, queries, and recovery.

## Usage

This example consumes a local invocation allowance and checks that its limit
survives reopening. It creates only a temporary database.

```rust
use chio_kernel::budget_store::{BudgetAuthorizeHoldDecision, BudgetAuthorizeHoldRequest};
use chio_kernel::BudgetStore;
use chio_store_sqlite::SqliteBudgetStore;

fn invocation(hold_id: &str) -> BudgetAuthorizeHoldRequest {
    BudgetAuthorizeHoldRequest {
        capability_id: "local-capability".to_string(),
        grant_index: 0,
        max_invocations: Some(1),
        invocation_quotas: Vec::new(),
        cumulative_approval: None,
        admission_binding: None,
        requested_exposure_units: 0,
        max_cost_per_invocation: None,
        max_total_cost_units: None,
        hold_id: hold_id.to_string(),
        event_id: format!("{hold_id}:authorize"),
        authority: None,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("budget.sqlite3");
    let store = SqliteBudgetStore::open(&path)?;
    assert!(matches!(
        store.authorize_budget_hold(invocation("hold-1"))?,
        BudgetAuthorizeHoldDecision::Authorized(_)
    ));
    assert!(matches!(
        store.authorize_budget_hold(invocation("hold-2"))?,
        BudgetAuthorizeHoldDecision::Denied(_)
    ));
    drop(store);

    let reopened = SqliteBudgetStore::open(&path)?;
    assert!(matches!(
        reopened.authorize_budget_hold(invocation("hold-3"))?,
        BudgetAuthorizeHoldDecision::Denied(_)
    ));
    Ok(())
}
```

The example uses the crate's `tempfile` development dependency. The caller
supplies the capability identity, grant index, and limit after authorization.

## Constructors and custody

| Entry point | Scope and caller duties |
| --- | --- |
| `SqliteReceiptStore::open` | Creates parents and runs receipt migrations; default pools have eight readers and one writer connection. Protect the database and its sidecars. |
| `SqliteReceiptStore::open_existing` | Requires existing current receipt schema; opens read/write and can configure pragmas and integrity guards. |
| `SqliteBudgetStore::open` | Opens standalone budget state on one mutex-protected connection. A provisioned serving-authority file requires its joint owner. |
| `SqliteApprovalStore::open_colocated_with_receipt_store` | Adopts a receipt-anchored file; open the receipt store first. Approval operations retain their own transaction boundaries. |
| `SqliteAuthorityStore::provision` / `open_serving` | Provisions and opens joint authority state with file identity, an exclusive serving lock, epochs, and a rollback anchor. Requires Unix and a secure lock root. |
| `SqliteCapabilityAuthority::open` | Establishes Linux file custody before storing the plaintext signing seed. Requires a private owned parent and private single-link database/sidecars. |
| `SqliteSecurityStateStore::open` | Rejects empty, memory, URI, query, and fragment paths; Unix opens bind an unaliased main-file identity before migrations. Isolation-epoch evidence defaults to refusal. |

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

- `check_schema_version` rejects foreign application IDs, mismatched store
  anchors, and newer keyed schema revisions. Each participating constructor
  selects its own anchor tables; receipt/approval co-location is explicit.
- Receipt connection initialization verifies WAL, FULL synchronization,
  foreign keys, and a busy timeout of at least five seconds on every pooled
  connection. `wait_for_writer_ready` waits for the writer's verified seed.
- Budget hold authorization, capture, release, reversal, and settlement each
  check and update usage, the hold, and its mutation event inside one
  immediate transaction.
- Internal `SecurityStateWriteTransaction` and `ScopedMutation` compose
  selected flow and declassification mutations inside one owned transaction;
  failed mutations drop that owner and roll back its uncommitted work.
  Public legacy methods such as `FlowStateStore::join` commit independently.
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
