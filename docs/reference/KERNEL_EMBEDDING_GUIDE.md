# Kernel Embedding Guide

This guide covers the `chio-kernel` surfaces a host uses when it builds a
`ChioKernel` directly: the evaluation entrypoints, settlement runtime
installation, and delegated revocation.

## Evaluation entrypoints

The kernel evaluates a tool call through one pipeline: capability validation,
guards, dispatch, and receipt signing run as a single durable lifecycle. There
is no phase-level dispatch entrypoint.

From an async context, call the async entrypoint:

```rust
let response = kernel.evaluate_tool_call(&request).await?;
```

Callers that attach route evidence or other receipt metadata use the
metadata-preserving variant:

```rust
let response = kernel
    .evaluate_tool_call_with_metadata(&request, Some(route_metadata))
    .await?;
```

Synchronous host APIs that cannot enter an async context use the blocking
entrypoints:

```rust
let response = kernel.evaluate_tool_call_blocking(&request)?;
let response = kernel.evaluate_tool_call_blocking_with_metadata(&request, Some(route_metadata))?;
```

Inside a current-thread Tokio runtime the blocking bridge returns a typed
sync-bridge incompatibility error before any dispatch side effect.

## Settlement runtime installation

`ChioKernel::set_settlement_observer_runtime` takes the settlement hook, its
durable outcome store, a retry policy, and explicit receipt-signer trust for
persisted drain claims. It returns
`Result<(), KernelError>`:

```rust
let drain_trust = chio_kernel::SettlementDrainTrust::new(trusted_receipt_keys)?;
kernel.set_settlement_observer_runtime(hook, outcome_store, retry_policy, drain_trust)?;
```

The trusted runtime supplies the receipt keys; never derive this set from an
untrusted receipt or an unauthenticated history. `SettlementDrainTrust::new`
requires one to 64 distinct full public keys, including any historical signers
that may have pending work. Empty or duplicate sets are refused. There is no
default set or implicit insertion of the current key. For a runtime that trusts
only its current key, pass `SettlementDrainTrust::from(kernel.public_key())`
explicitly. Reinstallation replaces the set. Fresh observations still trust
only the current kernel key.

The drain loads receipts in batches of at most 256, checks exact response length
and each claimed receipt ID and timestamp, and retains per-claim completion CAS.
A batch error falls back to point reads so a failed row does not prevent healthy
claims from completing. Signature verification remains mandatory. A store that
implements optimized batch reads can share integrity verification within one
immutable snapshot; the default trait implementation still uses point reads.

Propagate the error or fail startup on it. A discarded error leaves the kernel
dispatching charges with settlement uninstalled.

### Settlement ledger

A host that configures a payment adapter installs the kernel settlement ledger
and refuses to start when the install fails:

```rust
let drain_trust = chio_kernel::SettlementDrainTrust::new(trusted_receipt_keys)?;
kernel.install_settlement_ledger(outcome_store, retry_policy, drain_trust)?;
```

`install_settlement_ledger` builds `KernelSettlementLedgerHook` over the
configured receipt store and installs it through
`set_settlement_observer_runtime`. The receipt store must also return `true`
from `supports_settlement_reconciliation`; otherwise the install fails with
`UnsupportedSettlementLedger`. The hook records one `reconciled`
`settlement_reconciliations` row for each charge whose receipt records
`settled`, dead-letters a charge whose receipt records any other status, and
keeps a retained payment retryable until the retry policy dead-letters it. The
reconciliation row records the signed receipt's historical settlement status; it
does not establish rail finality. The hook never mutates receipt rows or bytes.

The host drains due attempts from its maintenance tick:

```rust
let report = kernel.drain_settlement_attempts(limit)?;
```

The drain claims due `settle_attempts` rows, rebuilds each observation from the
stored receipt, and completes it through the claimed-outcome CAS, so a
`Retryable` attempt re-runs once its retry deadline passes. A claim or
completion persistence failure returns `KernelError::SettlementDrain` and leaves
the claimed rows leased until their lease lapses; a row another worker reclaimed
after this lease lapsed counts as a lost lease, not a failure. A receipt committed
through durable admission is seeded without an inline claim, so the drain is
the first hook invocation for it. `chio api protect`
installs the ledger whenever a payment adapter is configured and drains on its
admission maintenance tick.

### Required receipt-store capabilities

The receipt store paired with a settlement runtime implements three
`ReceiptStore` methods:

| Method | Required value |
|--------|----------------|
| `settlement_store_binding` | `Some(binding)` matching the outcome store's binding |
| `atomic_receipt_projection` | `AtomicReceiptProjection::SettlementObservationV1` |
| `supports_atomic_receipt_projection_with_timeout` | `true` |

The trait defaults are `None`, `Unsupported` and `false`, so a store that does
not opt in cannot install settlement. Any store can opt in by implementing the
three methods. The timeout capability keeps the receipt writer wait bounded by
the configured append deadline. There is no non-atomic settlement mode.

### Configuration order

The receipt store and the settlement runtime may be configured in either order.
Both setters validate symmetrically, and attaching an incompatible store fails
without replacing the store already installed.

### Failure modes

Installation failures surface as `KernelError::SettlementConfiguration`:

| `SettlementRuntimeConfigError` | Cause |
|-------|-------|
| `InvalidRetryPolicy` | the retry policy is rejected |
| `MissingReceiptStore` | no receipt store is configured |
| `UnsupportedAtomicProjection` | store lacks `SettlementObservationV1` or the timeout capability |
| `MissingStoreBinding` | store returns `None` from `settlement_store_binding` |
| `StoreBindingMismatch` | receipt store and outcome store name different backends |
| `ReceiptStoreReplacement` | the receipt store is replaced while a settlement runtime is installed |
| `UnsupportedSettlementLedger` | the receipt store cannot record settlement reconciliations for the ledger |

## Delegated revocation

The `delegation` feature is on in the `chio-kernel` default feature set and
enables `chio-core-types/delegation` (`chio_core_types::delegate`,
`DelegationReceipt`, `ScopeAttenuation`). `chio-core-types` keeps its own
`delegation` feature off by default, so direct consumers of the type crate opt
in explicitly:

```toml
chio-core-types = { workspace = true, features = ["delegation"] }
```

The `RevocationStore` lookup runs on every dispatch. When a host installs a
`chio_kernel_core::RevocationView`, the kernel also checks every link of the
delegation chain and the leaf capability against the installed snapshot and
denies with `KernelError::DelegationChainRevoked` or
`KernelError::CapabilityRevoked`:

```rust
let view = std::sync::Arc::new(RevocationView::new());
kernel.set_revocation_view(view.clone());
```

Federation gossip converts each signed epoch root into a `RevocationSnapshot`
and installs it with `view.install_if_newer(snapshot)`. The view is monotone: a
snapshot whose epoch does not advance the current one is rejected.

Mint child capabilities with `chio_core_types::delegate(...)`, which enforces
scope subset, expiry monotonicity and budget monotonicity at mint time.

### Code and tests

- Kernel consultation: `crates/kernel/chio-kernel/src/kernel/delegation.rs`
  (`no_view_installed_returns_ok` covers the store-only path)
- View cache: `crates/kernel/chio-kernel-core/src/revocation_view.rs`
- Propagation acceptance: `crates/trust/chio-revocation-oracle/tests/swarm_revocation_e2e.rs`
- Receipt-chain proof: `crates/trust/chio-revocation-oracle/tests/receipt_chain_proof.rs`
