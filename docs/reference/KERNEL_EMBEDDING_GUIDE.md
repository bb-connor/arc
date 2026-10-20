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
durable outcome store, and a retry policy, and returns
`Result<(), KernelError>`:

```rust
kernel.set_settlement_observer_runtime(hook, outcome_store, retry_policy)?;
```

Propagate the error or fail startup on it. A discarded error leaves the kernel
dispatching charges with settlement uninstalled.

No production `SettlementHook` ships in-tree yet, and no host drains
`settle_attempts` after the inline attempt (RFC-0013 F69). A host that installs
its own hook owns that drain.

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
