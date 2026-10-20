# chio-kernel

`chio-kernel` mediates tool calls in a native Chio host. `ChioKernel` validates
capabilities, selects grants, runs guards, manages admission and budget custody,
dispatches registered connections, and signs and records decisions. Portable
verification primitives come from `chio-kernel-core`; hosts supply connections,
trusted authority configuration, guards, and durable storage.

A DPoP-required grant needs the signed `chio.dpop_proof.v1` authority binding and
an independently configured, activated durable replay authority. Install that
authority with `ChioKernel::set_operation_owned_dpop_authority`; proof construction
can read the selected descriptor through `operation_owned_dpop_authority`.
`verify_dpop_proof_stateless` requires the expected authority explicitly and
returns cryptographic evidence. Dispatch separately acquires its exact durable
replay claim. Installing a volatile replay source enables source retirement only.

## Usage

This offline example constructs the primary kernel API with strict persistence
settings. It registers no tools and performs no dispatch or external I/O.
Construction alone does not install durable receipt or revocation stores.

```rust
use chio_core::crypto::Keypair;
use chio_kernel::{ChioKernel, HotPathDeadlineConfig, KernelConfig, MemoryBudgetConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let kernel = ChioKernel::try_new(KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: Vec::new(),
        max_delegation_depth: 5,
        policy_hash: "0".repeat(64),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: 300,
        max_stream_total_bytes: 256 * 1024 * 1024,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: false,
        allow_ephemeral_revocation_store: false,
        checkpoint_batch_size: 100,
        retention_config: None,
        memory_budget: MemoryBudgetConfig::default(),
        deadlines: HotPathDeadlineConfig::default(),
    })?;
    assert_eq!(kernel.guard_count(), 0);
    assert!(!kernel.is_emergency_stopped());
    Ok(())
}
```

Before serving, install compatible stores, configure authority trust, add guards
with `add_guard`, and register `ToolServerConnection` implementations with
`register_tool_server`. `evaluate_tool_call` is the async mediation entrypoint;
`evaluate_tool_call_blocking` provides a synchronous wrapper. Inspect both the
returned verdict and `KernelError`. Hosts own transport isolation and connector
side effects.

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Yes | Enables `delegation`. |
| `delegation` | Yes | Enables core delegation types and consultation of an installed recursive revocation view. |
| `finding-market` | No | Compiles finding purchase/recovery enforcement, pool ledger, and swarm authority dependency. |
| `admission-test-support` | No | Exposes admission qualification checkpoints, including capture-only native checkpoints, and the switch that lets test fixtures dispatch financial calls without durable admission. |
| `pq` | No | Enables core PQ support and the boot-gated hybrid signing configuration. |
| `otel` | No | Adds semantic-convention constants for GenAI tool-call telemetry. |
| `dhat-heap` | No | Enables the heap-profiling dispatch benchmark target. |
| `tokio-console-smoke` | No | Enables Tokio tracing for the console smoke test. |

## Guarantees

- `try_new` validates `HotPathDeadlineConfig`; receipt append budgets also have
  a finite floor when callers use the infallible constructor.
- `verify_capability_full_pre_admit` and `validate_delegation_admission` enforce
  the verifier and delegation checks used by tool mediation. Grant selection,
  subject binding, revocation and credential checks precede connector dispatch.
- `sign_receipt_body_with_backend` delegates to the portable signer, which
  recomputes the content hash from the supplied preimage before signing.
- Receipt readiness gates deny before dispatch when required storage is absent
  or serving-closed. A signed denial may remain local when storage is closed;
  storage errors can return `KernelError` without a completed response.
- `set_settlement_observer_runtime` requires paired durable outcome storage.
  Receipt-store validation requires atomic pending-observation projection,
  bounded append support, and matching store identity.

## Status

The manifest sets `publish = false`. Native host mediation, durable admission,
caller-delivery contracts, and settlement observer integration are implemented
surfaces with configuration-specific tests. Ephemeral receipt/revocation flags
and unsafe ephemeral financial dispatch are development options.

Metered billing validates quotes and budget inputs; verified-outcome pricing
always denies with `verified outcome pricing is not activated`. No metering
engine is installed by construction. Settlement hooks require explicit host
installation and compatible storage. Native flow preparation and its test
capture checkpoint do not activate native serving; that checkpoint stops before
connector execution. Test results apply to their exercised configurations.

## Related

- [Architecture](ARCHITECTURE.md)
- [Capability verification](../../../spec/PROTOCOL.md#53-verification-rules)
- [Receipt contract](../../../spec/PROTOCOL.md#6-receipt-contract)
- [Portable kernel core](../chio-kernel-core/README.md)
- [SQLite storage](../../platform/chio-store-sqlite/README.md)
- [License](../../../LICENSE)
