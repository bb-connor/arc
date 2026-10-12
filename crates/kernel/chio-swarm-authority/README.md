# chio-swarm-authority

Signed evidence verification for recursive Chio swarm delegation.
The crate checks task graphs, continuation tokens, delegation witnesses,
route plans, joins, revocation epochs, budget accounting, and terminal receipts.
The runtime hook consumes this verifier when admitting swarm-bound tool work.

## Usage

A trusted host loads an authority bundle and pins its witness issuer keys.
The live admission entrypoint accepts work before future completion evidence exists:

```rust
use chio_core_types::PublicKey;
use chio_swarm_authority::{
    verify_swarm_authority_for_admission, SwarmAuthorityBundle,
    SwarmAuthorityError, SwarmAuthorityVerifierReport,
};

fn verify_live_task(
    bundle: &SwarmAuthorityBundle,
    pinned_keys: &[PublicKey],
) -> Result<SwarmAuthorityVerifierReport, SwarmAuthorityError> {
    verify_swarm_authority_for_admission(bundle, pinned_keys)
}
```

This helper compiles with ordinary dependencies and performs no I/O.
The caller supplies the evaluation time in `bundle.now_unix_ms` and actual
trusted keys. Use `verify_swarm_authority_bundle` for complete evidence,
including all graph joins and terminal results. Neither function dispatches work.

## Guarantees

- `verify_bundle` requires pinned issuer keys and signed delegation evidence.
- `validate_task_graph` checks graph shape, depth, fan-out, bounds, and freshness.
- `validate_witness_chains` checks signed attenuation evidence across graph hops.
- `validate_swarm_budget_pool_accounting` checks allocation arithmetic.
- `verify_swarm_authority_for_admission` validates every supplied result;
  selected fan-in continuations require their join receipt.
- Signing helpers bind canonical signature bodies to the matching issuer key.

## Status

Implemented evidence verifier and budget transition helpers.
Single-use replay reservation belongs to runtime stores and kernel admission.
`finding_pool` authenticates allocation identity and canonical pool projections;
its signed allocations carry no debit state. A host must provide the qualifying
ledger integration for purchase accounting.
There are no declared Cargo features.

## Related

- [Architecture](ARCHITECTURE.md)
- [Swarm admission contract](../../../spec/PROTOCOL.md#642-swarm-authority-runtime-admission)
- [Runtime verifier wiring](../chio-runtime-core/README.md)
- [License](../../../LICENSE)
