# chio-pheromone

Local substrate for signed agent observation deposits and weighted, decaying
concentration. It defines passport admissions, scarcity policies, observation
cost evidence, workflow references, and an in-memory deposit store.

## Usage

Inspect a new local substrate with the public query interface. Deposit admission
requires a caller-supplied validation context with passport and policy pins.

```rust
use chio_pheromone::{
    DepositQuery, InMemoryPheromoneSubstrate, PheromoneSubstrate,
};

let substrate = InMemoryPheromoneSubstrate::new();
let deposits = substrate.query_deposits(&DepositQuery {
    subject_class: Some("tool.read".into()),
    treaty_id: None,
})?;
assert!(deposits.is_empty());
assert_eq!(substrate.gc_evaporated(1_000)?, 0);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Guarantees

- `validate_deposit_for_admission` validates deposit fields, timestamp window,
  subject/treaty and scarcity material, passport standing, and its signature.
  Stateful replay and quota consumption belong to substrate admission.
- `InMemoryPheromoneSubstrate::deposit` records nonce and scarcity state before
  storing an admitted deposit. Reused origin/passport/nonces reject.
- `query_concentration` checks reputation epoch and peer weights, applies
  exponential decay and newcomer discount, and reports weighted strength.
- Observation-cost validation binds the statement, telemetry inclusion proof,
  verifier root, runtime policy, and revocation floor required by local policy.

## Status

Implemented local observation substrate with process-local mutex-backed state.
Its deposits and quota history disappear when the instance is discarded.
Concentration is evidence for a verifier-owned policy; a deposit or query does
not issue capabilities or authorize tool dispatch. Workflow reference fields
are checked structurally here; receiver-owned resolution belongs to
`chio-pheromone-runtime`. The crate declares no Cargo features, requires
Rust 1.93, and is unpublished (`publish = false`).

## Related

- [Architecture](ARCHITECTURE.md)
- [Trust-control contract](../../../spec/PROTOCOL.md#9-trust-control-contract)
- [Persistent receiver](../chio-pheromone-runtime/README.md)
- [Reputation evidence](../chio-reputation/README.md)

[License](../../../LICENSE)
