# chio-swarm-authority architecture

## Responsibility and boundary

The crate owns bounded verification of recursive swarm authority artifacts.
Its public types describe graphs, budgets, continuations, witness chains,
routes, revocation epochs, joins, terminal receipts, and verification reports.
Signing and minting helpers construct evidence using caller-owned issuer keys.
Runtime dispatch and single-use replay custody belong to kernel/runtime integration.
The verifier receives pinned issuer keys and a caller-selected evaluation time.
It performs no filesystem or network operations.

## Structure

- `types.rs` defines strict serialized artifact shapes and schema constants.
- `error.rs` defines rejection and canonicalization errors.
- `verifier.rs` coordinates verification, signing, minting, and transitions.
- `verifier/graph.rs` checks graph topology, depth, fan-out, and freshness.
- `verifier/witness.rs` checks delegation hop chains and issuer identities.
- `verifier/budget_accounting.rs` checks allocation arithmetic.
- `verifier/util.rs` defines canonical signature bodies and shared validators.
- Public `finding_pool.rs` authenticates cognition-market pool allocations.

## Data and control flow

`verify_swarm_authority_for_admission` selects admission verification.
`verify_swarm_authority_bundle` selects complete verification.
Both call `verify_bundle`, which requires trusted keys and validates the task graph.
It verifies the graph signature and requires signed delegation evidence.
It indexes graph tasks and validates route plans and join receipts.
It checks budget allocations and the signed revocation epoch.
Complete verification requires terminal evidence and all graph joins.
Supplying terminal receipts during admission also selects complete result checks.
Continuation tokens then bind graph, route, allocation, epoch, and graph hop.
Witness chain validation checks the signed delegation structure.
A successful report lists only claims supported by supplied evidence.
Fan-in admission still requires the selected join receipt.

## Trust and invariants

Graph validation requires one root, unique task identifiers, an acyclic structure,
consistent edges, checked depth arithmetic, and explicit signed depth/fan-out limits.
Global task, edge, and join ceilings bound the accepted graph profile.
Graph and evidence expiry are checked against `now_unix_ms`.
Issuer identities must correspond to pinned witness keys.
Signing helpers reject a key that differs from the artifact issuer.
Canonical signature bodies and SHA-256 digests bind structured evidence.
Root-only evidence without continuation tokens or witness chains is rejected.
`validate_swarm_budget_pool_accounting` checks allocation states and rollups.
The budget pool is an unsigned planning object.
`finding_pool` signs a companion binding purchaser, currency, amount, and pool digest.
Its digest projection uses decimal strings for integer fields and preserves allocation order.
The allocation carries no debit state; a qualifying ledger integration must perform atomic debit.
Replay protection for single-use continuations requires store reservation at admission.

## Dependencies

`chio-core-types` provides Ed25519 keys, canonical serialization, and hashing.
Serde defines strict artifact decoding; `thiserror` provides typed failures.
Development dependencies include `proptest` and `chio-test-support` for generated
malformed cases and deterministic credentials.
The package has no optional features or service clients.

## Verification

`tests/swarm_authority_stage0.rs` checks signed bundle verification and mutations.
Its `graph_bounds.rs` cases exercise structural ceilings and depth arithmetic.
`live_admission.rs` checks admission without future joins or terminal results,
validation of supplied results, and required fan-in evidence.
Run `cargo test -p chio-swarm-authority` from the workspace root.
These tests cover evidence validation and arithmetic.
Actual dispatch binding and durable replay are exercised in runtime-core integration tests.
