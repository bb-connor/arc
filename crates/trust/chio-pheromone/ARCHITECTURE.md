# chio-pheromone architecture

## Responsibility and boundary

The crate owns observation deposit types, local validation, scarcity admission
calculations, and the `PheromoneSubstrate` abstraction. The supplied
`InMemoryPheromoneSubstrate` keeps deposits, nonce state, pair counters,
scarcity counters, and passport diversity state in process-local mutexes.

`PheromoneValidationContext` supplies the caller's time, accepted reputation
epochs, admitted passports, kernel keys, subject policies, scarcity windows,
runtime policy digest/issuer roots, cost-verifier roots, and trust-floor state.
This context must originate from the verifier's local policy boundary.
Network transit, persistent storage, workflow proof resolution, and runtime
verdict changes are handled by other crates and their callers.

## Structure

| Module | Responsibility |
|--------|----------------|
| `lib` | Typed deposits, policies, cost evidence, hashes, public validators |
| `validation` | Fields, passport signatures, cost proofs, quotas, decay |
| `substrate` | Nonce reservation, local storage, queries, evaporation |

`PheromoneDepositBody` carries origin identity, subject/namespace, treaty scope,
confidence, decay parameters, nonce, and optional workflow/cost attachments.
`PheromoneConcentration` reports weighted and unweighted totals, distinct
origins, peak confidence, evaluated epoch/time, and treaty scopes.

## Data and control flow

1. `sign_deposit` signs canonical deposit material with the agent key.
2. Static validation checks field ranges, schema, subject policy, accepted
   treaties, scarcity material, and the deposit's replay-window timestamp.
3. Passport resolution binds origin kernel, passport key hash, JWK thumbprint,
   validity at deposit time, and supplied revocation state. Kernel keys cannot
   stand in for agent deposit keys.
4. Substrate admission consumes replay identity and applicable quota buckets,
   then appends the validated deposit.
5. Concentration queries filter subject and namespace, apply exponential
   half-life decay, optional evaporation floor, peer weight, and newcomer age.
6. Garbage collection removes deposits below their explicit floor or the
   default 0.01 floor while retained nonce/quota state remains in the instance.

Preflight reservations support expensive receiver-owned resolution. Callers
must release a reservation on resolution failure or commit it through
`deposit_reserved`; the trait documents that lifecycle explicitly.

## Trust and invariants

`validate_deposit_for_admission` is a stateless validator. Duplicate nonces and
rate limits are enforced when the substrate commits admission state.
The replay key combines origin kernel, passport hash, and nonce.
The in-memory implementation records seen nonces for the instance lifetime;
it does not reclaim replay custody through garbage collection.

Deposit signing omits the cost commitment from its preimage. Cost evidence has
its own signature and binds the deposit through statement commitments.
Live cost verification checks the admitted verifier root and telemetry Merkle
path, statement identity/window/unit, runtime policy, and revocation-floor
material. Workflow references receive shape validation; this crate does not
resolve a proof package behind those references.

Peer weights must be finite and within [0, 1]. Reputation epochs must appear in
the supplied known-epoch list. Concentration can aggregate many observations;
its total is a sum rather than a probability bounded by one. No concentration
query grants capability authority or changes a kernel admission verdict.

## Dependencies

`chio-core-types` supplies canonical serialization, signatures, and Merkle
proofs. `sha2`, `hex`, and `base64` derive passport and policy identifiers.
`serde` and `serde_json` encode observation evidence and policy material.
No database, transport, or kernel dependency is present.

## Verification

Run `cargo test -p chio-pheromone` from the workspace root.
`tests/pheromone_substrate.rs` covers signed deposits, passport standing,
replay/quota limits, cost proofs, scarcity windows, decay, and newcomer weights.
`tests/public_surface.rs` checks ownership of exported schema constants.
The README exercises empty-store querying and garbage collection in memory.
