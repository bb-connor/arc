# chio-response-model architecture

## Responsibility and boundary

The crate owns pure response-plan and evidence validation, lifecycle projection,
and dry-run simulation shared by the kernel and quarantine runtime.
`state` exports plan building, record encoding/decoding, transition candidates,
and effect candidates.
`simulation` exports evaluation and rollback over supplied model snapshots.
Callers supply all timestamps and records.
The model has no store implementations, schedulers, clocks, network clients,
or live effect ports.
A candidate is data for a caller to authorize and persist.

## Structure

`state.rs` implements plan validation and candidate lifecycle rules.
`state/error.rs` defines category errors and detailed plan/record defects.
`state/canonicalization.rs` derives request and mutation identifiers from
canonical data with domain-separated hashing.
`state/projection.rs` builds initial evidence and dispatch projections.
`simulation.rs` evaluates contribution application, rollback, and expiry.
`rejection_codes.rs` maps model errors to security rejection codes.
The crate root re-exports `CanonicalFailure` and `StateMachineError`.

## Data and control flow

`build_response_plan` checks effect count and TTL, builds a bounded affected-ID
set, validates contributions, derives effect identifiers, computes the plan
hash, and runs `validate_plan` before returning.
`decode_response_record` decodes a snapshot and reconstructs its canonical bytes.
It compares the body hash and indexed fields, then validates the snapshot.
`transition_candidate` decodes the current record and checks expected generation
before producing a replacement record and evidence identifier.
`initial_response_snapshot` validates a plan and creates generation-zero
requested evidence without admission.
Simulation validates dry-run mode and snapshot tenant, plan hash, capture time,
state versions, and issuance-freeze scope bindings.
It evaluates apply and rollback, then contribution expiry in sorted model time.

## Trust and invariants

`validate_plan` checks affected-set commitments, canonical contributions,
contribution hashes, derived effect IDs, freeze bindings, and the plan hash.
The plan hash derives from `ResponsePlan::authorization_body()` through the
shared governed-response intent hash helper.
Record decoding rejects mismatched tenant, action, generation, state, and due
indexes, preventing index metadata from silently disagreeing with the body.
Candidate generation uses checked arithmetic and stale-generation rejection.
Lifecycle helpers enforce legal transitions and effect receipt ordering.
`encode_normalized_dispatch_response_record` requires a dispatch binding and
rejects an already-authorized snapshot.
It prepares evidence for admission; it cannot grant execution authority.
`rollback_response_simulation` checks exact contribution ownership on a clone
and replaces caller state only after the whole rollback succeeds.
Alerts are represented as simulated delivery and nonreversible outcomes.

## Dependencies

`chio-security-types` owns response plans, snapshots, bounded identifiers,
contributions, and port record types.
`chio-core-types` supplies canonical JSON, SHA-256, and intent hashing.
Serde and serde_json decode and encode snapshot and contribution data.
Hex formats derived identifiers and decodes digest output.
Thiserror preserves typed categories and inner error sources.
The manifest declares no feature switches.

## Verification

Projection tests reject snapshots missing dispatch bindings and snapshots
already carrying authorization hashes.
The README example exercises malformed-body rejection without external state.
Run `cargo test -p chio-response-model` for crate-local tests.
Kernel and quarantine tests provide consumer-level coverage for admission,
execution, scheduler fencing, and durable ordering outside this crate's scope.
Simulation output is model evidence; live effects and durable commits require
verification in those owning consumers.
