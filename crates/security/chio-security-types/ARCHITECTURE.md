# chio-security-types architecture

## Responsibility and boundary

This crate owns portable active-defense records and the contracts connecting
detectors, flow authorities, response executors, schedulers, and state stores.
The public surface includes `SecurityEventBody`, `CorrelatedFinding`,
`InformationLabel`, `ResponsePlan`, `ResponseSnapshot`, execution bindings,
declassification grant bodies, decoy lifecycle records, and migration bindings.
It also exports the typed identifiers and request/result records in `ports`.

The default build uses `no_std` and `alloc`. The `std` feature adds JSON and
SHA-256 dependencies, system-clock support, hashing helpers, and many service
traits. `ResponseSimulationSnapshotSource` is available without that feature.
This crate does not own connector dispatch, signing keys, or database commits.
Adapters and store implementations must enforce the port contracts at their
own trust boundary.

## Structure

| Module | Responsibility |
| --- | --- |
| `clock` | Unix milliseconds, process-local monotonic instants, strict and advancing clock fences. |
| `event` | Security event bodies, correlated findings, and detector-health evidence. |
| `flow`, `declassification` | Information labels, clearance vocabulary, and scoped grant bodies. |
| `deception` | Decoy records, encrypted envelopes, lifecycle state, and watermark observations. |
| `response`, `response_state` | Plans, compact commitments, mutation records, snapshots, and legal transitions. |
| `response_execution`, `response_dispatch` | Validated execution modes, fresh live wrapper, and typed dispatch rejections. |
| `response_simulation` | Read-only snapshot contracts and predicted response outcomes. |
| `migration` | Migration stages, transition records, minimum heads, and runtime revalidation. |
| `ports` | Bounded values plus approval, event, flow, effect, overlay, dispatch, and persistence contracts. |

`ports` separates each contract into a module and re-exports it from `ports.rs`.
Its overlay families include containment, session throttles, egress restrictions,
capability-set suspension, and issuance freezes. The private `response_domains`
module supplies domain constants re-exported through `ports`.

## Data and control flow

Identifier constructors check byte limits and canonical representation.
Collection wrappers reject excess entries, and `RecordIdSet` requires strictly
sorted, unique identifiers. Aggregate validators add relationships that those
wrappers cannot express: event timestamps, finding evidence cardinality,
response targets, effect ordinals, capability expiry, and mutation ordering.

A plan retains executable contribution bytes alongside their hashes.
`ResponsePlan::authorization_body()` projects compact effects containing each
effect ID, ordinal, kind, target, contribution hash, and observed base version.
It also retains plan identity, policy and finding commitments, time bounds,
operator capability binding, approval requirement, submitter, reason, and
execution binding. The projection omits `plan_hash` to avoid a self-referential
preimage. Canonicalization, hashing, and checking the supplied hashes belong to
the consuming authorization or execution layer.

`FreshLiveAdmission::new()` owns an immutable plan and checks live mode through
`require_live_execution()`. It does not perform full shape or authority
validation. Simulation records describe captured overlay state and predicted
apply, rollback, and expiry outcomes. Their read-only source trait exposes a
single `capture` method; a scope observation cannot acquire an issuance fence.

## Trust and invariants

The execution binding's private fields preserve schema version 1. Its decoder
rejects unsupported versions and unknown fields. Both the full plan and its
authorization body require that binding during decoding; missing and null
values fail. Changing live/dry-run mode changes the authorization body.

`ResponsePlan::validate_shape()` requires nonempty effects, consecutive ordinals,
unique effect IDs, compatible effect/target pairs, nonzero specified digests,
and checked expiry arithmetic. The operator capability must cover the plan's
expiry. Capability-set suspension or issuance freezing requires a leading
issuance freeze, and a plan may contain at most one such freeze.

`CanonicalBody::new()` enforces a 1 MiB byte ceiling. It accepts empty bytes
and does not parse JSON or establish canonical encoding. `BoundedVec` likewise
permits empty collections; aggregate validators decide when entries are
required. Public-field records can be constructed or modified independently of
their validators, so deserialization alone is insufficient for these checks.

`CorrelatedFinding::validate()` checks nonempty contributing events, equal event,
digest, and source-receipt counts, and monotonic time bounds. It does not verify
the signatures of those referenced receipts. `ResponseExecutionDispatchBinding`
validates response identity and the exact schema/fingerprint pairing; legacy
dispatch descriptor compatibility does not permit an unbound `ResponsePlan`.

## Dependencies

Serde supplies portable serialization with `alloc`. Optional `serde_json` and
`sha2` support the `std` helpers for overlay version commitments and migration
posture digests. The crate has no dependency on `chio-core` or a storage engine.
Tests use JSON Schema and JSON decoding to exercise the wire contracts.

## Verification

`tests/response.rs` exercises the transition matrix, required execution binding,
live admission rejection, mutation capacity, commitment shapes, and issuance
fence ordering. `tests/response_dispatch.rs` covers dispatch bindings, legacy
canonical descriptor vectors, and exact artifact schema/fingerprint pairing.
`tests/ports_compile.rs` compiles a fake implementing the service ports and
checks identifier, collection, byte-body, and strict wire-shape rejection.

`tests/event.rs` checks event evidence limits and finding cardinality/order.
The overlay test files check contribution/version rules for suspension, egress,
throttle, and issuance. `clock/tests.rs` exercises clock fences. The `cfg(kani)`
module supplies separate bounded model harnesses; ordinary Cargo tests do not
execute them.

Run `cargo test -p chio-security-types` for default-feature tests and
`cargo test -p chio-security-types --features std` for the gated contracts.
README doctests additionally exercise the repository response-plan fixture.
