# chio-runtime architecture

## Responsibility and boundary

This crate is the public runtime admission and orchestration facade.
It owns `ChioRuntimeError`, `ChioRuntimeAdmissionInput`, store wrappers,
and `ChioRuntimeAdmissionHook` at the application boundary.
Most report and artifact types alias the runtime-core definitions.
The facade delegates verification to one implementation in `chio-runtime-core`.
Native tool dispatch and signed receipts remain kernel responsibilities.
Applications supply profiles, verifier keys, stored evidence, and host policy.

## Structure

- `lib.rs` exports artifact types, schema constants, parsers, and report functions.
- It translates runtime-core errors into the facade's owned error type.
- `stores.rs` implements facade store traits and wraps implementation backends.
- `stores/replay_source.rs` exposes qualified SQLite replay-source operations.
- `admission_hook.rs` defines the owned hook and delegates kernel hook callbacks.
- `RuntimeCoreAdmissionStoreAdapter` translates the facade trait into the core trait.
- Type aliases preserve the underlying artifact representation.

## Data and control flow

`evaluate_runtime_admission` adapts `ChioRuntimeAdmissionInput` to the core input.
The store adapter forwards evidence lookup, reservations, and trust-floor transitions.
The core returns an accepted or rejected admission report, or an error.
The facade converts errors while preserving their codes.
Store wrappers forward insertion and orchestration operations to their inner stores.
The hook retains profile and trust/policy configuration.
It forwards kernel admission and dispatch-revalidation work to the core verifier.
`with_swarm_witness_keys` supplies pinned keys for stored swarm evidence.
`with_operation_owned_runtime_replay` supplies an explicit participant binding.
JSON and SQLite wrappers expose distinct persistence and concurrency boundaries.
`LayeredRuntimeAdmissionStore` separates admission evidence from trust-floor storage.
Its constituent backends still must satisfy the operation's required contract.

## Trust and invariants

Facade wrapping preserves the core admission checks.
`accepted: false` is a valid returned report and must stop caller dispatch.
The kernel hook performs enforcement at the actual mediated tool boundary.
Stored swarm evidence must match the request, route, and pinned issuer keys.
Single-use continuation reservation and destructive lease consumption use store operations.
Trust-floor updates require atomic validation and recording.
Process-local memory stores cannot provide restart-safe custody.
JSON clones coordinate one open instance; separate opens require a serialized backend.
SQLite replay APIs require sealed source verification and activated participant binding.
Trait defaults reject unsupported sealed operation-owned replay.
A configured hook or open database alone grants no tool capability.
Canonical hashing, signature verification, and bounded parsers delegate to runtime-core.
The facade does not provision provider services when generating their health reports.

## Dependencies

`chio-runtime-core` owns the verifier and storage implementation.
`chio-kernel` supplies runtime hook and operation-owned admission contracts.
`chio-core-types` supplies schemas and cryptographic types.
`chio-swarm-authority` and `chio-weights` supply exported evidence and policy types.
Serde supports facade insertion and JSON serialization interfaces.
There are no declared optional Cargo features.

## Verification

`tests/public_surface.rs` checks the source-level schema constant ownership convention.
`tests/runtime_boundary.rs` checks runtime-owned errors, hooks, and stores.
It also checks non-consuming immediate dispatch revalidation and replay-source behavior.
`tests/reserved_caller.rs` covers authenticated reserved caller access.
Run `cargo test -p chio-runtime` from the workspace root.
Core integration tests provide the deeper evidence and storage mutation coverage.
The README sample demonstrates the primary evaluation API's empty-store denial.
These are local API and integration checks using controlled authority fixtures.
