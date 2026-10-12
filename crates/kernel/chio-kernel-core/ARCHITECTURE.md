# chio-kernel-core architecture

## Responsibility and boundary

This crate owns portable computation for capability admission, scope matching,
synchronous guard evaluation, receipt signing, and portable passport verification.
`EvaluateInput` borrows requests, tokens, trusted keys, a clock, and guards.
`EvaluationVerdict` contains the verdict, optional reason, matched grant index,
and optional verified capability snapshot. A snapshot can survive a later denial;
callers must inspect the verdict before exercising authority.

Host orchestration owns transport, storage, asynchronous authorization, replay
state, and invocation mutation. `evaluate` returns a value directly, rather than
an `Ok` or `Err` wrapper. The core emits Allow or Deny; PendingApproval belongs
to the native shell.

## Structure

- `capability_verify` and its `lineage` module verify tokens and chain bindings.
- `evaluate` sequences admission, subject binding, scope, and guards.
- `scope`, `guard`, and `normalized` define matching, requests, and projections.
- `receipts` implements content-bound and upstream-trusted relay signing.
- `passport_verify` verifies the portable passport envelope.
- `budget_split` and `budget_split/registry` check delegated budget shares.
- `accounting` exposes checked counters and monetary balances.
- `clock` reexports typed, fallible clock interfaces; `rng` defines entropy input.
- `formal_core` and internal `formal_aeneas` hold shared proof-facing predicates.
- `revocation_view` and `fuzz` are feature-gated modules.

## Data and control flow

`evaluate` selects an allow-classical crypto floor and a no-op budget registry.
Configured entry points accept stronger floors, negotiation evidence, a root
capability or trust-root resolver, and a registry. Verification precedes request
subject matching; matching precedes ordered guards. Guard errors deny access.
The registry-aware path can reject delegated sibling-share oversubscription.
The host must retain authoritative registry state when coordinating calls.

`sign_receipt` hashes the supplied byte preimage and compares `content_hash`
before relay signing validates the key and signs the receipt body.
`sign_receipt_with_handle` consumes a move-only handle. Relay signing alone
accepts the caller's content hash, making upstream body integrity a caller duty.

## Trust and invariants

Portable evaluation refuses authenticated security bindings before guards and
budget admission because it lacks the authoritative security context. The full
portable evaluation path refuses aggregate invocation and cumulative approval
requirements. Offline capability verification is a distinct inspection surface;
its success cannot substitute for stateful host admission.

Passport verification decodes signed JSON with duplicate-aware parsing and
checks schema, subject, issuer trust, signature, and a fallible clock reading.
`ExposureUnits` and `InvocationCount` use checked arithmetic; storage adapters
must additionally enforce their representable ranges. `RevocationView` supplies
snapshot installation/read helpers, while callers own signature authentication
and freshness policy. Pure evaluation performs no revocation store lookup.

Proof-facing predicates describe bounded computation and projections. Their
presence does not prove tool isolation, persistence, cryptographic backend
correctness, or operating-system enforcement.

## Dependencies

`chio-core-types` supplies canonical artifacts and cryptographic primitives.
`chio-security-types` supplies the shared security clock. Serde and serde_json
supply allocation-compatible wire handling. Optional arc-swap enables atomic
revocation snapshots; arbitrary and dudect-bencher support fuzzing and timing
experiments. Default features enable hosted support despite the `no_std` source.

## Verification

`portable_build` exercises evaluation and receipt APIs; `security_binding` checks
portable refusal of host-bound authority; `signed_lineage` checks chain binding.
`property_evaluate`, scope/normalized property tests, and `mutation_boundaries`
exercise verdict and projection behavior. Accounting and registry modules have
unit tests. Feature-gated Kani harnesses and dudect binaries have separate runners.

```bash
cargo test -p chio-kernel-core
./scripts/check-portable-kernel.sh
```

The script installs `wasm32-unknown-unknown` and builds host and wasm without
default features. It establishes those build boundaries when actually run.
