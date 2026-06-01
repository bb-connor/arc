# chio-kernel-core Architecture

## Role

`chio-kernel-core` is the portable, pure-compute kernel subset. It is a
`no_std + alloc` crate by source and is built for hosted Rust plus
`wasm32-unknown-unknown` by the portable-kernel proof. It owns verdict
evaluation, capability verification, portable scope matching, receipt signing,
portable passport verification, normalized proof-facing projections, and
feature-gated revocation snapshot reads.

The full `chio-kernel` crate owns runtime orchestration: async dispatch,
persistent receipt, budget, revocation, and DPoP stores, transport, session
state, payment adapters, and other I/O.

## Module Boundaries

- `evaluate.rs` is the pure hot path for capability, subject, scope, guard, and
  delegated-budget admission.
- `capability_verify.rs` verifies signatures, trust roots, crypto floors,
  time windows, chain binding, and sibling budget splits without I/O.
- `scope.rs` is the fail-closed portable matcher. Constraints it cannot
  evaluate locally become explicit constraint errors.
- `budget_split.rs` is the pure sibling-sum registry contract used by hosted
  and portable callers.
- `passport_verify.rs` is the minimal signed-envelope verifier for browser,
  mobile, and FFI passport projections.
- `receipts.rs` delegates pure receipt signing to the shared signing backend.
- `revocation_view.rs` is behind `revocation-view` and gives hosted readers an
  atomic read-only revocation snapshot cache.
- `normalized.rs`, `formal_core.rs`, and Kani harnesses define the proof-facing
  subset and must stay aligned with runtime semantics.

## Constraints

The crate must preserve fail-closed behavior, canonical JSON byte stability,
signed capability and receipt compatibility, guard ordering, subject binding,
delegation chain binding, sibling budget enforcement, and the portable
`no_std + alloc` build. Public API compatibility matters because
`chio-kernel`, browser, mobile, C++ FFI, and AG-UI proxy surfaces import these
types directly.

No module in this crate should reach into `std`, wall-clock globals, filesystem,
network, async runtimes, stores, or policy engines. Hosted-only code must be
feature gated.

## Current Pain Points

The hot path now has reasonable separation, but wire-boundary strictness is
uneven. Most signed Chio artifacts deny unknown fields at their serde boundary.
`PortablePassportBody` and `PortablePassportEnvelope` currently do not, even
though the verifier treats them as the signed passport boundary for portable
adapters. Unknown fields are ignored before verification and are not part of
the returned verified projection, which is a needless ambiguity at a trust
boundary.

## Planned Improvement

Tighten portable passport parsing so unknown fields in either the envelope or
body fail closed before signature verification. This keeps the portable passport
wire contract explicit, aligns it with the rest of Chio's signed-artifact
posture, and does not alter canonical bytes for valid envelopes.

Affected dependents are the mobile and C++ FFI passport helpers, which generate
the typed envelope and should continue to round-trip unchanged. No generated
code should be edited for this slice.
