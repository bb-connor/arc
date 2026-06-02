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

The hot path has two public evaluation entry points: the legacy
floor-aware path and the current full-semantics path. They differ in capability
verification, but after a capability is verified they must perform the same
subject binding, scope match, guard pipeline, and deferred budget admission.
That post-verification sequence is security-critical because ordering prevents
invalid subjects, out-of-scope calls, and guard-denied calls from consuming
delegated sibling budget.

That sequence is currently duplicated. Any future fix in one branch can drift
from the other branch and silently weaken fail-closed ordering for browser,
mobile, FFI, or hosted callers.

## Improvement In This Slice

Move the post-verification evaluation sequence behind one internal boundary
used by both public evaluation entry points. Capability verification remains
separate because the entry points intentionally accept different trust-root and
feature-negotiation inputs. Subject binding, scope matching, guard ordering,
and budget admission become one shared implementation.

No public API or wire format changes are planned. No dependent crates should
need edits unless they rely on behavior that contradicts the existing ordering.
