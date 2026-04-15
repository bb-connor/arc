# Phase 301 Context

## Goal

Prove the bounded receipt-proof lane in Lean 4 so Merkle inclusion soundness,
checkpoint consistency, and receipt immutability are represented by real
theorems that build under the default `Arc` target.

## Constraints

- Phase 300 intentionally narrowed `Pact.Spec.Properties` to the capability
  theorem surface. Phase 301 must add the receipt/checkpoint proof lane
  without re-introducing the old unbuildable omnibus proof module.
- The real shipped receipt surface lives in Rust today under:
  - `crates/arc-core/src/receipt.rs`
  - `crates/arc-kernel/src/checkpoint.rs`
  - `crates/arc-core/src/merkle.rs`
- The Lean tree currently has no receipt-specific modules, so phase 301 must
  add a bounded model instead of pretending an existing proof surface already
  exists.

## Findings

- `arc-kernel/src/checkpoint.rs` builds signed checkpoint statements from a
  Merkle root and exposes `build_inclusion_proof` plus `verify_checkpoint_signature`.
- `arc-core/src/merkle.rs` implements RFC-6962-style leaf/node hashing and
  inclusion proof verification, but the phase-301 Lean proof can stay bounded
  to a symbolic Merkle model as long as the theorem surface matches the repo's
  claims.
- `arc-core/src/receipt.rs` already treats receipts as immutable signed audit
  records and ships runtime tests proving sign/verify round-trips plus tamper
  rejection.

## Implementation Direction

- Add a dedicated Lean receipt/checkpoint core model instead of expanding the
  capability-only `Pact.Spec.Properties` file.
- Model Merkle roots and signatures symbolically so the receipt theorems are
  buildable and structurally meaningful without importing a full cryptographic
  library into the Lean workspace.
- Prove:
  - a proof built from a receipt tree verifies against that tree's root
  - a checkpoint store keyed by `checkpoint_seq` cannot return two different
    roots for the same sequence
  - mutating a signed receipt body while reusing the original signature fails
    verification
- Import the receipt proof module through `Arc.lean` so `lake build` checks the
  new theorem surface by default.
