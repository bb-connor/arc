# Phase 300 Context

## Goal

Complete the bounded capability-proof lane in Lean 4 so attenuation
monotonicity, delegation-chain integrity, and a non-negative budget invariant
are represented by real theorems with no literal `sorry`, and the Lean build is
actually runnable.

## Constraints

- Phase 299 proved the literal `sorry` surface is small, but it also exposed a
  separate build-wiring blocker: `lake build` currently fails because the
  package expects `Arc.lean` while the tree is rooted in `Pact.lean`.
- The roadmap asks for three proof outcomes, but the current proof tree only
  partially matches that:
  - one literal `sorry` in `list_isSubsetOf_trans`
  - one delegation theorem stub that currently returns `True`
  - no explicit budget non-negative theorem in the shipped tree
- Phase 300 therefore has to do more than delete one placeholder; it must
  repair the proof workspace and tighten the capability-proof surface to match
  the roadmap requirement.

## Findings

- `formal/lean4/Pact/Pact/Proofs/Monotonicity.lean:36` contains the only literal
  `sorry`, and it belongs to the transitivity helper needed for monotonicity.
- `delegation_chain_monotone` is not a literal placeholder, but its current
  statement returns `True`, so it does not yet satisfy the roadmap's delegation
  integrity requirement.
- The current tree contains supporting capability monotonicity lemmas in
  `Arc.Spec.Properties`, but they are not enough on their own to satisfy all of
  phase 300.
- `lakefile.lean` declares `lean_lib Arc`, yet there is no `Arc.lean` and no
  `Arc/` module tree. The current module/import layout must be repaired before
  proof success can be verified with `lake build`.

## Implementation Direction

- Repair the Lean package/module layout with the smallest honest change that
  makes `lake build` resolve the `Arc.*` imports.
- Replace the literal `sorry` in `list_isSubsetOf_trans` with a real equality
  bridge under `LawfulBEq`.
- Replace or tighten the current delegation theorem stub so it proves a real
  attenuation-chain property instead of returning `True`.
- Add an explicit budget non-negative theorem over the bounded capability model
  so the roadmap requirement is represented by a theorem, not an assumption.
