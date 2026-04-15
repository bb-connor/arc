# Phase 299 Sorry Audit

## Tree Inventory

- Lean workspace root: `formal/lean4/Pact`
- Lean toolchain: `leanprover/lean4:v4.28.0-rc1`
- Total `.lean` files under the workspace: `7`
- Source/proof modules under `formal/lean4/Pact/Pact`: `5`
- Literal `sorry` count: `1`

## Placeholder Inventory

| File | Line | Theorem | Domain | Classification | Assigned Phase | Rationale |
|------|------|---------|--------|----------------|----------------|-----------|
| `formal/lean4/Pact/Pact/Proofs/Monotonicity.lean` | `36` | `list_isSubsetOf_trans` | Capability monotonicity / attenuation | `needs-lemma` | `Phase 300` | The missing step is a lawful `BEq` transitivity bridge needed to turn `x == y` and `y == z` into the witness required for `List.any_eq_true`. |

## Domain Assignment Result

- `Phase 300` (`Core Capability Proofs`): `1` placeholder
- `Phase 301` (`Receipt Proof Completion`): `0` placeholders in the shipped tree

No receipt-domain literal `sorry` placeholders currently exist in the shipped
Lean tree. The roadmap still reserves phase 301 for the intended receipt-theorem
lane, but phase 299's audited placeholder inventory does not currently assign
any literal `sorry` sites to it.

## Non-Placeholder Build Blockers

The placeholder inventory is not the only issue in the current proof workspace.
`cd formal/lean4/Pact && lake build` currently fails before proof checking
because:

- `lakefile.lean` declares `lean_lib Arc`
- `Arc.lean` does not exist
- the root import file in the tree is `Pact.lean`

This is a build-wiring blocker for later formal-verification phases, but it is
not counted as a `sorry` placeholder.

## Notes

- `formal/lean4/Pact/Pact.lean` deliberately does not import
  `Arc.Proofs.Monotonicity` while the module still contains a `sorry`.
- The audited placeholder surface is smaller than the roadmap premise implied:
  the shipped tree currently has one literal `sorry`, not a broad backlog of
  sorry-bearing proof modules.
