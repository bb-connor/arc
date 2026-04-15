# Phase 299 Context

## Goal

Inventory and classify every remaining literal `sorry` placeholder in the
shipped Lean 4 proof tree so later proof-completion work targets the real
surface, not the broader roadmap premise.

## Constraints

- The shipped Lean workspace is bounded to `formal/lean4/Pact`; phase 299 must
  audit that actual tree instead of assuming a larger proof surface.
- The roadmap success criteria are about placeholder inventory and domain
  assignment, not about finishing proofs yet.
- The audit must stay honest about adjacent proof-workspace blockers. A broken
  `lake build` configuration is not a `sorry`, but it still matters for phases
  300-302.

## Findings

- `rg -n "sorry" --glob '*.lean' formal/lean4/Pact` currently returns exactly
  one literal `sorry` site:
  `formal/lean4/Pact/Pact/Proofs/Monotonicity.lean:36`
- The only placeholder is in the capability-monotonicity proof lane
  (`list_isSubsetOf_trans`), so the real audited placeholder surface is
  smaller than the roadmap narrative implies.
- `formal/lean4/Pact/Pact.lean` intentionally does not import the
  sorry-bearing proof module into the root import.
- `cd formal/lean4/Pact && lake build` currently fails before proof checking
  because `lakefile.lean` declares `lean_lib Arc`, but `Arc.lean` does not
  exist; the root file is `Pact.lean`.

## Implementation Direction

- Publish an audit artifact that lists the single literal `sorry`, its theorem,
  file, line, classification, rationale, and assigned completion phase.
- Record that there are no receipt-domain literal `sorry` placeholders in the
  shipped tree today, so the audited placeholder inventory is fully assigned to
  phase 300.
- Note the `lake build` root-module mismatch as an adjacent build-wiring issue
  for later formal-verification phases, but keep phase 299 scoped to the
  placeholder inventory itself.
