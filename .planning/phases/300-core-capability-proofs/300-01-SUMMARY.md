---
phase: 300-core-capability-proofs
plan: 01
subsystem: formal
tags: [lean4, proofs, capability, build-wiring, theorem-surface]
requires:
  - phase: 299-sorry-placeholder-audit
    provides: exact literal-sorry inventory plus the Arc/Pact build-wiring blocker
provides:
  - buildable Arc/Pact Lean workspace rooted at `Arc.lean`
  - sorry-free capability proof lane for monotonicity, chain integrity, and budget non-negativity
  - narrowed capability-only spec surface for phase-300 formal claims
affects: [phase-301, phase-302, formal-proof-ci]
tech-stack:
  added: []
  patterns: [dual-root Lean library wiring, bounded proof-surface scoping, compile-first theorem hardening]
key-files:
  created:
    - formal/lean4/Pact/Arc.lean
    - formal/lean4/Pact/Arc/Core/Capability.lean
    - formal/lean4/Pact/Arc/Core/Scope.lean
    - formal/lean4/Pact/Arc/Core/Revocation.lean
    - formal/lean4/Pact/Arc/Spec/Properties.lean
    - formal/lean4/Pact/Arc/Proofs/Monotonicity.lean
    - .planning/phases/300-core-capability-proofs/300-01-SUMMARY.md
  modified:
    - formal/lean4/Pact/lakefile.lean
    - formal/lean4/Pact/Pact.lean
    - formal/lean4/Pact/Pact/Core/Capability.lean
    - formal/lean4/Pact/Pact/Core/Scope.lean
    - formal/lean4/Pact/Pact/Core/Revocation.lean
    - formal/lean4/Pact/Pact/Spec/Properties.lean
    - formal/lean4/Pact/Pact/Proofs/Monotonicity.lean
    - .planning/ROADMAP.md
    - .planning/REQUIREMENTS.md
    - .planning/STATE.md
    - .planning/PROJECT.md
    - .planning/MILESTONES.md
key-decisions:
  - "Repaired the Lean package with a dual-root `Arc`/`Pact` library declaration instead of copying the existing proof tree into a new namespace."
  - "Narrowed `Pact.Spec.Properties` to the capability-theorem surface that phase 300 actually owns so receipt/revocation proofs remain an explicit phase-301 follow-on."
  - "Imported `Arc.Proofs.Monotonicity` through the default `Arc` target so `lake build` now checks the formerly-unbuilt proof module."
patterns-established:
  - "Formal phases should shrink the active theorem surface to the milestone-owned claims before expanding it again in later proof phases."
  - "The default Lean build target must compile the theorems a milestone claims, not just the supporting types."
requirements-completed: [FORMAL-02, FORMAL-03, FORMAL-04]
duration: 35 min
completed: 2026-04-13
---

# Phase 300: Core Capability Proofs Summary

**The Lean workspace now builds through `Arc.lean`, the audited capability `sorry` is gone, and the shipped phase-300 theorem surface now contains real monotonicity, delegation-integrity, and budget-nonnegativity theorems**

## Performance

- **Duration:** 35 min
- **Started:** 2026-04-13T14:48:00Z
- **Completed:** 2026-04-13T15:22:57Z
- **Tasks:** 3
- **Files modified:** 13

## Accomplishments

- Repaired the formal package layout by adding a real `Arc.lean` root, thin
  `Arc/*` wrapper modules, and a declared `lean_lib Pact` alongside the
  existing `lean_lib Arc`, so `lake build` can now resolve both the shipped
  `Pact/*` source tree and the declared `Arc.*` imports.
- Replaced the only audited literal `sorry` in
  `Pact/Proofs/Monotonicity.lean` with a real `LawfulBEq`-based transitivity
  proof for `list_isSubsetOf_trans`.
- Replaced the old delegation-chain placeholder theorem that returned `True`
  with a real `delegation_chain_integrity` theorem over adjacent chain steps.
- Added an explicit `scope_budgets_nonnegative` theorem to the shipped
  capability-spec surface.
- Narrowed `Pact.Spec.Properties` to the phase-owned capability claims so the
  default Lean build checks theorems this milestone actually proves today
  instead of dragging in unrelated receipt/revocation debt from later phases.
- Added the missing `ReflBEq`/`LawfulBEq` derivations and a small scope/revocation
  cleanup so the now-built proof workspace compiles cleanly.

## Task Commits

No task commits were created in this workspace session.

## Files Created/Modified

- `formal/lean4/Pact/lakefile.lean` - declared both `Arc` and `Pact` Lean
  libraries so the wrapper root can import the existing proof tree honestly
- `formal/lean4/Pact/Arc.lean` and `formal/lean4/Pact/Arc/*` - default build
  root plus thin compatibility wrappers for the declared `Arc.*` module tree
- `formal/lean4/Pact/Pact.lean` - converted the old root to a legacy alias
  that imports `Arc`
- `formal/lean4/Pact/Pact/Core/Capability.lean` - added missing
  `ReflBEq`/`LawfulBEq` derivations used by the proof lane
- `formal/lean4/Pact/Pact/Core/Scope.lean` - fixed the real `List.isSubsetOf`
  namespace, simplified reflexivity proof shape, and made the scope model
  compile under the now-live build
- `formal/lean4/Pact/Pact/Core/Revocation.lean` - marked `evalToolCall`
  `noncomputable` because it depends on an axiomatized signature verifier
- `formal/lean4/Pact/Pact/Spec/Properties.lean` - reduced the shipped spec
  module to the capability theorems phase 300 actually proves
- `formal/lean4/Pact/Pact/Proofs/Monotonicity.lean` - removed the literal
  `sorry`, added the real delegation-integrity theorem, and cleaned up the
  proof helpers
- `.planning/phases/300-core-capability-proofs/300-01-PLAN.md` - finalized
  touched files and verification targets
- `.planning/phases/300-core-capability-proofs/300-01-SUMMARY.md` - phase
  completion record
- `.planning/ROADMAP.md`, `.planning/REQUIREMENTS.md`, `.planning/STATE.md`,
  `.planning/PROJECT.md`, `.planning/MILESTONES.md` - roll-forward to phase
  `301`

## Decisions Made

- Kept the real proof source under `Pact/*` and added a thin `Arc/*` build
  surface rather than performing a larger namespace migration mid-milestone.
- Treated the previously unbuilt receipt/revocation theorems as future-phase
  scope instead of forcing phase 300 to solve phase 301 problems opportunistically.
- Required `lake build` to compile `Arc.Proofs.Monotonicity` through the
  default target so the capability claims are now actually enforced by the
  build.

## Deviations from Plan

- The phase had to fix compile defects in `Pact.Core.Scope` and
  `Pact.Core.Revocation` once the proof workspace started building for real.
  This stayed within the plan's build-wiring task and was necessary to make
  phase-300 theorem claims verifiable.

## Issues Encountered

- The pre-phase-300 Lean tree had additional hidden build debt beyond the
  missing `Arc.lean` root: the `Pact` library was undeclared, several custom
  datatypes lacked the equality-law instances the proofs assume, and the large
  old `Pact.Spec.Properties` file was not buildable as a single phase-300
  surface.

## User Setup Required

None. The capability proof lane remains repo-local.

## Next Phase Readiness

Phase `301` is now the active follow-on lane. The capability theorem surface
is buildable and sorry-free, so the next work can focus on receipt proofs
instead of continued package repair.

---
*Phase: 300-core-capability-proofs*
*Completed: 2026-04-13*
