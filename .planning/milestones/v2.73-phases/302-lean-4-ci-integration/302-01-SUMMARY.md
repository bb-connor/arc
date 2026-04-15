---
phase: 302-lean-4-ci-integration
plan: 01
subsystem: formal
tags: [lean4, ci, release-qualification, proof-regression]
requires:
  - phase: 301-receipt-proof-completion
    provides: sorry-free Arc/Pact Lean workspace and default-root receipt proofs
provides:
  - shared formal-proof gate script
  - hosted CI wiring for Lean 4 build + sorry regression checks
  - release qualification inheritance of the same formal gate
affects: [formal-proof-ci, release-qualification, workspace-ci]
tech-stack:
  added: [Lean 4 CI install via elan in GitHub Actions]
  patterns: [shared gate script, fail-closed placeholder scan, CI flake hardening]
key-files:
  created:
    - scripts/check-formal-proofs.sh
    - .planning/phases/302-lean-4-ci-integration/302-CONTEXT.md
    - .planning/phases/302-lean-4-ci-integration/302-01-PLAN.md
    - .planning/phases/302-lean-4-ci-integration/302-01-SUMMARY.md
  modified:
    - .github/workflows/ci.yml
    - scripts/ci-workspace.sh
    - scripts/qualify-release.sh
    - crates/arc-cli/src/trust_control.rs
    - crates/arc-cli/src/trust_control/health.rs
    - crates/arc-cli/tests/scim_lifecycle.rs
    - crates/arc-control-plane/tests/runtime_boundaries.rs
    - docs/architecture/ARC_RUNTIME_BOUNDARIES.md
    - .planning/ROADMAP.md
    - .planning/REQUIREMENTS.md
    - .planning/STATE.md
    - .planning/PROJECT.md
    - .planning/MILESTONES.md
key-decisions:
  - "Kept the formal gate in one repo-local script so CI and release qualification cannot drift."
  - "Scoped the `sorry` regression scan to shipped Lean source modules and excluded generated `.lake` content."
  - "Treated the SCIM port race and stale runtime-boundary ceiling as CI blockers that had to be fixed before phase 302 could honestly close."
patterns-established:
  - "Future formal-proof work should extend `scripts/check-formal-proofs.sh` instead of adding ad hoc Lean invocations to workflows."
  - "Workspace-gate regressions exposed during a CI-wiring phase should be repaired in the same closeout if they block the shared script from passing."
requirements-completed: [FORMAL-08]
duration: 19 min
completed: 2026-04-13
---

# Phase 302: Lean 4 CI Integration Summary

**ARC's Lean proof tree is now a real shared gate: hosted CI installs Lean,
`ci-workspace` runs a dedicated formal-proof script, and release qualification
inherits the same build-plus-`sorry` check**

## Performance

- **Duration:** 19 min
- **Started:** 2026-04-13T15:36:41Z
- **Completed:** 2026-04-13T15:55:55Z
- **Tasks:** 3
- **Files modified:** 13

## Accomplishments

- Added [scripts/check-formal-proofs.sh](/Users/connor/Medica/backbay/standalone/arc/scripts/check-formal-proofs.sh), which:
  - fails closed when `lake` is unavailable
  - runs `cd formal/lean4/Pact && lake build`
  - fails if any literal `sorry` appears in the shipped Lean source modules
- Wired the shared gate into [scripts/ci-workspace.sh](/Users/connor/Medica/backbay/standalone/arc/scripts/ci-workspace.sh) so the formal lane sits inside the same repo-local CI script as `fmt`, `clippy`, `build`, and `test`.
- Wired hosted CI in [.github/workflows/ci.yml](/Users/connor/Medica/backbay/standalone/arc/.github/workflows/ci.yml) to install Lean 4 via `elan` before running the workspace lane.
- Kept release qualification aligned by documenting in [scripts/qualify-release.sh](/Users/connor/Medica/backbay/standalone/arc/scripts/qualify-release.sh) that it inherits the same formal-proof gate through `ci-workspace`.

## CI Blockers Closed During Verification

- Replaced two clippy-blocked quorum calculations in
  [trust_control.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/trust_control.rs)
  and
  [health.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/src/trust_control/health.rs)
  with the equivalent `div_ceil` form so the shared workspace lane stayed green.
- Hardened
  [scim_lifecycle.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-cli/tests/scim_lifecycle.rs)
  against ephemeral-port races by retrying trust-service startup when a
  reserved localhost port is reclaimed before bind.
- Updated the runtime-boundary regression guard in
  [runtime_boundaries.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-control-plane/tests/runtime_boundaries.rs)
  and
  [ARC_RUNTIME_BOUNDARIES.md](/Users/connor/Medica/backbay/standalone/arc/docs/architecture/ARC_RUNTIME_BOUNDARIES.md)
  so it now asserts the extracted federation-policy and SCIM-lifecycle
  boundaries explicitly and uses an honest post-v2.72 trust-control ceiling.

## Verification

- `/usr/bin/time -p ./scripts/check-formal-proofs.sh`
  - observed local runtime: `4.13s`
- `bash -n scripts/qualify-release.sh`
- `cargo fmt --all -- --check`
- `cargo test -p arc-cli --test scim_lifecycle -- --nocapture`
- `cargo test -p arc-control-plane --test runtime_boundaries -- --nocapture`
- `./scripts/ci-workspace.sh`
- `node /Users/connor/.codex/get-shit-done/bin/gsd-tools.cjs verify plan-structure .planning/phases/302-lean-4-ci-integration/302-01-PLAN.md`

## Next Phase Readiness

Phase `302` closes `v2.73`. All non-deferred phases in the ship-readiness
ladder are now complete locally; the only remaining ladder work is the
externally blocked `v2.71` live-chain milestone.
