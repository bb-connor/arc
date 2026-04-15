# Phase 302 Context

## Goal

Wire the shipped Lean 4 proof workspace into ARC's real CI gate so formal proof
regressions fail closed instead of relying on ad hoc local `lake build` runs.

## Constraints

- Phases 300 and 301 already made the `formal/lean4/Pact` workspace buildable
  and sorry-free. Phase 302 should gate that exact bounded proof surface rather
  than widening the formalization claims.
- The main CI gate currently lives in `.github/workflows/ci.yml` under the
  `check` job and runs `./scripts/ci-workspace.sh` plus SDK parity checks.
- `scripts/qualify-release.sh` currently runs the workspace, dashboard, SDK,
  conformance, trust-cluster, and coverage lanes, but it does not execute any
  Lean build or `sorry` regression check.

## Findings

- `.github/workflows/ci.yml` has no Lean or elan setup step and no formal-proof
  lane today.
- `scripts/ci-workspace.sh` is the repo-local gate used by the CI workflow for
  formatting, clippy, build, and test checks, so phase 302 should reuse that
  same gate instead of inventing a second independent CI script.
- The Lean workspace is rooted at `formal/lean4/Pact`, with `lean-toolchain`
  pinned and the default build target now flowing through `Arc.lean`.
- A tree-wide `rg -n "sorry"` would also scan generated `.lake` content, so the
  regression check should stay focused on the shipped source modules:
  `formal/lean4/Pact/Arc`, `formal/lean4/Pact/Pact`, `Arc.lean`, and
  `Pact.lean`.

## Implementation Direction

- Add one shared repo script that:
  - checks `lake` is available
  - runs `cd formal/lean4/Pact && lake build`
  - fails if any literal `sorry` appears in the shipped Lean source modules
- Call that script from `scripts/ci-workspace.sh` so the formal lane is part of
  the same CI gate as the Rust workspace checks.
- Add Lean toolchain installation to `.github/workflows/ci.yml` before the
  workspace CI lane so hosted CI can execute the formal check.
- Call the same shared script from `scripts/qualify-release.sh` so release
  qualification observes the identical proof gate instead of a parallel
  approximation.
