# Phase 274 Context

## Goal

Add crate-owned ARC-Wall tests that exercise the real rule and decision surfaces
present in the codebase today so policy and control-path regressions are caught
before CI.

## Code Surface

- `crates/arc-wall/src/main.rs` is a thin CLI wrapper with one command family:
  `control-path export|validate`
- `crates/arc-wall/src/commands.rs` contains the actual ARC-Wall lane logic:
  bounded control profile/policy/context builders, guard outcome derivation,
  denied-access record generation, ARC evidence export, and the validation /
  decision-record pipeline
- `crates/arc-wall-core/src/control_path.rs` defines the typed contract surface
  and validation rules used by the CLI

## Existing Tests

- `cargo test -p arc-wall -- --list` shows 2 existing CLI integration tests in
  `crates/arc-wall/tests/cli.rs`
- `cargo test -p arc-wall-core -- --list` shows 4 existing contract validation
  tests in `crates/arc-wall-core/src/control_path.rs`

## Important Constraint

The roadmap language for phase 274 mentions generic rule families such as
`allow`, `deny`, `conditional`, and `scoped`, plus barrier-review decisions such
as `approve`, `reject`, and `escalate`. The current ARC-Wall product surface is
explicitly narrower:

- docs state ARC-Wall is a single bounded allowlist-based control path
- `arc-wall-core` exposes one buyer motion, one control surface, one source /
  protected-domain pair, and `ArcWallGuardDecision::{Allow,Deny}`
- `arc-wall/src/commands.rs` emits one validation decision record:
  `proceed_arc_wall_only`

Phase 274 should therefore add tests for the rule and pipeline semantics that
actually exist in the bounded lane today, not invent new product surface just to
match stale roadmap phrasing.

## Requirement Mapping

- `TEST-05`: cover the real ARC-Wall rule surfaces that exist today
  fail-closed allowlist permit/deny behavior, contract validation guards, and
  guard-outcome invariants
- `TEST-06`: cover edge and boundary conditions
  empty fields, duplicate lists, same-domain violations, fail-closed flags, and
  output-directory preconditions
- `TEST-07`: cover the current barrier-review pipeline
  denied-access record generation, ARC evidence export package assembly, and the
  fixed control-room decision record emitted by `validate`

## Execution Direction

- Expand `arc-wall-core` unit tests for contract validators and fail-closed
  boundary behavior
- Add focused unit tests in `crates/arc-wall/src/commands.rs` so private builder
  functions can be exercised directly
- Keep CLI integration work narrow: assert export / validate edge cases and the
  control-room decision propagation already implemented by the bounded lane

## Files Likely In Scope

- `crates/arc-wall-core/src/control_path.rs`
- `crates/arc-wall/src/commands.rs`
- `crates/arc-wall/tests/cli.rs`
- `docs/arc-wall/README.md`
- `docs/arc-wall/CONTROL_PATH.md`
- `docs/arc-wall/OPERATIONS.md`
