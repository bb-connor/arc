---
phase: 318
title: Structured Errors and Production Qualification
created: 2026-04-14
status: in_progress
---

# Phase 318 Context

## Goal

Errors should guide developers to fixes, and the milestone should end with a
single qualification bundle that states what is production-ready, what the
measured quality bars currently are, and which gaps still remain in `v2.83`.

## Current Codebase State

- `crates/arc-cli/src/cli/types.rs` exposes a global `--json` boolean, but no
  `--format json` enum/flag pair yet.
- `crates/arc-cli/src/cli/dispatch.rs` currently emits only
  `{"error":"..."}` on JSON failures and `error: ...` on human failures, so
  the terminal path drops error code, structured context, and suggested fix.
- `crates/arc-control-plane/src/lib.rs` defines `CliError` as a plain
  `thiserror` enum without structured metadata/report helpers.
- `crates/arc-kernel/src/kernel/mod.rs` defines `KernelError` as a plain
  `thiserror` enum without a serializable error-report surface.
- Most CLI subcommands already accept a `json_output: bool`, so phase `318`
  can preserve existing command handlers and add the new format selection at
  the top-level CLI boundary.
- Phase `316` is verified `gaps_found` because the latest full-workspace
  coverage run is `72.52%`, and phase `317` is also `gaps_found`; the
  qualification bundle must surface those measured gaps instead of hiding them.

## Constraints

- Keep all local changes confined to `v2.83`; another agent is already working
  on the `v3.x.x` lane in this repository.
- Preserve backward compatibility for callers already using `--json`.
- Keep the first implementation slice narrow enough to verify with targeted
  unit tests and crate-level checks before expanding into the final
  qualification bundle.

## Likely Execution Shape

1. Add a shared structured error report type plus `report()` helpers for
   `KernelError` and `CliError`.
2. Add `--format json` at the CLI layer, treat `--json` as a compatibility
   alias, and route terminal error rendering through the new report surface.
3. Build the qualification bundle from current test, coverage, conformance,
   benchmark, and known-gap data already present in the repo and recent phase
   artifacts.
