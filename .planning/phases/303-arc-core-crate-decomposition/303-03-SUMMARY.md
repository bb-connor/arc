---
phase: 303-arc-core-crate-decomposition
plan: 03
subsystem: infra
tags:
  - rust
  - crates
  - arc-core
  - compilation
  - benchmarking
requires:
  - "303-01"
  - "303-02"
provides:
  - remaining direct-dependent migration onto `arc-core-types`
  - reproducible rebuild benchmark script
  - full compile and downstream test evidence for phase 303
affects:
  - phase-304
  - phase-305
  - phase-306
tech-stack:
  added: []
  patterns:
    - rename-package aliasing to preserve `arc_core` imports while changing dependency ownership
    - git-worktree benchmark comparison between pre-split and split checkpoints
    - quiet benchmark output with explicit `/usr/bin/time -p` reporting
key-files:
  created:
    - .planning/phases/303-arc-core-crate-decomposition/303-03-SUMMARY.md
  modified:
    - crates/arc-a2a-adapter/Cargo.toml
    - crates/arc-hosted-mcp/Cargo.toml
    - crates/arc-mcp-adapter/Cargo.toml
    - crates/arc-mcp-edge/Cargo.toml
    - crates/arc-mercury/Cargo.toml
    - crates/arc-mercury-core/Cargo.toml
    - crates/arc-reputation/Cargo.toml
    - crates/arc-siem/Cargo.toml
    - crates/arc-store-sqlite/Cargo.toml
    - examples/hello-tool/Cargo.toml
    - formal/diff-tests/Cargo.toml
    - tests/e2e/Cargo.toml
    - scripts/measure_arc_core_rebuild.sh
key-decisions:
  - "Remaining shared-type consumers now target `arc-core-types` under the existing `arc-core` dependency name so their Rust imports stay stable while the package graph becomes honest."
  - "The compile benchmark targets `hello-tool`, a narrow consumer that should benefit from shared-type changes without dragging the heavyweight business domains."
  - "The benchmark script compares a pre-split baseline worktree against the current split ref so DECOMP-04 remains reproducible after the migration lands."
patterns-established:
  - "Narrow consumers can migrate off the compatibility facade by aliasing `package = \"arc-core-types\"` to the historical `arc-core` dependency key."
  - "Phase evidence scripts should print machine-readable metrics cleanly and keep verbose build logs out of the numeric return path."
requirements-completed:
  - DECOMP-03
  - DECOMP-04
duration: 8 min
completed: 2026-04-13
---

# Phase 303 Plan 03: Direct-Dependent Migration and Benchmark Summary

**The remaining direct dependents now build against `arc-core-types` instead of the `arc-core` facade where shared substrate types are sufficient, and phase 303 now closes with full compile/test evidence plus a reproducible rebuild benchmark showing a 1.31x faster shared-type rebuild path**

## Performance

- **Duration:** 8 min
- **Started:** 2026-04-13T17:46:24Z
- **Completed:** 2026-04-13T17:54:15Z
- **Tasks:** 3
- **Files modified:** 13

## Accomplishments

- Repointed the remaining shared-type consumers to `arc-core-types` while
  preserving their existing `arc_core::*` imports through Cargo package
  aliasing.
- Added `scripts/measure_arc_core_rebuild.sh`, which compares a pre-split
  baseline worktree against the current split ref using the same `hello-tool`
  rebuild path and `/usr/bin/time -p cargo check`.
- Closed phase 303 with `cargo check --workspace`, the targeted downstream test
  bundle, and a measured incremental rebuild improvement from `5.63s` to
  `4.31s` on the benchmark path.

## Task Commits

Each code-bearing task landed as an atomic commit:

1. **Task 1: Finish the dependency migration for the remaining direct
   dependents** - `cd97e08` (`feat`)
2. **Task 2: Add the reproducible DECOMP-04 compile-time measurement** -
   `8de5f0d` (`chore`)
3. **Task 2 follow-up: Repair the benchmark script output capture uncovered
   during final verification** - `ba0eb62` (`fix`)

## Files Created/Modified

- `crates/arc-a2a-adapter/Cargo.toml`, `crates/arc-hosted-mcp/Cargo.toml`,
  `crates/arc-mcp-adapter/Cargo.toml`, `crates/arc-mcp-edge/Cargo.toml`,
  `crates/arc-mercury/Cargo.toml`, `crates/arc-mercury-core/Cargo.toml`,
  `crates/arc-reputation/Cargo.toml`, `crates/arc-siem/Cargo.toml`,
  `crates/arc-store-sqlite/Cargo.toml`, `examples/hello-tool/Cargo.toml`,
  `formal/diff-tests/Cargo.toml`, and `tests/e2e/Cargo.toml` - moved narrow
  consumers off the monolithic package path and onto `arc-core-types`.
- `scripts/measure_arc_core_rebuild.sh` - reproducible baseline-versus-split
  rebuild benchmark using temporary git worktrees and a fixed touched
  shared-type file.

## Decisions Made

- Used Cargo package aliasing rather than import rewrites so the remaining
  shared-type consumers could migrate without noisy source churn.
- Benchmarked `hello-tool` instead of a wide consumer such as `arc-kernel`
  because the compile win is supposed to show up on narrow shared-type users.
- Kept the benchmark self-contained in `scripts/` and based on git refs so the
  comparison remains runnable after phase 303 is complete.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Benchmark script mixed log output with numeric timing capture**
- **Found during:** Task 3
- **Issue:** The initial script version printed benchmark logs and numeric
  timings to the same output stream and used `split` as an awk variable name,
  which caused the final comparison step to fail even though the timings had
  been collected correctly.
- **Fix:** Routed human-readable benchmark logs to stderr, renamed the awk
  timing variables, and quieted cargo build noise so the script emits clean
  machine-readable timing output.
- **Files modified:** `scripts/measure_arc_core_rebuild.sh`
- **Verification:** `bash -n scripts/measure_arc_core_rebuild.sh && bash scripts/measure_arc_core_rebuild.sh`
- **Committed in:** `ba0eb62`

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** Necessary to make DECOMP-04 evidence reproducible. No
scope creep beyond the benchmark artifact itself.

## Issues Encountered

None.

## User Setup Required

None.

## Next Phase Readiness

- Phase 303 is complete: the shared substrate exists, heavyweight domain
  crates have explicit ownership, narrow consumers no longer depend on the
  monolithic package path by default, and the compile-time benchmark is
  reproducible.
- Phase 304 can now decompose the mega-files on top of real crate boundaries
  instead of one 32K-line `arc-core` gravity well.
- No open blocker remains for the transition from phase 303 to phase 304.

---
*Phase: 303-arc-core-crate-decomposition*
*Completed: 2026-04-13*
