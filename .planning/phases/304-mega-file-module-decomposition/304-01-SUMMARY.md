---
phase: 304-mega-file-module-decomposition
plan: 01
subsystem: infra
tags:
  - rust
  - cli
  - control-plane
  - hosted-mcp
  - decomposition
requires: []
provides:
  - `arc-cli` mega-file decomposition into `cli/`, `trust_control/`, and `remote_mcp/` chunks
  - thin root files that preserve `include!` and path-based consumers
  - clean CLI-lane compile evidence plus local size-gate clearance
affects:
  - phase-304-02
  - phase-304-03
  - phase-305
  - phase-306
tech-stack:
  added: []
  patterns:
    - thin facade roots with `include!` chunk files
    - path-stable decomposition for `arc-control-plane` and `arc-hosted-mcp`
    - mechanical split at item boundaries to avoid behavioral churn
key-files:
  created:
    - crates/arc-cli/src/cli/types.rs
    - crates/arc-cli/src/cli/dispatch.rs
    - crates/arc-cli/src/cli/runtime.rs
    - crates/arc-cli/src/cli/trust_commands.rs
    - crates/arc-cli/src/cli/session.rs
    - crates/arc-cli/src/trust_control/service_types.rs
    - crates/arc-cli/src/trust_control/config_and_public.rs
    - crates/arc-cli/src/trust_control/service_runtime.rs
    - crates/arc-cli/src/trust_control/http_handlers_a.rs
    - crates/arc-cli/src/trust_control/http_handlers_b.rs
    - crates/arc-cli/src/trust_control/cluster_and_reports.rs
    - crates/arc-cli/src/trust_control/capital_and_liability.rs
    - crates/arc-cli/src/trust_control/credit_and_loss.rs
    - crates/arc-cli/src/trust_control/underwriting_and_support.rs
    - crates/arc-cli/src/remote_mcp/session_core.rs
    - crates/arc-cli/src/remote_mcp/http_service.rs
    - crates/arc-cli/src/remote_mcp/oauth.rs
    - crates/arc-cli/src/remote_mcp/tests.rs
    - .planning/phases/304-mega-file-module-decomposition/304-01-SUMMARY.md
  modified:
    - crates/arc-cli/src/main.rs
    - crates/arc-cli/src/trust_control.rs
    - crates/arc-cli/src/remote_mcp.rs
key-decisions:
  - "Kept `main.rs`, `trust_control.rs`, and `remote_mcp.rs` as thin stable roots so existing `include!` and path-based consumers keep compiling without import-path churn."
  - "Used `include!` chunk files rather than semantic rewrites for the first cut because this phase is about decomposition honesty, not behavior changes."
  - "Preserved the existing `trust_control/health.rs` and `remote_mcp/admin.rs` leaf modules instead of folding them back into the new chunk layout."
patterns-established:
  - "Future oversized CLI surfaces can be reduced safely by keeping a tiny public root and pushing contiguous item groups into chunk files under a sibling directory."
  - "Path-included modules should decompose without renaming their outer module file so downstream `#[path = ...]` consumers remain stable."
requirements-completed:
  - DECOMP-05
  - DECOMP-07
duration: 22 min
completed: 2026-04-13
---

# Phase 304 Plan 01: CLI Mega-File Decomposition Summary

**The CLI lane now has thin stable roots over chunked source trees, `arc-cli`/`arc-control-plane`/`arc-hosted-mcp` compile cleanly, and the oversized-file gate no longer reports any `arc-cli` source file**

## Performance

- **Duration:** 22 min
- **Completed:** 2026-04-13T19:03:08Z
- **Files modified:** 21

## Accomplishments

- Split `crates/arc-cli/src/main.rs` into a thin root plus five chunk files
  under `crates/arc-cli/src/cli/`.
- Split `crates/arc-cli/src/trust_control.rs` into a thin root plus nine
  chunk files under `crates/arc-cli/src/trust_control/` while preserving the
  existing `health.rs` module.
- Split `crates/arc-cli/src/remote_mcp.rs` into a thin root plus four chunk
  files under `crates/arc-cli/src/remote_mcp/` while preserving the existing
  admin module.
- Cleared the CLI-side size gate: `find crates/arc-cli -name '*.rs' ! -path
  '*/tests/*' ... awk '$1 > 3000'` now returns no oversized `arc-cli` files.

## Verification

- `cargo check -p arc-cli -p arc-control-plane -p arc-hosted-mcp -p arc-mercury`
- `find crates/arc-cli -name '*.rs' ! -path '*/tests/*' -print0 | xargs -0 wc -l | sort -nr | awk '$1 > 3000 {print}'`

## Decisions Made

- Used mechanical item-chunk extraction instead of semantic handler moves to
  keep the CLI behavior unchanged while satisfying the file-size objective.
- Left the public roots in place so `crates/arc-cli/src/bin/arc.rs`,
  `arc-control-plane`, and `arc-hosted-mcp` continue to target the same file
  paths.
- Treated boundary-fix compile errors as part of the decomposition work and
  repaired the chunk splits before accepting verification.

## Deviations from Plan

### Auto-fixed Issues

**1. Mechanical split boundaries initially cut across attributed items**
- **Found during:** CLI-lane compile verification
- **Issue:** The first pass of the chunk split left a small number of orphaned
  derive and test attributes at chunk boundaries.
- **Fix:** Moved the affected attribute lines onto the correct side of the
  boundary so each chunk starts and ends on complete Rust items.
- **Verification:** `cargo check -p arc-cli -p arc-control-plane -p arc-hosted-mcp -p arc-mercury`

## Next Phase Readiness

- `304-01` is complete and the CLI lane is no longer on the oversized-file
  list.
- `304-02` can land independently and `304-03` can focus on the remaining
  global size-gate stragglers, especially `arc-mercury`, `arc-credit`, and the
  newly exposed large test modules.

---
*Phase: 304-mega-file-module-decomposition*
*Completed: 2026-04-13*
