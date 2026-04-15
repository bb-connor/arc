---
phase: 385-cli-test-bench-pack-and-install
plan: 02
subsystem: cli
tags: [wasm, guard, cli, tar, gzip, flate2, archive, packaging]

# Dependency graph
requires:
  - phase: 385-01
    provides: "guard.rs module with cmd_guard_pack/cmd_guard_install stubs, GuardCommands::Pack/Install variants"
provides:
  - "arc guard pack: creates .arcguard gzipped tar from guard-manifest.yaml and .wasm"
  - "arc guard install: extracts .arcguard archive to named subdirectory in target dir"
  - "Round-trip fidelity: pack then install produces identical file content"
affects: [guard-sdk-docs]

# Tech tracking
tech-stack:
  added: [flate2 for gzip, tar for archive creation/extraction]
  patterns: [explicit path-based project_dir parameter for testability, temp dir extraction with manifest-driven guard naming]

key-files:
  created: []
  modified:
    - crates/arc-cli/src/guard.rs
    - crates/arc-cli/Cargo.toml

key-decisions:
  - "pack_from_dir takes explicit project_dir path instead of relying on process-global current directory, enabling parallel test execution"
  - "Archive stores wasm as filename-only (not full build-time relative path) to ensure portable extraction"
  - "Install extracts to temp dir first, reads manifest for guard name, then moves files to final location to avoid gzip seek issues"
  - "Extracted manifest wasm_path is rewritten to co-located filename via serde_yml round-trip"
  - "Used std::env::temp_dir with PID suffix instead of adding tempfile to regular dependencies"

patterns-established:
  - "Archive format: gzipped tar named {name}-{version}.arcguard containing guard-manifest.yaml and {name}.wasm"
  - "Install layout: {target_dir}/{guard_name}/guard-manifest.yaml + {guard_name}/{wasm_file}"

requirements-completed: [GCLI-07, GCLI-08]

# Metrics
duration: 11min
completed: 2026-04-15
---

# Phase 385 Plan 02: Guard Pack and Install Summary

**arc guard pack creates .arcguard gzipped tar archives and arc guard install extracts them to named guard directories with wasm_path rewriting**

## Performance

- **Duration:** 11 min
- **Started:** 2026-04-15T01:30:14Z
- **Completed:** 2026-04-15T01:41:14Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- arc guard pack reads guard-manifest.yaml and .wasm binary, creates a gzipped tar archive named {name}-{version}.arcguard
- arc guard install extracts .arcguard to {target_dir}/{guard_name}/ subdirectory with both files and updated wasm_path
- Round-trip test proves pack then install preserves file content byte-for-byte
- 4 new tests (round-trip, missing manifest, missing wasm, missing archive); 22 total guard tests passing

## Task Commits

Each task was committed atomically:

1. **Task 1: Add flate2 and tar dependencies** - `53a6180` (chore)
2. **Task 2 (TDD RED): Failing tests for pack/install** - `e2b7212` (test)
3. **Task 2 (TDD GREEN): Implement pack and install** - `46231b4` (feat)

## Files Created/Modified
- `crates/arc-cli/src/guard.rs` - pack_from_dir, cmd_guard_install, update_manifest_wasm_path, and 4 new tests
- `crates/arc-cli/Cargo.toml` - flate2 and tar dependencies

## Decisions Made
- pack_from_dir accepts explicit project_dir instead of using process-global current directory, so tests can run in parallel without interfering
- Archive entries store wasm as filename-only (stripping build-time relative path like target/wasm32-unknown-unknown/release/) for portable extraction
- Install uses a two-phase extract: temp dir first, then move to final location, because gzip streams do not support seeking
- Extracted manifest has wasm_path rewritten to the co-located filename via serde_yml Value round-trip
- Used std::env::temp_dir with PID-scoped subdirectory for install temp space instead of adding tempfile as a regular dependency

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- All five GCLI requirements (04-08) for phase 385 are now satisfied
- Guard development lifecycle is complete: new, build, inspect, test, bench, pack, install
- 22 guard unit tests passing, arc-cli clippy and fmt clean

---
*Phase: 385-cli-test-bench-pack-and-install*
*Completed: 2026-04-15*
