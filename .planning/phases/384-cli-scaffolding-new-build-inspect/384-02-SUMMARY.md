---
phase: 384-cli-scaffolding-new-build-inspect
plan: 02
subsystem: cli
tags: [wasmparser, wasm, cli, guard-lifecycle, abi-inspection]

requires:
  - phase: 384-cli-scaffolding-new-build-inspect
    plan: 01
    provides: "Guard subcommand group with cmd_guard_new scaffold, GuardCommands enum, and build/inspect stubs"
  - phase: 382-guard-sdk-crate
    provides: "arc-guard-sdk ABI types defining evaluate, arc_alloc, arc_deny_reason exports"
provides:
  - "cmd_guard_build implementation compiling guard projects to wasm32-unknown-unknown"
  - "cmd_guard_inspect implementation analyzing WASM binaries for exports, ABI compatibility, and memory config"
  - "wasmparser dependency in arc-cli for WASM binary analysis"
affects: [arc-cli, guard-lifecycle]

tech-stack:
  added: [wasmparser 0.221]
  patterns: [wasmparser::Parser payload iteration for WASM section extraction, human-readable size formatting]

key-files:
  created: []
  modified: [crates/arc-cli/src/guard.rs, crates/arc-cli/Cargo.toml]

key-decisions:
  - "wasmparser 0.221 as direct arc-cli dep (not workspace), matching existing transitive dep from wasmtime"
  - "cmd_guard_build uses simple string matching on Cargo.toml (not a TOML parser) for cdylib detection and package name extraction"
  - "cmd_guard_inspect is informational-only: reports ABI incompatibility but does not fail with non-zero exit"
  - "Memory section maximum of None displayed as 'unbounded' matching WASM spec semantics"

patterns-established:
  - "WASM binary inspection pattern: wasmparser::Parser::new(0).parse_all() with ExportSection and MemorySection matching"
  - "ABI compatibility check against required exports: evaluate, arc_alloc, arc_deny_reason"

requirements-completed: [GCLI-02, GCLI-03]

duration: 10min
completed: 2026-04-14
---

# Phase 384 Plan 02: Guard Build and Inspect Commands Summary

**`arc guard build` compiles cdylib guard projects to wasm32-unknown-unknown and `arc guard inspect` analyzes WASM binaries for ABI compatibility using wasmparser**

## Performance

- **Duration:** 10 min
- **Started:** 2026-04-15T00:24:20Z
- **Completed:** 2026-04-15T00:35:13Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- `arc guard build` compiles the current guard project to wasm32-unknown-unknown in release mode and reports the output path and binary size
- `arc guard inspect` reads a WASM binary and prints all exported functions with their kinds (function/memory/table/global/tag)
- ABI compatibility check reports presence/absence of evaluate, arc_alloc, and arc_deny_reason with [+]/[-] markers
- Linear memory configuration extracted and displayed (initial pages, max pages, KiB calculation)
- Human-readable size formatting (bytes/KiB/MiB) shared between build and inspect commands

## Task Commits

Each task was committed atomically:

1. **Task 1: Add wasmparser dependency and implement cmd_guard_build** - `f91bfb3` (feat)
2. **Task 2: Implement cmd_guard_inspect with wasmparser** - `cd2a4f4` (feat)

## Files Created/Modified
- `crates/arc-cli/src/guard.rs` - Full guard subcommand implementations (cmd_guard_new from plan 01, cmd_guard_build and cmd_guard_inspect)
- `crates/arc-cli/Cargo.toml` - Added wasmparser 0.221 dependency for WASM binary inspection

## Decisions Made
- Used wasmparser 0.221 as a direct arc-cli dependency rather than adding it to workspace deps, since it is only needed by the CLI crate and 0.221.3 is already in Cargo.lock via wasmtime
- cmd_guard_build uses simple string contains/line matching for Cargo.toml parsing rather than pulling in a TOML parsing library; this is sufficient for the guard project layout which has a predictable template
- cmd_guard_inspect is intentionally non-failing on ABI incompatibility -- it prints the compatibility status but returns Ok(()), making it safe to use in scripts
- Export list display uses aligned columns with the longest export name as the column width
- Memory section's optional maximum is displayed as "unbounded" when None, matching WASM specification semantics for memories without explicit limits

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- All three guard lifecycle commands are now fully implemented: `arc guard new`, `arc guard build`, `arc guard inspect`
- The guard CLI module is complete and ready for end-to-end testing (requires wasm32-unknown-unknown target installed)
- Phase 384 is now complete (both plans done)

## Self-Check: PASSED

- FOUND: crates/arc-cli/src/guard.rs
- FOUND: crates/arc-cli/Cargo.toml
- FOUND: 384-02-SUMMARY.md
- FOUND: f91bfb3 (Task 1 commit)
- FOUND: cd2a4f4 (Task 2 commit)

---
*Phase: 384-cli-scaffolding-new-build-inspect*
*Completed: 2026-04-14*
