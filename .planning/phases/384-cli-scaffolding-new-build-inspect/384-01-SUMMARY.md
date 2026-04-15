---
phase: 384-cli-scaffolding-new-build-inspect
plan: 01
subsystem: cli
tags: [clap, scaffold, wasm-guards, cli, guard-sdk]

requires:
  - phase: 382-guard-sdk-crate
    provides: arc-guard-sdk and arc-guard-sdk-macros crates for guest-side guard development
  - phase: 383-proc-macro-and-example-guards
    provides: "#[arc_guard] proc macro and example guard crate pattern"
provides:
  - "Guard subcommand group in CLI (arc guard new/build/inspect)"
  - "cmd_guard_new scaffold implementation creating Cargo.toml, src/lib.rs, guard-manifest.yaml"
  - "GuardCommands enum with New, Build, Inspect variants"
affects: [384-02-PLAN, arc-cli]

tech-stack:
  added: [tempfile (dev)]
  patterns: [guard project scaffolding, inline template rendering with string replacement]

key-files:
  created: [crates/arc-cli/src/guard.rs]
  modified: [crates/arc-cli/src/cli/types.rs, crates/arc-cli/src/cli/dispatch.rs, crates/arc-cli/src/main.rs, crates/arc-cli/Cargo.toml]

key-decisions:
  - "Inline string templates for scaffold files instead of include_str! template directory (only 3 small files)"
  - "Package name derived from final path component, not full path, matching scaffold.rs pattern"
  - "SDK deps use version strings (\"0.1\") not path deps since scaffolded guards are standalone projects"

patterns-established:
  - "Guard CLI module pattern: guard.rs with cmd_guard_* public functions called from dispatch.rs"
  - "Guard project layout: Cargo.toml (cdylib), src/lib.rs (#[arc_guard] skeleton), guard-manifest.yaml"

requirements-completed: [GCLI-01]

duration: 9min
completed: 2026-04-14
---

# Phase 384 Plan 01: Guard CLI Scaffolding Summary

**`arc guard new` scaffolds cdylib guard projects with SDK deps, #[arc_guard] skeleton, and guard-manifest.yaml (ABI v1)**

## Performance

- **Duration:** 9 min
- **Started:** 2026-04-15T00:13:32Z
- **Completed:** 2026-04-15T00:22:29Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments
- Guard subcommand group wired into CLI with New, Build, and Inspect variants
- `arc guard new <name>` creates a correctly templated guard project directory
- Scaffolded Cargo.toml includes cdylib crate-type and arc-guard-sdk dependencies
- Scaffolded src/lib.rs has #[arc_guard] fn evaluate skeleton ready for guard logic
- Scaffolded guard-manifest.yaml has abi_version 1, wasm_path, and placeholder sha256
- Unit tests for package name sanitization, scaffold creation, and non-empty directory rejection

## Task Commits

Each task was committed atomically:

1. **Task 1: Add Guard subcommand types and dispatch wiring** - `e8d7699` (feat)
2. **Task 2: Implement cmd_guard_new scaffold command** - `b85a0c7` (feat)

## Files Created/Modified
- `crates/arc-cli/src/guard.rs` - Guard subcommand implementations (cmd_guard_new, stubs for build/inspect)
- `crates/arc-cli/src/cli/types.rs` - GuardCommands enum and Commands::Guard variant
- `crates/arc-cli/src/cli/dispatch.rs` - Guard dispatch arm routing to guard module
- `crates/arc-cli/src/main.rs` - mod guard declaration
- `crates/arc-cli/Cargo.toml` - tempfile dev-dependency for test isolation

## Decisions Made
- Inline string constants for template content rather than file-based templates (only 3 small files, no template directory needed)
- Package name derived from final path component via Path::file_name(), matching scaffold.rs convention
- SDK dependencies use version strings ("0.1") instead of path deps, since scaffolded guards are standalone projects not workspace members
- Sanitize fallback name is "arc-guard" (distinct from scaffold.rs "arc-app" fallback)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed package name derivation from full paths**
- **Found during:** Task 2 (cmd_guard_new implementation)
- **Issue:** When passing a full path like `/tmp/test-guard`, sanitize_package_name was processing the entire path string, producing mangled names
- **Fix:** Added Path::file_name() extraction (matching scaffold.rs pattern) to derive the directory name before sanitization
- **Files modified:** crates/arc-cli/src/guard.rs
- **Verification:** Unit test passes with tempdir-based full paths
- **Committed in:** b85a0c7 (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** Essential correctness fix. No scope creep.

## Issues Encountered
- Pre-existing clippy warning in arc-acp-proxy (large_enum_variant) causes `cargo clippy -p arc-cli -- -D warnings` to fail when checking dependencies; verified arc-cli itself is clean using --no-deps flag. Out of scope per deviation rules.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Guard subcommand structure is ready for plan 02 to implement cmd_guard_build and cmd_guard_inspect
- Build and inspect stubs return CliError::Other("not yet implemented")
- Guard module pattern established for adding new guard lifecycle commands

---
*Phase: 384-cli-scaffolding-new-build-inspect*
*Completed: 2026-04-14*
