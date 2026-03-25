---
phase: 02-e12-security-boundary-completion
plan: 01
subsystem: security
tags:
  - roots
  - normalization
  - kernel
  - guards
  - docs
requires: []
provides:
  - Shared normalized root helpers in the kernel/session layer without changing the transport-visible root snapshot
  - Explicit fail-closed contract for missing, empty, stale, non-filesystem, and unenforceable roots
  - Normalization fixture coverage for lexical absolute paths and root-containment traversal boundaries
affects:
  - 02-02
  - 02-03
  - 02-04
tech-stack:
  added: []
  patterns:
    - raw root snapshots remain transport-facing while normalized roots are cached for enforcement
    - enforceable filesystem roots come only from local absolute file URIs
    - later enforcement consumes one shared normalized root view instead of re-deriving root semantics ad hoc
key-files:
  created:
    - .planning/phases/02-e12-security-boundary-completion/02-01-SUMMARY.md
  modified:
    - crates/pact-core/src/session.rs
    - crates/pact-kernel/src/session.rs
    - crates/pact-kernel/src/lib.rs
    - crates/pact-guards/src/path_normalization.rs
    - docs/epics/E12-security-boundary-completion.md
key-decisions:
  - "Sessions should preserve raw root transport data and separately cache the normalized runtime root view needed by enforcement"
  - "Only local absolute file roots contribute to filesystem allow sets; non-file and non-local file roots remain metadata or unenforceable evidence"
  - "Missing, empty, stale, and otherwise non-provable roots must define a zero-root filesystem allow set so later enforcement can fail closed consistently"
patterns-established:
  - "Tool and resource enforcement slices should call the shared normalized-session-root helpers instead of re-normalizing roots inline"
  - "Cross-platform root fixtures should test Windows-drive lexical behavior separately from host-path absolutization"
requirements-completed: []
duration: 53min
completed: 2026-03-19
---

# Phase 2 Plan 01: E12 Security Boundary Completion Summary

**Phase 2 now has one normalized root model, one shared kernel/session accessor layer for later enforcement, and one explicit fail-closed contract for sessions that do not provide a provable filesystem root set**

## Performance

- **Duration:** 53 min
- **Started:** 2026-03-19T18:24:05Z
- **Completed:** 2026-03-19T19:17:15Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Cached normalized roots inside kernel sessions while preserving the raw `RootDefinition` snapshot for the wire-facing session APIs
- Added kernel helpers that expose the normalized root view and the enforceable filesystem root paths for later tool and resource enforcement work
- Expanded normalization fixtures to cover cwd-based lexical absolutization, traversal containment, and Windows-drive lexical boundaries
- Froze the E12 contract for local `file://` roots, metadata-only non-filesystem roots, and fail-closed behavior when no provable filesystem root set exists

## Task Commits

No task commits were created in this session because the repository is still being operated from an untracked working-tree baseline.

1. **Task 1: Define the normalized root model in the shared runtime layer** - working tree only
2. **Task 2: Freeze normalization and fail-closed semantics in docs and fixtures** - working tree only

## Files Created/Modified

- `crates/pact-core/src/session.rs` - formatted the preexisting normalized-root implementation so the workspace formatting gate passes
- `crates/pact-kernel/src/session.rs` - added cached normalized roots plus enforceable-root accessors on sessions
- `crates/pact-kernel/src/lib.rs` - exposed normalized session roots and enforceable filesystem root paths for later enforcement slices
- `crates/pact-guards/src/path_normalization.rs` - added lexical-absolute and root-containment tests, including Windows-drive cases
- `docs/epics/E12-security-boundary-completion.md` - documented the frozen root contract and explicit fail-closed semantics for non-provable root sets
- `.planning/phases/02-e12-security-boundary-completion/02-01-SUMMARY.md` - recorded the slice outcome and verification

## Decisions Made

- The runtime root model should be cached at the session layer so every later enforcement path consumes the same normalized classification
- The normalized root helper surface should expose both the full classified root list and the narrower enforceable filesystem root paths
- Non-file roots and unenforceable file roots must remain visible as classification outcomes, but they must not widen filesystem access

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Corrected Windows-drive handling in the new root-containment fixture helper**
- **Found during:** Task 2 verification
- **Issue:** `Path::is_absolute()` on the host platform did not treat `C:/...` examples as absolute, which caused the first Windows-drive containment test to incorrectly join against the Unix cwd
- **Fix:** Taught the test helper to recognize Windows-drive absolute paths lexically before falling back to cwd-based absolutization
- **Files modified:** `crates/pact-guards/src/path_normalization.rs`
- **Verification:** `cargo test -p pact-guards path_normalization` passes after the fix
- **Committed in:** working tree only

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** The slice stayed within scope; the only deviation was correcting the cross-platform fixture helper so the normalization contract matches the intended Windows semantics.

## Verification

- `cargo test -p pact-kernel roots` - passed
- `cargo test -p pact-guards path_normalization` - passed
- `cargo fmt --all -- --check` - passed

## Issues Encountered

- `cargo fmt --all -- --check` initially failed because the earlier partial `NormalizedRoot` work in `crates/pact-core/src/session.rs` had not yet been rustfmt-formatted
- Running multiple `cargo` verification commands in parallel created package-cache lock contention, so the final gate sequence was run serially

## User Setup Required

None - no external services or local configuration changes required.

## Next Phase Readiness

- Phase 2 now has one explicit root model for later tool and resource enforcement
- `02-02` can enforce path-bearing tool calls against the shared normalized-session-root helpers instead of redefining root semantics
- `02-03` can classify filesystem-backed resources using the same zero-root fail-closed contract already documented here

## Self-Check

PASSED - summary file exists, the slice verification commands are green, and Phase 2 planning metadata can advance to `02-02` without reopening the root-model contract.

---
*Phase: 02-e12-security-boundary-completion*
*Completed: 2026-03-19*
