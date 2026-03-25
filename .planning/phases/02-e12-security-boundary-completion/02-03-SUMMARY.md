---
phase: 02-e12-security-boundary-completion
plan: 03
subsystem: security
tags:
  - roots
  - resource-enforcement
  - kernel
  - mcp-edge
  - session-runtime
requires:
  - 02-01
  - 02-02
provides:
  - Explicit resource-URI classification that distinguishes enforceable local file URIs from provider-owned non-filesystem resources
  - Session-root enforcement for filesystem-backed resource reads before providers return content
  - Edge-level resource-read errors that preserve non-filesystem reads and surface root denials clearly
affects:
  - 02-04
tech-stack:
  added: []
  patterns:
    - resource reads classify URI shape explicitly before any provider call
    - only local absolute file URIs participate in root enforcement; other resource schemes stay provider-defined
    - filesystem-backed resource reads fail closed when roots are missing or containment cannot be proven
key-files:
  created:
    - .planning/phases/02-e12-security-boundary-completion/02-03-SUMMARY.md
  modified:
    - crates/pact-core/src/session.rs
    - crates/pact-kernel/src/lib.rs
    - crates/pact-mcp-adapter/src/edge.rs
key-decisions:
  - "Only local absolute `file://` resource URIs are classified as filesystem-backed for root enforcement; provider-owned schemes like `repo://` remain outside the filesystem boundary"
  - "Filesystem-backed resource reads must fail closed when the URI is unenforceable or the session cannot prove in-root membership"
  - "The MCP edge should return an explicit `resources/read` denial for root-boundary failures instead of collapsing them into `Resource not found`"
patterns-established:
  - "Resource-read enforcement should consume the shared root normalization helpers rather than re-parsing root semantics inside providers"
  - "Kernel-side resource denials should distinguish root-boundary failures from capability-scope failures so transport adapters can surface the right error"
requirements-completed:
  - SEC-03
  - SEC-04
duration: 12min
completed: 2026-03-19
---

# Phase 2 Plan 03: E12 Security Boundary Completion Summary

**Resource reads now classify local file URIs explicitly, enforce negotiated session roots before provider content is returned, and keep provider-owned non-filesystem resources out of the filesystem boundary**

## Performance

- **Duration:** 12 min
- **Started:** 2026-03-19T19:35:22Z
- **Completed:** 2026-03-19T19:47:37Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Added a shared `ResourceUriClassification` boundary in `pact-core` so the runtime can explicitly decide when a resource URI is filesystem-backed
- Enforced session roots for filesystem-backed resource reads in `pact-kernel` before any provider returns content, including fail-closed behavior when roots are missing or the file URI is unenforceable
- Updated the MCP edge to return clear `resources/read` denial errors for root-boundary failures while preserving the existing non-filesystem `repo://` resource flow
- Added kernel and edge coverage for in-root allow, out-of-root deny, missing-roots fail-closed, and preserved non-filesystem reads

## Task Commits

No task commits were created in this session because the owned source files are still untracked in the repository baseline, so path-scoped commits would snapshot full preexisting files instead of just this slice.

1. **Task 1: Add an explicit filesystem-backed resource classification boundary** - working tree only
2. **Task 2: Enforce roots for filesystem-backed resource reads** - working tree only

## Files Created/Modified

- `crates/pact-core/src/session.rs` - added `ResourceUriClassification`, shared local-file URI normalization reuse, and classification tests
- `crates/pact-kernel/src/lib.rs` - enforced session-root checks for filesystem-backed resource reads and added kernel tests for in-root, out-of-root, and missing-root behavior
- `crates/pact-mcp-adapter/src/edge.rs` - surfaced root-boundary resource denials as explicit `resources/read` errors and added edge tests for preserved non-filesystem and filesystem-backed cases
- `.planning/phases/02-e12-security-boundary-completion/02-03-SUMMARY.md` - recorded the slice outcome and verification

## Decisions Made

- The resource-side filesystem boundary should be URI-classification based and conservative: only local absolute `file://` URIs count as filesystem-backed for root enforcement
- Root enforcement belongs in the kernel’s shared resource-read path so providers do not each invent their own root semantics
- Root-boundary failures need a distinct kernel error so the edge can report a denial clearly instead of hiding it behind a not-found response

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- Starting the two cargo verification commands in parallel hit the shared cargo package/artifact locks, so the final verification pass was rerun serially
- `cargo fmt --all -- --check` initially reported rustfmt-only line wrapping in touched code paths; running `cargo fmt --all` resolved the gate cleanly

## User Setup Required

None - no external services or local configuration changes required.

## Next Phase Readiness

- Phase 2 now has both tool-side and resource-side root enforcement wired through the shared session-root model
- `02-04` can focus on broader cross-transport proof and documentation rather than reopening filesystem-boundary semantics

## Verification

- `cargo test -p pact-kernel read_resource` - passed
- `cargo test -p pact-mcp-adapter resources_read` - passed
- `cargo fmt --all -- --check` - passed
- `cargo test -p pact-core resource_uri` - passed (extra targeted check for the new shared classification tests)

## Self-Check

PASSED - summary file exists, the required verification commands are green, and the slice is ready for Phase 2 plan-state updates.

---
*Phase: 02-e12-security-boundary-completion*
*Completed: 2026-03-19*
