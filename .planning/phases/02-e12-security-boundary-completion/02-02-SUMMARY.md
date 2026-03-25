---
phase: 02-e12-security-boundary-completion
plan: 02
subsystem: security
tags:
  - roots
  - tool-enforcement
  - guards
  - policy
  - session-runtime
requires:
  - 02-01
provides:
  - Session-backed tool evaluation now passes enforceable filesystem roots into the guard path
  - Filesystem-shaped tool calls fail closed when session roots are missing or containment cannot be proven
  - The operator-facing YAML path now exposes `path_allowlist` through the supported runtime pipeline
affects:
  - 02-03
  - 02-04
tech-stack:
  added: []
  patterns:
    - session-backed root enforcement rides the existing guard pipeline instead of a kernel-only side path
    - root containment is evaluated with the same lexical and filesystem-aware normalization helpers already used for allowlist checks
    - PACT YAML now maps `path_allowlist` into the same runtime guard that HushSpec already used
key-files:
  created:
    - .planning/phases/02-e12-security-boundary-completion/02-02-SUMMARY.md
  modified:
    - crates/pact-kernel/src/lib.rs
    - crates/pact-guards/src/path_allowlist.rs
    - crates/pact-guards/src/action.rs
    - crates/pact-guards/src/pipeline.rs
    - crates/pact-guards/src/mcp_tool.rs
    - crates/pact-guards/src/patch_integrity.rs
    - crates/pact-guards/src/secret_leak.rs
    - crates/pact-guards/tests/integration.rs
    - crates/pact-cli/src/policy.rs
key-decisions:
  - "Root-aware tool enforcement should apply through the session-backed guard path because direct ToolCallRequest evaluation does not carry session identity"
  - "PathAllowlistGuard should enforce session root containment before optional allowlist matching so missing roots fail closed instead of widening access"
  - "The supported PACT YAML surface should expose `path_allowlist` directly rather than leaving root-aware tool enforcement reachable only through HushSpec"
patterns-established:
  - "Filesystem-shaped tool actions should expose a target path through ToolAction helpers so future runtime checks do not re-derive that classification"
  - "GuardContext can carry session-scoped runtime facts when enforcement depends on negotiated session state"
requirements-completed:
  - SEC-02
duration: 13min
completed: 2026-03-19
---

# Phase 2 Plan 02-02: E12 Security Boundary Completion Summary

**Session-backed filesystem tool calls now honor negotiated roots as a runtime boundary, missing roots fail closed in that path, and the supported YAML policy surface can actually instantiate the root-aware guard**

## Performance

- **Duration:** 13 min
- **Started:** 2026-03-19T19:22:12Z
- **Completed:** 2026-03-19T19:34:50Z
- **Tasks:** 2
- **Files modified:** 9

## Accomplishments

- Threaded session-owned enforceable filesystem root paths into `GuardContext` and the session-backed tool evaluation path
- Made `PathAllowlistGuard` deny clearly filesystem-shaped tool actions when the target path is out of root or when the session root set is empty
- Reused existing normalization helpers so root containment and allowlist behavior follow the same lexical and filesystem-aware rules
- Added session-backed integration coverage for in-root allow, out-of-root deny, and missing-roots fail-closed behavior
- Exposed `path_allowlist` on the operator-facing YAML policy path and added a policy test that proves the built pipeline denies out-of-root filesystem tools when session roots are present

## Task Commits

No task commits were created in this session because the repository is still being operated from an untracked working-tree baseline.

1. **Task 1: Wire root-aware checks into filesystem-shaped tool evaluation** - working tree only
2. **Task 2: Expose root-aware behavior through the supported runtime policy path** - working tree only

## Files Created/Modified

- `crates/pact-kernel/src/lib.rs` - passed session root paths into the guard path for session-backed tool evaluation
- `crates/pact-guards/src/path_allowlist.rs` - enforced session-root containment for filesystem-shaped actions and added fail-closed/root-aware tests
- `crates/pact-guards/src/action.rs` - exposed a shared filesystem-path helper on `ToolAction`
- `crates/pact-guards/src/pipeline.rs` - updated guard test contexts for the new session-root field
- `crates/pact-guards/src/mcp_tool.rs` - updated guard test contexts for the new session-root field
- `crates/pact-guards/src/patch_integrity.rs` - updated guard test contexts for the new session-root field
- `crates/pact-guards/src/secret_leak.rs` - updated guard test contexts for the new session-root field
- `crates/pact-guards/tests/integration.rs` - added session-backed filesystem tool integration tests covering allow, deny, and missing-root fail-closed behavior
- `crates/pact-cli/src/policy.rs` - added `path_allowlist` support to the PACT YAML guard loader and policy tests
- `.planning/phases/02-e12-security-boundary-completion/02-02-SUMMARY.md` - recorded slice results and verification

## Decisions Made

- Session-owned roots must be enforced through the shared guard pipeline, not a disconnected kernel-only check, so later policy/runtime paths stay aligned
- Root containment checks run before allowlist matching for filesystem-shaped actions because a broad allowlist must not override an out-of-root deny
- The operator-facing YAML path now needs `path_allowlist` support so root-aware tool enforcement is reachable without switching policy formats

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Rustfmt and context fallout from the new session-root guard plumbing**
- **Found during:** final slice verification
- **Issue:** adding session-root data to `GuardContext` required updating several guard test contexts and formatting a few multiline call sites before the final gate would go green
- **Fix:** propagated the new `session_filesystem_roots` field through the affected test fixtures and ran `cargo fmt --all`
- **Files modified:** `crates/pact-guards/src/pipeline.rs`, `crates/pact-guards/src/mcp_tool.rs`, `crates/pact-guards/src/patch_integrity.rs`, `crates/pact-guards/src/secret_leak.rs`, plus formatting in touched files
- **Verification:** `cargo test -p pact-guards filesystem_tool`, `cargo test -p pact-cli policy`, and `cargo fmt --all -- --check` all pass
- **Committed in:** working tree only

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** The slice stayed within scope; the only cleanup was propagating the new context field through existing guard tests and formatting the touched files.

## Verification

- `cargo test -p pact-guards filesystem_tool` - passed
- `cargo test -p pact-cli policy` - passed
- `cargo fmt --all -- --check` - passed

## Issues Encountered

- The direct `evaluate_tool_call(...)` API still has no session identity, so 02-02 intentionally scopes root enforcement to the supported session-backed runtime path
- Adding session-root facts to the shared guard context required touching several guard test modules even though their runtime behavior did not change

## User Setup Required

None - no external services or local configuration changes required.

## Next Phase Readiness

- Tool-side root enforcement now has one session-backed runtime path and one supported YAML loading path
- `02-03` can focus on filesystem-backed resource classification and enforcement without re-litigating the tool-side root contract
- `02-04` can use the new integration tests and YAML coverage as part of the broader cross-transport proof

## Self-Check

PASSED - the slice summary exists, the required verification commands are green, and Phase 2 can advance to `02-03` after independent verification.

---
*Phase: 02-e12-security-boundary-completion*
*Completed: 2026-03-19*
