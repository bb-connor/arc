---
phase: 02-e12-security-boundary-completion
plan: 04
subsystem: security
tags:
  - roots
  - resource-enforcement
  - signed-evidence
  - mcp-edge
  - transport
requires:
  - 02-02
  - 02-03
provides:
  - Signed deny evidence for filesystem-backed resource-read failures via `SessionOperationResponse::ResourceReadDenied`
  - JSON-RPC `resources/read` error data that carries the signed receipt instead of collapsing the denial into a plain transport error
  - Transport-level proof that in-root allow, out-of-root deny, and missing-roots fail-closed behavior hold in the live `mcp serve` path
  - Documentation updates that describe roots as an enforced boundary with fail-closed missing-roots semantics
affects: []
tech-stack:
  added: []
  patterns:
    - resource-root denials are emitted as signed receipts at the session boundary and then surfaced unchanged through transport error data
    - non-filesystem resources still bypass root enforcement and continue through the existing success path
    - the CLI binary must recognize the new session response variant even though only the resource-read path consumes it
key-files:
  created:
    - .planning/phases/02-e12-security-boundary-completion/02-04-SUMMARY.md
  modified:
    - crates/pact-kernel/src/session.rs
    - crates/pact-kernel/src/lib.rs
    - crates/pact-mcp-adapter/src/edge.rs
    - crates/pact-cli/tests/mcp_serve.rs
    - crates/pact-cli/src/main.rs
    - docs/epics/E12-security-boundary-completion.md
    - docs/POST_REVIEW_EXECUTION_PLAN.md
key-decisions:
  - "Filesystem-backed resource denials should keep using the session-backed runtime path so the kernel can sign the deny receipt before the edge renders any JSON-RPC error"
  - "The signed evidence should live in `error.data.receipt`, while the human-readable transport message continues to describe the root boundary that failed"
  - "Missing roots are a fail-closed condition, not a special success case, and the transport tests should prove that behavior against the live CLI wrapper"
patterns-established:
  - "The resource-read contract now mirrors tool-call denials by carrying signed evidence across the session/transport boundary"
  - "Wrapped transport tests should allow unrelated notifications and assert the response contract directly rather than assuming a quiet channel"
  - "The post-review plan should describe roots as an enforceable runtime boundary wherever filesystem access is in scope"
requirements-completed:
  - SEC-03
  - SEC-04
duration: 45min
completed: 2026-03-19
---

# Phase 2 Plan 02-04: E12 Security Boundary Completion Summary

**Filesystem-backed root-boundary denials now carry signed evidence through the supported session path, the MCP edge preserves that evidence in JSON-RPC error data, and the live `mcp serve` path proves in-root, out-of-root, and missing-roots fail-closed behavior**

## Performance

- **Duration:** 45 min
- **Completed:** 2026-03-19
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments

- Added `SessionOperationResponse::ResourceReadDenied` so filesystem-backed resource denials can return a signed `PactReceipt` instead of only a plain error
- Signed resource-read deny receipts at the kernel boundary with the roots guard encoded in the receipt decision
- Updated the MCP edge to translate signed resource-read denials into JSON-RPC errors with `error.data.receipt`
- Added live `pact mcp serve` coverage for in-root allow, out-of-root deny, and missing-roots fail-closed behavior using the real wrapped transport path
- Updated the E12 epic and post-review plan so they describe roots as an enforced boundary with fail-closed missing-roots semantics and signed evidence for filesystem-backed resource denials

## Task Commits

No task commits were created in this session because the repository is still being operated from an untracked working-tree baseline.

1. **Task 1: Carry signed deny evidence through filesystem-backed resource reads** - working tree only
2. **Task 2: Document the enforced boundary and close the review finding** - working tree only

## Files Created/Modified

- `crates/pact-kernel/src/session.rs` - added the signed resource-read deny response variant
- `crates/pact-kernel/src/lib.rs` - built signed deny receipts for filesystem-backed resource reads and returned them through the session response
- `crates/pact-mcp-adapter/src/edge.rs` - propagated signed deny evidence through JSON-RPC `error.data`
- `crates/pact-cli/tests/mcp_serve.rs` - added live transport coverage for in-root allow, out-of-root deny, and missing-roots fail-closed resource reads
- `crates/pact-cli/src/main.rs` - updated CLI response matches for the new session response variant
- `docs/epics/E12-security-boundary-completion.md` - documented enforced roots, fail-closed missing-roots semantics, and signed resource-read evidence
- `docs/POST_REVIEW_EXECUTION_PLAN.md` - updated the post-review boundary description and gate language

## Decisions Made

- Resource-read denials should be signed where the decision is made, not reconstructed later at the transport edge
- The transport should surface the signed receipt in `error.data` instead of flattening the denial into a plain not-found or invalid-params response
- Missing roots are a hard fail-closed condition for filesystem-backed access, and the live transport test should exercise that path explicitly

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Test strictness] Live transport tests initially assumed a quiet notification channel**
- **Found during:** `cargo test -p pact-cli mcp_serve`
- **Issue:** the wrapped `mcp serve` path emitted additional notifications during resource reads, which made the new tests too strict
- **Fix:** relaxed the tests to assert the response contract and signed receipt data directly, rather than requiring an empty notification list
- **Files modified:** `crates/pact-cli/tests/mcp_serve.rs`
- **Verification:** `cargo test -p pact-cli mcp_serve` passed after the adjustment

## Verification

- `cargo test -p pact-kernel read_resource` - passed
- `cargo test -p pact-mcp-adapter resources_read` - passed
- `cargo test -p pact-cli mcp_serve` - passed
- `cargo fmt --all -- --check` - passed

## Issues Encountered

- The new `SessionOperationResponse` variant also had to be added to the CLI binary’s exhaustiveness matches so the workspace could compile cleanly
- The wrapped transport emits unrelated notifications during the live resource-read flow, so the tests now verify the signed evidence and response shape rather than assuming silence

## User Setup Required

None - no external services or local configuration changes required.

## Next Phase Readiness

- The roots boundary now has signed deny evidence across the supported resource-read path and a live transport proof
- Remaining work should focus on other epics rather than reopening the roots boundary contract

## Self-Check

PASSED - the summary file exists, the signed-evidence gap is closed in code and transport tests, and the docs now describe roots as an enforced boundary with fail-closed missing-roots semantics.

---
*Phase: 02-e12-security-boundary-completion*
*Completed: 2026-03-19*
