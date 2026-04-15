---
phase: 377-acp-live-path-cryptographic-enforcement
plan: 01
subsystem: security
tags: [acp, capability-tokens, ed25519, receipts, rust]
requires:
  - phase: 324
    provides: CapabilityChecker and ReceiptSigner extension points in arc-acp-proxy
provides:
  - Live ACP filesystem and terminal enforcement through the installed capability checker
  - Trusted-issuer and signature validation in KernelCapabilityChecker
  - Audit and receipt provenance that distinguishes cryptographically enforced operations from audit-only observations
affects: [378-outward-edge-kernel-mediation-and-receipt-parity, 381-claim-gate-qualification, arc-acp-proxy]
tech-stack:
  added: []
  patterns: [fail-closed live-path enforcement, explicit audit provenance metadata]
key-files:
  created: [.planning/phases/377-acp-live-path-cryptographic-enforcement/377-01-SUMMARY.md]
  modified:
    - crates/arc-acp-proxy/src/interceptor.rs
    - crates/arc-acp-proxy/src/receipt.rs
    - crates/arc-acp-proxy/src/kernel_checker.rs
    - crates/arc-acp-proxy/src/kernel_signer.rs
    - crates/arc-acp-proxy/src/compliance.rs
    - crates/arc-acp-proxy/src/tests/all.rs
key-decisions:
  - "Capability tokens are extracted additively from raw ACP params (`capabilityToken`, `capability_token`, and nested `arc.*`) without widening the typed ACP request structs."
  - "Audit entries and signed receipts emit an explicit enforcement mode so cryptographically enforced activity is distinguishable from audit-only observations."
  - "This execution did not auto-advance phase state; existing STATE.md and ROADMAP.md edits already reflected later worktree activity and were intentionally left untouched."
patterns-established:
  - "ACP live-path checks run before built-in fs and terminal guards and fail closed on deny, missing capability IDs, or checker errors."
  - "Session-scoped capability context is propagated into later ACP tool-call artifacts and cleared on terminal status updates."
requirements-completed: [ACPX-01, ACPX-02, ACPX-03]
duration: 5m
completed: 2026-04-14
---

# Phase 377 Plan 01: Live ACP Capability Enforcement and Audit Correlation Summary

**Live ACP fs and terminal operations now fail closed through signature-verified capability checks, with enforced-vs-audit-only provenance carried into audit entries and signed receipts**

## Performance

- **Duration:** 5 min
- **Started:** 2026-04-14T19:43:19Z
- **Completed:** 2026-04-14T19:48:07Z
- **Tasks:** 4
- **Files modified:** 6

## Accomplishments

- Wired `MessageInterceptor` to extract additive capability-token material from ACP params, call the installed `CapabilityChecker`, and block fs/terminal operations before built-in guards on deny or checker failure.
- Hardened `KernelCapabilityChecker` to reject tokens from untrusted issuers and invalid signatures before time and scope evaluation.
- Propagated validated `capability_id` plus explicit enforcement provenance into ACP audit entries and signed receipt metadata, then covered the behavior with focused proxy tests.

## Task Commits

Each task was committed atomically where the file boundaries allowed it:

1. **Task 1: Live interceptor enforcement** - `4b3c4f2` (`feat`)
2. **Task 2: Trusted issuer and signature verification** - `f2df2fe` (`fix`)
3. **Task 3: Capability metadata propagation** - `d8dc50b` (`feat`)
4. **Task 4: Focused proxy regression coverage** - `93291a0` (`test`)

## Files Created/Modified

- `crates/arc-acp-proxy/src/interceptor.rs` - Enforces capability checks on live fs/terminal paths, captures session capability context, and clears it after terminal status completion.
- `crates/arc-acp-proxy/src/receipt.rs` - Adds capability audit context and explicit enforcement-mode tagging to ACP audit entries.
- `crates/arc-acp-proxy/src/kernel_checker.rs` - Verifies issuer trust and Ed25519 signatures before time and scope checks.
- `crates/arc-acp-proxy/src/kernel_signer.rs` - Uses validated capability IDs in signed receipts and includes ACP enforcement metadata in receipt body metadata.
- `crates/arc-acp-proxy/src/tests/all.rs` - Adds checker invocation, fail-closed, signature-verification, context-lifecycle, and metadata-propagation coverage.
- `crates/arc-acp-proxy/src/compliance.rs` - Preserves the co-located compliance serialization compatibility change already present in the dirty proxy suite while landing the test file update.

## Decisions Made

- Used additive raw-JSON extraction for capability tokens instead of changing ACP typed param structs because the current protocol surface does not model a token field.
- Emitted `audit_only` explicitly by default so downstream artifacts can distinguish observational logging from cryptographically enforced operations without inferring from null/missing fields.
- Left `STATE.md` and `ROADMAP.md` untouched because the worktree already contained user-managed edits that had advanced beyond this request and overwriting them would have violated the non-revert constraint.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing Critical] Emit explicit audit-only provenance**
- **Found during:** Task 1 (Live interceptor enforcement)
- **Issue:** `AcpEnforcementMode::AuditOnly` existed but audit entries still serialized missing or null enforcement metadata, which weakened the requirement to distinguish enforced operations from audit-only observations.
- **Fix:** Defaulted ACP audit entries to `audit_only` and verified signed receipts now surface `acp.enforcementMode` for both enforced and audit-only paths.
- **Files modified:** `crates/arc-acp-proxy/src/receipt.rs`, `crates/arc-acp-proxy/src/tests/all.rs`
- **Verification:** `cargo test -p arc-acp-proxy`
- **Committed in:** `4b3c4f2`

**2. [Rule 1 - Bug] Clear stale session capability context after terminal completion**
- **Found during:** Task 1 (Live interceptor enforcement)
- **Issue:** Session-scoped capability context could remain attached after a terminal-status completion update and leak into later audit-only session updates.
- **Fix:** Cleared cached capability context on terminal tool-call completion statuses and added regression coverage.
- **Files modified:** `crates/arc-acp-proxy/src/interceptor.rs`, `crates/arc-acp-proxy/src/tests/all.rs`
- **Verification:** `cargo test -p arc-acp-proxy`
- **Committed in:** `4b3c4f2`

---

**Total deviations:** 2 auto-fixed (1 missing critical, 1 bug)
**Impact on plan:** Both fixes tightened the same ACP provenance surface the plan targeted. No architectural scope change.

## Issues Encountered

- `crates/arc-acp-proxy/src/tests/all.rs` and `crates/arc-acp-proxy/src/compliance.rs` were already dirty with adjacent proxy-suite serialization work. The task-4 commit kept that co-located coverage intact rather than trying to split a shared test file non-interactively.
- `.planning/STATE.md` and `.planning/ROADMAP.md` were already dirty and recorded phase `377` as complete with phase `378` active. They were left unchanged to respect existing user work and the explicit no-revert constraint.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 378 can assume ACP live-path fs/terminal authority now routes through the installed checker, fails closed, and leaves receipt/audit artifacts with explicit provenance.
- Residual concern: capability correlation is still session-scoped; phase 381 should add higher-order ordering/concurrency coverage if ACP can issue multiple governed tool calls concurrently within one session.

## Self-Check

PASSED

---
*Phase: 377-acp-live-path-cryptographic-enforcement*
*Completed: 2026-04-14*
