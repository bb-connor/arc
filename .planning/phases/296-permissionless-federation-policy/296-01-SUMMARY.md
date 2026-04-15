---
phase: 296-permissionless-federation-policy
plan: 01
subsystem: federation
tags: [trust-control, federation, reputation, anti-sybil, cli, testing]
requires:
  - phase: 295-raft-consensus-for-trust-control
    provides: clustered trust-control runtime and bounded leader-backed write path
  - phase: 139-open-admission-stake-classes-and-shared-reputation-clearing
    provides: signed open-admission and shared reputation contract artifacts
provides:
  - file-backed permissionless federation policy registry
  - trust-control publication and evaluation surface for open-admission policy
  - integration coverage for proof-of-work, bond-backed entry, rate limits, and reputation gating
affects: [phase-297, phase-298, trust-control federation]
tech-stack:
  added: []
  patterns: [file-backed operator registry, leader-backed admission evaluation, bounded proof-of-work gate]
key-files:
  created:
    - crates/arc-cli/src/federation_policy.rs
    - crates/arc-cli/tests/federation_policy.rs
    - .planning/phases/296-permissionless-federation-policy/296-01-SUMMARY.md
  modified:
    - crates/arc-cli/src/admin.rs
    - crates/arc-cli/src/main.rs
    - crates/arc-cli/src/trust_control.rs
    - crates/arc-cli/src/trust_control/health.rs
    - crates/arc-control-plane/src/lib.rs
key-decisions:
  - "Kept the signed `FederatedOpenAdmissionPolicyArtifact` as the contract payload and wrapped it with trust-control runtime controls instead of creating a second federation artifact family."
  - "Used trust-control's existing local reputation inspection as the bounded runtime score source for federation entry gating."
patterns-established:
  - "Permissionless federation publication follows the same local/remote registry workflow as other trust-control operator surfaces."
  - "Admission evaluation stays fail-closed and returns explicit denial reasons for reputation, proof-of-work, bond, and rate-limit failures."
requirements-completed: [DIST-03, DIST-04]
duration: 50 min
completed: 2026-04-13
---

# Phase 296: Permissionless Federation Policy Summary

**Trust-control now publishes permissionless federation admission policies and evaluates peer entry with explicit anti-sybil and minimum-reputation gates**

## Performance

- **Duration:** 50 min
- **Started:** 2026-04-13T05:20:00Z
- **Completed:** 2026-04-13T06:10:00Z
- **Tasks:** 3
- **Files modified:** 10

## Accomplishments

- Added a file-backed permissionless federation policy registry that stores a signed `FederatedOpenAdmissionPolicyArtifact` plus operator runtime controls for rate limits, proof-of-work, bond-backed admission, and optional minimum reputation score.
- Added `arc trust federation-policy ...` local/remote operator commands and matching trust-control HTTP routes for list/get/upsert/delete/evaluate.
- Added a bounded federation admission evaluation path that fail-closes on invalid policy shape, disallowed admission class, missing or invalid proof-of-work, insufficient reputation, and exhausted rate-limit budget.
- Added dedicated integration coverage for CLI registry management, remote publication and health visibility, reputation-gated admission, and anti-sybil enforcement.

## Task Commits

No task commits were created in this workspace session.

## Files Created/Modified

- `crates/arc-cli/src/federation_policy.rs` - permissionless federation policy record, registry, proof-of-work helper, and evaluation request/response types
- `crates/arc-cli/src/admin.rs` - local/remote federation-policy CLI operator commands
- `crates/arc-cli/src/main.rs` - trust CLI command wiring and trust-service config flag
- `crates/arc-cli/src/trust_control.rs` - federation policy HTTP routes, client methods, evaluation logic, and in-memory rate limiter
- `crates/arc-cli/src/trust_control/health.rs` - health reporting for configured/open-admission federation policy state
- `crates/arc-control-plane/src/lib.rs` - exported the new federation-policy module to the shared control-plane surface
- `crates/arc-cli/tests/federation_policy.rs` - CLI and HTTP proving lane for publication, reputation gating, proof-of-work, bond-backed entry, and rate limiting
- `.planning/phases/296-permissionless-federation-policy/296-01-PLAN.md` - finalized touched-file list and verification targets
- `.planning/phases/296-permissionless-federation-policy/296-01-SUMMARY.md` - phase completion record
- `.planning/ROADMAP.md`, `.planning/REQUIREMENTS.md`, `.planning/STATE.md`, `.planning/PROJECT.md`, `.planning/MILESTONES.md` - milestone/state roll-forward

## Decisions Made

- Operationalized permissionless federation on the existing trust-control surface instead of building a separate federation admission daemon.
- Kept rate limiting state in-memory on trust-control and leader-forwarded the evaluation endpoint so repeated admission attempts stay centrally bounded.
- Used the local reputation score already exposed by trust-control as the minimum-score gate, which keeps federation entry tied to ARC's existing bounded reputation boundary.

## Deviations from Plan

None. The phase followed the planned registry-plus-evaluation implementation path.

## Issues Encountered

- The contract-level phase 139 artifacts did not already encode runtime controls for request rate limiting or proof-of-work, so phase 296 introduced a trust-control operator record that wraps the signed open-admission artifact with those runtime-only settings.

## User Setup Required

None - no external services or credentials are required for this phase.

## Next Phase Readiness

Phase 297 can build on a trust-control surface that now has a bounded permissionless federation admission lane and explicit policy publication workflow. No repo-local blocker remains for `v2.72` phase `297`.

---
*Phase: 296-permissionless-federation-policy*
*Completed: 2026-04-13*
