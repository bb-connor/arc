---
phase: 297-scim-lifecycle-automation
plan: 01
subsystem: federation
tags: [trust-control, federation, scim, lifecycle, receipts, testing]
requires:
  - phase: 295-raft-consensus-for-trust-control
    provides: clustered trust-control write path and leader-forwarded operator surfaces
  - phase: 296-permissionless-federation-policy
    provides: current trust-control federation health/reporting and bounded registry patterns
provides:
  - file-backed SCIM lifecycle registry for provisioned enterprise identities
  - trust-control SCIM create and delete surface with real revocation side effects
  - fail-closed federated issuance binding for deprovisioned SCIM identities
affects: [phase-298, trust-control federation, enterprise-provider lane]
tech-stack:
  added: []
  patterns: [operator-owned SCIM lifecycle registry, tracked-capability revocation, fail-closed SCIM admission]
key-files:
  created:
    - crates/arc-cli/src/scim_lifecycle.rs
    - crates/arc-cli/tests/scim_lifecycle.rs
    - .planning/phases/297-scim-lifecycle-automation/297-01-SUMMARY.md
  modified:
    - crates/arc-cli/src/main.rs
    - crates/arc-cli/src/trust_control.rs
    - crates/arc-cli/src/trust_control/health.rs
    - crates/arc-cli/tests/federated_issue.rs
    - crates/arc-control-plane/src/lib.rs
    - docs/IDENTITY_FEDERATION_GUIDE.md
key-decisions:
  - "Kept SCIM lifecycle automation on the existing trust-control service boundary instead of introducing a second identity control plane."
  - "Tracked capability IDs explicitly on each SCIM lifecycle record because ARC capability lineage is not keyed by enterprise subject alone."
  - "Returned the inactive SCIM user resource on delete so clustered leader-forwarding preserves an explicit deprovisioned state contract."
patterns-established:
  - "Validated `scim` providers can require an active SCIM lifecycle record before federated issuance when lifecycle storage is configured."
  - "SCIM deprovisioning has real security effect only when capability IDs issued through the SCIM-governed lane are rebound onto the lifecycle record."
requirements-completed: [DIST-05, DIST-06]
duration: 80 min
completed: 2026-04-13
---

# Phase 297: SCIM Lifecycle Automation Summary

**Trust-control now provisions and deprovisions bounded SCIM identities, revokes tracked capability state on delete, and denies later SCIM-governed issuance for inactive identities**

## Performance

- **Duration:** 80 min
- **Started:** 2026-04-13T13:10:00Z
- **Completed:** 2026-04-13T14:29:47Z
- **Tasks:** 3
- **Files modified:** 13

## Accomplishments

- Added a file-backed SCIM lifecycle registry that stores the SCIM user
  resource, derived ARC enterprise identity context, tracked capability IDs,
  and deprovisioning metadata without creating a second identity subsystem.
- Added `POST /scim/v2/Users` and `DELETE /scim/v2/Users/{id}` on trust-control
  with validated-provider checks, leader-forwarded clustered writes, SCIM JSON
  responses, capability revocation, and signed deprovisioning receipts.
- Bound the enterprise-provider federated-issue lane to SCIM lifecycle state so
  validated `scim` providers require a matching active lifecycle record before
  issuance, successful issuance records the new capability ID, and later
  issuance fails closed after delete.
- Added black-box proving coverage for SCIM provisioning/deprovisioning plus a
  federated-issue regression showing that deprovisioned SCIM identities cannot
  receive new capabilities.
- Updated the identity federation guide so the documented SCIM boundary matches
  the shipped operator surface.

## Task Commits

No task commits were created in this workspace session.

## Files Created/Modified

- `crates/arc-cli/src/scim_lifecycle.rs` - SCIM models, ARC extension parsing,
  lifecycle registry, identity derivation, and validation helpers
- `crates/arc-cli/src/main.rs` - trust-service CLI flag wiring for
  `--scim-lifecycle-file`
- `crates/arc-cli/src/trust_control.rs` - SCIM routes, provider validation,
  lifecycle registry loading, deprovision receipt emission, and federated-issue
  lifecycle binding
- `crates/arc-cli/src/trust_control/health.rs` - federation health reporting
  for configured SCIM lifecycle storage and record counts
- `crates/arc-cli/tests/scim_lifecycle.rs` - black-box trust-control proving
  lane for SCIM create/delete behavior
- `crates/arc-cli/tests/federated_issue.rs` - fail-closed regression for
  deprovisioned SCIM identities in the federated-issue path
- `crates/arc-control-plane/src/lib.rs` - exported the shared SCIM lifecycle
  module
- `docs/IDENTITY_FEDERATION_GUIDE.md` - documented the shipped SCIM lifecycle
  operator surface and updated the current-boundaries section
- `.planning/phases/297-scim-lifecycle-automation/297-01-PLAN.md` - finalized
  touched files and verification targets
- `.planning/phases/297-scim-lifecycle-automation/297-01-SUMMARY.md` - phase
  completion record
- `.planning/ROADMAP.md`, `.planning/REQUIREMENTS.md`, `.planning/STATE.md`,
  `.planning/PROJECT.md`, `.planning/MILESTONES.md` - milestone/state
  roll-forward

## Decisions Made

- Reused the existing provider-admin registry and trust-control stores so SCIM
  lifecycle stays bounded to operator-owned ARC surfaces.
- Enforced SCIM lifecycle only for validated `scim` providers and only when the
  lifecycle registry is configured, preserving the existing non-SCIM and
  legacy-provider behavior.
- Used tracked capability IDs on the lifecycle record to make delete-driven
  revocation precise instead of trying to infer capability lineage from
  enterprise subject metadata after the fact.

## Deviations from Plan

None. The implementation followed the planned bounded-registry plus
authorization-consequence path.

## Issues Encountered

- ARC's generic `/v1/capabilities/issue` path does not know which enterprise
  identity a capability belongs to, so only the SCIM-governed federated-issue
  lane binds capability IDs automatically. The direct delete integration test
  intentionally seeds a tracked capability ID to prove revocation and receipt
  behavior on the lower-level surface.

## User Setup Required

- To enable this lane in operator environments, start `arc trust serve` with
  `--scim-lifecycle-file` alongside `--enterprise-providers-file`. Deletion
  receipts and revocations also require the existing receipt, revocation, and
  authority stores to be configured.

## Next Phase Readiness

Phase 298 can now qualify a 3-region trust-control deployment with both
permissionless federation policy and SCIM lifecycle automation present on the
clustered runtime. No repo-local blocker remains for `v2.72` phase `298`.

---
*Phase: 297-scim-lifecycle-automation*
*Completed: 2026-04-13*
