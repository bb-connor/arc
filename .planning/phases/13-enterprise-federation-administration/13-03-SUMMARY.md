---
phase: 13-enterprise-federation-administration
plan: 03
subsystem: federation
tags:
  - enterprise-federation
  - policy
  - trust-control
  - portable-trust
requires:
  - 13-01
  - 13-02
provides:
  - Enterprise origin policy now matches provider, tenant, organization, groups, and roles explicitly
  - Federated issue now distinguishes legacy bearer observability from the validated enterprise-provider lane
  - Allow and deny outcomes preserve structured enterprise admission audit context
key-files:
  created:
    - .planning/phases/13-enterprise-federation-administration/13-03-SUMMARY.md
  modified:
    - crates/arc-policy/src/models.rs
    - crates/arc-policy/src/evaluate.rs
    - crates/arc-policy/src/lib.rs
    - crates/arc-cli/src/trust_control.rs
    - crates/arc-cli/src/main.rs
    - crates/arc-cli/tests/federated_issue.rs
requirements-completed:
  - FED-02
completed: 2026-03-24
---

# Phase 13 Plan 03 Summary

Enterprise origin matching is now first-class in `arc-policy`, and
trust-control uses that richer origin context when a request enters the
enterprise-provider lane.

## Accomplishments

- Added `organization_id`, `groups`, and `roles` to the shared origin policy
  model and enforced explicit subset matching without falling back to
  `actor_role`
- Added `selected_origin_profile_id` so trust-control can reuse the shared
  origin matcher instead of inventing a parallel enterprise-only evaluator
- Extended `trust federated-issue` with optional admission-policy and
  enterprise-identity payloads
- Defined the lane boundary explicitly: bearer observability without a
  validated provider record stays on the legacy path, while a validated
  provider record activates fail-closed enterprise admission
- Added `enterpriseAudit` / `enterprise_audit` on federated issue results and
  structured deny bodies

## Verification

- `cargo test -p arc-policy enterprise_origin -- --nocapture`
- `cargo test -p arc-cli --test federated_issue -- --nocapture`

## Notes

No task-level code commit was created for this slice because the branch
already contains extensive unrelated in-flight work and this autonomous pass
preserved that mixed working tree.
