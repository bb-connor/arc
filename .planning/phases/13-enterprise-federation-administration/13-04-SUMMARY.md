---
phase: 13-enterprise-federation-administration
plan: 04
subsystem: federation
tags:
  - enterprise-federation
  - provider-admin
  - docs
  - trust-control
requires:
  - 13-01
  - 13-02
  - 13-03
provides:
  - Operators can manage provider records through explicit CLI and HTTP surfaces
  - Invalid provider records remain visible with validation errors
  - Operator docs now describe the enterprise-provider lane and enterprise audit fields truthfully
key-files:
  created:
    - .planning/phases/13-enterprise-federation-administration/13-04-SUMMARY.md
    - crates/arc-cli/tests/provider_admin.rs
  modified:
    - crates/arc-cli/src/main.rs
    - crates/arc-cli/src/trust_control.rs
    - crates/arc-cli/src/enterprise_federation.rs
    - crates/arc-cli/tests/federated_issue.rs
    - crates/arc-cli/tests/mcp_serve_http.rs
    - docs/IDENTITY_FEDERATION_GUIDE.md
    - docs/AGENT_PASSPORT_GUIDE.md
    - docs/CHANGELOG.md
requirements-completed:
  - FED-01
  - FED-02
completed: 2026-03-24
---

# Phase 13 Plan 04 Summary

Phase 13 now has operator-facing administration and diagnostics instead of
only bearer-auth alpha internals.

## Accomplishments

- Added `arc trust provider list|get|upsert|delete` for local file-backed
  provider-admin workflows and matching trust-control HTTP routes under
  `/v1/federation/providers`
- Reused the shared enterprise provider registry so HTTP and CLI admin paths
  see the same validation results and trust-boundary metadata
- Added provider-admin integration coverage for both the local CLI workflow
  and HTTP visibility of invalid provider records
- Expanded federated issue integration coverage for allow, deny, legacy
  bearer fallback, and invalid-provider no-fallback behavior
- Updated identity-federation, passport, and changelog docs to describe the
  shipped provider-admin workflow and enterprise audit fields

## Verification

- `cargo test -p arc-cli --test provider_admin -- --nocapture`
- `cargo test -p arc-cli --test mcp_serve_http -- --nocapture`
- `cargo test -p arc-cli --test federated_issue -- --nocapture`
- `rg -n "enterprise-providers-file|SCIM|SAML|enterprise_audit|enterpriseAudit|provider-admin|federation/providers|enterprise-provider lane|attributeSources|trust_material_ref|trustMaterialRef" docs/IDENTITY_FEDERATION_GUIDE.md docs/AGENT_PASSPORT_GUIDE.md docs/CHANGELOG.md`

## Notes

No code commit was created for this slice because the current branch already
contains extensive unrelated tracked and untracked work; the implementation
was kept additive-only to avoid disturbing that state.
