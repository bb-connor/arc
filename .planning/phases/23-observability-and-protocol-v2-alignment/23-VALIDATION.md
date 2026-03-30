---
phase: 23
slug: observability-and-protocol-v2-alignment
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-25
---

# Phase 23 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust integration tests plus doc contract verification with `rg` |
| **Quick run command** | `cargo test -p arc-cli --test mcp_serve_http mcp_serve_http_admin_health_reports_runtime_state -- --nocapture` |
| **Canonical verification** | targeted trust-control, hosted-edge, and certification tests plus doc checks |
| **Operational doc verification** | `rg` against `docs/release/OBSERVABILITY.md`, `docs/release/OPERATIONS_RUNBOOK.md`, and `spec/PROTOCOL.md` |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 23-01 | PROD-11 | `rg -n '/admin/health|/health|/v1/internal/cluster/status|task registry' docs/release/OBSERVABILITY.md docs/release/OPERATIONS_RUNBOOK.md docs/A2A_ADAPTER_GUIDE.md` |
| 23-02 | PROD-11 | `cargo test -p arc-cli --test mcp_serve_http mcp_serve_http_admin_health_reports_runtime_state -- --nocapture`, `cargo test -p arc-cli --test provider_admin trust_service_health_reports_enterprise_and_verifier_policy_state -- --nocapture`, `cargo test -p arc-cli --test certify certify_registry_remote_publish_list_get_resolve_and_revoke_work -- --nocapture` |
| 23-03 | PROD-12 | `rg -n 'Version:\\*\\* 2.0|Capability Contract|Receipt Contract|Trust-Control Contract|A2A Adapter Contract|Certification Contract' spec/PROTOCOL.md` |

## Coverage Notes

- trust-control and hosted-edge health are now verified against real runtime
  state instead of documentation-only claims
- the observability guide ties together the deploy-time smoke checks and the
  runtime-admin drill-down surfaces
- the protocol doc is validated as a shipped contract, not as an aspirational
  architecture whitepaper

## Sign-Off

- [x] trust-control health exposes authority, store, federation, and cluster state
- [x] hosted-edge health exposes auth, store, session, federation, and OAuth state
- [x] operators have one supported observability guide
- [x] the protocol doc matches the shipped repository profile

**Approval:** completed
