---
phase: 23
slug: observability-and-protocol-v2-alignment
status: passed
completed: 2026-03-25
---

# Phase 23 Verification

Phase 23 passed. The runtime now exposes a supported production diagnostics
contract and `spec/PROTOCOL.md` aligns to the shipped `v2` repository profile.

## Automated Verification

- `cargo clippy -p arc-cli -- -D warnings`
- `cargo test -p arc-cli --test mcp_serve_http mcp_serve_http_admin_health_reports_runtime_state -- --nocapture`
- `cargo test -p arc-cli --test provider_admin trust_service_health_reports_enterprise_and_verifier_policy_state -- --nocapture`
- `cargo test -p arc-cli --test certify certify_registry_remote_publish_list_get_resolve_and_revoke_work -- --nocapture`
- `rg -n '/admin/health|/health|/v1/internal/cluster/status|task registry' docs/release/OBSERVABILITY.md docs/release/OPERATIONS_RUNBOOK.md docs/A2A_ADAPTER_GUIDE.md`
- `rg -n 'Version:\\*\\* 2.0|Capability Contract|Receipt Contract|Trust-Control Contract|A2A Adapter Contract|Certification Contract' spec/PROTOCOL.md`

## Result

Passed. Phase 23 now satisfies `PROD-11` and `PROD-12`:

- trust-control and hosted-edge health surfaces expose operator-meaningful
  authority, store, federation, session, and cluster state
- the runbook and observability guide define how operators should use those
  surfaces in production
- the protocol document now describes the real capability, receipt, portable
  trust, federation, A2A, and certification contract instead of the older
  pre-RFC draft
