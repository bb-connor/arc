---
phase: 13
slug: enterprise-federation-administration
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-24
---

# Phase 13 -- Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (Rust workspace integration + unit tests) |
| **Config file** | `Cargo.toml` / crate-local `Cargo.toml` files |
| **Quick run command** | `cargo test -p pact-cli --test mcp_serve_http --test federated_issue && cargo test -p pact-policy` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~90 seconds |

---

## Sampling Rate

- **After every task commit:** Run the smallest relevant target for touched files (`pact-policy`, `mcp_serve_http`, `federated_issue`, or new provider-admin tests)
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 90 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 13-01-01 | 01 | 1 | FED-01 | integration | `cargo test -p pact-cli provider_admin` | ❌ W0 | ⬜ pending |
| 13-02-01 | 02 | 1 | FED-01 | unit/integration | `cargo test -p pact-cli scim_identity saml_identity` | ❌ W0 | ⬜ pending |
| 13-03-01 | 03 | 2 | FED-02 | unit | `cargo test -p pact-policy enterprise_origin` | ❌ W0 | ⬜ pending |
| 13-04-01 | 04 | 2 | FED-01, FED-02 | integration | `cargo test -p pact-cli --test mcp_serve_http --test federated_issue` | ✅ partial | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] Provider-admin types, validation path, and persistence/tests in `pact-cli`
- [ ] Transport-agnostic enterprise identity normalization path or shared type in `pact-core`
- [ ] SCIM normalization fixtures/tests
- [ ] SAML normalization fixtures/tests
- [ ] Policy schema/evaluator coverage for organization, groups, and roles
- [ ] Portable-trust admission provenance assertions in `federated_issue`

*Existing HTTP/admin federation tests exist, but enterprise-provider coverage is not in place yet.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Provider-admin diagnostics are understandable to operators | FED-01 | Explanation quality is partly human-judged | Exercise CLI/HTTP admin surfaces with a failing provider config and confirm the output identifies the failing field/trust anchor/mapping clearly |
| Admission/deny provenance is operationally clear | FED-02 | Need human review of final operator-facing explanations | Run one allow and one deny federated admission case, then inspect CLI/HTTP output for provider, tenant, org, role/group, subject key, and matched/missed policy clause |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 90s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
