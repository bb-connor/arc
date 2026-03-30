---
phase: 13
slug: enterprise-federation-administration
status: ready
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-24
---

# Phase 13 -- Validation Strategy

> Per-phase validation contract for fast feedback during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (Rust workspace integration + unit tests) |
| **Config file** | `Cargo.toml` / crate-local `Cargo.toml` files |
| **Quick run command** | `cargo test -p arc-cli enterprise_provider -- --nocapture` |
| **Full suite command** | `cargo test --workspace` |
| **Targeted feedback loop** | 20-45 seconds per task-target pair |

---

## Sampling Rate

- **After every task commit:** Run the smallest relevant target for the touched files only.
- **After every plan:** Run the plan-local package targets, not the full workspace.
- **Before `/gsd:verify-work`:** Full suite must be green.
- **Before phase closeout:** Run `cargo test --workspace`.
- **Max targeted feedback latency:** 45 seconds.

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 13-01-01 | 01 | 1 | FED-01 | unit | `cargo test -p arc-cli enterprise_provider -- --nocapture` | ❌ W0 | ⬜ pending |
| 13-01-02 | 01 | 1 | FED-01 | compile/integration | `cargo test -p arc-cli enterprise_provider -- --nocapture` | ❌ W0 | ⬜ pending |
| 13-02-01 | 02 | 2 | FED-01 | unit/integration | `cargo test -p arc-core session -- --nocapture && cargo test -p arc-cli mcp_serve_http -- --nocapture enterprise_identity` | ❌ W0 | ⬜ pending |
| 13-02-02 | 02 | 2 | FED-01 | unit | `cargo test -p arc-cli scim_identity saml_identity enterprise_subject_key -- --nocapture` | ❌ W0 | ⬜ pending |
| 13-03-01 | 03 | 3 | FED-02 | unit | `cargo test -p arc-policy enterprise_origin -- --nocapture` | ❌ W0 | ⬜ pending |
| 13-03-02 | 03 | 3 | FED-02 | integration | `cargo test -p arc-cli federated_issue -- --nocapture` | ✅ partial | ⬜ pending |
| 13-04-01 | 04 | 4 | FED-01, FED-02 | integration | `cargo test -p arc-cli provider_admin -- --nocapture && cargo test -p arc-cli mcp_serve_http -- --nocapture` | ❌ W0 | ⬜ pending |
| 13-04-02 | 04 | 4 | FED-01, FED-02 | docs/assertion | `rg -n "enterprise-providers-file|enterprise-provider lane|attributeSources|trust_material_ref|enterprise_audit|federation/providers" docs/IDENTITY_FEDERATION_GUIDE.md docs/AGENT_PASSPORT_GUIDE.md docs/CHANGELOG.md` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] Provider-admin types, validation path, and persistence/tests in `arc-cli`
- [ ] Provider provenance and trust-boundary validation coverage in `arc-cli`
- [ ] Transport-agnostic enterprise identity normalization path or shared type in `arc-core`
- [ ] Explicit enterprise-provider lane boundary coverage for bearer vs provider-admin paths
- [ ] SCIM normalization fixtures/tests
- [ ] SAML normalization fixtures/tests
- [ ] Provider-scoped subject-key derivation coverage across bearer, SCIM, and SAML
- [ ] Policy schema/evaluator coverage for organization, groups, and roles
- [ ] Portable-trust admission provenance assertions in `federated_issue`

*Existing HTTP/admin federation tests exist, but enterprise-provider coverage is not in place yet.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Provider-admin diagnostics are understandable to operators | FED-01 | Explanation quality is partly human-judged | Exercise CLI/HTTP admin surfaces with a failing provider config and confirm the output identifies the failing field, trust anchor, and mapping clearly. |
| Enterprise-provider lane boundary is operator-comprehensible | FED-01, FED-02 | Need human confirmation that docs and output explain when legacy bearer-only admission still applies | Run one bearer-only flow without a validated provider record and one validated-provider flow, then confirm the output/docs distinguish the two paths clearly. |
| Admission/deny provenance is operationally clear | FED-02 | Need human review of final operator-facing explanations | Run one allow and one deny federated admission case, then inspect CLI/HTTP output for provider, tenant, org, role/group, subject key, and matched/missed policy clause. |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 45s for targeted loops
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** ready
