---
phase: 31
slug: protocol-artifact-and-identity-migration
status: completed
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-25
---

# Phase 31 -- Validation Strategy

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | targeted crate checks/tests plus spec/doc compatibility grep |
| **Workspace checks** | `cargo check -p arc-kernel -p arc-credentials -p arc-cli` |
| **Kernel validation** | `cargo test -p arc-kernel -- --nocapture` |
| **Credential validation** | `cargo test -p arc-credentials -- --nocapture` |
| **CLI compatibility validation** | `cargo test -p arc-cli --test certify --test passport --test provider_admin --test mcp_serve_http --test federated_issue --test evidence_export -- --nocapture` |
| **Spec/doc grep** | `rg -n 'did:arc|did:arc|arc\\.|arc\\.' spec/PROTOCOL.md docs/standards/ARC_PORTABLE_TRUST_PROFILE.md docs/AGENT_PASSPORT_GUIDE.md docs/DID_ARC_METHOD.md docs/standards/ARC_IDENTITY_TRANSITION.md docs/release/OPERATIONS_RUNBOOK.md docs/release/ARC_RENAME_MIGRATION.md` |

## Per-Plan Verification Map

| Plan | Requirement | Verification |
|------|-------------|--------------|
| 31-01 | ARC-04, ARC-05 | targeted schema/registry tests in `arc-kernel`, `arc-credentials`, `certify`, `passport`, `provider_admin`, `federated_issue`, and `evidence_export` |
| 31-02 | ARC-04, ARC-05 | `mcp_serve_http` runtime-env alias coverage plus operations/migration-doc grep |
| 31-03 | ARC-04, ARC-05, ARC-06 | protocol and portable-trust doc grep for ARC-vs-ARC issuance semantics and `did:arc` / `did:arc` contract |

## Coverage Notes

- this phase intentionally keeps legacy `arc.*` verification/import behavior
  explicit instead of pretending old artifacts disappeared
- `did:arc` is treated as a frozen compatibility method, not force-migrated
  mid-release
- ARC-branded issuance only claims surfaces that are actually implemented in
  code; frozen markers such as `arc.manifest.v1` remain documented as frozen

## Sign-Off

- [x] new issuance uses ARC-primary protocol and artifact markers where shipped
- [x] legacy PACT artifacts remain verifiable or importable under an explicit
  compatibility contract
- [x] the `did:arc` / `did:arc` transition is documented as one coherent model
- [x] spec, operator docs, and migration docs match the implementation

**Approval:** completed
