---
phase: 313-threat-model-and-security-specification
created: 2026-04-13
status: complete
---

# Phase 313 Validation

## Required Evidence

- A standalone security specification exists and covers the agent-kernel-tool
  trust boundary without relying on remediation memos for the primary model.
- The threat register enumerates at minimum:
  - capability token theft
  - kernel impersonation
  - tool server escape
  - native-channel replay
  - resource-exhaustion denial of service
  - delegation-chain abuse
- Every threat entry records:
  - existing or planned mitigations
  - an explicit residual-risk statement
- Transport requirements explicitly state:
  - when TLS is required
  - when mTLS is required
  - when DPoP is required
  - what happens when transport security is absent
- The machine-readable artifact is checked in and validated by tests.

## Verification Commands

- `cargo test -p arc-core-types threat_model_`
- `git diff --check -- spec/SECURITY.md spec/security/arc-threat-model.v1.json spec/WIRE_PROTOCOL.md crates/arc-core-types/tests/threat_model_artifacts.rs .planning/phases/313-threat-model-and-security-specification`

## Regression Focus

- security guidance does not accidentally claim universal sender constraint for
  all shipped flows
- transport requirements stay surface-specific rather than collapsing hosted,
  native, and kernel-to-tool lanes into one rule
- every required threat remains represented in both the prose doc and the
  machine-readable register
