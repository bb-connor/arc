---
phase: 313
plan: 02
created: 2026-04-13
status: complete
---

# Summary 313-02

Phase `313` also turned the threat model into a checked-in machine-readable
contract.

- `spec/security/arc-threat-model.v1.json` records the required threats,
  mitigation/residual-risk mapping, and the transport requirements for native
  ARC, hosted MCP HTTP, trust-control HTTP, and kernel-to-tool transport.
- `spec/SECURITY.md` now freezes when TLS is required, when mTLS becomes
  mandatory, when DPoP is required, and what happens when transport security is
  absent.
- `crates/arc-core-types/tests/threat_model_artifacts.rs` validates that the
  required threat set and surface-specific transport requirements stay present
  over time.
- `spec/WIRE_PROTOCOL.md` now points readers at the new security spec so the
  transport and threat-model documents stay discoverable together.

This gives phase `314` a stable security registry it can reference when adding
native conformance and standards-facing artifacts.
