---
phase: 313-threat-model-and-security-specification
created: 2026-04-13
status: complete
---

# Phase 313 Research

## Sources Reviewed

- `spec/WIRE_PROTOCOL.md`
- `spec/PROTOCOL.md`
- `crates/arc-kernel/src/runtime.rs`
- `crates/arc-kernel/src/dpop.rs`
- `crates/arc-cli/src/remote_mcp/http_service.rs`
- `docs/review/02-delegation-enforcement-remediation.md`
- `docs/review/03-runtime-attestation-remediation.md`
- `docs/review/05-non-repudiation-remediation.md`
- `docs/review/06-authentication-dpop-remediation.md`
- `docs/review/09-session-isolation-remediation.md`

## Findings

1. ARC already has concrete controls that belong in a threat model:
   signed capabilities and receipts, time-bounded capabilities, ARC-native
   DPoP verification, hosted sender-constrained session admission, revocation
   state, size limits on native frames, and explicit hosted session lifecycle
   states.
2. ARC also has known gaps that must be stated as residual risk rather than
   silently erased:
   replay stores are not yet durable across restart/failover, session reuse is
   narrower than a full immutable security-context comparison, and delegation
   enforcement is not yet a universally recursive admission dependency.
3. Transport security requirements need to be defined per surface, not as one
   project-wide slogan:
   native direct transport, hosted MCP HTTP, trust-control HTTP, and
   kernel-to-tool transport do not share the same TLS/mTLS/DPoP rules.

## Resulting Direction

- Add a standalone `spec/SECURITY.md` that names the concrete surfaces and
  lists the mandatory threats from the roadmap.
- Add a machine-readable threat register so the minimum threat set and
  transport rules can be validated in tests.
- Keep the security language honest:
  when a mitigation is compatibility-profile dependent or still needs stronger
  runtime enforcement, say so directly in the residual-risk field.
