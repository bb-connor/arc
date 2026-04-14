---
phase: 313-threat-model-and-security-specification
milestone: v2.82
created: 2026-04-13
status: complete
---

# Phase 313 Context

## Goal

Publish a standalone threat model for the agent-kernel-tool trust boundary
that names the concrete ARC attack surfaces, maps each required threat to real
shipped controls or explicit planned mitigations, and freezes transport
security requirements tightly enough for protocol consumers and operators to
implement safely.

## Current Reality

- `spec/WIRE_PROTOCOL.md` defines the framed native lane and the hosted
  surfaces, but it intentionally stops short of being a security specification.
- The repo already contains useful security analysis, but it is scattered
  across remediation memos rather than expressed as one normative ARC threat
  model:
  - `docs/review/02-delegation-enforcement-remediation.md`
  - `docs/review/03-runtime-attestation-remediation.md`
  - `docs/review/05-non-repudiation-remediation.md`
  - `docs/review/06-authentication-dpop-remediation.md`
  - `docs/review/09-session-isolation-remediation.md`
- The shipped implementation already exposes some transport-security facts that
  the spec should not contradict:
  - native tool invocations can require ARC-native DPoP proofs
  - the hosted edge can enforce sender-constrained DPoP and mTLS thumbprint
    continuity
  - production tool-server connections are modeled as mTLS over UDS or TCP

## Boundaries

- Be explicit about what is already enforced versus what remains a planned
  mitigation. Phase `313` must not turn remediation ambitions into false
  present-tense guarantees.
- Keep the deliverable focused on the agent-kernel-tool trust boundary rather
  than the repo's broader web3, wallet, or passport surfaces.
- Do not disturb the unrelated dirty planning files already present in the
  worktree.

## Key Risks

- If the threat model overstates current delegation or replay defenses, the
  resulting spec will be easier to read but technically false.
- If transport requirements fail to distinguish same-host development from
  cross-host production, operators will misread "TLS required" or "mTLS
  required" as blanket statements detached from the actual shipped surfaces.
- If the machine-readable artifact does not encode the mandatory threats and
  transport rules, later phases will have nothing concrete to build standards
  and conformance work on top of.

## Decision

Publish two coupled artifacts:

1. `spec/SECURITY.md` as the standalone normative threat model and transport
   security specification.
2. `spec/security/arc-threat-model.v1.json` as the machine-readable register
   that records the mandatory threats, their mitigations, residual risks, and
   the transport requirements that phase `314` can reference.
