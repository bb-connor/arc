# ARC Security And Threat Model

**Version:** 1.0  
**Date:** 2026-04-13  
**Status:** Normative shipped surface

This document defines the standalone threat model for the ARC agent-kernel-tool
trust boundary. It complements [WIRE_PROTOCOL.md](WIRE_PROTOCOL.md): that
document defines message shapes and lifecycle flows; this document defines the
attacks those flows must resist and the minimum transport security posture
required for safe deployment.

The keywords **MUST**, **SHOULD**, and **MAY** are normative in this document.

## 1. Boundary

ARC's security boundary for this document is the path from one caller with
authority material to one mediated tool execution:

1. capability issuance or continuation on the trust-control surface
2. hosted or native delivery of that authority to the kernel
3. kernel admission and policy evaluation
4. transport from the kernel to the selected tool server
5. receipt generation and return

Out of scope:

- broader wallet, passport, and web3 settlement profiles except where they
  directly change sender constraint or delegation semantics at this boundary
- host OS hardening details beyond the transport and process-isolation
  requirements stated here

Primary assets protected by this boundary:

- capability tokens and delegation state
- session identifiers and sender-binding context
- kernel authenticity
- tool-server execution confinement
- receipt integrity and policy verdict provenance
- availability of the mediated runtime

The machine-readable companion artifact for this document is:

- `spec/security/arc-threat-model.v1.json`

## 2. Threat Register

The required threats for the shipped ARC boundary are:

| ID | Threat | Primary surface |
| --- | --- | --- |
| `capability_token_theft` | capability token theft or reuse by an unintended caller | trust-control, hosted MCP, native ARC |
| `kernel_impersonation` | a caller speaks to a fake kernel or hosted edge | hosted MCP, native ARC |
| `tool_server_escape` | the selected tool server exceeds its intended confinement | kernel-to-tool transport, host runtime |
| `native_channel_replay` | a captured native request or proof is replayed on the framed lane | native ARC |
| `resource_exhaustion_dos` | memory, stream, or concurrency pressure denies service | all surfaces |
| `delegation_chain_abuse` | an attacker widens, truncates, or otherwise abuses delegated authority | trust-control, kernel admission |

### 2.1 Capability Token Theft

Attack:
an attacker captures a capability token, session artifact, or other authority
handle and attempts to reuse it from a different caller or at a later time.

Existing controls:

- capabilities are signed and time-bounded
- the kernel can require ARC-native DPoP per grant
- the hosted edge can enforce sender-constrained DPoP and mTLS thumbprint
  continuity
- revocation state exists for capability identifiers

Required mitigations:

- sensitive or cross-host flows **SHOULD** require sender constraint rather
  than rely on bearer-only capability use
- operators **SHOULD** pair capability lifetimes with the smallest feasible
  validity window
- deployments that scale across restart or failover **SHOULD** use durable or
  shared replay state for sender proofs

Residual risk:

- compatibility profiles still allow bearer-style capability use when DPoP or
  equivalent sender constraint is not required
- replay protection is weaker across restart or multi-node failover when proof
  nonce state is only process-local

### 2.2 Kernel Impersonation

Attack:
the caller establishes a session or native transport with a malicious service
that pretends to be the ARC kernel or hosted edge.

Existing controls:

- capabilities and receipts are signed artifacts rather than unsigned JSON
- version negotiation is explicit on the hosted edge and exact-match on the
  native lane
- production tool-server transport is modeled as authenticated transport rather
  than anonymous raw TCP

Required mitigations:

- any cross-host hosted MCP or trust-control deployment **MUST** use TLS
- any cross-host native deployment **MUST** use TLS and **MUST** authenticate
  the remote peer before authority is treated as valid
- operator distributions **SHOULD** pin or otherwise securely provision ARC
  verifier keys, service certificates, or equivalent trust anchors

Residual risk:

- plaintext local-development modes do not provide confidentiality or peer
  authenticity
- receipt verification still depends on the deployment's trust-anchor
  distribution discipline rather than one public transparency system

### 2.3 Tool Server Escape

Attack:
an admitted tool server process reads or mutates host state outside its
intended scope, or uses the kernel as a path to broader host compromise.

Existing controls:

- capability scope, tool name, and server id are mediated before invocation
- the kernel decides admission before any tool call reaches the server
- production tool-server transport is modeled as isolated transport rather than
  direct in-process mutation of kernel state

Required mitigations:

- tool servers **MUST** be treated as less trusted than the kernel unless they
  are part of the same reviewed binary and privilege domain
- cross-process or cross-host tool servers **MUST** run behind authenticated
  transport, and cross-host TCP **MUST** use mTLS
- operators **SHOULD** pair ARC mediation with OS or container confinement,
  least-privilege filesystem access, and outbound-network controls where the
  tool is not inherently trusted

Residual risk:

- ARC mediation cannot by itself sandbox arbitrary tool-server code
- a compromised tool process can still abuse whatever host privileges the
  operator granted it outside ARC

### 2.4 Native Channel Replay

Attack:
an attacker captures a native ARC frame or proof and replays it on the
length-prefixed channel to obtain duplicate or unauthorized execution.

Existing controls:

- the native lane is framed and typed, which limits parser ambiguity
- DPoP proofs can bind a request to capability id, tool target, action hash,
  sender key, freshness, and nonce uniqueness
- capabilities are time-bounded and can be revoked

Required mitigations:

- grants for replay-sensitive operations **SHOULD** require DPoP
- cross-host native traffic **MUST** use confidential authenticated transport
  so raw frames and proofs are not exposed on the network
- clustered or restart-tolerant deployments **SHOULD** avoid process-local-only
  nonce registries for high-value flows

Residual risk:

- the native framed lane has no independent in-band anti-replay marker outside
  the sender-proof and capability systems
- non-DPoP grants remain replayable within their validity window if the
  surrounding transport is exposed

### 2.5 Resource Exhaustion DoS

Attack:
an attacker attempts to consume memory, CPU, stream slots, or request capacity
to deny service to valid callers.

Existing controls:

- native frames larger than `16 MiB` are rejected
- hosted notification streams allow at most one active stream per session
- hosted sessions have explicit terminal states rather than silent resumption

Required mitigations:

- deployments **SHOULD** apply request-rate, concurrency, and time-budget
  limits at the hosted and trust-control edges
- operators **SHOULD** bound retained replay buffers, task queues, and
  per-session state
- high-value multi-tenant deployments **SHOULD** pair ARC with upstream load
  shedding and admission control

Residual risk:

- authenticated callers can still consume their own allowed budgets or queue
  share
- ARC's current size and lifecycle checks reduce but do not eliminate all
  asymmetric workload attacks

### 2.6 Delegation Chain Abuse

Attack:
an attacker attempts to widen scope during delegation, truncate lineage,
continue from the wrong parent, or exploit incomplete recursive validation.

Existing controls:

- trust-control delegated issuance already checks a signed delegation policy
  ceiling when one is supplied
- core helpers exist for delegation-chain validation and attenuation checks
- revocation state exists for capability identifiers

Required mitigations:

- delegated issuance **MUST NOT** exceed the signed delegation-policy ceiling
- runtime admission **SHOULD** resolve and validate complete parent lineage for
  high-trust delegated flows rather than trust presented metadata alone
- operators **SHOULD** revoke parent capabilities or delegation branches when
  downstream compromise is suspected

Residual risk:

- the current runtime boundary is stronger than unchecked delegation metadata
  but not yet a universally recursive, fail-closed delegated-authority proof
  system at every entry point
- revocation completeness is only as strong as the resolved lineage available
  to the runtime

## 3. Transport Security Requirements

Transport requirements are surface-specific. The matrix below defines the
minimum shipped rules.

| Surface | TLS requirement | mTLS requirement | DPoP requirement | When transport security is absent |
| --- | --- | --- | --- | --- |
| Native ARC direct transport | **MUST** use TLS for any cross-host or untrusted-network deployment. Same-host UDS or loopback development **MAY** omit TLS. | **MUST** use mTLS when the remote peer identity is itself part of the authorization trust decision or when operators cross an untrusted boundary. | **MUST** use DPoP whenever the matched grant requires it. | Only same-host UDS or loopback development is conformant. Otherwise the deployment is nonconformant and capability/session material is considered exposed. |
| Hosted MCP HTTP (`/mcp`) | **MUST** use TLS for any remote or non-loopback deployment. Plain HTTP is only for loopback or explicit test harnesses. | **MUST** use mTLS when the active sender-constrained session profile binds to an mTLS thumbprint. Otherwise mTLS is optional, not universal. | **MUST** use DPoP when the active sender-constrained profile or downstream matched grant requires it. Missing required proof is a denial, not a downgrade. | Remote plaintext deployment is nonconformant. Session ids, proofs, and authority material are treated as observable and replayable. |
| Trust-control HTTP (`/v1/...`) | **MUST** use TLS for any remote or non-loopback deployment. Plain HTTP is only for local development and test harnesses. | **MUST** use mTLS for operator-internal service-to-service deployments that rely on transport identity rather than bearer auth alone. | DPoP is not the primary trust-control transport mechanism today. If sender-constrained issuance inputs are used, the receiving profile **MUST** preserve their required proof semantics downstream. | Remote plaintext deployment is nonconformant and downgrades issuance, revocation, and receipt-query confidentiality and authenticity to local-dev-only posture. |
| Kernel-to-tool transport | Same-host UDS **SHOULD** be preferred. If TCP or another network transport is used, TLS is implicit in the mTLS requirement. | Cross-host or cross-process TCP transport **MUST** use mTLS. Same-host UDS does not need mTLS because the OS path is the authenticated boundary. | DPoP does not replace kernel-to-tool transport authentication. Sender proof binds the caller to the capability, not the tool server to the kernel. | Unauthenticated network transport is nonconformant for production. Tool identity and confidentiality are not established. |

Additional rules:

- Attestation alone never substitutes for sender proof. If a profile binds an
  attestation digest, it **MUST** still pair that with DPoP or mTLS continuity
  over the same request.
- A deployment **MUST NOT** claim production-grade impersonation resistance,
  confidentiality, or replay resistance when it intentionally operates on
  plaintext remote transports.
- If a required transport security property is missing, the implementation
  **MUST** deny the request or restrict the deployment to an explicitly local
  development posture.

## 4. Implementation Guidance

- Same-host development can rely on loopback or UDS transport, but that is a
  deployment carve-out, not a general weakening of the production rules.
- Cross-host deployments should treat sender constraint and transport
  authentication as complementary:
  transport authentication proves the service identity; DPoP proves caller
  possession of the sender-bound key.
- Tool servers are not made safe by transport security alone. ARC mediation
  protects admission and auditability, but host-level sandboxing remains the
  operator's responsibility.

## 5. Machine-Readable Register

`spec/security/arc-threat-model.v1.json` is the normative machine-readable
representation of:

- the minimum threat set
- the mitigation and residual-risk mapping for each threat
- the transport requirements per surface

Implementations and future standards work **SHOULD** treat that artifact as the
stable registry for phase `313`.
