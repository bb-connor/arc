Network Working Group                                          Chio Editors
Internet-Draft                                                April 2026
Intended status: Standards Track
Expires: October 2026

# The Chio Protocol

## Abstract

This document describes Chio, a protocol and runtime profile for mediated tool
execution under signed capabilities, signed receipts, explicit versioning, and
bounded transport security requirements. Chio defines a native framed transport,
an MCP-compatible hosted edge, and trust-control lifecycle endpoints for
capability issuance, delegated issuance, receipt query, and revocation.

## Status of This Memo

This Internet-Draft is submitted in full conformance with the provisions of
BCP 78 and BCP 79.

This document is not an Internet Standards Track specification; it is
published for review and discussion.

## 1. Introduction

Chio is designed to let one caller invoke one tool under explicit delegated
authority while producing signed audit receipts. The protocol surface is split
into three cooperating layers:

1. a native Chio framed transport for direct agent-to-kernel messages
2. a hosted MCP-compatible HTTP session transport
3. trust-control lifecycle APIs for issuance, delegation, receipt query, and
   revocation

The native transport alone is intentionally narrow. Chio's broader deployment
story depends on the cooperating hosted and trust-control surfaces.

## 2. Conventions And Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHOULD", "SHOULD NOT", and
"MAY" in this document are to be interpreted as described in BCP 14 when, and
only when, they appear in all capitals, as shown here.

Terms used in this document:

- capability: a signed Chio authority token
- receipt: a signed Chio audit artifact for one evaluated action
- sender constraint: proof that binds a caller to an issued capability or
  session profile
- native Chio transport: the framed transport defined in phase `311`

## 3. Protocol Surface

### 3.1 Native Chio Transport

The native Chio transport uses one frame format:

- 4-byte unsigned big-endian length prefix
- canonical JSON payload bytes

Current versioning is out-of-band exact match:

- wire version: `chio-wire-v1`
- no in-band downgrade
- incompatible peers close or reset the transport

The native message catalog contains:

- `AgentMessage`
  - `tool_call_request`
  - `list_capabilities`
  - `heartbeat`
- `KernelMessage`
  - `tool_call_chunk`
  - `tool_call_response`
  - `capability_list`
  - `capability_revoked`
  - `heartbeat`

### 3.2 Hosted MCP Transport

The hosted edge exposes:

- `POST /mcp`
- `GET /mcp`
- `DELETE /mcp`

Version selection occurs through `initialize.params.protocolVersion` and the
response echoes the selected value in `result.protocolVersion`. The current
shipped implementation supports exactly one MCP protocol version:
`2025-11-25`.

### 3.3 Trust-Control Lifecycle

The trust-control service exposes versioned HTTP endpoints under `/v1`,
including:

- capability issuance
- federated or delegated issuance
- receipt query
- revocation

Delegated issuance uses explicit continuation inputs and a signed delegation
policy ceiling when a parent capability is continued.

## 4. Error And Version Model

Chio publishes two machine-readable registries:

- `spec/versions/chio-protocol-negotiation.v1.json`
- `spec/errors/chio-error-registry.v1.json`

The negotiation artifact defines exact-match compatibility and rejection
behavior for the native, hosted, and trust-control surfaces. The error
registry defines numeric Chio error codes, categories, transient/permanent
classification, and retry guidance.

## 5. Security Considerations

The Chio threat model is defined in `spec/SECURITY.md` and the machine-readable
register `spec/security/chio-threat-model.v1.json`.

At minimum, Chio implementations need to address:

- capability token theft
- kernel impersonation
- tool-server escape
- replay on the native channel
- resource-exhaustion denial of service
- delegation-chain abuse

Transport rules are surface-specific:

- remote hosted and trust-control HTTP deployments require TLS
- cross-host tool-server transport over TCP requires mTLS
- DPoP is required when the selected sender-constrained or grant profile
  requires it
- plaintext remote deployment is nonconformant

Attestation does not authorize by itself; it is only valid when paired with
sender continuity over the same request.

## 6. Conformance

Checked-in conformance evidence for the native Chio lane lives under
`tests/conformance/native/`. The suite covers:

- capability validation
- delegation attenuation
- receipt integrity
- revocation propagation
- DPoP verification
- governed transaction enforcement

The suite is executed through JSON scenario files and language-neutral driver
contracts for `artifact`, `stdio`, and `http` execution modes.

## 7. IANA Considerations

This document has no IANA actions in its current form.

Future versions may request registrations for:

- Chio media types
- Chio protocol parameter names
- Chio error registry identifiers

## 8. References

### 8.1 Normative References

- RFC 8785, JSON Canonicalization Scheme
- RFC 9449, OAuth 2.0 Demonstrating Proof-of-Possession at the Application
  Layer (DPoP)

### 8.2 Informative References

- GNAP core work for delegated authorization continuation
- SCITT architecture and transparency evidence work
- RATS architecture for verifier-backed runtime claims
- W3C Verifiable Credentials Data Model
- OpenID for Verifiable Credential Issuance
- OpenID for Verifiable Presentations
