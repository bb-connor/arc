# chio-acp-edge Architecture Note

## Current Boundaries

- `lib.rs` is the public facade. It exposes ACP edge types and includes focused source fragments into one crate-root module.
- `config.rs` owns permission defaults and the fallback ACP category for discovered tools.
- `types.rs` owns public ACP capability, permission, invocation, deferred-task, and kernel execution-context structs.
- `bridge.rs` owns cross-protocol bridge selection, ACP category inference, bridge fidelity, target bindings, deferred-task limits, and orchestration.
- `conversion.rs` owns kernel-output projection, ACP source envelopes, surface metadata, lifecycle metadata, and permission-preview metadata.
- `edge.rs` owns the server object, capability publication, JSON-RPC dispatch, permission preview, invocation, compatibility wrapper, and deferred task lifecycle.
- `fuzz.rs` owns the optional fuzz-only JSON-RPC decode pipeline behind the `fuzz` feature.

## Pain Points

- `edge.rs` still owns multiple trust-boundary responsibilities: manifest-to-capability publication, JSON-RPC dispatch, permission preview, kernel execution, and deferred task lifecycle.
- Kernel-backed ACP permission preview now uses the kernel-owned stateless DPoP verifier, so preview and invoke agree on installed DPoP TTL, skew, and store/config presence without consuming the nonce.
- `ChioAcpEdge::new` still maps manifests directly into advertised ACP capabilities and authoritative target bindings before calling the canonical `chio_manifest::validate_manifest` envelope gate.
- That means unsupported manifest schema versions, invalid embedded public keys, empty tool lists, invalid tool names, malformed schemas, or duplicate server-tool allowlist entries can become ACP-visible capability metadata even though manifest signing and loader paths would reject them.

## Security And API Constraints

- Public Rust structs and method signatures must remain compatible.
- Authoritative invocation must continue through `CrossProtocolOrchestrator` and the Chio kernel.
- Permission preview remains preview-only, must not imply receipt-bearing execution, and must not consume the DPoP nonce that invoke will later spend.
- Compatibility-surface helpers must remain visibly non-authoritative and feature-gated.
- Deferred task ownership must stay bound to the authenticated `agent_id`.
- Receipt metadata, bridge route metadata, and lifecycle metadata must remain stable for valid requests.
- The `fuzz` feature must keep exercising the JSON-RPC handler without pulling fuzz dependencies into default builds.

## Affected Dependents

- `chio-kernel` remains the execution authority and DPoP preview verifier.
- `chio-cross-protocol` supplies bridge and lifecycle metadata. This slice should preserve those contracts.
- `chio-mcp-edge` remains a target executor dependency for multi-hop routes. No transitive edit is planned.
- ACP clients may see construction-time manifest errors earlier. Valid capability, permission, invocation, and deferred-task response shapes stay compatible.

## Planned Material Improvement

Validate every `ToolManifest` with `chio_manifest::validate_manifest` before ACP capability publication, bridge-fidelity classification, or authoritative capability binding construction. This is architectural because it makes manifest validation the single envelope gate before external ACP discovery and keeps permission preview focused on request-time admission.
