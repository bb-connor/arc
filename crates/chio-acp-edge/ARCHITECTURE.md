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

- `edge.rs` still mixes JSON-RPC request-boundary parsing with permission and execution logic.
- `session/request_permission` runs a DPoP preview before `tool/invoke`, but the preview path has used `DpopConfig::default()` instead of the DPoP configuration installed on the kernel.
- DPoP preview must not consume the replay nonce, but it still has to match the kernel's TTL and clock-skew policy or ACP can preview Allow for an invocation the kernel will deny.
- The kernel currently keeps its DPoP verifier private to invocation, so ACP has no authoritative stateless verifier to call for permission preview.

## Security And API Constraints

- Public Rust structs and method signatures must remain compatible.
- Authoritative invocation must continue through `CrossProtocolOrchestrator` and the Chio kernel.
- Permission preview remains preview-only, must not imply receipt-bearing execution, and must not consume the DPoP nonce that invoke will later spend.
- Compatibility-surface helpers must remain visibly non-authoritative and feature-gated.
- Deferred task ownership must stay bound to the authenticated `agent_id`.
- Receipt metadata, bridge route metadata, and lifecycle metadata must remain stable for valid requests.
- The `fuzz` feature must keep exercising the JSON-RPC handler without pulling fuzz dependencies into default builds.

## Affected Dependents

- `chio-kernel` remains the execution authority and must expose only a stateless DPoP preview verifier, not its nonce store internals.
- `chio-cross-protocol` supplies bridge and lifecycle metadata. This slice should preserve those contracts.
- `chio-mcp-edge` remains a target executor dependency for multi-hop routes. No transitive edit is planned.
- ACP clients may see `session/request_permission` Deny when a DPoP proof fails the kernel's configured TTL or clock-skew policy. Valid request and response shapes stay compatible.

## Planned Material Improvement

Route kernel-backed ACP permission preview through a kernel-owned stateless DPoP verifier that uses the installed DPoP config and verifies store/config presence without consuming the nonce. This is architectural because it keeps DPoP policy authority in `chio-kernel`, keeps ACP preview non-mutating, and makes `session/request_permission` and `tool/invoke` agree on sender-bound capability admission.
