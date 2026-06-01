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
- `capabilityId` is the authority selector for permission preview, invoke, and stream entrypoints. It currently defaults to an empty string when missing or non-string.
- Empty or malformed capability ids can cross into capability lookup, permission-deny behavior, or source-envelope construction instead of being rejected at the protocol boundary.
- `taskId` for `tool/cancel` and `tool/resume` is parsed inline. Empty ids currently fall through to deferred-task lookup and produce poor task-not-found errors.

## Security And API Constraints

- Public Rust structs and method signatures must remain compatible.
- Authoritative invocation must continue through `CrossProtocolOrchestrator` and the Chio kernel.
- Permission preview remains preview-only and must not imply receipt-bearing execution.
- Compatibility-surface helpers must remain visibly non-authoritative and feature-gated.
- Deferred task ownership must stay bound to the authenticated `agent_id`.
- Receipt metadata, bridge route metadata, and lifecycle metadata must remain stable for valid requests.
- The `fuzz` feature must keep exercising the JSON-RPC handler without pulling fuzz dependencies into default builds.

## Affected Dependents

- `chio-kernel` remains the execution authority. No kernel API change is planned.
- `chio-cross-protocol` supplies bridge and lifecycle metadata. This slice should preserve those contracts.
- `chio-mcp-edge` remains a target executor dependency for multi-hop routes. No transitive edit is planned.
- ACP clients may see clearer JSON-RPC invalid-params errors for malformed identifiers, while valid request and response shapes stay compatible.

## Planned Material Improvement

Move ACP JSON-RPC request-boundary parsing into its own internal source fragment and validate `capabilityId` / `taskId` as non-empty strings before permission preview, invocation, stream creation, cancellation, or resume. This is architectural because it separates protocol-boundary validation from edge execution and prevents malformed authority selectors from crossing into kernel-routing and deferred-task state.
