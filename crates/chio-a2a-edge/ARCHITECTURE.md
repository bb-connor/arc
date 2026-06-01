# chio-a2a-edge Architecture Note

## Current Boundaries

- `lib.rs` is the public facade. It exposes the A2A edge types and includes focused source fragments into one crate-root module.
- `config.rs` owns the advertised Agent Card settings: agent identity, endpoint URL, and protocol binding.
- `types.rs` owns the public A2A wire structs and the kernel execution context required for authoritative calls.
- `bridge.rs` owns cross-protocol bridge selection, target executor registration, bridge fidelity, skill candidate construction, and orchestration.
- `conversion.rs` owns A2A message-to-argument extraction, kernel output projection, and Chio metadata envelope construction.
- `edge.rs` owns the server object, skill publication, JSON-RPC dispatch, compatibility wrapper, and deferred task lifecycle.
- `metrics.rs` and `otel.rs` own edge-specific receipt metrics and optional GenAI span helpers.

## Pain Points

- `edge.rs` still owns multiple trust-boundary responsibilities: manifest-to-skill publication, JSON-RPC dispatch, target-skill routing, kernel execution, and deferred task lifecycle.
- JSON-RPC request-boundary parsing now lives in `jsonrpc.rs`, including non-empty `metadata.chio.targetSkillId` and `params.taskId` checks.
- `ChioA2aEdge::new` still builds Agent Card skills and authoritative skill bindings directly from manifests before calling the canonical `chio_manifest::validate_manifest` envelope gate.
- That means unsupported manifest schema versions, invalid embedded public keys, empty tool lists, invalid tool names, malformed schemas, or duplicate server-tool allowlist entries can become A2A-visible skill metadata even though manifest signing and loader paths would reject them.

## Security And API Constraints

- Public API compatibility must be preserved. Public request and response structs should not change.
- Authoritative calls must continue to route through `CrossProtocolOrchestrator` and the Chio kernel.
- Compatibility-surface helpers must remain visibly non-authoritative and feature-gated.
- Deferred task ownership must stay bound to the authenticated `agent_id`.
- Receipt metadata, capability ids, bridge route metadata, and lifecycle metadata must remain stable.
- No generated code is in scope.

## Affected Dependents

- `chio-kernel` sees this crate through kernel-mediated tool execution. No kernel API change is planned.
- `chio-cross-protocol` provides bridge and lifecycle metadata contracts. This slice should preserve those values.
- `chio-mcp-edge` remains a target executor dependency for multi-hop routes. No transitive change is planned.
- Downstream A2A clients may see construction-time manifest errors earlier. Successful Agent Card, JSON-RPC, task lifecycle, and response shapes stay compatible.

## Planned Material Improvement

Validate every `ToolManifest` with `chio_manifest::validate_manifest` before Agent Card skill publication, bridge-fidelity classification, or authoritative skill binding construction. This is architectural rather than cosmetic because it makes manifest validation the single envelope gate before external A2A discovery and keeps the existing JSON-RPC parser focused on request-boundary inputs.
