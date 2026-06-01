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

- `edge.rs` is still too broad. It mixes durable-ish deferred task lifecycle, JSON-RPC envelope validation, target-skill routing, and kernel execution orchestration.
- JSON-RPC target and task identifiers are trust-boundary inputs. They decide which Chio tool binding is invoked or which deferred task is resolved.
- `metadata.chio.targetSkillId` currently accepts empty strings at the parser boundary, then lets later lookup behavior decide the error path.
- `task/get` and `task/cancel` currently read `params.taskId` inline. Empty task ids fall through to task lookup and can return poor `ToolNotFound` errors instead of a request-boundary denial.

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
- Downstream A2A clients may see clearer JSON-RPC errors for malformed identifiers, but successful request shape and response shape stay compatible.

## Planned Material Improvement

Move JSON-RPC request-boundary parsing into its own internal source fragment and make target skill ids and task ids validate as non-empty strings before dispatch or task lookup. This is architectural rather than cosmetic because it separates protocol-boundary validation from edge execution and prevents malformed identifiers from crossing into authoritative skill or deferred-task resolution.
