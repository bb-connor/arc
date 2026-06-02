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
- `ChioA2aEdge::new` now validates every manifest with
  `chio_manifest::validate_manifest` before Agent Card skill publication,
  bridge-fidelity classification, or authoritative skill binding construction.
- `jsonrpc.rs` now owns a centralized known-method params-object gate used by
  both authoritative and compatibility dispatch. Missing params remain
  compatible as `{}`, unknown methods still return method-not-found, and
  non-object params for known A2A methods fail with `-32602` before message
  parsing, task lookup, or deferred lifecycle mutation can observe malformed
  params.

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

## Completed Baseline

Validate every `ToolManifest` with `chio_manifest::validate_manifest` before Agent Card skill publication, bridge-fidelity classification, or authoritative skill binding construction. This is architectural rather than cosmetic because it makes manifest validation the single envelope gate before external A2A discovery and keeps the existing JSON-RPC parser focused on request-boundary inputs.

## Completed Material Improvement

Added a centralized known-method params-object gate for the authoritative and
compatibility JSON-RPC dispatch paths. Missing params remain compatible as `{}`,
unknown methods still return method-not-found, and non-object params for known
A2A methods fail with `-32602` before message parsing, task lookup, or deferred
lifecycle mutation can observe malformed params.

## Deferred Terminal Task Retention Slice

### Current Boundary

- `edge.rs` owns the authoritative `message/stream`, `task/get`, and
  `task/cancel` lifecycle.
- `conversion.rs` owns terminal `TaskResponse` construction and receipt-bearing
  metadata projection.
- `bridge.rs` owns the bounded deferred-task cap and TTL constants.

### Pain Point

The A2A bridge contract says `task/get` executes a working deferred task once
and then persists the terminal result. The current edge updates the stored
response after execution but immediately removes the task record. It also
removes cancelled tasks after returning the cancellation response. That makes a
follow-up `task/get` or idempotent `task/cancel` see `tool not found` instead
of the already-produced terminal task response, and it loses the owner-bound
task state that proves the terminal receipt or cancellation belonged to the
same caller.

Terminal retention also has to count against the deferred task cap. Otherwise
callers can repeatedly create streams, resolve or cancel them, and retain
terminal entries until TTL expiry without consuming pending-task capacity.

### Security And API Constraints

- Preserve public API and wire structs.
- Preserve owner binding for all task states.
- Do not re-execute the kernel-backed deferred request after the first
  successful `task/get`.
- Keep task retention bounded by the existing TTL and deferred-task cap.
- Preserve signed receipt metadata on completed or failed terminal responses
  and cancellation metadata on cancelled responses.

### Affected Dependents

- A2A clients can now repeat `task/get` after completion and receive the same
  terminal response until TTL expiry instead of `tool not found`.
- `task/cancel` remains able to cancel only working tasks; repeated cancel for
  an already cancelled task returns the retained cancelled response.
- `chio-kernel`, `chio-cross-protocol`, and `chio-mcp-edge` APIs are unchanged.

### Completed Material Improvement

Retain terminal deferred-task responses in the internal task map until the
existing TTL expires, while preserving owner checks and bounded capacity.
Update lifecycle tests to prove completed tasks are not re-executed or removed
on the first `task/get`, cancelled tasks remain visible for idempotent
follow-up, and the deferred-task cap applies to all retained task records after
TTL pruning.
