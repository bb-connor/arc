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
- `ChioAcpEdge::new` now validates every manifest with
  `chio_manifest::validate_manifest` before ACP capability publication,
  bridge-fidelity classification, or authoritative capability binding
  construction.
- The remaining request-boundary gap is JSON-RPC params shape. The envelope
  parser defaults missing params to `{}`, but non-object params are preserved.
  Known ACP methods then fall through into method-specific parsers or no-params
  responses, producing deeper errors or successful responses instead of
  rejecting malformed request params at the JSON-RPC boundary.

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

## Completed Baseline

Validate every `ToolManifest` with `chio_manifest::validate_manifest` before ACP capability publication, bridge-fidelity classification, or authoritative capability binding construction. This is architectural because it makes manifest validation the single envelope gate before external ACP discovery and keeps permission preview focused on request-time admission.

## Completed Material Improvement

Added a centralized known-method params-object gate for authoritative and
compatibility JSON-RPC dispatch. Missing params remain compatible as `{}`,
unknown methods still return method-not-found, and non-object params for known
ACP methods fail with `-32602` before permission preview, invocation parsing,
task lifecycle lookup, or capability listing can observe malformed params.

## Deferred Terminal Task Retention Slice

### Current Boundary

- `edge.rs` owns the authoritative `tool/stream`, `tool/resume`, and
  `tool/cancel` lifecycle.
- `conversion.rs` owns receipt-bearing `AcpInvocationResult` construction and
  pending/cancelled lifecycle metadata.
- `bridge.rs` owns the bounded deferred-task cap and TTL constants.

### Pain Point

The ACP lifecycle contract advertises deferred `tool/stream` tasks resolved by
`tool/resume` with `resumed_terminal_payload` delivery. The edge now retains
completed, failed, and cancelled task records until TTL expiry so repeated
`tool/resume` or idempotent `tool/cancel` can return owner-bound terminal task
state.

The remaining capacity bug is that the deferred-task cap currently counts only
working tasks. Retained completed or cancelled task records can accumulate until
TTL expiry without consuming capacity, even though they still occupy the
owner-bound task registry.

### Security And API Constraints

- Preserve public Rust structs, JSON-RPC methods, and response shapes.
- Preserve owner binding for working, completed, failed, and cancelled tasks.
- Do not execute the deferred kernel request more than once.
- Keep all retained task records bounded by the existing TTL and deferred-task
  cap.
- Preserve signed receipt metadata on completed or failed resumed results and
  cancellation metadata on cancelled tasks.

### Affected Dependents

- ACP clients can repeat `tool/resume` after terminal resolution and receive
  the same retained task and result until TTL expiry.
- Repeated `tool/cancel` on an already cancelled task returns the retained
  cancelled task.
- `chio-kernel`, `chio-cross-protocol`, and `chio-mcp-edge` APIs are unchanged.

### Completed Terminal Retention Baseline

Retain terminal deferred-task records until the existing TTL expires, while
preserving owner checks. Lifecycle tests prove resume does not re-execute or
remove a terminal task, and cancel remains idempotent for retained cancelled
tasks.

### Completed Capacity Accounting Improvement

Make the deferred-task capacity gate count every retained task record after TTL
pruning, not just `working` tasks. Update lifecycle tests so retained cancelled
tasks at the cap reject a new `tool/stream`, proving terminal retention cannot
grow without bound until TTL expiry.
