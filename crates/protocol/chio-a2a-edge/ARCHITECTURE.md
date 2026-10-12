# chio-a2a-edge architecture

## Responsibility and boundary

`ChioA2aEdge` owns advertised skills, fidelity assessments, bindings, and an
in-memory task map. The host owns the listener, caller authentication, capability
resolution, and registered tool connections.

Exposes admitted Chio tools as A2A skills, builds an Agent Card, and dispatches
calls through the kernel and cross-protocol orchestrator.

## Structure

`config`, `types`, `bridge`, `conversion`, `edge`, and `jsonrpc` are included at
crate scope. `metrics` delegates receipt counters; `otel` is feature gated.

The Agent Card contains the derived skill list and configured endpoint data.
`A2aKernelExecutionContext` carries host agent identity, capability material, and
optional request-bound approval controls. Deferred tasks retain their prepared
request and owner identity rather than resolving ownership from card data.

## Data and control flow

Construction derives skills from admitted manifests and detects ambiguous
identifiers. Blocking calls convert message parts into tool arguments and use
cross-protocol dispatch. Deferred starts retain authorization context; follow-up
requests verify task ownership before resolving or canceling work.

`handle_send_message_with_request_id` and `handle_stream_message_with_request_id`
accept stable request binding. The variants without a request id reject
request-bound artifacts that cannot be safely correlated. `handle_jsonrpc_task_get`
checks trusted time and context before resolving a task or completing its retained
pending request.

## Trust and invariants

The execution context is supplied by the host and includes agent identity and
capability material. Peer feature negotiation comes from configuration.
Request-bound authorization artifacts require the request-ID entrypoints. The task
map is capped at 1,024 entries; it is process-local. Protocol streaming represents a
deferred lifecycle and does not provide a socket event pump.

`ChioA2aEdge::new` requires a `VerifiedManifestRegistry` and validates Agent Card
configuration. `handle_jsonrpc` validates original JSON bytes with a 1 MiB limit
before dispatch. Kernel execution supplies capability enforcement and receipts.

`resolve_task` checks the retained owner against execution.agent_id. Task-get and
cancellation use the same host execution-context validation. Expired work is pruned
using trusted authority-clock readings; clock failures return errors while retaining
pending work. Task ids use checked counters.

## Dependencies

`chio-manifest` supplies admission evidence, `chio-cross-protocol` supplies bridge
fidelity and orchestration, `chio-kernel` supplies authoritative evaluation, and
`chio-mcp-edge` supports MCP targets.

## Verification

`src/tests/agent_card.rs`, `message_conversion.rs`, `boundaries.rs`, and
`nonce_preflight.rs` cover publication, conversion, request limits, and nonce
preflight.

Run focused library tests from the workspace root:

```bash
cargo test -p chio-a2a-edge
```

`original_bytes_reject_duplicates_before_dispatch_and_preserve_integer_ids` checks
JSON ingress before kernel execution.
`task_clock_fault_preserves_work_and_exact_expiry_prevents_dispatch` checks
clock-error retention and deadline rejection.
`terminal_tasks_use_capacity_until_expiry_and_counters_cannot_wrap` checks that
completed entries still consume capacity until pruning.
