# chio-a2a-edge architecture

## Responsibility and boundary

`ChioA2aEdge` owns advertised skills, fidelity assessments, bindings, and an
in-memory task map. The host owns the listener, caller authentication, capability
resolution, and registered tool connections.

Exposes admitted Chio tools as A2A skills, builds an Agent Card, and dispatches
calls through the kernel and cross-protocol orchestrator.

## Structure

`config`, `types`, `bridge`, `conversion`, `edge`, and `jsonrpc` are included at
crate scope. `v1` holds the A2A v1.0.0 JSON-RPC projection and its owner
continuation; `task_completion` records whether kernel evaluation was entered.
`metrics` delegates receipt counters; `otel` is feature gated.

The Agent Card contains the derived skill list and configured endpoint data.
`A2aKernelExecutionContext` carries host agent identity, capability material, and
optional request-bound approval controls. Retained tasks keep their prepared
request, owner identity and output mode rather than resolving ownership from card
data.

## Data and control flow

Construction derives skills from admitted manifests and detects ambiguous
identifiers. `handle_jsonrpc` serves `SendMessage`, `GetTask` and `CancelTask`;
every other method returns `-32601`.

`SendMessage` converts message parts into tool arguments, retains a task under the
message ID, and completes it through cross-protocol dispatch in the same call. A
terminal result is delivered and its task released. An approval-blocked result is
retained as `TASK_STATE_INPUT_REQUIRED`. The owner resumes it with `SendMessage`
carrying the original message ID and task ID; only the signed approval artifacts may
differ from the retained request. `GetTask` observes a retained task and never
executes it. `CancelTask` cancels a working task and refuses a completed or failed
one with `-32002`.

`handle_send_message_with_request_id` binds a stable request ID for Rust hosts. The
variant without a request ID rejects request-bound artifacts that cannot be safely
correlated.

## Trust and invariants

The execution context is supplied by the host and includes agent identity and
capability material. Peer feature negotiation comes from configuration. Message
metadata never supplies authority. The task map is capped at 1,024 entries and 128
per capability subject; it is process-local, and each edge instance draws a fresh
task namespace so a restarted provider never resolves an old task ID to unrelated
work. The edge does not advertise streaming and refuses
`configuration.returnImmediately: true` with `-32004`.

`ChioA2aEdge::new` requires a `VerifiedManifestRegistry` and validates Agent Card
configuration. `handle_jsonrpc` validates original JSON bytes with a 1 MiB limit
before dispatch. Request decode failures keep their typed cause locally and emit
only its code. Kernel execution supplies capability enforcement and receipts.

Task lookup requires the retained owner agent and capability subject to match the
execution context. Absent and inaccessible tasks return the same `-32001`. Expired
work is pruned using trusted authority-clock readings; clock failures return errors
while retaining pending work. Task IDs use checked counters.

## Dependencies

`chio-manifest` supplies admission evidence, `chio-cross-protocol` supplies bridge
fidelity and orchestration, `chio-kernel` supplies authoritative evaluation, and
`chio-mcp-edge` supports MCP targets.

## Verification

`src/tests/agent_card.rs`, `message_conversion.rs`, `boundaries.rs`,
`nonce_preflight.rs` and `v1.rs` cover publication, conversion, request limits,
nonce preflight and the A2A v1.0.0 lifecycle.

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
