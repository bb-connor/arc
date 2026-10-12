# Architecture

## Responsibility and boundary

`ChioMcpEdge` owns MCP protocol state around a supplied `ChioKernel`.
Its public surface includes configuration, JSON-RPC handling, transport loops,
notifications, restoration, and shared tool-call bridge execution.
`McpTransport` describes upstream tool, resource, prompt, and callback access.
The crate defines discovery and result types used by adapters and remote hosts.
Listener authentication and subprocess creation belong to those hosts.

`new` accepts caller-provided manifests and validates their structure.
Registry constructors derive manifests from publisher-admitted records and
retain registry security metadata. The host registers kernel tool servers,
supplies the agent subject and capabilities, and configures durable stores.

## Structure

- `ingress` owns original-byte decoding, bounded framing, budgets, and inboxes.
- `authorization` projects supported authorization metadata into kernel requests.
- `runtime` owns the edge and protocol configuration.
- `runtime/protocol` validates envelopes, parameters, metadata, and results.
- `runtime/discovery` builds tool bindings and compiles schema validators.
- `runtime/state`, `tasks`, and `requests` manage lifecycle and request identity.
- `runtime/nested_flow` and `client_wait` own callback waits and cancellation.
- `runtime/receipts` and `refusals` retain decisions and protocol refusal evidence.
- `runtime/tool_calls` implements bridge calls and the MCP target executor.
- `tool_result` projects values; `metrics` exports receipt-write counters.
- `otel` and `fuzz` expose their modules only with the corresponding feature.

## Data and control flow

Transport owners decode bytes with `decode_mcp_request` and reserve ingress
capacity before retaining messages. The public `handle_jsonrpc` method accepts
an already decoded `Value`; callers own the original-byte decoding boundary.
The runtime forms a request digest, parses the envelope, and routes the method.
Initialization moves state from uninitialized to waiting for initialized.
`notifications/initialized` permits ready-state operations.
Protocol negotiation supports version `2025-11-25` through `initialize`.
Revision `2026-07-28` is served statelessly: a request naming it in
`_meta` opens the kernel session on an uninitialized edge, with no
server-initiated flows, and an edge opened by one era refuses the other.

Discovery projects retained manifest tools into MCP names and schemas.
Duplicate exposed names across manifests reject construction.
Tool calls resolve a binding, validate arguments, select authority, and enter
kernel evaluation. Resource, prompt, completion, and nested operations use
the corresponding kernel session interfaces.
Deferred tasks and notifications retain session ownership and bounded state.
Tool-result projection preserves MCP-shaped values and wraps ordinary values.

`execute_bridge_mcp_tool_call_async` validates peer capabilities before calling
`evaluate_tool_call_with_metadata`. The synchronous wrapper adapts to the
current Tokio runtime or creates a current-thread runtime.
`McpTargetExecutor` evaluates a bound cross-protocol request and retains
source-receipt context in the target metadata.

## Trust and invariants

`decode_mcp_request` validates bounded UTF-8 JSON and duplicate members.
It decodes the original `_meta.chioDpopProof` slice using signed JSON rules
before unsigned-envelope projection. Kernel evaluation owns cryptographic
proof verification, exact invocation binding, and replay authority.
Ordinary decimals remain accepted in the unsigned arguments document.

`IngressBudget` tracks retained wire bytes, node count, and text bytes.
Default ceilings are 8 MiB wire, 1,048,576 nodes, and 8 MiB text.
Frame reservations follow retained messages and release capacity on drop.
The runtime limits deferred tasks to 1,024, with a default five-minute TTL
and a maximum one-hour TTL. Callback waits retain their cancellation owner.
Kernel errors become protocol errors and receipt-write error metrics.
Projection functions alone do not mint authority or evaluate policies.

## Dependencies

`chio-kernel` supplies trusted dispatch, sessions, receipts, and nested flows.
`chio-manifest` validates manifests and compiles tool input schemas.
`chio-cross-protocol` supplies bound routing and source-receipt context.
`chio-edge-metrics` supplies shared metrics definitions.
Core/security types carry capability and clock contracts; Tokio supports async
execution, while Serde, JSON, Chrono, and UUID support protocol representation.

## Verification

Run `cargo test -p chio-mcp-edge` for runtime and loopback tests.
Ingress tests cover original proof bytes, duplicate members, bounds, and queues.
Runtime tests cover authorization, protocol states, request identity, roots
refresh, task behavior, receipt evidence, metrics, and clock recovery.
`tests/integration_smoke.rs` exercises initialize, tools/list, and tools/call
against a controlled kernel tool server through JSON-RPC messages.
The tests exercise local edge behavior; transport deployment and store custody
must be verified by the host using the edge.
