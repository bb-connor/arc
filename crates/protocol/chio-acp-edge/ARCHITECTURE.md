# chio-acp-edge architecture

## Responsibility and boundary

`ChioAcpEdge` owns capability advertisements, tool bindings, fidelity assessments,
and deferred tasks. It accepts kernel and execution-context references from its
embedding host.

Publishes admitted Chio tools as ACP capabilities and handles permission previews,
blocking invocations, and deferred invocation tasks.

## Structure

`config`, `types`, `bridge`, `conversion`, `edge`, and `jsonrpc` are crate-scope
fragments. `error` and `request_error` define rejection vocabulary. `metrics` owns
the edge counter sink; `fuzz` is optional.

`AcpKernelExecutionContext` carries the host-authenticated agent and capability. The
capability advertisements describe tool names and permission categories. Deferred
task entries retain owner_agent_id, a prepared request, terminal result, and any
execution error. The map uses interior mutability.

## Data and control flow

Construction validates the configured peer profile and manifests. Permission
requests resolve capability advertisements. Invocation converts ACP arguments to a
Chio request and dispatches it through the orchestrator. Streaming stores a deferred
task; resume executes the retained request and cancel terminates pending work.

`invoke_with_request_id` and `start_stream_with_request_id` bind stable request
identity for request-bound authorization artifacts.
`evaluate_permission_with_kernel` evaluates preview scope separately from execution;
it does not dispatch the advertised tool. `resume_stream_task` executes a retained
Working request and stores terminal results or errors. `cancel_stream_task` changes
Working to Cancelled and returns an already Cancelled task without executing it.

## Trust and invariants

Authentication occurs in the host before it supplies agent identity and capability
tokens. Permission preview does not itself execute a tool. Request-ID variants
support request-bound authorization. Task ownership is checked against execution
context. The task collection is capped at 1,024 entries. The byte entrypoint rejects
malformed original JSON before projection.

`ChioAcpEdge::new` validates peer features and admitted manifests. `handle_jsonrpc`
validates original JSON bytes with an 8 MiB limit. `invoke` dispatches through the
kernel; permission preview has a separate evaluation path.

Resume and cancel validate peer features and execution context, prune expired
entries using the kernel authority clock, and compare owner_agent_id with
execution.agent_id. A mismatched owner returns TaskOwnerMismatch. Missing task ids
return ToolNotFound. A completed task cannot transition through the Working-only
cancellation path.

## Dependencies

`chio-manifest` supplies admitted tool metadata, `chio-cross-protocol` supplies
conversion and orchestration, `chio-kernel` supplies authorization and receipts, and
`chio-mcp-edge` supplies MCP target execution.

## Verification

`src/tests/permissions.rs`, `document_input.rs`, `original_input.rs`, and
`nonce_preflight.rs` exercise permission, original-byte validation, and nonce
boundaries.

Run focused library tests from the workspace root:

```bash
cargo test -p chio-acp-edge
```

`public_byte_ingress_rejects_duplicates_and_bounds_before_dispatch` checks original
JSON and quota enforcement.
`permission_preview_accepts_valid_dpop_without_consuming_invocation_nonce` checks
the preview/execution distinction.
`task_clock_failures_retain_pending_work_and_counters_never_wrap` checks state
preservation on clock faults and task identifier saturation boundaries.
