//! Invoke one resolved connection using kernel-selected caller context.

use super::*;

impl ChioKernel {
    /// Drive one already-resolved tool-server invocation to completion. Taken
    /// over owned inputs and free of any `&self` borrow so the dispatch deadline
    /// path can move it onto a `spawn_blocking` thread (`'static`), isolating a
    /// connection that blocks synchronously before its first `.await` from the
    /// async worker.
    pub(super) async fn invoke_resolved_server(
        server: Arc<dyn ToolServerConnection>,
        context: crate::ToolInvocationContext,
        arguments: serde_json::Value,
        has_monetary_grant: bool,
    ) -> Result<(ToolServerOutput, Option<ToolInvocationCost>), KernelError> {
        // Try streaming first regardless of monetary mode.
        //
        // Why the kernel cannot bound stream memory "as chunks arrive" at THIS
        // seam, and where the actual bounds live.
        //
        // `ToolServerConnection::invoke_stream` returns a FULLY MATERIALIZED
        // `ToolServerStreamResult` (which owns a `ToolCallStream { chunks: Vec<..>
        // }`). The connector is in-process trusted code that drains its transport
        // and builds the entire Vec BEFORE returning; the kernel receives control
        // only after materialization. There is no incremental per-chunk arrival at
        // this seam, so `push_chunk_bounded` cannot be driven here to bound the
        // stream as it accumulates. True accumulation-time bounding would require
        // changing the trait contract to a kernel-driven pull model (invoke_stream
        // yielding a chunk source the kernel pulls), a public runtime-API change
        // affecting every implementor; and even then a malicious in-process
        // connector could allocate before yielding. So the transient peak
        // allocation of a non-cooperating out-of-tree connector is a genuine
        // connector-trust-boundary limit, bounded only by the process RSS ceiling
        // (cgroup/ulimit).
        //
        // Layered bounds that DO apply:
        //   - Accumulation is bounded by the ACCUMULATOR. In-tree connectors cap
        //     it (A2A: `parse_sse_stream_with_limit`, MAX_SSE_TOTAL_BYTES = 1 MiB).
        //     `enforce_stream_byte_limit` / `push_chunk_bounded` (crate::runtime)
        //     are pub fail-closed Overloaded { StreamBytes / StreamChunks }
        //     primitives (bounding total bytes AND retained chunk count) so
        //     out-of-tree connector authors can bound their own invoke_stream.
        //   - Retained memory is bounded at finalize by `apply_stream_limits` /
        //     `truncate_stream_to_limits`: the stream is truncated to
        //     `max_stream_total_bytes` / `max_stream_chunks` and the receipt is
        //     marked incomplete,
        //     PRESERVING the charge-for-work-done and financial metadata on
        //     governed monetary streams (pinned by
        //     `governed_monetary_incomplete_receipt_keeps_financial_and_governed_metadata`
        //     and `streamed_tool_byte_limit_truncates_output_and_marks_receipt_incomplete`).
        //     A hard-deny (Err) here was deliberately reverted because it unwinds
        //     the monetary charge for an already-executed stream, so this seam
        //     does not hard-deny.
        if let Some(stream) = server
            .invoke_stream_with_context(&context, arguments.clone(), None)
            .await?
        {
            return Ok((ToolServerOutput::Stream(stream), None));
        }

        if has_monetary_grant {
            let (value, cost) = server
                .invoke_with_cost_and_context(&context, arguments, None)
                .await?;
            Ok((ToolServerOutput::Value(value), cost))
        } else {
            let value = server
                .invoke_with_context(&context, arguments, None)
                .await?;
            Ok((ToolServerOutput::Value(value), None))
        }
    }
}
