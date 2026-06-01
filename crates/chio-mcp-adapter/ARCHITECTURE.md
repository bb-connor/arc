# chio-mcp-adapter architecture note

## Boundaries

- `lib.rs` owns the public wrapped-MCP adapter facade, adapted server/provider wrappers, serialized transport wrapper, and kernel-facing error mapping.
- `transport.rs` owns stdio JSON-RPC framing, upstream request routing, bounded frame reads, initialization, notification buffering, nested-flow request handling, task runtime state, and cancellation propagation.
- `native.rs` owns the native Chio authoring surface built around `NativeChioServiceBuilder`, including manifest emission and in-process tool/resource/prompt handlers.
- `loaded_weights.rs` owns the explicit "unavailable" implementation for MCP surfaces that cannot expose native model bytes.
- `fuzz.rs` owns the feature-gated MCP envelope parse entrypoint for the standalone fuzz workspace.

## Pain Points

- `lib.rs` mixes public adapter orchestration with MCP-to-Chio manifest projection and tool annotation interpretation.
- `transport.rs` owns both subprocess lifecycle and low-level stdio framing, so frame boundary drift is easy to miss during nested-flow changes.
- `read_bounded_line` enforces the maximum frame size, but it also defines whether EOF can terminate a frame.
- The crate has good behavior tests, but the stdio frame trust boundary needs explicit coverage for truncated or delimiterless upstream output.

## Constraints

- Preserve the public API for `McpAdapter`, `McpAdapterConfig`, `AdaptedMcpServer`, `SerializedMcpTransport`, `StdioMcpTransport`, native builder types, and re-exported MCP edge contracts.
- Preserve fail-closed behavior for malformed upstream metadata, JSON-RPC parse errors, transport failures, nested-flow denials, cancellation, and manifest validation.
- Preserve existing MCP annotation semantics: missing or malformed safety hints imply side effects; `destructiveHint=true` overrides `readOnlyHint=true`.
- Preserve wire compatibility with the JSON-RPC schema docs and the stdio MCP newline framing.
- Keep this slice scoped to the adapter crate unless a dependent gate proves a transitive change is required.

## Dependents

- `chio-cli`, `chio-control-plane`, `chio-hosted-mcp`, `chio-mcp-remote`, and `examples/hello-tool` depend on the public adapter and native-service APIs.
- `crates/chio-mcp-edge` owns first-class MCP hosting behavior; adapter changes must not move hosting responsibilities back into this crate.
- `spec/schemas/chio-wire/v1/jsonrpc` documents the transport JSON-RPC framing mirrored by `transport.rs`.
- `docs/start-here/NATIVE_ADOPTION_GUIDE.md` documents the native builder surface exposed from this crate.

## Planned Improvement

Make the stdio reader reject EOF before the newline delimiter for non-empty frames. This is architectural because MCP stdio is newline-delimited JSON-RPC, so accepting a delimiterless final JSON object weakens the frame boundary and lets a dying upstream process complete a Chio-visible response without producing a complete MCP frame.
