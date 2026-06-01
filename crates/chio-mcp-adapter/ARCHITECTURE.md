# chio-mcp-adapter architecture note

## Boundaries

- `lib.rs` owns the public wrapped-MCP adapter facade, adapted server/provider wrappers, serialized transport wrapper, and kernel-facing error mapping.
- `transport.rs` owns stdio JSON-RPC framing, upstream request routing, bounded frame reads, initialization, notification buffering, nested-flow request handling, task runtime state, and cancellation propagation.
- `native.rs` owns the native Chio authoring surface built around `NativeChioServiceBuilder`, including manifest emission and in-process tool/resource/prompt handlers.
- `loaded_weights.rs` owns the explicit "unavailable" implementation for MCP surfaces that cannot expose native model bytes.
- `fuzz.rs` owns the feature-gated MCP envelope parse entrypoint for the standalone fuzz workspace.

## Pain Points

- `lib.rs` mixes public adapter orchestration with MCP-to-Chio manifest projection and tool annotation interpretation.
- `generate_manifest` delegates Chio manifest validation to `chio-manifest`, but `chio-manifest` does not know MCP-specific JSON Schema shape requirements.
- Invalid upstream MCP `inputSchema` or `outputSchema` values can currently cross the adapter boundary and become signed Chio manifest metadata.
- The crate has good behavior tests, but the MCP metadata trust boundary is not isolated enough to audit independently from invocation and provider plumbing.

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

Move MCP-to-Chio manifest projection into an internal manifest module, then make that boundary reject non-object MCP `inputSchema` and `outputSchema` values before Chio manifest validation. This is architectural because it gives the adapter one auditable metadata trust boundary, keeps public APIs stable, and prevents malformed upstream MCP schemas from becoming signed Chio tool metadata.
