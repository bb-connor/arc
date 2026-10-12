# Architecture

## Responsibility and boundary

`OpenApiMcpBridge` owns a generated tool manifest and OpenAPI route dispatch map.
It exposes inspection, registry-bound MCP projection, and direct invocation.
`BridgeToolServer` borrows a bridge and `OwnedBridgeToolServer` consumes one;
both implement `ToolServerConnection` for kernel registration.
`BridgeConfig` identifies the server and upstream URL and carries an optional
egress contract. `HttpDispatcher` is a caller-supplied synchronous function.
The crate supplies no HTTP client or listener.

Kernel authorization and receipt signing occur when the host evaluates calls
through a registered kernel connection. Direct `invoke_tool` performs routing
and egress checks before delegating to the configured HTTP dispatcher.
It does not validate capabilities or sign receipts by itself.

## Structure

`lib.rs` defines public configuration, error, route, response, and bridge types.
It generates manifests, pairs MCP tools with admitted security sidecars,
and implements borrowed/owned kernel connections.
`dispatch.rs` builds route dispatches, validates required arguments, expands
path templates, appends query values, gates egress, and projects responses.
`tests.rs` contains parsing, export, routing, egress, and kernel tests.
The optional `fuzz` module exposes fuzz helpers with `arbitrary` support.

## Data and control flow

`from_spec` parses input through `chio_openapi::OpenApiSpec::parse`.
`from_parsed_spec` generates tools with output schemas and publish flags enabled.
It rejects an empty surface, constructs dispatch bindings, and validates the
resulting Chio manifest. The generated manifest remains unsigned until admitted
through the host's publisher-verification workflow.

`registry_bound_mcp_tools` retrieves the verified server manifest and compares
canonical JSON bytes against the generated manifest.
Each MCP projection retains an exact server/tool binding and effective-egress
security sidecar in a `RegistryBoundMcpTool` with private fields.
Plain `mcp_tools_list` rejects export because the HTTP topology needs that binding.

Invocation looks up the route, validates required body/query inputs, expands
path arguments, and constructs the URL using the configured base.
Path values are encoded as components and query arrays become repeated pairs.
The dispatcher receives method, URL, and the original argument value.
The bridge then rejects redirects, checks observed response bytes, and returns
MCP content plus structured HTTP status, route, and body metadata.
Kernel wrappers translate bridge errors into `KernelError::ToolServerError`.

## Trust and invariants

Registry export requires canonical equality of the full generated and admitted
manifests. Sidecars must retain registry coordinates, effective egress, and
exact server/tool identity. Missing bindings fail closed.
`invoke_tool` rejects an unknown tool or absent dispatcher.
A present dispatcher requires `HttpEgressContract`; URL and DNS are checked
before invocation through `enforce_dispatch_contract`.

The dispatcher must make one network hop and return redirects without following.
`enforce_no_redirect_response` rejects returned HTTP 300-399 statuses.
The bridge cannot detect a dispatcher that followed a redirect internally.
`enforce_bridged_response_body` requires `observed_body_bytes` and applies the
contract ceiling after dispatch. The dispatcher owns bounded reading and honest
raw-byte accounting before parsing or normalization.

Path parameters must match declared template names and be nonempty scalar values.
Dot segments reject before URL construction.
Required query parameters reject absent, null, or empty-array values.
Required request bodies reject absent or null `body` values.
These route checks do not implement complete JSON Schema validation; the kernel
and host must retain their tool-schema and policy evaluation boundaries.
Unknown tool names are treated as side-effecting by the connection's read-only
classification, preserving conservative durable admission behavior.

## Dependencies

`chio-openapi` parses documents and generates tool definitions.
`chio-manifest` validates surfaces and supplies verified security bindings.
`chio-egress-contract` gates URL/DNS and response size.
`chio-mcp-edge` supplies MCP discovery records.
`chio-kernel` supplies connection contracts; core supplies canonical bytes.
Serde/JSON handle representations, and tracing/thiserror support diagnostics.

## Verification

Run `cargo test -p chio-openapi-mcp-bridge` for bridge tests.
Tests cover parsing, tool generation, canonical registry equality, flow sidecars,
missing dispatchers/contracts, observed-byte requirements, and response ceilings.
Route tests cover encoded paths, query parameters, dot segments, and redirects.
`bridge_invocation_runtime_admission_denies_before_http_dispatch` tests kernel
admission using a controlled dispatcher with no external service dependency.
These tests exercise bridge and kernel integration in controlled fixtures.
A live HTTP client's egress, response reading, and credential handling require
verification by the host supplying the dispatcher.
