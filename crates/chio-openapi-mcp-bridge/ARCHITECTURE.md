# chio-openapi-mcp-bridge Architecture

## Boundaries

- `OpenApiMcpBridge` owns OpenAPI ingest, manifest conversion, route dispatch planning, and borrowed tool-server exposure.
- `OwnedBridgeToolServer` owns the same dispatch state after kernel registration consumes a bridge.
- `BridgeConfig` is caller-supplied trust configuration, including upstream base URL and the typed HTTP egress contract that gates every live dispatcher call.
- `RouteBinding` is the public method/path view. Internal dispatch state must carry any extra routing details without expanding that public struct.
- The optional `fuzz` module is a feature-gated trust-boundary harness for arbitrary OpenAPI input.

## Pain Points

- `src/lib.rs` is carrying route binding, URL construction, egress enforcement, response shaping, and test fixtures in one file.
- Manifest tool generation and route dispatch planning are parallel paths, so drift between advertised input schema and live dispatch behavior is easy to miss.
- Path parameter expansion still percent-encodes unreserved `.` bytes, so `.` or
  `..` parameter values can become real URL path segments after a downstream
  HTTP client reparses the URL.
- The caller-supplied dispatcher receives only a pre-flight-checked URL. If it
  follows redirects internally, the bridge cannot validate the redirected
  authority before the second network hop.

## Constraints

- Public `RouteBinding`, `BridgeConfig`, `BridgeError`, and response shapes stay compatible.
- Live dispatch must fail closed when egress contract state is absent or rejects the final URL.
- URL construction must remain deterministic because the dispatcher URL is part of the enforced egress boundary.
- The bridge must not bypass `chio-openapi` parsing, publish filtering, or `chio_manifest::validate_manifest`.

## Affected Dependents

- `chio-kernel` callers observe this crate through `ToolServerConnection`.
- `chio-mcp-edge` receives manifest-derived `McpToolInfo` entries.
- `chio-egress-contract` enforces the final URL and response-size limits.
- `chio-fuzz` compiles the `fuzz` module when exercising OpenAPI ingest.

## Planned Improvement

Reject dot-segment path parameter values before URL construction completes, and
make redirect handling explicit at the bridge boundary. Live dispatchers must
surface redirects as responses instead of following them internally, and the
bridge must reject redirect statuses before returning a tool result.

## Required Query Dispatch Slice

### Current Boundary

`dispatch.rs` now owns live URL construction after OpenAPI ingest. It receives
the merged path-level and operation-level parameters, records the public route
binding, expands path placeholders, appends declared query parameters, and hands
the final URL to the `HttpEgressContract` before the caller-supplied dispatcher
runs.

### Pain Point

The manifest generator already marks required query parameters in the generated
tool input schema, but the live dispatcher stores only query parameter names.
If a caller invokes the bridge directly, or a protocol layer fails to validate
the manifest schema, missing required query arguments are silently omitted from
the upstream URL. That creates drift between the advertised Chio tool contract
and the actual HTTP request the bridge is willing to dispatch.

### Security and API Constraints

The public `RouteBinding`, `BridgeConfig`, `BridgeError`, `BridgedResponse`,
`OpenApiMcpBridge`, and `OwnedBridgeToolServer` APIs must stay source
compatible. Egress contract enforcement must still run on the final URL, and
the dispatcher must not run when live request construction is missing required
OpenAPI evidence. Optional query parameters should remain optional.

### Affected Dependents

`chio-conformance` imports `OpenApiMcpBridge` for SSRF and response-size tests,
and fuzz targets compile the feature-gated ingest harness. No transitive source
changes are planned because the required-query metadata is internal to
`RouteDispatch`.

### Planned Material Improvement

Extend the internal dispatch plan from `Vec<String>` query names to query
metadata that includes OpenAPI `required`. Validate required query parameters
before appending any query string, reject missing/null/empty-array required
values before egress and before the dispatcher runs, and add focused tests for
both borrowed and owned bridge invocation paths.
