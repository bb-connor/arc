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
- Query parameters are promoted into generated tool input schemas by `chio-openapi`, but the bridge currently builds upstream URLs from path parameters only.

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

Introduce an internal dispatch plan that keeps the public route binding separate from bridge-only query parameter metadata. Live invocation will expand path parameters, append declared query parameters to the upstream URL with deterministic percent encoding, and keep undeclared arguments out of the URL.
