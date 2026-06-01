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
- Query parameter dispatch now follows the generated tool schema, but path
  template placeholders are still discovered by the dispatcher independently of
  declared OpenAPI path parameters. A malformed spec can therefore publish a
  tool whose input schema omits a required path argument, then fail only at live
  dispatch time.

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

Validate dispatch plans at ingest time by checking that every `{name}`
placeholder in a route path is declared as an OpenAPI `in: path` parameter after
path-level and operation-level parameter merge. The bridge should reject
malformed specs before manifest publication instead of advertising an input
schema that cannot satisfy live URL construction.
