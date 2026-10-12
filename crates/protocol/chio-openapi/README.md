# chio-openapi

Parses OpenAPI documents and generates Chio tool definitions with HTTP schemas
and typed `x-chio-*` policy metadata for downstream manifest assembly.

## Usage

```rust
let tools = chio_openapi::tools_from_spec(r#"{
  "openapi": "3.1.0",
  "info": {"title": "Inventory", "version": "1.0"},
  "paths": {"/items": {"get": {
    "operationId": "list_items",
    "responses": {"200": {"description": "Items"}}
  }}}
}"#)?;
assert_eq!(tools.len(), 1);
assert_eq!(tools[0].name, "list_items");
# Ok::<(), chio_openapi::OpenApiError>(())
```

The example parses an in-memory JSON document. `OpenApiSpec::parse` also accepts
YAML bytes; use `ManifestGenerator` for publication and output-schema controls.

## Guarantees

- `OpenApiSpec::parse` uses bounded original-byte decoding with duplicate rejection.
- `ManifestGenerator::generate_tools` validates supported Chio extensions and
  honors `x-chio-publish: false` with the default configuration.
- `OpenApiError` keeps ordinary Display and Debug peer-safe;
  `operator_diagnostic` exposes bounded local diagnostic detail.

## Status

Implemented document parser and tool generator. Generated definitions are
unsigned data. Callers assemble, sign, admit, and enforce manifests through
the relevant manifest and HTTP runtime components.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol trust boundaries](../../../spec/PROTOCOL.md#3-components-and-trust-boundaries)
- [chio-openapi-mcp-bridge](../chio-openapi-mcp-bridge/README.md)

## License

[Workspace license](../../../LICENSE).
