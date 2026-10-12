# chio-openapi architecture

## Responsibility and boundary

Parses OpenAPI documents and generates Chio tool definitions with HTTP schemas
and typed `x-chio-*` policy metadata for downstream manifest assembly.

Implemented document parser and tool generator. Generated definitions are
unsigned data. Callers assemble, sign, admit, and enforce manifests through
the relevant manifest and HTTP runtime components.

## Structure

`input` decodes original JSON or YAML with size and expansion limits.

`parser` builds `OpenApiSpec`, paths, operations, and parameters.

`extensions` decodes typed Chio extension metadata.

`generator` creates tool input/output schemas and annotations.

`policy` provides HTTP-method policy defaults.

`diagnostics` formats explicit operator-local error details.

## Data and control flow

`tools_from_spec` parses original text and runs a default generator.
`OpenApiSpec::parse` accepts bytes and rejects malformed or oversized input
before constructing the simplified document representation.

The parser extracts path and operation parameters and resolves supported
local references. Generation merges shared and operation parameters,
derives schemas and annotations, and filters unpublished operations.

Definitions use operation IDs when available, with method/path fallback.
Output schemas are included by default. A downstream component packages
definitions into an authoritative signed manifest and installs policy.

## Trust and invariants

Original input is limited to 8 MiB. JSON decoding rejects duplicate keys.
YAML decoding rejects duplicate keys and multiple documents and bounds
expanded nodes, depth, and string bytes. `from_value` receives an already
decoded value, so original duplicate and byte checks occur only in `parse`.

Version validation accepts strings beginning with `3.`. Parsing is a
simplified OpenAPI projection with supported local reference handling.
Generated policy annotations describe defaults and require runtime enforcement.

The generator emits `ToolDefinition` values and does not sign them.
Extensions carry structured policy hints; their presence alone does not
authorize calls. HTTP transport, capability admission, and receipt signing
belong to downstream integrations.

## Dependencies

Core types supply tool definitions and untrusted JSON decoding. `chio-http-core`
supplies method semantics. Serde JSON and YAML handle document values;
`chio-log-redact` supports safe operator diagnostics.

## Verification

Parser, generator, input, extension, and policy unit tests cover projection
and rejection behavior. `tests/extension_contract.rs` checks extension
contracts across generated definitions. No live API is required.

Run the focused crate suite from the workspace root:

```bash
cargo test -p chio-openapi
```

See the [README](README.md) for a minimal public API example and requirements.
