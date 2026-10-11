# chio-openapi architecture

## Overview

chio-openapi is a pure parsing and transformation library: no I/O, no async
runtime, `#![forbid(unsafe_code)]`. It is the ingest trust boundary for
operator-authored OpenAPI documents - `OpenApiSpec::parse` validates
structure and fails closed on missing fields, unresolved or non-local `$ref`,
and malformed parameters before any `ToolDefinition` is generated. The crate
stops at `ToolDefinition` values; assembling a signed `ToolManifest`, hosting
tools over MCP, and dispatching HTTP calls are out of scope and live in
`chio-openapi-mcp-bridge`.

## Module map

| Path | Responsibility |
|------|----------------|
| `src/lib.rs` | Public API surface: `OpenApiError`, the `Result` alias, and the `tools_from_spec` convenience function (parse + generate in one call). |
| `src/parser.rs` | OpenAPI 3.x JSON/YAML ingestion into `OpenApiSpec`: format auto-detection, required-field checks, local `$ref` resolution, parameter/request-body/response extraction. |
| `src/generator.rs` | `ManifestGenerator`: converts an `OpenApiSpec` into `Vec<ToolDefinition>`, merging parameters and building input/output JSON schemas and annotations. |
| `src/extensions.rs` | `ChioExtensions`: parses `x-chio-*` operation fields (`sensitivity`, `side_effects`, `approval_required`, `budget_limit`, `publish`) from the raw operation JSON. |
| `src/policy.rs` | `DefaultPolicy`: session-allow / deny-by-default decision per HTTP method, overridable by `ChioExtensions`. |

## Spec-to-tool pipeline

1. `OpenApiSpec::parse` (or `from_value`) ingests JSON or YAML, requires a
   `3.x` `openapi` version plus `info` and `paths`, and resolves `$ref`
   pointers that start with `#/` against the document itself. A missing
   field, unresolved ref, or malformed parameter (`name`/`in` absent, empty,
   or non-string; `in` outside `path`/`query`/`header`/`cookie`) fails the
   parse.
2. Paths are sorted lexicographically and each path's operations are visited
   in a fixed method order (`get`, `post`, `put`, `patch`, `delete`, `head`,
   `options`), so generation is deterministic regardless of source key order.
3. `ManifestGenerator::generate_tools` merges path-level and operation-level
   parameters (operation-level wins on a name+location collision) and skips
   an operation when `ChioExtensions::should_publish` is false and
   `respect_publish_flag` is set.
4. For each remaining operation, `build_tool_definition` builds an input
   schema from path/query parameters (header and cookie parameters are
   excluded) and the request body, an output schema from the first `200`,
   then `201`, then any other 2xx response, and annotations from the HTTP
   method and extensions.
5. The result is a `Vec<ToolDefinition>`. No manifest assembly, signing, or
   transport happens in this crate.

## Invariants and failure modes

- Parsing fails closed: an unrecognized parameter `in` value is rejected as
  `OpenApiError::InvalidSpec`, not silently coerced to a default location.
- `resolve_ref` only follows pointers beginning with `#/`; external refs
  (URLs, other files) are rejected as `UnresolvedRef`.
- Path parameters default to required when the document omits `required`;
  other locations default to not required.
- Present Chio security extensions require their declared types and recognized
  enum values. Sensitive and Restricted operations require the generated approval
  annotation and a deny-by-default policy; an explicit false approval hint cannot
  weaken that default. Admission still requires the owning capability and policy
  checks.
- `publish`, `side_effects`, and approval annotations affect generated tools.
  `budget_limit` is rejected until budget semantics are implemented; it never
  supplies currency enforcement or a price.
- `GeneratorConfig.server_id` is stored but not read by `generate_tools`; it
  has no effect on this crate's output.
- `ToolDefinition.pricing` is always `None`; this crate does not compute
  pricing from security extensions or elsewhere.

## Dependencies

`chio-core-types` supplies `ToolDefinition` and `ToolAnnotations`, the types
this crate produces. `chio-http-core` supplies `HttpMethod`, parsed from the
OpenAPI method string and consulted by `DefaultPolicy`. `serde`/`serde_json`
back the JSON model; `serde_yaml` backs YAML parsing; `thiserror` derives
`OpenApiError`. No dependency aliasing.

## Verification focus

The parser tests cover JSON and YAML input, local reference resolution, required
path parameters, unsupported parameter locations and external-reference rejection.
Extension tests reject unknown sensitivity values and retain strict Chio flow
declarations. Generator tests cover deterministic tool construction, merged
parameters, request and response schemas, publish exclusion, approval annotations
and flow preservation. Run `cargo test --locked -p chio-openapi --lib` to check
these owning boundaries. The crate does not establish runtime admission or
transport enforcement; those remain the kernel and protocol-edge owners' tests.
