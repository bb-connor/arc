# chio-openapi

chio-openapi parses OpenAPI 3.0 and 3.1 specifications (JSON or YAML) and
converts each operation into a Chio `ToolDefinition`: an input schema built
from path, query, and body parameters, an optional output schema from the
response, and annotations (`read_only`, `destructive`, `idempotent`,
`requires_approval`) derived from the HTTP method and `x-chio-*` extension
fields.

Use it to turn an OpenAPI-described HTTP API into Chio tool definitions. This
crate produces `ToolDefinition` values only: it does not assemble or sign a
`ToolManifest`, host tools over MCP, or dispatch HTTP calls.
`chio-openapi-mcp-bridge` adds those steps; `chio-api-protect` consumes the
parser and policy types directly for request-time policy evaluation.

## Responsibilities

- Parse OpenAPI 3.0/3.1 documents (JSON or YAML, auto-detected) into an
  `OpenApiSpec`, resolving local `#/components/...` `$ref` pointers and
  failing closed on missing required fields, malformed parameters, nonobject
  operations, and invalid or unsupported Chio operation extensions.
- Generate one `ToolDefinition` per operation: merge path- and
  operation-level parameters, build an input schema from path/query
  parameters and the request body, and select an output schema from the
  first 2xx response.
- Parse `x-chio-*` operation extensions (`ChioExtensions`) and apply the
  publish, side-effect, sensitivity, and approval-required declarations when
  generating tool annotations.
- Assign a default request policy per HTTP method (`DefaultPolicy`): safe
  methods are session-scoped allow, side-effecting methods are
  deny-by-default. Supported extensions can override side effects; Sensitive,
  Restricted, and approval-required operations always remain deny-by-default.

## Operation extension contract

| Field | Accepted value | Behavior |
| --- | --- | --- |
| `x-chio-sensitivity` | `public`, `internal`, `sensitive`, or `restricted` | Sensitive and Restricted set `requires_approval` and default policy denial. |
| `x-chio-side-effects` | Boolean | Overrides method side effects; cannot weaken an approval requirement. |
| `x-chio-approval-required` | Boolean | `true` sets approval metadata and default policy denial; `false` cannot weaken Sensitive or Restricted. |
| `x-chio-publish` | Boolean | `false` omits the generated tool. |
| `x-chio-flow` | Strict `ToolFlowDeclaration` object | Preserves the declaration in the generated tool. |

Present nulls, wrong types, unknown sensitivity values, and unsupported
operation-level `x-chio-*` fields reject at load time and in direct extension
decoding. Ordinary vendor fields and nested schema hints consumed by the bridge
are preserved.

`x-chio-budget-limit` is unsupported: no current consumer binds a supplied value
to currency and financial exposure. The exported `budget_limit` data field remains
for API compatibility, but the loader rejects every supplied operation value.
`x-chio-scope`, `x-chio-guard`, `x-chio-rate-limit`, `x-chio-require-auth`,
`x-chio-tool-name`, and `x-chio-cost-units` are also unsupported operation hints.
Tool names continue to use `operationId` or the method-and-path fallback.

Default policy denial requires an explicit capability grant. Approval metadata
does not introduce a separate human approval issuance mechanism in this crate.
Invalid typed extensions preserve the native validation error through
`Error::source`; their explicit operator diagnostic contains a fixed field,
closed cause category, and only available numeric coordinates. Peer error
rendering retains the registered `invalid-request-shape` code.

## Public API

- `tools_from_spec(input: &str) -> Result<Vec<chio_core_types::ToolDefinition>>`
  - parse and generate in one call.
- `OpenApiSpec::{parse, from_value}`, and the parsed model
  `parser::{Operation, Parameter, ParameterLocation, PathItem}`.
- `GeneratorConfig`, `ManifestGenerator::{new, generate_tools}` - tool
  generation from a parsed spec.
- `ChioExtensions::{from_operation, requires_approval}`, `Sensitivity` -
  strict `x-chio-*` decoding and effective approval metadata.
- `DefaultPolicy::{for_method, for_method_with_extensions, has_side_effects}`,
  `PolicyDecision` - method- and extension-driven policy.
- `OpenApiError`, `Result<T>` - the crate error type and its alias.

## Usage

```rust
// spec_text is an OpenAPI 3.0/3.1 document, JSON or YAML.
let tools = chio_openapi::tools_from_spec(spec_text)?;
```

## Testing

`cargo test -p chio-openapi`

## See also

- `chio-openapi-mcp-bridge` - wraps this crate's `ToolDefinition`s into an
  MCP-visible surface, assembles and signs the `ToolManifest`, and dispatches
  invocations through the kernel.
- `chio-api-protect` - consumes `OpenApiSpec`, `ChioExtensions`, and
  `DefaultPolicy` directly for request-time policy evaluation.
- `chio-core-types` - supplies the `ToolDefinition`/`ToolAnnotations` types
  this crate produces.
- `chio-http-core` - supplies `HttpMethod`, used for method parsing and
  default policy.
