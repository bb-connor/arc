# chio-spec-validate

`chio-spec-validate` checks JSON instances against JSON Schema definitions.
It supplies the library used by xtask scenario and fixture gates and a binary
that accepts a schema path and a document path. Schema paths also determine
where local references may resolve.

## Usage

Validate an in-memory instance using a self-contained schema:

```rust
use std::path::Path;
use chio_spec_validate::{validate_value, ValidateError};
use serde_json::json;

let schema = json!({
    "type": "object",
    "required": ["id"],
    "properties": {"id": {"type": "string", "minLength": 1}},
    "additionalProperties": false
});
validate_value(
    Path::new("<schema>"), &schema,
    Path::new("<document>"), &json!({"id": "tool-1"}),
)?;
assert!(matches!(
    validate_value(
        Path::new("<schema>"), &schema,
        Path::new("<document>"), &json!({"id": ""}),
    ),
    Err(ValidateError::SchemaViolation(_, _, _))
));
# Ok::<(), ValidateError>(())
```

The CLI accepts exactly two positional paths. It prints
`OK <document> -> <schema>` on success. Exit codes are 0 for success,
1 for validation or loading failure, and 2 for incorrect arguments.

## Guarantees

- `validate` loads both JSON files and delegates to `validate_value`.
- `validate_value` distinguishes schema compilation failure from instance
  violations and collects every message returned by `iter_errors`.
- For schemas with a nonempty parent path, `LocalSchemaRetriever` resolves
  Chio HTTPS identifiers from local files and rejects unregistered network
  references. Canonical referenced paths must stay within the schema root.
- `ValidateError` preserves the relevant file paths for I/O, JSON parse,
  compilation, and validation errors.

## Status

This workspace package ships a library and binary and is marked
`publish = false`. Callers provide trusted schemas. Validation checks the
schema's assertions; runtime cryptographic verification, authorization, and
canonical signed-payload parsing remain separate responsibilities.
`load_json` uses ordinary `serde_json` parsing and reads the whole file.

`cargo test -p chio-spec-validate` exercises local references, network
refusal, protocol artifacts, and positive and negative scenario fixtures.

## Related

- [Architecture](ARCHITECTURE.md)
- [Serialization contract](../../../spec/PROTOCOL.md#4-serialization-and-identity)
- [Schema generator](../chio-spec-codegen/README.md)
- [Workspace task runner](../../../xtask/README.md)

## License

[Apache-2.0](../../../LICENSE)
