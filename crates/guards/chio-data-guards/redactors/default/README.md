# chio-data-guards-redactors-default

Byte-oriented redaction for the `chio:guards/redact@0.1.0` contract. The crate
returns transformed bytes and a manifest of original-payload match locations
for callers that scrub data before buffering or persistence.

## Usage

Validate the built-in patterns during startup and redact a local payload:

```rust
use chio_data_guards_redactors_default::{
    redact_payload, validate_default_redactor_compiles, RedactClass, PASS_ID,
};

assert!(validate_default_redactor_compiles().is_ok());
let output = redact_payload(b"contact alice@example.com", RedactClass::default_full())?;
assert_eq!(output.bytes, b"contact [REDACTED-EMAIL]");
assert_eq!(output.manifest.pass_id, PASS_ID);
assert_eq!(output.manifest.matches.len(), 1);
# Ok::<(), chio_data_guards_redactors_default::RedactError>(())
```

This example needs no services or additional dependencies. `redact` is the
convenience API when the caller needs only the output bytes.

## Guarantees

- `redact_payload` scans bytes and reports offsets in the original payload.
- `collect_with_filter` rejects offsets or match lengths that overflow `u32`.
- `luhn_ok` filters credit-card candidates by digit count and checksum.
- `apply_spans` preserves bytes outside accepted spans; the manifest is sorted
  by original offset and length and carries `PASS_ID` plus elapsed time.
- `validate_default_redactor_compiles` recompiles the same pattern constants
  used by the lazy runtime regexes so callers can reject startup failures.

## Status

Implemented patterns cover AWS access-key IDs, JWT-shaped strings, Stripe and
OpenAI-style keys, long alphanumeric/underscore runs, basic email, US phone and
SSN formats, Luhn-valid card candidates, and Bearer-shaped tokens.
These heuristics can miss secrets and can redact ordinary matching text.
`pii_extended` and `custom` are accepted flags with no transformation.
`RedactClass::default()` enables no classes. Runtime regex compilation failure
skips the affected pattern, so strict callers must use the startup validator.
Callers own failure handling, persistence refusal, and manifest signing.

## Related

- [Architecture](ARCHITECTURE.md)
- [Data guards](../../README.md)
- [Redaction WIT contract](../../../../../wit/chio-guards-redact/world.wit)
- [Protocol safety properties](../../../../../spec/PROTOCOL.md#54-safety-properties-and-evidence-boundary)

## License

See [LICENSE](../../../../../LICENSE).
