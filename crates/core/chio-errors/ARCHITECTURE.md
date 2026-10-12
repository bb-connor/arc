# chio-errors architecture

## Responsibility and boundary

This crate owns diagnostic representation and registry lookup.
Its public surface exports `Code`, `Domain`, `Severity`, `Diagnostic`,
`ChioError`, constructor helpers, and the `Result<T>` alias.
Generated `ErrorCodeSpec` entries connect canonical URNs to legacy strings,
optional JSON-RPC numbers, help text, and consuming crate names.

The caller owns the decision that produced a diagnostic.
This crate does not validate a capability or sign a denial receipt.
Messages and optional help are owned strings supplied by callers.

## Structure

- `code.rs` implements an unconstrained, transparent string wrapper.
- `domain.rs` parses the enumerated domain slugs.
- `severity.rs` parses severities and supplies their ordering and rank.
- `diagnostic.rs` owns diagnostic fields and the error wrapper.
- `_generated/error_codes.rs` contains constants, the table, and lookups.
- `jsonrpc_bridge.rs` maps table entries to optional numeric pointers.

The implementation forbids unsafe code.
The generated table is exposed through the crate root for consumers.

## Data and control flow

A caller can construct a diagnostic with explicit fields or an `ErrorCodeSpec`.
`Diagnostic::from_spec` copies registry metadata and accepts a new message.
`into_error` retains the diagnostic in a `thiserror` error wrapper.
Display formatting emits code, domain, severity, message, and optional help.

`lookup_error_code` searches exact URNs.
`lookup_string_code_matches` exposes all matching legacy strings.
`lookup_string_code` succeeds only when that iterator has one match.
JSON-RPC conversion follows each entry's optional integer pointer.
Missing mappings return `None`.

## Trust and invariants

`Code::new` accepts arbitrary strings and does no registry validation.
`Domain::lookup` rejects unknown slugs; severity accepts `warn` and `warning`.
`Diagnostic::registry_spec` requires the code, domain, and severity to agree.
It does not compare message or help text against registry content.

Serde serialization carries typed fields but supplies no canonical JSON,
signature, or persistence contract. A registered diagnostic remains descriptive
until an enforcing caller binds it to an actual rejection.

## Dependencies

`serde` supplies serialization and deserialization derives.
`thiserror` supplies error implementations for typed diagnostics and parse errors.
Registry lookup uses the generated static table and standard iterators.
There are no runtime services or storage dependencies.

## Verification

`tests/lookup.rs` checks domain round trips, severity aliases, field preservation,
registry metadata rejection, free-form compatibility, and ambiguous legacy codes.
`tests/jsonrpc_bridge_property.rs` compares mapped codes with the wire registry
fixture and checks unmapped values.

Run the crate tests with:

```bash
cargo test -p chio-errors
```

These checks cover diagnostic and mapping behavior; they do not establish
runtime authorization or deployment acceptance.
