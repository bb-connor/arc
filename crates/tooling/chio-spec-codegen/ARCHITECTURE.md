# chio-spec-codegen Architecture

## Boundaries

- `src/lib.rs` owns Rust schema discovery, local `$ref` inlining, per-schema typify registration, deterministic path-named module assembly, prettyplease formatting, generated header stamping, and shared file writes.
- `src/errors_pass.rs` owns the Chio error registry parser and generated `chio-errors` Rust output.
- `src/threat_model.rs` owns threat-model JSON loading, optional schema validation, and per-threat stub generation.
- `src/threat_coverage_doc.rs` owns the generated markdown coverage report that joins threat-model rows, adversarial corpus cases, and existing threat tests.
- `src/main.rs` is a CLI dispatcher over the library entry points.

## Security And API Constraints

- The generator consumes trusted repository inputs and emits Rust source that downstream crates compile.
- Codegen must be deterministic: sorted schema files, one independent `TypeSpace` per schema, path-named module scopes, stable headers, rustfmt or prettyplease formatting, and write-if-changed output.
- Schema-local `$defs` are scoped to the module generated for their owning schema. A module-name normalization collision fails closed before source is emitted.
- Local schema references must stay under the configured schema tree. Symlinks and path escapes must fail closed.
- Network schema references must not become ambient authority or typify-side fallback behavior.
- Existing public entry points and generated header bytes must remain compatible.

## Schema Reference Resolution

`resolve_local_schema_ref` validates local filesystem references against the configured schema tree. Absolute `http` and `https` `$ref`s are rejected as a `SchemaRef` denial during the schema pre-pass, before typify generation, rather than left to fail as a backend-specific typify error. Internal fragment refs remain inside their owning schema's `TypeSpace`; local cross-file refs are inlined into the referring schema before generation.
