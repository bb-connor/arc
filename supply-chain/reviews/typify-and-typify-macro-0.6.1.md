# typify and typify-macro 0.6.1 source review

Reviewed September 16, 2026 by the executing Codex agent. Confidence is high
for the exact facade and macro source and their tested compilation boundaries.
This is direct source review, not independent human certification.

Both packages identify oxidecomputer/typify commit
`f65c6dd14317605f4f25a076d99ba4c4f41f0d15`. Verified registry archive SHA-256:

| Package | SHA-256 |
| --- | --- |
| typify 0.6.1 | `b715573a376585888b742ead9be5f4826105e622169180662e2c81bed4a149c3` |
| typify-macro 0.6.1 | `fd04bb1207cd4e250941cc1641f4c4815f7eaa2145f45c09dd49cb0a3691710a` |

## Scope and selected use

Reviewed both published and original manifests, the complete facade source,
both macro modules, upstream tests and documentation examples. Neither
package contains unsafe code or a build script. The facade only documents and
re-exports the backend and optional macro. The macro parses Rust configuration,
reads the explicitly selected local JSON schema, calls the backend, and emits
Rust tokens plus an `include_str!` dependency for rebuild tracking. It performs
no network access, process execution or filesystem writes.

The Linux confinement chain selects these versions through nono 0.53.0's
build dependency. That build script calls `TypeSpace` with its packaged
capability-manifest schema and default settings plus struct builders. The
macro feature is enabled by the facade's defaults, but this build script does
not invoke the macro. Chio's separate specification generator uses typify
0.4.3 and is outside these two audits.

These audits cover the facade and macro packages individually. The much
larger typify-impl backend remains a separate required review; successful
compilation does not substitute for that review.

## Boundaries and limitations

- Schema paths are trusted build inputs. Relative paths resolve against
  `CARGO_MANIFEST_DIR` (or the current directory if absent). Absolute paths
  and parent traversal are not restricted. The macro is not a filesystem
  sandbox. Tests confirm both relative and absolute schema imports.
- Configuration intentionally accepts Rust paths, attributes, derives,
  replacements and conversions. It has the authority of source code being
  compiled. Generated types and the backend's schema interpretation require
  their own review; this wrapper is not a runtime JSON Schema validator.
- Missing files produce compile errors. Invalid JSON uses an upstream
  `unwrap` and produces a proc-macro panic that fails compilation. Malformed
  settings also fail compilation. The retained tests exercise all three
  outcomes without accepting a partial generated type.
- The macro adds no schema-size or backend computation limit. Build systems
  accepting untrusted schemas need independent resource and process limits.
- The crate-name check is permissive and does not itself enforce all Rust
  identifier rules. Unsupported replacement trait names are silently ignored
  by the macro helper. Neither should be interpreted as policy enforcement.
- `unknown_crates = Deny` is documented by the wrapper as producing an error,
  but the backend's extension helper currently falls back to generation.
  Callers must not use that setting as a security allowlist. Nono's selected
  build uses the default `Generate` behavior.

## Validation

The two upstream facade integration tests pass. They compare generated source
with the unchanged golden files and compile all 21 distinct Rust fixtures
(the custom-map fixture is also compiled by its dedicated test). Both macro
unit tests and all nine facade/macro documentation checks pass. Strict Clippy
passes with all targets and features.

Five retained compile-boundary cases pass: relative schema, absolute schema,
missing file, malformed JSON and malformed settings. The first case includes
quotes, braces and a newline in schema documentation. No snapshot was updated
or assertion removed. All original files in both packages remain unchanged.

The standalone qualification workspace links the three checksum-verified
0.6.1 packages and seeds its dependency lock from Chio. Documentation examples
also need the parent `example.json`, which the registry archives omit. It was
retrieved at the exact release commit above; its SHA-256 is
`bdcb1d6e8e3b91486ce141ee7ee1ab95dc01d02584b82e02025d8b981014f6c5`.

Both packages receive individual `safe-to-deploy` source audits with the
trusted-build-input boundary above. This does not certify the backend,
dependencies, generated confinement behavior or the complete workspace.

Evidence is retained in the primary checkout under
`output/process-security-20260915/typify-audit-a19274a53/`. The companion
`typify-0.6.1-macro-boundaries.py` records expected successful compilations and
expected rejection diagnostics separately.
