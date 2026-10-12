# chio-spec-codegen architecture

## Responsibility and boundary

The crate owns specification-to-artifact generation. Its public surface
includes wire rendering and writing, error registry rendering, typed
state-machine loading and emission, threat inventory emission, and
threat-coverage document generation. `CodegenError` carries path-specific
loading, schema, reference, formatter, registry, and output-drift failures.

xtask invokes the Rust wire and state-machine passes together and exposes
error regeneration separately. The standalone binary also handles threat
inventory and coverage document generation. Type emission does not establish
canonical input, signature validity, capability authority, or conformance.

## Structure

| Module | Input and responsibility |
| --- | --- |
| `lib.rs` | Wire tree discovery, reference inlining, typify, formatting, writing |
| `errors_pass` | Indentation-based error registry parser and Rust table rendering |
| `statemachines_pass` | Typed TOML machines, validation, generated outputs and drift |
| `threat_model` | Threat JSON loading, schema helper, test inventory generation |
| `threat_coverage_doc` | Join threat rows with corpus and existing test inventory |
| `main.rs` | Positional wire mode and flags selecting the other passes |

Wire, error, and state-machine operations expose render functions so callers
can inspect output before writing. State-machine rendering returns a map
from repository-relative paths to file bodies. Coverage rendering accepts
`ThreatCoverageInputs` describing each source location.

## Data and control flow

Wire generation collects `.schema.json` files recursively and sorts them.
It identifies roots referenced by other schemas and skips those as separate
modules. Each remaining root is loaded with local references inlined,
converted to `schemars::RootSchema`, and registered with its own
`typify::TypeSpace`. Module names derive from the relative schema paths.

Typify token streams are parsed with `syn`, printed with `prettyplease`,
combined with `GENERATED_HEADER`, and formatted through a `rustfmt`
subprocess. `codegen_rust` creates the output directory and writes the
consolidated source plus the module marker. `render_chio_wire_v1` returns
the consolidated source without writing these files.

Error generation parses the restricted YAML registry and validates it before
rendering constants, tables, and lookups. State-machine loading decodes
TOML, validates each machine, and rejects duplicate machine names.
Its writing entrypoint removes obsolete files carrying managed generation
markers before writing expected output; its check entrypoint reports drift.

## Trust and invariants

Wire tree discovery rejects symlink entries. Local cross-file references
are canonicalized and required to remain inside the schema tree; external
URI schemes return `SchemaRef` errors. Merging differing definitions under
the same `$defs` key also returns an error.

The typify preprocessing step removes an entire `allOf` group when one of
its entries contains `if`. Generated Rust shapes therefore omit those
conditional assertions. JSON Schema validation remains the instance gate.
Formatting and unchanged-byte comparisons provide output reproducibility
under the pinned generator and selected formatter toolchain.

`load_threat_model` decodes the selected fields and checks the schema
identifier. Full schema validation is a separate public function; the binary
uses it only when the sibling threat schema exists. The generation wrapper
validates threat IDs and sanitizes comment text before writing stubs.
`render_threat_stub` accepts a caller-constructed entry directly, so callers
must supply a valid identifier themselves.

Threat files without a live placeholder marker are preserved by the writing
pass; remaining stubs may be refreshed. Newly emitted inventory contains a
failing placeholder. The coverage document joins declared
states and file inventory; creating that document does not execute those tests.

## Dependencies

`typify =0.4.3` converts schemas; `schemars` supplies its input representation.
`syn` and `prettyplease` handle generated Rust syntax and formatting.
`serde`, `serde_json`, and `toml` decode inputs. `jsonschema` powers the
explicit threat-model schema helper. `rustfmt` is an external process used
by Rust rendering, including the wire source string API.

## Verification

`cargo test -p chio-spec-codegen` exercises missing directories, symlink
refusal, external references, typed receipt emission, state-machine validation
and drift, and threat rendering and comment sanitization.
`tests/threat_model_schema_test.rs` checks the repository threat model and
negative mutations against its schema.

The [README](README.md) supplies a wire generation command whose output stays
in a temporary directory. [xtask](../../../xtask/README.md) documents the
workspace gate boundary and the [protocol](../../../spec/PROTOCOL.md#4-serialization-and-identity)
defines signed serialization requirements.
