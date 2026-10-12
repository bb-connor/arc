# chio-spec-codegen

`chio-spec-codegen` generates Rust wire types and supporting artifacts from
Chio specification inputs. The library supplies the Rust backend called by
xtask; its binary also exposes focused wire, error, state-machine, threat
inventory, and threat-coverage document passes.

## Usage

From the workspace root, generate wire bindings into a temporary output directory:

```sh
codegen_out="$(mktemp -d)"
cargo run -p chio-spec-codegen -- spec/schemas/chio-wire/v1 "$codegen_out"
```

This offline pass needs `rustfmt` on `PATH`. It writes `chio_wire_v1.rs` and
a header-only `mod.rs`; the latter declares no submodules. The two positional
arguments select the schema tree and output directory. Use a dedicated output
directory because generation overwrites differing output bytes.

Library callers can use `codegen_rust` for these files or
`render_chio_wire_v1` for the formatted wire source string. Other passes have
separate render and write entrypoints:

| Input | Output/API |
| --- | --- |
| Wire schema tree | `codegen_rust`, `render_chio_wire_v1` |
| Error registry YAML | `codegen_error_codes`, `render_error_codes` |
| State-machine TOML | `render_statemachine_outputs`, `codegen_statemachines` |
| Threat-model JSON | `codegen_threat_model`, `render_threat_stub` |
| Threat model and corpus inventory | `render_threat_coverage_doc` |

## Guarantees

- `walk_schema_files` sorts inputs through its callers and rejects symlink
  entries. Wire generation uses a separate `typify::TypeSpace` per emitted root.
- `resolve_local_schema_ref` rejects URI schemes and local references that
  canonicalize outside the schema tree. Definition collisions return errors.
- `codegen_rust` stamps `GENERATED_HEADER`, formats output with `rustfmt`,
  and avoids rewriting files whose bytes already match.
- `load_statemachines` validates typed tables before rendering.
  `check_statemachine_outputs` detects stale, missing, and obsolete managed files.
- `codegen_threat_model` checks threat IDs before using them as filenames
  and preserves per-threat files without a live placeholder marker.

## Status

This workspace package has a library and binary and is marked
`publish = false`. Generated wire bindings have a header-only module marker;
the pass does not add them to a crate's public modules. Conditional `allOf`
groups containing `if` are removed before typify conversion. Consumers still
need instance validation for the full JSON Schema contract.

Threat inventory files contain a failing placeholder until a test body is
supplied. The separate schema-validation helper checks the full threat model;
`load_threat_model` itself checks the discriminator and decodes selected fields.
`cargo test -p chio-spec-codegen` exercises generation and input rejection.

## Related

- [Architecture](ARCHITECTURE.md)
- [Serialization contract](../../../spec/PROTOCOL.md#4-serialization-and-identity)
- [Schema validator](../chio-spec-validate/README.md)
- [Generated core types](../../core/chio-core-types/README.md)
- [Workspace task runner](../../../xtask/README.md)

## License

[Apache-2.0](../../../LICENSE)
