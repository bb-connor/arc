# chio-config Architecture

## Boundary

`chio-config` owns ingestion of operator `chio.yaml` configuration before the
runtime, adapters, guard loaders, and control-plane code wire themselves from
that data. It does not instantiate kernels, start adapters, resolve guard
modules, or open storage connections. Its responsibility is to turn config text
or files into a typed `ChioConfig` only after interpolation, schema
deserialization, defaults, and validation have all succeeded.

## Module Boundaries

- `schema` owns the typed `chio.yaml` shape and serde defaults.
- `interpolation` owns `${VAR}` and `${VAR:-default}` expansion before YAML
  deserialization.
- `validation` owns cross-field checks after typed deserialization, including
  adapter IDs, edge references, auth blocks, kernel fields, and logging values.
- `loader` owns the canonical ingest sequence from file/string to validated
  `ChioConfig`.
- `fuzz` is feature-gated and drives arbitrary bytes through the same loader
  path without adding production dependencies.

## Pain Points

- The loader currently uses the same raw interpolation function as general
  string callers, even though loader interpolation happens before YAML parsing.
- Raw environment values can therefore affect YAML syntax if a replacement
  contains line breaks, quote delimiters, comment markers, or surrounding
  whitespace.
- Validation is correctly typed and aggregate, but it only runs after YAML has
  already accepted the interpolated document.

## Security And API Constraints

- Existing public API entry points must remain compatible:
  `load_from_file`, `load_from_str`, `interpolation::interpolate`, schema
  structs, and `validation::validate`.
- Unknown config fields must continue to fail at parse time through
  `deny_unknown_fields`.
- Missing interpolation variables without defaults must continue to fail closed
  before parsing.
- Loader interpolation must not let environment variables or defaults inject
  new YAML structure, truncate scalar values through comments, or break quoted
  strings.
- Validation must keep returning all detected semantic errors in one pass.
- The `fuzz` feature must remain optional and must not affect production
  dependencies.

## Affected Dependents

Direct dependents include `chio-wasm-guards`; downstream consumers include
`chio-cli`, e2e tests, `chio-conformance`, `chio-control-plane`,
`chio-hosted-mcp`, `chio-mcp-remote`, `chio-mercury`, and `chio-wall`.
The planned change is additive at the public API level and should not require
dependent source edits.

## Planned Improvement

Introduce a loader-specific interpolation boundary. Keep
`interpolation::interpolate` as the raw compatibility function, but make
`loader::load_from_str` call a stricter interpolation path that rejects
replacement values capable of changing YAML syntax before deserialization.

This is architectural because it separates general string interpolation from
trusted config ingestion and moves a security invariant to the earliest point
in the load lifecycle:
raw config -> loader-safe interpolation -> YAML deserialization -> validation.
