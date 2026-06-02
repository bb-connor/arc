# chio-errors Architecture

## Boundary

`chio-errors` owns the typed Chio error taxonomy and diagnostic construction
surface. It exposes canonical `Domain`, `Severity`, `Code`, `Diagnostic`, and
`ChioError` types, plus lookup access to the generated error registry and the
JSON-RPC bridge. It does not decide policy, evaluate guards, format CLI output,
or translate transport status codes. Callers should bring domain context and
message text; this crate should bind those messages to stable Chio registry
metadata when a registry entry exists.

## Module Boundaries

- `code` owns the serializable diagnostic code string wrapper.
- `domain` owns stable error-domain slugs and parsing.
- `severity` owns severity ordering and parsing.
- `diagnostic` owns the structured diagnostic and error types.
- `jsonrpc_bridge` owns conversion between registry entries and wire-side
  JSON-RPC numeric codes.
- `_generated::error_codes` is generated from `spec/errors/registry.yaml` by
  `chio-spec-codegen` and must not be edited directly.

## Pain Points

- Registry entries already carry canonical URN, domain, severity, summary, help,
  stability, string-code, and JSON-RPC metadata.
- Callers that want a `ChioError` from an `ErrorCodeSpec` currently reconstruct
  the diagnostic fields manually, which duplicates registry binding logic.
- Free-form `Code::new` must remain available for compatibility, so stronger
  registry invariants need an additive constructor path rather than a breaking
  validation change.
- Generated lookup helpers are intentionally simple, but no non-generated API
  currently centralizes the common "registered error with caller message" path.

## Security And API Constraints

- Preserve public API compatibility for `Code::new`, `diagnostic`, `error`,
  registry lookup functions, and generated `ErrorCodeSpec` constants.
- Do not edit `_generated` files directly. Registry data changes must go through
  `spec/errors/registry.yaml` and `chio-spec-codegen`.
- Diagnostics built from registry entries must use the registry's URN, domain,
  severity, and help text without allowing callers to accidentally mismatch
  those fields.
- Unknown free-form codes must remain representable for legacy CLI and transport
  surfaces.
- JSON-RPC bridge behavior must remain fail-closed for unmapped numeric codes.

## Affected Dependents

Direct dependents include `chio-cli`, `chio-control-plane`, and `chio-lsp`.
Downstream consumers through `chio-control-plane` include `chio-hosted-mcp`,
`chio-mcp-remote`, `chio-conformance`, `chio-mercury`, and `chio-wall`.
The planned change is additive and should not force dependent source edits.

## Planned Improvement

Add registry-bound constructors for diagnostics and errors. Keep the existing
free-form constructors intact, but add a path that takes an `ErrorCodeSpec` and
caller-supplied message, then fills in the canonical URN, domain, severity, and
help directly from the registry entry.

This is architectural because it moves registry binding into the owning crate
instead of making every consumer rebuild the same structure by convention:
registry entry + local message -> canonical diagnostic -> `ChioError`.
