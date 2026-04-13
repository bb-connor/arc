---
phase: 312
plan: 02
created: 2026-04-13
status: complete
---

# Summary 312-02

A machine-readable numeric ARC error registry now exists in
[spec/errors/arc-error-registry.v1.json](/Users/connor/Medica/backbay/standalone/arc/spec/errors/arc-error-registry.v1.json).

The registry assigns stable numeric codes across the roadmap categories:

- `protocol`
- `auth`
- `capability`
- `guard`
- `budget`
- `tool`
- `internal`

Each entry now carries explicit `transient` classification plus retry
guidance. The hosted MCP runtime uses that registry immediately for initialize
version rejection by returning `error.data.arcError` with the ARC numeric code,
category, transient flag, and retry strategy.

The new registry test in
[crates/arc-core-types/tests/protocol_error_registry.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-core-types/tests/protocol_error_registry.rs)
enforces unique numeric codes, complete category coverage, and consistency
between the negotiation artifact and the error registry.
