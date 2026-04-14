---
phase: 311
plan: 03
created: 2026-04-13
status: complete
---

# Summary 311-03

Versioned native message schemas now live in
[spec/schemas/arc-wire/v1](</Users/connor/Medica/backbay/standalone/arc/spec/schemas/arc-wire/v1>).
The checked-in schema set covers every shipped native message variant plus the
nested `ToolCallResult` and `ToolCallError` families.

The new validation harness in
[crates/arc-core-types/tests/wire_protocol_schema.rs](/Users/connor/Medica/backbay/standalone/arc/crates/arc-core-types/tests/wire_protocol_schema.rs)
serializes live Rust values and validates them with the checked-in schemas via
`jsonschema`. The test exercises:

- all `AgentMessage` variants
- all `KernelMessage` variants
- every `ToolCallResult` variant
- every `ToolCallError` variant

That means the schema directory is no longer passive documentation; it is a
conformance artifact tied directly to the Rust serialization contract.
