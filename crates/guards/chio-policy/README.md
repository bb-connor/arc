# chio-policy

Parse, validate, resolve, evaluate, and compile HushSpec policies for Chio.
`CompiledPolicy` contains request guards, response hooks, a default capability
scope, optional threshold approval requirements, and ordered guard names.
The kernel owns admission, tool execution, and signed enforcement receipts.

## Usage

Compile an explicit tool allowlist entirely in memory:

```rust
use chio_policy::{compile_policy, HushSpec};

let policy = HushSpec::parse(r#"
hushspec: "0.1.0"
rules:
  tool_access:
    enabled: true
    allow: ["files.read"]
    default: block
"#)?;
let compiled = compile_policy(&policy)?;
assert_eq!(compiled.default_scope.grants.len(), 1);
assert_eq!(compiled.default_scope.grants[0].tool_name, "files.read");
# Ok::<(), Box<dyn std::error::Error>>(())
```

The example uses existing dependencies and needs no files, services, or features.
Register both compiled pipelines with the runtime and use the scope through the
capability authority. The crate declares no Cargo features.

## Guarantees

- `HushSpec::parse` checks YAML input hazards and rejects unknown schema fields.
  Semantic validation is a separate operation.
- `validate` checks version `0.1.0`, patterns, limits, and extension constraints.
  `ValidationResult::is_valid` examines errors; warnings remain informational.
- `compile_policy` runs validation and rejects unsupported execution semantics,
  including origin-specific sender proof and unsupported approval fields.
- `compile_scope` emits no default grants for missing or disabled tool rules.
  Explicit default-allow rules can emit wildcard grants when representable.
- `resolve_from_path_with_limits` bounds document bytes and inheritance depth;
  the default limits are 4 MiB per document and depth 32. HTTP loading is rejected.

`evaluate` is a reference evaluator returning allow, warn, or deny. Unknown action
types deny; an unrestricted recognized action can allow without issuing authority.
`DecisionReceipt` records evaluation metadata and has no signature field.

## Status

Implemented modules include embedded rulesets, inheritance, conditions,
origin/posture evaluation, compilation, and bounded static analysis. Reference
evaluation and compiled enforcement cover different rule surfaces. Analysis
reports identify unsupported or inconclusive portions explicitly.

The crate has no platform feature matrix or conditional platform API exports.
Filesystem resolution and auxiliary detection assets require host file access;
the in-memory example avoids those operations. Local tests cover parsing,
compilation, validation, clock failures, approval, and scope authority boundaries.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol verification rules](../../../spec/PROTOCOL.md#53-verification-rules)
- [Native guards](../chio-guards/README.md)
- [Receipt semantics](../../../spec/PROTOCOL.md#61-receipt-semantics-and-decisions)

[License](../../../LICENSE)
