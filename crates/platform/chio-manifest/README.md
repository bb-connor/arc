# chio-manifest

Defines signed `chio.manifest.v2` tool discovery and admission. A tool
manifest describes input/output schemas, behavioral annotations, pricing,
provider-native tools, flow declarations, and host permissions.

## Usage

Sign a local manifest and verify it against an explicitly selected key. The
fixed seed is example key material. Admission callers obtain the registered
key from their trusted server registry.

```rust
use chio_core::Keypair;
use chio_manifest::{sign_manifest, verify_manifest, ToolManifest,
    ToolDefinition, ToolAnnotations, TOOL_MANIFEST_SCHEMA};

let key = Keypair::from_seed(&[5; 32]);
let manifest = ToolManifest {
    schema: TOOL_MANIFEST_SCHEMA.into(), server_id: "catalog".into(),
    name: "Catalog".into(), version: "1.0.0".into(), description: None,
    tools: vec![ToolDefinition {
        name: "lookup".into(), description: "Look up a record".into(),
        input_schema: serde_json::json!({"type": "object"}),
        output_schema: None, pricing: None, latency_hint: None, flow: None,
        annotations: ToolAnnotations {
            read_only: true, destructive: false,
            idempotent: true, requires_approval: false,
        },
    }],
    server_tools: vec![], required_permissions: None,
    public_key: key.public_key().to_hex(),
};
let signed = sign_manifest(&manifest, &key)?;
verify_manifest(&signed, &key.public_key())?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Guarantees

`sign_manifest` validates shape and requires the embedded public key to
match the signing key. `verify_manifest` repeats shape validation, checks
embedded/envelope/key agreement, and verifies canonical bytes.

`VerifiedManifestRegistry::register` adds caller-selected policy and runtime
topology, compiles input validators, and derives admitted flow security.
`ToolInputSchemaValidator::compile` refuses external schema retrieval. The
existing-file loader bounds signed input to 1 MiB and checks expected server
identity.

## Status

Implemented v2 format and verified admission registry. Serde checks field
layout; `validate_manifest` requires the v2 schema, valid identity fields,
and a nonempty tool list with unique names. Trusted registration also
requires signature verification and operator-owned policy/topology.
Sandbox installation and tool execution belong to consumers.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol](../../../spec/PROTOCOL.md#7-manifest-contract)
- [chio-config](../chio-config/README.md)
- [License](../../../LICENSE)
