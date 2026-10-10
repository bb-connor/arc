# chio-manifest

Defines `chio.manifest.v2`, the signed manifest format a Chio tool server uses
to declare its tools, and the functions to build, sign, and verify one. A
manifest is how a server advertises its tool schemas and how a verifier
confirms the advertisement came from the server's registered key before the
server is admitted.

## Responsibilities

- Define the manifest schema: `ToolManifest`, `ToolDefinition`, `ToolPricing`,
  `RequiredPermissions`, `LatencyHint`, `ServerTool`.
- Validate manifest structure independent of signing: non-empty tool list,
  unique tool names, object-shaped input/output schemas, per-model pricing
  completeness, and unpadded, control-character-free identity and permission
  text (`validate_manifest`).
- Sign a manifest's canonical JSON with an Ed25519 keypair and wrap the result
  in a `SignedManifest` envelope (`sign_manifest`).
- Verify a `SignedManifest` against a trusted public key, including that the
  manifest's self-declared `public_key` matches the actual signer
  (`verify_manifest`).

## Public API

- `ToolManifest` - identity (`server_id`, `name`, `version`), `tools`,
  allowlisted `server_tools`, `required_permissions`, `public_key`.
  `allows_server_tool` checks the allowlist.
- `TOOL_MANIFEST_SCHEMA` - the only accepted `schema` value, `"chio.manifest.v2"`.
- `ToolDefinition` - one tool: name, description, JSON Schema
  `input_schema`/`output_schema`, optional `pricing`, required behavioral
  `annotations`, optional `latency_hint` and authenticated `flow` declaration.
- `ServerTool` - provider-native tools that require explicit allowlisting
  (`ComputerUse`, `Bash`, `TextEditor`). `from_anthropic_wire_name` maps dated
  wire names (e.g. `bash_20241022`) to the stable variant.
- `ToolPricing` / `PricingModel` (`Flat`, `PerInvocation`, `PerUnit`, `Hybrid`) -
  advertised pricing metadata.
- `RequiredPermissions` - read/write paths, normalized network destinations
  with explicit nonzero ports, validated environment variable names and a
  required closed `native_syscall_profile`.
- `LatencyHint` - `Instant` | `Fast` | `Moderate` | `Slow`.
- `SignedManifest` - `manifest` plus its `signature` and `signer_key`.
- `ManifestError` - structural and signing failure modes; `Signing` wraps
  `chio_core::Error`.
- `validate_manifest`, `sign_manifest`, `verify_manifest` - structural check,
  sign, and verify. `sign_manifest` and `verify_manifest` each call
  `validate_manifest` internally.
- `VerifiedManifestRegistry` - admission against a registered key, independently
  selected policy and runtime topology; validates invocation input schemas.
- `load_existing_verified_manifest_registry` - bounded, duplicate-aware loading
  of an existing signed manifest with an out-of-band signer and server identity.

## Schema transition

The current runtime accepts v2 only. The former v1 migration API was removed;
there is no automatic conversion of a v1 signature or permission grant. An
operator must review the v2 annotations, flow policy and typed cage permissions,
then obtain a newly signed v2 manifest and admit it against the registered key.
Changing the schema string alone does not preserve the old signature.

Unknown fields and noncanonical optional-field spellings are rejected. Omit
absent optional fields instead of encoding them as `null`, and omit empty
`server_tools`. The normative shape is
[tool-manifest-v2.schema.json](../../../spec/schemas/chio-wire/v1/security/tool-manifest-v2.schema.json).

## Usage

```rust
use chio_core::Keypair;
use chio_manifest::{
    sign_manifest, verify_manifest, LatencyHint, ToolAnnotations, ToolDefinition, ToolManifest,
    TOOL_MANIFEST_SCHEMA,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = Keypair::generate();
    let manifest = ToolManifest {
        schema: TOOL_MANIFEST_SCHEMA.to_string(),
        server_id: "srv-example".into(),
        name: "Example Server".into(),
        description: None,
        version: "1.0.0".into(),
        tools: vec![ToolDefinition {
            name: "echo".into(),
            description: "Echo input".into(),
            input_schema: serde_json::json!({"type": "object"}),
            output_schema: None,
            pricing: None,
            annotations: ToolAnnotations {
                read_only: true,
                destructive: false,
                idempotent: true,
                requires_approval: false,
            },
            latency_hint: Some(LatencyHint::Instant),
            flow: None,
        }],
        server_tools: Vec::new(),
        required_permissions: None,
        public_key: keypair.public_key().to_hex(),
    };

    let signed = sign_manifest(&manifest, &keypair)?;
    verify_manifest(&signed, &keypair.public_key())?;
    Ok(())
}
```

## Testing

`cargo test -p chio-manifest`

## See also

- `chio-core` - supplies `Keypair`, `PublicKey`, `Signature`, and `MonetaryAmount`.
- `chio-mcp-adapter`, `chio-mcp-edge` - build and validate `ToolManifest`s for
  MCP-backed servers.
- `chio-binding-helpers` - FFI-facing JSON helpers that report structural and
  signature validity separately, built on this crate's `validate_manifest`.
