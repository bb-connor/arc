# chio-tee-frame

Typed capture records and validation for `chio-tee-frame.v1`. The wire crate
connects the `chio-tee` observation sidecar to replay consumers through
canonical JSON, redacted blob hashes, verdict metadata, and tenant signatures.

## Usage

Create and sign a local frame, then validate it against the chosen tenant key:

```rust
use base64::{engine::general_purpose::STANDARD, Engine};
use chio_core::crypto::Keypair;
use chio_tee_frame::{
    canonicalize, parse, signing_body, validate_signed, TEE_CAPTURE_FRAME_SCHEMA,
    Frame, FrameInputs, Otel, Provenance, Upstream, UpstreamSystem, Verdict,
};
let key = Keypair::from_seed(&[7; 32]);
let mut frame = Frame::build(FrameInputs {
    event_id: "01H7ZZZZZZZZZZZZZZZZZZZZZZ".into(),
    ts: "2026-04-25T18:02:11.418Z".into(), tee_id: "tee-local".into(),
    upstream: Upstream {
        system: UpstreamSystem::Mcp, operation: "tool.call".into(),
        api_version: "1".into(),
    },
    invocation: serde_json::json!({"tool": "read"}),
    provenance: Provenance {
        otel: Otel { trace_id: "0".repeat(32), span_id: "0".repeat(16) },
        supply_chain: None,
    },
    request_blob_sha256: "a".repeat(64), response_blob_sha256: "b".repeat(64),
    redaction_pass_id: "local@1".into(), verdict: Verdict::Allow,
    deny_reason: None, would_have_blocked: false,
    tenant_sig: format!("ed25519:{}", STANDARD.encode([0u8; 64])),
})?;
frame.tenant_sig = format!("ed25519:{}",
    STANDARD.encode(key.sign_wrapped(TEE_CAPTURE_FRAME_SCHEMA, &signing_body(&frame)?)?.to_bytes()));
let decoded = parse(&canonicalize(&frame)?)?;
validate_signed(&decoded, &key.public_key_bytes())?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

The sample hashes are fixture metadata. Consumers separately retrieve and
rehash referenced blobs, select trusted tenant keys, and enforce freshness.

## Guarantees

- `Frame::build`, `parse`, and `canonicalize` validate structural invariants:
  schema, identifiers, time format, object invocation, hashes, and reason gate.
- `parse` bounds original JSON to 16 MiB and rejects duplicate members.
- `signing_body` excludes only `tenant_sig` from canonical frame bytes; `signing_payload`
  is the 88-byte signing wrapper over it under `chio.tee-capture-frame.v1`.
  `validate_signed` adds Ed25519 verification using a caller-resolved key.
- Deny/rewrite require a namespaced reason; allow requires its absence.

## Status

Implemented capture schema, canonical encoding, and signed validation.
Structural parsing checks signature shape only. Signature verification does
not authenticate external blob contents, supply-chain metadata, or verdict
provenance; consumers provide those checks at their replay boundary.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol contract](../../../spec/PROTOCOL.md#41-canonical-json)
- [chio-tee](../chio-tee/README.md)

[License](../../../LICENSE)
