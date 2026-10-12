# chio-selective-disclosure

`chio-selective-disclosure` projects receipt and workflow fields into typed
message vectors, builds disclosure manifests, and optionally signs and verifies
BBS proofs. It re-exports the disclosure-lineage artifact verifier.

## Usage

Project one offline workflow step and inspect the generated disclosure policy.
The default build provides projection APIs without enabling BBS cryptography.

```rust
use chio_selective_disclosure::{
    project_step_record, bbs_projection_manifest_from_projection,
    BbsProjectionDisclosure,
};
use chio_workflow::receipt::{StepRecord, StepOutcome};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let step = StepRecord {
        step_index: 0, server_id: "server-1".into(), tool_name: "read".into(),
        allowed: true, tool_receipt_id: Some("receipt-1".into()),
        outcome: StepOutcome::Success, duration_ms: 42, cost: None,
        output_hash: None, bilateral_dsse_sha256: None, governance_receipt_id: None,
        parent_receipt_sha256: None, consistency_anchor: None, destructive: None,
    };
    let projection = project_step_record("workflow-1", &step)?;
    let manifest = bbs_projection_manifest_from_projection(&projection);
    let timing = manifest.message_slots.iter().find(|slot| slot.field == "duration_ms");
    assert!(timing.is_some_and(|slot| slot.disclosure == BbsProjectionDisclosure::Hidden));
    Ok(())
}
```

## Features

| Feature | Default | Effect |
| --- | --- | --- |
| `default` | Empty | Projections, artifact types, manifest and transparency checks, lineage APIs. |
| `bbs` | Off | Enables `affinidi-bbs`, key generation, BBS signing/proofs, context verification, and the fixture example. |

## Guarantees

- Projection functions fix field order and encodings; hash fields require 64
  lowercase hex characters. Structured fields use canonical JSON hashes.
- `sign_chio_receipt_with_bbs` checks the one-time `ReceiptSigningHandle` against
  the prepared content hash before producing BBS material.
- `verify_selective_disclosure_proof` checks a registered key and BBS proof,
  including its message count, disclosed indices, labels, encodings, and nonce.
- `verify_bbs_projection_manifest` separately enforces disclosed slots and blocks
  wholesale-only or exact `duration_ms` disclosure. Call it alongside proof checks.

## Status

Default projections and optional BBS operations are implemented. The issuer
registry is in memory. Crypto-context policy evaluates caller-supplied key,
revocation, holder, replay, and timing state; it does not fetch or authenticate
those inputs. BBS proofs reveal a stable subject digest, issuer identity, message
count, and selected metadata. They provide no general hidden range predicates.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol disclosure family](../../../spec/PROTOCOL.md#645-disclosure-and-lineage-family)
- [Disclosure lineage](../chio-disclosure-lineage/README.md)

## License

[Workspace license](../../../LICENSE)
