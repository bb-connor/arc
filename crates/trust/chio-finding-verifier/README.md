# chio-finding-verifier

Offline evidence verification for signed cognition-market findings. It turns
canonical finding bytes, pinned trust roots, and resolved evidence into a
read-only draft containing thirteen ordered verification facets.

## Usage

Verify a locally signed receipt's internal authenticity before resolving its
external trust and checkpoint standing. Full finding evaluation uses
`verify_finding_evidence(raw_finding, trust, bundle)`.

```rust
use chio_core_types::Keypair;
use chio_core_types::receipt::kinds::TrustLevel;
use chio_core_types::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core_types::receipt::decision::{Decision, ToolCallAction};
use chio_finding_verifier::verify_receipt_strict;

let key = Keypair::from_seed(&[7; 32]);
let body = ChioReceiptBody {
    id: String::new(), timestamp: 1, capability_id: "cap-local".into(),
    tool_server: "local".into(), tool_name: "read".into(),
    action: ToolCallAction::from_parameters(serde_json::json!({"path":"a"}))?,
    decision: Some(Decision::Allow), receipt_kind: Default::default(),
    boundary_class: Default::default(), observation_outcome: None,
    tool_origin: Default::default(), redaction_mode: Default::default(),
    actor_chain: vec![], content_hash: "a".repeat(64),
    policy_hash: "local-policy".into(), evidence: vec![], metadata: None,
    trust_level: TrustLevel::Mediated, tenant_id: None,
    kernel_key: key.public_key(), bbs_projection_version: None,
};
let receipt = ChioReceipt::sign(body, &key)?;
verify_receipt_strict(&receipt)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Guarantees

- `verify_finding_evidence` caps raw findings at 256 KiB and checks exact
  canonical bytes, profile standing, admitted kernel keys, and finding liveness.
- `verify_receipt_strict` rejects weak Ed25519 keys, validates BBS binding,
  recomputes the receipt id, and strictly verifies the signing body.
  External signer authorization belongs to the full evidence verifier.
- `FindingVerifierDraft::satisfies_required_facets` rejects every failed facet
  and requires exact `Verified` outcomes for all required facets.
- `sign_finding_verifier_report` binds the evaluated profile and its authorized
  signing key without exposing mutation of derived facets or evidence digests.

## Status

Implemented pure verifier and report signer. Callers resolve receipts,
checkpoints, recipe preimages, collateral snapshots, status proofs, and trusted
clock evidence. Trusted market admission additionally requires a venue-signed
admission bundle and its constituent checks. The crate declares no Cargo
features and is unpublished (`publish = false`).

## Related

- [Architecture](ARCHITECTURE.md)
- [Finding artifact contract](../../../spec/PROTOCOL.md#647-finding-artifact-family)
- [Challenge evaluator](../chio-finding-challenge/README.md)
- [Finding artifact types](../../economy/chio-finding/README.md)

[License](../../../LICENSE)
