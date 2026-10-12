# chio-enterprise-export

Verifies enterprise export evidence within a transaction proof bundle:
governance classifications, export digests, telemetry receipts, approval
quorum, control mapping, and risk-comptroller reports.

## Usage

Show that a supplied passport cannot make a bundle trusted without selected
root keys. Complete bundles additionally need committed
graph/policy/artifact bytes and separate receipt, approval, and
risk-authority pins. The fixture is embedded at compile time.

```rust
use std::collections::BTreeMap;
use chio_enterprise_export::{verify_enterprise_export, EnterpriseExportBundle};
use chio_transaction_passport::{decode_evidence_json, TransactionPassport,
    TransactionPassportError};

let passport: TransactionPassport = decode_evidence_json(include_bytes!(
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../../fixtures/proof-room/",
        "enterprise-export/valid-autonomous-commerce/transaction-passport.json")))?;
let bundle = EnterpriseExportBundle {
    passport, evidence_graph_bytes: vec![], root_evidence_graph_bytes: None,
    verifier_policy_bytes: vec![], artifacts: BTreeMap::new(),
    trusted_passport_signer_keys: vec![], trusted_receipt_kernel_keys: vec![],
    trusted_approval_signer_keys: vec![],
    trusted_risk_comptroller_signer_keys: vec![],
};
assert!(matches!(verify_enterprise_export(&bundle),
    Err(TransactionPassportError::MissingTrustedTransactionRootKeys)));
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Guarantees

`verify_enterprise_export` bounds evidence inputs and verifies the pinned
passport signature before family checks. Artifact lookup recomputes graph
digests; risk and approval signatures use caller-selected keys, and
telemetry receipt checks require trusted kernel keys.

`validate_evidence_export_bundle` recomputes the export index digest and
checks required artifact roles. Approval checks bind that digest, distinct
approvers/quorum, and issuance/expiry relative to export time. Control
mapping checks that each claim uses a suitable graph gate.

## Status

Implemented offline enterprise evidence verifier. `[lib] test = false`;
integration tests compose signed artifacts and exercise rejection cases.
Governance fields, export policy, and telemetry are checked as supplied
evidence. The crate does not perform exports, apply retention, enforce legal
holds, or query enterprise systems.

## Related

- [Architecture](ARCHITECTURE.md)
- [Protocol](../../../spec/PROTOCOL.md#643-transaction-passport-proof-root)
- [chio-risk-comptroller](../chio-risk-comptroller/README.md)
- [License](../../../LICENSE)
