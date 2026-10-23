# chio-mercury-core architecture

## Responsibility and boundary

Mercury core owns typed workflow evidence and its in-memory validation.
`MercuryReceiptMetadata` supplies the business envelope stored under
`metadata.mercury` in a signed Chio receipt. `MercuryProofPackage` wraps an
`EvidenceExportBundle`; `MercuryInquiryPackage` derives a reviewer projection.
The crate performs no database queries or file exports.

Public fields allow callers to assemble and mutate contracts. Consumers must
choose structural validation, bundled cryptographic verification, or trusted
signer verification according to their acceptance boundary.

## Structure

| Modules | Responsibility |
| --- | --- |
| `receipt_metadata`, private `validation` | Workflow identifiers, chronology, provenance, disclosure, approval, and required-field checks. |
| `bundle` | Artifact references, canonical bundle manifests, and signed-reference shapes. |
| `proof_package` | Package IDs, receipt acceptance, checkpoint coverage, publication material, and inquiry projections. |
| `query` | Filter fields and index records copied from metadata. |
| `fixtures`, `pilot`, `supervised_live` | Sample metadata, modeled workflow paths, capture gates, and health declarations. |
| `downstream_review`, `governance_workbench`, `assurance_suite` | Consumer, control-review, and reviewer/investigation contracts. |
| `embedded_oem`, `trust_network` | Partner and witness-exchange package contracts. |
| Distribution, account, and program modules | Schema-tagged profiles, artifact kinds, and upstream package references. |

The crate root re-exports primary contracts and schema constants.
The proof module also exposes `MercuryInquiryPackageArgs` for construction.
`MercuryReceiptQuery` is a Serde filter shape; storage owners implement matching.
`MercuryReceiptIndexRecord::from_metadata` copies fields and assumes the caller
has already validated metadata.

## Data and control flow

Metadata serialization calls `validate` before producing the `mercury` wrapper.
`merge_into_receipt_metadata` preserves an existing object and replaces its
Mercury member; a nonobject existing value rejects. Extraction validates the
member when present and returns `None` when it is absent.

`MercuryProofPackage::build` reads metadata from every exported tool receipt,
requires a shared workflow, derives common optional identifiers, and computes
coverage and publication material. It emits the v2 schema and hashes a
deterministic package identity before structural validation.
`validate` also recognizes legacy v1 identity derivation.

`verify_integrity_only` validates the package and calls `verify_chio_bundle` to
check receipt self-signatures, required checkpoint signatures, and Merkle
inclusion evidence, and reports `scope: integrity_only`.
`verify_with_trusted_kernel_keys` adds explicit signer membership, trusted
checkpoint requirements, and exact signed bundle-manifest coverage.

`MercuryInquiryPackage::build` chooses the greatest receipt sequence as the
source of approval and disclosure, authenticates its checkpoint order, and
builds a deterministic audience/redaction projection. Validation recomputes
its ID, rendered export, and rendered hash. The full proof remains embedded;
a redaction-profile label is part of the projection and does not remove that
embedded proof from the package.

## Trust and invariants

`validate_mercury_tool_receipt` requires a mediated allow decision, mediated
trust, and the `mercury` server. It verifies the action parameter hash and
matches workflow ID, event ID, decision type, stage, and tool name to the signed
metadata and receipt. Signed observations fail this authorization check.

Trusted verification requires checkpoints, inclusion proofs, no packaged
uncheckpointed receipts, required signature/proof flags, and coverage derived
from the actual bundle. Every tool, child, and checkpoint signer must occur in
the trusted key set. Manifest coverage rejects duplicate manifest IDs,
conflicting signed references, missing counterparts, and mismatched hash,
artifact count, or retention class.

Both proof verification methods report `verifier_equivalent: false`.
Signed checkpoint-prefix coverage does not authenticate the current source-log
tip or exclude later receipts. An unsigned export query and descriptor cannot
establish source-population equivalence. Inquiry construction downgrades a
requested equivalence flag, and inquiry validation rejects a true flag.

`MercuryBundleManifest::canonical_bytes` validates before canonical JSON;
`manifest_sha256` applies SHA-256. Manifest validation checks reference fields
but does not read artifact contents or enforce digest-string syntax.
Metadata extraction alone does not verify a receipt's signature.

## Dependencies and verification

The dependency named `chio-core` is an alias for `chio-core-types` and supplies
receipt types, cryptography, and canonical hashing. `chio-kernel` supplies
export bundles, checkpoint/inclusion verification, and publication contracts.
Serde provides wire shapes and Thiserror defines `MercuryContractError`.
There are no package-defined Cargo features or persistent resource owners.

`proof_package/tests.rs` covers mixed workflows, deny/observation acceptance,
action mismatches, trusted signer membership, signed manifest coverage, legacy
identities, and inquiry tampering. `proof_package/tests/completeness.rs` checks
selected receipt coverage against missing, extra, duplicate, and misbound proofs
and attempts to elevate coverage by mutating unsigned query fields.
Metadata and bundle unit tests reject padded identifiers and check stable hashes.
The integration smoke test exercises the exported fixtures.
Run `cargo test -p chio-mercury-core` for these contract and verifier tests.

[README](README.md) demonstrates metadata roundtripping and indexing.
