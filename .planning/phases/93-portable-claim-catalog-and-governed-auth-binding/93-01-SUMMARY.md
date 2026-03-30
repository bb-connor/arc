# Summary 93-01

Defined one shared portable claim-catalog and identity-binding contract for
ARC's standards-facing surfaces. The canonical types now live in
`crates/arc-core/src/standards.rs` and are consumed by the portable SD-JWT VC
type metadata and OID4VCI portable profile builders in `arc-credentials`.

This closes the earlier drift where claim disclosure support, binding strings,
and portable provenance semantics were duplicated across metadata, issuance,
verification, and verifier-request filtering.
