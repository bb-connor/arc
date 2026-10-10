//! A distinct authenticated Proposal terminal closes only its complete evidence owner.
use super::super::knowledge::references::{ProductEvidenceOwner, SourceAnchor};
use super::*;

mod source;
mod writer;

pub(in crate::admission_operation_store) use source::{
    product_reclamation_source, verify_product_reclamation_inventory,
    ProductEvidenceReclamationSource,
};
pub(in crate::admission_operation_store) use writer::VerifiedProductEvidenceReclamation;
pub(super) use writer::{append_reclamation, ProductReclamationWriter};

const RECLAMATION_PREFIX: &str = "product-disposition:reclaimed-proposal-evidence:";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReclaimedProposalEvidence {
    domain_version: VersionV1,
    scope: RecoveryScopeV1,
    proposal_id: ReviewId,
    proposal_digest: CanonicalPayloadDigest,
    original: SourceAnchor,
    archive: SourceAnchor,
    reclaimer: PrincipalId,
    reclaimer_subject: PublicKey,
    reclaimed_at_unix_ms: SafeInteger,
}

fn reclamation_key(
    scope: &RecoveryScopeV1,
    id: &ReviewId,
) -> Result<String, AdmissionOperationStoreError> {
    Ok(format!(
        "{RECLAMATION_PREFIX}{}:{}",
        protected::scope_key(scope)?,
        id.as_str()
    ))
}

fn immutable_local_source(
    tx: &Connection,
    scope: &RecoveryScopeV1,
    key: &str,
) -> Result<protected::ProtectedSourceReference, AdmissionOperationStoreError> {
    let source = protected::source_reference(tx, key)?;
    let local: bool = tx
        .query_row(
            "SELECT native_namespace IS NULL AND native_request IS NULL
             FROM main.admission_operation_recovery_records WHERE record_key=?1",
            [key],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    let foreign_global_kind: bool = tx
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM main.authority_global_commits
             WHERE projection_key=?1 AND projection_kind!='recovery')",
            [key],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if !local
        || foreign_global_kind
        || key.len() > 512
        || source.record_key() != key
        || source.scope_key() != protected::scope_key(scope)?
        || source.kind() != "command"
        || source.version() != 1
    {
        return Err(refused("proposal reclamation immutable native framing"));
    }
    protected::verify_source_reference(tx, &source)?;
    Ok(source)
}
