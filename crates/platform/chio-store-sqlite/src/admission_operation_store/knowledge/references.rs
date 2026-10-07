//! Active reference custody is indexed independently of immutable owner history.
use super::*;

mod baseline;
mod bucket;
mod collected;
mod owner;
mod prepare;
mod prepared;
mod readback;
mod reader;
mod ready;
mod rebuild;
mod source;
#[cfg(test)]
mod tests;

use bucket::{
    BucketState, ReferenceAggregate, ReferenceBaseline, ReferenceBucket, ReferenceInventory,
    ReferenceLeaf, ReferenceLocation, ReferenceOwnerState, ReferenceSchema,
    MAX_ACTIVE_REFERENCE_BUCKETS, MAX_ACTIVE_REFERENCE_OWNERS, MAX_OWNERS_PER_BUCKET,
};
use prepared::OwningSource;
use reader::{load_owner_leaf, load_reference_state, membership, ReferenceState};

pub(in crate::admission_operation_store) use baseline::{
    prepare_cold_reference_baseline, prepare_new_artifact_reference_baseline,
    verify_committed_cold_baseline, ColdReferenceWriteFootprint, PreparedColdReferenceBaseline,
    PreparedNewArtifactReferenceBaseline,
};
pub(in crate::admission_operation_store) use bucket::ReferenceBaselineSource;
pub(in crate::admission_operation_store) use collected::{
    collected_publication_closure, CollectedPublicationReferenceClosure,
};
pub(in crate::admission_operation_store) use owner::{ProductEvidenceOwner, ReferenceOwner};
pub(in crate::admission_operation_store) use prepare::{
    prepare_reference_retain, prepare_reference_retirement,
};
pub(in crate::admission_operation_store) use prepared::{
    PreparedReferenceUpdates, ReferenceWriteFootprint, StagedReferenceUpdate,
};
pub(in crate::admission_operation_store) use readback::{
    require_active_reference_owner, require_new_artifact_reference_baseline,
};
#[cfg(feature = "admission-test-support")]
pub(in crate::admission_operation_store) use reader::active_product_evidence_owner_count;
pub(in crate::admission_operation_store) use reader::active_reference_owner_count;
pub(in crate::admission_operation_store) use ready::{
    ready_reference_account, ReadyReferenceAccount, ReferenceAccount, ReferenceReadyRecord,
    ReferenceReadySchema,
};
pub(in crate::admission_operation_store) use rebuild::{
    prepare_reference_rebuild, PreparedReferenceRebuild,
};
pub(in crate::admission_operation_store) use source::SourceAnchor;

pub(in crate::admission_operation_store) fn reference_identity(
    reference: &ArtifactVersionRefV1,
) -> Result<CanonicalPayloadDigest, AdmissionOperationStoreError> {
    Ok(CanonicalPayloadDigest::from_bytes(
        knowledge_digest(RecoveryDigestDomain::KnowledgeReferenceIdentity, reference)
            .map_err(refused)?,
    ))
}

pub(in crate::admission_operation_store) fn aggregate_key(
    reference: CanonicalPayloadDigest,
) -> String {
    format!("knowledge-reference:{}", hex::encode(reference.as_bytes()))
}

fn leaf_key(reference: CanonicalPayloadDigest, owner: CanonicalPayloadDigest) -> String {
    format!(
        "knowledge-reference-owner:{}:{}",
        hex::encode(reference.as_bytes()),
        hex::encode(owner.as_bytes()),
    )
}

fn bucket_key(reference: CanonicalPayloadDigest, bucket: u64) -> String {
    format!(
        "knowledge-reference-bucket:{}:{bucket}",
        hex::encode(reference.as_bytes()),
    )
}
