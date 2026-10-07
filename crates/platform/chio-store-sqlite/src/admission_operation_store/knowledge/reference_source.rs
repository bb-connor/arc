//! Native source owners mint affine reference custody inside a fenced writer.
use super::*;

pub(in crate::admission_operation_store) use super::reference_activation::VerifiedKnowledgeReferenceRebuildAuthority;
pub(in crate::admission_operation_store) use super::reference_baseline::VerifiedNewArtifactReferenceBaseline;
pub(in crate::admission_operation_store) use super::reference_census::VerifiedKnowledgeReferenceColdCohort;
pub(in crate::admission_operation_store) use super::reference_custody::VerifiedKnowledgeReferenceRetain;
pub(in crate::admission_operation_store) use super::reference_retirement::VerifiedKnowledgeReferenceRetirement;

/// A retained global chain position is evidence, never a mutation grant.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::admission_operation_store) struct ReferenceCutoff {
    sequence: u64,
    chain_digest: [u8; 32],
}

impl ReferenceCutoff {
    pub(super) fn capture(
        tx: &Transaction<'_>,
        owner: &SqliteServingOwner,
    ) -> Result<Self, AdmissionOperationStoreError> {
        schema::verify_active_owner(tx, owner, Some(&owner.fence))?;
        let (sequence, digest): (i64, String) = tx
            .query_row(
                "SELECT head_sequence,head_chain_digest FROM authority_global_commit_meta WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(sqlite_error)?;
        let bytes = hex::decode(digest).map_err(refused)?;
        let result = Self {
            sequence: u64::try_from(sequence).map_err(refused)?,
            chain_digest: bytes
                .try_into()
                .map_err(|_| refused("reference cutoff digest"))?,
        };
        result.verify(tx)?;
        Ok(result)
    }

    pub(in crate::admission_operation_store) fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(in crate::admission_operation_store) fn chain_digest(&self) -> &[u8; 32] {
        &self.chain_digest
    }

    pub(in crate::admission_operation_store) fn verify(
        &self,
        tx: &Connection,
    ) -> Result<(), AdmissionOperationStoreError> {
        if self.sequence == 0 {
            return Err(refused("reference cutoff precedes native baseline"));
        }
        let sequence = i64::try_from(self.sequence).map_err(refused)?;
        let retained: Option<String> = tx
            .query_row(
                "SELECT chain_digest FROM authority_global_commits WHERE commit_sequence=?1",
                [sequence],
                |row| row.get(0),
            )
            .optional()
            .map_err(sqlite_error)?;
        if retained.as_deref() != Some(hex::encode(self.chain_digest).as_str()) {
            return Err(refused("reference cutoff lost immutable custody"));
        }
        let head: i64 = tx
            .query_row(
                "SELECT head_sequence FROM authority_global_commit_meta WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(sqlite_error)?;
        if head < sequence {
            return Err(refused("reference cutoff was reset"));
        }
        Ok(())
    }
}

impl std::fmt::Debug for ReferenceCutoff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReferenceCutoff([redacted])")
    }
}
