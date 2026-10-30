//! The certificate describes a supplied set or a signed retained snapshot reference.

use super::{ComplianceBundleError, ComplianceReceiptEntry};
use chio_core::crypto::PublicKey;
use serde::{Deserialize, Serialize};

/// A signed scope statement. Snapshot metadata alone does not authenticate a corpus or session closure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ComplianceCoverage {
    SuppliedReceiptSet,
    /// Descriptive signed reference. Corpus authentication belongs to the reader, not this DTO.
    RetainedSnapshotReference {
        session_id: String,
        tenant_id: Option<String>,
        snapshot_end_entry_seq: u64,
        archived_through_entry_seq: u64,
        checkpoint: Box<chio_core::receipt::checkpoint::KernelCheckpoint>,
    },
}

impl ComplianceCoverage {
    pub(crate) fn validate(
        &self,
        session_id: &str,
        entries: &[ComplianceReceiptEntry],
        kernel_key: &PublicKey,
        issued_at: u64,
    ) -> Result<(), ComplianceBundleError> {
        let Self::RetainedSnapshotReference {
            session_id: covered_session,
            tenant_id,
            snapshot_end_entry_seq,
            archived_through_entry_seq,
            checkpoint,
        } = self
        else {
            return Ok(());
        };
        let checkpoint = chio_kernel_core::evidence_verify::validate_checkpoint(
            checkpoint,
            std::slice::from_ref(kernel_key),
        )
            .map_err(|_| ComplianceBundleError::CoverageMismatch)?;
        if covered_session != session_id
            || *snapshot_end_entry_seq == 0
            || archived_through_entry_seq > snapshot_end_entry_seq
            || checkpoint.body.batch_end_seq != *snapshot_end_entry_seq
            || checkpoint.body.issued_at > issued_at
            || entries.iter().any(|entry| {
                entry
                    .entry_seq
                    .is_none_or(|seq| seq == 0 || seq > *snapshot_end_entry_seq)
                    || tenant_id
                        .as_ref()
                        .is_some_and(|tenant| entry.receipt.tenant_id.as_ref() != Some(tenant))
            })
        {
            return Err(ComplianceBundleError::CoverageMismatch);
        }
        Ok(())
    }
}
