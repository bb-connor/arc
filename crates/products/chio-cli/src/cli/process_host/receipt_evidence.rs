//! Membership of the original call receipt in its owning host's signed log.

use chio_core::{crypto::canonical_json_bytes, receipt::body::ChioReceipt, PublicKey};
use chio_kernel::checkpoint::{validate_checkpoint, KernelCheckpoint, ReceiptInclusionProof};
use serde::{Deserialize, Serialize};

use super::state::error;
use crate::CliError;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Evidence {
    pub checkpoint: KernelCheckpoint,
    pub inclusion: ReceiptInclusionProof,
}

impl Evidence {
    pub fn verify(
        &self,
        receipt: &ChioReceipt,
        key: &PublicKey,
        observed_at: u64,
    ) -> Result<(), CliError> {
        validate_checkpoint(&self.checkpoint).map_err(error)?;
        let body = &self.checkpoint.body;
        let proof = &self.inclusion;
        if body.kernel_key != *key
            || body.issued_at < receipt.timestamp
            || body.issued_at > observed_at / 1000
            || proof.checkpoint_seq != body.checkpoint_seq
            || proof.merkle_root != body.merkle_root
            || proof.receipt_seq < body.batch_start_seq
            || proof.receipt_seq > body.batch_end_seq
            || u64::try_from(proof.leaf_index).ok()
                != proof.receipt_seq.checked_sub(body.batch_start_seq)
            || proof.proof.tree_size != body.tree_size
            || !proof.verify(
                &canonical_json_bytes(receipt).map_err(error)?,
                &body.merkle_root,
            )
        {
            return Err(error("receipt log inclusion differs from original call"));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub(super) fn export(
    host: &super::state::Host,
    receipt: &ChioReceipt,
    observed_at: u64,
) -> Result<Evidence, CliError> {
    use chio_kernel::evidence_export::EvidenceExportQuery;

    let bundle = host
        .receipts
        .build_evidence_export_bundle(&EvidenceExportQuery {
            capability_id: Some(receipt.capability_id.clone()),
            since: Some(receipt.timestamp),
            until: Some(receipt.timestamp),
            ..EvidenceExportQuery::admin_all()
        })
        .map_err(error)?;
    let mut records = bundle
        .tool_receipts
        .iter()
        .filter(|record| record.receipt.id == receipt.id);
    let record = records
        .next()
        .ok_or_else(|| error("original call is missing from its receipt log"))?;
    if records.next().is_some()
        || canonical_json_bytes(&record.receipt).map_err(error)?
            != canonical_json_bytes(receipt).map_err(error)?
    {
        return Err(error("receipt log has a substituted or duplicate call"));
    }
    let inclusion = bundle
        .inclusion_proofs
        .into_iter()
        .find(|proof| proof.receipt_seq == record.seq)
        .ok_or_else(|| error("original call lacks receipt log inclusion"))?;
    let checkpoint = bundle
        .checkpoints
        .into_iter()
        .find(|checkpoint| checkpoint.body.checkpoint_seq == inclusion.checkpoint_seq)
        .ok_or_else(|| error("original call lacks its signed checkpoint"))?;
    let evidence = Evidence {
        checkpoint,
        inclusion,
    };
    evidence.verify(receipt, &host.kernel.public_key(), observed_at)?;
    Ok(evidence)
}
