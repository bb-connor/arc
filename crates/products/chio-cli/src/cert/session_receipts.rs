//! Exact conversion of a sealed authenticated reader result, without filtering.

use crate::CliError;
use chio_acp_proxy::{ComplianceCoverage, ComplianceReceiptEntry};
use chio_core::crypto::PublicKey;
use chio_kernel::receipt_query::ReceiptReadContext;
use chio_store_sqlite::RetainedSessionReceipts;
use std::path::Path;

pub(super) fn load_session_receipts(
    path: &Path,
    session_id: &str,
    trusted_key: &PublicKey,
    tenant: Option<&str>,
) -> Result<RetainedSessionReceipts, CliError> {
    let context = tenant.map_or_else(
        ReceiptReadContext::local_operator_admin_all,
        ReceiptReadContext::local_operator_tenant,
    );
    chio_store_sqlite::collect_retained_session_receipts_read_only(
        path,
        session_id,
        &context,
        trusted_key,
    )
    .map_err(|source| {
        CliError::with_public_source(
            &chio_errors::_generated::error_codes::ATTEST_RECEIPT_VERIFICATION_FAILED,
            "authenticated certificate session collection failed",
            source,
        )
    })
}

pub(super) fn certificate_entries(
    snapshot: &RetainedSessionReceipts,
) -> Vec<ComplianceReceiptEntry> {
    snapshot
        .receipts()
        .iter()
        .map(|stored| ComplianceReceiptEntry {
            receipt: stored.receipt.clone(),
            seq: stored.seq,
            entry_seq: Some(stored.entry_seq),
        })
        .collect()
}

pub(super) fn snapshot_reference(snapshot: &RetainedSessionReceipts) -> ComplianceCoverage {
    let coverage = snapshot.coverage();
    ComplianceCoverage::RetainedSnapshotReference {
        session_id: coverage.session_id.clone(),
        tenant_id: coverage.tenant_id.clone(),
        snapshot_end_entry_seq: coverage.snapshot_end_entry_seq,
        archived_through_entry_seq: coverage.archived_through_entry_seq,
        checkpoint: Box::new(coverage.checkpoint.clone()),
    }
}
