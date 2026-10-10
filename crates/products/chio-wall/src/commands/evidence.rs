//! Receipt store and signed evidence package production.

use super::*;

pub(super) fn create_chio_wall_receipt_db(
    receipt_db_path: &Path,
    authorization_context: &ChioWallAuthorizationContext,
    guard_outcome: &ChioWallGuardOutcome,
    denied_access_record: &ChioWallDeniedAccessRecord,
    policy_snapshot: &ChioWallPolicySnapshot,
) -> Result<Keypair, CliError> {
    let store = SqliteReceiptStore::open(receipt_db_path)?;
    let issuer = Keypair::generate();
    let subject = Keypair::generate();
    let kernel = Keypair::generate();
    let capability = chio_wall_capability_with_id("cap-chio-wall-1", &subject, &issuer)?;
    let receipt = chio_wall_receipt(
        authorization_context,
        guard_outcome,
        denied_access_record,
        policy_snapshot,
        &capability.body().id,
        &kernel,
    )?;
    let seq = store.append_chio_receipt_returning_seq(&receipt)?;
    let canonical = store.receipts_canonical_bytes_range(seq, seq)?;
    let checkpoint = build_checkpoint(
        1,
        seq,
        seq,
        &canonical
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>(),
        &kernel,
    )?;
    store.store_checkpoint(&checkpoint)?;
    Ok(kernel)
}

pub(super) fn write_chio_evidence_package(
    output: &Path,
    authorization_context: &ChioWallAuthorizationContext,
    guard_outcome: &ChioWallGuardOutcome,
    denied_access_record: &ChioWallDeniedAccessRecord,
    policy_snapshot: &ChioWallPolicySnapshot,
) -> Result<(), CliError> {
    let receipt_staging = tempfile::tempdir()?;
    let receipt_db_path = receipt_staging.path().join("chio-wall-receipts.sqlite3");
    let chio_evidence_dir = output.join("chio-evidence");

    let kernel = create_chio_wall_receipt_db(
        &receipt_db_path,
        authorization_context,
        guard_outcome,
        denied_access_record,
        policy_snapshot,
    )?;

    evidence_export::cmd_evidence_export(
        &chio_evidence_dir,
        None,
        None,
        None,
        None,
        None,
        true,
        None,
        None,
        false,
        Some(&receipt_db_path),
        None,
        None,
        &kernel,
    )?;

    let _ = fs::remove_file(receipt_db_path);
    Ok(())
}
