use super::*;

pub(crate) fn validate_claim_receipt_log_entries(
    connection: &Connection,
) -> Result<(), ReceiptStoreError> {
    // Every read below must observe the same database snapshot. Without a
    // shared transaction, each SELECT takes its own WAL snapshot, so a
    // writer that commits between the source-table scans and the
    // projection reads can make the projection appear to drift when it has
    // not (a spurious "set drift detected" conflict). A deferred
    // transaction pins the snapshot on its first read and keeps the
    // validator a reader.
    let tx = connection.unchecked_transaction()?;
    validate_claim_receipt_log_entries_in_transaction(&tx)?;
    tx.commit()?;
    Ok(())
}

pub(crate) fn validate_claim_receipt_log_entries_in_transaction(
    tx: &Connection,
) -> Result<(), ReceiptStoreError> {
    let mut expected = load_tool_claim_receipt_projection_rows(tx)?;
    expected.extend(load_child_claim_receipt_projection_rows(tx)?);
    expected.sort_by(|left, right| {
        (
            left.timestamp,
            left.kind_rank(),
            left.source_seq,
            left.receipt_id.as_str(),
        )
            .cmp(&(
                right.timestamp,
                right.kind_rank(),
                right.source_seq,
                right.receipt_id.as_str(),
            ))
    });

    let expected_receipt_ids = expected
        .iter()
        .map(|row| row.receipt_id.clone())
        .collect::<BTreeSet<_>>();

    for row in &expected {
        let Some(existing) = load_claim_receipt_log_projection_row(tx, &row.receipt_id)? else {
            return Err(ReceiptStoreError::Conflict(format!(
                "claim receipt log entry `{}` is missing for persisted {} source row",
                row.receipt_id, row.receipt_kind
            )));
        };
        if !existing.matches_projection_or_enrichment(row) {
            return Err(ReceiptStoreError::Conflict(format!(
                "claim receipt log entry `{}` diverges from persisted {} source row",
                row.receipt_id, row.receipt_kind
            )));
        }
    }

    let existing_receipt_ids = load_claim_receipt_log_receipt_ids(tx)?;
    if existing_receipt_ids != expected_receipt_ids {
        let missing = expected_receipt_ids
            .difference(&existing_receipt_ids)
            .next()
            .cloned();
        let extra = existing_receipt_ids
            .difference(&expected_receipt_ids)
            .next()
            .cloned();
        return Err(ReceiptStoreError::Conflict(format!(
            "claim receipt log entry set drift detected (missing: {}, extra: {})",
            missing.as_deref().unwrap_or("<none>"),
            extra.as_deref().unwrap_or("<none>")
        )));
    }

    Ok(())
}
