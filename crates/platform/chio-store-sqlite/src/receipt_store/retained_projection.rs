//! Bind queryable archive projections to the authenticated claim payloads.
use super::*;

pub(super) fn validate(
    live: &Connection,
    archive: &Connection,
    watermark: u64,
) -> Result<(), ReceiptStoreError> {
    let drift = || {
        ReceiptStoreError::Conflict(
            "archived receipt projection diverges from its authenticated claim log".into(),
        )
    };
    // Walk the authenticated prefix, including claims whose source row was
    // deleted. Starting at the source tables would silently miss those rows.
    // Stream one claim at a time; do not retain a second history in memory.
    let mut claims = archive.prepare(
        "SELECT source_seq, receipt_id, receipt_kind, raw_json, entry_seq
         FROM claim_receipt_log_entries WHERE entry_seq <= ?1 ORDER BY entry_seq",
    )?;
    let mut tools = archive.prepare(
        "SELECT COUNT(*) = 1 FROM chio_tool_receipts r
         LEFT JOIN capability_lineage cl ON cl.capability_id = r.capability_id
         WHERE r.seq = ?1 AND r.receipt_id = ?2 AND r.raw_json = ?3
           AND r.timestamp = ?4 AND r.capability_id = ?5
           AND r.tool_server = ?6 AND r.tool_name = ?7 AND r.decision_kind = ?8
           AND r.tenant_id IS ?9 AND r.cost_currency IS ?10
           AND r.cost_charged_be IS ?11 AND r.attempted_cost_be IS ?12
           AND COALESCE(r.subject_key, cl.subject_key) IS ?13
           AND COALESCE(r.issuer_key, cl.issuer_key) IS ?14
           AND r.grant_index IS ?15 AND r.policy_hash = ?16 AND r.content_hash = ?17",
    )?;
    let mut children = archive.prepare(
        "SELECT COUNT(*) = 1 FROM chio_child_receipts
         WHERE seq = ?1 AND receipt_id = ?2 AND raw_json = ?3 AND timestamp = ?4
           AND session_id = ?5 AND parent_request_id = ?6 AND request_id = ?7
           AND operation_kind = ?8 AND terminal_state = ?9
           AND policy_hash = ?10 AND outcome_hash = ?11",
    )?;
    let rows = claims.query_map([sqlite_i64(watermark, "retained watermark")?], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
        ))
    })?;
    for row in rows {
        let (source_seq, id, kind, raw, entry_seq) = row?;
        if source_seq <= 0 {
            return Err(drift());
        }
        let entry_seq = sqlite_positive_u64(entry_seq, "retained claim sequence")?;
        let matches = match kind.as_str() {
            "tool_receipt" => {
                let receipt = decode_verified_chio_receipt(
                    &raw,
                    "retained claim projection",
                    Some(entry_seq),
                )?;
                if receipt.id != id {
                    return Err(drift());
                }
                let cost = receipt_cost_projection(&receipt)?;
                let attribution = extract_receipt_attribution(&receipt);
                // Unsigned archive lineage must not grant a different subject
                // filter. Use the validated lineage from the pinned live store
                // only when the signed receipt has no explicit attribution.
                let lineage =
                    if attribution.subject_key.is_none() || attribution.issuer_key.is_none() {
                        SqliteReceiptStore::get_lineage_on_connection(live, &receipt.capability_id)
                            .map_err(super::super::support::capability_lineage_store_error)?
                    } else {
                        None
                    };
                let subject = attribution
                    .subject_key
                    .as_deref()
                    .or_else(|| lineage.as_ref().map(|value| value.subject_key.as_str()));
                let issuer = attribution
                    .issuer_key
                    .as_deref()
                    .or_else(|| lineage.as_ref().map(|value| value.issuer_key.as_str()));
                tools.query_row(
                    params![
                        source_seq,
                        id,
                        raw,
                        sqlite_i64(receipt.timestamp, "retained receipt timestamp")?,
                        receipt.capability_id,
                        receipt.tool_server,
                        receipt.tool_name,
                        receipt_decision_kind(&receipt),
                        receipt.tenant_id,
                        cost.currency,
                        cost.charged,
                        cost.attempted,
                        subject,
                        issuer,
                        attribution.grant_index.map(i64::from),
                        receipt.policy_hash,
                        receipt.content_hash
                    ],
                    |row| row.get::<_, bool>(0),
                )?
            }
            "child_receipt" => {
                let receipt = decode_verified_child_receipt(
                    &raw,
                    "retained child projection",
                    Some(entry_seq),
                )?;
                if receipt.id != id {
                    return Err(drift());
                }
                children.query_row(
                    params![
                        source_seq,
                        id,
                        raw,
                        sqlite_i64(receipt.timestamp, "retained child timestamp")?,
                        receipt.session_id.as_str(),
                        receipt.parent_request_id.as_str(),
                        receipt.request_id.as_str(),
                        receipt.operation_kind.as_str(),
                        terminal_state_kind(&receipt.terminal_state),
                        receipt.policy_hash,
                        receipt.outcome_hash
                    ],
                    |row| row.get::<_, bool>(0),
                )?
            }
            _ => return Err(drift()),
        };
        if !matches {
            return Err(drift());
        }
    }
    Ok(())
}
