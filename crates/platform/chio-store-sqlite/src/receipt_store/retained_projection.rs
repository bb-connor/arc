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
    // Source cursors are unsigned projections. Neither archive DDL nor matching
    // claim/source columns establish their uniqueness or allocation authority.
    let duplicate_cursors: bool = archive.query_row(
        "SELECT EXISTS(SELECT 1 FROM claim_receipt_log_entries WHERE entry_seq <= ?1
         GROUP BY receipt_kind, source_seq HAVING COUNT(*) > 1)",
        [sqlite_i64(watermark, "retained watermark")?],
        |row| row.get(0),
    )?;
    if duplicate_cursors {
        return Err(drift());
    }
    let (tool_ceiling, child_ceiling): (i64, i64) = live.query_row(
        "SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'chio_tool_receipts'), 0),
                COALESCE((SELECT seq FROM sqlite_sequence WHERE name = 'chio_child_receipts'), 0)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let mut live_tools =
        live.prepare("SELECT EXISTS(SELECT 1 FROM chio_tool_receipts WHERE seq = ?1)")?;
    let mut live_children =
        live.prepare("SELECT EXISTS(SELECT 1 FROM chio_child_receipts WHERE seq = ?1)")?;
    // Walk the authenticated prefix, including claims whose source row was
    // deleted. Starting at the source tables would silently miss those rows.
    // Stream one claim at a time; do not retain a second history in memory.
    let mut claims = archive.prepare(
        "SELECT source_seq, receipt_id, receipt_kind, raw_json, entry_seq
         FROM claim_receipt_log_entries WHERE entry_seq <= ?1 ORDER BY entry_seq",
    )?;
    let mut tools =
        archive.prepare(crate::receipt_query_snapshot::project::TOOL_SOURCE_PROJECTION_SQL)?;
    let mut children =
        archive.prepare(crate::receipt_query_snapshot::project::CHILD_SOURCE_PROJECTION_SQL)?;
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
                if source_seq > tool_ceiling
                    || live_tools.query_row([source_seq], |row| row.get::<_, bool>(0))?
                {
                    return Err(drift());
                }
                let receipt = decode_verified_chio_receipt(
                    &raw,
                    "retained claim projection",
                    Some(entry_seq),
                )?;
                if receipt.id != id {
                    return Err(drift());
                }
                // Unsigned archive lineage must not grant a different subject
                // filter. The shared rule falls back to validated lineage from
                // the pinned live store only when the signed receipt has no
                // explicit attribution.
                crate::receipt_query_snapshot::project::SignedToolProjection::derive(
                    &receipt, live,
                )?
                .source_matches(&mut tools, source_seq, &raw)?
            }
            "child_receipt" => {
                if source_seq > child_ceiling
                    || live_children.query_row([source_seq], |row| row.get::<_, bool>(0))?
                {
                    return Err(drift());
                }
                let receipt = decode_verified_child_receipt(
                    &raw,
                    "retained child projection",
                    Some(entry_seq),
                )?;
                if receipt.id != id {
                    return Err(drift());
                }
                crate::receipt_query_snapshot::project::child_source_matches(
                    &mut children,
                    source_seq,
                    &raw,
                    &receipt,
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
