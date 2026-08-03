/// Recover a store whose claim-log projection rows survived a source-row
/// delete: the source rows were deleted but the projection rows remained,
/// producing set drift that fails the projection guard on open. Fail-closed:
/// only the `extra` claim-log rows -- present in the projection but absent from
/// BOTH source tables -- are candidates, and each
/// candidate must already be covered by a previously committed retention
/// watermark, archive identity, archive path, and canonical prefix digest. The
/// archive must retain its signed claim, matching source receipt, and auxiliary
/// evidence. Repair never creates or advances archival authority. Entry point for
/// `SqliteReceiptStore::retention_repair`, run on the single writer
/// connection.
#[derive(Debug, Eq, PartialEq)]
struct RepairClaimLogRow {
    entry_seq: i64,
    receipt_id: String,
    receipt_kind: String,
    source_seq: i64,
    timestamp: i64,
    capability_id: Option<String>,
    session_id: Option<String>,
    parent_request_id: Option<String>,
    request_id: Option<String>,
    subject_key: Option<String>,
    issuer_key: Option<String>,
    tool_server: Option<String>,
    tool_name: Option<String>,
    raw_json: String,
}

fn repair_claim_log_row_at(
    connection: &rusqlite::Connection,
    entry_seq: i64,
) -> Result<Option<RepairClaimLogRow>, ReceiptStoreError> {
    connection
        .query_row(
            "SELECT entry_seq, receipt_id, receipt_kind, source_seq, timestamp, capability_id, \
                    session_id, parent_request_id, request_id, subject_key, issuer_key, \
                    tool_server, tool_name, raw_json \
             FROM claim_receipt_log_entries WHERE entry_seq = ?1",
            params![entry_seq],
            |row| {
                Ok(RepairClaimLogRow {
                    entry_seq: row.get(0)?,
                    receipt_id: row.get(1)?,
                    receipt_kind: row.get(2)?,
                    source_seq: row.get(3)?,
                    timestamp: row.get(4)?,
                    capability_id: row.get(5)?,
                    session_id: row.get(6)?,
                    parent_request_id: row.get(7)?,
                    request_id: row.get(8)?,
                    subject_key: row.get(9)?,
                    issuer_key: row.get(10)?,
                    tool_server: row.get(11)?,
                    tool_name: row.get(12)?,
                    raw_json: row.get(13)?,
                })
            },
        )
        .optional()
        .map_err(ReceiptStoreError::from)
}

fn validate_repair_archive_claim_identity(
    row: &RepairClaimLogRow,
) -> Result<(), ReceiptStoreError> {
    let entry_seq = sqlite_positive_u64(row.entry_seq, "repair archive entry_seq")?;
    let timestamp = sqlite_u64(row.timestamp, "repair archive receipt timestamp")?;
    let (signed_id, signed_timestamp) = match row.receipt_kind.as_str() {
        "tool_receipt" => {
            let receipt = decode_verified_chio_receipt(
                &row.raw_json,
                "retention repair archive tool receipt",
                Some(entry_seq),
            )?;
            (receipt.id, receipt.timestamp)
        }
        "child_receipt" => {
            let receipt = decode_verified_child_receipt(
                &row.raw_json,
                "retention repair archive child receipt",
                Some(entry_seq),
            )?;
            (receipt.id, receipt.timestamp)
        }
        other => {
            return Err(ReceiptStoreError::Conflict(format!(
                "unsupported claim receipt kind {other:?} in retention repair archive"
            )));
        }
    };
    if signed_id != row.receipt_id || signed_timestamp != timestamp {
        return Err(ReceiptStoreError::Conflict(format!(
            "retention repair archive projection at entry {entry_seq} does not match its signed \
             receipt identity"
        )));
    }
    Ok(())
}

fn repair_archive_source_incomplete(
    table: &'static str,
    archived: bool,
) -> ReceiptStoreError {
    ReceiptStoreError::RetentionArchiveIncomplete {
        table,
        live: 1,
        archived: if archived { 1 } else { 0 },
    }
}

fn validate_repair_archive_source_projection(
    archive: &rusqlite::Connection,
    rounded_watermark: u64,
) -> Result<(), ReceiptStoreError> {
    let rounded = sqlite_i64(rounded_watermark, "repair source validation watermark")?;
    let mut statement = archive.prepare(
        "SELECT entry_seq, receipt_id, receipt_kind, source_seq, timestamp, capability_id, \
                session_id, parent_request_id, request_id, subject_key, issuer_key, \
                tool_server, tool_name, raw_json \
         FROM claim_receipt_log_entries WHERE entry_seq <= ?1 ORDER BY entry_seq",
    )?;
    let rows = statement.query_map(params![rounded], |row| {
        Ok(RepairClaimLogRow {
            entry_seq: row.get(0)?,
            receipt_id: row.get(1)?,
            receipt_kind: row.get(2)?,
            source_seq: row.get(3)?,
            timestamp: row.get(4)?,
            capability_id: row.get(5)?,
            session_id: row.get(6)?,
            parent_request_id: row.get(7)?,
            request_id: row.get(8)?,
            subject_key: row.get(9)?,
            issuer_key: row.get(10)?,
            tool_server: row.get(11)?,
            tool_name: row.get(12)?,
            raw_json: row.get(13)?,
        })
    })?;

    for row in rows {
        let row = row?;
        validate_repair_archive_claim_identity(&row)?;
        let claim_projection =
            super::support::load_claim_receipt_log_projection_row(archive, &row.receipt_id)?
                .ok_or_else(|| {
                    repair_archive_source_incomplete("claim_receipt_log_entries", false)
                })?;
        let (table, source_projection) = match row.receipt_kind.as_str() {
            "tool_receipt" => (
                "chio_tool_receipts",
                super::support::load_tool_claim_receipt_projection_row_by_id(
                    archive,
                    &row.receipt_id,
                )?,
            ),
            "child_receipt" => (
                "chio_child_receipts",
                super::support::load_child_claim_receipt_projection_row_by_id(
                    archive,
                    &row.receipt_id,
                )?,
            ),
            other => {
                return Err(ReceiptStoreError::Conflict(format!(
                    "unsupported claim receipt kind {other:?} in retention repair archive"
                )));
            }
        };
        let Some(source_projection) = source_projection else {
            return Err(repair_archive_source_incomplete(table, false));
        };
        let source_matches_key = source_projection.receipt_kind == row.receipt_kind
            && source_projection.receipt_id == row.receipt_id
            && source_projection.source_seq
                == sqlite_positive_u64(row.source_seq, "repair archive source_seq")?;
        if !source_matches_key
            || !claim_projection.matches_projection_or_enrichment(&source_projection)
        {
            return Err(repair_archive_source_incomplete(table, true));
        }
    }
    Ok(())
}

fn load_repair_evidence_rows(
    connection: &rusqlite::Connection,
    sql: &str,
) -> Result<Vec<Vec<rusqlite::types::Value>>, ReceiptStoreError> {
    let mut statement = connection.prepare(sql)?;
    let column_count = statement.column_count();
    let rows = statement.query_map([], |row| {
        let mut values = Vec::with_capacity(column_count);
        for column in 0..column_count {
            values.push(row.get::<_, rusqlite::types::Value>(column)?);
        }
        Ok(values)
    })?;
    let mut values = Vec::new();
    for row in rows {
        values.push(row?);
    }
    Ok(values)
}

fn validate_repair_archive_auxiliary_table(
    live: &rusqlite::Connection,
    archive: &rusqlite::Connection,
    table: &'static str,
    key_column: &'static str,
    key_position: usize,
    live_sql: &str,
) -> Result<(), ReceiptStoreError> {
    let live_rows = load_repair_evidence_rows(live, live_sql)?;
    let archive_sql = format!("SELECT * FROM main.{table} WHERE {key_column} = ?1");
    for live_row in live_rows {
        let key = live_row.get(key_position).cloned().ok_or_else(|| {
            ReceiptStoreError::Conflict(format!(
                "retention repair evidence table {table} lost its identity column"
            ))
        })?;
        let archived_row = archive
            .query_row(&archive_sql, params![key], |row| {
                let mut values = Vec::with_capacity(live_row.len());
                for column in 0..live_row.len() {
                    values.push(row.get::<_, rusqlite::types::Value>(column)?);
                }
                Ok(values)
            })
            .optional()?;
        if archived_row.as_ref() != Some(&live_row) {
            return Err(ReceiptStoreError::RetentionArchiveIncomplete {
                table,
                live: 1,
                archived: if archived_row.is_some() { 1 } else { 0 },
            });
        }
    }
    Ok(())
}

fn validate_repair_archive_auxiliary_evidence(
    live: &rusqlite::Connection,
    archive: &rusqlite::Connection,
    rounded_watermark: u64,
) -> Result<(), ReceiptStoreError> {
    let w = sqlite_i64(rounded_watermark, "repair auxiliary validation watermark")?;
    let checks: [(&str, &str, usize, String); 9] = [
        (
            "kernel_checkpoints",
            "id",
            0,
            format!(
                "SELECT * FROM main.kernel_checkpoints WHERE batch_end_seq <= {w} \
                 ORDER BY checkpoint_seq"
            ),
        ),
        (
            "checkpoint_tree_heads",
            "checkpoint_seq",
            0,
            format!(
                "SELECT p.* FROM main.checkpoint_tree_heads p \
                 INNER JOIN main.kernel_checkpoints k ON k.checkpoint_seq = p.checkpoint_seq \
                 WHERE k.batch_end_seq <= {w} ORDER BY p.checkpoint_seq"
            ),
        ),
        (
            "checkpoint_predecessor_witnesses",
            "witness_checkpoint_seq",
            1,
            format!(
                "SELECT p.* FROM main.checkpoint_predecessor_witnesses p \
                 INNER JOIN main.kernel_checkpoints k \
                    ON k.checkpoint_seq = p.witness_checkpoint_seq \
                 WHERE k.batch_end_seq <= {w} ORDER BY p.witness_checkpoint_seq"
            ),
        ),
        (
            "checkpoint_publication_metadata",
            "checkpoint_seq",
            0,
            format!(
                "SELECT p.* FROM main.checkpoint_publication_metadata p \
                 INNER JOIN main.kernel_checkpoints k ON k.checkpoint_seq = p.checkpoint_seq \
                 WHERE k.batch_end_seq <= {w} ORDER BY p.checkpoint_seq"
            ),
        ),
        (
            "checkpoint_publication_trust_anchor_bindings",
            "checkpoint_seq",
            0,
            format!(
                "SELECT p.* FROM main.checkpoint_publication_trust_anchor_bindings p \
                 INNER JOIN main.kernel_checkpoints k ON k.checkpoint_seq = p.checkpoint_seq \
                 WHERE k.batch_end_seq <= {w} ORDER BY p.checkpoint_seq"
            ),
        ),
        (
            "capability_lineage",
            "capability_id",
            0,
            format!(
                "SELECT * FROM main.capability_lineage WHERE capability_id IN \
                 (SELECT capability_id FROM main.claim_receipt_log_entries \
                  WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt') \
                 ORDER BY capability_id"
            ),
        ),
        (
            "settlement_reconciliations",
            "receipt_id",
            0,
            format!(
                "SELECT * FROM main.settlement_reconciliations WHERE receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries \
                  WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt') \
                 ORDER BY receipt_id"
            ),
        ),
        (
            "metered_billing_reconciliations",
            "receipt_id",
            0,
            format!(
                "SELECT * FROM main.metered_billing_reconciliations WHERE receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries \
                  WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt') \
                 ORDER BY receipt_id"
            ),
        ),
        (
            "chio_authorization_receipt_consumptions",
            "authorization_receipt_id",
            0,
            format!(
                "SELECT * FROM main.chio_authorization_receipt_consumptions \
                 WHERE authorization_receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries \
                  WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt') \
                 ORDER BY authorization_receipt_id"
            ),
        ),
    ];
    for (table, key_column, key_position, sql) in checks {
        validate_repair_archive_auxiliary_table(
            live,
            archive,
            table,
            key_column,
            key_position,
            &sql,
        )?;
    }
    validate_repair_archive_auxiliary_table(
        live,
        archive,
        "receipt_lineage_statements",
        "receipt_id",
        0,
        &format!(
            "SELECT * FROM main.receipt_lineage_statements WHERE receipt_id IN \
             (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w}) \
             ORDER BY receipt_id"
        ),
    )?;
    let live_iou_envelope_exists = live.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_master \
         WHERE type = 'table' AND name = 'iou_envelope')",
        [],
        |row| row.get::<_, i64>(0),
    )? != 0;
    if live_iou_envelope_exists {
        validate_repair_archive_auxiliary_table(
            live,
            archive,
            "iou_envelope",
            "receipt_id",
            0,
            &format!(
                "SELECT * FROM main.iou_envelope WHERE receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries \
                  WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt') \
                 ORDER BY receipt_id"
            ),
        )?;
    }
    Ok(())
}

fn validate_repair_live_mutation_contract(
    connection: &rusqlite::Connection,
) -> Result<(), ReceiptStoreError> {
    ensure_retention_iou_ownership_schema(connection)?;
    super::support::validate_receipt_retention_watermark_schema(connection)?;
    super::support::validate_receipt_retention_tombstones_schema(connection)?;
    validate_transparency_projection_guards(connection)?;
    super::bootstrap::open::validate_settlement_observer_outbox_schema(connection, false)?;
    validate_retention_claim_projection_triggers(connection)?;
    validate_retention_mutation_trigger_allowlist(connection)?;
    validate_retention_foreign_key_delete_closure(connection)
}

fn validate_repair_locked_archive_authority(
    connection: &rusqlite::Connection,
    expected_watermark: u64,
    expected_archive_path: &str,
    expected_archive_identity: &str,
    expected_archive_content_sha256: &str,
) -> Result<(), ReceiptStoreError> {
    let expected_watermark_i64 =
        sqlite_i64(expected_watermark, "repair committed archival watermark")?;
    let checkpoint_boundary = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM kernel_checkpoints WHERE batch_end_seq = ?1)",
        params![expected_watermark_i64],
        |row| row.get::<_, i64>(0),
    )? != 0;
    if !checkpoint_boundary {
        return Err(ReceiptStoreError::Conflict(format!(
            "retention repair committed watermark {expected_watermark} is not a checkpoint \
             boundary"
        )));
    }
    if super::support::retention_watermark(connection)? != Some(expected_watermark) {
        return Err(ReceiptStoreError::Conflict(
            "retention repair watermark changed after archive preflight; retry against the \
             current prefix"
                .to_string(),
        ));
    }
    if super::support::latest_watermark_archive_path(connection)?.as_deref()
        != Some(expected_archive_path)
    {
        return Err(ReceiptStoreError::Conflict(
            "retention repair archive path ledger changed after preflight; retry against the \
             current watermark"
                .to_string(),
        ));
    }
    if super::support::latest_watermark_archive_sha256(connection)?.as_deref()
        != Some(expected_archive_identity)
    {
        return Err(ReceiptStoreError::Conflict(
            "retention repair archive identity ledger changed after preflight; retry against the \
             current watermark"
                .to_string(),
        ));
    }
    if super::support::latest_watermark_archive_content_sha256(connection)?.as_deref()
        != Some(expected_archive_content_sha256)
    {
        return Err(ReceiptStoreError::Conflict(
            "retention repair archive content ledger changed after preflight; retry against the \
             current watermark"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_repair_live_projection_drift(
    connection: &rusqlite::Connection,
    allowed_extras: &[(i64, String)],
) -> Result<(), ReceiptStoreError> {
    let mut allowed_extra_ids = std::collections::BTreeSet::new();
    for (entry_seq, receipt_id) in allowed_extras {
        if !allowed_extra_ids.insert(receipt_id.clone()) {
            return Err(ReceiptStoreError::Conflict(format!(
                "retention repair selected duplicate orphan receipt id {receipt_id:?}"
            )));
        }
        let actual_entry_seq = connection
            .query_row(
                "SELECT entry_seq FROM claim_receipt_log_entries WHERE receipt_id = ?1",
                params![receipt_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if actual_entry_seq != Some(*entry_seq) {
            return Err(ReceiptStoreError::Conflict(format!(
                "retention repair selected orphan {receipt_id:?} moved from entry {entry_seq:?}"
            )));
        }
    }

    let mut expected = super::support::load_tool_claim_receipt_projection_rows(connection)?;
    expected.extend(super::support::load_child_claim_receipt_projection_rows(
        connection,
    )?);
    let mut expected_receipt_ids = std::collections::BTreeSet::new();
    for row in &expected {
        if allowed_extra_ids.contains(&row.receipt_id) {
            return Err(ReceiptStoreError::Conflict(format!(
                "retention repair candidate {:?} regained a live source",
                row.receipt_id
            )));
        }
        expected_receipt_ids.insert(row.receipt_id.clone());
        let existing = super::support::load_claim_receipt_log_projection_row(
            connection,
            &row.receipt_id,
        )?
        .ok_or_else(|| {
            ReceiptStoreError::Conflict(format!(
                "claim receipt log entry {:?} is missing for live {} source row during \
                 retention repair",
                row.receipt_id, row.receipt_kind
            ))
        })?;
        if !existing.matches_projection_or_enrichment(row) {
            return Err(ReceiptStoreError::Conflict(format!(
                "claim receipt log entry {:?} diverges from its live {} source row during \
                 retention repair",
                row.receipt_id, row.receipt_kind
            )));
        }
    }

    let mut permitted_receipt_ids = expected_receipt_ids;
    permitted_receipt_ids.extend(allowed_extra_ids);
    let existing_receipt_ids =
        super::support::load_claim_receipt_log_receipt_ids(connection)?;
    if existing_receipt_ids != permitted_receipt_ids {
        let missing = permitted_receipt_ids
            .difference(&existing_receipt_ids)
            .next()
            .map(String::as_str)
            .unwrap_or("<none>");
        let extra = existing_receipt_ids
            .difference(&permitted_receipt_ids)
            .next()
            .map(String::as_str)
            .unwrap_or("<none>");
        return Err(ReceiptStoreError::Conflict(format!(
            "retention repair found unrelated claim receipt projection drift \
             (missing: {missing}, extra: {extra})"
        )));
    }
    Ok(())
}

fn validate_repair_archive_live_overlap(
    live: &rusqlite::Connection,
    archive: &rusqlite::Connection,
    committed_watermark: u64,
    extras: &[(i64, String)],
) -> Result<(), ReceiptStoreError> {
    let mut selected = std::collections::BTreeMap::new();
    for (entry_seq, receipt_id) in extras {
        if selected.insert(receipt_id.clone(), *entry_seq).is_some() {
            return Err(ReceiptStoreError::Conflict(format!(
                "retention repair selected duplicate orphan receipt id {receipt_id:?}"
            )));
        }
    }
    let mut matched = std::collections::BTreeSet::new();
    let committed = sqlite_i64(committed_watermark, "repair overlap watermark")?;
    {
        let mut live_statement = live.prepare(
            "SELECT entry_seq, receipt_id FROM claim_receipt_log_entries \
             WHERE entry_seq <= ?1 ORDER BY entry_seq",
        )?;
        let live_rows = live_statement.query_map(params![committed], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        for live_row in live_rows {
            let (entry_seq, receipt_id) = live_row?;
            if selected.get(&receipt_id) != Some(&entry_seq) {
                return Err(ReceiptStoreError::Conflict(format!(
                    "committed archive prefix overlaps a distinct live claim occurrence \
                     {receipt_id:?} at entry {entry_seq}"
                )));
            }
        }
    }
    let mut statement = archive.prepare(
        "SELECT entry_seq, receipt_id, receipt_kind, source_seq, timestamp, capability_id, \
                session_id, parent_request_id, request_id, subject_key, issuer_key, \
                tool_server, tool_name, raw_json \
         FROM claim_receipt_log_entries WHERE entry_seq <= ?1 ORDER BY entry_seq",
    )?;
    let rows = statement.query_map(params![committed], |row| {
        Ok(RepairClaimLogRow {
            entry_seq: row.get(0)?,
            receipt_id: row.get(1)?,
            receipt_kind: row.get(2)?,
            source_seq: row.get(3)?,
            timestamp: row.get(4)?,
            capability_id: row.get(5)?,
            session_id: row.get(6)?,
            parent_request_id: row.get(7)?,
            request_id: row.get(8)?,
            subject_key: row.get(9)?,
            issuer_key: row.get(10)?,
            tool_server: row.get(11)?,
            tool_name: row.get(12)?,
            raw_json: row.get(13)?,
        })
    })?;
    for row in rows {
        let archived = row?;
        let live_source_exists = live.query_row(
            "SELECT EXISTS(SELECT 1 FROM chio_tool_receipts WHERE receipt_id = ?1) \
                 OR EXISTS(SELECT 1 FROM chio_child_receipts WHERE receipt_id = ?1)",
            params![archived.receipt_id],
            |row| row.get::<_, i64>(0),
        )? != 0;
        if live_source_exists {
            return Err(ReceiptStoreError::Conflict(format!(
                "archived receipt {:?} overlaps a live source receipt during retention repair",
                archived.receipt_id
            )));
        }

        let live_entry_seq = live
            .query_row(
                "SELECT entry_seq FROM claim_receipt_log_entries WHERE receipt_id = ?1",
                params![archived.receipt_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?;
        if let Some(live_entry_seq) = live_entry_seq {
            if selected.get(&archived.receipt_id) != Some(&live_entry_seq)
                || live_entry_seq != archived.entry_seq
            {
                return Err(ReceiptStoreError::Conflict(format!(
                    "archived receipt {:?} has a distinct live claim occurrence during \
                     retention repair",
                    archived.receipt_id
                )));
            }
            let live_row = repair_claim_log_row_at(live, live_entry_seq)?;
            if live_row.as_ref() != Some(&archived) {
                return Err(ReceiptStoreError::RetentionArchiveIncomplete {
                    table: "claim_receipt_log_entries",
                    live: 1,
                    archived: 1,
                });
            }
            matched.insert(archived.receipt_id.clone());
        }
    }
    if matched.len() != selected.len() {
        let missing = selected
            .keys()
            .find(|receipt_id| !matched.contains(*receipt_id))
            .map(String::as_str)
            .unwrap_or("<unknown>");
        return Err(ReceiptStoreError::Conflict(format!(
            "retention repair candidate {missing:?} is absent from the committed archive prefix"
        )));
    }
    Ok(())
}

fn reject_repair_prunable_evidence_rows(
    connection: &rusqlite::Connection,
    archived_receipt_ids: &std::collections::BTreeSet<String>,
    table: &'static str,
    receipt_ids_sql: &str,
) -> Result<(), ReceiptStoreError> {
    let mut statement = connection.prepare(receipt_ids_sql)?;
    let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
    for row in rows {
        let receipt_id = row?;
        if archived_receipt_ids.contains(&receipt_id) {
            return Err(ReceiptStoreError::Conflict(format!(
                "retention repair refuses orphan cleanup while live {table} evidence remains \
                 for archived receipt {receipt_id:?}"
            )));
        }
    }
    Ok(())
}

fn ensure_repair_archive_ids_have_no_prunable_evidence(
    connection: &rusqlite::Connection,
    archive: &rusqlite::Connection,
    committed_watermark: u64,
) -> Result<(), ReceiptStoreError> {
    let committed = sqlite_i64(
        committed_watermark,
        "repair prunable evidence archive watermark",
    )?;
    let mut archived_statement = archive.prepare(
        "SELECT receipt_id FROM claim_receipt_log_entries \
         WHERE entry_seq <= ?1 ORDER BY entry_seq",
    )?;
    let archived_rows =
        archived_statement.query_map(params![committed], |row| row.get::<_, String>(0))?;
    let mut archived_receipt_ids = std::collections::BTreeSet::new();
    for row in archived_rows {
        archived_receipt_ids.insert(row?);
    }

    let checks = [
        (
            "settlement_reconciliations",
            "SELECT receipt_id FROM settlement_reconciliations ORDER BY receipt_id",
        ),
        (
            "metered_billing_reconciliations",
            "SELECT receipt_id FROM metered_billing_reconciliations ORDER BY receipt_id",
        ),
        (
            "chio_authorization_receipt_consumptions",
            "SELECT authorization_receipt_id FROM chio_authorization_receipt_consumptions \
             UNION SELECT consumer_receipt_id FROM chio_authorization_receipt_consumptions \
             ORDER BY 1",
        ),
        (
            "chio_settlement_observer_outbox",
            "SELECT receipt_id FROM chio_settlement_observer_outbox ORDER BY receipt_id",
        ),
    ];
    for (table, sql) in checks {
        reject_repair_prunable_evidence_rows(
            connection,
            &archived_receipt_ids,
            table,
            sql,
        )?;
    }

    let iou_exists = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_master \
         WHERE type = 'table' AND name = 'iou_envelope')",
        [],
        |row| row.get::<_, i64>(0),
    )? != 0;
    if iou_exists {
        reject_repair_prunable_evidence_rows(
            connection,
            &archived_receipt_ids,
            "iou_envelope",
            "SELECT receipt_id FROM iou_envelope ORDER BY receipt_id",
        )?;
    }

    let settle_attempts_exists = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_master \
         WHERE type = 'table' AND name = 'settle_attempts')",
        [],
        |row| row.get::<_, i64>(0),
    )? != 0;
    if settle_attempts_exists {
        reject_repair_prunable_evidence_rows(
            connection,
            &archived_receipt_ids,
            "settle_attempts",
            "SELECT receipt_id FROM settle_attempts ORDER BY receipt_id",
        )?;
    }
    Ok(())
}

fn verify_repair_checkpoint_chain_and_projections(
    live: &rusqlite::Connection,
    archive: &rusqlite::Connection,
    committed_watermark: u64,
) -> Result<(), ReceiptStoreError> {
    if !super::support::archive_connection_backs_prefix(live, archive, committed_watermark)? {
        return Err(ReceiptStoreError::RetentionArchiveIncomplete {
            table: "claim_receipt_log_entries",
            live: committed_watermark,
            archived: 0,
        });
    }

    let rows = super::support::load_all_persisted_checkpoint_rows(live)?;
    let mut latest = None;
    let mut expected_head_ids = std::collections::BTreeSet::new();
    let mut expected_witness_ids = std::collections::BTreeSet::new();
    let mut expected_publication_ids = std::collections::BTreeSet::new();
    for row in rows {
        let checkpoint = super::support::parse_persisted_checkpoint_row(row.clone())?;
        if checkpoint.body.batch_end_seq > committed_watermark {
            super::support::validate_checkpoint_against_claim_log(live, &checkpoint)?;
        }
        super::support::validate_checkpoint_projection_rows(live, &row, &checkpoint)?;
        expected_head_ids.insert(row.checkpoint_seq);
        if checkpoint.body.previous_checkpoint_sha256.is_some() {
            expected_witness_ids.insert(row.checkpoint_seq);
        }
        expected_publication_ids.insert(row.checkpoint_seq);
        if let Some(predecessor) = latest.as_ref() {
            chio_kernel::checkpoint::validate_checkpoint_predecessor(predecessor, &checkpoint)
                .map_err(super::support::checkpoint_error_to_receipt_store)?;
        } else {
            super::support::validate_checkpoint_base(&checkpoint)?;
        }
        latest = Some(checkpoint);
    }

    if super::support::load_checkpoint_tree_head_projection_ids(live)? != expected_head_ids {
        return Err(ReceiptStoreError::Conflict(
            "retention repair found checkpoint tree head projection set drift".to_string(),
        ));
    }
    if super::support::load_checkpoint_predecessor_witness_projection_ids(live)?
        != expected_witness_ids
    {
        return Err(ReceiptStoreError::Conflict(
            "retention repair found checkpoint predecessor witness projection set drift"
                .to_string(),
        ));
    }
    if super::support::load_checkpoint_publication_metadata_projection_ids(live)?
        != expected_publication_ids
    {
        return Err(ReceiptStoreError::Conflict(
            "retention repair found checkpoint publication metadata projection set drift"
                .to_string(),
        ));
    }
    Ok(())
}

fn repair_rounded_watermark(
    connection: &rusqlite::Connection,
) -> Result<Option<u64>, ReceiptStoreError> {
    let max_extra_entry_seq: Option<i64> = connection.query_row(
        "SELECT MAX(e.entry_seq) FROM claim_receipt_log_entries e \
         WHERE NOT EXISTS (SELECT 1 FROM chio_tool_receipts t WHERE t.receipt_id = e.receipt_id) \
           AND NOT EXISTS (SELECT 1 FROM chio_child_receipts c WHERE c.receipt_id = e.receipt_id)",
        [],
        |row| row.get(0),
    )?;
    let Some(max_extra_entry_seq) = max_extra_entry_seq else {
        return Ok(None);
    };
    let rounded: Option<i64> = connection.query_row(
        "SELECT MIN(batch_end_seq) FROM kernel_checkpoints WHERE batch_end_seq >= ?1",
        params![max_extra_entry_seq],
        |row| row.get(0),
    )?;
    let rounded = rounded.ok_or_else(|| {
        ReceiptStoreError::Conflict(
            "retention repair: extra claim-log rows are not covered by any checkpoint; \
             refusing to touch the uncheckpointed suffix"
                .to_string(),
        )
    })?;
    sqlite_positive_u64(rounded, "repair rounded watermark").map(Some)
}

pub(super) fn retention_repair_on_writer(
    connection: &mut rusqlite::Connection,
    archive_path: &str,
) -> Result<u64, ReceiptStoreError> {
    retention_repair_on_writer_with_precommit_boundary(connection, archive_path, || Ok(()))
}

#[cfg(test)]
pub(super) fn retention_repair_on_writer_with_precommit_boundary_for_test<F>(
    connection: &mut rusqlite::Connection,
    archive_path: &str,
    precommit_boundary: F,
) -> Result<u64, ReceiptStoreError>
where
    F: FnOnce() -> Result<(), ReceiptStoreError>,
{
    retention_repair_on_writer_with_precommit_boundary(connection, archive_path, precommit_boundary)
}

fn retention_repair_on_writer_with_precommit_boundary<F>(
    connection: &mut rusqlite::Connection,
    archive_path: &str,
    precommit_boundary: F,
) -> Result<u64, ReceiptStoreError>
where
    F: FnOnce() -> Result<(), ReceiptStoreError>,
{
    let Some(preflight_rounded_watermark) = repair_rounded_watermark(connection)? else {
        return Ok(0);
    };
    ensure_durable_distinct_archive_path(connection, archive_path)?;
    let archive_path = absolute_archive_path(archive_path)?;
    let archive_path = archive_path.as_str();
    let preflight_watermark = super::support::retention_watermark(connection)?.ok_or_else(|| {
        ReceiptStoreError::Conflict(
            "retention repair requires an existing committed archival watermark; repair cannot \
             create archival authority"
                .to_string(),
        )
    })?;
    if preflight_watermark < preflight_rounded_watermark {
        return Err(ReceiptStoreError::Conflict(format!(
            "retention repair checkpoint boundary {preflight_rounded_watermark} exceeds the \
             committed archival watermark {preflight_watermark}"
        )));
    }
    let archive_lock_watermark_i64 =
        sqlite_i64(preflight_watermark, "repair archive lock watermark")?;
    let preflight_archive_path =
        super::support::latest_watermark_archive_path(connection)?.ok_or_else(|| {
            ReceiptStoreError::Conflict(
                "retention repair requires a committed archive path".to_string(),
            )
        })?;
    if preflight_archive_path != archive_path {
        return Err(ReceiptStoreError::Conflict(format!(
            "retention repair archive {archive_path:?} differs from the archive \
             {preflight_archive_path:?} that backs the existing watermark"
        )));
    }
    let preflight_archive_identity =
        super::support::latest_watermark_archive_sha256(connection)?.ok_or_else(|| {
            ReceiptStoreError::Conflict(
                "retention repair requires a committed archive identity".to_string(),
            )
        })?;
    let preflight_committed_archive_content =
        super::support::latest_watermark_archive_content_sha256(connection)?.ok_or_else(|| {
            ReceiptStoreError::Conflict(
                "retention repair requires a committed canonical archive prefix digest"
                    .to_string(),
            )
        })?;
    // Repair has no ATTACH copy phase and therefore has no safe authority to
    // create an archive identity. Require a marker already created through the
    // original archive copy handle and inspect it read-only. This avoids any
    // pathname writer that a hardlink swap could redirect into the live inode.
    let archive_identity = {
        let flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW;
        let archive =
            rusqlite::Connection::open_with_flags(archive_path, flags).map_err(|error| {
                ReceiptStoreError::Conflict(format!(
                    "retention repair archive {archive_path:?} could not be opened read-only \
                     without following links during identity preflight: {error}"
                ))
            })?;
        archive.execute_batch("PRAGMA query_only = ON; BEGIN DEFERRED")?;
        archive.query_row("SELECT COUNT(*) FROM main.sqlite_master", [], |row| {
            row.get::<_, i64>(0)
        })?;
        let commitment = super::support::load_validated_retention_archive_identity(&archive)?;
        if commitment != preflight_archive_identity {
            return Err(ReceiptStoreError::Conflict(format!(
                "retention repair archive identity {commitment:?} differs from the committed \
                 watermark identity {preflight_archive_identity:?}"
            )));
        }
        validate_retention_archive_prefix_content_sha256(
            &archive,
            "main",
            archive_lock_watermark_i64,
            &preflight_committed_archive_content,
        )?;
        commitment
    };
    ensure_durable_distinct_archive_path(connection, archive_path)?;
    // Acquire archive ownership before the live IMMEDIATE transaction and hold
    // it through commit. Repair and rotation therefore share one lock order and
    // cannot deadlock each other while excluding concurrent archive writers.
    let recorded_archive_guard = open_verified_recorded_archive(
        archive_path,
        &archive_identity,
        &preflight_committed_archive_content,
        archive_lock_watermark_i64,
    )?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    super::bootstrap::open::validate_no_temp_schema_objects(&tx)?;
    ensure_durable_distinct_archive_path(&tx, archive_path)?;

    let extras: Vec<(i64, String)> = {
        let mut statement = tx.prepare(
            "SELECT e.entry_seq, e.receipt_id FROM claim_receipt_log_entries e \
             WHERE NOT EXISTS (SELECT 1 FROM chio_tool_receipts t WHERE t.receipt_id = e.receipt_id) \
               AND NOT EXISTS (SELECT 1 FROM chio_child_receipts c WHERE c.receipt_id = e.receipt_id) \
             ORDER BY e.entry_seq",
        )?;
        let rows = statement.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let mut extras = Vec::new();
        for row in rows {
            extras.push(row?);
        }
        extras
    };
    if extras.is_empty() {
        tx.commit()?;
        return Ok(0);
    }
    validate_repair_live_mutation_contract(&tx)?;
    let removed = extras.len() as u64;
    let rounded_watermark = repair_rounded_watermark(&tx)?.ok_or_else(|| {
        ReceiptStoreError::Conflict(
            "retention repair candidates disappeared after archive preflight".to_string(),
        )
    })?;
    if rounded_watermark != preflight_rounded_watermark {
        return Err(ReceiptStoreError::Conflict(format!(
            "retention repair checkpoint boundary changed from {preflight_rounded_watermark} to \
             {rounded_watermark} after archive preflight; retry against the current prefix"
        )));
    }
    let rounded = sqlite_i64(rounded_watermark, "repair rounded watermark")?;

    let live_in_prefix: i64 = tx.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries e \
         WHERE e.entry_seq <= ?1 \
           AND (EXISTS (SELECT 1 FROM chio_tool_receipts t WHERE t.receipt_id = e.receipt_id) \
                OR EXISTS (SELECT 1 FROM chio_child_receipts c WHERE c.receipt_id = e.receipt_id))",
        params![rounded],
        |row| row.get(0),
    )?;
    if live_in_prefix > 0 {
        return Err(ReceiptStoreError::Conflict(
            "retention repair: the checkpoint batch covering the orphaned rows still has live \
             source receipts; refusing to clean a partially archived batch"
                .to_string(),
        ));
    }

    validate_repair_locked_archive_authority(
        &tx,
        preflight_watermark,
        archive_path,
        &preflight_archive_identity,
        &preflight_committed_archive_content,
    )?;
    let trusted_tombstone_ceiling = preflight_watermark;

    let archive = recorded_archive_guard.connection();
    ensure_durable_distinct_archive_path(&tx, archive_path)?;
    validate_repair_live_projection_drift(&tx, &extras)?;
    ensure_no_late_settlement_barrier(&tx, archive_lock_watermark_i64)?;
    ensure_repair_archive_ids_have_no_prunable_evidence(
        &tx,
        archive,
        preflight_watermark,
    )?;
    validate_repair_archive_source_projection(archive, preflight_watermark)?;
    validate_repair_archive_auxiliary_evidence(&tx, archive, preflight_watermark)?;
    validate_repair_archive_live_overlap(&tx, archive, preflight_watermark, &extras)?;

    if !super::support::archive_connection_backs_prefix(&tx, archive, preflight_watermark)? {
        return Err(ReceiptStoreError::RetentionArchiveIncomplete {
            table: "claim_receipt_log_entries",
            live: preflight_watermark,
            archived: 0,
        });
    }
    validate_and_backfill_retention_capability_freezes(
        &tx,
        archive,
        archive_lock_watermark_i64,
        None,
    )?;

    tx.execute_batch("DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete;")?;
    let now_i64 = sqlite_i64(now, "repair tombstone timestamp")?;
    let archived_rows = {
        let mut archive_statement = archive.prepare(
            "SELECT entry_seq, receipt_id, receipt_kind, source_seq, timestamp, capability_id, \
                    session_id, parent_request_id, request_id, subject_key, issuer_key, \
                    tool_server, tool_name, raw_json \
             FROM claim_receipt_log_entries WHERE entry_seq <= ?1 ORDER BY entry_seq",
        )?;
        let archive_rows =
            archive_statement.query_map(params![archive_lock_watermark_i64], |row| {
            Ok(RepairClaimLogRow {
                entry_seq: row.get(0)?,
                receipt_id: row.get(1)?,
                receipt_kind: row.get(2)?,
                source_seq: row.get(3)?,
                timestamp: row.get(4)?,
                capability_id: row.get(5)?,
                session_id: row.get(6)?,
                parent_request_id: row.get(7)?,
                request_id: row.get(8)?,
                subject_key: row.get(9)?,
                issuer_key: row.get(10)?,
                tool_server: row.get(11)?,
                tool_name: row.get(12)?,
                raw_json: row.get(13)?,
            })
        })?;
        let mut expected_entry_seq = 1_i64;
        for row in archive_rows {
            let row = row?;
            if row.entry_seq != expected_entry_seq {
                return Err(ReceiptStoreError::RetentionArchiveIncomplete {
                    table: "claim_receipt_log_entries",
                    live: preflight_watermark,
                    archived: sqlite_u64(
                        expected_entry_seq.saturating_sub(1),
                        "repair archive rows",
                    )?,
                });
            }
            validate_repair_archive_claim_identity(&row)?;
            tx.execute(
                "INSERT OR IGNORE INTO receipt_retention_tombstones \
                     (receipt_id, receipt_kind, archived_through_entry_seq, tombstoned_at) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    row.receipt_id,
                    row.receipt_kind,
                    archive_lock_watermark_i64,
                    now_i64
                ],
            )?;
            let (stored_kind, stored_boundary): (String, i64) = tx.query_row(
                "SELECT receipt_kind, archived_through_entry_seq \
                 FROM receipt_retention_tombstones WHERE receipt_id = ?1",
                params![row.receipt_id],
                |stored| Ok((stored.get(0)?, stored.get(1)?)),
            )?;
            let stored_boundary = sqlite_u64(
                stored_boundary,
                "repair existing tombstone archival boundary",
            )?;
            let row_entry_seq = sqlite_positive_u64(row.entry_seq, "repair tombstone entry_seq")?;
            if stored_kind != row.receipt_kind
                || stored_boundary < row_entry_seq
                || stored_boundary > trusted_tombstone_ceiling
            {
                return Err(ReceiptStoreError::Conflict(format!(
                    "retention tombstone for archived receipt {:?} conflicts with the trusted \
                     archive prefix",
                    row.receipt_id
                )));
            }
            expected_entry_seq = expected_entry_seq.checked_add(1).ok_or_else(|| {
                ReceiptStoreError::Conflict(
                    "retention repair archive entry sequence overflowed".to_string(),
                )
            })?;
        }
        expected_entry_seq.saturating_sub(1)
    };
    if archived_rows != archive_lock_watermark_i64 {
        return Err(ReceiptStoreError::RetentionArchiveIncomplete {
            table: "claim_receipt_log_entries",
            live: preflight_watermark,
            archived: sqlite_u64(archived_rows, "repair archived prefix count")?,
        });
    }

    for (entry_seq, _) in &extras {
        let deleted = tx.execute(
            "DELETE FROM claim_receipt_log_entries WHERE entry_seq = ?1 \
             AND NOT EXISTS (SELECT 1 FROM chio_tool_receipts t \
                             WHERE t.receipt_id = claim_receipt_log_entries.receipt_id) \
             AND NOT EXISTS (SELECT 1 FROM chio_child_receipts c \
                             WHERE c.receipt_id = claim_receipt_log_entries.receipt_id)",
            params![entry_seq],
        )?;
        if deleted != 1 {
            return Err(ReceiptStoreError::Conflict(format!(
                "retention repair candidate at entry {entry_seq} regained a live source"
            )));
        }
    }

    ensure_transparency_projection_guards(&tx)?;
    super::bootstrap::open::validate_no_temp_schema_objects(&tx)?;
    validate_repair_live_projection_drift(&tx, &[])?;
    validate_repair_live_mutation_contract(&tx)?;
    verify_repair_checkpoint_chain_and_projections(&tx, archive, preflight_watermark)?;
    precommit_boundary()?;
    recorded_archive_guard.validate_binding()?;
    ensure_durable_distinct_archive_path(&tx, archive_path)?;
    validate_repair_locked_archive_authority(
        &tx,
        preflight_watermark,
        archive_path,
        &preflight_archive_identity,
        &preflight_committed_archive_content,
    )?;
    tx.commit()?;

    connection.execute_batch("PRAGMA incremental_vacuum")?;
    require_complete_wal_checkpoint(connection, "live retention database")?;
    Ok(removed)
}
