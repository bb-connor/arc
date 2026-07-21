/// Every row the delete will remove must already be in the archive, and it must
/// be IDENTICAL to the live row, not merely present. Presence alone is not
/// enough: the copy uses `INSERT OR IGNORE`, so a pre-existing archive row with
/// the same primary key but different bytes (a conflicting or partially-written
/// prior archive, or a reused archive file) is silently kept and the live row
/// is dropped by the IGNORE. A count-only check would pass while the archive
/// held stale bytes, and the delete would then leave the store with no faithful
/// archived copy. Every archived table the delete touches is therefore verified
/// by identity: the receipt tables (`chio_tool_receipts`, `chio_child_receipts`)
/// keyed on `seq` (the primary key the claim-log projection's `source_seq`
/// points at, so a same-`receipt_id` archive row copied under a different `seq`
/// cannot pass) with a NULL-safe (`IS`) compare of every remaining column, and
/// the claim-log projection, checkpoint rows, and
/// settlement/metered/consumption reconciliations by a NULL-safe (`IS`)
/// full-column compare of the live prefix rows against their archive
/// counterparts (keyed on each table's primary key). A partial compare that
/// skipped the indexed/attribution columns (`subject_key`, `issuer_key`,
/// `grant_index`, `tenant_id`, or the child session/request columns) would let a
/// reused archive row misattribute retained evidence after the live row is gone. Capability lineage is
/// verified the same way even though the delete leaves the live lineage rows in
/// place: the archived receipts ARE deleted, so the archive becomes the only
/// standalone-authoritative copy of their capability subject/issuer/grants, and
/// a divergent archived lineage row would misattribute them. The compare is
/// bounded to the archived prefix (`O(archived rows)`, a primary-key lookup per
/// row, never `O(full history)`). Any shortfall aborts before any delete
/// (fail-closed, `RetentionArchiveIncomplete`).
fn verify_co_archival_complete(
    connection: &rusqlite::Connection,
    w: i64,
) -> Result<(), ReceiptStoreError> {
    let mut checks: Vec<(&'static str, String, String)> = vec![
        (
            // Present AND every column identical: `archive_sql` counts only live
            // prefix rows whose archive row matches on the `seq` primary key and
            // NULL-safely (`IS`) on every remaining column, so a missing OR
            // divergent archive row (including a differing indexed/attribution
            // column such as `subject_key`, `issuer_key`, `grant_index`, or
            // `tenant_id`, which archive reads filter on) makes archived < live
            // and aborts before the delete. A `receipt_id`/`raw_json`-only check
            // would keep a reused archive row that misattributes the receipt.
            "chio_tool_receipts",
            format!(
                "SELECT COUNT(*) FROM main.chio_tool_receipts WHERE seq IN \
                 (SELECT source_seq FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt')"
            ),
            format!(
                "SELECT COUNT(*) FROM main.chio_tool_receipts m WHERE m.seq IN \
                 (SELECT source_seq FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt') \
                 AND EXISTS (SELECT 1 FROM archive.chio_tool_receipts a WHERE a.seq = m.seq \
                 AND a.receipt_id IS m.receipt_id AND a.timestamp IS m.timestamp \
                 AND a.capability_id IS m.capability_id AND a.subject_key IS m.subject_key \
                 AND a.issuer_key IS m.issuer_key AND a.grant_index IS m.grant_index \
                 AND a.tool_server IS m.tool_server AND a.tool_name IS m.tool_name \
                 AND a.decision_kind IS m.decision_kind AND a.policy_hash IS m.policy_hash \
                 AND a.content_hash IS m.content_hash AND a.raw_json IS m.raw_json \
                 AND a.tenant_id IS m.tenant_id)"
            ),
        ),
        (
            // Same full-row identity for child receipts: a reused archive row
            // matching only `seq`/`receipt_id`/`raw_json` but diverging on
            // `session_id`, `parent_request_id`, `request_id`, or the outcome
            // columns would misattribute retained child evidence once the live
            // row is deleted.
            "chio_child_receipts",
            format!(
                "SELECT COUNT(*) FROM main.chio_child_receipts WHERE seq IN \
                 (SELECT source_seq FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'child_receipt')"
            ),
            format!(
                "SELECT COUNT(*) FROM main.chio_child_receipts m WHERE m.seq IN \
                 (SELECT source_seq FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'child_receipt') \
                 AND EXISTS (SELECT 1 FROM archive.chio_child_receipts a WHERE a.seq = m.seq \
                 AND a.receipt_id IS m.receipt_id AND a.timestamp IS m.timestamp \
                 AND a.session_id IS m.session_id AND a.parent_request_id IS m.parent_request_id \
                 AND a.request_id IS m.request_id AND a.operation_kind IS m.operation_kind \
                 AND a.terminal_state IS m.terminal_state AND a.policy_hash IS m.policy_hash \
                 AND a.outcome_hash IS m.outcome_hash AND a.raw_json IS m.raw_json)"
            ),
        ),
        (
            // Identity on the full row (entry_seq is the PK, copied verbatim):
            // a divergent archived projection row makes archived < live.
            "claim_receipt_log_entries",
            format!("SELECT COUNT(*) FROM main.claim_receipt_log_entries WHERE entry_seq <= {w}"),
            format!(
                "SELECT COUNT(*) FROM main.claim_receipt_log_entries m WHERE m.entry_seq <= {w} \
                 AND EXISTS (SELECT 1 FROM archive.claim_receipt_log_entries a WHERE a.entry_seq = m.entry_seq \
                 AND a.receipt_id IS m.receipt_id AND a.receipt_kind IS m.receipt_kind \
                 AND a.source_seq IS m.source_seq AND a.timestamp IS m.timestamp \
                 AND a.capability_id IS m.capability_id AND a.session_id IS m.session_id \
                 AND a.parent_request_id IS m.parent_request_id AND a.request_id IS m.request_id \
                 AND a.subject_key IS m.subject_key AND a.issuer_key IS m.issuer_key \
                 AND a.tool_server IS m.tool_server AND a.tool_name IS m.tool_name \
                 AND a.raw_json IS m.raw_json)"
            ),
        ),
        (
            // Identity keyed on checkpoint_seq (UNIQUE): every content column,
            // including the signed statement and signature, must match.
            "kernel_checkpoints",
            format!("SELECT COUNT(*) FROM main.kernel_checkpoints WHERE batch_end_seq <= {w}"),
            format!(
                "SELECT COUNT(*) FROM main.kernel_checkpoints m WHERE m.batch_end_seq <= {w} \
                 AND EXISTS (SELECT 1 FROM archive.kernel_checkpoints a WHERE a.checkpoint_seq = m.checkpoint_seq \
                 AND a.id IS m.id AND a.batch_start_seq IS m.batch_start_seq \
                 AND a.batch_end_seq IS m.batch_end_seq AND a.tree_size IS m.tree_size \
                 AND a.merkle_root IS m.merkle_root AND a.issued_at IS m.issued_at \
                 AND a.statement_json IS m.statement_json AND a.signature IS m.signature \
                AND a.kernel_key IS m.kernel_key)"
            ),
        ),
        (
            "checkpoint_tree_heads",
            format!(
                "SELECT COUNT(*) FROM main.checkpoint_tree_heads p \
                 INNER JOIN main.kernel_checkpoints k ON k.checkpoint_seq = p.checkpoint_seq \
                 WHERE k.batch_end_seq <= {w}"
            ),
            format!(
                "SELECT COUNT(*) FROM main.checkpoint_tree_heads m \
                 INNER JOIN main.kernel_checkpoints k ON k.checkpoint_seq = m.checkpoint_seq \
                 WHERE k.batch_end_seq <= {w} \
                 AND EXISTS (SELECT 1 FROM archive.checkpoint_tree_heads a \
                 WHERE a.checkpoint_seq = m.checkpoint_seq \
                 AND a.batch_start_seq IS m.batch_start_seq \
                 AND a.batch_end_seq IS m.batch_end_seq AND a.tree_size IS m.tree_size \
                 AND a.merkle_root IS m.merkle_root AND a.issued_at IS m.issued_at \
                 AND a.kernel_key IS m.kernel_key \
                 AND a.previous_checkpoint_sha256 IS m.previous_checkpoint_sha256 \
                 AND a.statement_json IS m.statement_json AND a.signature IS m.signature)"
            ),
        ),
        (
            "checkpoint_predecessor_witnesses",
            format!(
                "SELECT COUNT(*) FROM main.checkpoint_predecessor_witnesses p \
                 INNER JOIN main.kernel_checkpoints k \
                    ON k.checkpoint_seq = p.witness_checkpoint_seq \
                 WHERE k.batch_end_seq <= {w}"
            ),
            format!(
                "SELECT COUNT(*) FROM main.checkpoint_predecessor_witnesses m \
                 INNER JOIN main.kernel_checkpoints k \
                    ON k.checkpoint_seq = m.witness_checkpoint_seq \
                 WHERE k.batch_end_seq <= {w} \
                 AND EXISTS (SELECT 1 FROM archive.checkpoint_predecessor_witnesses a \
                 WHERE a.witness_checkpoint_seq = m.witness_checkpoint_seq \
                 AND a.predecessor_checkpoint_seq IS m.predecessor_checkpoint_seq \
                 AND a.previous_checkpoint_sha256 IS m.previous_checkpoint_sha256 \
                 AND a.witnessed_at IS m.witnessed_at \
                 AND a.witness_statement_json IS m.witness_statement_json)"
            ),
        ),
        (
            "checkpoint_publication_metadata",
            format!(
                "SELECT COUNT(*) FROM main.checkpoint_publication_metadata p \
                 INNER JOIN main.kernel_checkpoints k ON k.checkpoint_seq = p.checkpoint_seq \
                 WHERE k.batch_end_seq <= {w}"
            ),
            format!(
                "SELECT COUNT(*) FROM main.checkpoint_publication_metadata m \
                 INNER JOIN main.kernel_checkpoints k ON k.checkpoint_seq = m.checkpoint_seq \
                 WHERE k.batch_end_seq <= {w} \
                 AND EXISTS (SELECT 1 FROM archive.checkpoint_publication_metadata a \
                 WHERE a.checkpoint_seq = m.checkpoint_seq \
                 AND a.publication_schema IS m.publication_schema \
                 AND a.merkle_root IS m.merkle_root AND a.published_at IS m.published_at \
                 AND a.kernel_key IS m.kernel_key AND a.log_tree_size IS m.log_tree_size \
                 AND a.entry_start_seq IS m.entry_start_seq \
                 AND a.entry_end_seq IS m.entry_end_seq \
                 AND a.previous_checkpoint_sha256 IS m.previous_checkpoint_sha256)"
            ),
        ),
        (
            "checkpoint_publication_trust_anchor_bindings",
            format!(
                "SELECT COUNT(*) FROM main.checkpoint_publication_trust_anchor_bindings p \
                 INNER JOIN main.kernel_checkpoints k ON k.checkpoint_seq = p.checkpoint_seq \
                 WHERE k.batch_end_seq <= {w}"
            ),
            format!(
                "SELECT COUNT(*) FROM main.checkpoint_publication_trust_anchor_bindings m \
                 INNER JOIN main.kernel_checkpoints k ON k.checkpoint_seq = m.checkpoint_seq \
                 WHERE k.batch_end_seq <= {w} \
                 AND EXISTS (SELECT 1 \
                 FROM archive.checkpoint_publication_trust_anchor_bindings a \
                 WHERE a.checkpoint_seq = m.checkpoint_seq \
                 AND a.binding_json IS m.binding_json)"
            ),
        ),
        (
            // Identity keyed on receipt_id (PK): state, note, and timestamp
            // must match the live reconciliation row being archived.
            "settlement_reconciliations",
            format!(
                "SELECT COUNT(*) FROM main.settlement_reconciliations WHERE receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt')"
            ),
            format!(
                "SELECT COUNT(*) FROM main.settlement_reconciliations m WHERE m.receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt') \
                 AND EXISTS (SELECT 1 FROM archive.settlement_reconciliations a WHERE a.receipt_id = m.receipt_id \
                 AND a.reconciliation_state IS m.reconciliation_state AND a.note IS m.note \
                 AND a.updated_at IS m.updated_at)"
            ),
        ),
        (
            // Identity keyed on receipt_id (PK): all metered evidence columns
            // (units, cost, currency, evidence hash, state, note) must match.
            "metered_billing_reconciliations",
            format!(
                "SELECT COUNT(*) FROM main.metered_billing_reconciliations WHERE receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt')"
            ),
            format!(
                "SELECT COUNT(*) FROM main.metered_billing_reconciliations m WHERE m.receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt') \
                 AND EXISTS (SELECT 1 FROM archive.metered_billing_reconciliations a WHERE a.receipt_id = m.receipt_id \
                 AND a.adapter_kind IS m.adapter_kind AND a.evidence_id IS m.evidence_id \
                 AND a.observed_units IS m.observed_units AND a.billed_cost_units IS m.billed_cost_units \
                 AND a.billed_cost_currency IS m.billed_cost_currency AND a.evidence_sha256 IS m.evidence_sha256 \
                 AND a.recorded_at IS m.recorded_at AND a.reconciliation_state IS m.reconciliation_state \
                 AND a.note IS m.note AND a.updated_at IS m.updated_at)"
            ),
        ),
        (
            // Identity keyed on authorization_receipt_id (PK): the consuming
            // receipt, request/session/tool-call identifiers, tenant, parameter
            // hash, and consumption timestamp must all match.
            "chio_authorization_receipt_consumptions",
            format!(
                "SELECT COUNT(*) FROM main.chio_authorization_receipt_consumptions WHERE authorization_receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt')"
            ),
            format!(
                "SELECT COUNT(*) FROM main.chio_authorization_receipt_consumptions m WHERE m.authorization_receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt') \
                 AND EXISTS (SELECT 1 FROM archive.chio_authorization_receipt_consumptions a \
                 WHERE a.authorization_receipt_id = m.authorization_receipt_id \
                 AND a.consumer_receipt_id IS m.consumer_receipt_id AND a.request_id IS m.request_id \
                 AND a.session_id IS m.session_id AND a.tool_call_id IS m.tool_call_id \
                 AND a.tenant_id IS m.tenant_id AND a.parameter_hash IS m.parameter_hash \
                 AND a.consumed_at_unix_ms IS m.consumed_at_unix_ms)"
            ),
        ),
        (
            // Identity keyed on capability_id (PK). The delete removes the live
            // receipts but NOT the live lineage rows, so the archive becomes the
            // ONLY copy of the archived receipts' capability lineage (subject,
            // issuer, grants). The idempotent `INSERT OR IGNORE` copy keeps a
            // pre-existing archive row on a capability_id conflict, so a reused
            // archive holding the same capability under divergent lineage bytes
            // would silently misattribute the archived receipts' subject/issuer/
            // grants and agent-subject filtering. Verify every lineage row
            // referenced by an archived tool receipt matches the live row before
            // the delete.
            "capability_lineage",
            format!(
                "SELECT COUNT(*) FROM main.capability_lineage m WHERE m.capability_id IN \
                 (SELECT r.capability_id FROM main.chio_tool_receipts r WHERE r.seq IN \
                  (SELECT source_seq FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt'))"
            ),
            format!(
                "SELECT COUNT(*) FROM main.capability_lineage m WHERE m.capability_id IN \
                 (SELECT r.capability_id FROM main.chio_tool_receipts r WHERE r.seq IN \
                  (SELECT source_seq FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt')) \
                 AND EXISTS (SELECT 1 FROM archive.capability_lineage a WHERE a.capability_id = m.capability_id \
                 AND a.subject_key IS m.subject_key AND a.issuer_key IS m.issuer_key \
                 AND a.issued_at IS m.issued_at AND a.expires_at IS m.expires_at \
                 AND a.grants_json IS m.grants_json AND a.delegation_depth IS m.delegation_depth \
                 AND a.parent_capability_id IS m.parent_capability_id)"
            ),
        ),
        (
            // Identity keyed on receipt_id (PK). Governed receipts persist a
            // lineage statement carrying their call-chain provenance and the
            // stored verification flags. The delete removes the receipts but not
            // the live lineage rows, so the archive becomes the ONLY standalone
            // copy of an archived receipt's lineage evidence, read back by
            // `receipt_lineage_verification` / lineage-link queries. The
            // idempotent `INSERT OR IGNORE` copy keeps a pre-existing archive row
            // on a receipt_id conflict, so a reused archive holding the same
            // receipt under divergent lineage bytes would misattribute its
            // provenance. Verify every lineage row for an archived receipt matches
            // the live row before the delete.
            "receipt_lineage_statements",
            format!(
                "SELECT COUNT(*) FROM main.receipt_lineage_statements WHERE receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w})"
            ),
            format!(
                "SELECT COUNT(*) FROM main.receipt_lineage_statements m WHERE m.receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w}) \
                 AND EXISTS (SELECT 1 FROM archive.receipt_lineage_statements a WHERE a.receipt_id = m.receipt_id \
                 AND a.statement_id IS m.statement_id AND a.request_id IS m.request_id \
                 AND a.session_id IS m.session_id AND a.session_anchor_id IS m.session_anchor_id \
                 AND a.chain_id IS m.chain_id AND a.parent_request_id IS m.parent_request_id \
                 AND a.parent_receipt_id IS m.parent_receipt_id AND a.evidence_class IS m.evidence_class \
                 AND a.evidence_sources_json IS m.evidence_sources_json \
                 AND a.verified_session_anchor IS m.verified_session_anchor \
                 AND a.verified_parent_request IS m.verified_parent_request \
                 AND a.verified_parent_receipt IS m.verified_parent_receipt \
                 AND a.replay_protected IS m.replay_protected AND a.recorded_at IS m.recorded_at \
                 AND a.source_kind IS m.source_kind AND a.json_sha256 IS m.json_sha256 \
                 AND a.raw_json IS m.raw_json)"
            ),
        ),
    ];
    let iou_envelope_exists = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_master \
         WHERE type = 'table' AND name = 'iou_envelope')",
        [],
        |row| row.get::<_, i64>(0),
    )? != 0;
    if iou_envelope_exists {
        checks.push((
            "iou_envelope",
            format!(
                "SELECT COUNT(*) FROM main.iou_envelope WHERE receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt')"
            ),
            format!(
                "SELECT COUNT(*) FROM main.iou_envelope m WHERE m.receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt') \
                 AND EXISTS (SELECT 1 FROM archive.iou_envelope a WHERE a.receipt_id = m.receipt_id \
                 AND a.iou_id IS m.iou_id AND a.receipt_timestamp IS m.receipt_timestamp \
                 AND a.tenant_id IS m.tenant_id AND a.amount_units IS m.amount_units \
                 AND a.currency IS m.currency AND a.issuer_key IS m.issuer_key \
                 AND a.canonical_json IS m.canonical_json)"
            ),
        ));
    }
    for (table, live_sql, archive_sql) in checks {
        let live: i64 = connection.query_row(&live_sql, [], |row| row.get(0))?;
        let archived: i64 = connection.query_row(&archive_sql, [], |row| row.get(0))?;
        if archived < live {
            return Err(ReceiptStoreError::RetentionArchiveIncomplete {
                table,
                live: sqlite_u64(live, "live co-archival count")?,
                archived: sqlite_u64(archived, "archive co-archival count")?,
            });
        }
    }
    Ok(())
}

/// Run the full co-archival identity check across two already-open primary
/// database handles. This is the final path-binding verifier: `live` is the
/// caller's active `BEGIN IMMEDIATE` writer transaction, while `archive` is the
/// separately retained archive ownership transaction opened through the
/// descriptor-bound durable file. Comparing the handles in Rust avoids
/// attaching or reopening the live pathname and therefore cannot be turned into an
/// archive-versus-itself comparison by replacing that pathname.
///
/// Every query selects the complete persisted row in primary-key order from
/// the newly advancing checkpoint-aligned suffix `(previous_watermark, w]`.
/// The previously committed prefix is verified independently against its signed
/// checkpoint roots before this function runs. Rows are streamed in lockstep,
/// so the check is O(suffix rows) with constant auxiliary memory. Equality
/// includes both SQLite value type and bytes for every column. The archive
/// schema contract is validated before this function runs, making `SELECT *`
/// column order an asserted part of the evidence contract rather than an
/// implicit assumption.
fn verify_co_archival_complete_between_connections(
    live: &rusqlite::Connection,
    archive: &rusqlite::Connection,
    previous_watermark: i64,
    w: i64,
) -> Result<(), ReceiptStoreError> {
    let mut checks: Vec<(&'static str, String)> = vec![
        (
            "chio_tool_receipts",
            format!(
                "SELECT * FROM main.chio_tool_receipts WHERE seq IN \
                 (SELECT source_seq FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} \
                  AND entry_seq > {previous_watermark} \
                  AND receipt_kind = 'tool_receipt') ORDER BY seq"
            ),
        ),
        (
            "chio_child_receipts",
            format!(
                "SELECT * FROM main.chio_child_receipts WHERE seq IN \
                 (SELECT source_seq FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} \
                  AND entry_seq > {previous_watermark} \
                  AND receipt_kind = 'child_receipt') ORDER BY seq"
            ),
        ),
        (
            "claim_receipt_log_entries",
            format!(
                "SELECT * FROM main.claim_receipt_log_entries WHERE entry_seq > {previous_watermark} \
                 AND entry_seq <= {w} \
                 ORDER BY entry_seq"
            ),
        ),
        (
            "kernel_checkpoints",
            format!(
                "SELECT * FROM main.kernel_checkpoints WHERE batch_end_seq > {previous_watermark} \
                 AND batch_end_seq <= {w} \
                 ORDER BY checkpoint_seq"
            ),
        ),
        (
            "checkpoint_tree_heads",
            format!(
                "SELECT p.* FROM main.checkpoint_tree_heads p \
                 INNER JOIN main.kernel_checkpoints k ON k.checkpoint_seq = p.checkpoint_seq \
                 WHERE k.batch_end_seq > {previous_watermark} AND k.batch_end_seq <= {w} \
                 ORDER BY p.checkpoint_seq"
            ),
        ),
        (
            "checkpoint_predecessor_witnesses",
            format!(
                "SELECT p.* FROM main.checkpoint_predecessor_witnesses p \
                 INNER JOIN main.kernel_checkpoints k \
                    ON k.checkpoint_seq = p.witness_checkpoint_seq \
                 WHERE k.batch_end_seq > {previous_watermark} AND k.batch_end_seq <= {w} \
                 ORDER BY p.witness_checkpoint_seq"
            ),
        ),
        (
            "checkpoint_publication_metadata",
            format!(
                "SELECT p.* FROM main.checkpoint_publication_metadata p \
                 INNER JOIN main.kernel_checkpoints k ON k.checkpoint_seq = p.checkpoint_seq \
                 WHERE k.batch_end_seq > {previous_watermark} AND k.batch_end_seq <= {w} \
                 ORDER BY p.checkpoint_seq"
            ),
        ),
        (
            "checkpoint_publication_trust_anchor_bindings",
            format!(
                "SELECT p.* FROM main.checkpoint_publication_trust_anchor_bindings p \
                 INNER JOIN main.kernel_checkpoints k ON k.checkpoint_seq = p.checkpoint_seq \
                 WHERE k.batch_end_seq > {previous_watermark} AND k.batch_end_seq <= {w} \
                 ORDER BY p.checkpoint_seq"
            ),
        ),
        (
            "settlement_reconciliations",
            format!(
                "SELECT * FROM main.settlement_reconciliations WHERE receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} \
                  AND entry_seq > {previous_watermark} \
                  AND receipt_kind = 'tool_receipt') ORDER BY receipt_id"
            ),
        ),
        (
            "metered_billing_reconciliations",
            format!(
                "SELECT * FROM main.metered_billing_reconciliations WHERE receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} \
                  AND entry_seq > {previous_watermark} \
                  AND receipt_kind = 'tool_receipt') ORDER BY receipt_id"
            ),
        ),
        (
            "chio_authorization_receipt_consumptions",
            format!(
                "SELECT * FROM main.chio_authorization_receipt_consumptions \
                 WHERE authorization_receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} \
                  AND entry_seq > {previous_watermark} \
                  AND receipt_kind = 'tool_receipt') ORDER BY authorization_receipt_id"
            ),
        ),
        (
            "capability_lineage",
            format!(
                "SELECT * FROM main.capability_lineage WHERE capability_id IN \
                 (SELECT r.capability_id FROM main.chio_tool_receipts r WHERE r.seq IN \
                  (SELECT source_seq FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} \
                   AND entry_seq > {previous_watermark} \
                   AND receipt_kind = 'tool_receipt')) ORDER BY capability_id"
            ),
        ),
        (
            "receipt_lineage_statements",
            format!(
                "SELECT * FROM main.receipt_lineage_statements WHERE receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries \
                  WHERE entry_seq > {previous_watermark} AND entry_seq <= {w}) \
                 ORDER BY receipt_id"
            ),
        ),
    ];
    let live_iou_envelope_exists = live.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_master \
         WHERE type = 'table' AND name = 'iou_envelope')",
        [],
        |row| row.get::<_, i64>(0),
    )? != 0;
    if live_iou_envelope_exists {
        checks.push((
            "iou_envelope",
            format!(
                "SELECT * FROM main.iou_envelope WHERE receipt_id IN \
                 (SELECT receipt_id FROM main.claim_receipt_log_entries WHERE entry_seq <= {w} \
                  AND entry_seq > {previous_watermark} \
                  AND receipt_kind = 'tool_receipt') ORDER BY receipt_id"
            ),
        ));
    }

    for (table, sql) in checks {
        let mut live_statement = live.prepare(&sql)?;
        let mut archive_statement = archive.prepare(&sql)?;
        let live_column_count = live_statement.column_count();
        let archive_column_count = archive_statement.column_count();
        if live_column_count != archive_column_count {
            return Err(ReceiptStoreError::Conflict(format!(
                "archive table {table} exposes {archive_column_count} columns but the live \
                 evidence table exposes {live_column_count}"
            )));
        }

        let mut live_rows = live_statement.query([])?;
        let mut archive_rows = archive_statement.query([])?;
        let mut live_count = 0_u64;
        let mut archive_count = 0_u64;
        let mut identical = true;
        loop {
            let live_row = live_rows.next()?;
            let archive_row = archive_rows.next()?;
            match (live_row, archive_row) {
                (Some(live_row), Some(archive_row)) => {
                    live_count = live_count.saturating_add(1);
                    archive_count = archive_count.saturating_add(1);
                    for column in 0..live_column_count {
                        if live_row.get_ref(column)? != archive_row.get_ref(column)? {
                            identical = false;
                        }
                    }
                }
                (Some(_), None) => {
                    live_count = live_count.saturating_add(1);
                    identical = false;
                }
                (None, Some(_)) => {
                    archive_count = archive_count.saturating_add(1);
                    identical = false;
                }
                (None, None) => break,
            }
        }
        if !identical {
            return Err(ReceiptStoreError::RetentionArchiveIncomplete {
                table,
                live: live_count,
                archived: archive_count,
            });
        }
    }
    Ok(())
}

/// Delete the [1, W] prefix from the live store in ONE BEGIN IMMEDIATE
/// transaction (FK-safe order: the reconciliation/consumption children first,
/// then the receipts, then the claim-log last so its rows drive the receipt
/// deletes), record the watermark, and restore the immutability guards. A
/// rollback restores rows AND triggers together, so a failed delete cannot
/// leave the store with its append-only guards dropped.
///
/// The claim-log and source-receipt tables must lose EXACTLY the same
/// receipt_id set together and atomically: deleting source rows while leaving
/// the claim-log projection intact would make the next projection validation
/// see set drift (the expected set shrank, the projection did not) and brick
/// the store on the following rotation.
#[allow(clippy::too_many_arguments)]
pub(super) fn delete_archived_prefix_in_tx(
    connection: &mut rusqlite::Connection,
    previous_watermark: i64,
    w: i64,
    cutoff_unix_secs: u64,
    archive_path: &str,
    archive_identity: &str,
    previous_archive_content_sha256: Option<&str>,
    archive_content_sha256: &str,
) -> Result<u64, ReceiptStoreError> {
    delete_archived_prefix_in_tx_with_boundary(
        connection,
        previous_watermark,
        w,
        cutoff_unix_secs,
        archive_path,
        archive_identity,
        previous_archive_content_sha256,
        archive_content_sha256,
        || Ok(()),
    )
}

#[cfg(test)]
pub(super) fn delete_archived_prefix_in_tx_with_precommit_boundary_for_test<F>(
    connection: &mut rusqlite::Connection,
    previous_watermark: i64,
    w: i64,
    cutoff_unix_secs: u64,
    archive_path: &str,
    archive_identity: &str,
    previous_archive_content_sha256: Option<&str>,
    archive_content_sha256: &str,
    precommit_boundary: F,
) -> Result<u64, ReceiptStoreError>
where
    F: FnOnce() -> Result<(), ReceiptStoreError>,
{
    delete_archived_prefix_in_tx_with_boundary(
        connection,
        previous_watermark,
        w,
        cutoff_unix_secs,
        archive_path,
        archive_identity,
        previous_archive_content_sha256,
        archive_content_sha256,
        precommit_boundary,
    )
}

#[allow(clippy::too_many_arguments)]
fn delete_archived_prefix_in_tx_with_boundary<F>(
    connection: &mut rusqlite::Connection,
    previous_watermark: i64,
    w: i64,
    cutoff_unix_secs: u64,
    archive_path: &str,
    archive_identity: &str,
    previous_archive_content_sha256: Option<&str>,
    archive_content_sha256: &str,
    precommit_boundary: F,
) -> Result<u64, ReceiptStoreError>
where
    F: FnOnce() -> Result<(), ReceiptStoreError>,
{
    super::bootstrap::open::validate_no_temp_schema_objects(connection)?;
    let archive_attached = super::bootstrap::open::sqlite_database_list(connection)?
        .into_iter()
        .any(|(_, schema, _)| schema == "archive");
    if archive_attached {
        return Err(ReceiptStoreError::Conflict(
            "retention archive must be detached before the final identity-bound delete".to_string(),
        ));
    }
    // Always acquire archive writer ownership before the live writer lock.
    // The archive EXCLUSIVE transaction in rollback-journal mode excludes
    // SQLite writers through every hardlink alias until the staged live
    // deletion has committed or rolled back.
    let recorded_archive_guard = open_verified_recorded_archive(
        archive_path,
        archive_identity,
        archive_content_sha256,
        w,
    )?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
    let locked_previous_watermark = super::support::retention_watermark(&tx)?.unwrap_or(0);
    let locked_previous_w = sqlite_i64(
        locked_previous_watermark,
        "locked previous archival watermark",
    )?;
    if locked_previous_w != previous_watermark {
        return Err(ReceiptStoreError::Conflict(format!(
            "retention watermark changed from {previous_watermark} to {locked_previous_w} while \
             the archive suffix was being copied; retry the rotation against the current prefix"
        )));
    }
    ensure_retention_iou_ownership_schema(&tx)?;
    super::support::validate_receipt_retention_watermark_schema(&tx)?;
    super::support::validate_receipt_retention_tombstones_schema(&tx)?;
    validate_transparency_projection_guards(&tx)?;
    super::bootstrap::open::validate_settlement_observer_outbox_schema(&tx, false)?;
    validate_retention_claim_projection_triggers(&tx)?;
    validate_retention_mutation_trigger_allowlist(&tx)?;
    validate_retention_foreign_key_delete_closure(&tx)?;
    ensure_no_late_settlement_barrier(&tx, w)?;
    // The archive copy ran before this transaction took the write lock, so a
    // second process could have committed a new dependent row in that window.
    // The independent full-row verifier below repeats completeness against the
    // locked live snapshot and fails on any late row before deletion.
    // The archive-path pin and the backing check also ran before this
    // transaction took the write lock, so a concurrent rotation could have
    // committed the shared prefix to a DIFFERENT archive, or moved/emptied the
    // pinned archive, in that window: one rotation commits `[1, W1]` to archive
    // A after the outer check, and this rotation would then copy only the
    // surviving suffix to archive B and record a higher watermark naming B,
    // leaving the ledger pointing at a file that lacks the earlier prefix.
    // Re-read the ledger under BEGIN IMMEDIATE (the same TOCTOU class as the
    // co-archival re-check above) and re-enforce both, so a rotation never
    // advances a watermark that splits the archived prefix or extends an archive
    // that no longer backs the committed prefix. The rollback on error leaves the
    // prefix intact and re-runnable.
    ensure_archive_path_matches_ledger(&tx, archive_path)?;
    // Repeat the device/inode alias check at the authoritative boundary. In WAL
    // mode, a hard link opened under another pathname can use a different
    // pathname-derived `-wal`/`-shm` pair, so a second SQLite writer lock alone
    // is not a reliable same-inode discriminator.
    ensure_durable_distinct_archive_path(&tx, archive_path)?;
    let locked_archive_identity = super::support::latest_watermark_archive_sha256(&tx)?;
    if previous_watermark > 0 {
        match locked_archive_identity.as_deref() {
            Some(committed) if committed == archive_identity => {}
            Some(committed) => {
                return Err(ReceiptStoreError::Conflict(format!(
                    "retention archive identity changed from {archive_identity:?} to \
                     {committed:?} while the archive suffix was being copied"
                )))
            }
            None => {
                return Err(ReceiptStoreError::Conflict(
                    "retention cannot advance a legacy watermark without a committed archive \
                     identity"
                        .to_string(),
                ))
            }
        }
    } else if locked_archive_identity.is_some() {
        return Err(ReceiptStoreError::Conflict(
            "retention archive identity ledger changed while the first archive prefix was being \
             copied"
                .to_string(),
        ));
    }
    let locked_archive_content_sha256 =
        super::support::latest_watermark_archive_content_sha256(&tx)?;
    if previous_watermark > 0 {
        match (
            locked_archive_content_sha256.as_deref(),
            previous_archive_content_sha256,
        ) {
            (Some(locked), Some(expected)) if locked == expected => {}
            (Some(locked), Some(expected)) => {
                return Err(ReceiptStoreError::Conflict(format!(
                    "retention archive content digest changed from {expected:?} to {locked:?} \
                     while the archive suffix was being copied"
                )))
            }
            _ => {
                return Err(ReceiptStoreError::Conflict(
                    "retention cannot advance a legacy watermark without a committed canonical \
                     archive content digest"
                        .to_string(),
                ))
            }
        }
    } else if locked_archive_content_sha256.is_some() || previous_archive_content_sha256.is_some() {
        return Err(ReceiptStoreError::Conflict(
            "retention archive content ledger changed while the first archive prefix was being \
             copied"
                .to_string(),
        ));
    }
    let target_watermark = sqlite_u64(w, "locked archive target watermark")?;
    if !super::support::archive_connection_backs_prefix(
        &tx,
        recorded_archive_guard.connection(),
        target_watermark,
    )? {
        return Err(ReceiptStoreError::RetentionArchiveIncomplete {
            table: "claim_receipt_log_entries",
            live: target_watermark,
            archived: 0,
        });
    }
    validate_and_backfill_retention_capability_freezes(
        &tx,
        recorded_archive_guard.connection(),
        w,
        Some((w, sqlite_i64(now, "retention completion timestamp")?)),
    )?;
    verify_co_archival_complete_between_connections(
        &tx,
        recorded_archive_guard.connection(),
        previous_watermark,
        w,
    )?;
    let archived_tool_receipts: i64 = tx.query_row(
        "SELECT COUNT(*) FROM chio_tool_receipts AS receipt \
         WHERE EXISTS ( \
             SELECT 1 FROM claim_receipt_log_entries AS claim \
             WHERE claim.entry_seq <= ?1 AND claim.receipt_kind = 'tool_receipt' \
               AND claim.source_seq = receipt.seq AND claim.receipt_id = receipt.receipt_id \
         )",
        params![w],
        |row| row.get(0),
    )?;
    let iou_envelope_exists = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_master \
         WHERE type = 'table' AND name = 'iou_envelope')",
        [],
        |row| row.get::<_, i64>(0),
    )? != 0;
    if iou_envelope_exists {
        // IOU envelopes are append-only evidence outside retention. Drop only
        // the raw DELETE guard for this verified co-archive operation, then
        // recreate and exact-SQL-validate both immutability guards before any
        // other live evidence is deleted. SQLite DDL is transactional here: a
        // later failure rolls back the IOU delete and restores the original
        // guard atomically.
        tx.execute_batch("DROP TRIGGER IF EXISTS iou_envelope_reject_delete")?;
        tx.execute(
            "DELETE FROM iou_envelope WHERE receipt_id IN ( \
                 SELECT receipt_id FROM claim_receipt_log_entries \
                 WHERE entry_seq <= ?1 AND receipt_kind = 'tool_receipt' \
             )",
            params![w],
        )?;
        crate::iou_store::ensure_iou_immutability_schema(&tx).map_err(|error| {
            ReceiptStoreError::Conflict(format!(
                "retention could not restore the IOU immutability guards: {error}"
            ))
        })?;
    }
    // Preserve the archived-id uniqueness sentinel before deleting any live
    // source row. A pre-existing row is not automatically trustworthy: raw SQL
    // can insert a tombstone after its source already exists, and `OR IGNORE`
    // would otherwise keep a wrong kind or boundary while retention removes the
    // authoritative live receipt. Every tombstone for this advancing suffix must
    // therefore equal the row this transaction just intends to create.
    tx.execute(
        "INSERT OR IGNORE INTO receipt_retention_tombstones \
             (receipt_id, receipt_kind, archived_through_entry_seq, tombstoned_at) \
         SELECT receipt_id, receipt_kind, ?1, ?2 \
         FROM claim_receipt_log_entries WHERE entry_seq <= ?1",
        params![w, sqlite_i64(now, "retention tombstone timestamp")?],
    )?;
    let conflicting_tombstones: i64 = tx.query_row(
        "SELECT COUNT(*) FROM claim_receipt_log_entries e \
         LEFT JOIN receipt_retention_tombstones t ON t.receipt_id = e.receipt_id \
         WHERE e.entry_seq <= ?1 \
           AND (t.receipt_id IS NULL OR t.receipt_kind IS NOT e.receipt_kind \
                OR t.archived_through_entry_seq IS NOT ?1 OR t.tombstoned_at IS NOT ?2)",
        params![w, sqlite_i64(now, "retention tombstone timestamp")?],
        |row| row.get(0),
    )?;
    if conflicting_tombstones != 0 {
        return Err(ReceiptStoreError::Conflict(
            "retention tombstone conflicts with the exact archive suffix being deleted".to_string(),
        ));
    }
    tx.execute_batch(&format!(
        r#"
        DROP TRIGGER IF EXISTS chio_tool_receipts_reject_delete;
        DROP TRIGGER IF EXISTS chio_child_receipts_reject_delete;
        DROP TRIGGER IF EXISTS claim_receipt_log_entries_reject_delete;

        -- `compute_archival_watermark` never advances W past a receipt whose
        -- settlement or metered-billing reconciliation is still nonterminal, so
        -- every reconciliation row removed here has already reached a terminal
        -- state and its co-archived copy preserves the closed record. No live,
        -- actionable reconciliation loses the receipt its upsert path resolves.
        DELETE FROM settlement_reconciliations WHERE receipt_id IN (
            SELECT receipt_id FROM claim_receipt_log_entries
            WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt');
        DELETE FROM metered_billing_reconciliations WHERE receipt_id IN (
            SELECT receipt_id FROM claim_receipt_log_entries
            WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt');
        -- Safe to key this delete on the archived authorization alone:
        -- `compute_archival_watermark` never advances W past an authorization
        -- whose bound consumer is still live, so every consumption removed here
        -- has both its authorization and (when the consumer is a live receipt)
        -- its consumer inside the archived prefix. No live consumer loses its
        -- binding, and the co-archived copy preserves the archived pair.
        DELETE FROM chio_authorization_receipt_consumptions WHERE authorization_receipt_id IN (
            SELECT receipt_id FROM claim_receipt_log_entries
            WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt');
        -- The watermark blocks every unfinished observer row and settlement
        -- retry attempt, so only completed observer tombstones can reach this
        -- prefix. Remove those tombstones in the same transaction as the live
        -- receipt; no actionable delivery or retry can lose authoritative lookup.
        DELETE FROM chio_settlement_observer_outbox
        WHERE state = 'completed'
          AND receipt_id IN (
              SELECT receipt_id FROM claim_receipt_log_entries
              WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt');
        DELETE FROM chio_tool_receipts WHERE seq IN (
            SELECT source_seq FROM claim_receipt_log_entries
            WHERE entry_seq <= {w} AND receipt_kind = 'tool_receipt');
        DELETE FROM chio_child_receipts WHERE seq IN (
            SELECT source_seq FROM claim_receipt_log_entries
            WHERE entry_seq <= {w} AND receipt_kind = 'child_receipt');
        DELETE FROM claim_receipt_log_entries WHERE entry_seq <= {w};
        "#
    ))?;
    insert_receipt_retention_watermark(
        &tx,
        sqlite_u64(w, "watermark entry_seq")?,
        cutoff_unix_secs,
        archive_path,
        archive_identity,
        archive_content_sha256,
        now,
    )?;
    ensure_transparency_projection_guards(&tx)?; // recreate all reject-delete/update guards
    super::bootstrap::open::validate_no_temp_schema_objects(&tx)?;
                                                 // Tests place adversarial archive activity here, after every destructive
                                                 // live statement is staged but while both database writer locks remain
                                                 // held. Any failure below drops `tx`, restoring every live row and guard.
    precommit_boundary()?;
    recorded_archive_guard.validate_binding()?;
    ensure_durable_distinct_archive_path(&tx, archive_path)?;
    tx.commit()?;
    sqlite_u64(archived_tool_receipts, "deleted archived tool receipt count")
}

fn validate_retention_mutation_trigger_allowlist(
    connection: &rusqlite::Connection,
) -> Result<(), ReceiptStoreError> {
    super::bootstrap::open::validate_no_temp_schema_objects(connection)?;
    let mut actual_statement = connection.prepare(
        "SELECT tbl_name, name FROM main.sqlite_master \
         WHERE type = 'trigger' AND tbl_name IN ( \
             'chio_tool_receipts', 'chio_child_receipts', \
             'claim_receipt_log_entries', 'receipt_retention_watermark', \
             'receipt_retention_tombstones', \
             'receipt_retention_capability_freezes', 'capability_lineage', \
             'iou_envelope', \
             'settlement_reconciliations', 'metered_billing_reconciliations', \
             'chio_authorization_receipt_consumptions', \
             'chio_settlement_observer_outbox' \
         ) ORDER BY tbl_name, name",
    )?;
    let actual_rows = actual_statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut actual = Vec::new();
    for row in actual_rows {
        actual.push(row?);
    }

    let mut expected = vec![
        ("chio_child_receipts", "chio_child_receipts_project_claim_log_entry"),
        ("chio_child_receipts", "chio_child_receipts_reject_archived_reuse"),
        ("chio_child_receipts", "chio_child_receipts_reject_delete"),
        ("chio_child_receipts", "chio_child_receipts_reject_update"),
        (
            "chio_settlement_observer_outbox",
            "chio_settlement_observer_outbox_reject_unfinished_delete",
        ),
        (
            "chio_settlement_observer_outbox",
            "chio_settlement_observer_outbox_validate_update",
        ),
        ("chio_tool_receipts", "chio_tool_receipts_project_claim_log_entry"),
        ("chio_tool_receipts", "chio_tool_receipts_reject_archived_reuse"),
        ("chio_tool_receipts", "chio_tool_receipts_reject_delete"),
        ("chio_tool_receipts", "chio_tool_receipts_reject_update"),
        (
            "claim_receipt_log_entries",
            "claim_receipt_log_entries_reject_delete",
        ),
        (
            "claim_receipt_log_entries",
            "claim_receipt_log_entries_reject_update",
        ),
        (
            "receipt_retention_tombstones",
            "receipt_retention_tombstones_reject_delete",
        ),
        (
            "receipt_retention_tombstones",
            "receipt_retention_tombstones_reject_update",
        ),
        (
            "receipt_retention_capability_freezes",
            "receipt_retention_capability_freezes_reject_delete",
        ),
        (
            "receipt_retention_capability_freezes",
            "receipt_retention_capability_freezes_reject_update",
        ),
        (
            "capability_lineage",
            "capability_lineage_reject_archived_insert",
        ),
        (
            "capability_lineage",
            "capability_lineage_reject_archived_update",
        ),
        (
            "capability_lineage",
            "capability_lineage_reject_archived_delete",
        ),
        (
            "receipt_retention_watermark",
            "receipt_retention_watermark_reject_delete",
        ),
        (
            "receipt_retention_watermark",
            "receipt_retention_watermark_reject_regression",
        ),
        (
            "receipt_retention_watermark",
            "receipt_retention_watermark_reject_update",
        ),
    ];
    let iou_exists = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_master \
         WHERE type = 'table' AND name = 'iou_envelope')",
        [],
        |row| row.get::<_, i64>(0),
    )? != 0;
    if iou_exists {
        expected.extend([
            ("iou_envelope", "iou_envelope_reject_delete"),
            ("iou_envelope", "iou_envelope_reject_update"),
            ("iou_envelope", "iou_envelope_require_live_receipt_insert"),
        ]);
    }
    expected.sort_unstable();
    let expected = expected
        .into_iter()
        .map(|(table, name)| (table.to_string(), name.to_string()))
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(ReceiptStoreError::Conflict(
            "retention mutation trigger catalog contains a missing or unexpected trigger"
                .to_string(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RetentionCapabilityLineageAuthority {
    capability_id: String,
    subject_key: String,
    issuer_key: String,
    issued_at: i64,
    expires_at: i64,
    grants_json: String,
    delegation_depth: i64,
    parent_capability_id: Option<String>,
}

/// Reconcile the durable capability freeze ledger against the archive that has
/// already passed identity, content-digest, and prefix-completeness validation.
///
/// The ledger is an exact authority set, not a copy filter. Every distinct tool
/// capability reachable at `archive_watermark` has exactly one freeze row, and
/// no other capability may have one. Its boundary is the first committed
/// retention watermark that covers the capability's first archived claim entry;
/// `frozen_at` is that watermark's `rotated_at`. Rotation supplies its pending
/// watermark because the freeze rows and watermark commit in the same live
/// transaction. Repair supplies no pending watermark and may only bind rows to
/// the already committed ledger.
///
/// Backfill is deliberately last. Before writing any missing freeze, a live
/// lineage row for an archived capability must exactly match the committed
/// archive row. If the committed archive records no lineage, live absence is
/// authoritative. This prevents an upgrade with an empty freeze table from
/// blessing a snapshot inserted after the capability's original archival.
pub(super) fn validate_and_backfill_retention_capability_freezes(
    connection: &rusqlite::Connection,
    archive: &rusqlite::Connection,
    archive_watermark: i64,
    pending_watermark: Option<(i64, i64)>,
) -> Result<(), ReceiptStoreError> {
    if archive_watermark <= 0 {
        return Err(ReceiptStoreError::Conflict(
            "retention capability freeze authority requires a positive archive watermark"
                .to_string(),
        ));
    }

    let mut watermark_statement = connection.prepare(
        "SELECT archived_through_entry_seq, rotated_at \
         FROM receipt_retention_watermark \
         WHERE archived_through_entry_seq <= ?1 \
         ORDER BY archived_through_entry_seq",
    )?;
    let watermark_rows = watermark_statement.query_map(params![archive_watermark], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut watermarks = Vec::new();
    for row in watermark_rows {
        let (boundary, completed_at) = row?;
        if boundary <= 0
            || completed_at < 0
            || watermarks
                .last()
                .is_some_and(|(previous, _)| boundary <= *previous)
        {
            return Err(ReceiptStoreError::Conflict(
                "retention capability freeze authority found an invalid committed watermark"
                    .to_string(),
            ));
        }
        watermarks.push((boundary, completed_at));
    }
    drop(watermark_statement);

    match pending_watermark {
        Some((boundary, completed_at)) => {
            if boundary != archive_watermark
                || completed_at < 0
                || watermarks
                    .last()
                    .is_some_and(|(committed, _)| boundary <= *committed)
            {
                return Err(ReceiptStoreError::Conflict(
                    "pending retention capability freeze boundary is not a strict watermark advance"
                        .to_string(),
                ));
            }
            watermarks.push((boundary, completed_at));
        }
        None => {
            if watermarks.last().map(|(boundary, _)| *boundary) != Some(archive_watermark) {
                return Err(ReceiptStoreError::Conflict(
                    "retention capability freeze authority is not covered by a committed watermark"
                        .to_string(),
                ));
            }
        }
    }

    let mut capability_statement = archive.prepare(
        "SELECT receipt.capability_id, MIN(claim.entry_seq) \
         FROM main.chio_tool_receipts AS receipt \
         INNER JOIN main.claim_receipt_log_entries AS claim \
             ON claim.source_seq = receipt.seq \
            AND claim.receipt_id = receipt.receipt_id \
            AND claim.receipt_kind = 'tool_receipt' \
         WHERE claim.entry_seq <= ?1 \
         GROUP BY receipt.capability_id \
         ORDER BY receipt.capability_id",
    )?;
    let capability_rows = capability_statement.query_map(params![archive_watermark], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut archived_capabilities = Vec::new();
    for row in capability_rows {
        let (capability_id, first_entry_seq) = row?;
        if capability_id.is_empty() || first_entry_seq <= 0 {
            return Err(ReceiptStoreError::Conflict(
                "retention archive contains an invalid capability freeze authority row"
                    .to_string(),
            ));
        }
        archived_capabilities.push((capability_id, first_entry_seq));
    }
    drop(capability_statement);

    let mut expected = std::collections::BTreeMap::new();
    for (capability_id, first_entry_seq) in &archived_capabilities {
        let Some((boundary, completed_at)) = watermarks
            .iter()
            .find(|(boundary, _)| *boundary >= *first_entry_seq)
        else {
            return Err(ReceiptStoreError::Conflict(format!(
                "archived capability {capability_id:?} is not covered by a retention watermark"
            )));
        };
        expected.insert(capability_id.clone(), (*boundary, *completed_at));
    }

    let mut freeze_statement = connection.prepare(
        "SELECT capability_id, archived_through_entry_seq, frozen_at \
         FROM receipt_retention_capability_freezes ORDER BY capability_id",
    )?;
    let freeze_rows = freeze_statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;
    let mut actual = std::collections::BTreeMap::new();
    for row in freeze_rows {
        let (capability_id, boundary, completed_at) = row?;
        if actual
            .insert(capability_id.clone(), (boundary, completed_at))
            .is_some()
            || !expected.contains_key(&capability_id)
        {
            return Err(ReceiptStoreError::Conflict(
                "retention capability freeze ledger contains authority absent from the archive"
                    .to_string(),
            ));
        }
    }
    drop(freeze_statement);

    let mut archive_lineage_statement = archive.prepare(
        "SELECT capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json, \
                delegation_depth, parent_capability_id \
         FROM main.capability_lineage WHERE capability_id = ?1",
    )?;
    let mut live_lineage_statement = connection.prepare(
        "SELECT capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json, \
                delegation_depth, parent_capability_id \
         FROM main.capability_lineage WHERE capability_id = ?1",
    )?;
    for (capability_id, _) in &archived_capabilities {
        let archived = load_retention_capability_lineage_authority(
            &mut archive_lineage_statement,
            capability_id,
        )?;
        let live = load_retention_capability_lineage_authority(
            &mut live_lineage_statement,
            capability_id,
        )?;
        if live.is_some() && live != archived {
            return Err(ReceiptStoreError::Conflict(format!(
                "live capability lineage for archived capability {capability_id:?} is absent or divergent in the committed archive"
            )));
        }
    }
    drop(archive_lineage_statement);
    drop(live_lineage_statement);

    for (capability_id, expected_freeze) in &expected {
        if let Some(actual_freeze) = actual.get(capability_id) {
            if actual_freeze != expected_freeze {
                return Err(ReceiptStoreError::Conflict(format!(
                    "retention capability freeze for {capability_id:?} is not bound to its first committed watermark"
                )));
            }
            continue;
        }
        let inserted = connection.execute(
            "INSERT INTO receipt_retention_capability_freezes \
                 (capability_id, archived_through_entry_seq, frozen_at) \
             VALUES (?1, ?2, ?3)",
            params![capability_id, expected_freeze.0, expected_freeze.1],
        )?;
        if inserted != 1 {
            return Err(ReceiptStoreError::Conflict(format!(
                "retention capability freeze for {capability_id:?} was not recorded"
            )));
        }
    }

    let frozen_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM receipt_retention_capability_freezes",
        [],
        |row| row.get(0),
    )?;
    if usize::try_from(frozen_count).ok() != Some(expected.len()) {
        return Err(ReceiptStoreError::Conflict(
            "retention capability freeze ledger does not exactly match the archive authority set"
                .to_string(),
        ));
    }
    Ok(())
}

fn load_retention_capability_lineage_authority(
    statement: &mut rusqlite::Statement<'_>,
    capability_id: &str,
) -> Result<Option<RetentionCapabilityLineageAuthority>, ReceiptStoreError> {
    statement
        .query_row(params![capability_id], |row| {
            Ok(RetentionCapabilityLineageAuthority {
                capability_id: row.get(0)?,
                subject_key: row.get(1)?,
                issuer_key: row.get(2)?,
                issued_at: row.get(3)?,
                expires_at: row.get(4)?,
                grants_json: row.get(5)?,
                delegation_depth: row.get(6)?,
                parent_capability_id: row.get(7)?,
            })
        })
        .optional()
        .map_err(ReceiptStoreError::from)
}

fn validate_retention_claim_projection_triggers(
    connection: &rusqlite::Connection,
) -> Result<(), ReceiptStoreError> {
    let expected = [
        (
            "chio_tool_receipts_project_claim_log_entry",
            r#"
            CREATE TRIGGER chio_tool_receipts_project_claim_log_entry
            AFTER INSERT ON chio_tool_receipts
            BEGIN
                INSERT INTO claim_receipt_log_entries (
                    receipt_id, receipt_kind, source_seq, timestamp, capability_id,
                    session_id, parent_request_id, request_id, subject_key, issuer_key,
                    tool_server, tool_name, raw_json
                ) VALUES (
                    NEW.receipt_id, 'tool_receipt', NEW.seq, NEW.timestamp,
                    NEW.capability_id, NULL, NULL, NULL, NEW.subject_key, NEW.issuer_key,
                    NEW.tool_server, NEW.tool_name, NEW.raw_json
                );
            END
            "#,
        ),
        (
            "chio_child_receipts_project_claim_log_entry",
            r#"
            CREATE TRIGGER chio_child_receipts_project_claim_log_entry
            AFTER INSERT ON chio_child_receipts
            BEGIN
                INSERT INTO claim_receipt_log_entries (
                    receipt_id, receipt_kind, source_seq, timestamp, capability_id,
                    session_id, parent_request_id, request_id, subject_key, issuer_key,
                    tool_server, tool_name, raw_json
                ) VALUES (
                    NEW.receipt_id, 'child_receipt', NEW.seq, NEW.timestamp,
                    NULL, NEW.session_id, NEW.parent_request_id, NEW.request_id,
                    NULL, NULL, NULL, NULL, NEW.raw_json
                );
            END
            "#,
        ),
    ];
    for (name, expected_sql) in expected {
        let actual = connection
            .query_row(
                "SELECT sql FROM main.sqlite_master WHERE type = 'trigger' AND name = ?1",
                params![name],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                ReceiptStoreError::Conflict(format!(
                    "claim receipt projection trigger {name:?} is missing"
                ))
            })?;
        if normalize_retention_mutation_trigger_sql(&actual)
            != normalize_retention_mutation_trigger_sql(expected_sql)
        {
            return Err(ReceiptStoreError::Conflict(format!(
                "claim receipt projection trigger {name:?} is invalid"
            )));
        }
    }
    Ok(())
}

fn normalize_retention_mutation_trigger_sql(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" IF NOT EXISTS", "")
        .trim_end_matches(';')
        .to_string()
}

fn validate_retention_foreign_key_delete_closure(
    connection: &rusqlite::Connection,
) -> Result<(), ReceiptStoreError> {
    let foreign_keys: i64 = connection.query_row("PRAGMA foreign_keys", [], |row| row.get(0))?;
    if foreign_keys != 1 {
        return Err(ReceiptStoreError::Conflict(
            "retention requires SQLite foreign-key enforcement".to_string(),
        ));
    }

    let deleted_tables = [
        "chio_tool_receipts",
        "chio_child_receipts",
        "claim_receipt_log_entries",
        "receipt_retention_watermark",
        "receipt_retention_tombstones",
        "iou_envelope",
        "settlement_reconciliations",
        "metered_billing_reconciliations",
        "chio_authorization_receipt_consumptions",
        "chio_settlement_observer_outbox",
    ];
    let mut table_statement = connection.prepare(
        "SELECT name FROM main.sqlite_master \
         WHERE type = 'table' AND name NOT GLOB 'sqlite_*' ORDER BY name",
    )?;
    let table_rows = table_statement.query_map([], |row| row.get::<_, String>(0))?;
    let mut tables = Vec::new();
    for table in table_rows {
        tables.push(table?);
    }

    let mut cascading = Vec::new();
    for table in tables {
        let mut statement = connection.prepare(&format!(
            "PRAGMA main.foreign_key_list({})",
            quote_sqlite_identifier(&table)
        ))?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })?;
        for row in rows {
            let (parent, from, to, on_update, on_delete, match_kind) = row?;
            if deleted_tables.contains(&parent.as_str())
                && !matches!(on_delete.as_str(), "NO ACTION" | "RESTRICT")
            {
                cascading.push((
                    table.clone(),
                    parent,
                    from,
                    to,
                    on_update,
                    on_delete,
                    match_kind,
                ));
            }
        }
    }
    cascading.sort();
    let expected = vec![
        (
            "metered_billing_reconciliations".to_string(),
            "chio_tool_receipts".to_string(),
            "receipt_id".to_string(),
            Some("receipt_id".to_string()),
            "NO ACTION".to_string(),
            "CASCADE".to_string(),
            "NONE".to_string(),
        ),
        (
            "settlement_reconciliations".to_string(),
            "chio_tool_receipts".to_string(),
            "receipt_id".to_string(),
            Some("receipt_id".to_string()),
            "NO ACTION".to_string(),
            "CASCADE".to_string(),
            "NONE".to_string(),
        ),
    ];
    if cascading != expected {
        return Err(ReceiptStoreError::Conflict(
            "retention foreign-key delete closure contains an unexpected cascading mutation"
                .to_string(),
        ));
    }
    Ok(())
}
