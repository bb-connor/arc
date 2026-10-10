// Settlement reconciliation report query.

use super::*;

impl SqliteReceiptStore {
    pub fn query_settlement_reconciliation_report(
        &self,
        query: &OperatorReportQuery,
    ) -> Result<SettlementReconciliationReport, ReceiptStoreError> {
        require_admin_receipt_read_context(
            query.read_context.as_ref(),
            "settlement reconciliation report",
        )?;
        let capability_id = query.capability_id.as_deref();
        let tool_server = query.tool_server.as_deref();
        let tool_name = query.tool_name.as_deref();
        let since = query
            .since
            .map(crate::integer::checked::<_, i64>)
            .transpose()?;
        let until = query
            .until
            .map(crate::integer::checked::<_, i64>)
            .transpose()?;
        let agent_subject = query.agent_subject.as_deref();
        let row_limit = query.settlement_limit_or_default();

        let summary_sql = r#"
            SELECT
                COUNT(*) AS matching_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN json_extract(r.raw_json, '$.metadata.financial.settlement_status') = 'pending' THEN 1
                        ELSE 0
                    END
                ), 0) AS pending_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN json_extract(r.raw_json, '$.metadata.financial.settlement_status') = 'failed' THEN 1
                        ELSE 0
                    END
                ), 0) AS failed_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(sr.reconciliation_state, 'open') NOT IN ('reconciled', 'ignored') THEN 1
                        ELSE 0
                    END
                ), 0) AS actionable_receipts,
                COALESCE(SUM(
                    CASE
                        WHEN COALESCE(sr.reconciliation_state, 'open') = 'reconciled' THEN 1
                        ELSE 0
                    END
                ), 0) AS reconciled_receipts
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            LEFT JOIN settlement_reconciliations sr ON r.receipt_id = sr.receipt_id
            WHERE json_extract(r.raw_json, '$.metadata.financial.settlement_status') IN ('pending', 'failed')
              AND (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
        "#;

        let (
            matching_receipts,
            pending_receipts,
            failed_receipts,
            actionable_receipts,
            reconciled_receipts,
        ) = self.connection()?.query_row(
            summary_sql,
            params![
                capability_id,
                tool_server,
                tool_name,
                since,
                until,
                agent_subject
            ],
            |row| {
                Ok((
                    u64::try_from(row.get::<_, i64>(0)?.max(0)).unwrap_or_default(),
                    u64::try_from(row.get::<_, i64>(1)?.max(0)).unwrap_or_default(),
                    u64::try_from(row.get::<_, i64>(2)?.max(0)).unwrap_or_default(),
                    u64::try_from(row.get::<_, i64>(3)?.max(0)).unwrap_or_default(),
                    u64::try_from(row.get::<_, i64>(4)?.max(0)).unwrap_or_default(),
                ))
            },
        )?;

        let rows_sql = r#"
            SELECT
                r.seq,
                r.receipt_id,
                r.timestamp,
                r.capability_id,
                COALESCE(r.subject_key, cl.subject_key),
                r.tool_server,
                r.tool_name,
                json_extract(r.raw_json, '$.metadata.financial.payment_reference'),
                json_extract(r.raw_json, '$.metadata.financial.settlement_status'),
                CAST(json_extract(r.raw_json, '$.metadata.financial.cost_charged') AS INTEGER),
                json_extract(r.raw_json, '$.metadata.financial.currency'),
                COALESCE(sr.reconciliation_state, 'open'),
                sr.note,
                sr.updated_at,
                r.raw_json
            FROM chio_tool_receipts r
            LEFT JOIN capability_lineage cl ON r.capability_id = cl.capability_id
            LEFT JOIN settlement_reconciliations sr ON r.receipt_id = sr.receipt_id
            WHERE json_extract(r.raw_json, '$.metadata.financial.settlement_status') IN ('pending', 'failed')
              AND (?1 IS NULL OR r.capability_id = ?1)
              AND (?2 IS NULL OR r.tool_server = ?2)
              AND (?3 IS NULL OR r.tool_name = ?3)
              AND (?4 IS NULL OR r.timestamp >= ?4)
              AND (?5 IS NULL OR r.timestamp <= ?5)
              AND (?6 IS NULL OR COALESCE(r.subject_key, cl.subject_key) = ?6)
            ORDER BY r.timestamp DESC, r.seq DESC
            LIMIT ?7
        "#;

        let connection = self.connection()?;
        let mut stmt = connection.prepare(rows_sql)?;
        let rows = stmt.query_map(
            params![
                capability_id,
                tool_server,
                tool_name,
                since,
                until,
                agent_subject,
                crate::integer::checked::<_, i64>(row_limit)?
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, Option<String>>(12)?,
                    row.get::<_, Option<i64>>(13)?,
                    row.get::<_, String>(14)?,
                ))
            },
        )?;

        let mut receipts = Vec::new();
        for row in rows {
            let (
                seq,
                receipt_id,
                timestamp,
                capability_id,
                subject_key,
                tool_server,
                tool_name,
                payment_reference,
                settlement_status_text,
                cost_charged,
                currency,
                reconciliation_state_text,
                note,
                updated_at,
                raw_json,
            ) = row?;
            let receipt = decode_verified_chio_receipt(
                &raw_json,
                "persisted tool receipt",
                Some(u64::try_from(seq.max(0)).unwrap_or_default()),
            )?;
            let settlement_status = parse_settlement_status(&settlement_status_text)?;
            let reconciliation_state =
                parse_settlement_reconciliation_state(&reconciliation_state_text)?;
            let action_required = settlement_reconciliation_action_required(
                settlement_status.clone(),
                reconciliation_state,
            );
            receipts.push(SettlementReconciliationRow {
                receipt_id,
                timestamp: u64::try_from(timestamp.max(0)).unwrap_or_default(),
                capability_id,
                subject_key,
                tool_server,
                tool_name,
                payment_reference,
                settlement_status,
                cost_charged: cost_charged
                    .map(|value| u64::try_from(value.max(0)).unwrap_or_default()),
                currency,
                budget_authority: receipt.financial_budget_authority_metadata(),
                reconciliation_state,
                action_required,
                note,
                updated_at: updated_at.map(|value| u64::try_from(value.max(0)).unwrap_or_default()),
            });
        }

        Ok(SettlementReconciliationReport {
            summary: SettlementReconciliationSummary {
                matching_receipts,
                returned_receipts: crate::integer::count(receipts.len()),
                pending_receipts,
                failed_receipts,
                actionable_receipts,
                reconciled_receipts,
                truncated: matching_receipts > crate::integer::count(receipts.len()),
            },
            receipts,
        })
    }
}
