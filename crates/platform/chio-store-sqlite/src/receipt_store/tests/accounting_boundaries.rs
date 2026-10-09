//! Full-domain accounting through signed receipts and public report queries.
use super::support::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn cost_attribution_refuses_charged_and_attempted_overflow() -> TestResult {
    for attempted in [false, true] {
        let (_directory, path) = temp_db("attribution-overflow")?;
        let store = SqliteReceiptStore::open(&path)?;
        let key = receipt_test_keypair();
        let query = CostAttributionQuery {
            read_context: Some(ReceiptReadContext::local_operator_admin_all()),
            ..CostAttributionQuery::default()
        };
        for (index, amount) in [u64::MAX, 1].into_iter().enumerate() {
            let receipt = sample_financial_receipt(&format!("cost-{index}"), amount)?;
            let mut body = receipt.body();
            if attempted {
                let metadata = body.metadata.as_mut().ok_or("financial metadata missing")?;
                metadata["financial"]["cost_charged"] = serde_json::json!(0);
                metadata["financial"]["attempted_cost"] = serde_json::json!(amount);
            }
            let signed = ChioReceipt::sign(body, &key)?;
            store.append_chio_receipt_returning_seq(&signed)?;
            if index == 0 {
                let report = store.query_cost_attribution_report(&query)?;
                assert_eq!(
                    if attempted {
                        report.summary.total_attempted_cost
                    } else {
                        report.summary.total_cost_charged
                    },
                    u64::MAX
                );
            }
        }
        let field = if attempted {
            "attempted-cost"
        } else {
            "charged-cost"
        };
        let expected = format!("cost attribution {field} total exceeds the reportable u64 range");
        assert!(matches!(
            store.query_cost_attribution_report(&query),
            Err(ReceiptStoreError::ReadBoundary(message)) if message == expected
        ));
        // A report failure must leave both original signed receipts intact.
        assert_eq!(store.tool_receipt_count()?, 2);
    }
    Ok(())
}

#[test]
fn underwriting_refuses_premium_overflow_within_one_currency() -> TestResult {
    let (_directory, path) = temp_db("premium-overflow")?;
    let store = SqliteReceiptStore::open(&path)?;
    // Each persisted INTEGER is representable; their report total is not.
    let largest_stored = i64::MAX as u64;
    for (index, units) in [largest_stored, largest_stored, 2].into_iter().enumerate() {
        let decision = signed_underwriting_decision_fixture(
            "premium-subject",
            &format!("premium-{index}"),
            1_700_000_100 + index as u64,
            chio_kernel::UnderwritingDecisionOutcome::ReduceCeiling,
            chio_kernel::UnderwritingReviewState::Approved,
            chio_kernel::UnderwritingDecisionLifecycleState::Active,
            None,
            Some(usd(units)),
        );
        store.record_underwriting_decision(&decision)?;
        if index == 0 {
            assert_eq!(
                store
                    .query_underwriting_decisions(&UnderwritingDecisionQuery::default())?
                    .summary
                    .total_quoted_premium_units,
                largest_stored
            );
        }
    }
    assert!(matches!(
        store.query_underwriting_decisions(&UnderwritingDecisionQuery::default()),
        Err(ReceiptStoreError::ReadBoundary(message))
            if message == "underwriting quoted-premium total exceeds the reportable u64 range"
    ));
    Ok(())
}

#[test]
fn cost_attribution_propagates_corrupt_lineage_instead_of_reporting_a_gap() -> TestResult {
    let (_directory, path) = temp_db("attribution-lineage-corruption")?;
    let store = SqliteReceiptStore::open(&path)?;
    store.append_chio_receipt(&sample_financial_receipt("lineage-corrupt", 11)?)?;
    let external = rusqlite::Connection::open(&path)?;
    external.execute(
        "INSERT INTO capability_lineage
         (capability_id, subject_key, issuer_key, issued_at, expires_at, grants_json,
          delegation_depth, parent_capability_id, provenance)
         VALUES ('cap-cost', 'leaf', 'issuer', 1, 100, '{}', 0, 'cap-cost', 'legacy_projection')",
        [],
    )?;
    assert!(store.get_combined_delegation_chain("cap-cost").is_err());
    let result = store.query_cost_attribution_report(&CostAttributionQuery {
        read_context: Some(ReceiptReadContext::local_operator_admin_all()),
        ..CostAttributionQuery::default()
    });
    assert!(
        matches!(result, Err(ReceiptStoreError::Conflict(_))),
        "{result:?}"
    );
    Ok(())
}

#[test]
fn reports_refuse_an_oversized_signed_row_even_with_one_returned_receipt() -> TestResult {
    let (_directory, path) = temp_db("attribution-large-row")?;
    let store = SqliteReceiptStore::open(&path)?;
    let mut body = sample_financial_receipt("large-row", 11)?.body();
    body.action = ToolCallAction::from_parameters(serde_json::json!({
        "payload": "x".repeat(9 * 1024 * 1024),
    }))?;
    store.append_chio_receipt(&ChioReceipt::sign(body, &receipt_test_keypair())?)?;
    let context = ReceiptReadContext::local_operator_admin_all();
    let attribution = store.query_cost_attribution_report(&CostAttributionQuery {
        limit: Some(1),
        read_context: Some(context.clone()),
        ..CostAttributionQuery::default()
    });
    assert!(
        matches!(attribution, Err(ReceiptStoreError::ReadBoundary(_))),
        "oversized attribution succeeded"
    );
    let analytics = store.query_receipt_analytics(&ReceiptAnalyticsQuery {
        read_context: Some(context),
        ..ReceiptAnalyticsQuery::default()
    });
    assert!(
        matches!(analytics, Err(ReceiptStoreError::ReadBoundary(_))),
        "oversized analytics succeeded"
    );
    Ok(())
}

fn utf8_record_bytes(connection: &rusqlite::Connection, seq: u64) -> rusqlite::Result<usize> {
    connection.query_row(
        "SELECT * FROM chio_tool_receipts WHERE seq = ?1",
        [i64::try_from(seq).test_unwrap()],
        |row| {
            let mut total = 0_usize;
            for column in 0..row.as_ref().column_count() {
                if let rusqlite::types::ValueRef::Text(bytes)
                | rusqlite::types::ValueRef::Blob(bytes) = row.get_ref(column)?
                {
                    total = total
                        .checked_add(bytes.len())
                        .test_expect("small fixture record");
                }
            }
            Ok(total)
        },
    )
}

#[test]
fn utf16_public_reports_check_actual_utf8_record_bytes_at_exact_and_one_over_bound() -> TestResult {
    const BOUND: usize = 8 * 1024 * 1024;
    for encoding in ["UTF-16le", "UTF-16be"] {
        let (_directory, path) = temp_db("utf16-report-byte-bound")?;
        let external = rusqlite::Connection::open(&path)?;
        // Persist the encoding, then leave an empty database for the public
        // constructor to provision and stamp with the required store identity.
        external.execute_batch(&format!(
            "PRAGMA encoding='{encoding}';
             CREATE TABLE encoding_anchor (value TEXT);
             DROP TABLE encoding_anchor;"
        ))?;
        let user_tables: i64 = external.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(user_tables, 0);
        let store = SqliteReceiptStore::open(&path)?;
        let application_id: i32 =
            external.pragma_query_value(None, "application_id", |row| row.get(0))?;
        assert_eq!(application_id, crate::CHIO_SQLITE_APPLICATION_ID);
        let actual_encoding: String =
            external.pragma_query_value(None, "encoding", |row| row.get(0))?;
        assert_eq!(actual_encoding, encoding);
        let mut body = sample_financial_receipt("utf16-empty-payload", 11)?.body();
        body.action = ToolCallAction::from_parameters(serde_json::json!({"payload": ""}))?;
        let base = ChioReceipt::sign(body.clone(), &receipt_test_keypair())?;
        let base_seq = store.append_chio_receipt_returning_seq(&base)?;
        let overhead = utf8_record_bytes(&external, base_seq)?;
        let payload_bytes = BOUND
            .checked_sub(overhead)
            .test_expect("fixture overhead below limit");
        let mut payload = "中".repeat(payload_bytes / 3);
        payload.push_str(&"x".repeat(payload_bytes % 3));
        body.action = ToolCallAction::from_parameters(serde_json::json!({"payload": &payload}))?;
        let exact = ChioReceipt::sign(body.clone(), &receipt_test_keypair())?;
        let exact_seq = store.append_chio_receipt_returning_seq(&exact)?;
        assert_eq!(utf8_record_bytes(&external, exact_seq)?, BOUND);
        let context = ReceiptReadContext::local_operator_admin_all();
        let analytics_query = ReceiptAnalyticsQuery {
            read_context: Some(context.clone()),
            ..ReceiptAnalyticsQuery::default()
        };
        let attribution_query = CostAttributionQuery {
            limit: Some(1),
            read_context: Some(context),
            ..CostAttributionQuery::default()
        };
        assert_eq!(
            store
                .query_receipt_analytics(&analytics_query)?
                .summary
                .total_cost_charged,
            22
        );
        assert_eq!(
            store
                .query_cost_attribution_report(&attribution_query)?
                .summary
                .total_cost_charged,
            22
        );
        payload.push('x');
        body.action = ToolCallAction::from_parameters(serde_json::json!({"payload": &payload}))?;
        let over = ChioReceipt::sign(body, &receipt_test_keypair())?;
        let over_seq = store.append_chio_receipt_returning_seq(&over)?;
        assert_eq!(utf8_record_bytes(&external, over_seq)?, BOUND + 1);
        let encoded: i64 = external.query_row(
            "SELECT octet_length(raw_json) FROM chio_tool_receipts WHERE seq = ?1",
            [i64::try_from(over_seq)?],
            |row| row.get(0),
        )?;
        assert!(
            usize::try_from(encoded)? < BOUND,
            "UTF-16 metadata must undercount this CJK UTF-8 payload"
        );
        assert!(
            matches!(store.query_receipt_analytics(&analytics_query), Err(ReceiptStoreError::ReadBoundary(reason)) if reason.contains("raw record byte limit"))
        );
        assert!(
            matches!(store.query_cost_attribution_report(&attribution_query), Err(ReceiptStoreError::ReadBoundary(reason)) if reason.contains("raw record byte limit"))
        );
    }
    Ok(())
}
