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
    let mut store = SqliteReceiptStore::open(&path)?;
    for (index, units) in [u64::MAX, 1].into_iter().enumerate() {
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
                u64::MAX
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
