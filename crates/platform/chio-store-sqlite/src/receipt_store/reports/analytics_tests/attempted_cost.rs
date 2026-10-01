use super::*;

fn attempted_receipt(capability: &str, amount: Option<u64>) -> FixtureReceipt {
    FixtureReceipt {
        capability_id: capability.to_owned(),
        subject_key: "attempted-agent",
        tool_server: "shell",
        tool_name: "bash",
        decision: decision_for(1),
        timestamp: DAY_SECS,
        financial: Some((0, amount)),
    }
}

#[test]
fn attempted_cost_is_exact_across_unsigned_boundaries_and_dimensions() {
    let values = [0, (1 << 53) + 1, i64::MAX as u64, 1 << 63, u64::MAX];
    let receipts = values
        .iter()
        .enumerate()
        .map(|(index, amount)| attempted_receipt(&format!("cap-{index}"), Some(*amount)))
        .collect();
    let fixture = populate("chio-attempted-boundaries", receipts);
    for (index, expected) in values.into_iter().enumerate() {
        let report = fixture
            .store
            .query_receipt_analytics(&ReceiptAnalyticsQuery {
                capability_id: Some(format!("cap-{index}")),
                ..admin_query()
            })
            .test_expect("exact attempted cost");
        assert_eq!(report.summary.total_receipts, 1);
        assert_eq!(report.summary.total_attempted_cost, expected);
        assert_eq!(report.by_agent.len(), 1);
        assert_eq!(report.by_tool.len(), 1);
        assert_eq!(report.by_time.len(), 1);
        for metrics in [
            &report.by_agent[0].metrics,
            &report.by_tool[0].metrics,
            &report.by_time[0].metrics,
        ] {
            assert_eq!(metrics, &report.summary);
        }
    }
}

#[test]
fn attempted_cost_total_overflow_is_a_named_refusal() {
    let fixture = populate(
        "chio-attempted-overflow",
        vec![
            attempted_receipt("cap-overflow", Some(u64::MAX)),
            attempted_receipt("cap-overflow", Some(1)),
        ],
    );
    let error = fixture
        .store
        .query_receipt_analytics(&admin_query())
        .test_expect_err("attempted total exceeds u64");
    assert!(matches!(error,
        ReceiptStoreError::Sqlite(rusqlite::Error::UserFunctionError(error))
            if error.to_string() == "receipt analytics attempted-cost total exceeds the reportable range: 18446744073709551616"
    ));
}

#[test]
fn absent_attempted_cost_contributes_zero() {
    let mut absent = attempted_receipt("no-financial", None);
    absent.financial = None;
    let fixture = populate(
        "chio-attempted-absent",
        vec![absent, attempted_receipt("no-attempt", None)],
    );
    let report = fixture
        .store
        .query_receipt_analytics(&admin_query())
        .test_expect("absent financial totals");
    assert_eq!(report.summary.total_receipts, 2);
    assert_eq!(report.summary.total_attempted_cost, 0);
}
