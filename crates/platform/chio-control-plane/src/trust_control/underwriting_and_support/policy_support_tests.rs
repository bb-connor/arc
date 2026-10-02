use super::*;

#[test]
fn capability_budget_report_reads_all_matching_rows_before_display_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let receipts = SqliteReceiptStore::open(directory.path().join("receipts.db"))?;
    let budgets = SqliteBudgetStore::open(directory.path().join("budgets.db"))?;
    for (capability, grant) in [("cap-a", 0), ("cap-a", 1), ("cap-b", 0)] {
        assert!(budgets.try_increment(capability, grant, None)?);
    }
    let query = OperatorReportQuery {
        capability_id: Some("cap-a".to_owned()),
        budget_limit: Some(1),
        ..OperatorReportQuery::default()
    };
    let report = build_budget_utilization_report(&receipts, &budgets, &query)
        .map_err(|response| format!("filtered report status {}", response.status()))?;
    assert_eq!(report.summary.matching_grants, 2);
    assert_eq!(report.summary.total_invocations, 2);
    assert_eq!(report.summary.returned_grants, 1);
    assert!(report.summary.truncated);
    let absent = build_budget_utilization_report(
        &receipts,
        &budgets,
        &OperatorReportQuery {
            capability_id: Some("absent".to_owned()),
            ..query
        },
    )
    .map_err(|response| format!("absent report status {}", response.status()))?;
    assert_eq!(absent.summary.matching_grants, 0);
    Ok(())
}
