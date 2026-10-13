use super::*;

#[test]
fn capability_budget_report_reads_all_matching_rows_before_display_limit(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = chio_test_support::private_tempdir()?;
    let receipts = SqliteReceiptStore::open(directory.path().join("receipts.db"))?;
    let budgets = SqliteBudgetStore::open(directory.path().join("budgets.db"))?;
    for (capability, grant) in [("cap-a", 0), ("cap-a", 1), ("cap-b", 0)] {
        assert!(budgets.authorize_budget_hold(chio_kernel::budget_store::BudgetAuthorizeHoldRequest { capability_id: (capability).to_string(), grant_index: grant, max_invocations: None, invocation_quotas: Vec::new(), cumulative_approval: None, admission_binding: None, requested_exposure_units: 0, max_cost_per_invocation: None, max_total_cost_units: None, hold_id: format!("hold-{capability}-{grant}").to_string(), event_id: format!("hold-{capability}-{grant}:authorize").to_string(), authority: None }).map(|decision| matches!(decision, chio_kernel::budget_store::BudgetAuthorizeHoldDecision::Authorized(_)))?);
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
