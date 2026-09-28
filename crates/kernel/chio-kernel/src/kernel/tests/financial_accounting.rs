use super::*;

#[test]
fn signed_receipts_preserve_uncapped_and_full_width_grant_ceilings() {
    for ceiling in [None, Some(u64::MAX), Some(1_000)] {
        let mut kernel = make_kernel(make_monetary_config());
        kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
        let agent = Keypair::generate();
        let mut grant = make_monetary_grant("cost-srv", "compute", 100, 1_000, "USD");
        grant.max_total_cost = ceiling.map(|units| MonetaryAmount {
            units,
            currency: "USD".into(),
        });
        let cap = kernel
            .issue_capability(&agent.public_key(), make_scope(vec![grant]), 3600)
            .unwrap();
        for invocation in 1..=3 {
            let response = kernel
                .evaluate_tool_call_blocking(&make_request(
                    &format!("receipt-{invocation}"),
                    &cap,
                    "compute",
                    "cost-srv",
                ))
                .unwrap();
            assert_eq!(response.verdict, Verdict::Allow);
            assert!(response.receipt.verify_signature().unwrap());
            let financial: FinancialReceiptMetadata = serde_json::from_value(
                response.receipt.metadata.as_ref().unwrap()["financial"].clone(),
            )
            .unwrap();
            assert_eq!(financial.budget_total, ceiling);
            assert_eq!(
                financial.budget_remaining,
                ceiling.map(|value| value - invocation * 75)
            );
        }
    }
}

#[test]
fn denial_receipt_reports_the_committed_balance_not_the_original_ceiling() {
    let mut kernel = make_kernel(make_monetary_config());
    kernel.register_tool_server(Box::new(MonetaryCostServer::new("cost-srv", 75, "USD")));
    let agent = Keypair::generate();
    let grant = make_monetary_grant("cost-srv", "compute", 100, 150, "USD");
    let cap = kernel
        .issue_capability(&agent.public_key(), make_scope(vec![grant]), 3600)
        .unwrap();
    let allowed = kernel
        .evaluate_tool_call_blocking(&make_request("first", &cap, "compute", "cost-srv"))
        .unwrap();
    assert_eq!(allowed.verdict, Verdict::Allow);
    let denied = kernel
        .evaluate_tool_call_blocking(&make_request("second", &cap, "compute", "cost-srv"))
        .unwrap();
    assert_eq!(denied.verdict, Verdict::Deny);
    assert!(denied.receipt.verify_signature().unwrap());
    let financial = &denied.receipt.metadata.as_ref().unwrap()["financial"];
    assert_eq!(financial["budget_remaining"], serde_json::json!(75));
    assert_eq!(financial["cost_charged"], serde_json::json!(0));
}
