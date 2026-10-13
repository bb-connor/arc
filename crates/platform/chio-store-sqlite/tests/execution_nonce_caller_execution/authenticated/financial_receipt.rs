use super::*;
use chio_core::capability::scope::{ChioScope, MonetaryAmount, Operation, ToolGrant};
use chio_kernel::{BudgetStore, FinancialReceiptMetadata, ToolInvocationCost};

#[test]
fn signed_financial_receipts_bind_the_ceiling_and_all_committed_exposure() -> TestResult {
    for (ceiling, other_hold, remaining) in [
        (Some(150), false, Some(110)),
        (Some(150), true, Some(70)),
        (None, false, None),
    ] {
        let (mut fixture, key) = fixture()?;
        fixture.local_payment_rail = true;
        let runtime = fixture.open()?;
        let mut request = fixture.request(&runtime, "financial-receipt")?;
        request.capability = runtime.kernel.issue_capability(
            &fixture.agent.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: SERVER_ID.into(),
                    tool_name: TOOL_NAME.into(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: Some(2),
                    dpop_required: None,
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 40,
                        currency: "USD".into(),
                    }),
                    max_total_cost: ceiling.map(|units| MonetaryAmount {
                        units,
                        currency: "USD".into(),
                    }),
                }],
                ..Default::default()
            },
            600,
        )?;
        let reserved = runtime.kernel.reserve_caller_execution_blocking(&request)?;
        assert_eq!(reserved.verdict, Verdict::Allow, "{:?}", reserved.reason);
        request.execution_nonce = reserved.execution_nonce.map(|nonce| *nonce);
        if other_hold {
            let mut pending = request.clone();
            pending.request_id = "financial-receipt-other-hold".into();
            pending.execution_nonce = None;
            let reserved = runtime.kernel.reserve_caller_execution_blocking(&pending)?;
            assert_eq!(reserved.verdict, Verdict::Allow, "{:?}", reserved.reason);
            assert_state(&fixture, &pending, "ready_to_dispatch")?;
        }
        let authorization = start(&runtime, &request)?;
        let report = ledger(&fixture)?.execute_once(
            &authorization,
            &fixture.signer.public_key(),
            &authorization.authorization.invocation,
            &key,
            || {
                Ok(CallerExecutionReport {
                    output: serde_json::json!({"external": true}),
                    realized_cost: Some(ToolInvocationCost {
                        units: 40,
                        currency: "USD".into(),
                        breakdown: None,
                    }),
                })
            },
        )?;
        let response = runtime
            .kernel
            .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
        assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
        assert!(response.receipt.verify_signature()?);
        let value = response
            .receipt
            .metadata
            .as_ref()
            .ok_or("receipt metadata")?
            .get("financial")
            .ok_or("financial metadata")?;
        let financial: FinancialReceiptMetadata = serde_json::from_value(value.clone())?;
        assert_eq!(financial.cost_charged, 40);
        assert_eq!(financial.budget_total, ceiling);
        assert_eq!(financial.budget_remaining, remaining);
        assert_eq!(
            financial.root_budget_holder,
            request.capability.issuer.to_hex()
        );
        assert_eq!(financial.delegation_depth, 0);
        if ceiling.is_none() {
            assert_eq!(value["budget_total"], serde_json::Value::Null);
            assert_eq!(value["budget_remaining"], serde_json::Value::Null);
        }
        let usage = runtime
            .authority
            .budget_store()
            .get_usage(&request.capability.id, 0)?
            .ok_or("budget usage")?;
        assert_eq!(usage.total_cost_realized_spend, 40);
        assert_eq!(usage.total_cost_exposed, if other_hold { 40 } else { 0 });
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
