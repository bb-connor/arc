use super::*;
use chio_core::capability::scope::{ChioScope, MonetaryAmount, Operation, ToolGrant};
use chio_kernel::{BudgetStore, ToolInvocationCost};
use chio_store_sqlite::caller_execution_ledger::SqliteCallerExecutionLedger;

fn payment(fixture: &Fixture) -> TestResult<(i64, String, i64)> {
    let connection = rusqlite::Connection::open_with_flags(
        fixture.directory.path().join("local-payments.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    Ok(connection.query_row(
        "SELECT COUNT(*), MIN(state), SUM(amount_units) FROM chio_finding_operator_payments",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?)
}

#[test]
fn monetary_exposure_survives_lost_report_and_settles_original_authenticated_cost() -> TestResult {
    let (mut fixture, key) = fixture()?;
    fixture.local_payment_rail = true;
    let ledger = SqliteCallerExecutionLedger::provision(
        &fixture.directory.path().join("executor.db"),
        fixture.caller_executor.clone().ok_or("executor")?,
        4,
    )?;
    let (request, authorization, report) = {
        let runtime = fixture.open()?;
        let mut request = fixture.request(&runtime, "authenticated-monetary")?;
        request.capability = runtime.kernel.issue_capability(
            &fixture.agent.public_key(),
            ChioScope {
                grants: vec![ToolGrant {
                    server_id: SERVER_ID.into(),
                    tool_name: TOOL_NAME.into(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: Some(1),
                    dpop_required: None,
                    max_cost_per_invocation: Some(MonetaryAmount {
                        units: 100,
                        currency: "USD".into(),
                    }),
                    max_total_cost: Some(MonetaryAmount {
                        units: 100,
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
        let authorization = start(&runtime, &request)?;
        assert_eq!(payment(&fixture)?, (1, "held".into(), 100));
        let usage = runtime
            .authority
            .budget_store()
            .get_usage(&request.capability.id, 0)?
            .ok_or("usage")?;
        assert_eq!(
            (usage.total_cost_exposed, usage.total_cost_realized_spend),
            (100, 0)
        );
        let report = ledger.execute_once(
            &authorization,
            &fixture.signer.public_key(),
            &authorization.authorization.invocation,
            &key,
            || {
                Ok(CallerExecutionReport {
                    output: serde_json::json!({"external": true}),
                    realized_cost: Some(ToolInvocationCost {
                        units: 100,
                        currency: "USD".into(),
                        breakdown: None,
                    }),
                })
            },
        )?;
        (request, authorization, report)
    };
    let expires = u64::try_from(
        request
            .execution_nonce
            .as_ref()
            .ok_or("nonce")?
            .expires_at(),
    )?;
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(expires + 1, []);
    let runtime = fixture.open()?;
    assert_state(&fixture, &request, "awaiting_caller_report")?;
    assert_eq!(payment(&fixture)?, (1, "held".into(), 100));
    let usage = runtime
        .authority
        .budget_store()
        .get_usage(&request.capability.id, 0)?
        .ok_or("usage")?;
    assert_eq!(
        (usage.total_cost_exposed, usage.total_cost_realized_spend),
        (100, 0)
    );
    let response = runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    let replay = runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(canonical(&response.receipt)?, canonical(&replay.receipt)?);
    let usage = runtime
        .authority
        .budget_store()
        .get_usage(&request.capability.id, 0)?
        .ok_or("settled usage")?;
    assert_eq!(
        (usage.total_cost_exposed, usage.total_cost_realized_spend),
        (0, 100)
    );
    assert_eq!(grant_quota(&runtime, &request)?, (0, 1));
    assert_eq!(payment(&fixture)?, (1, "captured".into(), 100));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
