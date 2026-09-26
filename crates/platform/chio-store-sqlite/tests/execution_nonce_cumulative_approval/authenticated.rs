use super::*;
use chio_kernel::{
    CallerExecutionReport, CallerStartCredentials, CallerStartResponse, ToolCallOutput,
};
use chio_store_sqlite::caller_execution_ledger::SqliteCallerExecutionLedger;

#[test]
fn authenticated_caller_retains_cumulative_approval_and_settles_historical_cost() -> TestResult {
    let mut fixture = nonce_fixture(30)?;
    let key = Keypair::generate();
    let executor = chio_kernel::caller_delivery::CallerExecutorIdentityV1 {
        executor_id: chio_kernel::admission_operation::AdmissionIdentifier::try_new(
            "executor_id",
            "cumulative-executor",
        )?,
        public_key: key.public_key(),
        key_epoch: 9,
    };
    fixture.caller_executor = Some(executor.clone());
    let ledger = SqliteCallerExecutionLedger::provision(
        &fixture.directory.path().join("executor.db"),
        executor,
        4,
    )?;
    let (request, authorization, report) = {
        let runtime = fixture.open()?;
        let request = fixture.request(&runtime, "authenticated-cumulative")?;
        let nonce = preflight(&runtime, &request)?;
        let mut request = with_nonce(&request, &nonce);
        let parked = runtime.kernel.reserve_caller_execution_blocking(&request)?;
        assert_eq!(
            parked.verdict,
            Verdict::PendingApproval,
            "{:?}",
            parked.reason
        );
        let Some(ToolCallOutput::Value(value)) = parked.output else {
            return Err("proposal output".into());
        };
        let proposal = serde_json::from_value(value)?;
        approve(&fixture, &runtime, &mut request, &proposal)?;
        let reserved = runtime.kernel.reserve_caller_execution_blocking(&request)?;
        assert_eq!(reserved.verdict, Verdict::Allow, "{:?}", reserved.reason);
        assert_state(&fixture, &request, "ready_to_dispatch")?;
        let nonce = reserved.execution_nonce.ok_or("nonce")?;
        let connection = rusqlite::Connection::open(fixture.directory.path().join("admission.db"))?;
        let budget_events = || -> TestResult<i64> {
            Ok(
                connection.query_row("SELECT COUNT(*) FROM budget_mutation_events", [], |row| {
                    row.get(0)
                })?,
            )
        };
        let before = budget_events()?;
        let duplicate = runtime.kernel.reserve_caller_execution_blocking(&request)?;
        assert_eq!(duplicate.verdict, Verdict::Allow, "{:?}", duplicate.reason);
        assert_eq!(duplicate.execution_nonce.as_deref(), Some(nonce.as_ref()));
        assert_eq!(
            budget_events()?,
            before,
            "approved reservation replay must not create another budget event"
        );
        let authorization = match runtime
            .kernel
            .start_caller_execution_with_credentials_blocking(
                &nonce,
                &request.arguments,
                CallerStartCredentials {
                    approval_tokens: request.approval_tokens.clone(),
                    threshold_approval_proposal: request.threshold_approval_proposal.clone(),
                    ..Default::default()
                },
            )? {
            CallerStartResponse::Authorized(authorization) => *authorization,
            CallerStartResponse::Denied(response) => {
                return Err(format!("{:?}", response.reason).into())
            }
        };
        let report = ledger.execute_once(
            &authorization,
            &fixture.signer.public_key(),
            &authorization.authorization.invocation,
            &key,
            || {
                Ok(CallerExecutionReport {
                    output: serde_json::json!({"external": true}),
                    realized_cost: Some(chio_kernel::ToolInvocationCost {
                        units: 75,
                        currency: "USD".into(),
                        breakdown: None,
                    }),
                })
            },
        )?;
        assert_state(&fixture, &request, "dispatch_committed")?;
        (request, authorization, report)
    };
    let _clock =
        chio_kernel::scope_fixed_runtime_for_current_thread(request.capability.expires_at + 1, []);
    let runtime = fixture.open()?;
    assert_state(&fixture, &request, "awaiting_caller_report")?;
    let response = runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_state(&fixture, &request, "completed")?;
    let replay = runtime
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(canonical(&response.receipt)?, canonical(&replay.receipt)?);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
