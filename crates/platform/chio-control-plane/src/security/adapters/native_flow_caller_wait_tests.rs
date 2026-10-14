// A genuine pending native caller report exercises the scoped shared decision.
use super::*;

#[test]
fn scoped_original_decision_waits_for_the_authenticated_native_caller_report() -> TestResult {
    exercise_scoped_wait(false)
}

#[test]
fn scoped_original_decision_retains_late_authenticated_report_without_renewal() -> TestResult {
    exercise_scoped_wait(true)
}

fn exercise_scoped_wait(expire: bool) -> TestResult {
    let mut fixture = Fixture::new(std::array::from_fn(|_| InformationLabel::bottom()))?;
    let legacy = super::super::nonce::execution::configure(&mut fixture, false)?;
    let executor_key = Keypair::generate();
    let executor = CallerExecutorIdentityV1 {
        executor_id: AdmissionIdentifier::try_new("executor_id", "native-scoped-caller-wait")?,
        public_key: executor_key.public_key(),
        key_epoch: 41,
    };
    fixture.kernel.set_caller_executor(executor.clone())?;
    let ledger = SqliteCallerExecutionLedger::provision(
        &fixture._directory.path().join("executor.db"),
        executor,
        4,
    )?;
    let operation_id = super::super::nonce::execution::issue(&mut fixture)?;
    let reserved = fixture
        .kernel
        .reserve_caller_execution_blocking_with_security_context(
            &fixture.request,
            &fixture.context,
        )?;
    assert_eq!(reserved.verdict, Verdict::Allow, "{:?}", reserved.reason);
    let nonce = reserved.execution_nonce.ok_or("reserved caller nonce")?;
    let authorization = match fixture
        .kernel
        .start_caller_execution_blocking_with_security_context(
            &nonce,
            &fixture.request.arguments,
            start_credentials(&fixture),
            &fixture.context,
        )? {
        CallerStartResponse::Authorized(authorization) => *authorization,
        CallerStartResponse::Denied(response) => {
            return Err(format!("native caller start denied: {:?}", response.reason).into())
        }
    };
    assert_eq!(
        authorization.authorization.invocation.operation_id,
        operation_id
    );
    let effects = AtomicUsize::new(0);
    let report = ledger.execute_once(
        &authorization,
        &fixture.signer.public_key(),
        &authorization.authorization.invocation,
        &executor_key,
        || {
            effects.fetch_add(1, Ordering::SeqCst);
            Ok(CallerExecutionReport {
                output: serde_json::json!({"native_waited_effect":true}),
                realized_cost: None,
            })
        },
    )?;
    let before = fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(&operation_id)?
        .ok_or("captured native caller operation")?;
    assert_eq!(before.state(), AdmissionOperationState::DispatchCommitted);
    assert!(before.native_dispatch_ledger_digest().is_some());
    assert!(before.caller_dispatch_context_digest().is_some());
    assert_captured_quota(&fixture)?;
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(legacy.load(Ordering::SeqCst), 0);
    let until = fixture
        .request
        .capability
        .expires_at
        .max(u64::try_from(nonce.expires_at())?);
    let expired_now = until.checked_add(1).ok_or("caller expiry overflow")?;
    let _clock =
        expire.then(|| chio_kernel::scope_fixed_runtime_clock_for_current_thread(expired_now));
    if expire {
        assert_eq!(
            chio_kernel::fixed_runtime_unix_secs_for_current_thread(),
            Some(expired_now)
        );
        assert!(expired_now > fixture.request.capability.expires_at);
        assert!(expired_now > u64::try_from(nonce.expires_at())?);
        assert!(expired_now > authorization.authorization.expires_at_unix_ms / 1_000);
    }
    // The feature bridge has current fenced custody and the same per-operation
    // owner as the scoped continuation. It creates no synthetic recovery WF.
    assert_eq!(
        fixture
            .kernel
            .reconcile_scoped_caller_wait_for_test(&operation_id)?,
        AdmissionOperationState::AwaitingCallerReport,
        "a native caller with authenticated pending report became unknown",
    );
    let completed = fixture
        .kernel
        .reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(completed.verdict, Verdict::Allow, "{:?}", completed.reason);
    assert!(completed.receipt.verify_signature()?);
    assert!(
        matches!(&completed.output, Some(chio_kernel::ToolCallOutput::Value(value)) if value == &report.report.output)
    );
    let after = fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(&operation_id)?
        .ok_or("completed native caller operation")?;
    assert_eq!(after.state(), AdmissionOperationState::Completed);
    assert_eq!(after.binding(), before.binding());
    assert_eq!(
        after.native_dispatch_ledger_digest(),
        before.native_dispatch_ledger_digest()
    );
    assert_eq!(
        after.caller_dispatch_context_digest(),
        before.caller_dispatch_context_digest()
    );
    assert_captured_quota(&fixture)?;
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(legacy.load(Ordering::SeqCst), 0);
    Ok(())
}
