//! Real runtime participant custody through committed caller start and signed
//! historical return. Executor process-loss is covered in the SQLite suite.
use super::*;
use chio_kernel::caller_delivery::{
    CallerDeliveryReportBodyV1, CallerExecutorIdentityV1, SignedCallerDeliveryReportV1,
    CALLER_DELIVERY_REPORT_SCHEMA,
};

#[test]
fn authenticated_caller_report_uses_original_runtime_claim_after_lease_expiry() -> TestResult {
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, []);
    let fixture = Fixture::new(true)?;
    let signer = Keypair::generate();
    let executor_key = Keypair::generate();
    let executor = CallerExecutorIdentityV1 {
        executor_id: AdmissionIdentifier::try_new("executor_id", "runtime-executor")?,
        public_key: executor_key.public_key(),
        key_epoch: 13,
    };
    let mut kernel = fixture.kernel_with_key(fixture.hook()?, true, false, signer.clone())?;
    nonce_config(&mut kernel);
    kernel.set_caller_executor(executor.clone())?;
    let reserved = kernel.reserve_caller_execution_blocking(&fixture.request)?;
    assert_eq!(reserved.verdict, Verdict::Allow, "{:?}", reserved.reason);
    let nonce = reserved.execution_nonce.ok_or("nonce")?;
    let authorization =
        match kernel.start_caller_execution_blocking(&nonce, &fixture.request.arguments)? {
            chio_kernel::CallerStartResponse::Authorized(authorization) => *authorization,
            chio_kernel::CallerStartResponse::Denied(response) => {
                return Err(format!("{:?}", response.reason).into())
            }
        };
    let store = fixture.authority.admission_operation_store();
    let id = &authorization.authorization.invocation.operation_id;
    let (_, history) = store
        .load_runtime_participant_history(id, &fixture.authority.mutation_fence(), NOW)?
        .ok_or("runtime custody")?;
    assert_eq!(history.len(), 2);
    assert_eq!(
        history[0].disposition,
        RuntimeParticipantDisposition::ReleasedBeforeDispatch
    );
    assert_eq!(
        history[1].disposition,
        RuntimeParticipantDisposition::RetainedAfterDispatchCommit
    );
    let report = SignedCallerDeliveryReportV1::sign(
        CallerDeliveryReportBodyV1 {
            schema: CALLER_DELIVERY_REPORT_SCHEMA.into(),
            authorization_digest: authorization.verify_historical(
                &signer.public_key(),
                &executor,
                &authorization.authorization.invocation,
            )?,
            executor: executor.clone(),
            claim_id: AdmissionIdentifier::try_new("claim_id", "runtime-custody-test")?,
            execution_started_at_unix_ms: NOW,
            completed_at_unix_ms: NOW,
            output: serde_json::json!({"historical": true}),
            realized_cost: None,
        },
        &executor_key,
    )?;
    drop(store);
    drop(kernel);
    let Fixture {
        _directory,
        authority,
        source,
        binding,
        request,
        invocations,
    } = fixture;
    drop(authority);
    drop(source);
    let authority = SqliteAuthorityStore::open_serving(
        _directory.path().join("authority.sqlite3"),
        _directory.path().join("locks"),
    )?;
    let source = SqliteRuntimeOrchestrationStore::open(_directory.path().join("runtime.sqlite3"))?;
    let fixture = Fixture {
        _directory,
        authority,
        source,
        binding,
        request,
        invocations,
    };
    let mut kernel = fixture.kernel_with_key(fixture.hook()?, true, false, signer)?;
    nonce_config(&mut kernel);
    kernel.set_caller_executor(executor)?;
    let observed = fixture.request.capability.expires_at + 1;
    let _late = chio_kernel::scope_fixed_runtime_for_current_thread(observed, []);
    kernel.reconcile_durable_admission_startup()?;
    let completed =
        kernel.reconcile_authenticated_caller_execution_blocking(&authorization, &report)?;
    assert_eq!(completed.verdict, Verdict::Allow, "{:?}", completed.reason);
    assert_eq!(
        fixture
            .authority
            .admission_operation_store()
            .load_runtime_participant_history(
                id,
                &fixture.authority.mutation_fence(),
                observed * 1000,
            )?
            .ok_or("retained history")?
            .1,
        history
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
