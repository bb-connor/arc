//! Recorded native returns settle before current delivery controls apply.
use super::*;

use chio_kernel::tool_outcome::ToolOutcomeStore;

fn original_recorded_raw_custody(
    authority: &SqliteAuthorityStore,
    operation: &chio_kernel::admission_operation::AdmissionOperationV1,
) -> TestResult<Vec<u8>> {
    let outcomes = authority.tool_outcome_store();
    let outcome = outcomes
        .lookup_by_operation(operation.binding().operation_id())?
        .ok_or("original ordinary recorded outcome absent")?;
    outcome.validate_against(operation)?;
    let raw = outcomes
        .load_raw_invocation_by_operation(operation.binding().operation_id())?
        .ok_or("original ordinary recorded raw absent")?;
    let blob = raw.canonical_blob()?;
    outcome.validate_canonical_blob(operation, &blob)?;
    assert_eq!(blob.blob_ref().digest(), outcome.raw_output_digest());
    Ok(blob.bytes().to_vec())
}

fn trace_ordinary_recorded_child(stage: &'static str) {
    if std::env::var("CHIO_RECOVERY_ORDINARY_STAGE_TRACE").as_deref() == Ok("1") {
        eprintln!("{stage}");
    }
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "only the native recorded-return finalization parents start this child"]
async fn known_semantic_recorded_return_child() -> TestResult {
    let path = std::path::PathBuf::from(
        std::env::var_os("CHIO_RECOVERY_CRASH_ROOT").ok_or("semantic child root absent")?,
    );
    trace_ordinary_recorded_child("ordinary recorded child: fixture open enter");
    let f = RecoveryFixture::open(path, None, false)?;
    trace_ordinary_recorded_child("ordinary recorded child: fixture open complete");
    let key = "stopped-recorded-semantic-return";
    trace_ordinary_recorded_child("ordinary recorded child: prepare enter");
    let (runtime, request, profile) = prepare(&f, key, SemanticOutputDispositionV1::ReturnValue)?;
    trace_ordinary_recorded_child("ordinary recorded child: prepare complete");
    assert!(profile.invocation.annotations.as_slice().is_empty());
    assert!(profile.deployment.body().routes.as_slice()[0]
        .annotators
        .as_slice()
        .is_empty());
    std::fs::write(
        f.path.join("known-semantic-recorded-return-request.json"),
        chio_core::canonical_json_bytes(&request)?,
    )?;
    trace_ordinary_recorded_child("ordinary recorded child: request persisted");
    trace_ordinary_recorded_child("ordinary recorded child: execute_step enter");
    let response = runtime
        .execute_step(&f.process, "root", key, &request)
        .await?;
    trace_ordinary_recorded_child("ordinary recorded child: execute_step complete");
    Err(format!(
        "semantic child did not reach the recorded-return cutpoint: verdict={:?}, reason={:?}",
        response.verdict, response.reason,
    )
    .into())
}

#[cfg(unix)]
#[tokio::test]
async fn native_emergency_stop_keeps_recorded_return_settlement_and_controls_current_delivery(
) -> TestResult {
    verify_known_recorded_return_restoration(true).await
}

#[cfg(unix)]
#[tokio::test]
async fn native_known_recorded_semantic_return_settles_without_selection_change() -> TestResult {
    verify_known_recorded_return_restoration(false).await
}

#[cfg(unix)]
async fn verify_known_recorded_return_restoration(require_stop: bool) -> TestResult {
    use std::os::unix::process::ExitStatusExt;
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("semantic-kind"), "read-weak-manifest")?;
    std::fs::write(directory.path().join("public-original-profile"), "selected")?;
    empty_import::initialize_public_native_source(directory.path()).await?;
    let log_path = directory
        .path()
        .join("stopped-semantic-recorded-return-child.log");
    let log = std::fs::File::create(&log_path)?;
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "recovery::tests::semantic::emergency_stop_finalization::known_semantic_recorded_return_child",
            "--ignored", "--nocapture", "--test-threads=1",
        ])
        .env("CHIO_RECOVERY_CRASH_CHILD", "1")
        .env("CHIO_RECOVERY_CRASH_ROOT", directory.path())
        .env("CHIO_RECOVERY_CRASH_POINT", "return-recorded")
        .env("CHIO_RECOVERY_ORDINARY_STAGE_TRACE", "1")
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(90);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            child.kill()?;
            child.wait()?;
            return Err("semantic recorded-return child timed out".into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    };
    let log = std::fs::read_to_string(&log_path)?;
    assert_eq!(status.signal(), Some(6), "{log}");
    assert!(
        log.contains("recovery crash cutpoint: return-recorded"),
        "{log}"
    );
    let request: ToolCallRequest = serde_json::from_slice(&std::fs::read(
        directory
            .path()
            .join("known-semantic-recorded-return-request.json"),
    )?)?;
    let invocation: SemanticInvocationV1 = serde_json::from_value(request.arguments.clone())?;
    let scope = invocation.action.scope.clone();
    let operation_id;
    let original_request;
    let original_installation;
    let original_binding;
    let original_raw;
    let original_ledger;
    {
        let authority = SqliteAuthorityStore::open_serving(
            directory.path().join("admission.db"),
            directory.path().join("locks"),
        )?;
        let store = authority.admission_operation_store();
        let (operation, retained) = store
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
                &authority.mutation_fence(),
                now_ms()?,
            )?
            .ok_or("recorded native return original absent")?;
        assert_eq!(operation.state(), AdmissionOperationState::Finalizing);
        assert!(operation.dispatch_commit().is_some());
        assert!(operation.native_dispatch_ledger_digest().is_some());
        retained.validate_request_material(&request)?;
        operation_id = operation.binding().operation_id().clone();
        original_request = retained.canonical_bytes().to_vec();
        original_binding = chio_core::canonical_json_bytes(&operation.binding().to_persisted())?;
        original_raw = original_recorded_raw_custody(&authority, &operation)?;
        original_ledger = store
            .load_native_dispatch_ledger(&operation_id, &authority.mutation_fence(), now_ms()?)?
            .ok_or("original ordinary native ledger absent")?;
        assert_eq!(
            operation.native_dispatch_ledger_digest(),
            Some(&original_ledger.record_digest),
        );
        original_installation = chio_core::canonical_json_bytes(
            &store.read_semantic_installation(&scope, &authority.mutation_fence(), now_ms()?)?,
        )?;
        if require_stop {
            store.set_semantic_emergency_stop(&scope, true)?;
        }
        assert_eq!(
            chio_kernel::admission_operation::AdmissionOperationStore::semantic_output_disposition(
                &store,
                &operation,
                &request,
                &authority.mutation_fence(),
                now_ms()?,
            )?,
            Some(SemanticOutputDispositionV1::ReturnValue),
            "current delivery controls cannot block the private recorded-return disposition",
        );
    }
    let effects = rusqlite::Connection::open(directory.path().join("semantic-effects.db"))?;
    let count: i64 = effects.query_row("SELECT count(*) FROM semantic_submissions", [], |row| {
        row.get(0)
    })?;
    assert_eq!(count, 1);
    drop(effects);
    let f = RecoveryFixture::open(directory.path().to_path_buf(), None, false)?;
    let store = f.authority.admission_operation_store();
    assert_eq!(
        chio_core::canonical_json_bytes(&store.read_semantic_installation(
            &scope,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?)?,
        original_installation,
        "recorded-return restoration must not replace any installed authority or selection",
    );
    let operation = store
        .load_by_operation_id(&operation_id)?
        .ok_or("settled semantic original absent")?;
    assert_eq!(operation.state(), AdmissionOperationState::Completed);
    assert_eq!(
        chio_core::canonical_json_bytes(&operation.binding().to_persisted())?,
        original_binding,
    );
    assert_eq!(
        original_recorded_raw_custody(&f.authority, &operation)?,
        original_raw
    );
    assert_eq!(
        store
            .load_native_dispatch_ledger(&operation_id, &f.authority.mutation_fence(), now_ms()?)?
            .ok_or("completed original ordinary native ledger absent")?,
        original_ledger,
    );
    let (_, retained) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("settled semantic original request absent")?;
    assert_eq!(retained.canonical_bytes(), original_request.as_slice());
    let (_, influence) = store
        .retained_semantic_output_influence_for_test(
            &operation_id,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("retained semantic output origin absent")?;
    assert!(
        !influence.unknown,
        "this is a known-source stop control, not unknown-origin refusal"
    );
    let frozen = chio_core::canonical_json_bytes(&operation.to_persisted())?;
    let calls = f.process.process("root")?.tree_calls;
    let runtime = NativeSemanticRuntime::new(
        f.kernel.clone(),
        Arc::new(store.clone()),
        scope.clone(),
        f.authority.mutation_fence(),
    );
    if require_stop {
        let stopped = runtime
            .execute_step(
                &f.process,
                "root",
                "stopped-recorded-semantic-return",
                &request,
            )
            .await;
        assert!(
            stopped.is_err()
                || stopped
                    .as_ref()
                    .is_ok_and(|response| response.verdict == Verdict::Deny)
        );
        assert_eq!(f.effects.load(Ordering::SeqCst), 1);
        store.set_semantic_emergency_stop(&scope, false)?;
    }
    let released = runtime
        .execute_step(
            &f.process,
            "root",
            "stopped-recorded-semantic-return",
            &request,
        )
        .await?;
    assert_eq!(released.verdict, Verdict::Allow);
    let Some(chio_kernel::ToolCallOutput::Value(value)) = released.output else {
        return Err("known completed raw value absent".into());
    };
    assert!(chio_core::canonical_json_string(&value)?.contains("provider-output-canary"));
    let released_output = chio_core::canonical_json_bytes(&value)?;
    let released_receipt = chio_core::canonical_json_bytes(&released.receipt)?;
    let unchanged = store
        .load_by_operation_id(&operation_id)?
        .ok_or("settled semantic original disappeared")?;
    assert_eq!(
        chio_core::canonical_json_bytes(&unchanged.to_persisted())?,
        frozen
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    assert_eq!(f.process.process("root")?.tree_calls, calls);
    let outcomes = f.authority.tool_outcome_store();
    let completed_outcome = chio_core::canonical_json_bytes(
        &outcomes
            .lookup_by_operation(&operation_id)?
            .ok_or("completed ordinary outcome absent")?
            .to_persisted(),
    )?;
    let completed_release = outcomes
        .lookup_security_release(&operation_id)?
        .ok_or("completed ordinary release checkpoint absent")?
        .canonical_bytes()?;
    for _ in 0..2 {
        f.kernel.reconcile_durable_admission_startup()?;
        f.kernel.reconcile_recoverable_admissions()?;
        let retained = store
            .load_by_operation_id(&operation_id)?
            .ok_or("ordinary original disappeared during repeated startup")?;
        assert_eq!(
            chio_core::canonical_json_bytes(&retained.to_persisted())?,
            frozen
        );
        assert_eq!(
            original_recorded_raw_custody(&f.authority, &retained)?,
            original_raw
        );
        assert_eq!(
            chio_core::canonical_json_bytes(
                &outcomes
                    .lookup_by_operation(&operation_id)?
                    .ok_or("repeated ordinary outcome absent")?
                    .to_persisted(),
            )?,
            completed_outcome,
        );
        assert_eq!(
            outcomes
                .lookup_security_release(&operation_id)?
                .ok_or("repeated ordinary release absent")?
                .canonical_bytes()?,
            completed_release,
        );
        assert_eq!(f.effects.load(Ordering::SeqCst), 1);
        assert_eq!(f.process.process("root")?.tree_calls, calls);
    }
    // Every owned store and runtime handle releases its serving lease before
    // the second real startup of this same ordinary captured operation.
    drop(outcomes);
    drop(runtime);
    drop(store);
    drop(f);
    let reopened = RecoveryFixture::open(directory.path().to_path_buf(), None, false)?;
    let store = reopened.authority.admission_operation_store();
    let outcomes = reopened.authority.tool_outcome_store();
    let retained = store
        .load_by_operation_id(&operation_id)?
        .ok_or("ordinary original absent after second serving reopen")?;
    assert_eq!(
        chio_core::canonical_json_bytes(&retained.to_persisted())?,
        frozen
    );
    assert_eq!(
        original_recorded_raw_custody(&reopened.authority, &retained)?,
        original_raw
    );
    assert_eq!(
        chio_core::canonical_json_bytes(&retained.binding().to_persisted())?,
        original_binding,
    );
    assert_eq!(
        store
            .load_native_dispatch_ledger(
                &operation_id,
                &reopened.authority.mutation_fence(),
                now_ms()?
            )?
            .ok_or("reopened original ordinary ledger absent")?,
        original_ledger,
    );
    let (_, retained_request) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &reopened.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("reopened original ordinary request absent")?;
    assert_eq!(
        retained_request.canonical_bytes(),
        original_request.as_slice()
    );
    assert_eq!(
        chio_core::canonical_json_bytes(&store.read_semantic_installation(
            &scope,
            &reopened.authority.mutation_fence(),
            now_ms()?,
        )?)?,
        original_installation,
    );
    for _ in 0..2 {
        reopened.kernel.reconcile_durable_admission_startup()?;
        reopened.kernel.reconcile_recoverable_admissions()?;
        let stable = store
            .load_by_operation_id(&operation_id)?
            .ok_or("ordinary original disappeared after reopened startup")?;
        assert_eq!(
            chio_core::canonical_json_bytes(&stable.to_persisted())?,
            frozen
        );
        assert_eq!(
            original_recorded_raw_custody(&reopened.authority, &stable)?,
            original_raw
        );
        assert_eq!(
            chio_core::canonical_json_bytes(
                &outcomes
                    .lookup_by_operation(&operation_id)?
                    .ok_or("reopened ordinary outcome absent")?
                    .to_persisted(),
            )?,
            completed_outcome,
        );
        assert_eq!(
            outcomes
                .lookup_security_release(&operation_id)?
                .ok_or("reopened ordinary release absent")?
                .canonical_bytes()?,
            completed_release,
        );
        assert_eq!(reopened.effects.load(Ordering::SeqCst), 1);
        assert_eq!(reopened.process.process("root")?.tree_calls, calls);
    }
    let runtime = NativeSemanticRuntime::new(
        reopened.kernel.clone(),
        Arc::new(store.clone()),
        scope,
        reopened.authority.mutation_fence(),
    );
    let replay = runtime
        .execute_step(
            &reopened.process,
            "root",
            "stopped-recorded-semantic-return",
            &request,
        )
        .await?;
    assert_eq!(replay.verdict, Verdict::Allow);
    let Some(chio_kernel::ToolCallOutput::Value(replay_value)) = replay.output else {
        return Err("ordinary replay after second serving reopen has no raw value".into());
    };
    assert_eq!(
        chio_core::canonical_json_bytes(&replay_value)?,
        released_output
    );
    assert_eq!(
        chio_core::canonical_json_bytes(&replay.receipt)?,
        released_receipt
    );
    let stable = store
        .load_by_operation_id(&operation_id)?
        .ok_or("ordinary original disappeared after reopened delivery")?;
    assert_eq!(
        chio_core::canonical_json_bytes(&stable.to_persisted())?,
        frozen
    );
    assert_eq!(
        original_recorded_raw_custody(&reopened.authority, &stable)?,
        original_raw
    );
    assert_eq!(reopened.effects.load(Ordering::SeqCst), 1);
    assert_eq!(reopened.process.process("root")?.tree_calls, calls);
    Ok(())
}
