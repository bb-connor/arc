//! Recorded native returns settle before current delivery controls apply.
use super::*;

#[cfg(unix)]
#[tokio::test]
#[ignore = "only the native recorded-return finalization parents start this child"]
async fn known_semantic_recorded_return_child() -> TestResult {
    let path = std::path::PathBuf::from(
        std::env::var_os("CHIO_RECOVERY_CRASH_ROOT").ok_or("semantic child root absent")?,
    );
    let f = RecoveryFixture::open(path, None, false)?;
    let key = "stopped-recorded-semantic-return";
    let (runtime, request, profile) = prepare(&f, key, SemanticOutputDispositionV1::ReturnValue)?;
    assert!(profile.invocation.annotations.as_slice().is_empty());
    assert!(profile.deployment.body().routes.as_slice()[0]
        .annotators
        .as_slice()
        .is_empty());
    std::fs::write(
        f.path.join("known-semantic-recorded-return-request.json"),
        chio_core::canonical_json_bytes(&request)?,
    )?;
    runtime
        .execute_step(&f.process, "root", key, &request)
        .await?;
    Err("semantic child did not reach the recorded-return cutpoint".into())
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
    let unchanged = store
        .load_by_operation_id(&operation_id)?
        .ok_or("settled semantic original disappeared")?;
    assert_eq!(
        chio_core::canonical_json_bytes(&unchanged.to_persisted())?,
        frozen
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    assert_eq!(f.process.process("root")?.tree_calls, calls);
    Ok(())
}
