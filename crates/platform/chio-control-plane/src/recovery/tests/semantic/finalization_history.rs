//! Current semantic selection cannot strand an already recorded native return.
use super::*;

#[cfg(unix)]
#[tokio::test]
#[ignore = "only the native semantic finalization parent starts this child"]
async fn semantic_recorded_return_child() -> TestResult {
    let path = std::path::PathBuf::from(
        std::env::var_os("CHIO_RECOVERY_CRASH_ROOT").ok_or("semantic child root absent")?,
    );
    let f = RecoveryFixture::open(path, None, false)?;
    let store = f.authority.admission_operation_store();
    let legacy_capture = store.modeled_legacy_incomplete_annotation_capture_for_test()?;
    let key = "recorded-semantic-return";
    let (runtime, request, profile) = prepare(&f, key, SemanticOutputDispositionV1::ReturnValue)?;
    assert!(profile.invocation.annotations.as_slice().is_empty());
    assert_eq!(
        profile.deployment.body().routes.as_slice()[0]
            .annotators
            .as_slice()
            .len(),
        1
    );
    let legacy_input = store.modeled_legacy_semantic_input_floor_for_test(&request)?;
    std::fs::write(
        f.path.join("semantic-recorded-return-request.json"),
        chio_core::canonical_json_bytes(&request)?,
    )?;
    runtime
        .execute_step(&f.process, "root", key, &request)
        .await?;
    drop(legacy_input);
    drop(legacy_capture);
    Err("semantic child did not reach the recorded-return cutpoint".into())
}

#[cfg(unix)]
#[tokio::test]
async fn native_recorded_semantic_return_settles_after_selection_rotation_without_raw_release(
) -> TestResult {
    use std::os::unix::process::ExitStatusExt;
    let directory = tempfile::tempdir()?;
    std::fs::write(
        directory.path().join("semantic-kind"),
        "annotated-read-weak-manifest",
    )?;
    std::fs::write(directory.path().join("public-original-profile"), "selected")?;
    let log_path = directory.path().join("semantic-recorded-return-child.log");
    let log = std::fs::File::create(&log_path)?;
    let mut child = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "recovery::tests::semantic::finalization_history::semantic_recorded_return_child",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
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
            .join("semantic-recorded-return-request.json"),
    )?)?;
    let operation_id;
    let original_request;
    let scope;
    {
        // Opening the serving Store does not run the Kernel's finalizer. Inspect
        // genuine retained custody, then rotate only semantic selection.
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
        let invocation: SemanticInvocationV1 = serde_json::from_value(request.arguments.clone())?;
        scope = invocation.action.scope.clone();
        assert!(invocation.annotations.as_slice().is_empty());
        let mut selected =
            store.read_semantic_installation(&scope, &authority.mutation_fence(), now_ms()?)?;
        let (fixture, _) =
            chains::bundle(scope.clone(), now_ms()?, "annotated-read-weak-manifest")?;
        let original_binding = selected.native_authority.clone();
        let original_context = selected.security_context.clone();
        let mut deployment = selected.deployment.body().clone();
        deployment.generation = SafeInteger::new(
            deployment
                .generation
                .get()
                .checked_add(1)
                .ok_or("semantic generation overflow")?,
        )?;
        selected.deployment = SignedSemanticDeploymentV1::sign(deployment, &fixture.operator)?;
        store.configure_semantic_deployment(&selected)?;
        assert_eq!(selected.native_authority, original_binding);
        assert_eq!(selected.security_context, original_context);
        assert_ne!(
            semantic_registry_digest(selected.deployment.body())?,
            invocation.action.registry
        );
        // Missing source evidence is data. It cannot block the internal
        // Finalizing disposition or mint a current disclosure permission.
        assert_eq!(
            chio_kernel::admission_operation::AdmissionOperationStore::semantic_output_disposition(
                &store,
                &operation,
                &request,
                &authority.mutation_fence(),
                now_ms()?,
            )?,
            Some(SemanticOutputDispositionV1::ReturnValue)
        );
    }
    let effects = rusqlite::Connection::open(directory.path().join("semantic-effects.db"))?;
    let original_effects: i64 =
        effects.query_row("SELECT count(*) FROM semantic_submissions", [], |row| {
            row.get(0)
        })?;
    assert_eq!(original_effects, 1);
    drop(effects);
    let f = RecoveryFixture::open(directory.path().to_path_buf(), None, false)?;
    let store = f.authority.admission_operation_store();
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
        .ok_or("settled retained semantic request absent")?;
    assert_eq!(retained.canonical_bytes(), original_request);
    let frozen = chio_core::canonical_json_bytes(&operation.to_persisted())?;
    let runtime = NativeSemanticRuntime::new(
        f.kernel.clone(),
        Arc::new(store.clone()),
        scope,
        f.authority.mutation_fence(),
    );
    let result = runtime
        .execute_step(&f.process, "root", "recorded-semantic-return", &request)
        .await;
    assert!(
        result.is_err()
            || result
                .as_ref()
                .is_ok_and(|response| response.verdict == Verdict::Deny),
        "unknown historical annotations cannot authorize current raw disclosure"
    );
    let unchanged = store
        .load_by_operation_id(&operation_id)?
        .ok_or("settled semantic original disappeared")?;
    assert_eq!(
        chio_core::canonical_json_bytes(&unchanged.to_persisted())?,
        frozen
    );
    assert_eq!(f.effects.load(Ordering::SeqCst), 1);
    Ok(())
}
