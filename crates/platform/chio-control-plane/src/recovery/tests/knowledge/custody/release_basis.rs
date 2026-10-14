//! Current basis checks are distinguished from installation generation changes.
use super::*;
use chio_kernel::admission_operation::AdmissionOperationStoreError;

type RetainedRows = Vec<Vec<rusqlite::types::Value>>;

fn admission_state(f: &KnowledgeFixture) -> TestResult<Vec<RetainedRows>> {
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let mut state = Vec::new();
    for sql in [
        "SELECT * FROM main.admission_operation_recovery_records ORDER BY record_key",
        "SELECT * FROM main.admission_operation_recovery_events ORDER BY sequence",
        "SELECT * FROM main.authority_global_commits ORDER BY commit_sequence",
    ] {
        let mut statement = connection.prepare(sql)?;
        let columns = statement.column_count();
        let rows = statement.query_map([], |row| {
            (0..columns)
                .map(|column| row.get::<_, rusqlite::types::Value>(column))
                .collect::<Result<Vec<_>, _>>()
        })?;
        state.push(rows.collect::<Result<Vec<_>, _>>()?);
    }
    Ok(state)
}

#[test]
fn artifacts_prepared_read_survives_generation_change_with_the_same_current_basis() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let bytes = b"prepared-generation-positive";
    let reference = f.publish("prepared-generation-positive", bytes)?;
    let handle = f.runtime.handle(
        &f.f.control,
        &reference,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    let prepared = f.runtime.prepare_read(&f.f.control, &handle)?;
    let mut profile = f.profile.clone();
    profile.generation = SafeInteger::new(2)?;
    assert_eq!(profile.policy, f.profile.policy);
    assert_eq!(profile.contract, f.profile.contract);
    assert_eq!(
        serde_json::to_value(&profile.recipients)?,
        serde_json::to_value(&f.profile.recipients)?,
    );
    f.f.authority
        .admission_operation_store()
        .configure_knowledge(&profile)?;
    let actor = f.actor(RecoveryPermission::KnowledgeRead)?;
    let request = RequestId::new("prepared-generation-positive")?;
    let observer = observe_artifact_release_basis(&actor, &request)?;
    let sink = f.sink();
    let calls = f.f.process.process("root")?.tree_calls;
    f.runtime
        .release_into(&f.f.control, &request, prepared, &sink)?;
    assert_eq!(
        observer.observations()?,
        vec![ArtifactReleaseBasisObservation::Accepted],
    );
    assert_eq!(
        *sink.delivered.lock().map_err(|_| "sink")?,
        vec![bytes.to_vec()],
    );
    assert_eq!(retained_count(&f, "knowledge-join:")?, 1);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    Ok(())
}

#[test]
fn artifacts_prepared_read_policy_change_reaches_the_private_basis_rejection_before_join(
) -> TestResult {
    let mut f = KnowledgeFixture::new()?;
    let reference = f.publish("prepared-policy-negative", b"prepared-policy-negative")?;
    let handle = f.runtime.handle(
        &f.f.control,
        &reference,
        &ArtifactRecipientId::new("agent-root")?,
    )?;
    let prepared = f.runtime.prepare_read(&f.f.control, &handle)?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let first_actor = f.actor(RecoveryPermission::KnowledgeRead)?;
    let (record, _) = store.prepare_artifact_read(&first_actor, &handle, &fence, now_ms()?)?;
    assert_eq!(record.metadata.policy, f.profile.policy);
    assert_eq!(record.metadata.contract, f.profile.contract);
    let policy = PolicyDigest::from_bytes([217; 32]);
    assert_ne!(policy, f.profile.policy);
    let mut deployment = f.f.kernel.recovery_deployment(&f.profile.scope)?;
    deployment.policy_digest = policy;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    store.configure_recovery_deployment(&deployment)?;
    let mut profile = f.profile.clone();
    profile.generation = SafeInteger::new(2)?;
    profile.policy = policy;
    assert_eq!(profile.contract, record.metadata.contract);
    assert_eq!(
        serde_json::to_value(&profile.recipients)?,
        serde_json::to_value(&f.profile.recipients)?,
    );
    store.configure_knowledge(&profile)?;
    std::fs::write(
        f.f.path.join("current-recovery-policy"),
        policy
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    )?;
    let path = f.f.path.clone();
    let directory = f.f._directory.take();
    let control = f.f.control.clone();
    let control_bytes = chio_core::canonical_json_bytes(&control)?;
    let certificate = f.certificate.clone();
    // Release the old serving owner and every old Kernel holder before opening
    // the same physical journals under the selected current policy.
    drop(store);
    drop(f);
    let mut recovery = RecoveryFixture::open(path, directory, false)
        .map_err(|error| format!("current policy recovery reopen: {error}"))?;
    recovery.control = control;
    let broker = Arc::new(
        recovery
            .process
            .enable_durable_knowledge()
            .map_err(|error| format!("current policy process broker reopen: {error}"))?,
    );
    let runtime = NativeKnowledgeRuntime::new(
        recovery.kernel.clone(),
        Arc::new(recovery.authority.admission_operation_store()),
        broker.clone(),
        profile.clone(),
        recovery.authority.mutation_fence(),
    )
    .map_err(|error| format!("current policy knowledge reopen: {error}"))?;
    let f = KnowledgeFixture {
        f: recovery,
        runtime,
        profile,
        broker,
        certificate,
    };
    assert_eq!(
        chio_core::canonical_json_bytes(&f.f.control)?,
        control_bytes
    );
    let current_deployment =
        f.f.kernel
            .recovery_deployment(&f.profile.scope)
            .map_err(|error| format!("current policy native deployment validation: {error}"))?;
    assert_eq!(current_deployment.policy_digest, policy);
    assert_eq!(
        current_deployment.native_authority,
        deployment.native_authority
    );
    assert_eq!(
        current_deployment.security_context,
        deployment.security_context
    );
    let actor = f
        .actor(RecoveryPermission::KnowledgeRead)
        .map_err(|error| format!("current policy reader authentication: {error}"))?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let current_profile = store
        .knowledge_installation(&actor, &fence, now_ms()?)
        .map_err(|error| format!("current policy installation validation: {error}"))?;
    assert_eq!(current_profile.policy, policy);
    assert_eq!(current_profile.contract, record.metadata.contract);
    assert_eq!(current_profile.producer_context, f.profile.producer_context);
    assert_eq!(
        serde_json::to_value(&current_profile.recipients)?,
        serde_json::to_value(&f.profile.recipients)?,
    );
    let request = RequestId::new("prepared-policy-negative")?;
    let observer = observe_artifact_release_basis(&actor, &request)?;
    let sink = f.sink();
    let before = admission_state(&f)?;
    let calls = f.f.process.process("root")?.tree_calls;
    let private_result = store.admit_artifact_release(
        &actor,
        &handle,
        &request,
        record
            .seal
            .as_ref()
            .ok_or("actual authenticated private seal")?,
        &fence,
        now_ms()?,
    );
    assert!(matches!(
        private_result,
        Err(AdmissionOperationStoreError::Invariant(_)),
    ));
    assert_eq!(
        observer.observations()?,
        vec![ArtifactReleaseBasisObservation::PolicyRejected],
        "the actual private writer must reach its policy-only basis rejection",
    );
    assert_eq!(admission_state(&f)?, before);
    assert!(f
        .runtime
        .release_into(&f.f.control, &request, prepared, &sink)
        .is_err());
    assert_eq!(
        observer.observations()?,
        vec![
            ArtifactReleaseBasisObservation::PolicyRejected,
            ArtifactReleaseBasisObservation::PolicyRejected,
        ],
    );
    assert!(sink.delivered.lock().map_err(|_| "sink")?.is_empty());
    assert_eq!(retained_count(&f, "knowledge-join:")?, 0);
    assert_eq!(admission_state(&f)?, before);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    Ok(())
}
