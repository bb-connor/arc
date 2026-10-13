//! Genuine native roots inherit source restrictions before their first join.
use super::*;

fn second_native_root(f: &RecoveryFixture) -> TestResult<RecoveryDeploymentV1> {
    let mut deployment = f.kernel.recovery_deployment(f.runtime.scope())?;
    deployment.scope.process_id = ProcessId::new("second-original-root")?;
    let capability = f.kernel.issue_capability(
        &f.seed.capability.subject,
        f.seed.capability.scope.clone(),
        1_200,
    )?;
    assert_ne!(capability.id, f.seed.capability.id);
    assert_eq!(capability.subject, f.seed.capability.subject);
    f.process.create_root(
        deployment.scope.process_id.as_str(),
        &capability,
        ProcessLimits {
            max_processes: 8,
            max_depth: 2,
            max_calls: 32,
            state: Default::default(),
        },
    )?;
    deployment.security_context = f
        .process
        .recovery_security_context(deployment.scope.process_id.as_str())?;
    let first = recovery_flow_key(
        &f.kernel
            .recovery_deployment(f.runtime.scope())?
            .security_context,
    );
    let second = recovery_flow_key(&deployment.security_context);
    assert_eq!(first.tenant_id, second.tenant_id);
    assert_eq!(first.principal_id, second.principal_id);
    assert_eq!(first.session_id, second.session_id);
    assert_eq!(first.isolation_epoch_id, second.isolation_epoch_id);
    assert_ne!(first.lineage_id, second.lineage_id);
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    f.authority
        .admission_operation_store()
        .configure_recovery_deployment(&deployment)?;
    Ok(deployment)
}

fn exact_epoch_count(f: &RecoveryFixture, deployment: &RecoveryDeploymentV1) -> TestResult<i64> {
    let key = recovery_flow_key(&deployment.security_context);
    let database = rusqlite::Connection::open_with_flags(
        f.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    Ok(database.query_row(
        "SELECT COUNT(*) FROM security_participant_state_isolation_epochs
         WHERE security_authority_id=?1 AND tenant_id=?2 AND principal_id=?3
         AND lineage_id=?4 AND isolation_epoch_id=?5",
        rusqlite::params![
            deployment.native_authority.security_authority_id().as_str(),
            key.tenant_id.as_str(),
            key.principal_id.as_str(),
            key.lineage_id.as_str(),
            key.isolation_epoch_id.as_str(),
        ],
        |row| row.get::<_, i64>(0),
    )?)
}

#[tokio::test]
async fn genuine_new_lineage_observes_inherited_native_source_without_minting_epoch() -> TestResult
{
    let f = RecoveryFixture::new(false)?;
    let original = Box::pin(f.denied_seed_named("first-native-source")).await?;
    let before = f.kernel.observe_recovery_source(f.runtime.scope())?;
    let before_labels = before.snapshot().ok_or("first native source absent")?;
    assert_eq!(before_labels.principal_label, restricted_label());
    assert_eq!(before_labels.lineage_label, restricted_label());
    assert_eq!(before_labels.session_label, restricted_label());
    let second = second_native_root(&f)?;
    assert_eq!(exact_epoch_count(&f, &second)?, 0);
    assert_eq!(
        second.security_context.as_v1().flow_state_generation(),
        None
    );
    let calls = f
        .process
        .process(second.scope.process_id.as_str())?
        .tree_calls;
    let effects = external_count(&f.path)?;
    let store = f.authority.admission_operation_store();
    let inherited = store.observe_security_participant_flow(
        &second.native_authority,
        &recovery_flow_key(&second.security_context),
        &f.authority.mutation_fence(),
        now_ms()?,
    )?;
    let inherited_labels = inherited
        .snapshot()
        .ok_or("new lineage lost inherited source")?;
    assert_eq!(inherited_labels.principal_label, restricted_label());
    assert_eq!(inherited_labels.session_label, restricted_label());
    assert_eq!(inherited_labels.lineage_label, InformationLabel::bottom());
    assert_eq!(inherited.stored_context_generation(), None);
    assert_eq!(exact_epoch_count(&f, &second)?, 0);
    assert_eq!(external_count(&f.path)?, effects);
    assert_eq!(
        f.process
            .process(second.scope.process_id.as_str())?
            .tree_calls,
        calls
    );
    assert_eq!(
        f.kernel
            .observe_recovery_source(f.runtime.scope())?
            .snapshot(),
        before.snapshot()
    );
    let (operation, retained) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &original.request_id)?,
            &f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("first original custody disappeared")?;
    retained.validate_request_material(&original)?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    Ok(())
}

#[tokio::test]
async fn genuine_new_lineage_first_input_keeps_original_no_effect_custody_and_shared_source(
) -> TestResult {
    let f = RecoveryFixture::new(false)?;
    let first_request = Box::pin(f.denied_seed_named("first-native-source")).await?;
    let store = f.authority.admission_operation_store();
    let fence = f.authority.mutation_fence();
    let (first_operation, first_retained) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &first_request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("first original custody absent")?;
    let first_operation_bytes = chio_core::canonical_json_bytes(&first_operation)?;
    first_retained.validate_request_material(&first_request)?;
    let before = f.kernel.observe_recovery_source(f.runtime.scope())?;
    let second = second_native_root(&f)?;
    assert_eq!(exact_epoch_count(&f, &second)?, 0);
    let request = f.process.tool_request(
        second.scope.process_id.as_str(),
        "first-original",
        &f.seed.server_id,
        &f.seed.tool_name,
        f.seed.arguments.clone(),
    )?;
    assert_eq!(request.capability.subject, f.seed.capability.subject);
    assert_ne!(request.capability.id, f.seed.capability.id);
    let denial = Box::pin(f.process.invoke_known_only(
        second.scope.process_id.as_str(),
        "first-original",
        &request,
    ))
    .await?;
    assert_eq!(denial.verdict, Verdict::Deny);
    assert!(denial.receipt.verify_signature()?);
    assert_eq!(external_count(&f.path)?, 0);
    let (second_operation, second_retained) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("actual second original input was not retained")?;
    second_retained.validate_request_material(&request)?;
    second_retained.validate_native_security_context(&second.security_context)?;
    second_retained.validate_native_security_authority(&second.native_authority)?;
    assert_eq!(
        second_operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(second_operation.dispatch_commit().is_none());
    assert_eq!(exact_epoch_count(&f, &second)?, 1);
    let joined = store.observe_security_participant_flow(
        &second.native_authority,
        &recovery_flow_key(&second.security_context),
        &fence,
        now_ms()?,
    )?;
    let state = joined.snapshot().ok_or("second native join absent")?;
    assert_eq!(state.principal_label, restricted_label());
    assert_eq!(state.lineage_label, restricted_label());
    assert_eq!(state.session_label, restricted_label());
    assert_eq!(
        joined.stored_context_generation(),
        Some(state.context_generation)
    );
    assert!(
        state.context_generation
            > before
                .snapshot()
                .ok_or("first source absent")?
                .context_generation
    );
    let current_first = f.kernel.observe_recovery_source(f.runtime.scope())?;
    let first_labels = current_first
        .snapshot()
        .ok_or("first context source absent")?;
    assert_eq!(first_labels.principal_label, restricted_label());
    assert_eq!(first_labels.lineage_label, restricted_label());
    assert_eq!(first_labels.session_label, restricted_label());
    let old = store
        .load_by_operation_id(first_operation.binding().operation_id())?
        .ok_or("first original operation disappeared")?;
    assert_eq!(
        chio_core::canonical_json_bytes(&old)?,
        first_operation_bytes
    );
    let again = Box::pin(f.denied_seed_named("first-root-after-new-lineage")).await?;
    assert_ne!(again.request_id, first_request.request_id);
    assert_eq!(external_count(&f.path)?, 0);
    Ok(())
}
