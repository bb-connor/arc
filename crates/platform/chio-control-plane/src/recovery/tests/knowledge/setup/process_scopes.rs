//! Independent native processes qualify their own setup custody in one tenant.
use super::*;

#[tokio::test]
async fn setup_two_native_processes_in_one_tenant_keep_separate_capture_custody() -> TestResult {
    let fixture = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let first_workflow = Box::pin(fixture.f.ready()).await?;
    let first_service = setup(&fixture, &first_workflow)?;
    let first_scope = fixture.f.runtime.scope().clone();
    let store = fixture.f.authority.admission_operation_store();
    let fence = fixture.f.authority.mutation_fence();
    let mut semantic = store.read_semantic_installation(&first_scope, &fence, now_ms()?)?;
    let mut deployment = fixture.f.kernel.recovery_deployment(&first_scope)?;
    let KnowledgeFixture { mut f, .. } = fixture;
    deployment.scope.process_id = ProcessId::new("second-native-root")?;
    let second_capability = f.kernel.issue_capability(
        &f.seed.capability.subject,
        f.seed.capability.scope.clone(),
        1_200,
    )?;
    f.process.create_root(
        deployment.scope.process_id.as_str(),
        &second_capability,
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
    assert_ne!(
        recovery_flow_key(&deployment.security_context),
        recovery_flow_key(&semantic.security_context),
        "independent setup scopes must select distinct genuine native routes"
    );
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    store.configure_recovery_deployment(&deployment)?;
    semantic.security_context = deployment.security_context.clone();
    let mut body = semantic.deployment.body().clone();
    body.scope = deployment.scope.clone();
    body.context_binding = chio_core_types::recovery::semantic_content_digest(&(
        recovery_flow_key(&deployment.security_context),
        deployment.security_context.as_v1().context_generation(),
    ))?;
    semantic.deployment = SignedSemanticDeploymentV1::sign(body, &Keypair::from_seed(&[211; 32]))?;
    store.configure_semantic_deployment(&semantic)?;
    let runtime = crate::recovery::RecoveryRuntime::new(
        f.kernel.clone(),
        f.process.clone(),
        f.runtime.flow.clone(),
        deployment.scope.clone(),
        f.runtime.signer.clone(),
    )?;
    f.runtime = Arc::new(runtime);
    let original = Box::pin(f.denied_seed_named("second-setup-source-initialization"))
        .await
        .map_err(|error| format!("second setup ordinary native source input: {error}"))?;
    let observation = store.observe_security_participant_flow(
        &deployment.native_authority,
        &recovery_flow_key(&deployment.security_context),
        &fence,
        now_ms()?,
    )?;
    assert!(observation.snapshot().is_some(), "the second setup context must have an actual native input observation before knowledge configuration");
    let (operation, retained) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &original.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("second setup input custody absent")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    retained.validate_request_material(&original)?;
    retained.validate_native_security_context(&deployment.security_context)?;
    retained.validate_native_security_authority(&deployment.native_authority)?;
    let second = KnowledgeFixture::from(f)
        .map_err(|error| format!("second setup knowledge producer after native input: {error}"))?;
    let seed = Box::pin(second.f.denied_seed_named("second-native-setup")).await?;
    let creation = second.f.command(
        "second-native-setup-create",
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new("second-native-setup")?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(&seed)?,
        },
    )?;
    let second_service = RecoverySetupService::for_creation(
        RecoverySetupHost {
            runtime: second.f.runtime.clone(),
            store: Arc::new(store),
            fence,
            knowledge: Some(Arc::new(second.runtime.clone())),
            operator: Keypair::from_seed(&[211; 32]),
        },
        &second.f.control,
        &creation,
    )
    .await?;
    let second_workflow = Box::pin(
        second
            .f
            .ready_named("second-native-setup", "second-native-setup"),
    )
    .await?;
    assert_eq!(second_service.workflow(), &second_workflow);
    assert_ne!(first_scope, *second.f.runtime.scope());
    let first_calls = second.f.process.process("root")?.tree_calls;
    let second_calls = second.f.process.process("second-native-root")?.tree_calls;
    let first_probe = first_service
        .probe(&second.f.control, &first_workflow)
        .await?;
    let second_probe = second_service
        .probe(&second.f.control, &second_workflow)
        .await?;
    assert_eq!(first_probe.body().scope, first_scope);
    assert_eq!(second_probe.body().scope, *second.f.runtime.scope());
    assert_eq!(external_count(&second.f.path)?, 2);
    assert_eq!(second.f.process.process("root")?.tree_calls, first_calls);
    assert_eq!(
        second.f.process.process("second-native-root")?.tree_calls,
        second_calls
    );
    let first_actor = second.f.kernel.authenticate_recovery_actor(
        &first_scope,
        &second.f.control,
        RecoveryPermission::Inspect,
    )?;
    let first = second
        .f
        .kernel
        .read_recovery_workflow(&first_actor, &first_workflow)?;
    let other = second.f.record(&second_workflow)?;
    assert!(first.captured && other.captured);
    assert_ne!(first.native_link, other.native_link);
    assert_eq!(
        first_service
            .probe(&second.f.control, &first_workflow)
            .await?,
        first_probe
    );
    assert_eq!(
        second_service
            .probe(&second.f.control, &second_workflow)
            .await?,
        second_probe
    );
    assert_eq!(external_count(&second.f.path)?, 2);
    Ok(())
}
