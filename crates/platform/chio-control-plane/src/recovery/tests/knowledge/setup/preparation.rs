//! Setup preconditions must refuse before a benign operation can be dispatched.
use super::*;

async fn selected_self_test() -> TestResult<Box<OperatorBootstrap>> {
    let fixture = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let workflow = fixture.f.ready().await?;
    let service = setup(&fixture, &workflow)?;
    Ok(Box::new(OperatorBootstrap { fixture, service }))
}

#[tokio::test]
async fn setup_expired_bound_probe_refuses_before_dispatch() -> TestResult {
    let state = Box::pin(selected_self_test()).await?;
    let f = &state.fixture;
    let actor = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &f.f.control,
        RecoveryPermission::Inspect,
    )?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let prepared = store.setup_preparation(&actor, &fence, now_ms()?)?;
    let calls = f.f.process.process("root")?.tree_calls;
    let expired_secs = prepared.probe.expires_at_unix_ms.get() / 1_000 + 1;
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(
        expired_secs,
        std::iter::empty::<String>(),
    );
    assert!(
        matches!(
            store.setup_preparation(&actor, &fence, expired_secs * 1_000),
            Err(chio_store_sqlite::admission_operation_store::NativeSetupPreparationError::Expired)
        ),
        "an already bound command must not escape expired setup preparation"
    );
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert!(!f.f.record(state.service.workflow())?.captured);
    Ok(())
}

#[tokio::test]
async fn setup_writer_change_refuses_before_first_dispatch() -> TestResult {
    let mut state = Box::pin(selected_self_test()).await?;
    let workflow = state.service.workflow().clone();
    let path = state.fixture.f.path.clone();
    let directory = state.fixture.f._directory.take();
    let calls = state.fixture.f.process.process("root")?.tree_calls;
    drop(state);
    let f = KnowledgeFixture::from(RecoveryFixture::open(path, directory, false)?)?;
    let service = setup(&f, &workflow)?;
    assert_eq!(
        service.probe(&f.f.control, &workflow).await.err(),
        Some(crate::recovery::RecoveryRuntimeError::RestartRequired),
        "the writer mismatch must be reported before the self-test effect"
    );
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert!(!f.f.record(&workflow)?.captured);
    Ok(())
}

#[tokio::test]
async fn setup_stale_source_refuses_before_first_dispatch() -> TestResult {
    let state = Box::pin(selected_self_test()).await?;
    let f = &state.fixture;
    f.f.denied_seed_named("changed-setup-source").await?;
    let calls = f.f.process.process("root")?.tree_calls;
    assert_eq!(
        state
            .service
            .probe(&f.f.control, state.service.workflow())
            .await
            .err(),
        Some(crate::recovery::RecoveryRuntimeError::Conflict),
        "stale setup source must be a permanent basis conflict, not retryable unavailability"
    );
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert!(!f.f.record(state.service.workflow())?.captured);
    Ok(())
}

async fn attest_after_initial_probe_expiry(previously_qualified: bool) -> TestResult {
    let evidence = Box::pin(begin_restart_proof()).await?;
    let mut evidence = if previously_qualified {
        Box::pin(qualify_reopened_writer(
            evidence,
            "qualification-before-expiry",
        ))
        .await?
        .0
    } else {
        evidence
    };
    let f = KnowledgeFixture::from(RecoveryFixture::open(
        evidence.path.clone(),
        evidence.directory.take(),
        false,
    )?)?;
    let _service = setup(&f, &evidence.workflow)?;
    let actor = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &f.f.control,
        RecoveryPermission::Inspect,
    )?;
    // Obtain a real, freshly authorized replay of the identical retained
    // completion. This never creates another command or provider operation.
    let benign =
        f.f.kernel
            .replay_recovery_result(&actor, &evidence.workflow)?
            .receipt;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let calls = f.f.process.process("root")?.tree_calls;
    let expired_secs = evidence.probe.body().expires_at_unix_ms.get() / 1_000 + 1;
    let expired_ms = expired_secs * 1_000;
    let current_capability = f.f.kernel.issue_capability(
        &f.f.approval_key.public_key(),
        f.f.control.scope.clone(),
        1_200,
    )?;
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(
        expired_secs,
        std::iter::empty::<String>(),
    );
    let actor = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &current_capability,
        RecoveryPermission::Inspect,
    )?;
    let body = store.prepare_setup_report(&actor, &evidence.probe, &benign, &fence, expired_ms);
    if previously_qualified {
        let body = body?;
        assert_eq!(body.benign_operation, evidence.operation);
        assert_eq!(body.probe, *evidence.probe.body());
        assert!(body.qualified_at_unix_ms >= body.probe.expires_at_unix_ms);
        let report = chio_core_types::recovery::SignedRecoverySetupReportV1::sign(
            body,
            &Keypair::from_seed(&[211; 32]),
        )?;
        assert_eq!(
            store.accept_setup_report(&report, &fence, expired_ms)?,
            report
        );
        assert_eq!(
            store.accept_setup_report(&report, &fence, expired_ms)?,
            report
        );
    } else {
        assert!(
            body.is_err(),
            "an expired first qualification cannot become readiness"
        );
        assert!(store
            .setup_preparation(&actor, &fence, expired_ms)?
            .report
            .is_none());
    }
    assert_eq!(external_count(&f.f.path)?, evidence.effects);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    Ok(())
}

#[tokio::test]
async fn setup_accepted_profile_reattests_a_later_writer_after_probe_expiry() -> TestResult {
    Box::pin(attest_after_initial_probe_expiry(true)).await
}

#[tokio::test]
async fn setup_expired_first_qualification_cannot_unlock_work() -> TestResult {
    Box::pin(attest_after_initial_probe_expiry(false)).await
}

fn second_inspector(f: &KnowledgeFixture) -> TestResult<CapabilityToken> {
    let key = Keypair::from_seed(&[212; 32]);
    let permissions = vec![RecoveryPermission::Inspect, RecoveryPermission::Resume];
    let mut deployment = f.f.kernel.recovery_deployment(f.f.runtime.scope())?;
    let mut actors = deployment.actors.as_slice().to_vec();
    let preview_clearance = actors
        .first()
        .ok_or("selected setup inspector clearance")?
        .preview_clearance
        .clone();
    actors.push(RecoveryActorAssignment {
        subject: key.public_key(),
        principal: PrincipalId::new("second-setup-inspector")?,
        permissions: BoundedList::new(permissions.clone())?,
        preview_clearance,
    });
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    f.f.authority
        .admission_operation_store()
        .configure_recovery_deployment(&deployment)?;
    Ok(f.f.kernel.issue_capability(
        &key.public_key(),
        ChioScope {
            grants: permissions
                .iter()
                .map(|permission| ToolGrant {
                    server_id: "chio.recovery".into(),
                    tool_name: permission.wire_name().into(),
                    operations: vec![Operation::Invoke],
                    constraints: vec![],
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                })
                .collect(),
            ..Default::default()
        },
        1_200,
    )?)
}

#[tokio::test]
async fn setup_current_inspector_qualifies_the_retained_completion_without_a_new_resume(
) -> TestResult {
    let mut f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let inspector = second_inspector(&f)?;
    let workflow = Box::pin(f.f.ready()).await?;
    let service = setup(&f, &workflow)?;
    let probe = service.probe(&f.f.control, &workflow).await?;
    let operation =
        f.f.record(&workflow)?
            .native_link
            .ok_or("benign native operation")?;
    let path = f.f.path.clone();
    let directory = f.f._directory.take();
    let calls = f.f.process.process("root")?.tree_calls;
    drop(service);
    drop(f);
    let reopened = KnowledgeFixture::from(RecoveryFixture::open(path, directory, false)?)?;
    let service = setup(&reopened, &workflow)?;
    let report = service.qualify(&inspector, &probe).await?;
    assert_eq!(report.body().benign_operation, operation);
    assert_eq!(external_count(&reopened.f.path)?, 1);
    assert_eq!(reopened.f.process.process("root")?.tree_calls, calls);
    Ok(())
}

#[tokio::test]
async fn setup_foreign_resume_cannot_acquire_the_pinned_benign_identity() -> TestResult {
    let f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let inspector = second_inspector(&f)?;
    let workflow = Box::pin(f.f.ready()).await?;
    let _service = setup(&f, &workflow)?;
    let calls = f.f.process.process("root")?.tree_calls;
    let command = f.f.command(
        "foreign-setup-resume",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: workflow.clone(),
            expected_revision: f.f.record(&workflow)?.revision,
        },
    )?;
    assert!(f
        .f
        .runtime
        .execute_command(&inspector, &command)
        .await
        .is_err());
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert!(!f.f.record(&workflow)?.captured);
    Ok(())
}

#[tokio::test]
async fn setup_stale_unprobed_selection_can_be_replaced_without_waiting_for_expiry() -> TestResult {
    let state = Box::pin(selected_self_test()).await?;
    let f = &state.fixture;
    let previous_workflow = state.service.workflow().clone();
    let previous = f.f.record(&previous_workflow)?;
    let seed = f.f.denied_seed_named("fresh-setup-replacement").await?;
    assert_eq!(
        state
            .service
            .probe(&f.f.control, &previous_workflow)
            .await
            .err(),
        Some(crate::recovery::RecoveryRuntimeError::Conflict)
    );
    let creation = f.f.command(
        "fresh-setup-replacement-create",
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new("fresh-setup-replacement")?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(&seed)?,
        },
    )?;
    require_eligible_original(f, &seed)?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let inspector = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &f.f.control,
        RecoveryPermission::Inspect,
    )?;
    store.observe_setup_coverage(
        &inspector,
        &f.f.kernel.receipt_signing_public_key(),
        &fence,
        now_ms()?,
    )?;
    let creator = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &f.f.control,
        RecoveryPermission::Create,
    )?;
    let pinned = store
        .pin_setup_creation(
            &creator,
            &creation,
            chio_store_sqlite::admission_operation_store::NativeSetupCreationHost {
                receipt_key: &f.f.kernel.receipt_signing_public_key(),
                operator: &Keypair::from_seed(&[211; 32]).public_key(),
                process: &f.f.process,
            },
            &fence,
            now_ms()?,
        )
        .map_err(|error| format!("replacement pin after fresh actor, mediator inventory and original custody: {error}"))?;
    let host = RecoverySetupHost {
        runtime: f.f.runtime.clone(),
        store: Arc::new(f.f.authority.admission_operation_store()),
        fence: f.f.authority.mutation_fence(),
        knowledge: Some(Arc::new(f.runtime.clone())),
        operator: Keypair::from_seed(&[211; 32]),
    };
    let replacement = RecoverySetupService::for_creation(host, &f.f.control, &creation).await?;
    assert_eq!(replacement.workflow(), &pinned);
    assert_ne!(replacement.workflow(), &previous_workflow);
    let retired = f.f.record(&previous_workflow)?;
    assert_eq!(retired.control, WorkflowControlV1::Cancelled);
    assert_eq!(retired.origin, previous.origin);
    assert_eq!(retired.creation_seed, previous.creation_seed);
    assert!(!retired.captured);
    assert!(retired.native_link.is_none());
    assert_eq!(external_count(&f.f.path)?, 0);
    let replacement_calls = f.f.process.process("root")?.tree_calls;
    let old_resume = f.f.command(
        "retired-setup-resume",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: previous_workflow.clone(),
            expected_revision: retired.revision,
        },
    )?;
    assert!(f
        .f
        .runtime
        .execute_command(&f.f.control, &old_resume)
        .await
        .is_err());
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, replacement_calls);
    let workflow =
        Box::pin(f.f.ready_named("fresh-setup-replacement", "fresh-setup-replacement")).await?;
    assert_eq!(replacement.workflow(), &workflow);
    let calls = f.f.process.process("root")?.tree_calls;
    let probe = replacement.probe(&f.f.control, &workflow).await?;
    assert_eq!(probe.body().benign_workflow, workflow);
    assert_eq!(external_count(&f.f.path)?, 1);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert!(!f.f.record(&previous_workflow)?.captured);
    Ok(())
}

#[tokio::test]
async fn setup_a_bare_runtime_cannot_skip_the_selected_live_mediator() -> TestResult {
    let state = Box::pin(selected_self_test()).await?;
    let f = &state.fixture;
    let bare = crate::recovery::RecoveryRuntime::new(
        f.f.kernel.clone(),
        f.f.process.clone(),
        f.f.runtime.flow.clone(),
        f.f.runtime.scope().clone(),
        f.f.runtime.signer.clone(),
    )?;
    let calls = f.f.process.process("root")?.tree_calls;
    assert_eq!(
        bare.review_document(&f.f.control, state.service.workflow())
            .err(),
        Some(crate::recovery::RecoveryRuntimeError::UncoveredMediation),
        "a retained protected marker requires live mediator validation in every runtime"
    );
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    Ok(())
}
