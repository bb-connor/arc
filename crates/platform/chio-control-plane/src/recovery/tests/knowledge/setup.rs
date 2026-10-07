//! Real native setup requires a completed model-free effect and a fresh writer.
use super::*;
use crate::recovery::RecoverySetupHost;
use crate::recovery::RecoverySetupService;
use chio_core_types::recovery::{SignedRecoverySetupProbeV1, SignedSemanticDeploymentV1};
use chio_security_types::semantic::SemanticOutputDispositionV1;
mod cli_host;
mod coverage;
mod denied_mediation;
mod journal_availability;
mod legacy_retirement;
mod live_mediator;
mod mandatory_policy;
mod policy;
mod preparation;
mod process_scopes;
mod signed_proof_refusals;
mod transport_admission;
mod validity;

fn setup(f: &KnowledgeFixture, workflow: &WorkflowId) -> TestResult<RecoverySetupService> {
    Ok(RecoverySetupService::new(
        f.f.runtime.clone(),
        Arc::new(f.f.authority.admission_operation_store()),
        f.f.authority.mutation_fence(),
        Some(Arc::new(f.runtime.clone())),
        Keypair::from_seed(&[211; 32]),
        workflow.clone(),
    )?)
}
async fn new_work(f: &KnowledgeFixture, key: &str) -> TestResult<RecoveryCommandResultV1> {
    let seed = f.f.denied_seed_named(key).await?;
    create_work(f, key, &seed).await
}
async fn create_work(
    f: &KnowledgeFixture,
    key: &str,
    seed: &ToolCallRequest,
) -> TestResult<RecoveryCommandResultV1> {
    f.f.execute(
        key,
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new(key)?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(seed)?,
        },
    )
    .await
}
async fn refuse_new_work(f: &KnowledgeFixture, key: &str) -> TestResult {
    // Establish the original operation before observing setup refusal. A
    // provenance failure must not stand in for the readiness gate under test.
    let seed = f.f.denied_seed_named(key).await?;
    refuse_work_creation(f, key, &seed).await
}
fn retained_workflow_count(f: &KnowledgeFixture) -> TestResult<i64> {
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    Ok(connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE kind='workflow'",
        [],
        |row| row.get(0),
    )?)
}
async fn refuse_work_creation(
    f: &KnowledgeFixture,
    key: &str,
    seed: &ToolCallRequest,
) -> TestResult {
    require_eligible_original(f, seed)?;
    let command = f.f.command(
        key,
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new(key)?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(seed)?,
        },
    )?;
    let before = retained_workflow_count(f)?;
    let calls = f.f.process.process("root")?.tree_calls;
    let effects = external_count(&f.f.path)?;
    assert_eq!(
        f.f.runtime
            .execute_command(&f.f.control, &command)
            .await
            .err(),
        Some(crate::recovery::RecoveryRuntimeError::UncoveredMediation),
        "the protected setup owner must refuse this genuine original"
    );
    assert_eq!(retained_workflow_count(f)?, before);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert_eq!(external_count(&f.f.path)?, effects);
    Ok(())
}
fn require_eligible_original(f: &KnowledgeFixture, seed: &ToolCallRequest) -> TestResult {
    let scope = f.f.runtime.scope();
    let deployment = f.f.kernel.recovery_deployment(scope)?;
    // A valid actor and an independently retained pre-dispatch original are
    // positive controls. Neither a missing role nor an ineligible original may
    // substitute for the setup refusal under test.
    for permission in [RecoveryPermission::Create, RecoveryPermission::Inspect] {
        f.f.kernel
            .authenticate_recovery_actor(scope, &f.f.control, permission)?;
    }
    chio_kernel::recovery::RecoveryProcessOriginPort::verify_original_request(
        &f.f.process,
        scope,
        seed,
        deployment.security_context.as_v1().session_id().as_str(),
    )?;
    let (operation, retained) =
        f.f.authority
            .admission_operation_store()
            .load_unambiguous_retained_tool_request(
                &AdmissionIdentifier::try_new("request_id", &seed.request_id)?,
                &f.f.authority.mutation_fence(),
                now_ms()?,
            )?
            .ok_or("setup original custody absent")?;
    assert_eq!(
        operation.binding().kind(),
        chio_kernel::admission_operation::AdmissionOperationKind::ToolDispatch
    );
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    retained.validate_request_material(seed)?;
    retained.validate_native_security_context(&deployment.security_context)?;
    retained.validate_native_security_authority(&deployment.native_authority)?;
    Ok(())
}
struct RestartProof {
    path: std::path::PathBuf,
    directory: Option<tempfile::TempDir>,
    workflow: WorkflowId,
    probe: SignedRecoverySetupProbeV1,
    operation: OperationId,
    tree_calls: u32,
    effects: usize,
}
async fn begin_restart_proof() -> TestResult<RestartProof> {
    let mut f = KnowledgeFixture::from(super::super::semantic::native_fixture("read")?)?;
    let unused_denial = f.f.denied_seed_named("before-ready").await?;
    let workflow = f.f.ready().await?;
    let service = setup(&f, &workflow)?;
    // Establish unused original denials before the selected action is frozen.
    // Readiness refusal must not create an unrelated native flow generation.
    refuse_work_creation(&f, "before-ready", &unused_denial).await?;
    let probe = service.probe(&f.f.control, &workflow).await?;
    assert!(probe.verify_signature()?);
    assert_eq!(
        service.qualify(&f.f.control, &probe).await.err(),
        Some(crate::recovery::RecoveryRuntimeError::RestartRequired)
    );
    let operation =
        f.f.record(&workflow)?
            .native_link
            .ok_or("native operation")?;
    let tree_calls = f.f.process.process("root")?.tree_calls;
    assert_eq!(external_count(&f.f.path)?, 1);
    Ok(RestartProof {
        path: f.f.path.clone(),
        directory: f.f._directory.take(),
        workflow,
        probe,
        operation,
        tree_calls,
        effects: 1,
    })
}
async fn qualify_reopened_writer(
    mut evidence: RestartProof,
    key: &str,
) -> TestResult<(
    RestartProof,
    chio_core_types::recovery::SignedRecoverySetupReportV1,
)> {
    let mut f = KnowledgeFixture::from(RecoveryFixture::open(
        evidence.path.clone(),
        evidence.directory.take(),
        false,
    )?)?;
    let service = setup(&f, &evidence.workflow)?;
    refuse_new_work(&f, &format!("{key}-unqualified")).await?;
    let before_qualification = f.f.process.process("root")?.tree_calls;
    assert_eq!(before_qualification, evidence.tree_calls + 1);
    let report = service.qualify(&f.f.control, &evidence.probe).await?;
    assert_eq!(
        report.authority_key(),
        &Keypair::from_seed(&[211; 32]).public_key()
    );
    assert!(report.verify_signature()?);
    assert_eq!(report.body().benign_operation, evidence.operation);
    assert_eq!(
        service.qualify(&f.f.control, &evidence.probe).await?,
        report
    );
    assert_eq!(external_count(&f.f.path)?, evidence.effects);
    assert_eq!(
        f.f.process.process("root")?.tree_calls,
        before_qualification
    );
    new_work(&f, &format!("{key}-qualified")).await?;
    // The fresh original denial and its continuation carry their own charges.
    // The next writer must replay qualification without adding another call.
    evidence.tree_calls = f.f.process.process("root")?.tree_calls;
    evidence.directory = f.f._directory.take();
    Ok((evidence, report))
}
#[tokio::test]
async fn setup_real_restart_recovers_the_identical_operation_once() -> TestResult {
    let evidence = Box::pin(begin_restart_proof()).await?;
    let (evidence, first) = Box::pin(qualify_reopened_writer(evidence, "second-writer")).await?;
    let (_, second) = Box::pin(qualify_reopened_writer(evidence, "third-writer")).await?;
    assert_ne!(
        first.body().current_serving_fence,
        second.body().current_serving_fence
    );
    Ok(())
}
#[tokio::test]
async fn setup_every_foreign_binding_and_old_profile_refuses() -> TestResult {
    let state = Box::pin(replacement_after_profile_change()).await?;
    let evidence = Box::pin(finish_operator_bootstrap(
        state,
        "new-profile-self-test",
        2,
        6,
    ))
    .await?;
    Box::pin(qualify_reopened_writer(evidence, "replacement-profile")).await?;
    Ok(())
}
struct OperatorBootstrap {
    fixture: KnowledgeFixture,
    service: RecoverySetupService,
}
async fn replacement_after_profile_change() -> TestResult<Box<OperatorBootstrap>> {
    let mut f = KnowledgeFixture::from(super::super::semantic::native_fixture("read")?)?;
    let workflow = f.f.ready().await?;
    let service = setup(&f, &workflow)?;
    let probe = service.probe(&f.f.control, &workflow).await?;
    let path = f.f.path.clone();
    let directory = f.f._directory.take();
    drop(service);
    drop(f);
    let f = KnowledgeFixture::from(RecoveryFixture::open(path, directory, false)?)?;
    let service = setup(&f, &workflow)?;
    for mutation in 0..9 {
        let mut body = probe.body().clone();
        match mutation {
            0 => body.scope.authority_domain = AuthorityDomainId::new("foreign-store")?,
            1 => body.scope.process_id = ProcessId::new("foreign-process")?,
            2 => body.deployment = DeploymentDigest::from_bytes([80; 32]),
            3 => body.source_profile = SourceDigest::from_bytes([81; 32]),
            4 => body.required_coverage = CoverageDigest::from_bytes([82; 32]),
            5 => body.native_authority = SourceDigest::from_bytes([83; 32]),
            6 => body.scope.tenant_id = RecoveryTenantId::new("foreign-tenant")?,
            7 => body.probe_id = ChallengeId::new("foreign-challenge")?,
            _ => body.benign_workflow = WorkflowId::new("foreign-self-test")?,
        }
        let signed = SignedRecoverySetupProbeV1::sign(body, &Keypair::from_seed(&[211; 32]))?;
        assert!(service.qualify(&f.f.control, &signed).await.is_err());
    }
    let wrong_signer =
        SignedRecoverySetupProbeV1::sign(probe.body().clone(), &Keypair::from_seed(&[210; 32]))?;
    assert!(service.qualify(&f.f.control, &wrong_signer).await.is_err());
    let report = service.qualify(&f.f.control, &probe).await?;
    let store = f.f.authority.admission_operation_store();
    let mut installation = store.read_semantic_installation(
        f.f.runtime.scope(),
        &f.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    let mut body = installation.deployment.body().clone();
    body.generation = SafeInteger::new(body.generation.get() + 1)?;
    installation.deployment =
        SignedSemanticDeploymentV1::sign(body, &Keypair::from_seed(&[211; 32]))?;
    store.configure_semantic_deployment(&installation)?;
    refuse_new_work(&f, "after-profile-change").await?;
    assert!(service.qualify(&f.f.control, &probe).await.is_err());
    assert!(store
        .accept_setup_report(&report, &f.f.authority.mutation_fence(), now_ms()?)
        .is_err());
    assert_eq!(external_count(&f.f.path)?, 1);
    let unused_denial =
        f.f.denied_seed_named("operator-pin-does-not-unlock-work")
            .await?;
    let seed = f.f.denied_seed_named("new-profile-self-test").await?;
    let creation = f.f.command(
        "new-profile-self-test",
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new("new-profile-self-test")?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(&seed)?,
        },
    )?;
    let host = RecoverySetupHost {
        runtime: f.f.runtime.clone(),
        store: Arc::new(store),
        fence: f.f.authority.mutation_fence(),
        knowledge: Some(Arc::new(f.runtime.clone())),
        operator: Keypair::from_seed(&[211; 32]),
    };
    let replacement = RecoverySetupService::for_creation(host, &f.f.control, &creation).await?;
    assert_ne!(replacement.workflow(), &workflow);
    assert!(f.f.record(replacement.workflow())?.action.is_some());
    refuse_work_creation(&f, "operator-pin-does-not-unlock-work", &unused_denial).await?;
    assert_eq!(external_count(&f.f.path)?, 1);
    Ok(Box::new(OperatorBootstrap {
        fixture: f,
        service: replacement,
    }))
}

async fn finish_operator_bootstrap(
    mut state: Box<OperatorBootstrap>,
    creation_key: &str,
    effects: usize,
    expected_calls: u32,
) -> TestResult<RestartProof> {
    let f = &mut state.fixture;
    let service = &state.service;
    let workflow = Box::pin(f.f.ready_named(creation_key, creation_key)).await?;
    assert_eq!(service.workflow(), &workflow);
    let actor = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &f.f.control,
        RecoveryPermission::Inspect,
    )?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let prepared = store.setup_preparation(&actor, &fence, now_ms()?)?;
    assert!(matches!(prepared.command.command,
        RecoveryCommandBodyV1::ResumeWorkflow { expected_revision, .. }
        if expected_revision == f.f.record(&workflow)?.revision));
    let before = f.f.process.process("root")?.tree_calls;
    // Native preparation already owns the logical call reservation. The probe
    // and its replay must complete that same charge instead of adding another.
    assert_eq!(before, expected_calls);
    let probe = service.probe(&f.f.control, &workflow).await?;
    assert_eq!(external_count(&f.f.path)?, effects);
    let tree_calls = f.f.process.process("root")?.tree_calls;
    assert_eq!(tree_calls, before);
    let replay = store.setup_preparation(&actor, &fence, now_ms()?)?;
    assert_eq!(replay.command, prepared.command);
    assert_eq!(service.probe(&f.f.control, &workflow).await?, probe);
    assert_eq!(f.f.process.process("root")?.tree_calls, tree_calls);
    assert_eq!(
        service.qualify(&f.f.control, &probe).await.err(),
        Some(crate::recovery::RecoveryRuntimeError::RestartRequired)
    );
    let operation =
        f.f.record(&workflow)?
            .native_link
            .ok_or("native operation")?;
    Ok(RestartProof {
        path: f.f.path.clone(),
        directory: f.f._directory.take(),
        workflow,
        probe,
        operation,
        tree_calls,
        effects,
    })
}

#[tokio::test]
async fn setup_initial_operator_bootstrap_binds_after_approval_and_restarts_once() -> TestResult {
    let state = Box::pin(initial_operator_bootstrap()).await?;
    let evidence = Box::pin(finish_operator_bootstrap(state, "initial-setup", 1, 2)).await?;
    Box::pin(qualify_reopened_writer(evidence, "initial-bootstrap")).await?;
    Ok(())
}
async fn initial_operator_bootstrap() -> TestResult<Box<OperatorBootstrap>> {
    let f = KnowledgeFixture::from(super::super::semantic::native_fixture("read")?)?;
    let seed = f.f.denied_seed_named("initial-setup").await?;
    let creation = f.f.command(
        "initial-setup-create",
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new("initial-setup")?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(&seed)?,
        },
    )?;
    let host = RecoverySetupHost {
        runtime: f.f.runtime.clone(),
        store: Arc::new(f.f.authority.admission_operation_store()),
        fence: f.f.authority.mutation_fence(),
        knowledge: Some(Arc::new(f.runtime.clone())),
        operator: Keypair::from_seed(&[211; 32]),
    };
    let service = RecoverySetupService::for_creation(host, &f.f.control, &creation).await?;
    assert!(service
        .probe(&f.f.control, service.workflow())
        .await
        .is_err());
    assert_eq!(external_count(&f.f.path)?, 0);
    Ok(Box::new(OperatorBootstrap {
        fixture: f,
        service,
    }))
}

#[tokio::test]
async fn setup_preapproval_pin_binds_once_without_changing_after_capture() -> TestResult {
    let state = Box::pin(preapproval_setup_pin()).await?;
    let evidence = Box::pin(finish_operator_bootstrap(state, "early-setup", 1, 2)).await?;
    Box::pin(qualify_reopened_writer(evidence, "early-pin")).await?;
    Ok(())
}
async fn preapproval_setup_pin() -> TestResult<Box<OperatorBootstrap>> {
    let f = KnowledgeFixture::from(super::super::semantic::native_fixture("read")?)?;
    let created = new_work(&f, "early-setup").await?;
    let service = setup(&f, &created.status.workflow_id)?;
    assert!(service
        .probe(&f.f.control, service.workflow())
        .await
        .is_err());
    assert_eq!(external_count(&f.f.path)?, 0);
    Ok(Box::new(OperatorBootstrap {
        fixture: f,
        service,
    }))
}
#[tokio::test]
async fn setup_lost_live_broker_refuses_the_protected_review_route() -> TestResult {
    let f = KnowledgeFixture::from(super::super::semantic::native_fixture("read")?)?;
    let workflow = f.f.ready().await?;
    let _service = setup(&f, &workflow)?;
    assert!(f.f.runtime.review_document(&f.f.control, &workflow).is_ok());
    f.f.process.cancel("root")?;
    assert!(f
        .f
        .runtime
        .review_document(&f.f.control, &workflow)
        .is_err());
    assert_eq!(external_count(&f.f.path)?, 0);
    Ok(())
}
#[tokio::test]
async fn setup_cannot_accept_a_new_native_semantic_plan_before_ready() -> TestResult {
    let f = KnowledgeFixture::from(super::super::semantic::native_fixture("write")?)?;
    let workflow = f.f.ready().await?;
    let _service = setup(&f, &workflow)?;
    assert!(super::super::semantic::prepare(
        &f.f,
        "unqualified-native-plan",
        SemanticOutputDispositionV1::ReturnValue
    )
    .is_err());
    assert_eq!(external_count(&f.f.path)?, 0);
    Ok(())
}
#[tokio::test]
async fn setup_profile_change_between_preflight_and_native_capture_refuses() -> TestResult {
    type Change = (
        SqliteAdmissionOperationStore,
        RecoveryScopeV1,
        chio_core_types::StoreMutationFence,
    );
    let pending: Arc<Mutex<Option<Change>>> = Arc::new(Mutex::new(None));
    let observed = Arc::new(AtomicUsize::new(0));
    let holder = pending.clone();
    let observations = observed.clone();
    let observer: chio_kernel::NativeSecurityCaptureObserver = Arc::new(move |committed| {
        if committed {
            observations.fetch_add(100, Ordering::SeqCst);
            return Ok(());
        }
        let Some((store, scope, fence)) = holder
            .lock()
            .map_err(|_| KernelError::Internal("setup race".into()))?
            .take()
        else {
            return Ok(());
        };
        observations.fetch_add(1, Ordering::SeqCst);
        let mutate = || -> TestResult {
            let mut installation = store.read_semantic_installation(&scope, &fence, now_ms()?)?;
            let mut body = installation.deployment.body().clone();
            body.generation = SafeInteger::new(body.generation.get() + 1)?;
            installation.deployment =
                SignedSemanticDeploymentV1::sign(body, &Keypair::from_seed(&[211; 32]))?;
            store.configure_semantic_deployment(&installation)?;
            Ok(())
        };
        mutate().map_err(|_| KernelError::Internal("setup race".into()))
    });
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("semantic-kind"), "read")?;
    let f = KnowledgeFixture::from(RecoveryFixture::open_with_native_observer(
        directory.path().to_path_buf(),
        Some(directory),
        false,
        Some(observer),
    )?)?;
    let workflow = f.f.ready().await?;
    let service = setup(&f, &workflow)?;
    *pending.lock().map_err(|_| "setup race")? = Some((
        f.f.authority.admission_operation_store(),
        f.f.runtime.scope().clone(),
        f.f.authority.mutation_fence(),
    ));
    assert!(service.probe(&f.f.control, &workflow).await.is_err());
    assert_eq!(observed.load(Ordering::SeqCst), 1);
    assert_eq!(external_count(&f.f.path)?, 0);
    refuse_new_work(&f, "race-bypass").await?;
    f.f.execute(
        "cancel-after-race",
        RecoveryCommandBodyV1::CancelWorkflow {
            workflow_id: workflow.clone(),
            expected_revision: f.f.record(&workflow)?.revision,
        },
    )
    .await?;
    Ok(())
}
#[tokio::test]
async fn setup_missing_broker_and_failed_benign_cannot_unlock_work() -> TestResult {
    let f = KnowledgeFixture::from(super::super::semantic::native_fixture("read")?)?;
    let seed = f.f.denied_seed_named("after-failed-benign").await?;
    let workflow = f.f.ready().await?;
    assert!(RecoverySetupService::new(
        f.f.runtime.clone(),
        Arc::new(f.f.authority.admission_operation_store()),
        f.f.authority.mutation_fence(),
        None,
        Keypair::from_seed(&[211; 32]),
        workflow.clone()
    )
    .is_err());
    let service = setup(&f, &workflow)?;
    let original =
        f.f.record(&workflow)?
            .original_flow
            .ok_or("selected native source")?;
    let observed = f.f.kernel.observe_recovery_source(f.f.runtime.scope())?;
    assert_eq!(observed.snapshot(), Some(&original));
    f.f.kernel.revoke_capability(&f.f.seed.capability.id)?;
    assert!(service.probe(&f.f.control, &workflow).await.is_err());
    assert!(create_work(&f, "after-failed-benign", &seed).await.is_err());
    assert_eq!(external_count(&f.f.path)?, 0);
    Ok(())
}
