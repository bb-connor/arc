//! Product feedback uses real fenced stores, immutable artifacts and live actors.
use super::*;
use crate::recovery::RecoveryMaintenanceRuntime;
use chio_core_types::recovery::{SignedPolicyDeploymentChangeV1, SignedSemanticDeploymentV1};
use chio_security_types::semantic::{SemanticOutputDispositionV1, SemanticSelectorV1};
use chio_semantic_contracts::{compile_semantic_registry, VerificationBudget};
mod evidence_owners;
mod historical_audience;
mod lifecycle;
mod read_privacy;
mod transport_admission;

fn maintenance(f: &KnowledgeFixture) -> TestResult<RecoveryMaintenanceRuntime> {
    Ok(RecoveryMaintenanceRuntime::new(
        f.f.runtime.clone(),
        Arc::new(f.f.authority.admission_operation_store()),
        f.f.authority.mutation_fence(),
    )?)
}
fn maintain(f: &mut KnowledgeFixture) -> TestResult {
    let mut deployment = f.f.kernel.recovery_deployment(f.f.runtime.scope())?;
    let mut actors = deployment.actors.as_slice().to_vec();
    let mut permissions = actors[0].permissions.as_slice().to_vec();
    permissions.push(RecoveryPermission::Maintain);
    permissions.sort();
    actors[0].permissions = BoundedList::new(permissions.clone())?;
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    f.f.authority
        .admission_operation_store()
        .configure_recovery_deployment(&deployment)?;
    f.f.control = f.f.kernel.issue_capability(
        &f.f.approval_key.public_key(),
        ChioScope {
            grants: permissions
                .iter()
                .map(|p| ToolGrant {
                    server_id: "chio.recovery".into(),
                    tool_name: p.wire_name().into(),
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
        1200,
    )?;
    Ok(())
}
fn report(
    f: &KnowledgeFixture,
    workflow: &WorkflowId,
    attachment: ArtifactVersionRefV1,
) -> TestResult<DecisionReportV1> {
    Ok(DecisionReportV1 {
        domain_version: VersionV1,
        scope: f.f.runtime.scope().clone(),
        workflow_id: workflow.clone(),
        expected_revision: f.f.record(workflow)?.revision,
        decision: RecoveryReportedDecision::NeedsReview,
        reporter_text: ProtectedText::new("policy-feedback-secret-canary")?,
        desired_outcome: ProtectedText::new("permit the reviewed benign public title")?,
        attachments: BoundedList::new(vec![attachment])?,
    })
}
fn report_count(f: &KnowledgeFixture) -> TestResult<i64> {
    Ok(rusqlite::Connection::open(f.f.path.join("admission.db"))?.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'product-report:*'",
        [], |row| row.get(0),
    )?)
}
fn active_product_quota(f: &KnowledgeFixture, category: &str) -> TestResult<u64> {
    let payload: Vec<u8> = rusqlite::Connection::open(f.f.path.join("admission.db"))?.query_row(
        "SELECT payload FROM admission_operation_recovery_records WHERE record_key GLOB ?1",
        [format!("product-quota:{category}:*")],
        |row| row.get(0),
    )?;
    Ok(serde_json::from_slice::<SafeInteger>(&payload)?.get())
}
#[tokio::test]
async fn policy_report_retains_classification_replay_and_artifact_pins_after_restart() -> TestResult
{
    let mut f = KnowledgeFixture::new()?;
    let workflow = f.f.ready().await?;
    let attachment = publish_label(
        &f,
        "product-attachment",
        b"policy-private-attachment-canary",
        restricted_label(),
    )?;
    let report = report(&f, &workflow, attachment.clone())?;
    let command = CommandId::new("report-command")?;
    let service = maintenance(&f)?;
    let stored = service.submit_report(&f.f.control, &command, &report)?;
    assert_eq!(stored.label, restricted_label());
    assert!(stored.influence.externally_influenced && stored.influence.unknown);
    assert!(!format!("{stored:?}").contains("policy-feedback-secret-canary"));
    assert_eq!(
        service.submit_report(&f.f.control, &command, &report)?.id,
        stored.id
    );
    assert_eq!(report_count(&f)?, 1);
    assert!(f.runtime.collect(&f.f.control, &attachment).is_err());
    let independent = f.publish("unreferenced-artifact", b"unreferenced")?;
    f.runtime.collect(&f.f.control, &independent)?;
    let changed = DecisionReportV1 {
        reporter_text: ProtectedText::new("changed semantic feedback")?,
        ..report
    };
    assert_eq!(
        service
            .submit_report(&f.f.control, &command, &changed)
            .err(),
        Some(crate::recovery::RecoveryRuntimeError::Conflict)
    );
    assert_eq!(f.f.effects.load(Ordering::SeqCst), 0);
    let path = f.f.path.clone();
    let directory = f.f._directory.take();
    drop(service);
    drop(f);
    let reopened = KnowledgeFixture::from(RecoveryFixture::open(path, directory, false)?)?;
    let restored = maintenance(&reopened)?.read_report(&reopened.f.control, &stored.id)?;
    assert_eq!(restored.report, stored.report);
    assert_eq!(restored.label, restricted_label());
    assert!(restored.influence.unknown);
    assert_eq!(report_count(&reopened)?, 1);
    assert_eq!(reopened.f.effects.load(Ordering::SeqCst), 0);
    Ok(())
}
#[tokio::test]
async fn policy_report_release_rechecks_current_clearance_and_capability() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let workflow = f.f.ready().await?;
    let attachment = publish_label(
        &f,
        "audience-attachment",
        b"private-attachment",
        restricted_label(),
    )?;
    let report = report(&f, &workflow, attachment)?;
    let command = CommandId::new("audience-report")?;
    let service = maintenance(&f)?;
    let stored = service.submit_report(&f.f.control, &command, &report)?;
    let mut deployment = f.f.kernel.recovery_deployment(f.f.runtime.scope())?;
    let mut actors = deployment.actors.as_slice().to_vec();
    actors[0].preview_clearance = InformationLabel::bottom();
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    f.f.authority
        .admission_operation_store()
        .configure_recovery_deployment(&deployment)?;
    assert!(service.read_report(&f.f.control, &stored.id).is_err());
    assert!(service
        .submit_report(&f.f.control, &command, &report)
        .is_err());
    let changed = DecisionReportV1 {
        reporter_text: ProtectedText::new("probe a retained classified command")?,
        ..report.clone()
    };
    assert_eq!(
        service
            .submit_report(&f.f.control, &command, &changed)
            .err(),
        Some(crate::recovery::RecoveryRuntimeError::AuthorityDenied)
    );
    assert!(service
        .read_report(&f.f.seed.capability, &stored.id)
        .is_err());
    assert_eq!(report_count(&f)?, 1);
    assert_eq!(f.f.effects.load(Ordering::SeqCst), 0);
    Ok(())
}
#[tokio::test]
async fn policy_reports_stop_at_the_retained_tenant_domain_quota() -> TestResult {
    let f = KnowledgeFixture::new()?;
    let workflow = f.f.ready().await?;
    let attachment = f.publish("quota-attachment", b"quota-evidence")?;
    let report = report(&f, &workflow, attachment)?;
    let service = maintenance(&f)?;
    for index in 0..63 {
        service.submit_report(
            &f.f.control,
            &CommandId::new(&format!("quota-report-{index}"))?,
            &report,
        )?;
    }
    let mut other = f.f.kernel.recovery_deployment(f.f.runtime.scope())?;
    other.scope.process_id = ProcessId::new("report-quota-other-process")?;
    f.f.process.create_root(
        other.scope.process_id.as_str(),
        &f.f.seed.capability,
        chio_process::ProcessLimits {
            max_processes: 8,
            max_depth: 2,
            max_calls: 8,
            state: Default::default(),
        },
    )?;
    other.security_context =
        f.f.process
            .recovery_security_context(other.scope.process_id.as_str())?;
    other.authority_scope = recovery_authority_scope_digest(&other)?;
    let store = f.f.authority.admission_operation_store();
    store.configure_recovery_deployment(&other)?;
    let seed = f.f.process.tool_request(
        other.scope.process_id.as_str(),
        "quota-seed",
        "server-a",
        "send",
        f.f.seed.arguments.clone(),
    )?;
    let denied =
        f.f.process
            .invoke_known_only(other.scope.process_id.as_str(), "quota-seed", &seed)
            .await?;
    assert_eq!(denied.verdict, Verdict::Deny);
    assert_eq!(external_count(&f.f.path)?, 0);
    let (original, _) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &seed.request_id)?,
            &f.f.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("quota original denial")?;
    assert_eq!(
        original.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(original.dispatch_commit().is_none());
    let actor = f.f.kernel.authenticate_recovery_actor(
        &other.scope,
        &f.f.control,
        RecoveryPermission::Create,
    )?;
    let created = f.f.kernel.execute_recovery_command_with_origin(
        &actor,
        &f.f.command(
            "quota-create-other",
            RecoveryCommandBodyV1::CreateWorkflow {
                creation_key: CreationKey::new("quota-other-ticket")?,
                template: RecoveryTemplateV1::SupportTicketPublicIssue,
                request_seed: text(&seed)?,
            },
        )?,
        &f.f.process,
    )?;
    let workflow = created.workflow_id;
    let actor = f.f.kernel.authenticate_recovery_actor(
        &other.scope,
        &f.f.control,
        RecoveryPermission::Inspect,
    )?;
    let record = f.f.kernel.read_recovery_workflow(&actor, &workflow)?;
    let other_report = DecisionReportV1 {
        scope: other.scope.clone(),
        workflow_id: workflow,
        expected_revision: record.revision,
        attachments: BoundedList::new(vec![])?,
        ..report.clone()
    };
    let actor = f.f.kernel.authenticate_recovery_actor(
        &other.scope,
        &f.f.control,
        RecoveryPermission::Report,
    )?;
    store.submit_decision_report(
        &actor,
        None,
        &CommandId::new("quota-other-64")?,
        &other_report,
        &f.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    assert!(service
        .submit_report(&f.f.control, &CommandId::new("quota-report-65")?, &report)
        .is_err());
    assert!(service
        .submit_report(&f.f.control, &CommandId::new("quota-report-0")?, &report)
        .is_ok());
    assert_eq!(report_count(&f)?, 64);
    assert_eq!(f.f.effects.load(Ordering::SeqCst), 0);
    Ok(())
}
#[tokio::test]
async fn policy_selected_operator_alone_applies_exact_proposal_and_native_target() -> TestResult {
    let mut f = KnowledgeFixture::from(super::super::semantic::native_fixture("read")?)?;
    maintain(&mut f)?;
    let workflow = f.f.ready().await?;
    let attachment = f.publish(
        "policy-trajectory",
        b"benign and adversarial synthetic trajectories",
    )?;
    let service = maintenance(&f)?;
    let report = service.submit_report(
        &f.f.control,
        &CommandId::new("policy-report")?,
        &report(&f, &workflow, attachment.clone())?,
    )?;
    let (runtime, _request, p) = super::super::semantic::prepare(
        &f.f,
        "pre-change-plan",
        SemanticOutputDispositionV1::ReturnValue,
    )?;
    let (completed_runtime, completed_request, _) = super::super::semantic::prepare(
        &f.f,
        "completed-before-change",
        SemanticOutputDispositionV1::ReturnValue,
    )?;
    let completed = completed_runtime
        .execute_step(
            &f.f.process,
            "root",
            "completed-before-change",
            &completed_request,
        )
        .await
        .map_err(|error| format!("initial completed effect: {error}"))?;
    assert_eq!(completed.verdict, Verdict::Allow);
    assert_eq!(f.f.effects.load(Ordering::SeqCst), 1);
    let store = f.f.authority.admission_operation_store();
    let old = store.read_semantic_installation(
        f.f.runtime.scope(),
        &f.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    let mut target = old.clone();
    let mut deployment = old.deployment.body().clone();
    deployment.generation = SafeInteger::new(deployment.generation.get() + 1)?;
    let mut routes = deployment.routes.as_slice().to_vec();
    routes[0].operator_selectors = BoundedList::new(vec![SemanticSelectorV1::TextBytesAtMost {
        field: SemanticFieldId::new("title")?,
        bytes: SafeInteger::new(128)?,
    }])?;
    deployment.routes = NonEmptyBoundedList::new(routes)?;
    target.deployment = SignedSemanticDeploymentV1::sign(deployment, &p.operator)?;
    let base = service.policy_basis(&f.f.control)?;
    let target_basis = target.policy_basis()?;
    let trajectory = PolicyTrajectoryRefV1 {
        artifact: attachment,
        case_id: EvidenceRef::new("benign")?,
    };
    let proposal = PolicyMaintenanceProposalV1 {
        domain_version: VersionV1,
        scope: f.f.runtime.scope().clone(),
        proposal_id: ReviewId::new("policy-proposal")?,
        report_id: report.id.clone(),
        base_deployment: base.deployment,
        base_policy: base.policy,
        target_policy: target_basis.policy,
        rationale: ProtectedText::new("bound public titles without losing useful work")?,
        affected_contracts: NonEmptyBoundedList::new(
            old.deployment.body().packages.as_slice().to_vec(),
        )?,
        benign_trajectories: NonEmptyBoundedList::new(vec![trajectory.clone()])?,
        adversarial_trajectories: NonEmptyBoundedList::new(vec![PolicyTrajectoryRefV1 {
            case_id: EvidenceRef::new("adversarial")?,
            ..trajectory
        }])?,
        expected_effects: ProtectedText::new(
            "retain ordinary useful titles; refuse oversized titles",
        )?,
        rollback_policy: base.policy,
        rollback_plan: ProtectedText::new("new proposal and higher signed generation")?,
    };
    let mut missing = proposal.clone();
    missing.proposal_id = ReviewId::new("missing-trajectory-proposal")?;
    let mut cases = missing.benign_trajectories.as_slice().to_vec();
    cases[0].artifact.version = ArtifactRevisionId::new("absent-version")?;
    missing.benign_trajectories = NonEmptyBoundedList::new(cases)?;
    assert!(service.propose(&f.f.control, &missing).is_err());
    let proposed = service.propose(&f.f.control, &proposal)?;
    assert_eq!(
        service.propose(&f.f.control, &proposal)?.digest,
        proposed.digest
    );
    let mut stale_proposal = proposal.clone();
    stale_proposal.proposal_id = ReviewId::new("stale-staged-proposal")?;
    let stale_proposed = service.propose(&f.f.control, &stale_proposal)?;
    let change = PolicyDeploymentChangeV1 {
        domain_version: VersionV1,
        scope: proposal.scope.clone(),
        proposal_id: proposal.proposal_id.clone(),
        proposal_digest: proposed.digest,
        base_deployment: base.deployment,
        base_policy: base.policy,
        target_deployment: target_basis.deployment,
        target_policy: target_basis.policy,
        base_generation: PolicyGeneration::new(base.generation.get())?,
        target_generation: PolicyGeneration::new(target_basis.generation.get())?,
        writer_fence: base.writer_fence,
    };
    for foreign_key in [&f.f.approval_key, &Keypair::from_seed(&[141; 32])] {
        let foreign = SignedPolicyDeploymentChangeV1::sign(change.clone(), foreign_key)?;
        assert!(store
            .apply_reviewed_semantic_deployment(&foreign, &target)
            .is_err());
    }
    let signed = SignedPolicyDeploymentChangeV1::sign(change.clone(), &p.operator)?;
    for field in [
        "proposal_digest",
        "base_deployment",
        "target_deployment",
        "target_policy",
        "writer_fence",
    ] {
        let mut body = serde_json::to_value(&change)?;
        body[field] = serde_json::to_value([99u8; 32])?;
        let mutation: PolicyDeploymentChangeV1 = serde_json::from_value(body)?;
        let mutation = SignedPolicyDeploymentChangeV1::sign(mutation, &p.operator)?;
        assert!(
            store
                .apply_reviewed_semantic_deployment(&mutation, &target)
                .is_err(),
            "{field}"
        );
    }
    assert_eq!(
        service.policy_basis(&f.f.control)?.deployment,
        base.deployment
    );
    let applied = store.apply_reviewed_semantic_deployment(&signed, &target)?;
    assert_eq!(applied.target_deployment, target_basis.deployment);
    assert_eq!(
        active_product_quota(&f, "reports")?,
        0,
        "independent completed policy review must return the report's active intake slot"
    );
    assert_eq!(
        active_product_quota(&f, "proposals")?,
        1,
        "only the independently applied proposal may return its active intake slot"
    );
    assert_eq!(
        store.apply_reviewed_semantic_deployment(&signed, &target)?,
        applied
    );
    assert_eq!(active_product_quota(&f, "reports")?, 0);
    assert_eq!(active_product_quota(&f, "proposals")?, 1);
    let installed = store.read_semantic_installation(
        f.f.runtime.scope(),
        &f.f.authority.mutation_fence(),
        now_ms()?,
    )?;
    assert_eq!(
        chio_core::canonical_json_bytes(&installed)?,
        chio_core::canonical_json_bytes(&target)?
    );
    let compiled = compile_semantic_registry(
        &installed.deployment,
        installed.packages.as_slice(),
        &installed.operator_root,
        installed.publisher_roots.as_slice(),
        installed.exposed.as_slice(),
        &mut VerificationBudget::new(4096)?,
    )?;
    assert_eq!(
        compiled.deployment().routes.as_slice()[0]
            .operator_selectors
            .as_slice()
            .len(),
        1
    );
    assert_ne!(service.policy_basis(&f.f.control)?.policy, base.policy);
    assert!(runtime.accept_plan(&f.f.control, &p.plan).is_err());
    let stale = SignedPolicyDeploymentChangeV1::sign(
        PolicyDeploymentChangeV1 {
            proposal_id: stale_proposal.proposal_id.clone(),
            proposal_digest: stale_proposed.digest,
            ..change.clone()
        },
        &p.operator,
    )?;
    assert!(store
        .apply_reviewed_semantic_deployment(&stale, &target)
        .is_err());
    // Replay an already completed effect under the new policy without resubmission.
    let replay = completed_runtime
        .execute_step(
            &f.f.process,
            "root",
            "completed-before-change",
            &completed_request,
        )
        .await
        .map_err(|error| format!("completed replay: {error}"))?;
    assert_eq!(replay.request_id, completed.request_id);
    assert_eq!(f.f.effects.load(Ordering::SeqCst), 1);
    assert_eq!(report_count(&f)?, 1);
    let current = service.policy_basis(&f.f.control)?;
    let mut rollback = old.clone();
    let mut body = rollback.deployment.body().clone();
    body.generation = SafeInteger::new(current.generation.get() + 1)?;
    rollback.deployment = SignedSemanticDeploymentV1::sign(body, &p.operator)?;
    let rollback_identity = rollback.policy_basis()?;
    let rollback_proposal = PolicyMaintenanceProposalV1 {
        proposal_id: ReviewId::new("new-generation-rollback")?,
        base_deployment: current.deployment,
        base_policy: current.policy,
        target_policy: rollback_identity.policy,
        rollback_policy: current.policy,
        ..proposal.clone()
    };
    let rollback_proposed = service.propose(&f.f.control, &rollback_proposal)?;
    let rollback_change = PolicyDeploymentChangeV1 {
        proposal_id: rollback_proposal.proposal_id,
        proposal_digest: rollback_proposed.digest,
        base_deployment: current.deployment,
        base_policy: current.policy,
        target_deployment: rollback_identity.deployment,
        target_policy: rollback_identity.policy,
        base_generation: PolicyGeneration::new(current.generation.get())?,
        target_generation: PolicyGeneration::new(rollback_identity.generation.get())?,
        writer_fence: current.writer_fence,
        ..change.clone()
    };
    let old_rollback = SignedPolicyDeploymentChangeV1::sign(rollback_change.clone(), &p.operator)?;
    let path = f.f.path.clone();
    let directory = f.f._directory.take();
    drop(completed_runtime);
    drop(runtime);
    drop(service);
    drop(store);
    drop(f);
    let reopened = KnowledgeFixture::from(
        RecoveryFixture::open(path, directory, false)
            .map_err(|error| format!("reopen policy host: {error}"))?,
    )?;
    let (runtime, request, _) = super::super::semantic::prepare(
        &reopened.f,
        "useful-after-policy-restart",
        SemanticOutputDispositionV1::ReturnValue,
    )?;
    let response = runtime
        .execute_step(
            &reopened.f.process,
            "root",
            "useful-after-policy-restart",
            &request,
        )
        .await?;
    assert_eq!(response.verdict, Verdict::Allow, "{:?}", response.reason);
    assert_eq!(reopened.f.effects.load(Ordering::SeqCst), 2);
    let (runtime, request, _) = super::super::semantic::prepare_title(
        &reopened.f,
        "at-policy-title-limit",
        &"x".repeat(128),
    )?;
    let allowed = runtime
        .execute_step(
            &reopened.f.process,
            "root",
            "at-policy-title-limit",
            &request,
        )
        .await?;
    assert_eq!(allowed.verdict, Verdict::Allow, "{:?}", allowed.reason);
    assert_eq!(reopened.f.effects.load(Ordering::SeqCst), 3);
    let (runtime, request, _) = super::super::semantic::prepare_title(
        &reopened.f,
        "over-policy-title-limit",
        &"x".repeat(129),
    )?;
    let refused = runtime
        .execute_step(
            &reopened.f.process,
            "root",
            "over-policy-title-limit",
            &request,
        )
        .await?;
    assert_eq!(refused.verdict, Verdict::Deny);
    assert_eq!(reopened.f.effects.load(Ordering::SeqCst), 3);
    let store = reopened.f.authority.admission_operation_store();
    // An old serving-fence signature cannot authorize a fresh rollback/application.
    assert!(store
        .apply_reviewed_semantic_deployment(&stale, &target)
        .is_err());
    assert!(store
        .apply_reviewed_semantic_deployment(&old_rollback, &rollback)
        .is_err());
    let current = maintenance(&reopened)?.policy_basis(&reopened.f.control)?;
    let fresh_rollback = SignedPolicyDeploymentChangeV1::sign(
        PolicyDeploymentChangeV1 {
            writer_fence: current.writer_fence,
            ..rollback_change
        },
        &p.operator,
    )?;
    store.apply_reviewed_semantic_deployment(&fresh_rollback, &rollback)?;
    assert_eq!(
        maintenance(&reopened)?
            .policy_basis(&reopened.f.control)?
            .generation,
        rollback_identity.generation
    );
    assert_eq!(
        store.apply_reviewed_semantic_deployment(&signed, &target)?,
        applied
    );
    assert_eq!(
        maintenance(&reopened)?
            .policy_basis(&reopened.f.control)?
            .generation,
        rollback_identity.generation
    );
    assert_eq!(reopened.f.effects.load(Ordering::SeqCst), 3);
    Ok(())
}

#[tokio::test]
async fn policy_http_projection_rechecks_revoked_audience_without_canaries() -> TestResult {
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let f = KnowledgeFixture::new()?;
    let workflow = f.f.ready().await?;
    let attachment = publish_label(
        &f,
        "http-report-evidence",
        b"http-private-attachment-canary",
        restricted_label(),
    )?;
    let report = report(&f, &workflow, attachment)?;
    let router = crate::recovery::recovery_maintenance_router(Arc::new(maintenance(&f)?));
    let submit = serde_json::json!({"capability":text::<32768, _>(&f.f.control)?,"command_id":"http-report-command","report":text::<32768, _>(&report)?});
    let request = |path: &str, value: &serde_json::Value| -> TestResult<Request<Body>> {
        Ok(Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json")
            .body(Body::from(chio_core::canonical_json_bytes(value)?))?)
    };
    let response = router
        .clone()
        .oneshot(request("/v1/recovery/reports/submit", &submit)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let view: DecisionReportViewV1 =
        chio_core_types::recovery::decode_contract(&to_bytes(response.into_body(), 262144).await?)?;
    assert_eq!(view.label, restricted_label());
    assert!(view.influence.unknown);
    assert_eq!(view.report, report);
    let read =
        serde_json::json!({"capability":text::<32768, _>(&f.f.control)?,"report_id":view.id});
    let response = router
        .clone()
        .oneshot(request("/v1/recovery/reports/read", &read)?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let mut deployment = f.f.kernel.recovery_deployment(f.f.runtime.scope())?;
    let mut actors = deployment.actors.as_slice().to_vec();
    actors[0].preview_clearance = InformationLabel::bottom();
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    f.f.authority
        .admission_operation_store()
        .configure_recovery_deployment(&deployment)?;
    for (path, body) in [
        ("/v1/recovery/reports/read", &read),
        ("/v1/recovery/reports/submit", &submit),
    ] {
        let response = router.clone().oneshot(request(path, body)?).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let bytes = to_bytes(response.into_body(), 262144).await?;
        assert_eq!(bytes.as_ref(), b"recovery.authority_denied");
    }
    assert_eq!(report_count(&f)?, 1);
    assert_eq!(f.f.effects.load(Ordering::SeqCst), 0);
    Ok(())
}

mod source_integrity;
