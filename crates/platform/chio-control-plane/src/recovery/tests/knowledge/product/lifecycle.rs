//! Active review slots can retire without deleting classified historical bytes.
use super::*;

fn records(f: &KnowledgeFixture) -> TestResult<Vec<(String, u64, Vec<u8>)>> {
    let connection = rusqlite::Connection::open(f.f.path.join("admission.db"))?;
    let mut statement = connection.prepare("SELECT record_key,version,payload FROM admission_operation_recovery_records ORDER BY record_key")?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, Vec<u8>>(2)?,
        ))
    })?;
    let values = rows.collect::<Result<Vec<_>, _>>()?;
    values
        .into_iter()
        .map(|(key, version, payload)| Ok((key, u64::try_from(version)?, payload)))
        .collect()
}

#[tokio::test]
async fn policy_report_archive_returns_one_active_slot_and_preserves_immutable_history(
) -> TestResult {
    let mut f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    maintain(&mut f)?;
    let workflow = Box::pin(f.f.ready()).await?;
    let attachment = f.publish("terminal-report-evidence", b"classified terminal evidence")?;
    let input = report(&f, &workflow, attachment.clone())?;
    let service = maintenance(&f)?;
    let first = service.submit_report(
        &f.f.control,
        &CommandId::new("terminal-first-report")?,
        &input,
    )?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let actor = f.actor(RecoveryPermission::Maintain)?;
    let reader = f.actor(RecoveryPermission::KnowledgeRead)?;
    let inspector = f.actor(RecoveryPermission::Inspect)?;
    let before = records(&f)?;
    assert!(store
        .archive_decision_report(&inspector, Some(&reader), &first.id, &fence, now_ms()?)
        .is_err());
    assert_eq!(records(&f)?, before);
    assert_eq!(active_product_quota(&f, "reports")?, 1);
    assert_eq!(service.read_report(&f.f.control, &first.id)?, first);
    let archived =
        store.archive_decision_report(&actor, Some(&reader), &first.id, &fence, now_ms()?);
    assert!(
        archived.is_ok(),
        "archive_decision_report refused after the exact native report, current reader, Maintain actor and active slot were verified: {archived:?}"
    );
    assert_eq!(archived?, first);
    assert_eq!(active_product_quota(&f, "reports")?, 0);
    let terminal = records(&f)?;
    assert_eq!(
        store.archive_decision_report(&actor, Some(&reader), &first.id, &fence, now_ms()?)?,
        first
    );
    assert_eq!(
        records(&f)?,
        terminal,
        "terminal replay must not append writes"
    );
    assert!(f.runtime.collect(&f.f.control, &attachment).is_err());
    assert_eq!(service.read_report(&f.f.control, &first.id)?, first);
    // Historical evidence beyond the old lifetime ceiling is ordinary use.
    // At most one report is active throughout this campaign.
    for index in 0..65 {
        let stored = service.submit_report(
            &f.f.control,
            &CommandId::new(&format!("terminal-report-{index}"))?,
            &input,
        )?;
        assert_eq!(active_product_quota(&f, "reports")?, 1);
        store.archive_decision_report(&actor, Some(&reader), &stored.id, &fence, now_ms()?)?;
        assert_eq!(active_product_quota(&f, "reports")?, 0);
    }
    assert_eq!(report_count(&f)?, 66);
    assert_eq!(external_count(&f.f.path)?, 0);
    Ok(())
}

pub(super) fn proposal(
    f: &KnowledgeFixture,
    service: &RecoveryMaintenanceRuntime,
    report: &chio_store_sqlite::admission_operation_store::StoredDecisionReportV1,
    artifact: &ArtifactVersionRefV1,
) -> TestResult<PolicyMaintenanceProposalV1> {
    let base = service.policy_basis(&f.f.control)?;
    let installation =
        f.f.authority
            .admission_operation_store()
            .read_semantic_installation(
                f.f.runtime.scope(),
                &f.f.authority.mutation_fence(),
                now_ms()?,
            )?;
    let case = PolicyTrajectoryRefV1 {
        artifact: artifact.clone(),
        case_id: EvidenceRef::new("terminal-benign")?,
    };
    Ok(PolicyMaintenanceProposalV1 {
        domain_version: VersionV1,
        scope: f.f.runtime.scope().clone(),
        proposal_id: ReviewId::new("terminal-proposal")?,
        report_id: report.id.clone(),
        base_deployment: base.deployment,
        base_policy: base.policy,
        target_policy: PolicyDigest::from_bytes([71; 32]),
        rationale: ProtectedText::new("independent terminal review")?,
        affected_contracts: NonEmptyBoundedList::new(
            installation.deployment.body().packages.as_slice().to_vec(),
        )?,
        benign_trajectories: NonEmptyBoundedList::new(vec![case.clone()])?,
        adversarial_trajectories: NonEmptyBoundedList::new(vec![PolicyTrajectoryRefV1 {
            case_id: EvidenceRef::new("terminal-adversarial")?,
            ..case
        }])?,
        expected_effects: ProtectedText::new("no policy change before independent application")?,
        rollback_policy: base.policy,
        rollback_plan: ProtectedText::new("retain old authenticated policy evidence")?,
    })
}

#[tokio::test]
async fn policy_proposal_archive_keeps_active_report_dependencies_then_returns_exact_capacity(
) -> TestResult {
    let mut f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    maintain(&mut f)?;
    let workflow = Box::pin(f.f.ready()).await?;
    let attachment = f.publish(
        "terminal-policy-trajectory",
        b"bounded classified trajectory",
    )?;
    let service = maintenance(&f)?;
    let report = service.submit_report(
        &f.f.control,
        &CommandId::new("terminal-policy-report")?,
        &report(&f, &workflow, attachment.clone())?,
    )?;
    let proposal = proposal(&f, &service, &report, &attachment)?;
    let first = service.propose(&f.f.control, &proposal)?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let actor = f.actor(RecoveryPermission::Maintain)?;
    let reader = f.actor(RecoveryPermission::KnowledgeRead)?;
    let inspector = f.actor(RecoveryPermission::Inspect)?;
    let before = records(&f)?;
    assert!(store
        .archive_decision_report(&actor, Some(&reader), &report.id, &fence, now_ms()?)
        .is_err());
    assert!(store
        .archive_policy_maintenance(
            &inspector,
            &reader,
            &proposal.proposal_id,
            &fence,
            now_ms()?
        )
        .is_err());
    assert_eq!(records(&f)?, before);
    assert_eq!(active_product_quota(&f, "proposals")?, 1);
    assert_eq!(service.propose(&f.f.control, &proposal)?, first);
    let archived =
        store.archive_policy_maintenance(&actor, &reader, &proposal.proposal_id, &fence, now_ms()?);
    assert!(
        archived.is_ok(),
        "archive_policy_maintenance refused after the exact native proposal, current evidence reader, Maintain actor and active slot were verified: {archived:?}"
    );
    assert_eq!(archived?, first);
    assert_eq!(active_product_quota(&f, "proposals")?, 0);
    let retired = records(&f)?;
    assert_eq!(
        store.archive_policy_maintenance(
            &actor,
            &reader,
            &proposal.proposal_id,
            &fence,
            now_ms()?
        )?,
        first
    );
    assert_eq!(records(&f)?, retired);
    for index in 0..17 {
        let input = PolicyMaintenanceProposalV1 {
            proposal_id: ReviewId::new(&format!("terminal-proposal-{index}"))?,
            ..proposal.clone()
        };
        service.propose(&f.f.control, &input)?;
        store.archive_policy_maintenance(&actor, &reader, &input.proposal_id, &fence, now_ms()?)?;
        assert_eq!(active_product_quota(&f, "proposals")?, 0);
    }
    store.archive_decision_report(&actor, Some(&reader), &report.id, &fence, now_ms()?)?;
    assert_eq!(active_product_quota(&f, "reports")?, 0);
    assert!(f.runtime.collect(&f.f.control, &attachment).is_err());
    assert_eq!(external_count(&f.f.path)?, 0);
    Ok(())
}

#[tokio::test]
async fn policy_shared_artifact_pin_preserves_both_native_process_owners_until_each_retires(
) -> TestResult {
    let mut first = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    maintain(&mut first)?;
    let first_workflow = Box::pin(first.f.ready()).await?;
    let artifact = first.publish("shared-policy-evidence", b"shared classified trajectory")?;
    let first_service = maintenance(&first)?;
    let first_input = DecisionReportV1 {
        attachments: BoundedList::new(vec![])?,
        ..report(&first, &first_workflow, artifact.clone())?
    };
    let first_report = first_service.submit_report(
        &first.f.control,
        &CommandId::new("shared-first-report")?,
        &first_input,
    )?;
    let first_proposal = proposal(&first, &first_service, &first_report, &artifact)?;
    let first_stored = first_service.propose(&first.f.control, &first_proposal)?;
    let first_knowledge = first.runtime.clone();
    let first_scope = first.f.runtime.scope().clone();
    let store = first.f.authority.admission_operation_store();
    let fence = first.f.authority.mutation_fence();
    let mut deployment = first.f.kernel.recovery_deployment(&first_scope)?;
    let mut semantic = store.read_semantic_installation(&first_scope, &fence, now_ms()?)?;
    let KnowledgeFixture { mut f, .. } = first;
    deployment.scope.process_id = ProcessId::new("shared-evidence-second-process")?;
    // Separate roots need separate native lineage identities. Reusing the
    // first root's capability would intentionally select the same native route.
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
        "the second genuine process must have independent native route custody"
    );
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    store.configure_recovery_deployment(&deployment)?;
    semantic.security_context = deployment.security_context.clone();
    let mut semantic_body = semantic.deployment.body().clone();
    semantic_body.scope = deployment.scope.clone();
    semantic_body.context_binding = chio_core_types::recovery::semantic_content_digest(&(
        recovery_flow_key(&deployment.security_context),
        deployment.security_context.as_v1().context_generation(),
    ))?;
    semantic.deployment =
        SignedSemanticDeploymentV1::sign(semantic_body, &Keypair::from_seed(&[211; 32]))?;
    store.configure_semantic_deployment(&semantic)?;
    f.runtime = Arc::new(crate::recovery::RecoveryRuntime::new(
        f.kernel.clone(),
        f.process.clone(),
        f.runtime.flow.clone(),
        deployment.scope.clone(),
        f.runtime.signer.clone(),
    )?);
    // Establish this independent context through an ordinary mediated input.
    // Constructing a root alone does not create its native source observation.
    let original = Box::pin(f.denied_seed_named("shared-second-source-initialization"))
        .await
        .map_err(|error| format!("second ordinary native source input: {error}"))?;
    let observation = store.observe_security_participant_flow(
        &deployment.native_authority,
        &recovery_flow_key(&deployment.security_context),
        &fence,
        now_ms()?,
    )?;
    assert!(observation.snapshot().is_some(), "the independent process needs a real native input observation before its knowledge producer is configured");
    let (operation, retained) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &original.request_id)?,
            &fence,
            now_ms()?,
        )?
        .ok_or("second ordinary input custody absent")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(operation.dispatch_commit().is_none());
    retained.validate_request_material(&original)?;
    retained.validate_native_security_context(&deployment.security_context)?;
    retained.validate_native_security_authority(&deployment.native_authority)?;
    let second = KnowledgeFixture::from(f)
        .map_err(|error| format!("second knowledge producer after real native input: {error}"))?;
    let second_workflow = Box::pin(
        second
            .f
            .ready_named("shared-second-original", "shared-second-original"),
    )
    .await?;
    let second_service = maintenance(&second)?;
    let second_report = second_service.submit_report(
        &second.f.control,
        &CommandId::new("shared-second-report")?,
        &DecisionReportV1 {
            attachments: BoundedList::new(vec![])?,
            ..report(&second, &second_workflow, artifact.clone())?
        },
    )?;
    let second_proposal = proposal(&second, &second_service, &second_report, &artifact)?;
    let second_stored = second_service.propose(&second.f.control, &second_proposal)?;
    assert_eq!(first_proposal.proposal_id, second_proposal.proposal_id);
    assert_ne!(first_proposal.scope, second_proposal.scope);
    assert_ne!(first_stored.digest, second_stored.digest);
    assert_eq!(
        store.inspect_product_evidence_owner_count(&artifact, &fence, now_ms()?)?,
        2,
        "one physical pin must retain two independently scoped product owners"
    );
    let first_actor = second.f.kernel.authenticate_recovery_actor(
        &first_scope,
        &second.f.control,
        RecoveryPermission::Maintain,
    )?;
    let first_reader = second.f.kernel.authenticate_recovery_actor(
        &first_scope,
        &second.f.control,
        RecoveryPermission::KnowledgeRead,
    )?;
    let second_actor = second.actor(RecoveryPermission::Maintain)?;
    let second_reader = second.actor(RecoveryPermission::KnowledgeRead)?;
    store.archive_policy_maintenance(
        &first_actor,
        &first_reader,
        &first_proposal.proposal_id,
        &fence,
        now_ms()?,
    )?;
    store.reclaim_archived_policy_evidence(
        &first_actor,
        &first_reader,
        &first_proposal.proposal_id,
        &fence,
        now_ms()?,
    )?;
    assert!(
        first_knowledge
            .collect(&second.f.control, &artifact)
            .is_err(),
        "one terminal process must not unpin the other process's active proposal"
    );
    assert_eq!(
        second_service.propose(&second.f.control, &second_proposal)?,
        second_stored
    );
    let before_replay = records(&second)?;
    store.reclaim_archived_policy_evidence(
        &first_actor,
        &first_reader,
        &first_proposal.proposal_id,
        &fence,
        now_ms()?,
    )?;
    assert_eq!(records(&second)?, before_replay);
    store.archive_policy_maintenance(
        &second_actor,
        &second_reader,
        &second_proposal.proposal_id,
        &fence,
        now_ms()?,
    )?;
    store.reclaim_archived_policy_evidence(
        &second_actor,
        &second_reader,
        &second_proposal.proposal_id,
        &fence,
        now_ms()?,
    )?;
    first_knowledge.collect(&second.f.control, &artifact)?;
    assert_eq!(external_count(&second.f.path)?, 0);
    Ok(())
}

// Every artifact/source/admin precondition is real and independently exercised.
#[tokio::test]
async fn reclaimed_policy_evidence_replays_retained_sources_without_repinning_collected_bytes(
) -> TestResult {
    let mut f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    maintain(&mut f)?;
    let workflow = Box::pin(f.f.ready()).await?;
    let artifact = f.publish(
        "reclaimed-policy-evidence",
        b"retired native policy trajectory",
    )?;
    let input = DecisionReportV1 {
        attachments: BoundedList::new(vec![])?,
        ..report(&f, &workflow, artifact.clone())?
    };
    let service = maintenance(&f)?;
    let command = CommandId::new("reclaimed-policy-report")?;
    let report = service.submit_report(&f.f.control, &command, &input)?;
    assert_eq!(service.read_report(&f.f.control, &report.id)?, report);
    let proposal = proposal(&f, &service, &report, &artifact)?;
    let stored = service.propose(&f.f.control, &proposal)?;
    assert_eq!(service.propose(&f.f.control, &proposal)?, stored);
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    assert_eq!(
        store.inspect_product_evidence_owner_count(&artifact, &fence, now_ms()?)?,
        1,
        "the genuine proposal must own its complete deduplicated trajectory before retirement",
    );
    let actor = f.actor(RecoveryPermission::Maintain)?;
    let reader = f.actor(RecoveryPermission::KnowledgeRead)?;
    let calls = f.f.process.process("root")?.tree_calls;
    assert_eq!(external_count(&f.f.path)?, 0);
    assert!(f.runtime.collect(&f.f.control, &artifact).is_err());
    store
        .archive_policy_maintenance(&actor, &reader, &proposal.proposal_id, &fence, now_ms()?)
        .map_err(|error| format!("reclaimed evidence phase=actual archive: {error}"))?;
    assert_eq!(active_product_quota(&f, "proposals")?, 0);
    assert_eq!(
        store.inspect_product_evidence_owner_count(&artifact, &fence, now_ms()?)?,
        1,
        "queue archive alone must retain the evidence owner",
    );
    store
        .reclaim_archived_policy_evidence(&actor, &reader, &proposal.proposal_id, &fence, now_ms()?)
        .map_err(|error| {
            format!("reclaimed evidence phase=independent scoped reclamation: {error}")
        })?;
    assert_eq!(
        store.inspect_product_evidence_owner_count(&artifact, &fence, now_ms()?)?,
        0,
        "only the actual separate native reclaim transition can retire this owner",
    );
    f.runtime
        .collect(&f.f.control, &artifact)
        .map_err(|error| format!("reclaimed evidence phase=actual collection: {error}"))?;
    let before = records(&f)?;
    assert_eq!(
        service.propose(&f.f.control, &proposal)?,
        stored,
        "exact lost-ack replay after collection must return retained data without a new pin",
    );
    assert_eq!(
        service.submit_report(&f.f.control, &command, &input)?,
        report
    );
    assert_eq!(service.read_report(&f.f.control, &report.id)?, report);
    store.reclaim_archived_policy_evidence(
        &actor,
        &reader,
        &proposal.proposal_id,
        &fence,
        now_ms()?,
    )?;
    assert_eq!(
        records(&f)?,
        before,
        "retained replay must append no source or owner"
    );
    assert_eq!(active_product_quota(&f, "proposals")?, 0);
    assert_eq!(active_product_quota(&f, "reports")?, 1);
    let fresh = PolicyMaintenanceProposalV1 {
        proposal_id: ReviewId::new("fresh-cannot-repin-collected-evidence")?,
        ..proposal
    };
    fresh.validate()?;
    assert!(
        service.propose(&f.f.control, &fresh).is_err(),
        "retained metadata is not Available authority for fresh evidence intake",
    );
    assert_eq!(records(&f)?, before);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert_eq!(external_count(&f.f.path)?, 0);
    Ok(())
}
