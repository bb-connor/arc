//! An effect-free closed original may acquire one new remediation owner.
use super::command_quotas::{
    protected_usage, require_live_creation_authority, QuotaTestDiagnostics,
};
use super::*;

fn immutable_original_claim(fixture: &RecoveryFixture) -> TestResult<Vec<u8>> {
    let connection = rusqlite::Connection::open_with_flags(
        fixture.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut statement = connection.prepare(
        "SELECT record_key,scope_key,kind,version,payload,native_namespace,native_request
         FROM admission_operation_recovery_records
         WHERE record_key GLOB 'recovery-origin:*' ORDER BY record_key",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(rows.len(), 1, "the first original claim remains permanent");
    Ok(chio_core::canonical_json_bytes(&rows)?)
}

fn owned_workflow_rows(fixture: &RecoveryFixture, workflow: &WorkflowId) -> TestResult<Vec<u8>> {
    let connection = rusqlite::Connection::open_with_flags(
        fixture.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let scope = chio_core::sha256_hex(&chio_core::canonical_json_bytes(fixture.runtime.scope())?);
    let keys = [
        format!("workflow:{scope}:{}", workflow.as_str()),
        format!("workflow-quota:{scope}:{}", workflow.as_str()),
        format!("recovery-workflow-allocation:{scope}:{}", workflow.as_str()),
    ];
    let mut statement = connection.prepare(
        "SELECT record_key,scope_key,kind,version,payload,native_namespace,native_request
         FROM admission_operation_recovery_records
         WHERE record_key IN (?1,?2,?3) ORDER BY record_key",
    )?;
    let rows = statement
        .query_map(rusqlite::params![keys[0], keys[1], keys[2]], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Option<String>>(5)?,
                row.get::<_, Option<String>>(6)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(rows.len(), 3, "the real workflow owns its quota and lease");
    Ok(chio_core::canonical_json_bytes(&rows)?)
}

fn replacement_command(
    fixture: &RecoveryFixture,
    record: &RecoveryWorkflowRecordV1,
    identity: &str,
) -> TestResult<RecoveryCommandV1> {
    fixture.command(
        identity,
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new(identity)?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: record.creation_seed.clone(),
        },
    )
}

async fn approve_replacement(
    fixture: &RecoveryFixture,
    create: &RecoveryCommandV1,
) -> TestResult<WorkflowId> {
    let result = Box::pin(fixture.runtime.execute_command(&fixture.control, create)).await?;
    let workflow = result.status.workflow_id;
    let record = fixture.record(&workflow)?;
    let action = record.action.as_ref().ok_or("replacement action absent")?;
    let bytes = recovery_digest(
        chio_core_types::recovery::RecoveryDigestDomain::ActionIntent,
        action,
    )?;
    let offer = format!(
        "offer:{}",
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    Box::pin(fixture.execute(
        "replacement-select",
        RecoveryCommandBodyV1::SelectOffer {
            workflow_id: workflow.clone(),
            expected_revision: record.revision,
            offer_id: OfferId::new(&offer)?,
        },
    ))
    .await?;
    let intent = fixture
        .runtime
        .approval_intent(&fixture.control, &workflow)?;
    let record = fixture.record(&workflow)?;
    let action = record
        .action
        .as_ref()
        .ok_or("replacement review action absent")?;
    let coverage = AuthorityCoverageAttestationV1 {
        schema: AuthorityCoverageSchema::V1,
        version: VersionV1,
        scope: fixture.runtime.scope().clone(),
        approval_intent: intent.approval_intent.clone(),
        challenge: intent.challenge.clone(),
        action_intent: intent.action_intent,
        authorization_requirements: intent.authorization_requirements,
        source_basis: action.basis,
        issuer_id: IssuerId::new("reviewer")?,
        principal: PrincipalId::new("reviewer")?,
        obligations: intent.obligations.clone(),
        issued_at_unix_ms: intent.issued_at_unix_ms,
        expires_at_unix_ms: intent.expires_at_unix_ms,
    };
    let submission = RecoveryApprovalSubmissionV1 {
        intent,
        coverage: NonEmptyBoundedList::new(vec![SignedAuthorityCoverageAttestationV1::sign(
            coverage,
            &fixture.approval_key,
        )?])?,
    };
    Box::pin(fixture.execute(
        "replacement-approve",
        RecoveryCommandBodyV1::SubmitApproval {
            workflow_id: workflow.clone(),
            expected_revision: record.revision,
            approval: text(&submission)?,
        },
    ))
    .await?;
    Ok(workflow)
}

#[tokio::test]
async fn recovery_cancelled_never_admitted_original_can_acquire_one_new_workflow() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = Box::new(RecoveryFixture::new(false)?);
    let result: TestResult = Box::pin(async {
        let seed = Box::pin(fixture.denied_seed_named("closed-original-replacement")).await?;
        let create = fixture.command(
            "initial-no-effect-owner",
            RecoveryCommandBodyV1::CreateWorkflow {
                creation_key: CreationKey::new("initial-no-effect-owner")?,
                template: RecoveryTemplateV1::SupportTicketPublicIssue,
                request_seed: text(&seed)?,
            },
        )?;
        let creator = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Create,
        )?;
        require_live_creation_authority(&creator, &create)?;
        let initial = fixture.kernel.execute_recovery_command_with_origin(
            &creator,
            &create,
            &fixture.process,
        )?;
        let first_resume = fixture.command(
            "initial-owner-lost-ack-resume",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: initial.workflow_id.clone(),
                expected_revision: initial.revision,
            },
        )?;
        let resumer = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Resume,
        )?;
        let first_reply = fixture
            .kernel
            .execute_recovery_command(&resumer, &first_resume)?;
        let cancel = fixture.command(
            "close-unused-original-owner",
            RecoveryCommandBodyV1::CancelWorkflow {
                workflow_id: initial.workflow_id.clone(),
                expected_revision: first_reply.revision,
            },
        )?;
        let canceller = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Cancel,
        )?;
        fixture
            .kernel
            .execute_recovery_command(&canceller, &cancel)?;
        let closed = Box::new(fixture.record(&initial.workflow_id)?);
        assert_eq!(closed.control, WorkflowControlV1::Cancelled);
        assert!(closed.admission_closed && closed.admission.is_none());
        assert!(closed.native_link.is_none() && closed.process_reservation.is_none());
        assert!(!closed.captured && closed.historical_hold.is_none());
        assert_eq!(closed.effect, EffectObservationV1::NeverAdmitted);
        assert_eq!(external_count(&fixture.path)?, 0);
        let claim = immutable_original_claim(&fixture)?;
        let old_rows = owned_workflow_rows(&fixture, &initial.workflow_id)?;
        let process_calls = fixture.process.process("root")?.tree_calls;
        let next = replacement_command(&fixture, &closed, "replacement-no-effect-owner")?;
        require_live_creation_authority(&creator, &next)?;
        diagnostics.phase("new workflow for the exact cancelled never-admitted original");
        let result =
            fixture
                .kernel
                .execute_recovery_command_with_origin(&creator, &next, &fixture.process);
        diagnostics.observe_failure(Some(&fixture), &result);
        let accepted = result?;
        assert_ne!(accepted.workflow_id, initial.workflow_id);
        let replacement = fixture.record(&accepted.workflow_id)?;
        assert_eq!(replacement.control, WorkflowControlV1::Active);
        assert_eq!(replacement.creation_seed, closed.creation_seed);
        assert_eq!(replacement.origin, closed.origin);
        assert_ne!(replacement.step_id, closed.step_id);
        assert_ne!(replacement.continuation_id, closed.continuation_id);
        assert!(!replacement.captured && !replacement.admission_closed);
        assert!(replacement.admission.is_none() && replacement.native_link.is_none());
        assert_eq!(immutable_original_claim(&fixture)?, claim);
        assert_eq!(
            owned_workflow_rows(&fixture, &initial.workflow_id)?,
            old_rows
        );
        assert_eq!(fixture.process.process("root")?.tree_calls, process_calls);
        assert_eq!(external_count(&fixture.path)?, 0);
        let competitor = replacement_command(&fixture, &closed, "second-active-original-owner")?;
        require_live_creation_authority(&creator, &competitor)?;
        let before = protected_usage(&fixture)?;
        assert!(matches!(
            fixture.kernel.execute_recovery_command_with_origin(
                &creator,
                &competitor,
                &fixture.process,
            ),
            Err(RecoveryCommandError::Conflict)
        ));
        assert_eq!(protected_usage(&fixture)?, before);
        let reply = fixture
            .kernel
            .execute_recovery_command(&resumer, &first_resume)?;
        assert_eq!(
            chio_core::canonical_json_bytes(&reply)?,
            chio_core::canonical_json_bytes(&first_reply)?
        );
        let _old_driver = Box::pin(
            fixture
                .runtime
                .execute_command(&fixture.control, &first_resume),
        )
        .await;
        assert_eq!(protected_usage(&fixture)?, before);
        assert_eq!(
            owned_workflow_rows(&fixture, &initial.workflow_id)?,
            old_rows
        );
        assert_eq!(
            fixture.record(&accepted.workflow_id)?.continuation_id,
            replacement.continuation_id
        );
        assert_eq!(immutable_original_claim(&fixture)?, claim);
        assert_eq!(fixture.process.process("root")?.tree_calls, process_calls);
        assert_eq!(external_count(&fixture.path)?, 0);
        diagnostics.phase("the single successor captures and completes exactly one real effect");
        let ready = Box::pin(approve_replacement(&fixture, &next)).await?;
        assert_eq!(ready, accepted.workflow_id);
        let completed = Box::pin(fixture.execute(
            "replacement-resume",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: ready.clone(),
                expected_revision: fixture.record(&ready)?.revision,
            },
        ))
        .await?;
        assert!(matches!(
            completed.status.effect,
            EffectObservationV1::Complete { .. }
        ));
        let replacement = fixture.record(&ready)?;
        assert!(replacement.captured);
        assert_eq!(
            replacement.effect.applied_effects(),
            Some(SafeInteger::new(1)?)
        );
        assert!(matches!(
            replacement.release,
            ReleaseDispositionV1::Released { .. }
        ));
        assert_eq!(
            fixture.process.process("root")?.tree_calls,
            process_calls + 1
        );
        assert_eq!(external_count(&fixture.path)?, 1);
        assert_eq!(
            owned_workflow_rows(&fixture, &initial.workflow_id)?,
            old_rows
        );
        assert_eq!(immutable_original_claim(&fixture)?, claim);
        let after = protected_usage(&fixture)?;
        let _ = Box::pin(
            fixture
                .runtime
                .execute_command(&fixture.control, &first_resume),
        )
        .await;
        assert_eq!(protected_usage(&fixture)?, after);
        assert_eq!(external_count(&fixture.path)?, 1);
        Ok(())
    })
    .await;
    diagnostics.finish(Some(&fixture), result)
}

async fn captured_original_cannot_transfer(unknown: bool) -> TestResult {
    let fixture = Box::new(RecoveryFixture::new(false)?);
    let workflow = Box::pin(fixture.ready()).await?;
    fixture
        .behavior
        .store(usize::from(unknown), Ordering::SeqCst);
    Box::pin(fixture.execute(
        "captured-original-owner",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: workflow.clone(),
            expected_revision: fixture.record(&workflow)?.revision,
        },
    ))
    .await?;
    let record = Box::new(fixture.record(&workflow)?);
    assert!(record.captured);
    assert_eq!(external_count(&fixture.path)?, 1);
    let native = record
        .native_link
        .as_ref()
        .ok_or("captured original link absent")?;
    let native =
        chio_kernel::admission_operation::AdmissionOperationId::from_persisted(native.as_str())?;
    let original = fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(&native)?
        .ok_or("captured original operation absent")?;
    assert!(original.dispatch_commit().is_some());
    assert_eq!(
        original.state(),
        if unknown {
            AdmissionOperationState::OutcomeUnknownAfterDispatch
        } else {
            AdmissionOperationState::Completed
        }
    );
    let original_bytes = chio_core::canonical_json_bytes(&original.to_persisted())?;
    let claim = immutable_original_claim(&fixture)?;
    let old_rows = owned_workflow_rows(&fixture, &workflow)?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Create,
    )?;
    let next = replacement_command(&fixture, &record, "forbidden-captured-owner-transfer")?;
    require_live_creation_authority(&actor, &next)?;
    let before = protected_usage(&fixture)?;
    assert!(matches!(
        fixture
            .kernel
            .execute_recovery_command_with_origin(&actor, &next, &fixture.process,),
        Err(RecoveryCommandError::Conflict)
    ));
    assert_eq!(protected_usage(&fixture)?, before);
    assert_eq!(immutable_original_claim(&fixture)?, claim);
    assert_eq!(owned_workflow_rows(&fixture, &workflow)?, old_rows);
    let after = fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(&native)?
        .ok_or("captured original operation disappeared")?;
    assert_eq!(
        chio_core::canonical_json_bytes(&after.to_persisted())?,
        original_bytes
    );
    assert_eq!(external_count(&fixture.path)?, 1);
    Ok(())
}

#[tokio::test]
async fn recovery_completed_captured_original_refuses_new_owner_transfer() -> TestResult {
    Box::pin(captured_original_cannot_transfer(false)).await
}

#[tokio::test]
async fn recovery_unknown_captured_original_refuses_new_owner_transfer() -> TestResult {
    Box::pin(captured_original_cannot_transfer(true)).await
}
