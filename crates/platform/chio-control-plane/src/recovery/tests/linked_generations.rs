//! Same-owner retry advances only a verified effect-free closed generation.
use super::command_quotas::{protected_usage, require_live_quota_capability, QuotaTestDiagnostics};
use super::*;

fn retained_original_claim(fixture: &RecoveryFixture) -> TestResult<Vec<u8>> {
    let connection = rusqlite::Connection::open_with_flags(
        fixture.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut statement = connection.prepare(
        "SELECT record_key,scope_key,kind,version,payload
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
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(rows.len(), 1, "one permanent original claim is retained");
    Ok(chio_core::canonical_json_bytes(&rows)?)
}

fn retained_workflow(fixture: &RecoveryFixture, workflow: &WorkflowId) -> TestResult<Vec<u8>> {
    let connection = rusqlite::Connection::open_with_flags(
        fixture.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let row: (String, String, String, i64, Vec<u8>) = connection.query_row(
        "SELECT record_key,scope_key,kind,version,payload
         FROM admission_operation_recovery_records
         WHERE kind='workflow' AND record_key GLOB 'workflow:*'
           AND json_extract(payload,'$.workflow_id')=?1",
        [workflow.as_str()],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    Ok(chio_core::canonical_json_bytes(&row)?)
}

async fn cancelled_original(
    fixture: &RecoveryFixture,
) -> TestResult<(WorkflowId, Box<RecoveryCommandV1>, Vec<u8>)> {
    let seed = Box::pin(fixture.denied_seed_named("same-owner-closed-original")).await?;
    let create = fixture.command(
        "same-owner-create",
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new("same-owner-closed-original")?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(&seed)?,
        },
    )?;
    let create_actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Create,
    )?;
    super::command_quotas::require_live_creation_authority(&create_actor, &create)?;
    let created = fixture.kernel.execute_recovery_command_with_origin(
        &create_actor,
        &create,
        &fixture.process,
    )?;
    let first = Box::new(fixture.command(
        "same-owner-first-resume",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: created.workflow_id.clone(),
            expected_revision: created.revision,
        },
    )?);
    let resume_actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Resume,
    )?;
    let first_response = fixture
        .kernel
        .execute_recovery_command(&resume_actor, &first)?;
    let cancel = fixture.command(
        "same-owner-effect-free-cancel",
        RecoveryCommandBodyV1::CancelWorkflow {
            workflow_id: created.workflow_id.clone(),
            expected_revision: first_response.revision,
        },
    )?;
    let cancel_actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Cancel,
    )?;
    fixture
        .kernel
        .execute_recovery_command(&cancel_actor, &cancel)?;
    let closed = fixture.record(&created.workflow_id)?;
    assert_eq!(closed.control, WorkflowControlV1::Cancelled);
    assert!(closed.admission_closed && closed.admission.is_none());
    assert!(closed.native_link.is_none() && closed.process_reservation.is_none());
    assert!(!closed.captured && closed.historical_hold.is_none());
    assert_eq!(closed.effect, EffectObservationV1::NeverAdmitted);
    assert_eq!(external_count(&fixture.path)?, 0);
    Ok((
        created.workflow_id,
        first,
        chio_core::canonical_json_bytes(&first_response)?,
    ))
}

#[tokio::test]
async fn recovery_cancelled_original_advances_one_owner_and_keeps_historical_resume() -> TestResult
{
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = Box::new(RecoveryFixture::new(false)?);
    let (workflow, first, first_response) = Box::pin(cancelled_original(&fixture)).await?;
    let result: TestResult = Box::pin(async {
        let closed = Box::new(fixture.record(&workflow)?);
        let initial_claim = retained_original_claim(&fixture)?;
        let physical_closed = retained_workflow(&fixture, &workflow)?;
        let actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Resume,
        )?;
        require_live_quota_capability("generation control capability", &fixture.control)?;
        require_live_quota_capability("generation original capability", &closed.seed.capability)?;
        let advance = fixture.command(
            "same-owner-next-generation",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: workflow.clone(),
                expected_revision: closed.revision,
            },
        )?;
        diagnostics.phase("fresh same-owner Resume after authenticated effect-free cancellation");
        let advanced = fixture.kernel.execute_recovery_command(&actor, &advance);
        diagnostics.observe_failure(Some(&fixture), &advanced);
        let advanced = advanced?;
        assert_eq!(advanced.workflow_id, workflow);
        assert_eq!(
            advanced.control,
            WorkflowControlV1::Active,
            "a verified effect-free closed original has no next same-owner generation"
        );
        assert!(advanced.revision > closed.revision);
        let next = Box::new(fixture.record(&workflow)?);
        assert_ne!(next.step_id, closed.step_id);
        assert_ne!(next.continuation_id, closed.continuation_id);
        assert_eq!(next.creation_seed, closed.creation_seed);
        assert_eq!(next.origin, closed.origin);
        assert_eq!(retained_original_claim(&fixture)?, initial_claim);
        assert_eq!(retained_workflow(&fixture, &workflow)?, physical_closed);
        assert!(next.action.is_none() && next.approval.is_none() && next.admission.is_none());
        assert!(!next.captured && !next.admission_closed);
        assert_eq!(external_count(&fixture.path)?, 0);
        let before = protected_usage(&fixture)?;
        let replay = fixture.kernel.execute_recovery_command(&actor, &first)?;
        assert_eq!(chio_core::canonical_json_bytes(&replay)?, first_response);
        diagnostics.phase("historical Resume cannot materialize or drive the current generation");
        let _historical = Box::pin(fixture.runtime.execute_command(&fixture.control, &first)).await;
        assert_eq!(protected_usage(&fixture)?, before);
        assert_eq!(
            fixture.record(&workflow)?.continuation_id,
            next.continuation_id
        );
        assert_eq!(retained_original_claim(&fixture)?, initial_claim);
        assert_eq!(retained_workflow(&fixture, &workflow)?, physical_closed);
        assert_eq!(external_count(&fixture.path)?, 0);
        Ok(())
    })
    .await;
    diagnostics.finish(Some(&fixture), result)
}

async fn captured_original(fixture: &RecoveryFixture, unknown: bool) -> TestResult<WorkflowId> {
    let workflow = Box::pin(fixture.ready()).await?;
    fixture
        .behavior
        .store(usize::from(unknown), Ordering::SeqCst);
    Box::pin(fixture.execute(
        "nonretirable-native-original",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: workflow.clone(),
            expected_revision: fixture.record(&workflow)?.revision,
        },
    ))
    .await?;
    assert_eq!(external_count(&fixture.path)?, 1);
    let record = fixture.record(&workflow)?;
    assert!(record.captured);
    assert!(if unknown {
        matches!(record.effect, EffectObservationV1::Unknown { .. })
    } else {
        matches!(record.effect, EffectObservationV1::Complete { .. })
    });
    Ok(workflow)
}

fn require_nonretirable_generation(fixture: &RecoveryFixture, workflow: &WorkflowId) -> TestResult {
    let current = Box::new(fixture.record(workflow)?);
    let original = retained_original_claim(fixture)?;
    let physical = retained_workflow(fixture, workflow)?;
    let native = current
        .native_link
        .as_ref()
        .ok_or("captured native link absent")?;
    let native_id =
        chio_kernel::admission_operation::AdmissionOperationId::from_persisted(native.as_str())?;
    let operation = fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(&native_id)?
        .ok_or("captured original operation absent")?;
    assert!(operation.dispatch_commit().is_some());
    let operation_bytes = chio_core::canonical_json_bytes(&operation.to_persisted())?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Resume,
    )?;
    require_live_quota_capability("nonretirable control capability", &fixture.control)?;
    let command = fixture.command(
        "forbidden-next-captured-generation",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: workflow.clone(),
            expected_revision: current.revision,
        },
    )?;
    let _response = fixture.kernel.execute_recovery_command(&actor, &command);
    let after = fixture.record(workflow)?;
    assert_eq!(after.step_id, current.step_id);
    assert_eq!(after.continuation_id, current.continuation_id);
    assert_eq!(after.origin, current.origin);
    assert_eq!(after.effect, current.effect);
    assert_eq!(after.captured, current.captured);
    assert_eq!(retained_original_claim(fixture)?, original);
    assert_eq!(retained_workflow(fixture, workflow)?, physical);
    let after_operation = fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(&native_id)?
        .ok_or("original operation disappeared")?;
    assert_eq!(
        chio_core::canonical_json_bytes(&after_operation.to_persisted())?,
        operation_bytes
    );
    assert_eq!(external_count(&fixture.path)?, 1);
    Ok(())
}

#[tokio::test]
async fn recovery_unknown_original_never_advances_a_retry_generation() -> TestResult {
    let fixture = Box::new(RecoveryFixture::new(false)?);
    let workflow = Box::pin(captured_original(&fixture, true)).await?;
    require_nonretirable_generation(&fixture, &workflow)
}

#[tokio::test]
async fn recovery_completed_captured_original_never_advances_a_retry_generation() -> TestResult {
    let fixture = Box::new(RecoveryFixture::new(false)?);
    let workflow = Box::pin(captured_original(&fixture, false)).await?;
    require_nonretirable_generation(&fixture, &workflow)
}
