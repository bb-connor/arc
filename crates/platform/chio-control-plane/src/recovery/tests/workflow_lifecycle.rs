//! Closed original identities retain exact replay while live workflow capacity is reclaimed.
use super::command_quotas::{
    protected_usage, require_live_creation_authority, require_live_quota_capability,
    QuotaTestDiagnostics,
};
use super::*;

struct ClosedWorkflowReplay {
    workflow: WorkflowId,
    create: RecoveryCommandV1,
    create_response: Vec<u8>,
    cancel: RecoveryCommandV1,
    cancel_response: Vec<u8>,
}

fn connection(fixture: &RecoveryFixture) -> TestResult<rusqlite::Connection> {
    Ok(rusqlite::Connection::open(
        fixture.path.join("admission.db"),
    )?)
}

async fn create_and_close_workflow(
    fixture: &RecoveryFixture,
    index: usize,
    diagnostics: &QuotaTestDiagnostics,
) -> TestResult<Box<ClosedWorkflowReplay>> {
    let creation = format!("closed-original-{index}");
    let seed = Box::pin(fixture.denied_seed_named(&creation)).await?;
    let create = fixture.command(
        &format!("create-closed-original-{index}"),
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new(&creation)?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(&seed)?,
        },
    )?;
    let create_actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Create,
    )?;
    require_live_creation_authority(&create_actor, &create)?;
    diagnostics.phase("new verified original after cumulatively closed workflow identities");
    let response = fixture.kernel.execute_recovery_command_with_origin(
        &create_actor,
        &create,
        &fixture.process,
    );
    diagnostics.observe_failure(Some(fixture), &response);
    let response = response.map_err(|error| format!("creation index {index}: {error}"))?;
    let workflow = response.workflow_id.clone();
    let create_response = chio_core::canonical_json_bytes(&response)?;
    let cancel = fixture.command(
        &format!("cancel-closed-original-{index}"),
        RecoveryCommandBodyV1::CancelWorkflow {
            workflow_id: workflow.clone(),
            expected_revision: response.revision,
        },
    )?;
    let cancel_actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Cancel,
    )?;
    require_live_quota_capability("control capability", &fixture.control)?;
    let cancelled = fixture
        .kernel
        .execute_recovery_command(&cancel_actor, &cancel)?;
    let closed = fixture.record(&workflow)?;
    assert_eq!(closed.control, WorkflowControlV1::Cancelled);
    assert!(closed.admission_closed);
    assert!(closed.admission.is_none());
    assert!(closed.native_link.is_none());
    assert!(!closed.captured);
    assert_eq!(closed.effect, EffectObservationV1::NeverAdmitted);
    assert_eq!(external_count(&fixture.path)?, 0);
    Ok(Box::new(ClosedWorkflowReplay {
        workflow,
        create,
        create_response,
        cancel,
        cancel_response: chio_core::canonical_json_bytes(&cancelled)?,
    }))
}

#[tokio::test]
async fn recovery_closed_workflows_reclaim_active_capacity_and_keep_identity_replay() -> TestResult
{
    let diagnostics = QuotaTestDiagnostics::new();
    let directory = tempfile::tempdir()?;
    std::fs::write(
        directory.path().join("workflow-flood"),
        b"bounded workflow capacity fixture",
    )?;
    let fixture = Box::new(diagnostics.finish(
        None,
        RecoveryFixture::open(directory.path().to_path_buf(), Some(directory), false),
    )?);
    let result: TestResult = Box::pin(async {
        let mut first = None;
        for index in 0..139 {
            let replay = Box::pin(create_and_close_workflow(&fixture, index, &diagnostics)).await?;
            if first.is_none() { first = Some(replay); }
        }
        let connection = connection(&fixture)?;
        let (workflows, claims, still_open): (i64, i64, i64) = connection.query_row(
            "SELECT
                (SELECT count(*) FROM admission_operation_recovery_records WHERE kind='workflow' AND record_key GLOB 'workflow:*'),
                (SELECT count(*) FROM admission_operation_recovery_records WHERE kind='command' AND record_key GLOB 'recovery-origin:*'),
                (SELECT count(*) FROM admission_operation_recovery_records WHERE kind='workflow' AND record_key GLOB 'workflow:*' AND json_extract(payload,'$.admission_closed')!=1)",
            [], |row: &rusqlite::Row<'_>| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?)),
        )?;
        assert_eq!(workflows, 139);
        assert_eq!(claims, 139);
        assert_eq!(still_open, 0);
        drop(connection);
        let first = first.ok_or("closed replay fixture is absent")?;
        diagnostics.phase("retired original identities remain exact under current authorization");
        let before = protected_usage(&fixture)?;
        let create_actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(), &fixture.control, RecoveryPermission::Create,
        )?;
        let create = fixture.kernel.execute_recovery_command_with_origin(
            &create_actor, &first.create, &fixture.process,
        )?;
        assert_eq!(chio_core::canonical_json_bytes(&create)?, first.create_response);
        let cancel_actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(), &fixture.control, RecoveryPermission::Cancel,
        )?;
        let cancel = fixture.kernel.execute_recovery_command(&cancel_actor, &first.cancel)?;
        assert_eq!(chio_core::canonical_json_bytes(&cancel)?, first.cancel_response);
        assert_eq!(fixture.record(&first.workflow)?.control, WorkflowControlV1::Cancelled);
        assert_eq!(protected_usage(&fixture)?, before);
        assert_eq!(external_count(&fixture.path)?, 0);
        Ok(())
    }).await;
    diagnostics.finish(Some(&fixture), result)
}
