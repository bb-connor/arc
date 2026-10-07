//! Workflow control never grants preview of an uncleared workflow.
use super::*;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use tower::ServiceExt;

const PREVIEW_ACTOR_MARKER: &str = "finite-preview-control-actor";

fn preview_actor_key() -> Keypair {
    Keypair::from_seed(&[174; 32])
}

pub(super) fn extend_fixture_actors(
    path: &std::path::Path,
    profile: &mut RecoveryDeploymentV1,
) -> TestResult {
    if !path.join(PREVIEW_ACTOR_MARKER).exists() {
        return Ok(());
    }
    let clearance = if std::fs::read(path.join(PREVIEW_ACTOR_MARKER))? == b"initially-cleared" {
        restricted_label()
    } else {
        InformationLabel::bottom()
    };
    let mut actors = profile.actors.as_slice().to_vec();
    actors.push(RecoveryActorAssignment {
        subject: preview_actor_key().public_key(),
        principal: PrincipalId::new("finite-preview-controller")?,
        permissions: BoundedList::new(vec![
            RecoveryPermission::Inspect,
            RecoveryPermission::Cancel,
            RecoveryPermission::Report,
            RecoveryPermission::Settle,
        ])?,
        preview_clearance: clearance,
    });
    profile.actors = NonEmptyBoundedList::new(actors)?;
    Ok(())
}

fn fixture(initially_cleared: bool) -> TestResult<(RecoveryFixture, CapabilityToken)> {
    let directory = tempfile::tempdir()?;
    std::fs::write(
        directory.path().join(PREVIEW_ACTOR_MARKER),
        if initially_cleared {
            b"initially-cleared".as_slice()
        } else {
            b"uncleared".as_slice()
        },
    )?;
    let fixture = RecoveryFixture::open(directory.path().to_path_buf(), Some(directory), false)?;
    let capability = fixture.kernel.issue_capability(
        &preview_actor_key().public_key(),
        ChioScope {
            grants: [
                RecoveryPermission::Inspect,
                RecoveryPermission::Cancel,
                RecoveryPermission::Report,
                RecoveryPermission::Settle,
            ]
            .into_iter()
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
        1200,
    )?;
    for permission in [
        RecoveryPermission::Inspect,
        RecoveryPermission::Cancel,
        RecoveryPermission::Report,
        RecoveryPermission::Settle,
    ] {
        fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &capability,
            permission,
        )?;
    }
    Ok((fixture, capability))
}

async fn protected_workflow(fixture: &RecoveryFixture, completed: bool) -> TestResult<WorkflowId> {
    let workflow = Box::pin(fixture.ready()).await?;
    let record = fixture.record(&workflow)?;
    let action = record.action.as_ref().ok_or("restricted action absent")?;
    assert_eq!(
        action.authorization_requirements.source_label,
        restricted_label()
    );
    assert!(!action
        .authorization_requirements
        .source_label
        .flows_to(&InformationLabel::bottom()));
    if completed {
        Box::pin(fixture.execute(
            "complete-for-preview",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: workflow.clone(),
                expected_revision: record.revision,
            },
        ))
        .await?;
        let completed = fixture.record(&workflow)?;
        assert!(completed.captured);
        assert!(matches!(
            completed.effect,
            EffectObservationV1::Complete { .. }
        ));
        assert_eq!(external_count(&fixture.path)?, 1);
    }
    Ok(workflow)
}

#[derive(Debug, Eq, PartialEq)]
struct ProtectedSnapshot {
    workflow_digest: String,
    records_digest: String,
    counts: (i64, i64, i64, i64),
    effects: usize,
    process_calls: u32,
}

fn protected_snapshot(
    fixture: &RecoveryFixture,
    workflow: &WorkflowId,
) -> TestResult<ProtectedSnapshot> {
    let connection = rusqlite::Connection::open_with_flags(
        fixture.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let rows = connection.prepare(
        "SELECT record_key,version,scope_key,kind,hex(payload),coalesce(native_namespace,''),coalesce(native_request,'') FROM admission_operation_recovery_records ORDER BY record_key"
    )?.query_map([], |row| Ok((row.get::<_,String>(0)?,row.get::<_,i64>(1)?,
        row.get::<_,String>(2)?,row.get::<_,String>(3)?,row.get::<_,String>(4)?,
        row.get::<_,String>(5)?,row.get::<_,String>(6)?)))?
        .collect::<Result<Vec<_>,_>>()?;
    let counts = connection.query_row(
        "SELECT (SELECT count(*) FROM admission_operation_recovery_events), (SELECT count(*) FROM admission_operation_commits), (SELECT count(*) FROM authority_global_commits), (SELECT count(*) FROM admission_operation_terminal_records WHERE record_kind='receipt')",
        [], |row| Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?,row.get::<_,i64>(3)?)),
    )?;
    Ok(ProtectedSnapshot {
        workflow_digest: chio_core::sha256_hex(&chio_core::canonical_json_bytes(
            &fixture.record(workflow)?,
        )?),
        records_digest: chio_core::sha256_hex(&chio_core::canonical_json_bytes(&rows)?),
        counts,
        effects: external_count(&fixture.path)?,
        process_calls: fixture.process.process("root")?.tree_calls,
    })
}

fn command_body(
    permission: RecoveryPermission,
    workflow: WorkflowId,
    revision: SafeInteger,
) -> TestResult<RecoveryCommandBodyV1> {
    Ok(match permission {
        RecoveryPermission::Inspect => RecoveryCommandBodyV1::InspectWorkflow {
            workflow_id: workflow,
        },
        RecoveryPermission::Cancel => RecoveryCommandBodyV1::CancelWorkflow {
            workflow_id: workflow,
            expected_revision: revision,
        },
        RecoveryPermission::Report => RecoveryCommandBodyV1::ReportDecision {
            workflow_id: workflow,
            expected_revision: revision,
            decision: RecoveryReportedDecision::Accepted,
        },
        _ => return Err("unsupported preview command".into()),
    })
}

async fn native_command_refuses(permission: RecoveryPermission, completed: bool) -> TestResult {
    let (fixture, capability) = fixture(false)?;
    let workflow = Box::pin(protected_workflow(&fixture, completed)).await?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &capability,
        permission,
    )?;
    assert!(
        fixture
            .kernel
            .read_recovery_workflow(&actor, &workflow)
            .is_err(),
        "uncleared actor unexpectedly has preview"
    );
    let revision = fixture.record(&workflow)?.revision;
    let before = protected_snapshot(&fixture, &workflow)?;
    let mut categories = Vec::new();
    for (index, target, revision) in [
        (0, workflow.clone(), revision),
        (
            1,
            WorkflowId::new("workflow:absent-preview-control")?,
            revision,
        ),
        (2, workflow.clone(), SafeInteger::new(revision.get() + 1)?),
    ] {
        let command = fixture.command(
            &format!("native-hidden-{}-{index}", permission.wire_name()),
            command_body(permission, target, revision)?,
        )?;
        let result = fixture.kernel.execute_recovery_command(&actor, &command);
        categories.push(matches!(result, Err(RecoveryCommandError::AuthorityDenied)));
        assert_eq!(
            protected_snapshot(&fixture, &workflow)?,
            before,
            "uncleared control changed protected records before refusing"
        );
    }
    assert!(
        categories.into_iter().all(|category| category),
        "hidden and absent workflows need the same fixed authority refusal before revision checks"
    );
    Ok(())
}

#[tokio::test]
async fn native_uncleared_cancel_cannot_mutate_hidden_workflow() -> TestResult {
    Box::pin(native_command_refuses(RecoveryPermission::Cancel, false)).await
}
#[tokio::test]
async fn native_uncleared_report_cannot_mutate_hidden_workflow() -> TestResult {
    Box::pin(native_command_refuses(RecoveryPermission::Report, true)).await
}
#[tokio::test]
async fn native_hidden_and_absent_inspection_have_one_refusal() -> TestResult {
    Box::pin(native_command_refuses(RecoveryPermission::Inspect, false)).await
}

#[tokio::test]
async fn native_settlement_port_requires_preview_before_projecting_effect_status() -> TestResult {
    let (fixture, capability) = fixture(false)?;
    let workflow = Box::pin(protected_workflow(&fixture, true)).await?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &capability,
        RecoveryPermission::Settle,
    )?;
    assert!(fixture
        .kernel
        .read_recovery_workflow(&actor, &workflow)
        .is_err());
    let before = protected_snapshot(&fixture, &workflow)?;
    let result = RecoveryAuthorityPort::settle(
        &fixture.authority.admission_operation_store(),
        &actor,
        &workflow,
        &fixture.authority.mutation_fence(),
        now_ms()?,
    );
    assert_eq!(protected_snapshot(&fixture, &workflow)?, before);
    assert!(
        result.is_err(),
        "Store settlement projected a protected effect, release and revision to an uncleared actor"
    );
    Ok(())
}

async fn mounted_call(
    router: &Router,
    route: &str,
    wire: Vec<u8>,
) -> TestResult<(StatusCode, Vec<u8>)> {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(route)
                .body(Body::from(wire))?,
        )
        .await?;
    let status = response.status();
    Ok((
        status,
        to_bytes(response.into_body(), 262144).await?.to_vec(),
    ))
}

fn settlement_wire(capability: &CapabilityToken, workflow: &WorkflowId) -> TestResult<Vec<u8>> {
    Ok(chio_core::canonical_json_bytes(&serde_json::json!({
        "capability": text::<32768,_>(capability)?.as_str(), "workflow_id": workflow,
    }))?)
}

async fn mounted_refuses(permission: RecoveryPermission, completed: bool) -> TestResult {
    let (fixture, capability) = fixture(false)?;
    let workflow = Box::pin(protected_workflow(&fixture, completed)).await?;
    let router = crate::recovery::recovery_router(fixture.runtime.clone())?;
    let positive = fixture.command(
        "cleared-preview-inspect",
        RecoveryCommandBodyV1::InspectWorkflow {
            workflow_id: workflow.clone(),
        },
    )?;
    let positive = mounted_call(&router, "/v1/recovery/commands", chio_core::canonical_json_bytes(&serde_json::json!({
        "capability": text::<32768,_>(&fixture.control)?.as_str(), "command": text::<32768,_>(&positive)?.as_str(),
    }))?).await?;
    assert_eq!(
        positive.0,
        StatusCode::OK,
        "cleared actor cannot inspect the actual restricted workflow"
    );
    let revision = fixture.record(&workflow)?.revision;
    let before = protected_snapshot(&fixture, &workflow)?;
    let mut replies = Vec::new();
    for (index, target, revision) in [
        (0, workflow.clone(), revision),
        (
            1,
            WorkflowId::new("workflow:absent-preview-control")?,
            revision,
        ),
        (2, workflow.clone(), SafeInteger::new(revision.get() + 1)?),
    ] {
        let (route, wire) = if permission == RecoveryPermission::Settle {
            (
                "/v1/recovery/settle",
                settlement_wire(&capability, &target)?,
            )
        } else {
            let command = fixture.command(
                &format!("mounted-hidden-{}-{index}", permission.wire_name()),
                command_body(permission, target, revision)?,
            )?;
            (
                "/v1/recovery/commands",
                chio_core::canonical_json_bytes(&serde_json::json!({
                    "capability": text::<32768,_>(&capability)?.as_str(), "command": text::<32768,_>(&command)?.as_str(),
                }))?,
            )
        };
        replies.push(mounted_call(&router, route, wire).await?);
        assert_eq!(
            protected_snapshot(&fixture, &workflow)?,
            before,
            "mounted uncleared control changed protected records before refusing"
        );
    }
    for (status, body) in replies {
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "hidden or absent response exposed status or existence"
        );
        assert_eq!(
            body, b"recovery.authority_denied",
            "response exposed effect, release, control, revision or diagnostics"
        );
    }
    Ok(())
}

#[tokio::test]
async fn mounted_uncleared_settlement_hides_effect_status_and_absence() -> TestResult {
    Box::pin(mounted_refuses(RecoveryPermission::Settle, true)).await
}
#[tokio::test]
async fn mounted_uncleared_cancel_cannot_mutate_or_identify_hidden_workflow() -> TestResult {
    Box::pin(mounted_refuses(RecoveryPermission::Cancel, false)).await
}
#[tokio::test]
async fn mounted_uncleared_report_cannot_mutate_or_identify_hidden_workflow() -> TestResult {
    Box::pin(mounted_refuses(RecoveryPermission::Report, true)).await
}
#[tokio::test]
async fn mounted_hidden_and_absent_inspection_have_one_refusal() -> TestResult {
    Box::pin(mounted_refuses(RecoveryPermission::Inspect, false)).await
}

#[tokio::test]
async fn native_retained_mutation_replay_rechecks_current_preview_clearance() -> TestResult {
    let (fixture, capability) = fixture(true)?;
    let workflow = Box::pin(protected_workflow(&fixture, true)).await?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &capability,
        RecoveryPermission::Report,
    )?;
    let command = fixture.command(
        "preview-bound-retained-report",
        command_body(
            RecoveryPermission::Report,
            workflow.clone(),
            fixture.record(&workflow)?.revision,
        )?,
    )?;
    fixture.kernel.execute_recovery_command(&actor, &command)?;
    let mut profile = fixture
        .kernel
        .recovery_deployment(fixture.runtime.scope())?;
    let mut actors = profile.actors.as_slice().to_vec();
    let controller = actors
        .iter_mut()
        .find(|actor| actor.principal.as_str() == "finite-preview-controller")
        .ok_or("current preview controller absent")?;
    controller.preview_clearance = InformationLabel::bottom();
    profile.actors = NonEmptyBoundedList::new(actors)?;
    profile.authority_scope = recovery_authority_scope_digest(&profile)?;
    // Genuine operator profile rotation changes current assignment clearance;
    // the original request, action, output, command and signed bytes stay intact.
    fixture
        .authority
        .admission_operation_store()
        .configure_recovery_deployment(&profile)?;
    let current = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &capability,
        RecoveryPermission::Report,
    )?;
    assert!(fixture
        .kernel
        .read_recovery_workflow(&current, &workflow)
        .is_err());
    let before = protected_snapshot(&fixture, &workflow)?;
    let result = fixture.kernel.execute_recovery_command(&current, &command);
    assert_eq!(protected_snapshot(&fixture, &workflow)?, before);
    assert!(
        matches!(result, Err(RecoveryCommandError::AuthorityDenied)),
        "retained mutation replay returned protected status after current audience loss"
    );
    Ok(())
}

#[tokio::test]
async fn cleared_finite_actor_can_control_the_restricted_workflow() -> TestResult {
    let (fixture, _) = fixture(false)?;
    let workflow = Box::pin(protected_workflow(&fixture, true)).await?;
    let settled = fixture.runtime.settle(&fixture.control, &workflow)?;
    assert!(matches!(
        settled.effect,
        EffectObservationV1::Complete { .. }
    ));
    for permission in [
        RecoveryPermission::Inspect,
        RecoveryPermission::Report,
        RecoveryPermission::Cancel,
    ] {
        Box::pin(fixture.execute(
            &format!("cleared-{}", permission.wire_name()),
            command_body(
                permission,
                workflow.clone(),
                fixture.record(&workflow)?.revision,
            )?,
        ))
        .await?;
    }
    assert_eq!(external_count(&fixture.path)?, 1);
    assert!(fixture.record(&workflow)?.effect.is_settled());
    Ok(())
}
