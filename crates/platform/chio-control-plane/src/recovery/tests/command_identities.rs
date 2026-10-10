//! Durable same-value aliases preserve identity without spending finishing capacity.
use super::command_quotas::{protected_usage, require_live_quota_capability, QuotaTestDiagnostics};
use super::*;
use rusqlite::{params, Connection, OpenFlags};

const FRESH_IDENTITIES: usize = 96;

#[derive(Debug, Eq, PartialEq)]
struct MutationCustody {
    recovery: Vec<(String, i64, String)>,
    native: Vec<(String, i64, String)>,
    capture: Vec<(String, String)>,
}

fn mutation_custody(
    fixture: &RecoveryFixture,
    workflow: &WorkflowId,
) -> TestResult<MutationCustody> {
    let connection = Connection::open_with_flags(
        fixture.path.join("admission.db"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let scope = chio_core::sha256_hex(&chio_core::canonical_json_bytes(fixture.runtime.scope())?);
    let mut recovery = connection.prepare(
        "SELECT record_key,version,payload FROM admission_operation_recovery_records
         WHERE record_key IN (?1,?2,?3) OR record_key GLOB 'recovery-workflow-capacity:*'
         ORDER BY record_key",
    )?;
    let recovery = recovery
        .query_map(
            params![
                format!("workflow:{scope}:{}", workflow.as_str()),
                format!("workflow-quota:{scope}:{}", workflow.as_str()),
                format!("recovery-workflow-allocation:{scope}:{}", workflow.as_str())
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    chio_core::sha256_hex(&row.get::<_, Vec<u8>>(2)?),
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    let mut native = connection.prepare(
        "SELECT operation_id,version,operation_json FROM admission_operations ORDER BY operation_id",
    )?;
    let native = native
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                chio_core::sha256_hex(&row.get::<_, Vec<u8>>(2)?),
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let mut capture = connection.prepare(
        "SELECT operation_id,record_digest FROM admission_operation_native_dispatch_ledger ORDER BY operation_id",
    )?;
    let capture = capture
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(MutationCustody {
        recovery,
        native,
        capture,
    })
}

fn assert_retained_identity(
    fixture: &RecoveryFixture,
    actor: &AuthenticatedRecoveryActor,
    command: &RecoveryCommandV1,
    response: &RecoveryCommandResponseV1,
) -> TestResult {
    let identity = chio_core::sha256_hex(&chio_core::canonical_json_bytes(&(
        actor.scope(),
        actor.principal(),
        command.command.permission(),
        &command.command_id,
    ))?);
    let connection = Connection::open_with_flags(
        fixture.path.join("admission.db"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let mut statement = connection.prepare(
        "SELECT scope_key,kind,version,payload FROM admission_operation_recovery_records
         WHERE record_key IN (?1,?2)",
    )?;
    let rows = statement
        .query_map(
            params![
                format!("command:{identity}"),
                format!("command-alias:{identity}")
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        rows.len(),
        1,
        "same-value alias has no unique durable identity"
    );
    let (scope, kind, version, payload) = &rows[0];
    assert_eq!(
        scope,
        &chio_core::sha256_hex(&chio_core::canonical_json_bytes(actor.scope())?)
    );
    assert_eq!(kind, "command");
    assert_eq!(*version, 1);
    assert!(
        payload.len() <= 4096,
        "alias custody exceeds its closed metadata envelope"
    );
    let value: Value = serde_json::from_slice(payload)?;
    assert_eq!(chio_core::canonical_json_bytes(&value)?, *payload);
    assert_eq!(
        value["digest"],
        serde_json::to_value(CommandDigest::from_bytes(recovery_digest(
            chio_core_types::recovery::RecoveryDigestDomain::Command,
            &command.command
        )?))?
    );
    assert_eq!(
        chio_core::canonical_json_bytes(&value["response"])?,
        chio_core::canonical_json_bytes(response)?
    );
    if value.get("schema").is_some() {
        assert_eq!(value["schema"], "chio.recovery.command-alias.v1");
        assert_eq!(value["scope"], serde_json::to_value(actor.scope())?);
        assert_eq!(value["principal"], serde_json::to_value(actor.principal())?);
        assert_eq!(
            value["permission"],
            serde_json::to_value(actor.permission())?
        );
        assert_eq!(value["mode"], "control_only");
        assert_eq!(value["selection"]["generation"], 1);
        assert_eq!(
            value["selection"]["record_version"],
            response.revision.get()
        );
        let source = value["selection"]["record_key"]
            .as_str()
            .ok_or("alias has no physical generation key")?;
        let (digest, event): (String, i64) = connection.query_row(
            "SELECT record_digest,sequence FROM admission_operation_recovery_events
             WHERE record_key=?1 AND record_version=?2",
            params![source, i64::try_from(response.revision.get())?],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let digest: [u8; 32] = hex::decode(digest)?
            .try_into()
            .map_err(|_| "alias source digest has the wrong length")?;
        assert_eq!(
            value["selection"]["record_digest"],
            serde_json::to_value(ProjectionDigest::from_bytes(digest))?
        );
        assert_eq!(value["selection"]["event_sequence"], u64::try_from(event)?);
    }
    Ok(())
}

/// Fresh control tokens retain the current approver and control-only scope.
/// Original execution authority and native capture remain historical custody.
struct ReportControlWindow {
    capability: CapabilityToken,
    principal: PrincipalId,
    deployment: Vec<u8>,
    duration_seconds: u64,
}

impl ReportControlWindow {
    fn new(fixture: &RecoveryFixture, actor: &AuthenticatedRecoveryActor) -> TestResult<Self> {
        let duration_seconds = fixture
            .control
            .expires_at
            .checked_sub(fixture.control.issued_at)
            .ok_or("Report control duration regressed")?;
        assert_eq!(duration_seconds, 1200);
        assert!(fixture
            .control
            .scope
            .grants
            .iter()
            .all(|grant| grant.server_id == "chio.recovery"));
        let deployment = chio_core::canonical_json_bytes(
            &fixture
                .kernel
                .recovery_deployment(fixture.runtime.scope())?,
        )?;
        let mut window = Self {
            capability: fixture.control.clone(),
            principal: actor.principal().clone(),
            deployment,
            duration_seconds,
        };
        window.issue_current(fixture)?;
        Ok(window)
    }

    fn issue_current(&mut self, fixture: &RecoveryFixture) -> TestResult {
        assert_eq!(
            chio_core::canonical_json_bytes(
                &fixture
                    .kernel
                    .recovery_deployment(fixture.runtime.scope())?,
            )?,
            self.deployment,
            "Report control refresh changed the installed deployment"
        );
        let capability = fixture.kernel.issue_capability(
            &fixture.approval_key.public_key(),
            fixture.control.scope.clone(),
            self.duration_seconds,
        )?;
        assert_eq!(capability.subject, fixture.control.subject);
        assert_eq!(capability.issuer, fixture.control.issuer);
        assert_ne!(capability.id, self.capability.id);
        assert_eq!(
            chio_core::canonical_json_bytes(&capability.scope)?,
            chio_core::canonical_json_bytes(&fixture.control.scope)?
        );
        assert_eq!(
            capability.expires_at.checked_sub(capability.issued_at),
            Some(self.duration_seconds)
        );
        self.capability = capability;
        Ok(())
    }

    fn current_actor(
        &mut self,
        fixture: &RecoveryFixture,
    ) -> TestResult<AuthenticatedRecoveryActor> {
        if chio_kernel::fixed_runtime_unix_secs_for_current_thread().is_some() {
            return Err("Report control windows require the real runtime clock".into());
        }
        let current_seconds = now_ms()? / 1000;
        if self.capability.expires_at.saturating_sub(current_seconds) <= 120 {
            self.issue_current(fixture)?;
        }
        require_live_quota_capability("current Report control window", &self.capability)?;
        let actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &self.capability,
            RecoveryPermission::Report,
        )?;
        assert_eq!(actor.scope(), fixture.runtime.scope());
        assert_eq!(actor.principal(), &self.principal);
        assert_eq!(actor.permission(), RecoveryPermission::Report);
        Ok(actor)
    }
}

fn probe_same_value(
    fixture: &RecoveryFixture,
    diagnostics: &QuotaTestDiagnostics,
    prefix: &str,
    permission: RecoveryPermission,
    body: RecoveryCommandBodyV1,
    expected: (&WorkflowId, SafeInteger),
) -> TestResult {
    let (workflow, revision) = expected;
    let before = mutation_custody(fixture, workflow)?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        permission,
    )?;
    let report_custody = if permission == RecoveryPermission::Report {
        Some((
            chio_core::canonical_json_bytes(&fixture.seed)?,
            fixture.process.process("root")?.tree_calls,
        ))
    } else {
        None
    };
    let mut report_window = if permission == RecoveryPermission::Report {
        Some(ReportControlWindow::new(fixture, &actor)?)
    } else {
        None
    };
    for index in 0..FRESH_IDENTITIES {
        let current_report_actor = match report_window.as_mut() {
            Some(window) => Some(window.current_actor(fixture)?),
            None => None,
        };
        let current_actor = match current_report_actor.as_ref() {
            Some(current) => current,
            None => &actor,
        };
        require_live_quota_capability("no-op control capability", current_actor.capability())?;
        let command = fixture.command(&format!("{prefix}-{index}"), body.clone())?;
        diagnostics.phase("fresh same-value identities with live current authority");
        let result = fixture
            .kernel
            .execute_recovery_command(current_actor, &command);
        diagnostics.observe_failure(Some(fixture), &result);
        let response = result.map_err(|error| format!("{prefix} index {index}: {error}"))?;
        assert_eq!(response.command_id, command.command_id);
        assert_eq!(&response.workflow_id, workflow);
        assert_eq!(response.revision, revision);
        assert_retained_identity(fixture, current_actor, &command, &response)?;
        if report_window.is_some() {
            require_live_quota_capability(
                "Report alias completion control capability",
                current_actor.capability(),
            )?;
        }
    }
    if let Some((seed, process_calls)) = report_custody {
        assert_eq!(chio_core::canonical_json_bytes(&fixture.seed)?, seed);
        assert_eq!(fixture.process.process("root")?.tree_calls, process_calls);
    }
    assert_eq!(mutation_custody(fixture, workflow)?, before);
    Ok(())
}

fn request_first_resume(
    fixture: &RecoveryFixture,
    workflow: &WorkflowId,
) -> TestResult<(Box<RecoveryCommandV1>, Vec<u8>)> {
    let record = fixture.record(workflow)?;
    let command = fixture.command(
        "first-execution-request",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: workflow.clone(),
            expected_revision: record.revision,
        },
    )?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Resume,
    )?;
    let response = fixture.kernel.execute_recovery_command(&actor, &command)?;
    assert_eq!(external_count(&fixture.path)?, 0);
    Ok((
        Box::new(command),
        chio_core::canonical_json_bytes(&response)?,
    ))
}

async fn capture_requested_generation(
    fixture: &RecoveryFixture,
    command: &RecoveryCommandV1,
) -> TestResult {
    let result =
        Box::pin(fixture.execute(command.command_id.as_str(), command.command.clone())).await?;
    assert!(matches!(
        result.status.effect,
        EffectObservationV1::Complete { .. }
    ));
    assert!(matches!(
        &result.status.release,
        ReleaseDispositionV1::Released { .. }
    ));
    assert_eq!(external_count(&fixture.path)?, 1);
    Ok(())
}

#[tokio::test]
async fn recovery_same_value_resume_identities_preserve_first_execution_and_replay() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = Box::new(RecoveryFixture::new(false)?);
    let workflow = Box::pin(fixture.ready()).await?;
    let (first, retained) = request_first_resume(&fixture, &workflow)?;
    let result: TestResult = Box::pin(async {
        let revision = fixture.record(&workflow)?.revision;
        probe_same_value(
            &fixture,
            &diagnostics,
            "read-existing-execution-request",
            RecoveryPermission::Resume,
            first.command.clone(),
            (&workflow, revision),
        )?;
        diagnostics.phase("actual execution of retained first Resume identity");
        Box::pin(capture_requested_generation(&fixture, &first)).await?;
        let before = protected_usage(&fixture)?;
        let actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Resume,
        )?;
        let replay = fixture.kernel.execute_recovery_command(&actor, &first)?;
        assert_eq!(chio_core::canonical_json_bytes(&replay)?, retained);
        let mut conflict = *first.clone();
        if let RecoveryCommandBodyV1::ResumeWorkflow {
            expected_revision, ..
        } = &mut conflict.command
        {
            *expected_revision = SafeInteger::new(expected_revision.get() + 1)?;
        }
        assert_eq!(
            fixture
                .kernel
                .execute_recovery_command(&actor, &conflict)
                .err(),
            Some(RecoveryCommandError::Conflict)
        );
        assert_eq!(protected_usage(&fixture)?, before);
        assert_eq!(external_count(&fixture.path)?, 1);
        Ok(())
    })
    .await;
    diagnostics.finish(Some(&fixture), result)
}

async fn create_cancelled(fixture: &RecoveryFixture) -> TestResult<(WorkflowId, SafeInteger)> {
    let seed = Box::pin(fixture.denied_seed_named("closed-original")).await?;
    let create = fixture.command(
        "create-closed-original",
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new("closed-original")?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(&seed)?,
        },
    )?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Create,
    )?;
    let created =
        fixture
            .kernel
            .execute_recovery_command_with_origin(&actor, &create, &fixture.process)?;
    let cancel = fixture.command(
        "first-cancel",
        RecoveryCommandBodyV1::CancelWorkflow {
            workflow_id: created.workflow_id.clone(),
            expected_revision: created.revision,
        },
    )?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Cancel,
    )?;
    let cancelled = fixture.kernel.execute_recovery_command(&actor, &cancel)?;
    let record = fixture.record(&created.workflow_id)?;
    assert_eq!(record.control, WorkflowControlV1::Cancelled);
    assert!(record.admission_closed && record.admission.is_none() && !record.captured);
    assert_eq!(record.effect, EffectObservationV1::NeverAdmitted);
    Ok((created.workflow_id, cancelled.revision))
}

#[tokio::test]
async fn recovery_same_value_cancel_identities_do_not_spend_mutation_capacity() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = Box::new(RecoveryFixture::new(false)?);
    let (workflow, revision) = Box::pin(create_cancelled(&fixture)).await?;
    let result = probe_same_value(
        &fixture,
        &diagnostics,
        "read-already-cancelled",
        RecoveryPermission::Cancel,
        RecoveryCommandBodyV1::CancelWorkflow {
            workflow_id: workflow.clone(),
            expected_revision: revision,
        },
        (&workflow, revision),
    );
    assert_eq!(external_count(&fixture.path)?, 0);
    diagnostics.finish(Some(&fixture), result)
}

async fn completed_workflow(fixture: &RecoveryFixture) -> TestResult<WorkflowId> {
    let workflow = Box::pin(fixture.ready()).await?;
    let (resume, _) = request_first_resume(fixture, &workflow)?;
    Box::pin(capture_requested_generation(fixture, &resume)).await?;
    Ok(workflow)
}

#[tokio::test]
async fn recovery_same_value_report_identities_do_not_spend_mutation_capacity() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = Box::new(RecoveryFixture::new(false)?);
    let workflow = Box::pin(completed_workflow(&fixture)).await?;
    let result: TestResult = (|| {
        let record = fixture.record(&workflow)?;
        assert!(record.captured && record.effect.is_settled());
        assert!(record.reported_decision.is_none());
        let actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Report,
        )?;
        let first = fixture.command(
            "first-accepted-decision",
            RecoveryCommandBodyV1::ReportDecision {
                workflow_id: workflow.clone(),
                expected_revision: record.revision,
                decision: RecoveryReportedDecision::Accepted,
            },
        )?;
        let accepted = fixture.kernel.execute_recovery_command(&actor, &first)?;
        assert_eq!(
            fixture.record(&workflow)?.reported_decision,
            Some(RecoveryReportedDecision::Accepted)
        );
        probe_same_value(
            &fixture,
            &diagnostics,
            "read-accepted-decision",
            RecoveryPermission::Report,
            RecoveryCommandBodyV1::ReportDecision {
                workflow_id: workflow.clone(),
                expected_revision: accepted.revision,
                decision: RecoveryReportedDecision::Accepted,
            },
            (&workflow, accepted.revision),
        )?;
        assert_eq!(external_count(&fixture.path)?, 1);
        Ok(())
    })();
    diagnostics.finish(Some(&fixture), result)
}

#[tokio::test]
async fn recovery_same_value_selection_identities_do_not_spend_mutation_capacity() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = Box::new(RecoveryFixture::new(false)?);
    let workflow = Box::pin(fixture.ready()).await?;
    let result: TestResult = (|| {
        let record = fixture.record(&workflow)?;
        assert!(record.selected && record.approval.is_some());
        let action = record.action.as_ref().ok_or("selected action is absent")?;
        let offer = format!(
            "offer:{}",
            recovery_digest(
                chio_core_types::recovery::RecoveryDigestDomain::ActionIntent,
                action,
            )?
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
        );
        probe_same_value(
            &fixture,
            &diagnostics,
            "read-selected-offer",
            RecoveryPermission::Select,
            RecoveryCommandBodyV1::SelectOffer {
                workflow_id: workflow.clone(),
                expected_revision: record.revision,
                offer_id: OfferId::new(&offer)?,
            },
            (&workflow, record.revision),
        )?;
        assert_eq!(external_count(&fixture.path)?, 0);
        Ok(())
    })();
    diagnostics.finish(Some(&fixture), result)
}

#[tokio::test]
async fn recovery_same_value_approval_identities_do_not_spend_mutation_capacity() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = Box::new(RecoveryFixture::new(false)?);
    let workflow = Box::pin(fixture.ready()).await?;
    let result: TestResult = (|| {
        let record = fixture.record(&workflow)?;
        assert!(record.selected && record.approval.is_some());
        let approval = record
            .approval
            .as_ref()
            .ok_or("retained approval is absent")?;
        probe_same_value(
            &fixture,
            &diagnostics,
            "read-retained-approval",
            RecoveryPermission::Approve,
            RecoveryCommandBodyV1::SubmitApproval {
                workflow_id: workflow.clone(),
                expected_revision: record.revision,
                approval: text(approval)?,
            },
            (&workflow, record.revision),
        )?;
        assert_eq!(external_count(&fixture.path)?, 0);
        Ok(())
    })();
    diagnostics.finish(Some(&fixture), result)
}

#[tokio::test]
async fn recovery_duplicate_creation_identities_do_not_spend_mutation_capacity() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = Box::new(RecoveryFixture::new(false)?);
    let workflow = Box::pin(fixture.ready()).await?;
    let result: TestResult = (|| {
        let record = fixture.record(&workflow)?;
        let body = RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new("ticket-1")?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: record.creation_seed.clone(),
        };
        let actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Create,
        )?;
        let before = mutation_custody(&fixture, &workflow)?;
        for index in 0..FRESH_IDENTITIES {
            let command =
                fixture.command(&format!("read-existing-creation-{index}"), body.clone())?;
            super::command_quotas::require_live_creation_authority(&actor, &command)?;
            diagnostics.phase("fresh duplicate creation identities with live original");
            let response = fixture.kernel.execute_recovery_command_with_origin(
                &actor,
                &command,
                &fixture.process,
            );
            diagnostics.observe_failure(Some(&fixture), &response);
            let response =
                response.map_err(|error| format!("duplicate creation {index}: {error}"))?;
            assert_eq!(response.workflow_id, workflow);
            assert_eq!(response.revision, record.revision);
            assert_retained_identity(&fixture, &actor, &command, &response)?;
        }
        assert_eq!(mutation_custody(&fixture, &workflow)?, before);
        assert_eq!(external_count(&fixture.path)?, 0);
        Ok(())
    })();
    diagnostics.finish(Some(&fixture), result)
}

async fn accepted_alias_after_completion(
    fixture: &RecoveryFixture,
) -> TestResult<(WorkflowId, Box<RecoveryCommandV1>, Vec<u8>)> {
    let workflow = Box::pin(fixture.ready()).await?;
    let (first, _) = request_first_resume(fixture, &workflow)?;
    let alias = Box::new(fixture.command("retained-same-value-alias", first.command.clone())?);
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Resume,
    )?;
    let response = fixture.kernel.execute_recovery_command(&actor, &alias)?;
    assert_retained_identity(fixture, &actor, &alias, &response)?;
    let retained = chio_core::canonical_json_bytes(&response)?;
    Box::pin(capture_requested_generation(fixture, &first)).await?;
    assert!(fixture.record(&workflow)?.revision.get() > response.revision.get());
    Ok((workflow, alias, retained))
}

#[tokio::test]
async fn recovery_same_value_alias_replays_exact_reply_after_native_completion() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = Box::new(RecoveryFixture::new(false)?);
    let (workflow, alias, retained) = Box::pin(accepted_alias_after_completion(&fixture)).await?;
    let result: TestResult = (|| {
        require_live_quota_capability("alias replay current capability", &fixture.control)?;
        let actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Resume,
        )?;
        let before = protected_usage(&fixture)?;
        let mutation = mutation_custody(&fixture, &workflow)?;
        let replay = fixture.kernel.execute_recovery_command(&actor, &alias)?;
        assert_eq!(chio_core::canonical_json_bytes(&replay)?, retained);
        assert_eq!(protected_usage(&fixture)?, before);
        assert_eq!(mutation_custody(&fixture, &workflow)?, mutation);
        assert_eq!(external_count(&fixture.path)?, 1);
        Ok(())
    })();
    diagnostics.finish(Some(&fixture), result)
}

#[tokio::test]
async fn recovery_same_value_alias_changed_body_conflicts_after_native_completion() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = Box::new(RecoveryFixture::new(false)?);
    let (workflow, mut alias, _) = Box::pin(accepted_alias_after_completion(&fixture)).await?;
    let result: TestResult = (|| {
        require_live_quota_capability("alias conflict current capability", &fixture.control)?;
        let current = fixture.record(&workflow)?;
        if let RecoveryCommandBodyV1::ResumeWorkflow {
            expected_revision, ..
        } = &mut alias.command
        {
            assert!(current.revision.get() > expected_revision.get());
            *expected_revision = current.revision;
        } else {
            return Err("alias fixture did not retain a Resume".into());
        }
        let actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Resume,
        )?;
        let before = protected_usage(&fixture)?;
        let mutation = mutation_custody(&fixture, &workflow)?;
        assert_eq!(
            fixture
                .kernel
                .execute_recovery_command(&actor, &alias)
                .err(),
            Some(RecoveryCommandError::Conflict)
        );
        assert_eq!(protected_usage(&fixture)?, before);
        assert_eq!(mutation_custody(&fixture, &workflow)?, mutation);
        assert_eq!(external_count(&fixture.path)?, 1);
        Ok(())
    })();
    diagnostics.finish(Some(&fixture), result)
}

#[tokio::test]
async fn recovery_fresh_resume_alias_cannot_drive_an_unexecuted_first_request() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = Box::new(RecoveryFixture::new(false)?);
    let workflow = Box::pin(fixture.ready()).await?;
    let (first, _) = request_first_resume(&fixture, &workflow)?;
    let before = mutation_custody(&fixture, &workflow)?;
    let result: TestResult = Box::pin(async {
        require_live_quota_capability("alias execution current capability", &fixture.control)?;
        diagnostics.phase("fresh alias CP execution remains control-only");
        let alias =
            Box::new(fixture.command("read-unexecuted-first-request", first.command.clone())?);
        let reply =
            Box::pin(fixture.execute(alias.command_id.as_str(), alias.command.clone())).await?;
        assert_eq!(reply.status.effect, EffectObservationV1::NeverAdmitted);
        assert_eq!(external_count(&fixture.path)?, 0);
        assert_eq!(mutation_custody(&fixture, &workflow)?, before);
        let actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Resume,
        )?;
        let retained = fixture.kernel.execute_recovery_command(&actor, &alias)?;
        assert_retained_identity(&fixture, &actor, &alias, &retained)?;
        diagnostics
            .phase("original first Resume lost acknowledgement completes its fixed generation");
        Box::pin(capture_requested_generation(&fixture, &first)).await?;
        assert_eq!(external_count(&fixture.path)?, 1);
        Ok(())
    })
    .await;
    diagnostics.finish(Some(&fixture), result)
}
