//! Real authenticated commands retain quota separation and existing-work headroom.
use super::*;
use chio_store_sqlite::admission_operation_store::{
    apply_recovery_quota_fixture_resumptions, construct_recovery_planning_fixture_legacy_format,
    construct_recovery_quota_fixture_legacy_format, fill_recovery_quota_fixture_intake_bytes,
    fill_recovery_quota_fixture_intake_events, grow_recovery_quota_fixture_retained_history,
    grow_recovery_quota_fixture_uncheckpointed_history, observe_recovery_quota_fixture_errors,
    recovery_quota_fixture_finalized_shape, retain_recovery_planning_fixture_legacy_revisions,
    retain_recovery_quota_fixture_legacy_inspections, retain_recovery_quota_fixture_records,
    RecoveryQuotaFixtureDiagnosticScope, RecoveryQuotaFixtureRecord,
};

pub(super) struct QuotaTestDiagnostics {
    started: std::time::Instant,
    phase: std::cell::Cell<&'static str>,
    reported: std::cell::Cell<bool>,
    observer: RecoveryQuotaFixtureDiagnosticScope,
}

impl QuotaTestDiagnostics {
    pub(super) fn new() -> Self {
        Self {
            started: std::time::Instant::now(),
            phase: std::cell::Cell::new("fixture bootstrap"),
            reported: std::cell::Cell::new(false),
            observer: observe_recovery_quota_fixture_errors(),
        }
    }

    pub(super) fn phase(&self, phase: &'static str) {
        self.phase.set(phase);
        self.observer.reset();
    }

    pub(super) fn finish<T>(
        &self,
        fixture: Option<&RecoveryFixture>,
        result: TestResult<T>,
    ) -> TestResult<T> {
        self.observe_failure(fixture, &result);
        result
    }

    pub(super) fn observe_failure<T, E: std::fmt::Display>(
        &self,
        fixture: Option<&RecoveryFixture>,
        result: &Result<T, E>,
    ) {
        let Err(error) = result else { return };
        if self.reported.replace(true) {
            return;
        }
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok());
        let durable = fixture.map(|fixture| -> TestResult<serde_json::Value> {
            let connection = rusqlite::Connection::open_with_flags(
                fixture.path.join("admission.db"),
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )?;
            let values = connection.query_row(
                "SELECT trusted_time_high_water_unix_ms,
                    (SELECT coalesce(max(observed_at),0) FROM admission_operation_recovery_events),
                    (SELECT count(*) FROM admission_operation_recovery_events),
                    (SELECT coalesce(sum(length(payload)),0) FROM admission_operation_recovery_records)
                 FROM admission_operation_commit_meta WHERE singleton=1",
                [],
                |row| Ok((row.get::<_,i64>(0)?, row.get::<_,i64>(1)?, row.get::<_,i64>(2)?, row.get::<_,i64>(3)?)),
            )?;
            Ok(serde_json::json!({
                "trusted_high_water_unix_ms": values.0,
                "max_recovery_observed_unix_ms": values.1,
                "recovery_events": values.2,
                "retained_recovery_bytes": values.3,
            }))
        }).map(|result| result.unwrap_or_else(|error| {
                    serde_json::json!({"read_error": self.observer.error_text(&error)})
        }));
        let refusal = self.observer.snapshot();
        let clock = refusal
            .as_ref()
            .and_then(|refusal| refusal.clock_regression)
            .map(
                |(observed, high_water, recovery_high_water, fixed_runtime)| {
                    serde_json::json!({
                        "observed_unix_ms": observed,
                        "fixed_runtime_unix_s_at_refusal": fixed_runtime,
                        "trusted_high_water_unix_ms": high_water,
                        "max_recovery_observed_unix_ms": recovery_high_water,
                    })
                },
            );
        eprintln!(
            "RECOVERY_QUOTA_FIXTURE_FAILURE {}",
            serde_json::json!({
                "phase": self.phase.get(),
                "elapsed_ms": self.started.elapsed().as_millis(),
                "error": self.observer.error_text(error),
                "wall_sampled_after_refusal_unix_ms": wall,
                "fixed_runtime_unix_s": chio_kernel::fixed_runtime_unix_secs_for_current_thread(),
                "durable_snapshot_after_refusal": durable,
                "original_typed_store_refusal": refusal.as_ref().and_then(|refusal| refusal.command_refusal.as_ref()),
                "original_issuance_store_refusal": refusal.as_ref().and_then(|refusal| refusal.issuance_refusal.as_ref()),
                "original_native_capture_refusal": refusal.as_ref().and_then(|refusal| refusal.native_capture_refusal.as_ref()),
                "exact_clock_regression_sample": clock,
                "seed_expires_unix_s": fixture.map(|fixture| fixture.seed.capability.expires_at),
                "control_expires_unix_s": fixture.map(|fixture| fixture.control.expires_at),
            })
        );
    }
}

pub(super) fn require_live_quota_capability(
    label: &str,
    capability: &CapabilityToken,
) -> TestResult {
    let current = match chio_kernel::fixed_runtime_unix_secs_for_current_thread() {
        Some(fixed) => fixed,
        None => now_ms()? / 1000,
    };
    if current >= capability.expires_at {
        return Err(format!(
            "{label} expired before quota proof: current_unix_s={current}, expires_unix_s={}",
            capability.expires_at
        )
        .into());
    }
    Ok(())
}

pub(super) fn require_live_creation_authority(
    actor: &AuthenticatedRecoveryActor,
    command: &RecoveryCommandV1,
) -> TestResult {
    require_live_quota_capability("control capability", actor.capability())?;
    let RecoveryCommandBodyV1::CreateWorkflow { request_seed, .. } = &command.command else {
        return Err("quota fixture is not a Create command".into());
    };
    let seed: ToolCallRequest = serde_json::from_str(request_seed.as_str())?;
    require_live_quota_capability("original seed capability", &seed.capability)
}

fn expect_quota_refusal<T>(
    fixture: &RecoveryFixture,
    diagnostics: &QuotaTestDiagnostics,
    response: Result<T, RecoveryCommandError>,
    reason: &str,
) -> TestResult {
    let error = response.err();
    if error != Some(RecoveryCommandError::Unavailable) {
        let failure: TestResult =
            Err(format!("expected quota Unavailable, received {error:?}").into());
        diagnostics.observe_failure(Some(fixture), &failure);
    }
    assert_eq!(error, Some(RecoveryCommandError::Unavailable));
    let expected = format!("admission operation invariant failed: {reason}");
    let actual = diagnostics
        .observer
        .snapshot()
        .and_then(|snapshot| snapshot.command_refusal);
    if actual.as_deref() != Some(expected.as_str()) {
        return Err(format!("expected quota refusal {expected:?}, received {actual:?}").into());
    }
    Ok(())
}

fn connection(fixture: &RecoveryFixture) -> TestResult<rusqlite::Connection> {
    Ok(rusqlite::Connection::open(
        fixture.path.join("admission.db"),
    )?)
}

fn recovery_commands(fixture: &RecoveryFixture) -> TestResult<usize> {
    Ok(usize::try_from(connection(fixture)?.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records
         WHERE kind='command' AND record_key GLOB 'command:*'",
        [],
        |row| row.get::<_, i64>(0),
    )?)?)
}

fn foreign_retained_bytes(fixture: &RecoveryFixture) -> TestResult<u64> {
    Ok(u64::try_from(connection(fixture)?.query_row(
        "SELECT COALESCE(sum(length(payload)),0) FROM admission_operation_recovery_records
         WHERE record_key GLOB 'knowledge-*'",
        [],
        |row| row.get::<_, i64>(0),
    )?)?)
}

fn foreign_events(fixture: &RecoveryFixture) -> TestResult<u64> {
    Ok(u64::try_from(connection(fixture)?.query_row(
        "SELECT count(*) FROM admission_operation_recovery_events WHERE record_key GLOB 'knowledge-*'",
        [], |row| row.get::<_, i64>(0),
    )?)?)
}

fn foreign_snapshot(fixture: &RecoveryFixture) -> TestResult<Vec<(String, i64, String)>> {
    let connection = connection(fixture)?;
    let mut statement = connection.prepare(
        "SELECT record_key,version,payload FROM admission_operation_recovery_records
         WHERE kind='command' AND
           (record_key GLOB '*:quota-fixture:*' OR record_key GLOB 'knowledge-pin:*:quota-*')
         ORDER BY record_key",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                chio_core::sha256_hex(&row.get::<_, Vec<u8>>(2)?),
            ))
        })?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

fn fill_foreign(fixture: &RecoveryFixture, scope: &RecoveryScopeV1, count: usize) -> TestResult {
    let namespaces = [
        "semantic-capture",
        "knowledge-checkpoint",
        "knowledge-join",
        "confined-boundary",
        "product-report",
        "protected-setup",
    ];
    let records = (0..count)
        .map(|index| {
            Ok(RecoveryQuotaFixtureRecord {
                scope: scope.clone(),
                key: format!(
                    "{}:quota-fixture:{index}",
                    namespaces[index % namespaces.len()]
                ),
                payload: chio_core::canonical_json_bytes(&serde_json::json!({
                    "fixture": "foreign quota occupancy",
                    "index": index,
                }))?,
            })
        })
        .collect::<TestResult<Vec<_>>>()?;
    retain_recovery_quota_fixture_records(
        &fixture.authority.admission_operation_store(),
        &fixture.authority.mutation_fence(),
        &records,
    )?;
    Ok(())
}

async fn unused_creation(fixture: &RecoveryFixture, key: &str) -> TestResult<RecoveryCommandV1> {
    let seed = Box::pin(fixture.denied_seed_named(key)).await?;
    fixture.command(
        key,
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new(key)?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(&seed)?,
        },
    )
}

#[tokio::test]
async fn recovery_intake_ignores_foreign_command_rows_in_its_tenant() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = diagnostics.finish(None, RecoveryFixture::new(false))?;
    let result: TestResult = Box::pin(async {
        diagnostics.phase("foreign tenant record filling");
        fill_foreign(&fixture, fixture.runtime.scope(), 3584)?;
        let retained = foreign_snapshot(&fixture)?;
        assert_eq!(retained.len(), 3584);
        assert_eq!(recovery_commands(&fixture)?, 0);
        diagnostics.phase("readiness after foreign tenant records");
        let ready = fixture.ready().await;
        diagnostics.observe_failure(Some(&fixture), &ready);
        assert!(
            ready.is_ok(),
            "foreign tenant records exhausted recovery intake: {ready:?}"
        );
        let workflow = ready?;
        diagnostics.phase("cancel after foreign tenant records");
        fixture
            .execute(
                "cancel-after-foreign-tenant-traffic",
                RecoveryCommandBodyV1::CancelWorkflow {
                    workflow_id: workflow.clone(),
                    expected_revision: fixture.record(&workflow)?.revision,
                },
            )
            .await?;
        assert_eq!(
            fixture.record(&workflow)?.control,
            WorkflowControlV1::Cancelled
        );
        assert_eq!(foreign_snapshot(&fixture)?, retained);
        assert_eq!(external_count(&fixture.path)?, 0);
        Ok(())
    })
    .await;
    diagnostics.finish(Some(&fixture), result)
}

#[tokio::test]
async fn recovery_existing_work_ignores_foreign_authority_command_rows() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = diagnostics.finish(None, RecoveryFixture::new(false))?;
    let result: TestResult = Box::pin(async {
        diagnostics.phase("initial retained original and workflow readiness");
        let workflow = fixture.ready().await?;
        diagnostics.phase("native capture before foreign authority records");
        fixture
            .execute(
                "capture-before-foreign-traffic",
                RecoveryCommandBodyV1::ResumeWorkflow {
                    workflow_id: workflow.clone(),
                    expected_revision: fixture.record(&workflow)?.revision,
                },
            )
            .await?;
        let mut foreign_scope = fixture.runtime.scope().clone();
        foreign_scope.tenant_id = RecoveryTenantId::new("foreign-tenant")?;
        diagnostics.phase("foreign authority record filling");
        fill_foreign(&fixture, &foreign_scope, 8192)?;
        let retained = foreign_snapshot(&fixture)?;
        diagnostics.phase("inspect after foreign authority records");
        let inspect = fixture
            .execute(
                "inspect-after-foreign-authority-traffic",
                RecoveryCommandBodyV1::InspectWorkflow {
                    workflow_id: workflow.clone(),
                },
            )
            .await;
        diagnostics.observe_failure(Some(&fixture), &inspect);
        assert!(
            inspect.is_ok(),
            "foreign authority records exhausted existing work: {:?}",
            inspect.as_ref().err(),
        );
        diagnostics.phase("resume after foreign authority records");
        fixture
            .execute(
                "resume-after-foreign-authority-traffic",
                RecoveryCommandBodyV1::ResumeWorkflow {
                    workflow_id: workflow.clone(),
                    expected_revision: fixture.record(&workflow)?.revision,
                },
            )
            .await?;
        diagnostics.phase("report after foreign authority records");
        fixture
            .execute(
                "report-after-foreign-authority-traffic",
                RecoveryCommandBodyV1::ReportDecision {
                    workflow_id: workflow.clone(),
                    expected_revision: fixture.record(&workflow)?.revision,
                    decision: RecoveryReportedDecision::Accepted,
                },
            )
            .await?;
        assert_eq!(foreign_snapshot(&fixture)?, retained);
        assert_eq!(external_count(&fixture.path)?, 1);
        Ok(())
    })
    .await;
    diagnostics.finish(Some(&fixture), result)
}

fn command_units(
    fixture: &RecoveryFixture,
    workflow: &WorkflowId,
    slot: usize,
) -> TestResult<usize> {
    let scope = chio_core::sha256_hex(&chio_core::canonical_json_bytes(fixture.runtime.scope())?);
    let key = format!("workflow-quota:{scope}:{}", workflow.as_str());
    Ok(usize::try_from(connection(fixture)?.query_row(
        "SELECT json_extract(payload,?2) FROM admission_operation_recovery_records
         WHERE record_key=?1 AND kind='command'",
        rusqlite::params![key, format!("$.commands[{slot}]")],
        |row| row.get::<_, i64>(0),
    )?)?)
}

fn require_live_workflow_seed(fixture: &RecoveryFixture, workflow: &WorkflowId) -> TestResult {
    let record = fixture.record(workflow)?;
    let seed: ToolCallRequest = serde_json::from_str(record.creation_seed.as_str())?;
    require_live_quota_capability("owned original seed capability", &seed.capability)
}

#[tokio::test]
async fn recovery_mutation_identity_partitions_preserve_native_and_control_allowances() -> TestResult
{
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = diagnostics.finish(None, RecoveryFixture::new(false))?;
    let result: TestResult = Box::pin(async {
        let workflow = fixture.ready().await?;
        let record = fixture.record(&workflow)?;
        let action = record.action.as_ref().ok_or("action is absent")?;
        let offer = OfferId::new(&format!(
            "offer:{}",
            recovery_digest(
                chio_core_types::recovery::RecoveryDigestDomain::ActionIntent,
                action
            )?
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
        ))?;
        for (slot, permission, body) in [
            (
                0,
                RecoveryPermission::Create,
                RecoveryCommandBodyV1::CreateWorkflow {
                    creation_key: CreationKey::new("ticket-1")?,
                    template: RecoveryTemplateV1::SupportTicketPublicIssue,
                    request_seed: record.creation_seed.clone(),
                },
            ),
            (
                1,
                RecoveryPermission::Select,
                RecoveryCommandBodyV1::SelectOffer {
                    workflow_id: workflow.clone(),
                    expected_revision: record.revision,
                    offer_id: offer,
                },
            ),
            (
                2,
                RecoveryPermission::Approve,
                RecoveryCommandBodyV1::SubmitApproval {
                    workflow_id: workflow.clone(),
                    expected_revision: record.revision,
                    approval: text(record.approval.as_ref().ok_or("approval is absent")?)?,
                },
            ),
        ] {
            let actor = fixture.kernel.authenticate_recovery_actor(
                fixture.runtime.scope(),
                &fixture.control,
                permission,
            )?;
            let mut replay = None;
            diagnostics
                .phase("same-valued planning identities reach their exact purpose allocation");
            for index in command_units(&fixture, &workflow, slot)?..8 {
                let command =
                    fixture.command(&format!("planning-identity-{slot}-{index}"), body.clone())?;
                require_live_quota_capability("control capability", &fixture.control)?;
                let response = fixture.kernel.execute_recovery_command_with_origin(
                    &actor,
                    &command,
                    &fixture.process,
                )?;
                assert_eq!(fixture.record(&workflow)?.revision, record.revision);
                replay = Some((command, response));
            }
            assert_eq!(command_units(&fixture, &workflow, slot)?, 8);
            let overflow = fixture.command(&format!("planning-overflow-{slot}"), body)?;
            diagnostics
                .phase("planning identity refuses without using native or control allocation");
            require_live_quota_capability("control capability", &fixture.control)?;
            if permission == RecoveryPermission::Create {
                require_live_creation_authority(&actor, &overflow)?;
            }
            let before = protected_usage(&fixture)?;
            expect_quota_refusal(
                &fixture,
                &diagnostics,
                fixture.kernel.execute_recovery_command_with_origin(
                    &actor,
                    &overflow,
                    &fixture.process,
                ),
                "recovery command quota exhausted",
            )?;
            assert_eq!(protected_usage(&fixture)?, before);
            let (command, response) = replay.ok_or("planning replay is absent")?;
            let replayed = fixture.kernel.execute_recovery_command_with_origin(
                &actor,
                &command,
                &fixture.process,
            )?;
            assert_eq!(
                chio_core::canonical_json_bytes(&replayed)?,
                chio_core::canonical_json_bytes(&response)?
            );
            assert_eq!(protected_usage(&fixture)?, before);
        }
        let resume =
            fill_resumptions(&fixture, &workflow, 24)?.ok_or("retained resumption is absent")?;
        require_live_workflow_seed(&fixture, &workflow)?;
        diagnostics
            .phase("actual native capture after all planning and Resume identities are occupied");
        fixture
            .runtime
            .execute_command(&fixture.control, &resume)
            .await?;
        let completed = fixture.record(&workflow)?;
        assert!(completed.captured && completed.effect.is_settled());
        assert!(matches!(
            &completed.release,
            ReleaseDispositionV1::Released { .. }
        ));
        assert_eq!(external_count(&fixture.path)?, 1);
        for (slot, permission) in [
            (4, RecoveryPermission::Cancel),
            (5, RecoveryPermission::Report),
        ] {
            let actor = fixture.kernel.authenticate_recovery_actor(
                fixture.runtime.scope(),
                &fixture.control,
                permission,
            )?;
            for index in 0..8 {
                let revision = fixture.record(&workflow)?.revision;
                let body = if slot == 4 {
                    RecoveryCommandBodyV1::CancelWorkflow {
                        workflow_id: workflow.clone(),
                        expected_revision: revision,
                    }
                } else {
                    RecoveryCommandBodyV1::ReportDecision {
                        workflow_id: workflow.clone(),
                        expected_revision: revision,
                        decision: RecoveryReportedDecision::Accepted,
                    }
                };
                let command = fixture.command(&format!("last-control-{slot}-{index}"), body)?;
                fixture.kernel.execute_recovery_command(&actor, &command)?;
                if index > 0 {
                    assert_eq!(fixture.record(&workflow)?.revision, revision);
                }
            }
            assert_eq!(command_units(&fixture, &workflow, slot)?, 8);
            let body = if slot == 4 {
                RecoveryCommandBodyV1::CancelWorkflow {
                    workflow_id: workflow.clone(),
                    expected_revision: fixture.record(&workflow)?.revision,
                }
            } else {
                RecoveryCommandBodyV1::ReportDecision {
                    workflow_id: workflow.clone(),
                    expected_revision: fixture.record(&workflow)?.revision,
                    decision: RecoveryReportedDecision::Accepted,
                }
            };
            let overflow = fixture.command(&format!("control-overflow-{slot}"), body)?;
            diagnostics.phase("control identity refuses at its own exact allocation");
            require_live_quota_capability("control capability", &fixture.control)?;
            let before = protected_usage(&fixture)?;
            expect_quota_refusal(
                &fixture,
                &diagnostics,
                fixture.kernel.execute_recovery_command(&actor, &overflow),
                "recovery command quota exhausted",
            )?;
            assert_eq!(protected_usage(&fixture)?, before);
        }
        assert_eq!(recovery_commands(&fixture)?, 64);
        let before = protected_usage(&fixture)?;
        let settled = fixture.runtime.settle(&fixture.control, &workflow)?;
        assert!(settled.effect.is_settled());
        assert_eq!(protected_usage(&fixture)?, before);
        Ok(())
    })
    .await;
    diagnostics.finish(Some(&fixture), result)
}

pub(super) fn protected_usage(fixture: &RecoveryFixture) -> TestResult<(i64, i64, i64)> {
    Ok(connection(fixture)?.query_row(
        "SELECT
            (SELECT count(*) FROM admission_operation_recovery_records),
            (SELECT count(*) FROM admission_operation_recovery_events),
            (SELECT count(*) FROM authority_global_commits)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?)
}

#[tokio::test]
async fn recovery_inspection_keeps_command_and_event_capacity() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = diagnostics.finish(None, RecoveryFixture::new(false))?;
    let result: TestResult = Box::pin(async {
        let workflow = fixture.ready().await?;
        let actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Inspect,
        )?;
        let before = protected_usage(&fixture)?;
        let commands_before = recovery_commands(&fixture)?;
        let revision = fixture.record(&workflow)?.revision;
        for index in 0..8193 {
            diagnostics.phase("fresh authorized status polling");
            let command = fixture.command(
                &format!("fresh-status-poll-{index}"),
                RecoveryCommandBodyV1::InspectWorkflow {
                    workflow_id: workflow.clone(),
                },
            )?;
            let status = fixture.kernel.execute_recovery_command(&actor, &command)?;
            assert_eq!(status.workflow_id, workflow);
            assert_eq!(status.revision, revision);
            if index == 0 {
                assert_eq!(
                    protected_usage(&fixture)?,
                    before,
                    "Inspect retained a tombstone, event or global commit"
                );
            }
        }
        require_live_quota_capability("inspect capability", &fixture.control)?;
        assert_eq!(protected_usage(&fixture)?, before);
        assert_eq!(recovery_commands(&fixture)?, commands_before);
        assert_eq!(fixture.record(&workflow)?.revision, revision);
        assert_eq!(external_count(&fixture.path)?, 0);
        diagnostics.phase("actual native capture after authority-sized status polling");
        require_live_quota_capability("control capability", &fixture.control)?;
        require_live_workflow_seed(&fixture, &workflow)?;
        fixture
            .execute(
                "native-effect-after-status-polling",
                RecoveryCommandBodyV1::ResumeWorkflow {
                    workflow_id: workflow.clone(),
                    expected_revision: revision,
                },
            )
            .await?;
        let current = fixture.record(&workflow)?;
        assert!(current.captured);
        assert!(current.effect.is_settled());
        assert_eq!(current.effect.applied_effects(), Some(SafeInteger::new(1)?));
        assert!(matches!(
            current.release,
            ReleaseDispositionV1::Released { .. }
        ));
        assert_eq!(external_count(&fixture.path)?, 1);
        Ok(())
    })
    .await;
    diagnostics.finish(Some(&fixture), result)
}

#[tokio::test]
async fn recovery_inspection_returns_current_status_for_reused_identity() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = diagnostics.finish(None, RecoveryFixture::new(false))?;
    let result: TestResult = Box::pin(async {
        let workflow = fixture.ready().await?;
        let actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Inspect,
        )?;
        let inspect = fixture.command(
            "current-status-poll",
            RecoveryCommandBodyV1::InspectWorkflow {
                workflow_id: workflow.clone(),
            },
        )?;
        let initial = fixture.kernel.execute_recovery_command(&actor, &inspect)?;
        assert!(!initial.effect.is_settled());
        diagnostics.phase("native effect between reads of one Inspect identity");
        fixture
            .execute(
                "effect-between-status-polls",
                RecoveryCommandBodyV1::ResumeWorkflow {
                    workflow_id: workflow.clone(),
                    expected_revision: fixture.record(&workflow)?.revision,
                },
            )
            .await?;
        let current = fixture.record(&workflow)?;
        assert!(current.captured);
        assert!(current.effect.is_settled());
        assert!(matches!(
            current.release,
            ReleaseDispositionV1::Released { .. }
        ));
        let before = protected_usage(&fixture)?;
        diagnostics.phase("current status under reused Inspect identity");
        let latest = fixture.kernel.execute_recovery_command(&actor, &inspect)?;
        assert_eq!(latest.revision, current.revision);
        assert_eq!(latest.control, current.control);
        assert_eq!(latest.effect, current.effect);
        assert_eq!(latest.release, current.release);
        assert_eq!(protected_usage(&fixture)?, before);
        assert_eq!(external_count(&fixture.path)?, 1);
        fixture.kernel.revoke_capability(&fixture.control.id)?;
        let after_revocation = protected_usage(&fixture)?;
        assert!(matches!(
            fixture
                .runtime
                .execute_command(&fixture.control, &inspect)
                .await,
            Err(crate::recovery::RecoveryRuntimeError::AuthorityDenied)
        ));
        assert_eq!(protected_usage(&fixture)?, after_revocation);
        Ok(())
    })
    .await;
    diagnostics.finish(Some(&fixture), result)
}

async fn foreign_retained_growth_preserves_native_work(byte_ceiling: bool) -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = diagnostics.finish(None, RecoveryFixture::new(false))?;
    let result: TestResult = Box::pin(async {
        diagnostics.phase("retained original before materializing approved work");
        let create = unused_creation(&fixture, "fresh-work-after-foreign-growth").await?;
        let workflow = fixture.ready().await?;
        let store = fixture.authority.admission_operation_store();
        let fence = fixture.authority.mutation_fence();
        diagnostics.phase("foreign participant retained growth");
        if byte_ceiling {
            fill_recovery_quota_fixture_intake_bytes(
                &store,
                &fence,
                fixture.runtime.scope(),
                48 * 1024 * 1024,
            )?;
            assert_eq!(foreign_retained_bytes(&fixture)?, 48 * 1024 * 1024);
        } else {
            fill_recovery_quota_fixture_intake_events(
                &store,
                &fence,
                fixture.runtime.scope(),
                57344,
            )?;
            assert_eq!(foreign_events(&fixture)?, 57344);
        }
        diagnostics.phase("ordinary participant refuses only its own exhausted pool");
        let scope =
            chio_core::sha256_hex(&chio_core::canonical_json_bytes(fixture.runtime.scope())?);
        let before = protected_usage(&fixture)?;
        assert_eq!(
            retain_recovery_quota_fixture_records(
                &store,
                &fence,
                &[RecoveryQuotaFixtureRecord {
                    scope: fixture.runtime.scope().clone(),
                    key: format!("knowledge-pin:{scope}:quota-pool-overflow"),
                    payload: chio_core::canonical_json_bytes(&"foreign participant overflow")?,
                }]
            )
            .err(),
            Some(
                chio_kernel::admission_operation::AdmissionOperationStoreError::Invariant(
                    "recovery retained resource exhausted".to_owned()
                )
            )
        );
        assert_eq!(protected_usage(&fixture)?, before);
        let retained = foreign_snapshot(&fixture)?;
        let create_actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Create,
        )?;
        require_live_creation_authority(&create_actor, &create)?;
        diagnostics.phase("fresh recovery intake after foreign participant growth");
        let created = fixture.kernel.execute_recovery_command_with_origin(
            &create_actor,
            &create,
            &fixture.process,
        );
        diagnostics.observe_failure(Some(&fixture), &created);
        assert!(
            created.is_ok(),
            "foreign participants exhausted recovery intake: {created:?}"
        );
        let inspect_actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Inspect,
        )?;
        let before_polling = protected_usage(&fixture)?;
        for index in 0..128 {
            let inspect = fixture.command(
                &format!("status-after-foreign-growth-{index}"),
                RecoveryCommandBodyV1::InspectWorkflow {
                    workflow_id: workflow.clone(),
                },
            )?;
            fixture
                .kernel
                .execute_recovery_command(&inspect_actor, &inspect)?;
        }
        assert_eq!(protected_usage(&fixture)?, before_polling);
        diagnostics.phase("actual native capture and settlement after foreign growth");
        require_live_quota_capability("control capability", &fixture.control)?;
        require_live_workflow_seed(&fixture, &workflow)?;
        fixture
            .execute(
                "native-effect-after-foreign-growth",
                RecoveryCommandBodyV1::ResumeWorkflow {
                    workflow_id: workflow.clone(),
                    expected_revision: fixture.record(&workflow)?.revision,
                },
            )
            .await?;
        let current = fixture.record(&workflow)?;
        assert!(current.captured);
        assert!(current.effect.is_settled());
        assert!(matches!(
            current.release,
            ReleaseDispositionV1::Released { .. }
        ));
        assert_eq!(external_count(&fixture.path)?, 1);
        assert_eq!(foreign_snapshot(&fixture)?, retained);
        Ok(())
    })
    .await;
    diagnostics.finish(Some(&fixture), result)
}

#[tokio::test]
async fn recovery_foreign_retained_events_preserve_intake_and_native_capture() -> TestResult {
    foreign_retained_growth_preserves_native_work(false).await
}

#[tokio::test]
async fn recovery_foreign_retained_bytes_preserve_intake_and_native_capture() -> TestResult {
    foreign_retained_growth_preserves_native_work(true).await
}

#[tokio::test]
async fn recovery_native_capture_survives_large_retained_database_history() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = diagnostics.finish(None, RecoveryFixture::new(false))?;
    let result: TestResult = Box::pin(async {
        let workflow = fixture.ready().await?;
        diagnostics.phase("bounded unrelated SQLite retained history");
        let before = protected_usage(&fixture)?;
        let bytes = grow_recovery_quota_fixture_retained_history(
            &fixture.authority.admission_operation_store(),
            &fixture.authority.mutation_fence(),
            2 * 1024 * 1024 * 1024 + 1,
        )?;
        assert!(bytes > 2 * 1024 * 1024 * 1024);
        assert_eq!(protected_usage(&fixture)?, before);
        diagnostics.phase("actual native capture with retained history above two GiB");
        require_live_quota_capability("control capability", &fixture.control)?;
        require_live_workflow_seed(&fixture, &workflow)?;
        fixture
            .execute(
                "native-effect-after-large-history",
                RecoveryCommandBodyV1::ResumeWorkflow {
                    workflow_id: workflow.clone(),
                    expected_revision: fixture.record(&workflow)?.revision,
                },
            )
            .await?;
        let current = fixture.record(&workflow)?;
        assert!(current.captured);
        assert!(current.effect.is_settled());
        assert!(matches!(
            &current.release,
            ReleaseDispositionV1::Released { .. }
        ));
        assert_eq!(external_count(&fixture.path)?, 1);
        Ok(())
    })
    .await;
    diagnostics.finish(Some(&fixture), result)
}

fn legacy_inspection_snapshot(fixture: &RecoveryFixture) -> TestResult<Vec<(String, i64, String)>> {
    let connection = connection(fixture)?;
    let mut statement = connection.prepare(
        "SELECT record_key,version,payload FROM admission_operation_recovery_records
         WHERE kind='command' AND record_key GLOB 'command:*'
           AND json_extract(payload,'$.response.command_id') GLOB 'legacy-status-poll-*'
         ORDER BY record_key",
    )?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                chio_core::sha256_hex(&row.get::<_, Vec<u8>>(2)?),
            ))
        })?
        .collect::<Result<_, _>>()?;
    Ok(rows)
}

#[tokio::test]
async fn recovery_legacy_inspection_saturation_preserves_native_controls() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = diagnostics.finish(None, RecoveryFixture::new(false))?;
    let result: TestResult = Box::pin(async {
        // Construct one genuine authenticated old-format workflow from its beginning.
        // This does not delete/reset any reservation or manufacture protected state.
        let expected = WorkflowId::new(&format!(
            "workflow:{}",
            chio_core::sha256_hex(&chio_core::canonical_json_bytes(&(
                fixture.runtime.scope(),
                CreationKey::new("ticket-1")?
            ))?)
        ))?;
        let legacy_scope = construct_recovery_quota_fixture_legacy_format(
            &fixture.authority.admission_operation_store(),
            &fixture.authority.mutation_fence(),
            fixture.runtime.scope(),
            &expected,
        )?;
        let workflow = fixture.ready().await?;
        assert_eq!(workflow, expected);
        let inspector = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Inspect,
        )?;
        diagnostics.phase("retained old-format Inspect identities at tenant ceiling");
        retain_recovery_quota_fixture_legacy_inspections(
            &fixture.authority.admission_operation_store(),
            &inspector,
            &workflow,
            4096 - recovery_commands(&fixture)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?;
        assert_eq!(recovery_commands(&fixture)?, 4096);
        drop(legacy_scope);
        let retained = legacy_inspection_snapshot(&fixture)?;
        assert!(!retained.is_empty());
        diagnostics.phase("native capture after legacy Inspect saturation");
        require_live_quota_capability("control capability", &fixture.control)?;
        require_live_workflow_seed(&fixture, &workflow)?;
        fixture
            .execute(
                "resume-after-legacy-status-polling",
                RecoveryCommandBodyV1::ResumeWorkflow {
                    workflow_id: workflow.clone(),
                    expected_revision: fixture.record(&workflow)?.revision,
                },
            )
            .await?;
        let record = fixture.record(&workflow)?;
        assert!(record.captured);
        assert!(record.effect.is_settled());
        assert!(matches!(
            &record.release,
            ReleaseDispositionV1::Released { .. }
        ));
        let before = protected_usage(&fixture)?;
        let old_inspect = fixture.command(
            "legacy-status-poll-0",
            RecoveryCommandBodyV1::InspectWorkflow {
                workflow_id: workflow.clone(),
            },
        )?;
        let latest = fixture
            .kernel
            .execute_recovery_command(&inspector, &old_inspect)?;
        assert_eq!(latest.revision, record.revision);
        assert_eq!(latest.effect, record.effect);
        assert_eq!(latest.release, record.release);
        assert_eq!(protected_usage(&fixture)?, before);
        for (id, permission, report) in [
            (
                "cancel-after-legacy-status-polling",
                RecoveryPermission::Cancel,
                false,
            ),
            (
                "report-after-legacy-status-polling",
                RecoveryPermission::Report,
                true,
            ),
        ] {
            let expected_revision = fixture.record(&workflow)?.revision;
            let body = if report {
                RecoveryCommandBodyV1::ReportDecision {
                    workflow_id: workflow.clone(),
                    expected_revision,
                    decision: RecoveryReportedDecision::Accepted,
                }
            } else {
                RecoveryCommandBodyV1::CancelWorkflow {
                    workflow_id: workflow.clone(),
                    expected_revision,
                }
            };
            let actor = fixture.kernel.authenticate_recovery_actor(
                fixture.runtime.scope(),
                &fixture.control,
                permission,
            )?;
            fixture
                .kernel
                .execute_recovery_command(&actor, &fixture.command(id, body)?)?;
        }
        assert_eq!(legacy_inspection_snapshot(&fixture)?, retained);
        assert_eq!(external_count(&fixture.path)?, 1);
        Ok(())
    })
    .await;
    diagnostics.finish(Some(&fixture), result)
}

fn fill_resumptions(
    fixture: &RecoveryFixture,
    workflow: &WorkflowId,
    target: usize,
) -> TestResult<Option<RecoveryCommandV1>> {
    let revision = fixture.record(workflow)?.revision;
    let current = command_units(fixture, workflow, 3)?;
    if target > 24 || current > target {
        return Err("resumption fixture exceeds its allocation".into());
    }
    let commands = (current..target)
        .map(|index| {
            fixture.command(
                &format!("retained-resumption-{index}"),
                RecoveryCommandBodyV1::ResumeWorkflow {
                    workflow_id: workflow.clone(),
                    expected_revision: revision,
                },
            )
        })
        .collect::<TestResult<Vec<_>>>()?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Resume,
    )?;
    apply_recovery_quota_fixture_resumptions(
        &fixture.authority.admission_operation_store(),
        &actor,
        &commands,
        &fixture.authority.mutation_fence(),
        now_ms()?,
    )?;
    assert_eq!(command_units(fixture, workflow, 3)?, target);
    assert_eq!(fixture.record(workflow)?.revision, revision);
    Ok(commands.last().cloned())
}

#[tokio::test]
async fn recovery_mutating_command_pressure_preserves_owned_native_progress() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = diagnostics.finish(None, RecoveryFixture::new(false))?;
    let result: TestResult = Box::pin(async {
        let workflow = fixture.ready().await?;
        diagnostics.phase("real Resume identities fill the owning workflow allocation");
        let resume =
            fill_resumptions(&fixture, &workflow, 24)?.ok_or("retained resumption is absent")?;
        assert_eq!(external_count(&fixture.path)?, 0);
        let actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Resume,
        )?;
        let overflow = fixture.command(
            "resumption-over-the-owned-command-ceiling",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: workflow.clone(),
                expected_revision: fixture.record(&workflow)?.revision,
            },
        )?;
        require_live_quota_capability("control capability", &fixture.control)?;
        let before = protected_usage(&fixture)?;
        diagnostics.phase("fresh mutation identity refuses at the exact command ceiling");
        expect_quota_refusal(
            &fixture,
            &diagnostics,
            fixture.kernel.execute_recovery_command(&actor, &overflow),
            "recovery command quota exhausted",
        )?;
        assert_eq!(protected_usage(&fixture)?, before);
        diagnostics.phase("retained mutation drives actual native progress after saturation");
        require_live_workflow_seed(&fixture, &workflow)?;
        let result = fixture
            .runtime
            .execute_command(&fixture.control, &resume)
            .await?;
        let current = fixture.record(&workflow)?;
        assert!(current.captured);
        assert!(current.effect.is_settled());
        assert!(matches!(
            &current.release,
            ReleaseDispositionV1::Released { .. }
        ));
        assert_eq!(command_units(&fixture, &workflow, 3)?, 24);
        assert_eq!(external_count(&fixture.path)?, 1);
        let replay = fixture
            .runtime
            .execute_command(&fixture.control, &resume)
            .await?;
        assert_eq!(
            chio_core::canonical_json_bytes(&result.original_response)?,
            chio_core::canonical_json_bytes(&replay.original_response)?,
        );
        assert_eq!(external_count(&fixture.path)?, 1);
        Ok(())
    })
    .await;
    diagnostics.finish(Some(&fixture), result)
}

pub(super) async fn prepared_provider_unknown(
    diagnostics: &QuotaTestDiagnostics,
) -> TestResult<(Box<RecoveryFixture>, WorkflowId)> {
    eprintln!("RECOVERY_PROVIDER_FINALITY_PHASE fixture_bootstrap_before");
    let fixture = Box::new(diagnostics.finish(None, RecoveryFixture::new(false))?);
    eprintln!("RECOVERY_PROVIDER_FINALITY_PHASE fixture_bootstrap_returned");
    eprintln!(
        "RECOVERY_PROVIDER_FINALITY_READY_FRAME bytes={}",
        future_frame_bytes(|| fixture.ready()),
    );
    eprintln!("RECOVERY_PROVIDER_FINALITY_PHASE ready_before_await");
    let workflow = Box::pin(fixture.ready()).await?;
    eprintln!("RECOVERY_PROVIDER_FINALITY_PHASE ready_returned");
    fixture.behavior.store(1, Ordering::SeqCst);
    eprintln!(
        "RECOVERY_PROVIDER_FINALITY_EXECUTION_FRAME bytes={}",
        future_frame_bytes(|| fixture.execute(
            "captured-unknown-before-resource-pressure",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: workflow.clone(),
                expected_revision: SafeInteger::ZERO,
            },
        )),
    );
    eprintln!("RECOVERY_PROVIDER_FINALITY_PHASE native_capture_before_await");
    Box::pin(fixture.execute(
        "captured-unknown-before-resource-pressure",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: workflow.clone(),
            expected_revision: fixture.record(&workflow)?.revision,
        },
    ))
    .await?;
    eprintln!("RECOVERY_PROVIDER_FINALITY_PHASE native_capture_returned");
    assert!(matches!(
        fixture.record(&workflow)?.effect,
        EffectObservationV1::Unknown { .. }
    ));
    assert_eq!(external_count(&fixture.path)?, 1);
    Ok((fixture, workflow))
}

fn wait_for_provider_lookup_spacing(
    fixture: &RecoveryFixture,
    workflow: &WorkflowId,
) -> TestResult {
    use sha2::{Digest, Sha256};
    let key = format!(
        "workflow:{}:{}",
        hex::encode(Sha256::digest(chio_core::canonical_json_bytes(
            fixture.runtime.scope(),
        )?)),
        workflow.as_str(),
    );
    // Observe the exact current workflow event that the owning cooldown uses.
    // The reader changes no clock, event, quota, deadline or authority token.
    let observed: i64 = connection(fixture)?.query_row(
        "SELECT e.observed_at FROM admission_operation_recovery_records r
         JOIN admission_operation_recovery_events e
           ON e.record_key=r.record_key AND e.record_version=r.version
         WHERE r.record_key=?1 AND r.kind='workflow'",
        [&key],
        |row| row.get(0),
    )?;
    let observed = u64::try_from(observed)?;
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?;
    let elapsed = now
        .checked_sub(observed)
        .ok_or("provider test wall time precedes its durable lookup event")?;
    if elapsed < 1000 {
        std::thread::sleep(std::time::Duration::from_millis(1001 - elapsed));
    }
    require_live_quota_capability("spaced settlement capability", &fixture.control)?;
    Ok(())
}

fn provider_finality_observations(
    fixture: &RecoveryFixture,
    workflow: &WorkflowId,
    diagnostics: &QuotaTestDiagnostics,
    actor: &AuthenticatedRecoveryActor,
) -> TestResult<(
    chio_kernel::admission_operation::AdmissionOperationId,
    Vec<u8>,
    Box<chio_core_types::recovery::SignedRecoveryProviderFinalityV1>,
)> {
    diagnostics.phase("all thirty-two actual provider lookup reservations");
    eprintln!("RECOVERY_PROVIDER_FINALITY_PHASE provider_lookups_before");
    let mut last_lookup = None;
    for index in 0..32 {
        if index != 0 {
            wait_for_provider_lookup_spacing(fixture, workflow)?;
        }
        require_live_quota_capability("provider lookup capability", &fixture.control)?;
        last_lookup = Some(
            fixture
                .kernel
                .reserve_recovery_provider_lookup(actor, workflow)?,
        );
    }
    assert_eq!(fixture.record(workflow)?.provider_lookups.get(), 32);
    let before = protected_usage(fixture)?;
    // Exclude the cooldown from the thirty-third refusal's cause.
    wait_for_provider_lookup_spacing(fixture, workflow)?;
    require_live_quota_capability("settlement capability", &fixture.control)?;
    assert!(fixture
        .kernel
        .reserve_recovery_provider_lookup(actor, workflow)
        .is_err());
    assert_eq!(protected_usage(fixture)?, before);
    eprintln!("RECOVERY_PROVIDER_FINALITY_PHASE provider_lookups_returned");
    let lookup = last_lookup.ok_or("provider lookup is absent")?;
    let record = lookup.workflow();
    let native = fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(
            &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                record
                    .admission
                    .as_ref()
                    .ok_or("admission is absent")?
                    .native_operation_id
                    .as_str(),
            )?,
        )?
        .ok_or("native original is absent")?;
    let native_id = native.binding().operation_id().clone();
    let native_before = chio_core::canonical_json_bytes(&native.to_persisted())?;
    let proof = Box::new(provider_finality_proof(fixture, &lookup)?);
    Ok((native_id, native_before, proof))
}

async fn pressured_provider_finality(
    fixture: &RecoveryFixture,
    workflow: &WorkflowId,
    diagnostics: &QuotaTestDiagnostics,
) -> TestResult {
    diagnostics.phase("foreign events and actual mutation identities before settlement");
    eprintln!("RECOVERY_PROVIDER_FINALITY_PHASE foreign_pressure_before");
    fill_recovery_quota_fixture_intake_events(
        &fixture.authority.admission_operation_store(),
        &fixture.authority.mutation_fence(),
        fixture.runtime.scope(),
        57344,
    )?;
    fill_resumptions(fixture, workflow, 24)?;
    eprintln!("RECOVERY_PROVIDER_FINALITY_PHASE foreign_pressure_returned");
    fixture
        .kernel
        .revoke_capability(&fixture.seed.capability.id)?;
    eprintln!("RECOVERY_PROVIDER_FINALITY_PHASE cancel_before_await");
    Box::pin(fixture.execute(
        "cancel-captured-original-before-provider-observations",
        RecoveryCommandBodyV1::CancelWorkflow {
            workflow_id: workflow.clone(),
            expected_revision: fixture.record(workflow)?.revision,
        },
    ))
    .await?;
    eprintln!("RECOVERY_PROVIDER_FINALITY_PHASE cancel_returned");
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Settle,
    )?;
    let (native_id, native_before, proof) =
        provider_finality_observations(fixture, workflow, diagnostics, &actor)?;
    diagnostics.phase("positive native provider finality after pressure and lookup ceiling");
    eprintln!("RECOVERY_PROVIDER_FINALITY_PHASE finality_attachment_before");
    fixture
        .kernel
        .attach_recovery_provider_finality(&actor, workflow, &proof)?;
    eprintln!("RECOVERY_PROVIDER_FINALITY_PHASE finality_attachment_returned");
    eprintln!("RECOVERY_PROVIDER_FINALITY_PHASE report_before_await");
    Box::pin(fixture.execute(
        "report-settled-original-after-control-cancellation",
        RecoveryCommandBodyV1::ReportDecision {
            workflow_id: workflow.clone(),
            expected_revision: fixture.record(workflow)?.revision,
            decision: RecoveryReportedDecision::Accepted,
        },
    ))
    .await?;
    eprintln!("RECOVERY_PROVIDER_FINALITY_PHASE report_returned");
    let revision = fixture.record(workflow)?.revision;
    diagnostics.phase("same-valued controls after both one-way control changes");
    for index in 0..7 {
        for (permission, body) in [
            (
                RecoveryPermission::Cancel,
                RecoveryCommandBodyV1::CancelWorkflow {
                    workflow_id: workflow.clone(),
                    expected_revision: revision,
                },
            ),
            (
                RecoveryPermission::Report,
                RecoveryCommandBodyV1::ReportDecision {
                    workflow_id: workflow.clone(),
                    expected_revision: revision,
                    decision: RecoveryReportedDecision::Accepted,
                },
            ),
        ] {
            let actor = fixture.kernel.authenticate_recovery_actor(
                fixture.runtime.scope(),
                &fixture.control,
                permission,
            )?;
            let command = fixture.command(
                &format!("same-control-{}-{index}", permission.wire_name()),
                body,
            )?;
            fixture.kernel.execute_recovery_command(&actor, &command)?;
            assert_eq!(fixture.record(workflow)?.revision, revision);
        }
    }
    for (slot, permission, body) in [
        (
            4,
            RecoveryPermission::Cancel,
            RecoveryCommandBodyV1::CancelWorkflow {
                workflow_id: workflow.clone(),
                expected_revision: revision,
            },
        ),
        (
            5,
            RecoveryPermission::Report,
            RecoveryCommandBodyV1::ReportDecision {
                workflow_id: workflow.clone(),
                expected_revision: revision,
                decision: RecoveryReportedDecision::Accepted,
            },
        ),
    ] {
        assert_eq!(command_units(fixture, workflow, slot)?, 8);
        let actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            permission,
        )?;
        let command = fixture.command(&format!("same-control-overflow-{slot}"), body)?;
        diagnostics.phase("same-valued controls stop at their own identity allocation");
        require_live_quota_capability("control capability", &fixture.control)?;
        let before = protected_usage(fixture)?;
        expect_quota_refusal(
            fixture,
            diagnostics,
            fixture.kernel.execute_recovery_command(&actor, &command),
            "recovery command quota exhausted",
        )?;
        assert_eq!(protected_usage(fixture)?, before);
    }
    let before = protected_usage(fixture)?;
    eprintln!("RECOVERY_PROVIDER_FINALITY_PHASE retained_finality_and_settlement_before");
    fixture
        .kernel
        .attach_recovery_provider_finality(&actor, workflow, &proof)?;
    let settled = fixture.runtime.settle(&fixture.control, workflow)?;
    assert!(settled.effect.is_settled());
    assert_eq!(settled.effect.applied_effects(), Some(SafeInteger::new(1)?));
    assert_eq!(settled.release, ReleaseDispositionV1::NotAvailable);
    assert_eq!(protected_usage(fixture)?, before);
    let after = fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(&native_id)?
        .ok_or("native original lost")?;
    assert_eq!(
        native_before,
        chio_core::canonical_json_bytes(&after.to_persisted())?
    );
    assert_eq!(external_count(&fixture.path)?, 1);
    eprintln!("RECOVERY_PROVIDER_FINALITY_PHASE native_integrity_assertions_returned");
    Ok(())
}

#[tokio::test]
async fn recovery_provider_finality_survives_mutation_and_foreign_pressure() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    eprintln!(
        "RECOVERY_PROVIDER_FINALITY_PREPARATION_FRAME bytes={}",
        future_frame_bytes(|| prepared_provider_unknown(&diagnostics)),
    );
    let (fixture, workflow) = diagnostics.finish(
        None,
        Box::pin(prepared_provider_unknown(&diagnostics)).await,
    )?;
    eprintln!(
        "RECOVERY_PROVIDER_FINALITY_PRESSURE_FRAME bytes={}",
        future_frame_bytes(|| pressured_provider_finality(&fixture, &workflow, &diagnostics)),
    );
    let result = Box::pin(pressured_provider_finality(
        &fixture,
        &workflow,
        &diagnostics,
    ))
    .await;
    diagnostics.finish(Some(&fixture), result)
}
#[tokio::test]
async fn recovery_command_flood_cannot_steal_another_workflows_resume() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = diagnostics.finish(None, RecoveryFixture::new(false))?;
    let result: TestResult = Box::pin(async {
        let attacker = fixture.ready().await?;
        fixture
            .execute(
                "completed-work-before-command-flood",
                RecoveryCommandBodyV1::ResumeWorkflow {
                    workflow_id: attacker.clone(),
                    expected_revision: fixture.record(&attacker)?.revision,
                },
            )
            .await?;
        let victim = fixture
            .ready_named("unresumed-owned-work", "victim")
            .await?;
        assert_eq!(external_count(&fixture.path)?, 1);
        assert!(!fixture.record(&victim)?.captured);
        let actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Resume,
        )?;
        let revision = fixture.record(&attacker)?.revision;
        let make = |index| {
            fixture.command(
                &format!("fresh-noop-on-completed-work-{index}"),
                RecoveryCommandBodyV1::ResumeWorkflow {
                    workflow_id: attacker.clone(),
                    expected_revision: revision,
                },
            )
        };
        diagnostics.phase("real mutating command flood on a different completed workflow");
        let mut accepted = 0;
        let mut rejected_batch = false;
        for batch in 0..512 {
            let commands = (batch * 8..batch * 8 + 8)
                .map(&make)
                .collect::<TestResult<Vec<_>>>()?;
            let before = protected_usage(&fixture)?;
            match apply_recovery_quota_fixture_resumptions(
                &fixture.authority.admission_operation_store(),
                &actor,
                &commands,
                &fixture.authority.mutation_fence(),
                now_ms()?,
            ) {
                Ok(_) => accepted += commands.len(),
                Err(RecoveryCommandPortError::Store(
                    chio_kernel::admission_operation::AdmissionOperationStoreError::Invariant(
                        reason,
                    ),
                )) if reason == "recovery command quota exhausted" => {
                    assert_eq!(protected_usage(&fixture)?, before);
                    rejected_batch = true;
                    break;
                }
                Err(error) => {
                    return Err(format!("command flood failed outside quota: {error}").into())
                }
            }
        }
        assert!(
            rejected_batch,
            "bounded mutation flood never reached an owning quota"
        );
        assert!(accepted > 0);
        let mut saturated = false;
        for index in accepted..accepted + 8 {
            diagnostics.phase("exact last command allocation on completed work");
            require_live_quota_capability("control capability", &fixture.control)?;
            let before = protected_usage(&fixture)?;
            let result = fixture
                .kernel
                .execute_recovery_command(&actor, &make(index)?);
            if result.is_err() {
                expect_quota_refusal(
                    &fixture,
                    &diagnostics,
                    result,
                    "recovery command quota exhausted",
                )?;
                assert_eq!(protected_usage(&fixture)?, before);
                saturated = true;
                break;
            }
        }
        assert!(
            saturated,
            "last partial batch did not reach the exact command allocation"
        );
        assert_eq!(fixture.record(&attacker)?.revision, revision);
        diagnostics
            .phase("fresh Resume for an already-ready workflow with no prior Resume identity");
        require_live_quota_capability("control capability", &fixture.control)?;
        require_live_workflow_seed(&fixture, &victim)?;
        fixture
            .execute(
                "victim-fresh-resume-after-other-work-saturated",
                RecoveryCommandBodyV1::ResumeWorkflow {
                    workflow_id: victim.clone(),
                    expected_revision: fixture.record(&victim)?.revision,
                },
            )
            .await?;
        let record = fixture.record(&victim)?;
        assert!(record.captured);
        assert!(record.effect.is_settled());
        assert!(matches!(
            &record.release,
            ReleaseDispositionV1::Released { .. }
        ));
        assert_eq!(external_count(&fixture.path)?, 2);
        Ok(())
    })
    .await;
    diagnostics.finish(Some(&fixture), result)
}

pub(super) fn provider_finality_proof(
    fixture: &RecoveryFixture,
    lookup: &RecoveryProviderLookup,
) -> TestResult<chio_core_types::recovery::SignedRecoveryProviderFinalityV1> {
    use chio_core_types::recovery::SignedRecoveryProviderFinalityV1;
    let record = lookup.workflow();
    let operation = match &record.effect {
        EffectObservationV1::Unknown { operation } => operation,
        _ => return Err("provider proof requires the captured unknown original".into()),
    };
    let native = fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(
            &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                operation.operation_id().as_str(),
            )?,
        )?
        .ok_or("native original is absent")?;
    let profile = lookup.deployment();
    let now = now_ms()?;
    Ok(SignedRecoveryProviderFinalityV1::sign(
        RecoveryProviderFinalityV1 {
            schema: RecoveryProviderFinalitySchema::V1,
            version: VersionV1,
            scope: record.scope.clone(),
            workflow_id: record.workflow_id.clone(),
            continuation_id: record.continuation_id.clone(),
            operation_id: operation.operation_id().clone(),
            native_admission_digest: operation.native_admission_digest(),
            attempt_id: ProviderAttemptId::new(
                &native
                    .provider_attempt()
                    .ok_or("provider attempt")?
                    .attempt_id,
            )?,
            provider: profile.effect_contract.provider.clone(),
            account: profile.effect_contract.account.clone(),
            resource_digest: ResourceDigest::from_bytes(recovery_digest(
                chio_core_types::recovery::RecoveryDigestDomain::ProviderResource,
                &profile.effect_contract.resource,
            )?),
            contract_digest: profile.contract_digest,
            observed_at_unix_ms: SafeInteger::new(now)?,
            expires_at_unix_ms: SafeInteger::new(now + 30_000)?,
            disposition: RecoveryEffectDisposition::Succeeded,
            applied_effects: SafeInteger::new(1)?,
        },
        &Keypair::from_seed(&[143; 32]),
    )?)
}

fn wal_observation(fixture: &RecoveryFixture) -> TestResult<(i64, i64)> {
    let connection = rusqlite::Connection::open_with_flags(
        fixture.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (busy, log, checkpointed): (i64, i64, i64) =
        connection.query_row("PRAGMA wal_checkpoint(NOOP)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    assert_eq!(busy, 0);
    assert!(log >= checkpointed && checkpointed >= 0);
    Ok((log, checkpointed))
}

#[tokio::test]
async fn recovery_mutation_replay_and_status_survive_uncheckpointed_intake_pressure() -> TestResult
{
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = diagnostics.finish(None, RecoveryFixture::new(false))?;
    let result: TestResult = Box::pin(async {
        let workflow = fixture.ready().await?;
        fixture.behavior.store(1, Ordering::SeqCst);
        let resume = fixture.command(
            "captured-before-uncheckpointed-history",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: workflow.clone(),
                expected_revision: fixture.record(&workflow)?.revision,
            },
        )?;
        fixture
            .runtime
            .execute_command(&fixture.control, &resume)
            .await?;
        assert!(matches!(
            fixture.record(&workflow)?.effect,
            EffectObservationV1::Unknown { .. }
        ));
        assert_eq!(external_count(&fixture.path)?, 1);
        let actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Resume,
        )?;
        let committed = fixture.kernel.execute_recovery_command(&actor, &resume)?;
        let reader = rusqlite::Connection::open_with_flags(
            fixture.path.join("admission.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        reader.execute_batch("BEGIN")?;
        let _: i64 = reader.query_row(
            "SELECT count(*) FROM admission_operation_recovery_events",
            [],
            |row| row.get(0),
        )?;
        let before = protected_usage(&fixture)?;
        diagnostics.phase("pinned reader and real unrelated uncheckpointed pages");
        let pressure = grow_recovery_quota_fixture_uncheckpointed_history(
            &fixture.authority.admission_operation_store(),
            &fixture.authority.mutation_fence(),
            80 * 1024 * 1024,
        )?;
        assert!((80 * 1024 * 1024..128 * 1024 * 1024).contains(&pressure));
        assert_eq!(protected_usage(&fixture)?, before);
        let cancel_actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Cancel,
        )?;
        let fresh = fixture.command(
            "fresh-control-at-physical-intake-pressure",
            RecoveryCommandBodyV1::CancelWorkflow {
                workflow_id: workflow.clone(),
                expected_revision: fixture.record(&workflow)?.revision,
            },
        )?;
        diagnostics.phase("fresh mutation must retain the physical intake floor");
        require_live_quota_capability("control capability", &fixture.control)?;
        expect_quota_refusal(
            &fixture,
            &diagnostics,
            fixture
                .kernel
                .execute_recovery_command(&cancel_actor, &fresh),
            "recovery disk headroom exhausted",
        )?;
        assert_eq!(protected_usage(&fixture)?, before);
        let wal = wal_observation(&fixture)?;
        diagnostics
            .phase("committed mutation replay and current status do not checkpoint or write");
        let replay = fixture.kernel.execute_recovery_command(&actor, &resume)?;
        assert_eq!(
            chio_core::canonical_json_bytes(&replay)?,
            chio_core::canonical_json_bytes(&committed)?
        );
        let conflict = fixture.command(
            resume.command_id.as_str(),
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: workflow.clone(),
                expected_revision: fixture.record(&workflow)?.revision,
            },
        )?;
        assert_eq!(
            fixture
                .kernel
                .execute_recovery_command(&actor, &conflict)
                .err(),
            Some(RecoveryCommandError::Conflict)
        );
        let inspector = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Inspect,
        )?;
        let status = fixture.kernel.execute_recovery_command(
            &inspector,
            &fixture.command(
                "status-at-physical-pressure",
                RecoveryCommandBodyV1::InspectWorkflow {
                    workflow_id: workflow.clone(),
                },
            )?,
        )?;
        assert_eq!(status.revision, fixture.record(&workflow)?.revision);
        assert_eq!(protected_usage(&fixture)?, before);
        assert_eq!(wal_observation(&fixture)?, wal);
        diagnostics.phase(
            "trusted native lookup and finality use settlement headroom below the hard WAL floor",
        );
        let settled = fixture.runtime.settle(&fixture.control, &workflow)?;
        assert!(matches!(
            settled.effect,
            EffectObservationV1::Unknown { .. }
        ));
        let settler = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Settle,
        )?;
        let lookup = fixture
            .kernel
            .reserve_recovery_provider_lookup(&settler, &workflow)?;
        let proof = provider_finality_proof(&fixture, &lookup)?;
        fixture
            .kernel
            .attach_recovery_provider_finality(&settler, &workflow, &proof)?;
        assert!(fixture
            .runtime
            .settle(&fixture.control, &workflow)?
            .effect
            .is_settled());
        assert_eq!(external_count(&fixture.path)?, 1);
        reader.execute_batch("COMMIT")?;
        drop(reader);
        diagnostics
            .phase("production checkpoint restores fresh mutation intake after the reader ends");
        let fresh = fixture.command(
            "fresh-control-after-pinned-reader-ends",
            RecoveryCommandBodyV1::CancelWorkflow {
                workflow_id: workflow.clone(),
                expected_revision: fixture.record(&workflow)?.revision,
            },
        )?;
        require_live_quota_capability("control capability", &fixture.control)?;
        fixture
            .kernel
            .execute_recovery_command(&cancel_actor, &fresh)?;
        let (log, checkpointed) = wal_observation(&fixture)?;
        let page_size: i64 =
            connection(&fixture)?.query_row("PRAGMA page_size", [], |row| row.get(0))?;
        assert!((log - checkpointed) * (page_size + 24) < 64 * 1024 * 1024);
        assert_eq!(external_count(&fixture.path)?, 1);
        Ok(())
    })
    .await;
    diagnostics.finish(Some(&fixture), result)
}

pub(super) fn fixture_source_labels(
    path: &std::path::Path,
    default: InformationLabel,
) -> TestResult<[InformationLabel; 3]> {
    use std::collections::BTreeSet;
    let marker = path.join("dense-source-padding");
    if !marker.exists() {
        return Ok([default.clone(), default.clone(), default]);
    }
    let shared = path.join("dense-source-native").exists();
    let components = if shared { 1 } else { 3 };
    let mut padding = std::fs::read_to_string(marker)?.parse::<usize>()?;
    if padding > components * 255 * 240 {
        return Err("dense source fixture exceeds identifier limits".into());
    }
    let owner = PrincipalId::new("reviewer")?;
    let mut labels = Vec::new();
    for component in 0..components {
        let mut readers = BTreeSet::from([owner.clone()]);
        for index in 0..255 {
            let prefix = format!("reader-{component}-{index:03}:");
            let used = padding.min(256 - prefix.len());
            padding -= used;
            readers.insert(PrincipalId::new(format!("{prefix}{}", "\"".repeat(used)))?);
        }
        labels.push(InformationLabel::try_known(
            BTreeMap::from([(owner.clone(), readers)]),
            restricted_label()
                .compartments()
                .ok_or("restricted compartments")?
                .clone(),
        )?);
    }
    if padding != 0 {
        return Err("dense source padding was not fully represented".into());
    }
    if shared {
        let label = labels.pop().ok_or("shared source label is absent")?;
        Ok([label.clone(), label.clone(), label])
    } else {
        labels
            .try_into()
            .map_err(|_| "dense source component count changed".into())
    }
}

pub(super) fn fixture_preview_clearance(path: &std::path::Path) -> TestResult<InformationLabel> {
    use std::collections::BTreeSet;
    if !path.join("dense-source-padding").exists() {
        return Ok(restricted_label());
    }
    let owner = PrincipalId::new("reviewer")?;
    Ok(InformationLabel::try_known(
        BTreeMap::from([(owner.clone(), BTreeSet::from([owner]))]),
        restricted_label()
            .compartments()
            .ok_or("restricted compartments")?
            .clone(),
    )?)
}

pub(super) fn fixture_seed_arguments(
    path: &std::path::Path,
    default: serde_json::Value,
) -> TestResult<serde_json::Value> {
    let marker = path.join("support-issue-body-bytes");
    if !marker.exists() {
        return Ok(default);
    }
    let bytes = std::fs::read_to_string(marker)?.parse::<usize>()?;
    if !(1..=16384).contains(&bytes) {
        return Err("support issue fixture exceeds the actual body bound".into());
    }
    let input = RecoverySupportIssueInputV1 {
        title: ProtectedText::new("support ticket")?,
        body: ProtectedText::new(&"\"".repeat(bytes))?,
    };
    let canonical = chio_core::canonical_json_bytes(&input)?;
    let _: RecoverySupportIssueInputV1 = chio_core_types::recovery::decode_contract(&canonical)?;
    Ok(serde_json::from_slice(&canonical)?)
}

fn dense_fixture(padding: usize, body_bytes: usize) -> TestResult<RecoveryFixture> {
    dense_fixture_with_capture_observation(padding, body_bytes, None)
}

type NativeBoundaryObservation = Arc<std::sync::Mutex<Option<(usize, usize, String)>>>;

fn future_frame_bytes<F: std::future::Future>(_: impl FnOnce() -> F) -> usize {
    std::mem::size_of::<F>()
}

fn observe_native_boundary_record(
    database: &std::path::Path,
) -> Result<(usize, usize, String), &'static str> {
    let observed: TestResult<(usize, usize, String)> = (|| {
        let connection = rusqlite::Connection::open_with_flags(
            database,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let count: i64 = connection.query_row(
            "SELECT count(*) FROM admission_operation_recovery_records WHERE kind='workflow'",
            [],
            |row| row.get(0),
        )?;
        if count != 1 {
            return Err("native boundary observation requires one owned workflow".into());
        }
        let bytes: Option<Vec<u8>> = connection.query_row(
            "SELECT CASE WHEN length(payload) BETWEEN 1 AND 262144 THEN payload END
             FROM admission_operation_recovery_records WHERE kind='workflow'",
            [],
            |row| row.get(0),
        )?;
        let bytes = bytes.ok_or("native boundary observation exceeds record bound")?;
        let record: RecoveryWorkflowRecordV1 = serde_json::from_slice(&bytes)?;
        if record.captured
            || record.native_link.is_none()
            || chio_core::canonical_json_bytes(&record)? != bytes
        {
            return Err("native boundary observation changed its pre-capture shape".into());
        }
        let normalized =
            chio_core::canonical_json_bytes(&recovery_quota_fixture_finalized_shape(&record)?)?;
        Ok((
            bytes.len(),
            normalized.len(),
            chio_core::sha256_hex(&normalized),
        ))
    })();
    observed.map_err(|_| "bounded native record observation unavailable")
}

fn dense_fixture_with_capture_observation(
    padding: usize,
    body_bytes: usize,
    observation: Option<NativeBoundaryObservation>,
) -> TestResult<RecoveryFixture> {
    let directory = tempfile::tempdir()?;
    std::fs::write(
        directory.path().join("dense-source-padding"),
        padding.to_string(),
    )?;
    std::fs::write(
        directory.path().join("dense-source-native"),
        b"core-native-owner",
    )?;
    if body_bytes != 0 {
        std::fs::write(
            directory.path().join("support-issue-body-bytes"),
            body_bytes.to_string(),
        )?;
    }
    let observer = observation.map(|observation| {
        let database = directory.path().join("admission.db");
        let observer: chio_kernel::NativeSecurityCaptureObserver = Arc::new(move |committed| {
            eprintln!("RECOVERY_NATIVE_BOUNDARY_CALLBACK_ENTRY committed={committed}");
            if committed {
                return Ok(());
            }
            // Keep diagnostic decoding off the deep native evaluation stack.
            // One read-only worker uses its normal default stack and joins
            // before capture proceeds; it grants no authority and writes nothing.
            let database = database.clone();
            let worker = std::thread::Builder::new()
                .name("native-record-observation".into())
                .spawn(move || {
                    eprintln!("RECOVERY_NATIVE_BOUNDARY_WORKER_ENTRY");
                    observe_native_boundary_record(&database)
                })
                .map_err(|_| {
                    KernelError::Internal("native observation worker unavailable".into())
                })?;
            eprintln!("RECOVERY_NATIVE_BOUNDARY_SPAWN_RETURNED");
            let joined = worker
                .join()
                .map_err(|_| KernelError::Internal("native observation worker failed".into()))?;
            eprintln!("RECOVERY_NATIVE_BOUNDARY_JOIN_RETURNED");
            let observed = joined.map_err(|error| KernelError::Internal(error.into()))?;
            let mut observation = observation
                .lock()
                .map_err(|_| KernelError::Internal("native observation lock failed".into()))?;
            if observation.is_some() {
                return Err(KernelError::Internal(
                    "native boundary capture observation repeated".into(),
                ));
            }
            *observation = Some(observed);
            Ok(())
        });
        observer
    });
    RecoveryFixture::open_with_native_observer(
        directory.path().to_path_buf(),
        Some(directory),
        false,
        observer,
    )
}

async fn finalized_candidate_near_size(target: usize) -> TestResult<(RecoveryFixture, WorkflowId)> {
    // Fixed shared legal readers leave native policy/caller custody headroom.
    // The actual bounded issue body grows through seed, creation seed and the
    // caller envelope, including their canonical JSON string escaping.
    const SOURCE_PADDING: usize = 8000;
    let reference = dense_fixture(SOURCE_PADDING, 0)?;
    let workflow = Box::pin(native_dense_ready(&reference)).await?;
    let actor = reference.kernel.authenticate_recovery_actor(
        reference.runtime.scope(),
        &reference.control,
        RecoveryPermission::Resume,
    )?;
    reference.runtime.prepare_original(&actor, &workflow)?;
    let base = verify_finalized_shape_invariance(&reference.record(&workflow)?)?;
    if target <= base {
        return Err(format!(
            "dense reference already exceeds target: base={base}, target={target}"
        )
        .into());
    }
    // One quote costs two bytes in the structured seed, four in its protected
    // creation text and four in the protected finalized request text.
    let fixture = dense_fixture(SOURCE_PADDING, (target - base) / 10)?;
    let workflow = Box::pin(native_dense_ready(&fixture)).await?;
    Ok((fixture, workflow))
}

fn staged_finalized_candidate(
    fixture: &RecoveryFixture,
    workflow: &WorkflowId,
) -> TestResult<(
    RecoveryWorkflowRecordV1,
    FinalizedRequestEnvelopeV1,
    RecoveryNativeIdentity,
)> {
    let mut record = fixture.record(workflow)?;
    let published = record.envelope.is_some();
    let grant = record
        .signed_grant
        .as_ref()
        .ok_or("signature was not retained before finalization")?;
    let mut request = record.seed.clone();
    request.declassification_grant = Some(grant.clone().into());
    let profile = fixture
        .kernel
        .recovery_deployment(fixture.runtime.scope())?;
    let identity = fixture
        .kernel
        .recovery_native_identity(&request, &profile.security_context)?;
    let (request_digest, binding_digest) = fixture.process.recovery_request_digests(
        fixture.runtime.scope().process_id.as_str(),
        &crate::recovery::materialize::operation_key(&record.continuation_id),
        &request,
    )?;
    let from_hex = |value: &str| -> TestResult<[u8; 32]> {
        if value.len() != 64 {
            return Err("native digest has wrong size".into());
        }
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
        }
        Ok(bytes)
    };
    let envelope = FinalizedRequestEnvelopeV1 {
        action_intent: grant.body().recovery.action_intent,
        authorization_requirements: grant.body().recovery.authorization_requirements,
        request: text(&request)?,
        process_request_digest: ProcessRequestDigest::from_bytes(from_hex(&request_digest)?),
        process_binding_digest: ProcessCallBindingDigest::from_bytes(from_hex(&binding_digest)?),
    };
    let operation = OperationId::new(identity.binding().operation_id().as_str())?;
    record.envelope = Some(envelope.clone());
    record.admission = Some(RecoveryAdmissionIntentV1 {
        intent: AdmissionIntentRef::new(&format!("admission:{}", operation.as_str()))?,
        native_binding: identity.binding().to_persisted(),
        native_operation_id: operation,
        process_request_digest: envelope.process_request_digest,
        process_binding_digest: envelope.process_binding_digest,
    });
    record.effect = EffectObservationV1::AdmissionUnresolved {
        admission_intent: record
            .admission
            .as_ref()
            .ok_or("staged intent")?
            .intent
            .clone(),
    };
    if !published {
        record.revision = SafeInteger::new(record.revision.get() + 1)?;
    }
    Ok((record, envelope, identity))
}

fn verify_finalized_shape_invariance(record: &RecoveryWorkflowRecordV1) -> TestResult<usize> {
    let original = serde_json::to_value(record)?;
    let normalized = recovery_quota_fixture_finalized_shape(record)?;
    let shape = serde_json::to_value(&normalized)?;
    for field in [
        "scope",
        "origin",
        "workflow_id",
        "step_id",
        "continuation_id",
        "seed",
        "creation_seed",
        "deployment_digest",
        "created_by",
        "effect_cardinality",
        "action",
        "process_reservation",
        "selected",
        "review",
        "approval",
        "issuance",
        "signed_grant",
        "envelope",
        "admission",
        "original_flow",
    ] {
        assert!(
            original.get(field) == shape.get(field),
            "accounting clone changed immutable {field}"
        );
    }
    Ok(chio_core::canonical_json_bytes(&normalized)?.len())
}

fn verify_candidate_input_bounds(
    fixture: &RecoveryFixture,
    candidate: &RecoveryWorkflowRecordV1,
) -> TestResult {
    let issue: RecoverySupportIssueInputV1 = chio_core_types::recovery::decode_contract(
        &chio_core::canonical_json_bytes(&candidate.seed.arguments)?,
    )?;
    let seed_bytes = candidate.creation_seed.as_str().len();
    let request_bytes = candidate
        .envelope
        .as_ref()
        .ok_or("finalized request is absent")?
        .request
        .as_str()
        .len();
    assert!(issue.title.as_str().len() <= 256);
    assert!(issue.body.as_str().len() <= 16384);
    assert!(seed_bytes <= 32768);
    assert!(request_bytes <= 65536);
    let flow = candidate
        .original_flow
        .as_ref()
        .ok_or("original flow absent")?;
    assert!(flow.principal_label == flow.lineage_label);
    assert!(flow.principal_label == flow.session_label);
    let label_bytes = chio_core::canonical_json_bytes(&flow.principal_label)?.len();
    assert!(
        label_bytes <= 24 * 1024,
        "fixture policy labels exceeded their reserved margin"
    );
    let store = fixture.authority.admission_operation_store();
    let (operation, original) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &fixture.seed.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("original denial request is absent")?;
    assert_eq!(
        operation.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    let retained_bytes = original.canonical_bytes().len();
    assert!(retained_bytes <= 262144);
    eprintln!(
        "RECOVERY_CANDIDATE_INPUT_BOUNDS {}",
        serde_json::json!({
            "issue_body_bytes":issue.body.as_str().len(),"seed_bytes":seed_bytes,
            "finalized_request_bytes":request_bytes,"original_retained_request_bytes":retained_bytes,
            "shared_label_bytes":label_bytes,"shared_label_digest":chio_core::sha256_hex(&chio_core::canonical_json_bytes(&flow.principal_label)?),
            "policy_argument_representation":"live request digest; actual argument payload is absent from native policy evidence",
            "route":"trusted native owner; CP command/display transport is independently bounded",
        })
    );
    Ok(())
}

fn verify_captured_native_bounds(
    fixture: &RecoveryFixture,
    record: &RecoveryWorkflowRecordV1,
) -> TestResult {
    use chio_kernel::admission_operation::AdmissionOperationId;
    let operation_id = AdmissionOperationId::from_persisted(
        record
            .admission
            .as_ref()
            .ok_or("captured admission absent")?
            .native_operation_id
            .as_str(),
    )?;
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let (operation, original) = store
        .load_retained_tool_request(&operation_id, &fence, now_ms()?)?
        .ok_or("captured retained request absent")?;
    let ledger = store
        .load_native_dispatch_ledger(&operation_id, &fence, now_ms()?)?
        .ok_or("captured native ledger absent")?;
    let policy = serde_json::from_slice::<serde_json::Value>(&ledger.canonical_record)?;
    let policy_bytes =
        chio_core::canonical_json_bytes(policy.get("policy").ok_or("native policy absent")?)?.len();
    assert!(original.canonical_bytes().len() <= 262144);
    assert!(
        policy_bytes <= 224 * 1024,
        "native policy must retain at least 32KiB safety margin"
    );
    assert!(
        ledger.canonical_record.len() <= 224 * 1024,
        "native ledger must retain at least 32KiB safety margin"
    );
    let connection = rusqlite::Connection::open_with_flags(
        fixture.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    use rusqlite::OptionalExtension;
    let context: Option<Option<Vec<u8>>> = connection
        .query_row(
            "SELECT CASE WHEN length(context_json) BETWEEN 1 AND 1048576 THEN context_json END
         FROM admission_operation_caller_contexts WHERE operation_id=?1",
            [operation_id.as_str()],
            |row| row.get(0),
        )
        .optional()?;
    let native_caller = operation
        .provider_attempt()
        .is_some_and(|attempt| attempt.is_native_caller_report());
    // This fixture uses the actual in-process broker path. It never creates
    // caller-release custody or a caller frame, including before completion.
    assert!(
        !native_caller,
        "native fixture transport changed to caller execution"
    );
    assert!(operation.caller_dispatch_context_digest().is_none());
    assert!(
        context.is_none(),
        "broker native capture unexpectedly retained a caller frame"
    );
    eprintln!(
        "RECOVERY_CAPTURED_NATIVE_BOUNDS {}",
        serde_json::json!({
            "retained_request_bytes":original.canonical_bytes().len(),"native_policy_bytes":policy_bytes,
            "native_ledger_bytes":ledger.canonical_record.len(),"native_ledger_limit":1048576,
            "native_policy_limit":262144,"native_caller":native_caller,"caller_frame_present":false,
            "caller_custody_qualification":false,
        })
    );
    Ok(())
}

#[tokio::test]
async fn recovery_finalized_candidate_reserves_terminal_growth_before_publication() -> TestResult {
    const SPARE_BOUNDARY: usize = 262144 - 32768;
    let diagnostics = QuotaTestDiagnostics::new();
    let (fixture, workflow) = finalized_candidate_near_size(SPARE_BOUNDARY + 768).await?;
    let result: TestResult = Box::pin(async {
        let actor = fixture.kernel.authenticate_recovery_actor(fixture.runtime.scope(), &fixture.control, RecoveryPermission::Resume)?;
        require_live_workflow_seed(&fixture, &workflow)?;
        diagnostics.phase("real finalized candidate just beyond required terminal byte headroom");
        let publication = fixture.runtime.prepare_original(&actor, &workflow);
        let (candidate, envelope, identity) = staged_finalized_candidate(&fixture, &workflow)?;
        verify_candidate_input_bounds(&fixture, &candidate)?;
        let bytes = chio_core::canonical_json_bytes(&candidate)?.len();
        let normalized_bytes = verify_finalized_shape_invariance(&candidate)?;
        eprintln!("RECOVERY_FINALIZED_CANDIDATE_BOUNDARY {}", serde_json::json!({
            "bytes":bytes, "spare_boundary":SPARE_BOUNDARY, "maximum":262144,
            "normalized_bytes":normalized_bytes,
            "published":fixture.record(&workflow)?.envelope.is_some(), "captured":candidate.captured,
        }));
        assert!((SPARE_BOUNDARY+1..SPARE_BOUNDARY+2048).contains(&bytes),
            "supported dense source did not reach the intended spare-byte boundary: {bytes}");
        assert!(publication.is_err(), "oversized finalized candidate was durably published with only {} bytes of terminal headroom", 262144-bytes);
        assert!(fixture.record(&workflow)?.envelope.is_none());
        let before = protected_usage(&fixture)?;
        let error = fixture.authority.admission_operation_store().finalize_envelope(
            &actor, &workflow, &envelope, &identity, &fixture.authority.mutation_fence(), now_ms()?,
        ).err();
        assert_eq!(error, Some(chio_kernel::admission_operation::AdmissionOperationStoreError::Invariant(
            "recovery terminal record headroom exhausted".to_owned())));
        assert_eq!(protected_usage(&fixture)?, before);
        assert_eq!(external_count(&fixture.path)?, 0);
        Ok(())
    }).await;
    diagnostics.finish(Some(&fixture), result)
}

#[tokio::test]
async fn recovery_finalized_candidate_with_terminal_headroom_captures_and_releases() -> TestResult {
    const SPARE_BOUNDARY: usize = 262144 - 32768;
    let diagnostics = QuotaTestDiagnostics::new();
    let (fixture, workflow) = finalized_candidate_near_size(SPARE_BOUNDARY - 768).await?;
    let result: TestResult = Box::pin(async {
        let actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Resume,
        )?;
        diagnostics.phase("real finalized candidate just within required terminal byte headroom");
        fixture.runtime.prepare_original(&actor, &workflow)?;
        let bytes = chio_core::canonical_json_bytes(&fixture.record(&workflow)?)?.len();
        let normalized_bytes = verify_finalized_shape_invariance(&fixture.record(&workflow)?)?;
        verify_candidate_input_bounds(&fixture, &fixture.record(&workflow)?)?;
        eprintln!(
            "RECOVERY_FINALIZED_CANDIDATE_BOUNDARY {}",
            serde_json::json!({"bytes":bytes,"normalized_bytes":normalized_bytes,"spare_boundary":SPARE_BOUNDARY})
        );
        assert!(
            (SPARE_BOUNDARY - 2048..=SPARE_BOUNDARY).contains(&bytes),
            "supported dense source did not reach the intended spare-byte boundary: {bytes}"
        );
        require_live_workflow_seed(&fixture, &workflow)?;
        let response = fixture
            .execute(
                "native-effect-near-terminal-byte-boundary",
                RecoveryCommandBodyV1::ResumeWorkflow {
                    workflow_id: workflow.clone(),
                    expected_revision: fixture.record(&workflow)?.revision,
                },
            )
            .await?;
        let completed = fixture.record(&workflow)?;
        if !completed.captured || !completed.effect.is_settled() {
            let native = completed.admission.as_ref().map(|admission| {
                let operation = chio_kernel::admission_operation::AdmissionOperationId::from_persisted(admission.native_operation_id.as_str())?;
                fixture.authority.admission_operation_store().load_by_operation_id(&operation)
            }).transpose()?.flatten();
            let decision = fixture.kernel.receipt_log().receipts().last().and_then(|receipt| {
                use chio_core::receipt::decision::Decision;
                match receipt.decision.as_ref()? {
                    Decision::Allow => Some(serde_json::json!({"verdict":"allow"})),
                    Decision::Deny { reason,guard } => Some(serde_json::json!({"verdict":"deny","reason":diagnostics.observer.error_text(reason),"guard":diagnostics.observer.error_text(guard)})),
                    Decision::Cancelled { reason } => Some(serde_json::json!({"verdict":"cancelled","reason":diagnostics.observer.error_text(reason)})),
                    Decision::Incomplete { reason } => Some(serde_json::json!({"verdict":"incomplete","reason":diagnostics.observer.error_text(reason)})),
                }
            });
            eprintln!("RECOVERY_FINALIZED_NATIVE_PROGRESS {}",serde_json::json!({
                "whole_record_bytes":chio_core::canonical_json_bytes(&completed)?.len(),
                "normalized_record_bytes":chio_core::canonical_json_bytes(&recovery_quota_fixture_finalized_shape(&completed)?)?.len(),
                "captured":completed.captured,"admission_closed":completed.admission_closed,
                "control":completed.control,"effect":completed.effect,"release":completed.release,
                "native_state":native.as_ref().map(|operation|operation.state()),
                "native_version":native.as_ref().map(|operation|operation.version()),
                "native_dispatch_committed":native.as_ref().is_some_and(|operation|operation.dispatch_commit().is_some()),
                "returned_original_present":response.original_response.is_some(),
                "latest_native_receipt_decision":decision,"external_effects":external_count(&fixture.path)?,
            }));
            return Err("supported near-boundary candidate did not complete its original native effect".into());
        }
        assert!(matches!(
            &completed.release,
            ReleaseDispositionV1::Released { .. }
        ));
        assert!(chio_core::canonical_json_bytes(&completed)?.len() < 262144);
        verify_captured_native_bounds(&fixture, &completed)?;
        assert_eq!(external_count(&fixture.path)?, 1);
        Ok(())
    })
    .await;
    diagnostics.finish(Some(&fixture), result)
}

async fn calibrated_native_edge_fixture(
) -> TestResult<(Box<RecoveryFixture>, WorkflowId, NativeBoundaryObservation)> {
    const BOUNDARY: usize = 262144 - 32768;
    const TARGET: usize = BOUNDARY - 32;
    const SOURCE_PADDING: usize = 8000;
    let reference = dense_fixture(SOURCE_PADDING, 0)?;
    let reference_workflow = Box::pin(native_dense_ready(&reference)).await?;
    let actor = reference.kernel.authenticate_recovery_actor(
        reference.runtime.scope(),
        &reference.control,
        RecoveryPermission::Resume,
    )?;
    reference
        .runtime
        .prepare_original(&actor, &reference_workflow)?;
    let base = verify_finalized_shape_invariance(&reference.record(&reference_workflow)?)?;
    let mut body_bytes = TARGET
        .checked_sub(base)
        .ok_or("native edge reference exceeds target")?
        / 10;
    drop(reference);
    // Fresh native identities change the encoded digest-array lengths slightly.
    // Every bounded calibration attempt repeats all real owners on a private
    // store; only the supported issue-body length is adjusted before creation.
    for attempt in 0..16 {
        let observation: NativeBoundaryObservation = Arc::new(std::sync::Mutex::new(None));
        let fixture = dense_fixture_with_capture_observation(
            SOURCE_PADDING,
            body_bytes,
            Some(observation.clone()),
        )?;
        let workflow = Box::pin(native_dense_ready(&fixture)).await?;
        let actor = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Resume,
        )?;
        require_live_workflow_seed(&fixture, &workflow)?;
        let publication = fixture.runtime.prepare_original(&actor, &workflow);
        let (candidate, _, _) = staged_finalized_candidate(&fixture, &workflow)?;
        let normalized = verify_finalized_shape_invariance(&candidate)?;
        assert!(candidate.native_link.is_none());
        let operation_id = candidate
            .admission
            .as_ref()
            .ok_or("edge admission absent")?
            .native_operation_id
            .clone();
        let link_growth = chio_core::canonical_json_bytes(&Some(operation_id))?
            .len()
            .checked_sub(chio_core::canonical_json_bytes(&candidate.native_link)?.len())
            .ok_or("native link encoded growth regressed")?;
        let whole_bytes = chio_core::canonical_json_bytes(&candidate)?.len();
        let guaranteed_crossing = whole_bytes
            .checked_add(link_growth)
            .is_some_and(|bytes| bytes > BOUNDARY);
        eprintln!(
            "RECOVERY_ADMITTED_EDGE_CALIBRATION {}",
            serde_json::json!({
                "attempt":attempt,"target":TARGET,"normalized_bytes":normalized,"body_bytes":body_bytes,
                "whole_bytes":whole_bytes,"native_link_growth_bytes":link_growth,
                "guaranteed_crossing":guaranteed_crossing,
                "published":fixture.record(&workflow)?.envelope.is_some(),
            })
        );
        if normalized <= BOUNDARY {
            publication?;
        } else if publication.is_ok() {
            return Err("oversized calibration candidate was published".into());
        }
        if (BOUNDARY - 128..=BOUNDARY).contains(&normalized) && guaranteed_crossing {
            return Ok((Box::new(fixture), workflow, observation));
        }
        let adjustment = normalized.abs_diff(TARGET).div_ceil(10);
        body_bytes = if normalized > TARGET {
            body_bytes.checked_sub(adjustment)
        } else {
            body_bytes.checked_add(adjustment)
        }
        .filter(|bytes| (1..=16384).contains(bytes))
        .ok_or("native edge calibration exceeded actual body limit")?;
    }
    Err("native edge calibration did not reach its bounded target".into())
}

#[tokio::test]
async fn recovery_finalized_candidate_keeps_native_progress_at_admitted_byte_edge() -> TestResult {
    const BOUNDARY: usize = 262144 - 32768;
    let diagnostics = QuotaTestDiagnostics::new();
    let (fixture, workflow, observation) = Box::pin(calibrated_native_edge_fixture()).await?;
    let result: TestResult = Box::pin(async {
        diagnostics.phase("native progress crosses whole-record boundary with frozen shape retained");
        let published = fixture.record(&workflow)?;
        verify_candidate_input_bounds(&fixture, &published)?;
        let normalized = chio_core::canonical_json_bytes(&recovery_quota_fixture_finalized_shape(&published)?)?;
        let published_digest = chio_core::sha256_hex(&normalized);
        eprintln!("RECOVERY_NATIVE_EDGE_EXECUTION_FRAME {}",serde_json::json!({
            "workflow_record_type_bytes":std::mem::size_of::<RecoveryWorkflowRecordV1>(),
            "fixture_type_bytes":std::mem::size_of::<RecoveryFixture>(),
            "request_type_bytes":std::mem::size_of::<ToolCallRequest>(),
            "execute_future_bytes":future_frame_bytes(|| fixture.execute(
                "native-effect-at-admitted-byte-edge",
                RecoveryCommandBodyV1::ResumeWorkflow { workflow_id:workflow.clone(), expected_revision:published.revision },
            )),
            "phase":"before constructing execution future",
        }));
        let execute_future = fixture.execute(
            "native-effect-at-admitted-byte-edge",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: workflow.clone(), expected_revision: published.revision,
            },
        );
        eprintln!("RECOVERY_NATIVE_EDGE_EXECUTION_CONSTRUCTED bytes={}",std::mem::size_of_val(&execute_future));
        let execute_future = Box::pin(execute_future);
        eprintln!("RECOVERY_NATIVE_EDGE_BEFORE_AWAIT");
        let response = execute_future.await?;
        eprintln!("RECOVERY_NATIVE_EDGE_AWAIT_COMPLETED");
        let progress = observation.lock().map_err(|_| "native observation lock failed")?
            .clone().ok_or("native pre-capture observation absent")?;
        eprintln!("RECOVERY_ADMITTED_EDGE_NATIVE_PROGRESS {}",serde_json::json!({
            "publication_normalized_bytes":normalized.len(),"pre_capture_whole_bytes":progress.0,
            "pre_capture_normalized_bytes":progress.1,"boundary":BOUNDARY,
            "normalized_binding_unchanged":progress.2==published_digest,
            "returned_original_present":response.original_response.is_some(),
        }));
        assert!((BOUNDARY - 128..=BOUNDARY).contains(&normalized.len()));
        assert!(progress.0 > BOUNDARY, "actual native progress did not cross the whole-record boundary");
        assert_eq!(progress.1, normalized.len());
        assert_eq!(progress.2, published_digest);
        let completed = fixture.record(&workflow)?;
        assert!(completed.captured);
        assert!(completed.effect.is_settled());
        assert!(matches!(&completed.release, ReleaseDispositionV1::Released { .. }));
        assert!(chio_core::canonical_json_bytes(&completed)?.len() <= 262144);
        assert_eq!(verify_finalized_shape_invariance(&completed)?, normalized.len());
        verify_captured_native_bounds(&fixture, &completed)?;
        assert_eq!(external_count(&fixture.path)?, 1);
        Ok(())
    }).await;
    diagnostics.finish(Some(&fixture), result)
}

#[tokio::test]
async fn recovery_legacy_planning_history_preserves_current_operator_rotation() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("admission.db");
    let legacy_scope = construct_recovery_planning_fixture_legacy_format(&database_path)?;
    let fixture = diagnostics.finish(
        None,
        RecoveryFixture::open(directory.path().to_path_buf(), Some(directory), false),
    )?;
    let result: TestResult = Box::pin(async {
        diagnostics.phase("thirty thousand valid protected old-format operator revisions");
        let current = fixture.kernel.recovery_deployment(fixture.runtime.scope())?;
        let alternate = retain_recovery_planning_fixture_legacy_revisions(
            &fixture.authority.admission_operation_store(), &fixture.authority.mutation_fence(), fixture.runtime.scope(), 30000,
        )?;
        assert_eq!(chio_core::canonical_json_bytes(&fixture.kernel.recovery_deployment(fixture.runtime.scope())?)?, chio_core::canonical_json_bytes(&current)?);
        let connection = connection(&fixture)?;
        let (events, roots): (i64,i64) = connection.query_row(
            "SELECT (SELECT count(*) FROM admission_operation_recovery_events WHERE record_key GLOB 'deployment:*'),
                (SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'deployment-history:*')",
            [], |row| Ok((row.get(0)?,row.get(1)?)),
        )?;
        assert!(events >= 30000 && events < 57344);
        assert!(roots <= 3);
        let new_metadata: i64 = connection.query_row("SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'recovery-planning-quota:*'", [], |row| row.get(0))?;
        assert_eq!(new_metadata, 0, "legacy format fixture created new allocation metadata");
        drop(connection);
        drop(legacy_scope);
        diagnostics.phase("current trusted operator rotation after accepted legacy planning history");
        require_live_quota_capability("current operator control capability", &fixture.control)?;
        let rotation = fixture.authority.admission_operation_store().configure_recovery_deployment(&alternate);
        diagnostics.observe_failure(Some(&fixture), &rotation);
        if let Err(error) = rotation {
            assert_eq!(error, chio_kernel::admission_operation::AdmissionOperationStoreError::Invariant(
                "recovery tenant planning resource exhausted".to_owned()), "legacy history RED failed outside new tenant planning accounting");
            return Err("accepted legacy operator history exhausted its newly introduced planning allowance".into());
        }
        assert_eq!(chio_core::canonical_json_bytes(&fixture.kernel.recovery_deployment(fixture.runtime.scope())?)?, chio_core::canonical_json_bytes(&alternate)?);
        assert_eq!(external_count(&fixture.path)?, 0);
        Ok(())
    }).await;
    diagnostics.finish(Some(&fixture), result)
}

fn digest_from_hex(value: &str) -> TestResult<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("native digest has wrong shape".into());
    }
    let mut bytes = [0_u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)?;
    }
    Ok(bytes)
}

// The public native owner accepts exact current action/review artifacts. This
// fixture uses that core contract; the CP display envelope remains capped32KiB.
async fn native_dense_ready(fixture: &RecoveryFixture) -> TestResult<WorkflowId> {
    let before = fixture
        .kernel
        .observe_recovery_source(fixture.runtime.scope())?;
    let before = before
        .snapshot()
        .ok_or("initial native source is absent")?
        .clone();
    let original = Box::pin(fixture.denied_seed_named("ticket-1")).await?;
    let after = fixture
        .kernel
        .observe_recovery_source(fixture.runtime.scope())?;
    let after = after.snapshot().ok_or("retained native source is absent")?;
    let before_labels = (
        &before.principal_label,
        &before.lineage_label,
        &before.session_label,
    );
    let after_labels = (
        &after.principal_label,
        &after.lineage_label,
        &after.session_label,
    );
    assert!(
        before_labels == after_labels,
        "real original denial compacted the shared legal readers"
    );
    eprintln!(
        "RECOVERY_NATIVE_SOURCE_PROVENANCE {}",
        serde_json::json!({
            "pre_denial_bytes":chio_core::canonical_json_bytes(&before)?.len(),
            "post_denial_bytes":chio_core::canonical_json_bytes(after)?.len(),
            "pre_denial_generation":before.context_generation,
            "post_denial_generation":after.context_generation,
            "label_bytes":chio_core::canonical_json_bytes(&after.principal_label)?.len(),
            "source_digest":chio_core::sha256_hex(&chio_core::canonical_json_bytes(after)?),
            "route":"trusted core native owner, separate from bounded CP display",
        })
    );
    assert!(chio_core::canonical_json_bytes(after)?.len() < 262144);
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Create,
    )?;
    let created = fixture.kernel.execute_recovery_command_with_origin(
        &actor,
        &fixture.command(
            "create",
            RecoveryCommandBodyV1::CreateWorkflow {
                creation_key: CreationKey::new("ticket-1")?,
                template: RecoveryTemplateV1::SupportTicketPublicIssue,
                request_seed: text(&original)?,
            },
        )?,
        &fixture.process,
    )?;
    let id = created.workflow_id;
    let record = fixture.record(&id)?;
    let profile = fixture
        .kernel
        .recovery_deployment(fixture.runtime.scope())?;
    let mut request = record.seed.clone();
    request.request_id = fixture.process.request_id(
        fixture.runtime.scope().process_id.as_str(),
        &crate::recovery::materialize::operation_key(&record.continuation_id),
    )?;
    let identity = fixture
        .kernel
        .recovery_native_identity(&request, &profile.security_context)?;
    let observation = fixture
        .kernel
        .observe_recovery_source(fixture.runtime.scope())?;
    let state = observation
        .snapshot()
        .ok_or("observed current source is absent")?;
    let source = fixture.runtime.flow.recovery_input_source(
        &request,
        &profile.security_context,
        &observation,
    )?;
    let semantics = request.recovery_review_projection().canonical_semantics()?;
    let ceiling = (now_ms()? + MAX_RECOVERY_REVIEW_MS).min(request.capability.expires_at * 1000);
    let requirements = AuthorizationRequirementsV1 {
        schema: AuthorizationRequirementsSchema::V1,
        version: VersionV1,
        scope: fixture.runtime.scope().clone(),
        source_label: source.clone(),
        admitted_target: profile.target_label.clone(),
        source_join: SourceDigest::from_bytes(recovery_digest(
            chio_core_types::recovery::RecoveryDigestDomain::Source,
            &source,
        )?),
        influence_basis: SourceDigest::from_bytes(recovery_digest(
            chio_core_types::recovery::RecoveryDigestDomain::Influence,
            state,
        )?),
        recipient: profile.recipient.clone(),
        purpose: profile.purpose.clone(),
        obligations: chio_flow::required_recovery_disclosure_obligations(
            &source,
            &profile.target_label,
        )?,
        issuer_scope: profile.authority_scope,
        validity_ceiling_unix_ms: SafeInteger::new(ceiling)?,
        attachment_profile: profile.attachment_profile,
    };
    let action = ActionIntentV1 {
        schema: ActionIntentSchema::V1,
        version: VersionV1,
        origin: record.origin.clone(),
        scope: record.scope.clone(),
        workflow_id: id.clone(),
        step_id: record.step_id.clone(),
        continuation_id: record.continuation_id.clone(),
        request_id: RequestId::new(&request.request_id)?,
        request_namespace: RequestNamespaceDigest::from_bytes(digest_from_hex(
            identity.binding().request_namespace_digest().as_str(),
        )?),
        capability_id: RecordId::new(&request.capability.id)?,
        capability_body: CapabilityBodyDigest::from_bytes(recovery_digest(
            chio_core_types::recovery::RecoveryDigestDomain::CapabilityBody,
            &request.capability.signing_body(),
        )?),
        semantic_request: SemanticRequestDigest::from_bytes(
            *chio_core::sha256(semantics.as_bytes()).as_bytes(),
        ),
        authorization_requirements: requirements,
        policy_digest: profile.policy_digest,
        contract_digest: profile.contract_digest,
        authority_scope: profile.authority_scope,
        basis: BasisDigest::from_bytes(recovery_digest(
            chio_core_types::recovery::RecoveryDigestDomain::Basis,
            &(
                state,
                profile.policy_digest,
                profile.contract_digest,
                profile.authority_scope,
            ),
        )?),
        source_generation: SafeInteger::new(state.context_generation)?,
        output_disposition: OutputDispositionDigest::from_bytes(recovery_digest(
            chio_core_types::recovery::RecoveryDigestDomain::OutputDisposition,
            &(
                "original-process",
                fixture.runtime.scope(),
                &profile.target_label,
            ),
        )?),
        isolation_lineage: IsolationLineageId::new(
            profile.security_context.as_v1().lineage_root_id().as_str(),
        )?,
        isolation_epoch: SafeInteger::new(profile.security_context.as_v1().context_generation())?,
    };
    let preview = request
        .recovery_review_projection()
        .canonical_action_preview(&action)?;
    eprintln!(
        "RECOVERY_NATIVE_ACTION_PROVENANCE {}",
        serde_json::json!({
            "action_bytes":chio_core::canonical_json_bytes(&action)?.len(),
            "source_label_bytes":chio_core::canonical_json_bytes(&source)?.len(),
            "full_review_bytes":preview.as_bytes().len(),
            "review_digest":recovery_review_digest(&action,&request)?,
            "native_identity_digest":chio_core::sha256_hex(&chio_core::canonical_json_bytes(&identity.binding().to_persisted())?),
        })
    );
    fixture
        .kernel
        .materialize_recovery_action(&actor, &id, &action)?;
    // Existing exact materialization attaches a real process reservation without
    // asking the small CP display renderer to encode this core-owner review.
    fixture.runtime.materialize(&actor, &id)?;
    let record = fixture.record(&id)?;
    let intent = recovery_digest(
        chio_core_types::recovery::RecoveryDigestDomain::ActionIntent,
        record.action.as_ref().ok_or("materialized action absent")?,
    )?;
    let offer = format!(
        "offer:{}",
        intent
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    fixture
        .execute(
            "select",
            RecoveryCommandBodyV1::SelectOffer {
                workflow_id: id.clone(),
                expected_revision: record.revision,
                offer_id: OfferId::new(&offer)?,
            },
        )
        .await?;
    let review = fixture.runtime.approval_intent(&fixture.control, &id)?;
    let record = fixture.record(&id)?;
    let action = record.action.as_ref().ok_or("reviewed action absent")?;
    assert_eq!(
        review.preview,
        recovery_review_digest(action, &record.seed)?
    );
    let evidence = AuthorityCoverageAttestationV1 {
        schema: AuthorityCoverageSchema::V1,
        version: VersionV1,
        scope: record.scope.clone(),
        approval_intent: review.approval_intent.clone(),
        challenge: review.challenge.clone(),
        action_intent: review.action_intent,
        authorization_requirements: review.authorization_requirements,
        source_basis: action.basis,
        issuer_id: IssuerId::new("reviewer")?,
        principal: PrincipalId::new("reviewer")?,
        obligations: review.obligations.clone(),
        issued_at_unix_ms: review.issued_at_unix_ms,
        expires_at_unix_ms: review.expires_at_unix_ms,
    };
    let submission = RecoveryApprovalSubmissionV1 {
        intent: review,
        coverage: NonEmptyBoundedList::new(vec![SignedAuthorityCoverageAttestationV1::sign(
            evidence,
            &fixture.approval_key,
        )?])?,
    };
    fixture
        .execute(
            "approve",
            RecoveryCommandBodyV1::SubmitApproval {
                workflow_id: id.clone(),
                expected_revision: record.revision,
                approval: text(&submission)?,
            },
        )
        .await?;
    assert_eq!(external_count(&fixture.path)?, 0);
    Ok(id)
}
