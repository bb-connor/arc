//! Serial same-owner generations follow only verified effect-free closed predecessors.
//! One current owner is named by the optional head projection; old commands
//! replay exactly without native execution, and lost or tampered owner
//! projections refuse every public entry point.
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

fn retained_owner_projection_count(fixture: &RecoveryFixture) -> TestResult<i64> {
    let connection = rusqlite::Connection::open_with_flags(
        fixture.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    Ok(connection.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records
         WHERE record_key GLOB 'recovery-owner:*'",
        [],
        |row| row.get(0),
    )?)
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
    let creator = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Create,
    )?;
    super::command_quotas::require_live_creation_authority(&creator, &create)?;
    let created =
        fixture
            .kernel
            .execute_recovery_command_with_origin(&creator, &create, &fixture.process)?;
    let first = Box::new(fixture.command(
        "same-owner-first-resume",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: created.workflow_id.clone(),
            expected_revision: created.revision,
        },
    )?);
    let resumer = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Resume,
    )?;
    let first_response = fixture.kernel.execute_recovery_command(&resumer, &first)?;
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

/// A fresh creation reusing the closed generation's seed becomes the next
/// serial generation of the same original.
async fn transferred_successor(
    fixture: &RecoveryFixture,
    creator: &AuthenticatedRecoveryActor,
    closed: &RecoveryWorkflowRecordV1,
    identity: &str,
) -> TestResult<RecoveryWorkflowRecordV1> {
    let create = fixture.command(
        identity,
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new(identity)?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: closed.creation_seed.clone(),
        },
    )?;
    require_live_quota_capability("successor control capability", &fixture.control)?;
    require_live_quota_capability("successor original capability", &closed.seed.capability)?;
    let accepted =
        fixture
            .kernel
            .execute_recovery_command_with_origin(creator, &create, &fixture.process)?;
    let successor = fixture.record(&accepted.workflow_id)?;
    Ok(successor)
}

fn cancel_generation(
    fixture: &RecoveryFixture,
    record: &RecoveryWorkflowRecordV1,
) -> TestResult<()> {
    let cancel = fixture.command(
        &format!("cancel:{}", record.workflow_id.as_str()),
        RecoveryCommandBodyV1::CancelWorkflow {
            workflow_id: record.workflow_id.clone(),
            expected_revision: record.revision,
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
    let closed = fixture.record(&record.workflow_id)?;
    assert_eq!(closed.control, WorkflowControlV1::Cancelled);
    assert!(closed.admission_closed && closed.admission.is_none());
    assert_eq!(closed.effect, EffectObservationV1::NeverAdmitted);
    Ok(())
}

/// Repeated cancelled generations transfer serially under one current owner.
/// The immutable claim and every retired generation row stay byte-identical,
/// a superseded generation refuses fresh effects, a competing creation
/// conflicts while the current generation is active, and stale old commands
/// replay exactly without native execution.
#[tokio::test]
async fn recovery_cancelled_originals_transfer_serially_with_one_current_owner() -> TestResult {
    let diagnostics = QuotaTestDiagnostics::new();
    let fixture = Box::new(RecoveryFixture::new(false)?);
    let result: TestResult = Box::pin(async {
        let (original, first, first_response) = Box::pin(cancelled_original(&fixture)).await?;
        let creator = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Create,
        )?;
        let resumer = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Resume,
        )?;
        let claim = retained_original_claim(&fixture)?;
        let original_row = retained_workflow(&fixture, &original)?;
        let mut predecessor = Box::new(fixture.record(&original)?);
        let mut stale_replies = Vec::new();
        // Generations two through four: three repeated cancelled transfers.
        for index in 0..3 {
            let identity = format!("same-owner-generation-{}", index + 2);
            diagnostics.phase("fresh transfer from the closed generation");
            let predecessor_row = retained_workflow(&fixture, &predecessor.workflow_id)?;
            let successor = Box::pin(transferred_successor(
                &fixture,
                &creator,
                &predecessor,
                &identity,
            ))
            .await?;
            assert_ne!(successor.workflow_id, predecessor.workflow_id);
            assert_eq!(successor.control, WorkflowControlV1::Active);
            assert_eq!(successor.origin, predecessor.origin);
            assert_eq!(successor.creation_seed, predecessor.creation_seed);
            assert_ne!(successor.step_id, predecessor.step_id);
            assert_ne!(successor.continuation_id, predecessor.continuation_id);
            assert!(!successor.captured && !successor.admission_closed);
            // The immutable claim and every retired generation row stay
            // byte-identical through each transfer.
            assert_eq!(retained_original_claim(&fixture)?, claim);
            assert_eq!(retained_workflow(&fixture, &original)?, original_row);
            assert_eq!(
                retained_workflow(&fixture, &predecessor.workflow_id)?,
                predecessor_row
            );
            let resume = fixture.command(
                &format!("{identity}-resume"),
                RecoveryCommandBodyV1::ResumeWorkflow {
                    workflow_id: successor.workflow_id.clone(),
                    expected_revision: successor.revision,
                },
            )?;
            diagnostics.phase("resume the new current generation");
            let response = fixture.kernel.execute_recovery_command(&resumer, &resume)?;
            stale_replies.push((resume, chio_core::canonical_json_bytes(&response)?));
            let resumed = fixture.record(&successor.workflow_id)?;
            assert_eq!(resumed.revision, response.revision);
            if index < 2 {
                diagnostics.phase("cancel the current generation for another transfer");
                cancel_generation(&fixture, &resumed)?;
            }
            *predecessor = fixture.record(&successor.workflow_id)?;
            // No generation produced an external effect.
            assert_eq!(external_count(&fixture.path)?, 0);
        }
        // One current-owner head exists across every repeated transfer.
        assert_eq!(retained_owner_projection_count(&fixture)?, 1);
        // The last generation stays active: a competing creation conflicts.
        let competitor = fixture.command(
            "same-owner-competing-creation",
            RecoveryCommandBodyV1::CreateWorkflow {
                creation_key: CreationKey::new("same-owner-competing-creation")?,
                template: RecoveryTemplateV1::SupportTicketPublicIssue,
                request_seed: predecessor.creation_seed.clone(),
            },
        )?;
        require_live_quota_capability("competing control capability", &fixture.control)?;
        require_live_quota_capability(
            "competing original capability",
            &predecessor.seed.capability,
        )?;
        let before = protected_usage(&fixture)?;
        assert!(matches!(
            fixture.kernel.execute_recovery_command_with_origin(
                &creator,
                &competitor,
                &fixture.process
            ),
            Err(RecoveryCommandError::Conflict)
        ));
        assert_eq!(protected_usage(&fixture)?, before);
        // A superseded generation refuses fresh effects.
        let stale = fixture.command(
            "same-owner-superseded-resume",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: original.clone(),
                expected_revision: fixture.record(&original)?.revision,
            },
        )?;
        assert!(matches!(
            fixture.kernel.execute_recovery_command(&resumer, &stale),
            Err(RecoveryCommandError::Conflict)
        ));
        assert_eq!(protected_usage(&fixture)?, before);
        // Stale old commands replay exactly without native execution.
        let replay = fixture.kernel.execute_recovery_command(&resumer, &first)?;
        assert_eq!(chio_core::canonical_json_bytes(&replay)?, first_response);
        let _driver = Box::pin(fixture.runtime.execute_command(&fixture.control, &first)).await;
        for (command, reply) in &stale_replies {
            let replayed = fixture.kernel.execute_recovery_command(&resumer, command)?;
            assert_eq!(chio_core::canonical_json_bytes(&replayed)?, *reply);
        }
        let _ = Box::pin(
            fixture
                .runtime
                .execute_command(&fixture.control, &stale_replies[0].0.clone()),
        )
        .await;
        assert_eq!(protected_usage(&fixture)?, before);
        assert_eq!(external_count(&fixture.path)?, 0);
        assert_eq!(retained_owner_projection_count(&fixture)?, 1);
        assert_eq!(retained_original_claim(&fixture)?, claim);
        assert_eq!(retained_workflow(&fixture, &original)?, original_row);
        Ok(())
    })
    .await;
    diagnostics.finish(Some(&fixture), result)
}

/// Lost and tampered owner projections never reinitialize and refuse every
/// public entry point and startup verification.
#[tokio::test]
async fn recovery_owner_projection_loss_or_tamper_refuses_public_entry_points() -> TestResult {
    for stage in 0..3 {
        let mut fixture = Box::new(RecoveryFixture::new(false)?);
        let (original, _, _) = Box::pin(cancelled_original(&fixture)).await?;
        let creator = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Create,
        )?;
        let closed = Box::new(fixture.record(&original)?);
        let successor = Box::pin(transferred_successor(
            &fixture,
            &creator,
            &closed,
            "projection-loss-successor",
        ))
        .await?;
        assert_eq!(successor.control, WorkflowControlV1::Active);
        let inspector = fixture.kernel.authenticate_recovery_actor(
            fixture.runtime.scope(),
            &fixture.control,
            RecoveryPermission::Inspect,
        )?;
        {
            let connection = rusqlite::Connection::open(fixture.path.join("admission.db"))?;
            match stage {
                0 => {
                    let delete = "DELETE FROM admission_operation_recovery_records
                                  WHERE record_key GLOB 'recovery-owner:*'";
                    assert!(connection.execute(delete, []).is_err());
                    let trigger: String = connection.query_row(
                        "SELECT sql FROM sqlite_schema WHERE type='trigger'
                         AND name='admission_operation_recovery_no_delete'",
                        [],
                        |row| row.get(0),
                    )?;
                    // Damage only this fixture's projection, retaining its
                    // history and restoring the original trigger before reads.
                    connection.pragma_update(None, "foreign_keys", false)?;
                    connection
                        .execute_batch("DROP TRIGGER admission_operation_recovery_no_delete")?;
                    let deleted = connection.execute(delete, [])?;
                    connection.execute_batch(&trigger)?;
                    assert_eq!(deleted, 1, "one owner head row is retained");
                }
                1 => {
                    let changed = connection.execute(
                        "UPDATE admission_operation_recovery_records SET payload=CAST('{}' AS BLOB),version=version+1
                         WHERE record_key GLOB 'recovery-successor:*'",
                        [],
                    )?;
                    assert_eq!(changed, 1, "one successor binding row is retained");
                }
                _ => {
                    let changed = connection.execute(
                        "UPDATE admission_operation_recovery_records SET payload=CAST('{}' AS BLOB),version=version+1
                         WHERE record_key GLOB 'recovery-owner:*'",
                        [],
                    )?;
                    assert_eq!(changed, 1, "one owner head row is retained");
                }
            }
        }
        // A lost or forged projection never reinitializes or transfers again.
        let competitor = fixture.command(
            "projection-loss-competitor",
            RecoveryCommandBodyV1::CreateWorkflow {
                creation_key: CreationKey::new("projection-loss-competitor")?,
                template: RecoveryTemplateV1::SupportTicketPublicIssue,
                request_seed: successor.creation_seed.clone(),
            },
        )?;
        require_live_quota_capability("loss control capability", &fixture.control)?;
        require_live_quota_capability("loss original capability", &successor.seed.capability)?;
        assert!(matches!(
            fixture.kernel.execute_recovery_command_with_origin(
                &creator,
                &competitor,
                &fixture.process,
            ),
            Err(RecoveryCommandError::Unavailable)
        ));
        // The bound successor generation no longer serves public reads.
        assert!(fixture
            .kernel
            .read_recovery_workflow(&inspector, &successor.workflow_id)
            .is_err());
        assert_eq!(external_count(&fixture.path)?, 0);
        // Reopen the actual authority. Repeating startup on the existing
        // Kernel would only observe its already-completed reconciliation.
        let path = fixture.path.clone();
        let directory = fixture._directory.take();
        drop(fixture);
        assert!(RecoveryFixture::open(path, directory, false).is_err());
    }
    Ok(())
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
