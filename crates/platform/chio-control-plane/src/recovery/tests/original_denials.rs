//! Recovery must remedy one verified, effect-free original operation.
use super::*;

async fn create_from(
    fixture: &RecoveryFixture,
    key: &str,
    seed: &ToolCallRequest,
) -> TestResult<Result<RecoveryCommandResultV1, crate::recovery::RecoveryRuntimeError>> {
    Ok(fixture
        .runtime
        .execute_command(
            &fixture.control,
            &fixture.command(
                key,
                RecoveryCommandBodyV1::CreateWorkflow {
                    creation_key: CreationKey::new(key)?,
                    template: RecoveryTemplateV1::SupportTicketPublicIssue,
                    request_seed: text(seed)?,
                },
            )?,
        )
        .await)
}

fn native_state(
    fixture: &RecoveryFixture,
    record: &RecoveryWorkflowRecordV1,
) -> TestResult<AdmissionOperationState> {
    let id = record.native_link.as_ref().ok_or("native link absent")?;
    Ok(fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(
            &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(id.as_str())?,
        )?
        .ok_or("original native operation absent")?
        .state())
}

#[tokio::test]
async fn recovery_origin_requires_a_retained_native_denial() -> TestResult {
    let fixture = RecoveryFixture::new(false)?;
    let result = create_from(&fixture, "unattempted-request", &fixture.seed).await?;
    assert!(
        result.is_err(),
        "an unattempted request has no denial to remedy"
    );
    assert_eq!(external_count(&fixture.path)?, 0);
    assert_eq!(fixture.process.process("root")?.tree_calls, 0);
    Ok(())
}

#[tokio::test]
async fn recovery_competing_creation_keys_have_one_original_owner() -> TestResult {
    let fixture = RecoveryFixture::new(false)?;
    let seed = Box::pin(fixture.denied_seed_named("competing-original")).await?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Create,
    )?;
    let commands = ["competing-first", "competing-second"].map(|key| {
        fixture.command(
            key,
            RecoveryCommandBodyV1::CreateWorkflow {
                creation_key: CreationKey::new(key)?,
                template: RecoveryTemplateV1::SupportTicketPublicIssue,
                request_seed: text(&seed)?,
            },
        )
    });
    let commands = commands.into_iter().collect::<TestResult<Vec<_>>>()?;
    let barrier = std::sync::Barrier::new(2);
    let results = std::thread::scope(|threads| {
        let attempts = commands
            .iter()
            .map(|command| {
                let barrier = &barrier;
                let kernel = &fixture.kernel;
                let process = &fixture.process;
                let actor = &actor;
                threads.spawn(move || {
                    barrier.wait();
                    kernel.execute_recovery_command_with_origin(actor, command, process)
                })
            })
            .collect::<Vec<_>>();
        attempts
            .into_iter()
            .map(|attempt| {
                attempt
                    .join()
                    .map_err(|_| "creation contender panicked".into())
            })
            .collect::<TestResult<Vec<_>>>()
    })?;
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(RecoveryCommandError::Conflict)))
            .count(),
        1
    );
    let database = rusqlite::Connection::open(fixture.path.join("admission.db"))?;
    let owners: i64 = database.query_row(
        "SELECT count(*) FROM admission_operation_recovery_records WHERE record_key GLOB 'recovery-origin:*'",
        [], |row| row.get(0),
    )?;
    assert_eq!(owners, 1);
    assert_eq!(external_count(&fixture.path)?, 0);
    assert_eq!(fixture.process.process("root")?.tree_calls, 1);
    Ok(())
}

#[tokio::test]
async fn recovery_fresh_action_refuses_absent_or_substituted_original_claims() -> TestResult {
    let fixture = RecoveryFixture::new(false)?;
    let workflow = Box::pin(fixture.ready()).await?;
    let record = fixture.record(&workflow)?;
    let before = chio_core::canonical_json_bytes(&record)?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Create,
    )?;
    let action = record.action.as_ref().ok_or("action absent")?;
    for mutation in 0..3 {
        let mut substituted = action.clone();
        match mutation {
            0 => substituted.origin = None,
            1 => {
                substituted
                    .origin
                    .as_mut()
                    .ok_or("origin absent")?
                    .request_id = RequestId::new("foreign-original")?
            }
            _ => {
                substituted.origin.as_mut().ok_or("origin absent")?.closure =
                    EvidenceRef::new("foreign-closure")?
            }
        }
        assert!(fixture
            .kernel
            .materialize_recovery_action(&actor, &workflow, &substituted)
            .is_err());
        assert_eq!(
            chio_core::canonical_json_bytes(&fixture.record(&workflow)?)?,
            before
        );
    }
    fixture
        .kernel
        .materialize_recovery_action(&actor, &workflow, action)?;
    assert_eq!(
        chio_core::canonical_json_bytes(&fixture.record(&workflow)?)?,
        before
    );
    assert_eq!(external_count(&fixture.path)?, 0);
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    Ok(())
}

#[tokio::test]
async fn recovery_origin_requires_the_owning_process_even_for_native_create() -> TestResult {
    let fixture = RecoveryFixture::new(false)?;
    let seed = fixture.denied_seed_named("native-create").await?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Create,
    )?;
    let command = fixture.command(
        "native-create",
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new("native-create")?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(&seed)?,
        },
    )?;
    assert_eq!(
        fixture
            .kernel
            .execute_recovery_command(&actor, &command)
            .err(),
        Some(RecoveryCommandError::Unavailable),
    );
    // Refusing the unproven port must leave the same identity and original
    // available to the authenticated owning process.
    let response =
        fixture
            .kernel
            .execute_recovery_command_with_origin(&actor, &command, &fixture.process)?;
    let record = fixture.record(&response.workflow_id)?;
    assert!(record.origin.is_some());
    assert!(record.action.is_none());
    assert_eq!(external_count(&fixture.path)?, 0);
    assert_eq!(fixture.process.process("root")?.tree_calls, 1);
    Ok(())
}

#[tokio::test]
async fn recovery_origin_is_in_the_exact_review_and_signed_authorization() -> TestResult {
    let fixture = RecoveryFixture::new(false)?;
    let workflow = fixture.ready().await?;
    let record = fixture.record(&workflow)?;
    let origin = record.origin.as_ref().ok_or("original denial absent")?;
    assert_eq!(origin.request_id.as_str(), fixture.seed.request_id);
    let parent = fixture
        .authority
        .admission_operation_store()
        .load_by_operation_id(
            &chio_kernel::admission_operation::AdmissionOperationId::from_persisted(
                origin.operation.operation_id().as_str(),
            )?,
        )?
        .ok_or("original native parent absent")?;
    assert_eq!(
        parent.state(),
        AdmissionOperationState::CompensatedBeforeDispatch
    );
    assert!(parent.dispatch_commit().is_none());
    assert_eq!(origin.operation.operation_version().get(), parent.version());
    assert_eq!(
        origin.closure.as_str(),
        format!("closure:{}", parent.binding().operation_id().as_str())
    );
    let action = record.action.as_ref().ok_or("action absent")?;
    assert_eq!(action.origin.as_ref(), Some(origin));
    let document = fixture
        .runtime
        .review_document(&fixture.control, &workflow)?;
    let reviewed: serde_json::Value = serde_json::from_str(document.canonical_preview.as_str())?;
    assert_eq!(reviewed[0]["origin"], serde_json::to_value(origin)?);
    let action_digest = IntentDigest::from_bytes(recovery_digest(
        chio_core_types::recovery::RecoveryDigestDomain::ActionIntent,
        action,
    )?);
    let mut substituted = action.clone();
    substituted
        .origin
        .as_mut()
        .ok_or("origin absent")?
        .request_id = RequestId::new("foreign-denial")?;
    assert_ne!(
        recovery_digest(
            chio_core_types::recovery::RecoveryDigestDomain::ActionIntent,
            &substituted
        )?,
        *action_digest.as_bytes()
    );
    let resume = fixture.command(
        "authorize-linked-continuation",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: workflow.clone(),
            expected_revision: record.revision,
        },
    )?;
    let completed = fixture
        .runtime
        .execute_command(&fixture.control, &resume)
        .await?;
    assert!(matches!(
        completed.status.effect,
        EffectObservationV1::Complete { .. }
    ));
    let captured = fixture.record(&workflow)?;
    let grant = captured.signed_grant.ok_or("signed grant absent")?;
    assert!(grant.verify_signature()?);
    assert_eq!(grant.body().recovery.action_intent, action_digest);
    assert_eq!(captured.origin.as_ref(), Some(origin));
    assert_eq!(external_count(&fixture.path)?, 1);
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    Ok(())
}

#[tokio::test]
async fn recovery_origin_refuses_changed_original_request_bytes() -> TestResult {
    let fixture = RecoveryFixture::new(false)?;
    let original = fixture.denied_seed_named("changed-parent").await?;
    let mut foreign = original.clone();
    foreign.arguments["body"] = "different original payload".into();
    assert!(create_from(&fixture, "changed-parent", &foreign)
        .await?
        .is_err());
    let accepted = create_from(&fixture, "changed-parent", &original).await??;
    assert!(fixture
        .record(&accepted.status.workflow_id)?
        .origin
        .is_some());
    assert_eq!(external_count(&fixture.path)?, 0);
    Ok(())
}

#[tokio::test]
async fn recovery_originless_history_refuses_new_owners_and_retains_control() -> TestResult {
    let fixture = RecoveryFixture::new(false)?;
    let actor = fixture.kernel.authenticate_recovery_actor(
        fixture.runtime.scope(),
        &fixture.control,
        RecoveryPermission::Create,
    )?;
    let template_seed = Box::pin(fixture.denied_seed_named("history-template")).await?;
    let created = fixture.kernel.execute_recovery_command_with_origin(
        &actor,
        &fixture.command(
            "history-template",
            RecoveryCommandBodyV1::CreateWorkflow {
                creation_key: CreationKey::new("history-template")?,
                template: RecoveryTemplateV1::SupportTicketPublicIssue,
                request_seed: text(&template_seed)?,
            },
        )?,
        &fixture.process,
    )?;
    let seed = Box::pin(fixture.denied_seed_named("legacy-original")).await?;
    let legacy =
        chio_store_sqlite::admission_operation_store::retain_unadmitted_legacy_recovery_fixture(
            &fixture.authority.admission_operation_store(),
            &actor,
            &created.workflow_id,
            &seed,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?;
    assert!(legacy.origin.is_none());
    let canonical = chio_core::canonical_json_bytes(&legacy)?;
    assert!(!serde_json::to_value(&legacy)?
        .as_object()
        .ok_or("legacy shape")?
        .contains_key("origin"));
    let replacement = create_from(&fixture, "legacy-replacement", &seed).await?;
    assert!(
        replacement.is_err(),
        "unlinked legacy history cannot prove this parent is unused"
    );
    assert_eq!(
        chio_core::canonical_json_bytes(&fixture.record(&legacy.workflow_id)?)?,
        canonical
    );
    fixture
        .execute(
            "inspect-legacy",
            RecoveryCommandBodyV1::InspectWorkflow {
                workflow_id: legacy.workflow_id.clone(),
            },
        )
        .await?;
    fixture
        .execute(
            "cancel-legacy",
            RecoveryCommandBodyV1::CancelWorkflow {
                workflow_id: legacy.workflow_id.clone(),
                expected_revision: legacy.revision,
            },
        )
        .await?;
    fixture
        .runtime
        .settle(&fixture.control, &legacy.workflow_id)?;
    assert!(fixture.record(&legacy.workflow_id)?.origin.is_none());
    assert_eq!(external_count(&fixture.path)?, 0);
    assert_eq!(fixture.process.process("root")?.tree_calls, 2);
    Ok(())
}

#[tokio::test]
#[ignore = "run with a retained pre-upgrade native effect fixture"]
async fn recovery_legacy_native_effect_retains_settlement_and_refuses_new_owners() -> TestResult {
    let path = std::path::PathBuf::from(
        std::env::var_os("CHIO_RECOVERY_LEGACY_ROOT").ok_or("legacy fixture root")?,
    );
    let fixture = RecoveryFixture::open(path, None, false)?;
    let workflow: WorkflowId =
        serde_json::from_slice(&std::fs::read(fixture.path.join("workflow.json"))?)?;
    let record = fixture.record(&workflow)?;
    assert!(record.origin.is_none());
    assert!(record
        .action
        .as_ref()
        .is_some_and(|action| action.origin.is_none()));
    assert!(record.captured);
    assert_eq!(
        native_state(&fixture, &record)?,
        AdmissionOperationState::Completed
    );
    assert_eq!(external_count(&fixture.path)?, 1);
    let action = chio_core::canonical_json_bytes(&record.action)?;
    let grant = chio_core::canonical_json_bytes(&record.signed_grant)?;
    let envelope = chio_core::canonical_json_bytes(&record.envelope)?;
    let replacement = create_from(&fixture, "legacy-effect-replacement", &fixture.seed).await?;
    assert!(
        replacement.is_err(),
        "the old workflow already consumed this original denial"
    );
    fixture.runtime.settle(&fixture.control, &workflow)?;
    let settled = fixture.record(&workflow)?;
    assert!(matches!(
        settled.effect,
        EffectObservationV1::Complete { .. }
    ));
    assert_eq!(chio_core::canonical_json_bytes(&settled.action)?, action);
    assert_eq!(
        chio_core::canonical_json_bytes(&settled.signed_grant)?,
        grant
    );
    assert_eq!(
        chio_core::canonical_json_bytes(&settled.envelope)?,
        envelope
    );
    fixture
        .runtime
        .review_document(&fixture.control, &workflow)?;
    assert_eq!(external_count(&fixture.path)?, 1);
    Ok(())
}

#[tokio::test]
async fn recovery_origin_unknown_effect_cannot_create_a_second_continuation() -> TestResult {
    let fixture = RecoveryFixture::new(false)?;
    let id = fixture.ready().await?;
    fixture.behavior.store(1, Ordering::SeqCst);
    let response = fixture
        .execute(
            "original-response-lost",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: id.clone(),
                expected_revision: fixture.record(&id)?.revision,
            },
        )
        .await?;
    assert!(matches!(
        response.status.effect,
        EffectObservationV1::Unknown { .. }
    ));
    let original = fixture.record(&id)?;
    assert_eq!(
        native_state(&fixture, &original)?,
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    assert_eq!(external_count(&fixture.path)?, 1);
    let retry = create_from(&fixture, "unknown-remedy", &original.seed).await?;
    assert!(
        retry.is_err(),
        "a lost response must reconcile the original operation"
    );
    assert_eq!(external_count(&fixture.path)?, 1);
    Ok(())
}

#[tokio::test]
async fn recovery_origin_delivered_denial_cannot_create_a_second_continuation() -> TestResult {
    let directory = tempfile::tempdir()?;
    std::fs::write(
        directory.path().join("mismatched-output-digest"),
        b"enabled",
    )?;
    let fixture = RecoveryFixture::open(directory.path().to_path_buf(), Some(directory), false)?;
    let id = fixture.ready().await?;
    let response = fixture
        .execute(
            "original-delivery-denied",
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id: id.clone(),
                expected_revision: fixture.record(&id)?.revision,
            },
        )
        .await?;
    assert!(matches!(
        response.status.effect,
        EffectObservationV1::Unknown { .. }
    ));
    let original = fixture.record(&id)?;
    assert_eq!(
        native_state(&fixture, &original)?,
        AdmissionOperationState::DeniedAfterDelivery
    );
    assert_eq!(external_count(&fixture.path)?, 1);
    let retry = create_from(&fixture, "delivered-denial-remedy", &original.seed).await?;
    assert!(
        retry.is_err(),
        "a denial after delivery is not evidence of no effect"
    );
    assert_eq!(external_count(&fixture.path)?, 1);
    Ok(())
}

#[tokio::test]
async fn recovery_origin_has_one_durable_workflow_owner() -> TestResult {
    let directory = tempfile::tempdir()?;
    let fixture = RecoveryFixture::open(directory.path().to_path_buf(), None, false)?;
    let denial = fixture
        .process
        .invoke_known_only("root", "seed", &fixture.seed)
        .await?;
    assert_eq!(denial.verdict, Verdict::Deny);
    assert_eq!(external_count(&fixture.path)?, 0);
    fixture.ready().await?;
    let path = fixture.path.clone();
    drop(fixture);
    let fixture = RecoveryFixture::open(path, None, false)?;
    let duplicate = create_from(&fixture, "second-owner", &fixture.seed).await?;
    assert!(
        duplicate.is_err(),
        "a closed original cannot authorize two workflows"
    );
    assert_eq!(external_count(&fixture.path)?, 0);
    Ok(())
}

#[derive(Clone, Copy)]
enum OriginalInvokeMode {
    Invoke,
    KnownOnly,
}

fn original_owner_counts(fixture: &RecoveryFixture) -> TestResult<(u64, u64, u64)> {
    let database = rusqlite::Connection::open(fixture.path.join("admission.db"))?;
    let counts: (i64, i64, i64) = database.query_row(
        "SELECT
         (SELECT count(*) FROM admission_operation_recovery_records
          WHERE record_key GLOB 'workflow:*'),
         (SELECT count(*) FROM admission_operation_recovery_records
          WHERE record_key GLOB 'recovery-origin:*'),
         (SELECT count(*) FROM admission_operation_recovery_events)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    Ok((
        u64::try_from(counts.0)?,
        u64::try_from(counts.1)?,
        u64::try_from(counts.2)?,
    ))
}

async fn refuse_dispatched_ordinary_original(
    mode: OriginalInvokeMode,
    delivered_denial: bool,
) -> TestResult {
    let directory = tempfile::tempdir()?;
    std::fs::write(directory.path().join("public-original-profile"), b"enabled")?;
    if delivered_denial {
        std::fs::write(
            directory.path().join("mismatched-output-digest"),
            b"enabled",
        )?;
    }
    let fixture = RecoveryFixture::open(directory.path().to_path_buf(), Some(directory), false)?;
    if !delivered_denial {
        fixture.behavior.store(1, Ordering::SeqCst);
    }
    let key = match mode {
        OriginalInvokeMode::Invoke => "ordinary-original",
        OriginalInvokeMode::KnownOnly => "known-ordinary-original",
    };
    let request = fixture.process.tool_request(
        "root",
        key,
        &fixture.seed.server_id,
        &fixture.seed.tool_name,
        fixture.seed.arguments.clone(),
    )?;
    let response = match mode {
        OriginalInvokeMode::Invoke => fixture.process.invoke("root", key, &request).await?,
        OriginalInvokeMode::KnownOnly => {
            fixture
                .process
                .invoke_known_only("root", key, &request)
                .await?
        }
    };
    assert_eq!(response.verdict, Verdict::Deny);
    assert_eq!(external_count(&fixture.path)?, 1);
    let scope = fixture.runtime.scope();
    let profile = fixture.kernel.recovery_deployment(scope)?;
    chio_kernel::recovery::RecoveryProcessOriginPort::verify_original_request(
        &fixture.process,
        scope,
        &request,
        profile.security_context.as_v1().session_id().as_str(),
    )?;
    let (operation, retained) = fixture
        .authority
        .admission_operation_store()
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &request.request_id)?,
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?
        .ok_or("ordinary original custody absent")?;
    retained.validate_request_material(&request)?;
    assert_eq!(
        operation.state(),
        if delivered_denial {
            AdmissionOperationState::DeniedAfterDelivery
        } else {
            AdmissionOperationState::OutcomeUnknownAfterDispatch
        },
    );
    assert!(operation.dispatch_commit().is_some());
    let before = original_owner_counts(&fixture)?;
    let error = create_from(&fixture, "dispatched-original-remedy", &request)
        .await?
        .err()
        .ok_or("a dispatched ordinary original acquired a new recovery owner")?;
    assert_eq!(
        error.to_string(),
        "recovery original is not eligible",
        "a native effect refusal must not be reported as a retryable outage",
    );
    assert_eq!(original_owner_counts(&fixture)?, before);
    assert_eq!(external_count(&fixture.path)?, 1);
    Ok(())
}

#[tokio::test]
async fn ordinary_unknown_original_passes_process_proof_and_is_permanently_refused() -> TestResult {
    refuse_dispatched_ordinary_original(OriginalInvokeMode::Invoke, false).await?;
    refuse_dispatched_ordinary_original(OriginalInvokeMode::KnownOnly, false).await
}

#[tokio::test]
async fn ordinary_delivered_denial_passes_process_proof_and_is_permanently_refused() -> TestResult {
    refuse_dispatched_ordinary_original(OriginalInvokeMode::Invoke, true).await?;
    refuse_dispatched_ordinary_original(OriginalInvokeMode::KnownOnly, true).await
}

#[tokio::test(flavor = "current_thread")]
async fn public_recovery_execution_leaves_the_callers_executor_running() -> TestResult {
    let fixture = RecoveryFixture::new(false)?;
    let seed = fixture.denied_seed_named("executor-original").await?;
    let command = fixture.command(
        "executor-owner",
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new("executor-owner")?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(&seed)?,
        },
    )?;
    let path = fixture.path.join("admission.db");
    let (entered, entered_writer) = std::sync::mpsc::sync_channel(1);
    let (release, wait) = std::sync::mpsc::sync_channel(1);
    let writer = std::thread::spawn({
        move || -> Result<bool, String> {
            let mut database =
                rusqlite::Connection::open(path).map_err(|error| error.to_string())?;
            let transaction = database
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|error| error.to_string())?;
            entered.send(()).map_err(|error| error.to_string())?;
            let released_by_executor = wait.recv_timeout(std::time::Duration::from_secs(2)).is_ok();
            transaction.rollback().map_err(|error| error.to_string())?;
            Ok(released_by_executor)
        }
    });
    entered_writer.recv_timeout(std::time::Duration::from_secs(5))?;
    let heartbeat = tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        release.send(()).is_ok()
    });
    tokio::task::yield_now().await;
    let result = fixture
        .runtime
        .execute_command(&fixture.control, &command)
        .await;
    let responsive = writer.join().map_err(|_| "writer test thread panicked")??;
    assert!(
        responsive,
        "the public async entry point blocked the only executor thread until the writer timed out",
    );
    assert!(heartbeat.await?);
    assert!(result.is_ok(), "{:?}", result.err());
    assert_eq!(external_count(&fixture.path)?, 0);
    Ok(())
}
