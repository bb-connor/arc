//! Setup preconditions must refuse before a benign operation can be dispatched.
use super::*;

async fn selected_self_test() -> TestResult<Box<OperatorBootstrap>> {
    let fixture = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let workflow = fixture.f.ready().await?;
    let service = setup(&fixture, &workflow)?;
    Ok(Box::new(OperatorBootstrap { fixture, service }))
}

#[tokio::test]
async fn setup_expired_bound_probe_refuses_before_dispatch() -> TestResult {
    let state = Box::pin(selected_self_test()).await?;
    let f = &state.fixture;
    let actor = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &f.f.control,
        RecoveryPermission::Inspect,
    )?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let prepared = store.setup_preparation(&actor, &fence, now_ms()?)?;
    let calls = f.f.process.process("root")?.tree_calls;
    let expired_secs = prepared.probe.expires_at_unix_ms.get() / 1_000 + 1;
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(
        expired_secs,
        std::iter::empty::<String>(),
    );
    assert!(
        matches!(
            store.setup_preparation(&actor, &fence, expired_secs * 1_000),
            Err(chio_store_sqlite::admission_operation_store::NativeSetupPreparationError::Expired)
        ),
        "an already bound command must not escape expired setup preparation"
    );
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert!(!f.f.record(state.service.workflow())?.captured);
    Ok(())
}

#[tokio::test]
async fn setup_writer_change_refuses_before_first_dispatch() -> TestResult {
    let mut state = Box::pin(selected_self_test()).await?;
    let workflow = state.service.workflow().clone();
    let path = state.fixture.f.path.clone();
    let directory = state.fixture.f._directory.take();
    let calls = state.fixture.f.process.process("root")?.tree_calls;
    drop(state);
    let f = KnowledgeFixture::from(RecoveryFixture::open(path, directory, false)?)?;
    let service = setup(&f, &workflow)?;
    assert_eq!(
        service.probe(&f.f.control, &workflow).await.err(),
        Some(crate::recovery::RecoveryRuntimeError::RestartRequired),
        "the writer mismatch must be reported before the self-test effect"
    );
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert!(!f.f.record(&workflow)?.captured);
    Ok(())
}

#[tokio::test]
async fn setup_stale_source_refuses_before_first_dispatch() -> TestResult {
    let state = Box::pin(selected_self_test()).await?;
    let f = &state.fixture;
    f.f.denied_seed_named("changed-setup-source").await?;
    let calls = f.f.process.process("root")?.tree_calls;
    assert_eq!(
        state
            .service
            .probe(&f.f.control, state.service.workflow())
            .await
            .err(),
        Some(crate::recovery::RecoveryRuntimeError::Conflict),
        "stale setup source must be a permanent basis conflict, not retryable unavailability"
    );
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert!(!f.f.record(state.service.workflow())?.captured);
    Ok(())
}

async fn attest_after_initial_probe_expiry(previously_qualified: bool) -> TestResult {
    let evidence = Box::pin(begin_restart_proof()).await?;
    let mut evidence = if previously_qualified {
        Box::pin(qualify_reopened_writer(
            evidence,
            "qualification-before-expiry",
        ))
        .await?
        .0
    } else {
        evidence
    };
    let f = KnowledgeFixture::from(RecoveryFixture::open(
        evidence.path.clone(),
        evidence.directory.take(),
        false,
    )?)?;
    let _service = setup(&f, &evidence.workflow)?;
    let actor = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &f.f.control,
        RecoveryPermission::Inspect,
    )?;
    // Obtain a real, freshly authorized replay of the identical retained
    // completion. This never creates another command or provider operation.
    let benign =
        f.f.kernel
            .replay_recovery_result(&actor, &evidence.workflow)?
            .receipt;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let calls = f.f.process.process("root")?.tree_calls;
    let expired_secs = evidence.probe.body().expires_at_unix_ms.get() / 1_000 + 1;
    let expired_ms = expired_secs * 1_000;
    let current_capability = f.f.kernel.issue_capability(
        &f.f.approval_key.public_key(),
        f.f.control.scope.clone(),
        1_200,
    )?;
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(
        expired_secs,
        std::iter::empty::<String>(),
    );
    let actor = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &current_capability,
        RecoveryPermission::Inspect,
    )?;
    let body = store.prepare_setup_report(&actor, &evidence.probe, &benign, &fence, expired_ms);
    if previously_qualified {
        let body = body?;
        assert_eq!(body.benign_operation, evidence.operation);
        assert_eq!(body.probe, *evidence.probe.body());
        assert!(body.qualified_at_unix_ms >= body.probe.expires_at_unix_ms);
        let report = chio_core_types::recovery::SignedRecoverySetupReportV1::sign(
            body,
            &Keypair::from_seed(&[211; 32]),
        )?;
        assert_eq!(
            store.accept_setup_report(&report, &fence, expired_ms)?,
            report
        );
        assert_eq!(
            store.accept_setup_report(&report, &fence, expired_ms)?,
            report
        );
    } else {
        assert!(
            body.is_err(),
            "an expired first qualification cannot become readiness"
        );
        assert!(store
            .setup_preparation(&actor, &fence, expired_ms)?
            .report
            .is_none());
    }
    assert_eq!(external_count(&f.f.path)?, evidence.effects);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    Ok(())
}

#[tokio::test]
async fn setup_accepted_profile_reattests_a_later_writer_after_probe_expiry() -> TestResult {
    Box::pin(attest_after_initial_probe_expiry(true)).await
}

#[tokio::test]
async fn setup_expired_first_qualification_cannot_unlock_work() -> TestResult {
    Box::pin(attest_after_initial_probe_expiry(false)).await
}

fn second_inspector(f: &KnowledgeFixture) -> TestResult<CapabilityToken> {
    let key = Keypair::from_seed(&[212; 32]);
    let permissions = vec![RecoveryPermission::Inspect, RecoveryPermission::Resume];
    let mut deployment = f.f.kernel.recovery_deployment(f.f.runtime.scope())?;
    let mut actors = deployment.actors.as_slice().to_vec();
    let preview_clearance = actors
        .first()
        .ok_or("selected setup inspector clearance")?
        .preview_clearance
        .clone();
    actors.push(RecoveryActorAssignment {
        subject: key.public_key(),
        principal: PrincipalId::new("second-setup-inspector")?,
        permissions: BoundedList::new(permissions.clone())?,
        preview_clearance,
    });
    deployment.actors = NonEmptyBoundedList::new(actors)?;
    deployment.authority_scope = recovery_authority_scope_digest(&deployment)?;
    f.f.authority
        .admission_operation_store()
        .configure_recovery_deployment(&deployment)?;
    Ok(f.f.kernel.issue_capability(
        &key.public_key(),
        ChioScope {
            grants: permissions
                .iter()
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
        1_200,
    )?)
}

#[tokio::test]
async fn setup_current_inspector_qualifies_the_retained_completion_without_a_new_resume(
) -> TestResult {
    let mut f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let inspector = second_inspector(&f)?;
    let workflow = Box::pin(f.f.ready()).await?;
    let service = setup(&f, &workflow)?;
    let probe = service.probe(&f.f.control, &workflow).await?;
    let operation =
        f.f.record(&workflow)?
            .native_link
            .ok_or("benign native operation")?;
    let path = f.f.path.clone();
    let directory = f.f._directory.take();
    let calls = f.f.process.process("root")?.tree_calls;
    drop(service);
    drop(f);
    let reopened = KnowledgeFixture::from(RecoveryFixture::open(path, directory, false)?)?;
    let service = setup(&reopened, &workflow)?;
    let report = service.qualify(&inspector, &probe).await?;
    assert_eq!(report.body().benign_operation, operation);
    assert_eq!(external_count(&reopened.f.path)?, 1);
    assert_eq!(reopened.f.process.process("root")?.tree_calls, calls);
    Ok(())
}

#[tokio::test]
async fn setup_foreign_resume_cannot_acquire_the_pinned_benign_identity() -> TestResult {
    type RetainedProcessRows = Vec<(String, Vec<Vec<rusqlite::types::Value>>)>;
    let f = KnowledgeFixture::from(super::super::super::semantic::native_fixture("read")?)?;
    let inspector = second_inspector(&f)?;
    let workflow = Box::pin(f.f.ready()).await?;
    let _service = setup(&f, &workflow)?;
    let actor = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &inspector,
        RecoveryPermission::Resume,
    )?;
    assert_eq!(actor.permission(), RecoveryPermission::Resume);
    assert_ne!(actor.principal(), &f.f.record(&workflow)?.created_by);
    let inspection = f.f.command(
        "foreign-setup-inspect",
        RecoveryCommandBodyV1::InspectWorkflow {
            workflow_id: workflow.clone(),
        },
    )?;
    let inspected = f.f.runtime.execute_command(&inspector, &inspection).await?;
    assert_eq!(inspected.status.workflow_id, workflow);
    // The legitimate inspection may append its bounded command audit. Take
    // the refusal baseline after that completed, freshly authorized read.
    let before_workflow = chio_core_types::canonical_json_bytes(&f.f.record(&workflow)?)?;
    let before_flow =
        f.f.kernel
            .observe_recovery_source(f.f.runtime.scope())?
            .snapshot()
            .cloned()
            .ok_or("authenticated current setup source")?;
    let retained_process_rows = || -> TestResult<RetainedProcessRows> {
        let connection = rusqlite::Connection::open_with_flags(
            f.f.path.join("process.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let mut tables = connection
            .prepare("SELECT name FROM main.sqlite_schema WHERE type='table' ORDER BY name")?;
        let table_rows = tables.query_map([], |row| row.get::<_, String>(0))?;
        let names = table_rows.collect::<Result<Vec<_>, _>>()?;
        let mut snapshot = Vec::new();
        for name in names {
            let quoted = name.replace('"', "\"\"");
            let mut statement = connection.prepare(&format!("SELECT * FROM main.\"{quoted}\""))?;
            let columns = statement.column_count();
            if columns == 0 {
                return Err("retained Process table has no columns".into());
            }
            let order = (1..=columns)
                .map(|column| column.to_string())
                .collect::<Vec<_>>()
                .join(",");
            statement =
                connection.prepare(&format!("SELECT * FROM main.\"{quoted}\" ORDER BY {order}"))?;
            let rows = statement.query_map([], |row| {
                (0..columns)
                    .map(|column| row.get::<_, rusqlite::types::Value>(column))
                    .collect::<Result<Vec<_>, _>>()
            })?;
            snapshot.push((name, rows.collect::<Result<Vec<_>, _>>()?));
        }
        Ok(snapshot)
    };
    let before_process = retained_process_rows()?;
    let calls = f.f.process.process("root")?.tree_calls;
    let command = f.f.command(
        "foreign-setup-resume",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: workflow.clone(),
            expected_revision: f.f.record(&workflow)?.revision,
        },
    )?;
    assert_eq!(
        f.f.runtime
            .execute_command(&inspector, &command)
            .await
            .err(),
        Some(crate::recovery::RecoveryRuntimeError::AuthorityDenied),
        "a valid foreign Resume actor must reach the pinned setup owner refusal"
    );
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert!(!f.f.record(&workflow)?.captured);
    assert_eq!(
        chio_core_types::canonical_json_bytes(&f.f.record(&workflow)?)?,
        before_workflow
    );
    assert_eq!(
        f.f.kernel
            .observe_recovery_source(f.f.runtime.scope())?
            .snapshot(),
        Some(&before_flow)
    );
    assert_eq!(retained_process_rows()?, before_process);
    Ok(())
}

/// A genuine rotation that leaves an unprobed materialized setup selection
/// unable to ever qualify again: its native flow source moved, or its pinned
/// profile rotated.
#[derive(Clone, Copy)]
enum UnusedSetupRotation {
    StaleNativeSource,
    ChangedProfile,
}

async fn rotate_unprobed_selection(
    f: &KnowledgeFixture,
    rotation: UnusedSetupRotation,
) -> TestResult<ToolCallRequest> {
    match rotation {
        UnusedSetupRotation::StaleNativeSource => {
            // A later denied materialization under the same native context
            // moves the flow source past the selection's retained snapshot.
            f.f.denied_seed_named("fresh-setup-replacement").await
        }
        UnusedSetupRotation::ChangedProfile => {
            // A selected additional inspector rotates the deployment, so the
            // selection's pinned source profile genuinely changed.
            second_inspector(f)?;
            f.f.denied_seed_named("fresh-setup-replacement").await
        }
    }
}

/// Replace an unprobed materialized selection through a genuine rotation and
/// prove its unused custody is actually closed: the old admission closes with
/// its immutable original, the Process reservation closure commits before any
/// replay, the live allocation retires, no effect or double charge appears,
/// and the distinct replacement stays current and usable. This is unused
/// custody retirement, not an end-to-end native effect acceptance.
async fn unprobed_selection_replacement_closes_its_unused_custody(
    rotation: UnusedSetupRotation,
) -> TestResult {
    let state = Box::pin(selected_self_test()).await?;
    let f = &state.fixture;
    let previous_workflow = state.service.workflow().clone();
    let previous = f.f.record(&previous_workflow)?;
    assert!(previous.process_reservation.is_some());
    let seed = Box::pin(rotate_unprobed_selection(f, rotation)).await?;
    // The rotated selection can no longer qualify its own probe.
    let expected_probe_refusal = match rotation {
        UnusedSetupRotation::StaleNativeSource => crate::recovery::RecoveryRuntimeError::Conflict,
        UnusedSetupRotation::ChangedProfile => crate::recovery::RecoveryRuntimeError::Unavailable,
    };
    assert_eq!(
        state
            .service
            .probe(&f.f.control, &previous_workflow)
            .await
            .err(),
        Some(expected_probe_refusal),
        "a rotated unprobed selection must refuse its own probe before replacement"
    );
    let creation = f.f.command(
        "fresh-setup-replacement-create",
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new("fresh-setup-replacement")?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(&seed)?,
        },
    )?;
    require_eligible_original(f, &seed)?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let inspector = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &f.f.control,
        RecoveryPermission::Inspect,
    )?;
    store.observe_setup_coverage(
        &inspector,
        &f.f.kernel.receipt_signing_public_key(),
        &fence,
        now_ms()?,
    )?;
    let creator = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &f.f.control,
        RecoveryPermission::Create,
    )?;
    let calls_before_pin = f.f.process.process("root")?.tree_calls;
    let pinned = store
        .pin_setup_creation(
            &creator,
            &creation,
            chio_store_sqlite::admission_operation_store::NativeSetupCreationHost {
                receipt_key: &f.f.kernel.receipt_signing_public_key(),
                operator: &Keypair::from_seed(&[211; 32]).public_key(),
                process: &f.f.process,
                unused_closure: &f.f.process,
            },
            &fence,
            now_ms()?,
        )
        .map_err(|error| {
            format!("replacement pin after fresh actor, mediator inventory and original custody: {error}")
        })?;
    assert_eq!(f.f.process.process("root")?.tree_calls, calls_before_pin);
    let host = RecoverySetupHost {
        runtime: f.f.runtime.clone(),
        store: Arc::new(f.f.authority.admission_operation_store()),
        fence: f.f.authority.mutation_fence(),
        knowledge: Arc::new(f.runtime.clone()),
        operator: Keypair::from_seed(&[211; 32]),
    };
    let replacement = RecoverySetupService::for_creation(host, &f.f.control, &creation)
        .await
        .map_err(|error| format!("reopen replacement setup service: {error}"))?;
    assert_eq!(replacement.workflow(), &pinned);
    assert_ne!(replacement.workflow(), &previous_workflow);
    let retired = f.f.record(&previous_workflow)?;
    assert_eq!(retired.control, WorkflowControlV1::Cancelled);
    assert_eq!(retired.origin, previous.origin);
    assert_eq!(retired.creation_seed, previous.creation_seed);
    assert!(!retired.captured);
    assert!(retired.native_link.is_none());
    // The retired generation is actually closed and its live allocation is
    // retired, not merely marked: admission is closed with no intent and the
    // allocation row advanced to its retirement version.
    assert!(retired.admission_closed && retired.admission.is_none());
    assert_eq!(retired.effect, EffectObservationV1::NeverAdmitted);
    assert!(retired.process_reservation.is_none());
    {
        let connection = rusqlite::Connection::open_with_flags(
            f.f.path.join("admission.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )?;
        let allocation: i64 = connection.query_row(
            "SELECT version FROM admission_operation_recovery_records
             WHERE record_key GLOB ('recovery-workflow-allocation:*:' || ?1)",
            [previous_workflow.as_str()],
            |row| row.get(0),
        )?;
        assert_eq!(
            allocation, 2,
            "the retired generation's live allocation is retired"
        );
    }
    // The retired generation's reserved Process call is permanently closed:
    // observe the immutable closure row directly BEFORE replaying its writer,
    // so replay cannot create the evidence the retirement was required to
    // commit, with the original charge preserved and no double charge.
    let closed_reservation: RecoveryProcessReservationV1 = previous
        .process_reservation
        .as_ref()
        .map(|encoded| chio_core_types::recovery::decode_contract(encoded.as_str().as_bytes()))
        .transpose()?
        .ok_or("the retired generation lost its reserved process call")?;
    let journal = rusqlite::Connection::open_with_flags(
        f.f.path.join("process.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let already_closed: bool = journal.query_row(
        "SELECT EXISTS(SELECT 1 FROM process_unused_recovery_reservations
         WHERE process_id=?1 AND operation_key=?2 AND continuation_id=?3)",
        rusqlite::params![
            closed_reservation.process_id,
            closed_reservation.operation_key,
            closed_reservation.continuation_id.as_str(),
        ],
        |row| row.get(0),
    )?;
    assert!(
        already_closed,
        "setup replacement must commit the Process closure"
    );
    drop(journal);
    let calls_before_replay = f.f.process.process("root")?.tree_calls;
    let replayed = chio_kernel::recovery::RecoveryUnusedReservationClosurePort::close_unused_recovery_reservation(
        &f.f.process,
        &closed_reservation,
    )?;
    replayed.verify_for(&closed_reservation, fence.store_uuid.as_str())?;
    assert_eq!(external_count(&f.f.path)?, 0);
    let calls_after_replay = f.f.process.process("root")?.tree_calls;
    assert_eq!(calls_after_replay, calls_before_replay);
    let old_resume = f.f.command(
        "retired-setup-resume",
        RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id: previous_workflow.clone(),
            expected_revision: retired.revision,
        },
    )?;
    assert!(f
        .f
        .runtime
        .execute_command(&f.f.control, &old_resume)
        .await
        .is_err());
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls_after_replay);
    let workflow = Box::pin(f.f.ready_named("fresh-setup-replacement", "fresh-setup-replacement"))
        .await
        .map_err(|error| format!("materialize replacement setup workflow: {error}"))?;
    assert_eq!(replacement.workflow(), &workflow);
    let calls = f.f.process.process("root")?.tree_calls;
    let probe = replacement
        .probe(&f.f.control, &workflow)
        .await
        .map_err(|error| format!("execute replacement native setup probe: {error}"))?;
    assert_eq!(probe.body().benign_workflow, workflow);
    assert_eq!(external_count(&f.f.path)?, 1);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert!(!f.f.record(&previous_workflow)?.captured);
    Ok(())
}

#[tokio::test]
async fn setup_stale_unprobed_selection_can_be_replaced_without_waiting_for_expiry() -> TestResult {
    Box::pin(unprobed_selection_replacement_closes_its_unused_custody(
        UnusedSetupRotation::StaleNativeSource,
    ))
    .await
}

#[tokio::test]
async fn setup_profile_changed_unprobed_selection_closes_its_unused_reservation() -> TestResult {
    Box::pin(unprobed_selection_replacement_closes_its_unused_custody(
        UnusedSetupRotation::ChangedProfile,
    ))
    .await
}

#[tokio::test]
async fn setup_a_bare_runtime_cannot_skip_the_selected_live_mediator() -> TestResult {
    let state = Box::pin(selected_self_test()).await?;
    let f = &state.fixture;
    let bare = crate::recovery::RecoveryRuntime::new(
        f.f.kernel.clone(),
        f.f.process.clone(),
        f.f.runtime.flow.clone(),
        f.f.runtime.scope().clone(),
        f.f.runtime.signer.clone(),
    )?;
    let calls = f.f.process.process("root")?.tree_calls;
    assert_eq!(
        bare.review_document(&f.f.control, state.service.workflow())
            .err(),
        Some(crate::recovery::RecoveryRuntimeError::UncoveredMediation),
        "a retained protected marker requires live mediator validation in every runtime"
    );
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    Ok(())
}

/// Protected store counts that a stale selected-setup attempt must not move:
/// recovery records and events are admission custody history, operation
/// commits are the append chain, global commits are authority anchoring and
/// terminal records are receipt custody.
fn takeover_protected_counts(fixture: &RecoveryFixture) -> TestResult<(i64, i64, i64, i64, i64)> {
    Ok(rusqlite::Connection::open(fixture.path.join("admission.db"))?.query_row(
        "SELECT (SELECT count(*) FROM admission_operation_recovery_records), (SELECT count(*) FROM admission_operation_recovery_events), (SELECT count(*) FROM admission_operation_commits), (SELECT count(*) FROM authority_global_commits), (SELECT count(*) FROM admission_operation_terminal_records WHERE record_kind='receipt')",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?)
}

/// Writer A keeps its genuine live Kernel, Store and Process handles while a
/// new writer B takes over the same store with a strictly higher serving
/// epoch. A's selected setup preparation genuinely worked at A's own epoch.
/// After the takeover B constructs a matching live native mediator
/// composition, retires A's unprobed selection through the genuine
/// WriterChanged replacement path, and demonstrates a real selected-setup
/// preparation positive for its own pinned selection before the parked
/// finishing boundary. No probe, benign effect or native finishing is
/// executed. A's corresponding selected setup routes then refuse with the
/// exact typed fenced result while A stays alive, and none of the stale
/// attempts disturbs the retained workflow bytes, B's retained preparation
/// identity, protected counts, Process state or external effects. Baselines
/// are taken after B's legitimate replacement work, so only the stale
/// attempts are required to be mutation free.
#[tokio::test]
async fn setup_selected_preparation_refuses_the_stale_owner_while_the_fresh_writer_progresses(
) -> TestResult {
    let state = Box::pin(selected_self_test()).await?;
    let f = &state.fixture;
    let workflow = state.service.workflow().clone();
    let a_fence = f.f.authority.mutation_fence();
    let a_store = f.f.authority.admission_operation_store();
    let a_receipt_key = f.f.kernel.receipt_signing_public_key();
    let a_actor = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &f.f.control,
        RecoveryPermission::Inspect,
    )?;
    // A's selected setup route genuinely prepares while A still serves.
    let a_prepared = a_store.setup_preparation(&a_actor, &a_fence, now_ms()?)?;
    assert!(matches!(
        &a_prepared.command.command,
        RecoveryCommandBodyV1::ResumeWorkflow { workflow_id, .. } if workflow_id == &workflow
    ));
    assert_eq!(a_prepared.probe.benign_workflow, workflow);
    assert_eq!(external_count(&f.f.path)?, 0);
    // Retain A's original immutable identity while A still serves. Every
    // authoritative post-takeover read must go through B, so this pre-takeover
    // record is the only legitimate reference for the retired identity.
    let a_record = f.f.record(&workflow)?;
    // Releases the actual serving OS lock only. No fabricated epoch, poison
    // bit, rewritten authority record or replacement database is introduced,
    // and every A handle stays alive throughout.
    f.f.authority.release_serving_lock_for_stale_owner_test()?;
    let b = KnowledgeFixture::from(RecoveryFixture::open(f.f.path.clone(), None, false)?)
        .map_err(|error| format!("fresh writer fixture open on the same store: {error}"))?;
    let b_fence = b.f.authority.mutation_fence();
    assert_eq!(b_fence.store_uuid, a_fence.store_uuid);
    assert!(
        b_fence.owner_epoch > a_fence.owner_epoch,
        "the fresh writer must serve a strictly higher epoch on the same store"
    );
    assert_eq!(b.f.runtime.scope(), f.f.runtime.scope());
    assert_eq!(b.f.process.runtime_id(), f.f.process.runtime_id());
    // B's genuine progress: a real denied original, its retained custody, and
    // the actual creation pin that retires A's unprobed selection through the
    // WriterChanged replacement classification and pins B's own selection.
    let seed = b.f.denied_seed_named("fresh-writer-selected-setup").await?;
    require_eligible_original(&b, &seed)?;
    let creation = b.f.command(
        "fresh-writer-selected-setup-create",
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new("fresh-writer-selected-setup")?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(&seed)?,
        },
    )?;
    let host = RecoverySetupHost {
        runtime: b.f.runtime.clone(),
        store: Arc::new(b.f.authority.admission_operation_store()),
        fence: b_fence.clone(),
        knowledge: Arc::new(b.runtime.clone()),
        operator: Keypair::from_seed(&[211; 32]),
    };
    let service = RecoverySetupService::for_creation(host, &b.f.control, &creation)
        .await
        .map_err(|error| format!("fresh writer selected setup pin: {error}"))?;
    let b_workflow =
        Box::pin(b.f.ready_named("fresh-writer-selected-setup", "fresh-writer-selected-setup"))
            .await
            .map_err(|error| format!("fresh writer selected setup readiness: {error}"))?;
    assert_eq!(service.workflow(), &b_workflow);
    assert_ne!(&b_workflow, &workflow);
    // The selected-setup preparation positive itself: the real store prepares
    // B's own selected workflow with the matching actor, fence, runtime and
    // source, bound to B's current serving fence. No probe is run.
    let b_store = b.f.authority.admission_operation_store();
    let b_actor = b.f.kernel.authenticate_recovery_actor(
        b.f.runtime.scope(),
        &b.f.control,
        RecoveryPermission::Inspect,
    )?;
    let prepared = b_store.setup_preparation(&b_actor, &b_fence, now_ms()?)?;
    assert!(
        matches!(
            &prepared.command.command,
            RecoveryCommandBodyV1::ResumeWorkflow {
                workflow_id,
                expected_revision,
            } if workflow_id == &b_workflow
                && *expected_revision == b.f.record(&b_workflow)?.revision
        ),
        "the fresh writer's preparation must bind its own selected workflow and revision"
    );
    assert_eq!(prepared.probe.benign_workflow, b_workflow);
    assert_eq!(&prepared.probe.scope, b.f.runtime.scope());
    assert!(prepared.report.is_none() && prepared.signed_probe.is_none());
    assert_eq!(
        prepared.previous_serving_fence,
        SourceDigest::from_bytes(chio_kernel::recovery::recovery_digest(
            chio_core_types::recovery::RecoveryDigestDomain::ServingFence,
            &b_fence,
        )?),
        "the prepared selection must be pinned to the fresh writer's own serving fence"
    );
    assert_eq!(external_count(&b.f.path)?, 0);
    // B's takeover genuinely closed A's unused selection custody: the old
    // workflow retired with its original identity, closed admission, no
    // captured effect and no live reservation. This is B's legitimate work,
    // not a mutation the stale attempts are allowed to touch.
    let retired = b.f.record(&workflow)?;
    assert_eq!(retired.control, WorkflowControlV1::Cancelled);
    assert_eq!(retired.origin, a_record.origin);
    assert_eq!(retired.creation_seed, a_record.creation_seed);
    assert!(retired.admission_closed && retired.admission.is_none());
    assert_eq!(retired.effect, EffectObservationV1::NeverAdmitted);
    assert!(!retired.captured);
    assert!(retired.native_link.is_none());
    assert!(retired.process_reservation.is_none());
    // Baselines are taken after B's legitimate work.
    let baseline = takeover_protected_counts(&b.f)?;
    let stale_workflow_bytes = chio_core_types::canonical_json_bytes(&b.f.record(&workflow)?)?;
    let fresh_workflow_bytes = chio_core_types::canonical_json_bytes(&b.f.record(&b_workflow)?)?;
    // The same persisted Process namespace is observed only through B's
    // current authority. A's public Process reads also check the stale fence.
    let fresh_calls = b.f.process.process("root")?.tree_calls;
    let effects = external_count(&b.f.path)?;
    assert_eq!(effects, 0);
    // A's corresponding selected setup routes refuse with the exact typed
    // fenced result while A stays alive through its own retained handles.
    assert!(matches!(
        a_store.setup_preparation(&a_actor, &a_fence, now_ms()?),
        Err(
            chio_store_sqlite::admission_operation_store::NativeSetupPreparationError::Store(
                chio_kernel::admission_operation::AdmissionOperationStoreError::Fenced
            )
        )
    ));
    assert!(matches!(
        a_store.configure_protected_setup(
            f.f.runtime.scope(),
            &workflow,
            &a_receipt_key,
            &Keypair::from_seed(&[211; 32]).public_key(),
            &a_fence,
            now_ms()?,
        ),
        Err(chio_kernel::admission_operation::AdmissionOperationStoreError::Fenced)
    ));
    // None of the stale attempts moved protected counts, either workflow's
    // canonical bytes, the Process call trees, or external effects, and B's
    // preparation identity is retained when re-read through B.
    assert_eq!(takeover_protected_counts(&b.f)?, baseline);
    assert_eq!(
        chio_core_types::canonical_json_bytes(&b.f.record(&workflow)?)?,
        stale_workflow_bytes
    );
    assert_eq!(
        chio_core_types::canonical_json_bytes(&b.f.record(&b_workflow)?)?,
        fresh_workflow_bytes
    );
    let replay = b_store.setup_preparation(&b_actor, &b_fence, now_ms()?)?;
    assert_eq!(replay.command, prepared.command);
    assert_eq!(replay.probe, prepared.probe);
    assert!(replay.report.is_none() && replay.signed_probe.is_none());
    assert_eq!(
        replay.previous_serving_fence,
        prepared.previous_serving_fence
    );
    assert_eq!(service.workflow(), &b_workflow);
    assert_eq!(b.f.process.process("root")?.tree_calls, fresh_calls);
    assert_eq!(external_count(&b.f.path)?, effects);
    Ok(())
}
