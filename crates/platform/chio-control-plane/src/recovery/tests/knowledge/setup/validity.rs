//! Initial setup validity ends before a fresh selected effect can be acquired.
use super::*;
use chio_kernel::admission_operation::AdmissionOperationStoreError;

struct ExtendedValiditySetup {
    fixture: KnowledgeFixture,
    _service: RecoverySetupService,
    prepared: NativeSetupPreparationV1,
    replacement_original: Option<ToolCallRequest>,
}

async fn materialize_selected_setup(
    f: &KnowledgeFixture,
    create: &RecoveryCommandV1,
) -> TestResult<WorkflowId> {
    // Replay the independently retained creation without repeating original
    // denial lookup.
    let created = Box::pin(f.f.runtime.execute_command(&f.f.control, create))
        .await
        .map_err(|error| format!("setup validity phase=create replay: {error}"))?;
    let workflow = created.status.workflow_id;
    let record =
        f.f.record(&workflow)
            .map_err(|error| format!("setup validity phase=created workflow: {error}"))?;
    let action = record.action.as_ref().ok_or("late setup action")?;
    let digest = recovery_digest(
        chio_core_types::recovery::RecoveryDigestDomain::ActionIntent,
        action,
    )?;
    let offer = format!(
        "offer:{}",
        digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    let select = f.f.command(
        "select",
        RecoveryCommandBodyV1::SelectOffer {
            workflow_id: workflow.clone(),
            expected_revision: record.revision,
            offer_id: OfferId::new(&offer)?,
        },
    )?;
    Box::pin(f.f.runtime.execute_command(&f.f.control, &select))
        .await
        .map_err(|error| format!("setup validity phase=select offer: {error}"))?;
    let intent =
        f.f.runtime
            .approval_intent(&f.f.control, &workflow)
            .map_err(|error| format!("setup validity phase=approval intent: {error}"))?;
    let record =
        f.f.record(&workflow)
            .map_err(|error| format!("setup validity phase=selected workflow: {error}"))?;
    let action = record.action.as_ref().ok_or("late setup approval action")?;
    let evidence = AuthorityCoverageAttestationV1 {
        schema: AuthorityCoverageSchema::V1,
        version: VersionV1,
        scope: f.f.runtime.scope().clone(),
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
    let approval = RecoveryApprovalSubmissionV1 {
        intent,
        coverage: NonEmptyBoundedList::new(vec![SignedAuthorityCoverageAttestationV1::sign(
            evidence,
            &f.f.approval_key,
        )?])?,
    };
    let approve = f.f.command(
        "approve",
        RecoveryCommandBodyV1::SubmitApproval {
            workflow_id: workflow.clone(),
            expected_revision: record.revision,
            approval: text(&approval)?,
        },
    )?;
    Box::pin(f.f.runtime.execute_command(&f.f.control, &approve))
        .await
        .map_err(|error| format!("setup validity phase=submit approval: {error}"))?;
    Ok(workflow)
}

async fn extended_validity_setup() -> TestResult<ExtendedValiditySetup> {
    extended_validity_setup_with_options(false, false).await
}

/// A second authenticated original is denied before the selection, so the
/// native clock never has to move backwards to create it after late setup.
async fn extended_validity_setup_with_replacement_original() -> TestResult<ExtendedValiditySetup> {
    extended_validity_setup_with_options(false, true).await
}

async fn extended_validity_setup_with_options(
    checkpoint: bool,
    replacement_original: bool,
) -> TestResult<ExtendedValiditySetup> {
    let directory = tempfile::tempdir()?;
    if checkpoint {
        use chio_kernel::admission_operation::{
            NativeOutputEnvelopeBoundsV1, NativeOutputRetentionProfileV1,
        };
        // The capture checkpoint requires an explicitly selected native output
        // plan. Selection does not prepare or fund its physical finishing account.
        let retention = NativeOutputRetentionProfileV1::new(NativeOutputEnvelopeBoundsV1::new(
            1024 * 1024,
            1024 * 1024,
            1024 * 1024,
            1024 * 1024,
            1,
        )?);
        std::fs::write(
            directory.path().join("output-retention-profile.json"),
            chio_core::canonical_json_bytes(&retention)?,
        )?;
        std::fs::write(
            directory.path().join("setup-capture-clock-checkpoint"),
            "selected",
        )?;
    } else {
        // Without the checkpoint this setup keeps its original unselected.
        std::fs::write(directory.path().join("no-output-retention-profile"), "absent")?;
    }
    std::fs::write(directory.path().join("semantic-kind"), "read")?;
    // Both the original capability and the native policy clock must remain
    // valid when the initial setup window ends. The ordinary fixture stays
    // unchanged unless this independently bounded test profile is selected.
    std::fs::write(directory.path().join("extended-setup-validity"), "selected")?;
    let recovery = RecoveryFixture::open(directory.path().to_path_buf(), Some(directory), false)
        .map_err(|error| format!("setup validity phase=native fixture open: {error}"))?;
    let f = KnowledgeFixture::from(recovery)
        .map_err(|error| format!("setup validity phase=current knowledge fixture: {error}"))?;
    let replacement_original = if replacement_original {
        let original = Box::pin(f.f.denied_seed_named("replacement-setup-original"))
            .await
            .map_err(|error| {
                format!("setup validity phase=replacement original denial: {error}")
            })?;
        require_eligible_original(&f, &original)?;
        Some(original)
    } else {
        None
    };
    let original = Box::pin(f.f.denied_seed_named("ticket-1"))
        .await
        .map_err(|error| format!("setup validity phase=original denial: {error}"))?;
    require_eligible_original(&f, &original)?;
    let create = f.f.command(
        "create",
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new("ticket-1")?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(&original)?,
        },
    )?;
    // Create through the real Kernel to retain the authenticated original,
    // while postponing action materialization until near the probe deadline.
    let created = f.f.kernel.execute_recovery_command_with_origin(
        &f.actor(RecoveryPermission::Create)?,
        &create,
        &f.f.process,
    )?;
    let initial = f.f.record(&created.workflow_id)?;
    assert!(initial.origin.is_some());
    assert!(initial.action.is_none() && initial.process_reservation.is_none());
    assert!(!initial.captured && initial.native_link.is_none());
    let service = setup(&f, &created.workflow_id)
        .map_err(|error| format!("setup validity phase=trusted setup host: {error}"))?;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let selected = store.configure_protected_setup(
        f.f.runtime.scope(),
        &created.workflow_id,
        &f.f.kernel.receipt_signing_public_key(),
        &Keypair::from_seed(&[211; 32]).public_key(),
        &fence,
        now_ms()?,
    )?;
    let expiry = selected.probe.expires_at_unix_ms.get();
    let late_seconds = expiry
        .checked_div(1_000)
        .and_then(|seconds| seconds.checked_sub(10))
        .ok_or("setup validity late clock")?;
    let prepared = {
        let _clock = scope_synchronous_fixture_clock(late_seconds);
        let workflow = Box::pin(materialize_selected_setup(&f, &create))
            .await
            .map_err(|error| format!("setup validity phase=late action and approval: {error}"))?;
        assert_eq!(workflow, created.workflow_id);
        assert_eq!(external_count(&f.f.path)?, 0);
        let record = f.f.record(&workflow)?;
        assert!(!record.captured && record.native_link.is_none());
        let action = record.action.as_ref().ok_or("late native action")?;
        let approval = record.approval.as_ref().ok_or("late native approval")?;
        assert!(
            action
                .authorization_requirements
                .validity_ceiling_unix_ms
                .get()
                > expiry
        );
        assert!(approval.intent.expires_at_unix_ms.get() > expiry);
        assert!(approval
            .coverage
            .as_slice()
            .iter()
            .all(|proof| { proof.body().expires_at_unix_ms.get() > expiry }));
        assert!(record
            .seed
            .capability
            .expires_at
            .checked_mul(1_000)
            .is_some_and(|end| end > expiry + 1_000));
        assert!(f
            .f
            .control
            .expires_at
            .checked_mul(1_000)
            .is_some_and(|end| end > expiry + 1_000));
        let inspector = f
            .actor(RecoveryPermission::Inspect)
            .map_err(|error| format!("setup validity phase=late native inspector: {error}"))?;
        let prepared = store
            .setup_preparation(&inspector, &fence, late_seconds * 1_000)
            .map_err(|error| format!("setup validity phase=bound selected command: {error}"))?;
        assert_eq!(prepared.probe, selected.probe);
        assert!(prepared.report.is_none());
        let RecoveryCommandBodyV1::ResumeWorkflow {
            workflow_id,
            expected_revision,
        } = &prepared.command.command
        else {
            return Err("selected setup command is not Resume".into());
        };
        assert_eq!(workflow_id, &workflow);
        assert_eq!(*expected_revision, record.revision);
        f.runtime
            .validate_setup_binding(f.f.runtime.scope(), &f.profile.native_authority)
            .map_err(|error| {
                format!("setup validity phase=late current broker binding: {error}")
            })?;
        f.f.kernel
            .authenticate_recovery_actor(
                f.f.runtime.scope(),
                &f.f.control,
                RecoveryPermission::Resume,
            )
            .map_err(|error| format!("setup validity phase=late native Resume actor: {error}"))?;
        prepared
    };
    Ok(ExtendedValiditySetup {
        fixture: f,
        _service: service,
        prepared,
        replacement_original,
    })
}

#[tokio::test]
async fn setup_selected_command_before_initial_expiry_still_dispatches_once() -> TestResult {
    let state = Box::pin(extended_validity_setup()).await?;
    let f = &state.fixture;
    let valid_seconds = state.prepared.probe.expires_at_unix_ms.get() / 1_000 - 1;
    let _clock = scope_synchronous_fixture_clock(valid_seconds);
    let calls = f.f.process.process("root")?.tree_calls;
    let result =
        f.f.runtime
            .execute_command(&f.f.control, &state.prepared.command)
            .await
            .map_err(|error| format!("setup validity phase=valid public Resume: {error}"))?;
    let receipt = result
        .original_response
        .ok_or_else(|| {
            format!(
                "valid setup completion projection absent: status effect={:?}; {}",
                result.status.effect,
                dispatch_diagnostic(f, &state.prepared.probe.benign_workflow),
            )
        })?
        .receipt;
    assert!(receipt.is_allowed() && receipt.verify_signature()?);
    assert_eq!(external_count(&f.f.path)?, 1);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    let record = f.f.record(&state.prepared.probe.benign_workflow)?;
    assert!(record.captured && record.native_link.is_some());
    Ok(())
}

#[tokio::test]
async fn setup_expired_selected_command_refuses_without_an_effect_or_charge() -> TestResult {
    let state = Box::pin(extended_validity_setup()).await?;
    let f = &state.fixture;
    let expired_seconds = state.prepared.probe.expires_at_unix_ms.get() / 1_000 + 1;
    let _clock = scope_synchronous_fixture_clock(expired_seconds);
    let actor = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &f.f.control,
        RecoveryPermission::Resume,
    )?;
    let before =
        f.f.kernel
            .read_recovery_workflow(&actor, &state.prepared.probe.benign_workflow)?;
    let action = before
        .action
        .as_ref()
        .ok_or("still-valid selected native action")?;
    let approval = before
        .approval
        .as_ref()
        .ok_or("still-valid selected native approval")?;
    assert!(
        action
            .authorization_requirements
            .validity_ceiling_unix_ms
            .get()
            > expired_seconds * 1_000
    );
    assert!(approval.intent.expires_at_unix_ms.get() > expired_seconds * 1_000);
    assert!(!before.captured && before.native_link.is_none());
    f.runtime
        .validate_setup_binding(f.f.runtime.scope(), &f.profile.native_authority)?;
    let calls = f.f.process.process("root")?.tree_calls;
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(
        f.f.runtime.execute_command(&f.f.control, &state.prepared.command).await.err(),
        Some(crate::recovery::RecoveryRuntimeError::UncoveredMediation),
        "the native command owner must close the expired initial setup window before a fresh effect"
    );
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    let after =
        f.f.kernel
            .read_recovery_workflow(&actor, &state.prepared.probe.benign_workflow)?;
    assert_eq!(
        chio_core_types::canonical_json_bytes(&after)?,
        chio_core_types::canonical_json_bytes(&before)?
    );
    Ok(())
}

#[derive(Clone, Copy)]
enum SetupCaptureWindow {
    LiveThroughCommit,
    ExpiredBeforeEntry,
    ExpiresBeforeCommit,
}

/// Public workflow custody after a dispatch, for refusals that carry no error.
fn dispatch_diagnostic(f: &KnowledgeFixture, workflow: &WorkflowId) -> String {
    let effects = external_count(&f.f.path).ok();
    match f.f.record(workflow) {
        Ok(record) => format!(
            "workflow effect={:?} control={:?} captured={} linked={} external_effects={effects:?} authority_high_water={:?}",
            record.effect,
            record.control,
            record.captured,
            record.native_link.is_some(),
            retained_authority_high_water(f).ok(),
        ),
        Err(error) => format!("workflow unreadable: {error}; external_effects={effects:?}"),
    }
}

// Observe exactly the two durable clocks used by the admission authority.
// This read grants no progress, changes no high-water mark and writes no rows.
fn retained_authority_high_water(f: &KnowledgeFixture) -> TestResult<u64> {
    let connection = rusqlite::Connection::open_with_flags(
        f.f.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let (admission, recovery): (i64, i64) = connection.query_row(
        "SELECT trusted_time_high_water_unix_ms,
                (SELECT coalesce(max(observed_at),0) FROM admission_operation_recovery_events)
         FROM admission_operation_commit_meta WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok(u64::try_from(admission.max(recovery))?)
}

async fn capture_at_selected_setup_window(window: SetupCaptureWindow) -> TestResult {
    let state = Box::pin(extended_validity_setup_with_options(true, false))
        .await
        .map_err(|error| format!("setup capture phase=prepared native fixture: {error}"))?;
    let f = &state.fixture;
    let expiry_seconds = state.prepared.probe.expires_at_unix_ms.get() / 1_000;
    let entry_seconds = expiry_seconds
        .checked_sub(1)
        .ok_or("setup capture entry clock")?;
    let capture_seconds = if matches!(window, SetupCaptureWindow::ExpiredBeforeEntry) {
        expiry_seconds
            .checked_add(1)
            .ok_or("setup capture expiry clock")?
    } else {
        entry_seconds
    };
    let final_expiry = matches!(window, SetupCaptureWindow::ExpiresBeforeCommit);
    let inspect_seconds = if final_expiry {
        expiry_seconds
            .checked_add(1)
            .ok_or("setup final capture clock")?
    } else {
        capture_seconds
    };
    let final_observed_path = f.f.path.join("setup-capture-final-cutpoint-observed");
    assert!(!final_observed_path.exists());
    if final_expiry {
        std::fs::write(f.f.path.join("setup-capture-final-expiry"), "selected")?;
    }
    std::fs::write(
        f.f.path.join("setup-capture-selected-seconds"),
        capture_seconds.to_string(),
    )?;
    let _entry_clock = scope_synchronous_fixture_clock(entry_seconds);
    let before =
        f.f.record(&state.prepared.probe.benign_workflow)
            .map_err(|error| format!("setup capture phase=live retained workflow: {error}"))?;
    assert!(!before.captured && before.native_link.is_none());
    let action = before.action.as_ref().ok_or("setup capture action")?;
    let approval = before.approval.as_ref().ok_or("setup capture approval")?;
    assert!(
        action
            .authorization_requirements
            .validity_ceiling_unix_ms
            .get()
            > inspect_seconds * 1_000
    );
    assert!(approval.intent.expires_at_unix_ms.get() > inspect_seconds * 1_000);
    assert!(approval.coverage.as_slice().iter().all(|evidence| evidence
        .body()
        .expires_at_unix_ms
        .get()
        > inspect_seconds * 1_000));
    assert!(before.seed.capability.expires_at > inspect_seconds);
    let reservation: chio_kernel::recovery::RecoveryProcessReservationV1 =
        chio_core_types::recovery::decode_contract(
            before
                .process_reservation
                .as_ref()
                .ok_or("setup capture reservation")?
                .as_str()
                .as_bytes(),
        )?;
    let calls =
        f.f.process
            .process("root")
            .map_err(|error| format!("setup capture phase=original process charge: {error}"))?
            .tree_calls;
    let result =
        f.f.runtime
            .execute_command(&f.f.control, &state.prepared.command)
            .await;
    let public = match &result {
        Ok(result) => format!(
            "Ok(status effect={:?}, projection={})",
            result.status.effect,
            result.original_response.is_some()
        ),
        Err(error) => format!("Err({error:?})"),
    };
    let observation = std::fs::read_to_string(f.f.path.join("setup-capture-checkpoint-observed"))
        .map_err(|error| {
        format!(
            "setup capture phase=actual native checkpoint missing; public={public}; {}: {error}",
            dispatch_diagnostic(f, &state.prepared.probe.benign_workflow),
        )
    })?;
    // This default-off checkpoint always stops connector use, including after
    // a successful real physical capture. The public result therefore is not a
    // delivery control; the fenced ledger and quota are the owning controls.
    assert_eq!(
        external_count(&f.f.path).map_err(|error| format!(
            "setup capture phase=post-checkpoint effect count: {error}"
        ))?,
        0
    );
    let high_water = retained_authority_high_water(f).map_err(|error| {
        format!("setup capture phase=actual post-checkpoint authority time: {error}")
    })?;
    assert!(
        high_water <= inspect_seconds * 1_000,
        "post-checkpoint inspection must cover every committed native timestamp",
    );
    if matches!(window, SetupCaptureWindow::ExpiredBeforeEntry) {
        assert!(
            high_water > entry_seconds * 1_000,
            "the actual expired-entry checkpoint advanced durable authority time beyond the restored entry clock",
        );
    }
    // The real capture checkpoint may commit at its selected later time. All
    // subsequent metadata and custody reads use that time, never an earlier
    // restored entry sample that would violate the native monotone clock.
    let _capture_clock = scope_synchronous_fixture_clock(inspect_seconds);
    let after_calls = f
        .f
        .process
        .process("root")
        .map_err(|error| format!("setup capture phase=post-checkpoint process charge: {error}"))?
        .tree_calls;
    assert_eq!(after_calls, calls);
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let (operation, retained) = store
        .load_unambiguous_retained_tool_request(
            &AdmissionIdentifier::try_new("request_id", &reservation.request_id)?,
            &fence,
            inspect_seconds * 1_000,
        )
        .map_err(|error| format!("setup capture phase=actual native original custody: {error}"))?
        .ok_or("setup capture actual native original custody")?;
    let physical = store
        .load_native_dispatch_capture(
            operation.binding().operation_id(),
            &fence,
            inspect_seconds * 1_000,
        )
        .map_err(|error| {
            format!("setup capture phase=actual physical capture readback: {error}")
        })?;
    let usage =
        f.f.authority
            .budget_store()
            .get_invocation_quota_usage(&BudgetQuotaKey::grant(
                &retained.request_for_revalidation().capability.id,
                0,
            ))
            .map_err(|error| format!("setup capture phase=actual invocation quota: {error}"))?
            .ok_or("setup capture exact native quota")?;
    if final_expiry {
        let cutpoint = std::fs::read_to_string(&final_observed_path).map_err(|error| {
            format!(
                "setup final capture phase=verified cutpoint missing; public={public}; checkpoint={observation}: {error}",
            )
        })?;
        let scalars = cutpoint
            .split(',')
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()?;
        let [sampled_at, actual_deadline, advanced]: [u64; 3] = scalars
            .try_into()
            .map_err(|_| "setup final capture cutpoint cardinality")?;
        assert!(sampled_at >= entry_seconds * 1_000);
        assert!(sampled_at < actual_deadline);
        assert_eq!(
            actual_deadline,
            state.prepared.probe.expires_at_unix_ms.get()
        );
        assert_eq!(advanced, inspect_seconds * 1_000);
        assert!(
            advanced >= actual_deadline,
            "only the final private setup sample crosses the initial deadline",
        );
    }
    if !matches!(window, SetupCaptureWindow::LiveThroughCommit) {
        assert!(
            observation.starts_with("refused:"),
            "initial expiry must refuse the real checkpoint: {observation}"
        );
        assert!(physical.is_none() && operation.dispatch_commit().is_none());
        assert!(operation.native_dispatch_ledger_digest().is_none());
        assert_eq!(usage.captured_invocations, 0);
        let after = f
            .f
            .record(&state.prepared.probe.benign_workflow)
            .map_err(|error| format!("setup capture phase=refused workflow readback: {error}"))?;
        assert!(!after.captured);
    } else {
        assert_eq!(observation, "captured");
        assert!(physical.is_some() && operation.dispatch_commit().is_some());
        assert!(operation.native_dispatch_ledger_digest().is_some());
        assert_eq!(usage.captured_invocations, 1);
        let after = f
            .f
            .record(&state.prepared.probe.benign_workflow)
            .map_err(|error| format!("setup capture phase=committed workflow readback: {error}"))?;
        assert!(after.captured);
    }
    Ok(())
}

#[tokio::test]
async fn setup_pending_capture_before_initial_expiry_retains_the_real_native_ledger() -> TestResult
{
    capture_at_selected_setup_window(SetupCaptureWindow::LiveThroughCommit).await
}

#[tokio::test]
async fn setup_pending_capture_after_initial_expiry_refuses_the_real_native_ledger() -> TestResult {
    capture_at_selected_setup_window(SetupCaptureWindow::ExpiredBeforeEntry).await
}

#[tokio::test]
async fn setup_pending_capture_crossing_initial_expiry_before_commit_rolls_back_its_native_ledger(
) -> TestResult {
    capture_at_selected_setup_window(SetupCaptureWindow::ExpiresBeforeCommit).await
}

#[tokio::test]
async fn setup_expired_unprobed_selection_retires_without_refunding_its_call() -> TestResult {
    let state = Box::pin(extended_validity_setup()).await?;
    let f = &state.fixture;
    // Materialization advanced the persisted authority clock. Keep subsequent
    // reads and writes beyond that clock as well as the initial setup window.
    let expired_seconds = state.prepared.probe.expires_at_unix_ms.get() / 1_000 + 1;
    let _clock = scope_synchronous_fixture_clock(expired_seconds);
    let old_workflow = &state.prepared.probe.benign_workflow;
    let previous = f.f.record(old_workflow)?;
    let reservation: RecoveryProcessReservationV1 = chio_core_types::recovery::decode_contract(
        previous
            .process_reservation
            .as_ref()
            .ok_or("unused setup reservation")?
            .as_str()
            .as_bytes(),
    )?;
    let now = expired_seconds * 1_000;
    let store = f.f.authority.admission_operation_store();
    let fence = f.f.authority.mutation_fence();
    let deployment = f.f.kernel.recovery_deployment(f.f.runtime.scope())?;
    f.runtime
        .validate_setup_binding(f.f.runtime.scope(), &deployment.native_authority)?;
    let inspector = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &f.f.control,
        RecoveryPermission::Inspect,
    )?;
    assert!(matches!(
        store.setup_preparation(&inspector, &fence, now),
        Err(NativeSetupPreparationError::Expired)
    ));
    // Reuse the authenticated original denial. The replacement changes only
    // its continuation; no new call is needed to advance the native source.
    let original: ToolCallRequest =
        chio_core_types::recovery::decode_contract(previous.creation_seed.as_str().as_bytes())?;
    let calls = f.f.process.process("root")?.tree_calls;
    let replacement = pin_setup_replacement(f, &original, "expired-setup-replacement", now)??;
    assert_ne!(&replacement, old_workflow);
    let retired = f.f.record(old_workflow)?;
    assert_eq!(retired.control, WorkflowControlV1::Cancelled);
    assert_eq!(retired.origin, previous.origin);
    assert_eq!(retired.creation_seed, previous.creation_seed);
    assert!(retired.admission_closed && retired.admission.is_none());
    assert!(retired.process_reservation.is_none());
    assert!(!retired.captured && retired.native_link.is_none());
    assert_eq!(retired.effect, EffectObservationV1::NeverAdmitted);
    let current = f.f.record(&replacement)?;
    assert_eq!(current.origin, previous.origin);
    assert_eq!(current.creation_seed, previous.creation_seed);
    assert_eq!(current.control, WorkflowControlV1::Active);
    assert!(current.action.is_none() && current.process_reservation.is_none());
    assert_eq!(retained_allocation_version(f, old_workflow)?, 2);
    // Inspect physical custody before invoking the idempotent closure port.
    let journal = rusqlite::Connection::open_with_flags(
        f.f.path.join("process.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let closed: bool = journal.query_row(
        "SELECT EXISTS(SELECT 1 FROM process_unused_recovery_reservations
         WHERE process_id=?1 AND operation_key=?2 AND continuation_id=?3)",
        rusqlite::params![
            reservation.process_id,
            reservation.operation_key,
            reservation.continuation_id.as_str()
        ],
        |row| row.get(0),
    )?;
    assert!(closed);
    drop(journal);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    let replay = chio_kernel::recovery::RecoveryUnusedReservationClosurePort::close_unused_recovery_reservation(
        &f.f.process, &reservation,
    )?;
    replay.verify_for(&reservation, fence.store_uuid.as_str())?;
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    assert_eq!(external_count(&f.f.path)?, 0);
    Ok(())
}

fn retained_allocation_version(f: &KnowledgeFixture, workflow: &WorkflowId) -> TestResult<i64> {
    let connection = rusqlite::Connection::open_with_flags(
        f.f.path.join("admission.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    Ok(connection.query_row(
        "SELECT version FROM admission_operation_recovery_records
         WHERE record_key GLOB ('recovery-workflow-allocation:*:' || ?1)",
        [workflow.as_str()],
        |row| row.get(0),
    )?)
}

/// The outer result is a fixture failure. The inner result is the native
/// owner's decision for the trusted selected-operator replacement.
fn pin_setup_replacement(
    f: &KnowledgeFixture,
    original: &ToolCallRequest,
    key: &str,
    now: u64,
) -> TestResult<Result<WorkflowId, AdmissionOperationStoreError>> {
    let creator = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &f.f.control,
        RecoveryPermission::Create,
    )?;
    let command = f.f.command(
        key,
        RecoveryCommandBodyV1::CreateWorkflow {
            creation_key: CreationKey::new(key)?,
            template: RecoveryTemplateV1::SupportTicketPublicIssue,
            request_seed: text(original)?,
        },
    )?;
    Ok(f.f
        .authority
        .admission_operation_store()
        .pin_setup_creation(
            &creator,
            &command,
            chio_store_sqlite::admission_operation_store::NativeSetupCreationHost {
                receipt_key: &f.f.kernel.receipt_signing_public_key(),
                operator: &Keypair::from_seed(&[211; 32]).public_key(),
                process: &f.f.process,
                unused_closure: &f.f.process,
            },
            &f.f.authority.mutation_fence(),
            now,
        ))
}

#[tokio::test]
async fn setup_cancelled_unprobed_selection_is_replaced_after_its_initial_window() -> TestResult {
    let state = Box::pin(extended_validity_setup_with_replacement_original()).await?;
    let f = &state.fixture;
    let old_workflow = &state.prepared.probe.benign_workflow;
    let replacement_original = state
        .replacement_original
        .as_ref()
        .ok_or("replacement setup original")?;
    let expiry_seconds = state.prepared.probe.expires_at_unix_ms.get() / 1_000;
    {
        let _clock = scope_synchronous_fixture_clock(expiry_seconds - 1);
        let live = f.f.record(old_workflow)?;
        Box::pin(f.f.execute(
            "cancel-unprobed-setup",
            RecoveryCommandBodyV1::CancelWorkflow {
                workflow_id: old_workflow.clone(),
                expected_revision: live.revision,
            },
        ))
        .await?;
    }
    let expired_seconds = expiry_seconds + 1;
    let _clock = scope_synchronous_fixture_clock(expired_seconds);
    let now = expired_seconds * 1_000;
    let cancelled = f.f.record(old_workflow)?;
    assert_eq!(cancelled.control, WorkflowControlV1::Cancelled);
    assert!(!cancelled.captured && cancelled.native_link.is_none());
    let retained = chio_core_types::canonical_json_bytes(&cancelled)?;
    let allocation = retained_allocation_version(f, old_workflow)?;
    let calls = f.f.process.process("root")?.tree_calls;
    let replacement =
        pin_setup_replacement(f, replacement_original, "cancelled-setup-replacement", now)?
            .map_err(|error| format!("replace cancelled unprobed setup selection: {error}"))?;
    assert_ne!(&replacement, old_workflow);
    // Replacing the selection leaves the cancelled workflow, its original and
    // its allocation exactly as cancellation left them.
    assert_eq!(
        chio_core_types::canonical_json_bytes(&f.f.record(old_workflow)?)?,
        retained
    );
    assert_eq!(retained_allocation_version(f, old_workflow)?, allocation);
    let current = f.f.record(&replacement)?;
    assert_eq!(current.control, WorkflowControlV1::Active);
    assert_ne!(current.origin, cancelled.origin);
    assert_ne!(current.creation_seed, cancelled.creation_seed);
    assert!(current.action.is_none() && current.process_reservation.is_none());
    assert_eq!(external_count(&f.f.path)?, 0);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    Ok(())
}

/// The benign effect ran, but its probe evidence was never committed before
/// the initial window closed.
#[tokio::test]
async fn setup_dispatched_unprobed_selection_is_replaced_after_expiry_without_touching_its_effect(
) -> TestResult {
    let state = Box::pin(extended_validity_setup_with_replacement_original()).await?;
    let f = &state.fixture;
    let old_workflow = &state.prepared.probe.benign_workflow;
    let replacement_original = state
        .replacement_original
        .as_ref()
        .ok_or("replacement setup original")?;
    let expiry_seconds = state.prepared.probe.expires_at_unix_ms.get() / 1_000;
    let reservation: RecoveryProcessReservationV1 = {
        // Preparation advanced the retained authority clock near the deadline.
        // Enter that window before reading the retained reservation as well.
        let _clock = scope_synchronous_fixture_clock(expiry_seconds - 1);
        let reservation = chio_core_types::recovery::decode_contract(
            f.f.record(old_workflow)?
                .process_reservation
                .as_ref()
                .ok_or("dispatched setup reservation")?
                .as_str()
                .as_bytes(),
        )?;
        let result = Box::pin(
            f.f.runtime
                .execute_command(&f.f.control, &state.prepared.command),
        )
        .await
        .map_err(|error| format!("dispatch selected setup command: {error}"))?;
        assert!(result
            .original_response
            .ok_or_else(|| {
                format!(
                    "dispatched setup completion projection absent: status effect={:?}; {}",
                    result.status.effect,
                    dispatch_diagnostic(f, old_workflow),
                )
            })?
            .receipt
            .is_allowed());
        reservation
    };
    let expired_seconds = expiry_seconds + 1;
    let _clock = scope_synchronous_fixture_clock(expired_seconds);
    let now = expired_seconds * 1_000;
    let dispatched = f.f.record(old_workflow)?;
    assert!(dispatched.captured && dispatched.native_link.is_some());
    assert_eq!(external_count(&f.f.path)?, 1);
    let inspector = f.f.kernel.authenticate_recovery_actor(
        f.f.runtime.scope(),
        &f.f.control,
        RecoveryPermission::Inspect,
    )?;
    assert!(matches!(
        f.f.authority.admission_operation_store().setup_preparation(
            &inspector,
            &f.f.authority.mutation_fence(),
            now,
        ),
        Err(NativeSetupPreparationError::Expired)
    ));
    let retained = chio_core_types::canonical_json_bytes(&dispatched)?;
    let allocation = retained_allocation_version(f, old_workflow)?;
    let calls = f.f.process.process("root")?.tree_calls;
    // The dispatched effect still owns its original, so a second self-test on
    // that same original is refused and changes nothing.
    let same_original: ToolCallRequest =
        chio_core_types::recovery::decode_contract(dispatched.creation_seed.as_str().as_bytes())?;
    assert!(
        pin_setup_replacement(f, &same_original, "duplicate-dispatched-setup", now)?.is_err(),
        "a dispatched original must not receive a second self-test"
    );
    assert_eq!(
        chio_core_types::canonical_json_bytes(&f.f.record(old_workflow)?)?,
        retained
    );
    let replacement =
        pin_setup_replacement(f, replacement_original, "dispatched-setup-replacement", now)?
            .map_err(|error| format!("replace dispatched unprobed setup selection: {error}"))?;
    assert_ne!(&replacement, old_workflow);
    assert_eq!(
        chio_core_types::canonical_json_bytes(&f.f.record(old_workflow)?)?,
        retained,
        "replacement must not close or migrate the dispatched workflow"
    );
    assert_eq!(retained_allocation_version(f, old_workflow)?, allocation);
    let journal = rusqlite::Connection::open_with_flags(
        f.f.path.join("process.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    let closed_as_unused: bool = journal.query_row(
        "SELECT EXISTS(SELECT 1 FROM process_unused_recovery_reservations
         WHERE process_id=?1 AND operation_key=?2 AND continuation_id=?3)",
        rusqlite::params![
            reservation.process_id,
            reservation.operation_key,
            reservation.continuation_id.as_str()
        ],
        |row| row.get(0),
    )?;
    assert!(
        !closed_as_unused,
        "a dispatched reservation is never unused custody"
    );
    let current = f.f.record(&replacement)?;
    assert_eq!(current.control, WorkflowControlV1::Active);
    assert_ne!(current.origin, dispatched.origin);
    assert!(current.action.is_none() && current.process_reservation.is_none());
    assert_eq!(external_count(&f.f.path)?, 1);
    assert_eq!(f.f.process.process("root")?.tree_calls, calls);
    Ok(())
}
