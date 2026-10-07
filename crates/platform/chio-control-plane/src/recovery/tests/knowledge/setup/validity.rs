//! Initial setup validity ends before a fresh selected effect can be acquired.
use super::*;

struct ExtendedValiditySetup {
    fixture: KnowledgeFixture,
    _service: RecoverySetupService,
    prepared: NativeSetupPreparationV1,
}

async fn materialize_selected_setup(
    f: &KnowledgeFixture,
    create: &RecoveryCommandV1,
) -> TestResult<WorkflowId> {
    // Replay the independently retained creation directly. The general fixture
    // helper would repeat original denial lookup using its real-time clock.
    let created = Box::pin(f.f.runtime.execute_command(&f.f.control, create)).await?;
    let workflow = created.status.workflow_id;
    let record = f.f.record(&workflow)?;
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
    Box::pin(f.f.runtime.execute_command(&f.f.control, &select)).await?;
    let intent = f.f.runtime.approval_intent(&f.f.control, &workflow)?;
    let record = f.f.record(&workflow)?;
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
    Box::pin(f.f.runtime.execute_command(&f.f.control, &approve)).await?;
    Ok(workflow)
}

async fn extended_validity_setup() -> TestResult<ExtendedValiditySetup> {
    extended_validity_setup_with_capture_checkpoint(false).await
}

async fn extended_validity_setup_with_capture_checkpoint(
    checkpoint: bool,
) -> TestResult<ExtendedValiditySetup> {
    let directory = tempfile::tempdir()?;
    if checkpoint {
        std::fs::write(
            directory.path().join("setup-capture-clock-checkpoint"),
            "selected",
        )?;
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
        let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(
            late_seconds,
            std::iter::empty::<String>(),
        );
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
    })
}

#[tokio::test]
async fn setup_selected_command_before_initial_expiry_still_dispatches_once() -> TestResult {
    let state = Box::pin(extended_validity_setup()).await?;
    let f = &state.fixture;
    let valid_seconds = state.prepared.probe.expires_at_unix_ms.get() / 1_000 - 1;
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(
        valid_seconds,
        std::iter::empty::<String>(),
    );
    let calls = f.f.process.process("root")?.tree_calls;
    let result =
        f.f.runtime
            .execute_command(&f.f.control, &state.prepared.command)
            .await
            .map_err(|error| format!("setup validity phase=valid public Resume: {error}"))?;
    let receipt = result
        .original_response
        .ok_or("valid setup completion projection")?
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
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(
        expired_seconds,
        std::iter::empty::<String>(),
    );
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
    let state = Box::pin(extended_validity_setup_with_capture_checkpoint(true))
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
    let _entry_clock = chio_kernel::scope_fixed_runtime_for_current_thread(
        entry_seconds,
        std::iter::empty::<String>(),
    );
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
    let observation = std::fs::read_to_string(f.f.path.join("setup-capture-checkpoint-observed"))
        .map_err(|error| {
        format!(
            "setup capture phase=actual native checkpoint missing; public={:?}: {error}",
            result.as_ref().err()
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
    let _capture_clock = chio_kernel::scope_fixed_runtime_for_current_thread(
        inspect_seconds,
        std::iter::empty::<String>(),
    );
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
                "setup final capture phase=verified cutpoint missing; public={:?}; checkpoint={observation}: {error}",
                result.as_ref().err(),
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
