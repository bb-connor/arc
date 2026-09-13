//! Real qualified-store recovery through the kernel's trait-object port. Source
//! sealing uses the existing destination fixture, not a live runtime verifier.

use super::*;
use chio_kernel::admission_operation::runtime_participant::{
    RuntimeParticipantClaimHistoryV1, RuntimeParticipantClaimReferenceV1,
    RuntimeParticipantDisposition,
};
use chio_kernel::{ChioKernel, KernelConfig};

fn kernel(fixture: &Fixture) -> TestResult<ChioKernel> {
    let mut kernel = ChioKernel::new(KernelConfig {
        keypair: Keypair::generate(),
        ca_public_keys: vec![],
        max_delegation_depth: 5,
        policy_hash: sha256_hex(b"runtime-custody-recovery-test"),
        allow_sampling: false,
        allow_sampling_tool_use: false,
        allow_elicitation: false,
        max_stream_duration_secs: chio_kernel::DEFAULT_MAX_STREAM_DURATION_SECS,
        max_stream_total_bytes: chio_kernel::DEFAULT_MAX_STREAM_TOTAL_BYTES,
        require_web3_evidence: false,
        allow_ephemeral_receipt_log: true,
        allow_ephemeral_revocation_store: true,
        checkpoint_batch_size: chio_kernel::DEFAULT_CHECKPOINT_BATCH_SIZE,
        retention_config: None,
        memory_budget: chio_kernel::MemoryBudgetConfig::defaults(),
        deadlines: chio_kernel::HotPathDeadlineConfig::default(),
    });
    kernel.set_durable_admission_store(
        Arc::new(fixture.store.clone()),
        Arc::new(fixture.authority.tool_outcome_store()),
        fixture.fence.clone(),
    )?;
    kernel.set_budget_store_handle(Arc::new(fixture.authority.budget_store()));
    // Deliberately no hook, artifact lookup, tool server or legacy replay store.
    // Cleanup must work from the original retained ownership alone.
    Ok(kernel)
}

fn reopen(fixture: Fixture) -> TestResult<Fixture> {
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let store = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    Ok(Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        fence,
    })
}

fn prepared_nonce(fixture: &Fixture) -> TestResult<(AdmissionOperationV1, AdmissionRecoveryLease)> {
    let (operation, retained) = super::super::super::retained_request::original_with_requirements(
        &fixture.fence,
        "kernel-preflight-recovery",
        AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            execution_nonce: true,
            ..AdmissionParticipantRequirements::NONE
        },
    )?;
    let (operation, retained) =
        super::super::super::retained_request::authority_profile::prepare_with_profile(
            operation,
            retained,
            selected_profile(fixture)?,
        )?;
    fixture.store.begin_with_retained_tool_request(
        &operation,
        &retained,
        &fixture.fence,
        now_ms(),
    )?;
    let lease = claim(fixture, &operation, "preflight-owner", now_ms());
    Ok((operation, lease))
}

fn reserve(
    fixture: &Fixture,
    source: &RuntimeReplayMigrationRecordV1,
    operation: &AdmissionOperationV1,
    lease: &AdmissionRecoveryLease,
    episode: &str,
) -> TestResult<(AdmissionOperationV1, RuntimeParticipantClaimReferenceV1)> {
    let candidate = intent(
        operation,
        source,
        episode,
        &[
            (Kind::DestructiveLease, "destructive-resource"),
            (Kind::TreatyContinuation, "treaty-resource"),
            (Kind::SwarmContinuation, "swarm-resource"),
        ],
    )?;
    let candidate = if operation.state() == AdmissionOperationState::Prepared {
        let mut encoded = serde_json::to_value(candidate)?;
        encoded["phase"] = serde_json::json!("nonce_preflight");
        serde_json::from_value(encoded)?
    } else {
        candidate
    };
    let port: &dyn AdmissionOperationStore = &fixture.store;
    Ok(port.claim_runtime_participants(operation, lease, &candidate, now_ms())?)
}

fn history(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
) -> TestResult<Vec<RuntimeParticipantClaimHistoryV1>> {
    let port: &dyn AdmissionOperationStore = &fixture.store;
    Ok(port
        .load_runtime_participant_history(
            operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("runtime history missing")?
        .1)
}

#[test]
fn kernel_restart_releases_preflight_and_dispatch_claims_without_artifact_preparation() -> TestResult
{
    for preflight in [false, true] {
        let fixture = fixture();
        let source = imported(&fixture, false)?;
        let (operation, lease) = if preflight {
            prepared_nonce(&fixture)?
        } else {
            setup(&fixture, "kernel-dispatch-recovery")?
        };
        let (operation, first) = reserve(&fixture, &source, &operation, &lease, "first")?;
        let lease = renew(&fixture, &operation, &lease)?;
        let port: &dyn AdmissionOperationStore = &fixture.store;
        port.release_runtime_participants(&operation, &lease, &first, now_ms())?;
        let (operation, successor) = reserve(&fixture, &source, &operation, &lease, "successor")?;
        let before = history(&fixture, &operation)?;
        assert_eq!(before[0].reference, first);
        assert_eq!(before[1].reference, successor);

        let fixture = reopen(fixture)?;
        let kernel = kernel(&fixture)?;
        assert_eq!(kernel.reconcile_durable_admission_startup()?, 1);
        assert_eq!(kernel.reconcile_recoverable_admissions()?, 0);
        let current = fixture
            .store
            .load_by_operation_id(operation.binding().operation_id())?
            .ok_or("compensated operation missing")?;
        assert_eq!(
            current.state(),
            AdmissionOperationState::CompensatedBeforeDispatch
        );
        let after = history(&fixture, &current)?;
        let mut expected = before;
        expected[1].disposition = RuntimeParticipantDisposition::ReleasedBeforeDispatch;
        assert_eq!(after, expected);

        // Free resources can serve a different operation, but imported legacy
        // tombstones remain spent. Neither recovery nor owner rotation clears them.
        let (next, lease) = setup(&fixture, "after-kernel-recovery")?;
        let spent = intent(
            &next,
            &source,
            "historical",
            &[(Kind::DestructiveLease, "same-resource")],
        )?;
        assert!(fixture
            .store
            .claim_runtime_participants(&next, &lease, &spent, now_ms())
            .is_err());
        reserve(&fixture, &source, &next, &lease, "fresh")?;
    }
    Ok(())
}

#[test]
fn kernel_restart_retains_committed_runtime_claims_without_redispatch() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, true)?;
    let (operation, lease) = setup(&fixture, "kernel-committed-recovery")?;
    let (operation, _) = reserve(&fixture, &source, &operation, &lease, "committed")?;
    // The state fixture does not qualify executable budget settlement. This
    // regression proves that kernel unknown-outcome recovery never frees replay custody.
    let (operation, lease) = capture_pending(&fixture, operation, &lease)?;
    let operation = fixture
        .store
        .compare_and_swap(
            &command(
                &operation,
                lease,
                vec![],
                AdmissionOperationState::DispatchCommitted,
                None,
            ),
            now_ms(),
        )?
        .into_operation();
    let before = history(&fixture, &operation)?;
    let fixture = reopen(fixture)?;
    let kernel = kernel(&fixture)?;
    assert_eq!(kernel.reconcile_durable_admission_startup()?, 1);
    let current = fixture
        .store
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("unknown-outcome operation missing")?;
    assert_eq!(
        current.state(),
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    assert_eq!(history(&fixture, &current)?, before);
    assert_eq!(
        before[0].disposition,
        RuntimeParticipantDisposition::RetainedAfterDispatchCommit
    );
    let (next, lease) = setup(&fixture, "after-unknown-recovery")?;
    assert!(reserve(&fixture, &source, &next, &lease, "must-conflict").is_err());
    Ok(())
}

#[test]
fn kernel_recovery_release_and_terminal_cutpoints_preserve_retryable_custody() -> TestResult {
    for (table, released) in [
        ("runtime_replay_claim_releases", false),
        ("admission_operation_terminal_projections", true),
    ] {
        let fixture = fixture();
        let source = imported(&fixture, true)?;
        let (operation, lease) = setup(&fixture, "kernel-release-cutpoint")?;
        let (operation, reference) = reserve(&fixture, &source, &operation, &lease, "interrupted")?;
        let fixture = reopen(fixture)?;
        fixture.store.connection()?.execute_batch(&format!(
            "CREATE TEMP TRIGGER inject_kernel_runtime_recovery BEFORE INSERT ON {table}
             BEGIN SELECT RAISE(ABORT, 'injected kernel runtime recovery'); END"
        ))?;
        let recovery_kernel = kernel(&fixture)?;
        let error = recovery_kernel
            .reconcile_durable_admission_startup()
            .expect_err("recovery must reach the injected cutpoint");
        assert!(
            error
                .to_string()
                .contains("injected kernel runtime recovery"),
            "{table}: {error}"
        );
        assert_eq!(
            fixture
                .store
                .load_by_operation_id(operation.binding().operation_id())?,
            Some(operation.clone())
        );
        let retained = history(&fixture, &operation)?;
        assert_eq!(retained[0].reference, reference);
        assert_eq!(
            retained[0].disposition,
            if released {
                RuntimeParticipantDisposition::ReleasedBeforeDispatch
            } else {
                RuntimeParticipantDisposition::ReservedBeforeDispatch
            }
        );
        drop(recovery_kernel);

        // A new serving owner retries from physical history. A completed release
        // is acknowledged, not repeated, even if terminalization was interrupted.
        let fixture = reopen(fixture)?;
        let recovery_kernel = kernel(&fixture)?;
        assert_eq!(recovery_kernel.reconcile_durable_admission_startup()?, 1);
        let retained = history(&fixture, &operation)?;
        assert_eq!(retained[0].reference, reference);
        assert_eq!(
            retained[0].disposition,
            RuntimeParticipantDisposition::ReleasedBeforeDispatch
        );
        let releases: i64 = fixture.store.connection()?.query_row(
            "SELECT COUNT(*) FROM runtime_replay_claim_releases",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(releases, 1);
    }
    Ok(())
}
