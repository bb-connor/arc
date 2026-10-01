use super::*;
#[path = "claims/dispatch_snapshot.rs"]
mod dispatch_snapshot;
use chio_kernel::admission_operation::runtime_participant::{
    RuntimeParticipantClaimIntentInput, RuntimeParticipantClaimIntentV1, RuntimeParticipantPhase,
    RuntimeParticipantResourceV1,
};
use chio_kernel::admission_operation::RuntimeReplayParticipantKind as Kind;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
fn budget_selection_requires_the_live_runtime_grant_and_phase() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, true)?;
    let (operation, lease) = setup(&fixture, "budget-selection-binding")?;
    let candidate = intent(&operation, &source, "selected", &[])?;
    let (operation, reference) =
        fixture
            .store
            .claim_runtime_participants(&operation, &lease, &candidate, now_ms())?;
    let before = global_count(&fixture.store);
    {
        let connection = fixture.store.connection()?;
        crate::admission_operation_store::verify_runtime_budget_selection_tx(
            &connection,
            &operation,
            0,
            RuntimeParticipantPhase::Dispatch,
        )?;
        for (grant, phase) in [
            (1, RuntimeParticipantPhase::Dispatch),
            (0, RuntimeParticipantPhase::NoncePreflight),
        ] {
            assert!(
                crate::admission_operation_store::verify_runtime_budget_selection_tx(
                    &connection,
                    &operation,
                    grant,
                    phase
                )
                .is_err()
            );
        }
    }
    assert_eq!(global_count(&fixture.store), before);
    let lease = renew(&fixture, &operation, &lease)?;
    fixture
        .store
        .release_runtime_participants(&operation, &lease, &reference, now_ms())?;
    let connection = fixture.store.connection()?;
    assert!(
        crate::admission_operation_store::verify_runtime_budget_selection_tx(
            &connection,
            &operation,
            0,
            RuntimeParticipantPhase::Dispatch
        )
        .is_err()
    );
    Ok(())
}

#[path = "claims/faults.rs"]
mod faults;
#[path = "claims/kernel_recovery.rs"]
mod kernel_recovery;
#[path = "claims/migration.rs"]
mod migration;
#[path = "claims/recovery.rs"]
mod recovery;

fn setup(
    fixture: &Fixture,
    name: &str,
) -> TestResult<(AdmissionOperationV1, AdmissionRecoveryLease)> {
    setup_profile(fixture, name, true)
}

fn setup_profile(
    fixture: &Fixture,
    name: &str,
    retain_profile: bool,
) -> TestResult<(AdmissionOperationV1, AdmissionRecoveryLease)> {
    let (operation, retained) = super::super::retained_request::original_with_requirements(
        &fixture.fence,
        name,
        AdmissionParticipantRequirements {
            broker_attempt: true,
            budget_capture: true,
            ..AdmissionParticipantRequirements::NONE
        },
    )?;
    let profile = selected_profile(fixture)?;
    let (operation, retained) = if retain_profile {
        super::super::retained_request::authority_profile::prepare_with_profile(
            operation, retained, profile,
        )?
    } else {
        (operation, retained)
    };
    fixture.store.begin_with_retained_tool_request(
        &operation,
        &retained,
        &fixture.fence,
        now_ms(),
    )?;
    let lease = claim(fixture, &operation, name, now_ms());
    let operation = fixture
        .store
        .compare_and_swap(
            &command(
                &operation,
                lease.clone(),
                vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &operation, name,
                ))],
                AdmissionOperationState::BrokerAttemptRegistered,
                None,
            ),
            now_ms(),
        )?
        .into_operation();
    let lease = renew(fixture, &operation, &lease)?;
    Ok((operation, lease))
}

fn renew(
    fixture: &Fixture,
    operation: &AdmissionOperationV1,
    lease: &AdmissionRecoveryLease,
) -> TestResult<AdmissionRecoveryLease> {
    let now = now_ms();
    Ok(fixture.store.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        lease.untrusted_claim().claimant_id(),
        now,
        now + 10000,
        &fixture.fence,
    )?)
}

fn selected_profile(
    fixture: &Fixture,
) -> TestResult<chio_kernel::admission_operation::AdmissionAuthorityProfileV1> {
    // Select fixture configuration before begin, never while claiming or recovering.
    let selected = load(fixture)?;
    super::super::retained_request::authority_profile::selection(
        selected.map(|selected| chio_kernel::admission_operation::runtime_participant::RuntimeParticipantAuthorityBindingV1::new(
            identifier("runtime", RUNTIME_ID), selected.expectation_id().clone(),
        )), None, None,
    )
}

#[test]
fn runtime_claim_cannot_upgrade_absent_or_historical_authority_profile() -> TestResult {
    for retain_profile in [false, true] {
        let fixture = fixture();
        // The operation predates source selection. Importing later cannot
        // provide the authority its immutable original request never selected.
        let (operation, lease) = setup_profile(&fixture, "no-original-runtime", retain_profile)?;
        let source = imported(&fixture, true)?;
        let (_, original) = fixture
            .store
            .load_retained_tool_request(
                operation.binding().operation_id(),
                &fixture.fence,
                now_ms(),
            )?
            .ok_or("missing original")?;
        assert_eq!(original.authority_profile().is_some(), retain_profile);
        assert!(original
            .authority_profile()
            .and_then(|profile| profile.runtime())
            .is_none());
        let before = global_count(&fixture.store);
        let candidate = intent(&operation, &source, "forbidden-upgrade", &[])?;
        assert!(matches!(
            fixture.store.claim_runtime_participants(&operation, &lease, &candidate, now_ms()),
            Err(AdmissionOperationStoreError::Invariant(message)) if message.contains("original authority profile")
        ));
        assert_eq!(
            fixture
                .store
                .load_by_operation_id(operation.binding().operation_id())?,
            Some(operation)
        );
        assert_eq!(global_count(&fixture.store), before);
        let connection = fixture.store.connection()?;
        let claims: i64 = connection.query_row(
            "SELECT COUNT(*) FROM runtime_replay_claim_episodes",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(claims, 0);
    }
    Ok(())
}

fn intent(
    operation: &AdmissionOperationV1,
    source: &RuntimeReplayMigrationRecordV1,
    episode: &str,
    resources: &[(Kind, &str)],
) -> TestResult<RuntimeParticipantClaimIntentV1> {
    Ok(RuntimeParticipantClaimIntentV1::new(
        RuntimeParticipantClaimIntentInput {
            episode_id: identifier("episode", episode),
            runtime_authority_id: identifier("runtime", RUNTIME_ID),
            expectation_id: source.expectation_id().clone(),
            request_binding_hash: operation.binding().request_binding_hash().clone(),
            grant_index: 0,
            phase: RuntimeParticipantPhase::Dispatch,
            plan_digest: digest("plan", 'd'),
            resources: resources
                .iter()
                .map(|(kind, resource)| {
                    RuntimeParticipantResourceV1::new(
                        *kind,
                        identifier("resource", resource),
                        digest("artifact", 'c'),
                    )
                })
                .collect(),
        },
    )?)
}

fn imported(fixture: &Fixture, empty: bool) -> TestResult<RuntimeReplayMigrationRecordV1> {
    let source = Source::new(fixture, empty);
    let pinned = pin(fixture, &source)?;
    Ok(import(fixture, &source, &pinned)?)
}

fn capture_pending(
    fixture: &Fixture,
    mut operation: AdmissionOperationV1,
    lease: &AdmissionRecoveryLease,
) -> TestResult<(AdmissionOperationV1, AdmissionRecoveryLease)> {
    // This is a replay-custody store test, not budget settlement qualification.
    // Use the same operation-state fixture as the existing terminal tests.
    for (state, attachments) in [
        (
            AdmissionOperationState::BudgetAuthorized,
            vec![AdmissionAttachment::BudgetHoldId(identifier(
                "hold",
                "runtime-claim-test-hold",
            ))],
        ),
        (AdmissionOperationState::ReadyToDispatch, vec![]),
        (AdmissionOperationState::CapturePending, vec![]),
    ] {
        let current = renew(fixture, &operation, lease)?;
        operation = fixture
            .store
            .compare_and_swap(
                &command(&operation, current, attachments, state, None),
                now_ms(),
            )?
            .into_operation();
    }
    let lease = renew(fixture, &operation, lease)?;
    Ok((operation, lease))
}

#[test]
fn claim_retry_release_and_successor_have_exact_episode_ownership() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, true)?;
    let (operation, lease) = setup(&fixture, "claim-lifecycle")?;
    let first = intent(
        &operation,
        &source,
        "first",
        &[(Kind::DestructiveLease, "resource")],
    )?;
    let (operation, first_ref) =
        fixture
            .store
            .claim_runtime_participants(&operation, &lease, &first, now_ms())?;
    let lease = renew(&fixture, &operation, &lease)?;
    let count = global_count(&fixture.store);
    assert_eq!(
        fixture
            .store
            .claim_runtime_participants(&operation, &lease, &first, now_ms())?,
        (operation.clone(), first_ref.clone())
    );
    assert_eq!(global_count(&fixture.store), count);
    fixture
        .store
        .release_runtime_participants(&operation, &lease, &first_ref, now_ms())?;
    assert!(fixture
        .store
        .claim_runtime_participants(&operation, &lease, &first, now_ms())
        .is_err());
    let next = intent(
        &operation,
        &source,
        "next",
        &[(Kind::DestructiveLease, "resource")],
    )?;
    let (operation, next_ref) =
        fixture
            .store
            .claim_runtime_participants(&operation, &lease, &next, now_ms())?;
    assert_ne!(first_ref, next_ref);
    let count = global_count(&fixture.store);
    fixture
        .store
        .release_runtime_participants(&operation, &lease, &first_ref, now_ms())?;
    assert_eq!(
        global_count(&fixture.store),
        count,
        "old release may only acknowledge history"
    );
    let third = intent(&operation, &source, "third", &[])?;
    assert!(fixture
        .store
        .claim_runtime_participants(&operation, &lease, &third, now_ms())
        .is_err());
    fixture
        .store
        .release_runtime_participants(&operation, &lease, &next_ref, now_ms())?;
    let connection = fixture.store.connection()?;
    verify_admission_operation_invariants(&connection)?;
    Ok(())
}

#[test]
fn multi_resource_conflict_is_atomic_and_legacy_tombstones_remain_spent() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, false)?;
    let (first, lease) = setup(&fixture, "first-owner")?;
    let claim = intent(
        &first,
        &source,
        "owner",
        &[(Kind::SwarmContinuation, "swarm")],
    )?;
    fixture
        .store
        .claim_runtime_participants(&first, &lease, &claim, now_ms())?;
    let (second, lease) = setup(&fixture, "second-owner")?;
    for resources in [
        vec![
            (Kind::DestructiveLease, "free"),
            (Kind::TreatyContinuation, "free"),
            (Kind::SwarmContinuation, "swarm"),
        ],
        vec![(Kind::DestructiveLease, "same-resource")],
        vec![(Kind::TreatyContinuation, "same-resource")],
        vec![(Kind::SwarmContinuation, "same-resource")],
    ] {
        let candidate = intent(&second, &source, "conflict", &resources)?;
        let count = global_count(&fixture.store);
        assert!(fixture
            .store
            .claim_runtime_participants(&second, &lease, &candidate, now_ms())
            .is_err());
        assert_eq!(global_count(&fixture.store), count);
        assert_eq!(
            fixture
                .store
                .load_by_operation_id(second.binding().operation_id())?,
            Some(second.clone())
        );
    }
    let free = intent(
        &second,
        &source,
        "free",
        &[
            (Kind::DestructiveLease, "free"),
            (Kind::TreatyContinuation, "free"),
        ],
    )?;
    fixture
        .store
        .claim_runtime_participants(&second, &lease, &free, now_ms())?;
    Ok(())
}

#[test]
fn dispatch_committed_claim_cannot_be_released_after_recovery() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, true)?;
    let (operation, lease) = setup(&fixture, "committed")?;
    let candidate = intent(
        &operation,
        &source,
        "dispatch",
        &[(Kind::DestructiveLease, "spent")],
    )?;
    let (operation, reference) =
        fixture
            .store
            .claim_runtime_participants(&operation, &lease, &candidate, now_ms())?;
    let (operation, lease) = capture_pending(&fixture, operation, &lease)?;
    let operation = fixture
        .store
        .compare_and_swap(
            &command(
                &operation,
                lease.clone(),
                vec![],
                AdmissionOperationState::DispatchCommitted,
                None,
            ),
            now_ms(),
        )?
        .into_operation();
    let lease = renew(&fixture, &operation, &lease)?;
    assert!(fixture
        .store
        .release_runtime_participants(&operation, &lease, &reference, now_ms())
        .is_err());
    let later = lease.expires_at_unix_ms() + 1;
    let recovered = fixture.store.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &identifier("claimant", "recovered"),
        later,
        later + 10000,
        &fixture.fence,
    )?;
    assert!(fixture
        .store
        .release_runtime_participants(&operation, &recovered, &reference, later)
        .is_err());
    assert!(operation.dispatch_commit().is_some());
    Ok(())
}

#[test]
fn release_before_dispatch_blocks_generic_dispatch_commit() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, true)?;
    let (operation, lease) = setup(&fixture, "released")?;
    let candidate = intent(&operation, &source, "released", &[])?;
    let (operation, reference) =
        fixture
            .store
            .claim_runtime_participants(&operation, &lease, &candidate, now_ms())?;
    let lease = renew(&fixture, &operation, &lease)?;
    fixture
        .store
        .release_runtime_participants(&operation, &lease, &reference, now_ms())?;
    let (ready, lease) = capture_pending(&fixture, operation, &lease)?;
    assert!(fixture
        .store
        .compare_and_swap(
            &command(
                &ready,
                lease,
                vec![],
                AdmissionOperationState::DispatchCommitted,
                None
            ),
            now_ms()
        )
        .is_err());
    Ok(())
}

#[test]
fn missing_or_altered_claim_history_rejects_reads_and_replay() -> TestResult {
    for damage in [
        "DROP TRIGGER runtime_replay_claim_episodes_no_delete; DELETE FROM runtime_replay_claim_episodes",
        "DROP TRIGGER runtime_replay_claim_resources_no_delete; DELETE FROM runtime_replay_claim_resources",
        "DROP TRIGGER runtime_replay_claim_resources_no_update; UPDATE runtime_replay_claim_resources SET resource_id = 'forged'",
        "PRAGMA ignore_check_constraints = ON; DROP TRIGGER runtime_replay_claim_episodes_no_update; UPDATE runtime_replay_claim_episodes SET claim_json = zeroblob(16385)",
    ] {
        let fixture = fixture();
        let source = imported(&fixture, true)?;
        let (operation, lease) = setup(&fixture, "damaged")?;
        let candidate = intent(&operation, &source, "damaged", &[(Kind::DestructiveLease, "resource")])?;
        let (operation, _) = fixture.store.claim_runtime_participants(&operation, &lease, &candidate, now_ms())?;
        let connection = Connection::open(&fixture.database)?;
        connection.execute_batch("PRAGMA foreign_keys = OFF")?;
        connection.execute_batch(damage)?;
        assert!(fixture.store.load_by_operation_id(operation.binding().operation_id()).is_err(), "{damage}");
        assert!(fixture.store.claim_runtime_participants(&operation, &lease, &candidate, now_ms()).is_err(), "{damage}");
    }
    Ok(())
}
