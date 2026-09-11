use super::*;
#[path = "lifecycle/dispatch_snapshot.rs"]
mod dispatch_snapshot;

#[test]
fn expiry_reclaims_live_capacity_without_deleting_legacy_evidence() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let expires = now_ms() / 1000 + 60;
    for index in 0..8 {
        Connection::open(&source.path)?.execute("INSERT INTO chio_governed_approval_replay_entries VALUES ('historical', ?1, 'intent', ?2, NULL)",
            params![format!("historical-{index}"), i64::try_from(expires)?])?;
    }
    let binding = activate(&fixture, &source)?;
    let (operation, lease, credential) = setup(&fixture, "capacity-new")?;
    let intent = candidate(&operation, &binding, "claim", credential)?;
    let count = global_count(&fixture);
    let error = fixture
        .store
        .claim_governed_approval(&operation, &lease, &intent, now_ms())
        .expect_err("live capacity must deny");
    assert!(error.to_string().contains("live capacity"), "{error}");
    assert_eq!(global_count(&fixture), count);
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(expires, std::iter::empty());
    let now = expires * 1000;
    let lease = renew(&fixture, &operation, &lease, now)?;
    fixture
        .store
        .claim_governed_approval(&operation, &lease, &intent, now)?;
    assert_eq!(
        fixture.store.connection()?.query_row(
            "SELECT COUNT(*) FROM governed_approval_replay_legacy_tombstones",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        8
    );
    Ok(())
}

fn capture_pending(
    fixture: &Fixture,
    mut operation: AdmissionOperationV1,
    lease: &AdmissionRecoveryLease,
) -> AnchoredTestResult<(AdmissionOperationV1, AdmissionRecoveryLease)> {
    // This state-machine fixture proves replay custody, not executable budget settlement.
    for (state, attachments) in [
        (
            AdmissionOperationState::BudgetAuthorized,
            vec![AdmissionAttachment::BudgetHoldId(identifier(
                "hold",
                "approval-test-hold",
            ))],
        ),
        (AdmissionOperationState::ReadyToDispatch, vec![]),
        (AdmissionOperationState::CapturePending, vec![]),
    ] {
        let current = renew(fixture, &operation, lease, now_ms())?;
        operation = fixture
            .store
            .compare_and_swap(
                &command(&operation, current, attachments, state, None),
                now_ms(),
            )?
            .into_operation();
    }
    let lease = renew(fixture, &operation, lease, now_ms())?;
    Ok((operation, lease))
}

#[test]
fn expired_or_released_claim_cannot_cross_dispatch_commit() -> AnchoredTestResult {
    for released in [false, true] {
        let fixture = fixture();
        let source = Source::new(&fixture, true)?;
        let binding = activate(&fixture, &source)?;
        let (operation, lease, mut credential) = setup(&fixture, "dispatch-guard")?;
        let expires = now_ms() / 1000 + 60;
        credential.expires_at_unix_secs = expires;
        let intent = candidate(&operation, &binding, "dispatch", credential)?;
        let (operation, reference) =
            fixture
                .store
                .claim_governed_approval(&operation, &lease, &intent, now_ms())?;
        let lease = renew(&fixture, &operation, &lease, now_ms())?;
        let (operation, lease) = capture_pending(&fixture, operation, &lease)?;
        if released {
            fixture
                .store
                .release_governed_approval(&operation, &lease, &reference, now_ms())?;
        }
        let _clock =
            chio_kernel::scope_fixed_runtime_for_current_thread(expires, std::iter::empty());
        let now = expires * 1000;
        let lease = renew(&fixture, &operation, &lease, now)?;
        let count = global_count(&fixture);
        assert!(fixture
            .store
            .compare_and_swap(
                &command(
                    &operation,
                    lease,
                    vec![],
                    AdmissionOperationState::DispatchCommitted,
                    None
                ),
                now
            )
            .is_err());
        assert_eq!(global_count(&fixture), count);
        assert_eq!(
            fixture
                .store
                .load_by_operation_id(operation.binding().operation_id())?,
            Some(operation)
        );
    }
    Ok(())
}

#[test]
fn committed_approval_survives_expiry_and_restart_without_release_authority() -> AnchoredTestResult
{
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let binding = activate(&fixture, &source)?;
    let (operation, lease, mut credential) = setup(&fixture, "committed-approval")?;
    let expires = now_ms() / 1000 + 60;
    credential.expires_at_unix_secs = expires;
    let intent = candidate(&operation, &binding, "dispatch", credential)?;
    let (operation, reference) =
        fixture
            .store
            .claim_governed_approval(&operation, &lease, &intent, now_ms())?;
    let (operation, lease) = capture_pending(&fixture, operation, &lease)?;
    let committed = fixture
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
    drop(source);
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        fence,
    } = fixture;
    drop(store);
    drop(authority);
    let _clock =
        chio_kernel::scope_fixed_runtime_for_current_thread(expires + 1, std::iter::empty());
    let now = (expires + 1) * 1000;
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let store = authority.admission_operation_store();
    assert!(store
        .load_governed_approval_claim_history(committed.binding().operation_id(), &fence, now)
        .is_err());
    let fence = authority.mutation_fence();
    let (restored, history) = store
        .load_governed_approval_claim_history(committed.binding().operation_id(), &fence, now)?
        .ok_or("history missing")?;
    assert_eq!(restored, committed);
    assert_eq!(history[0].reference, reference);
    assert_eq!(
        history[0].disposition,
        GovernedApprovalClaimDisposition::RetainedAfterDispatchCommit
    );
    let lease = store.claim_recovery(
        committed.binding().operation_id(),
        committed.version(),
        &identifier("worker", "recovered"),
        now,
        now + 10000,
        &fence,
    )?;
    assert!(store
        .release_governed_approval(&committed, &lease, &reference, now)
        .is_err());
    let mut connection = store.connection()?;
    let tx = connection.transaction()?;
    crate::admission_operation_store::verify_approval_budget_selection_tx(
        &tx,
        &committed,
        0,
        GovernedApprovalClaimPhase::Dispatch,
    )?;
    Ok(())
}

#[test]
fn activation_waits_for_actual_authority_clock_and_never_uses_caller_skew() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let high = now_ms() / 1000 + 120;
    Connection::open(&source.path)?.execute("UPDATE chio_governed_approval_replay_clock SET wall_clock_high_water = ?1, pruned_through = ?1", [i64::try_from(high)?])?;
    let imported = import(&fixture, &source, &pin(&fixture, &source)?)?;
    let binding = GovernedApprovalAuthorityBindingV1::new(
        identifier("authority", AUTHORITY_ID),
        imported.expectation_id().clone(),
    );
    let count = global_count(&fixture);
    assert!(fixture
        .store
        .activate_governed_approval_replay_source(&binding, &source, &fixture.fence, high * 1000)
        .is_err());
    assert_eq!(global_count(&fixture), count);
    assert!(load(&fixture)?
        .ok_or("history missing")?
        .imported_inactive());
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(high, std::iter::empty());
    let active = fixture.store.activate_governed_approval_replay_source(
        &binding,
        &source,
        &fixture.fence,
        high * 1000,
    )?;
    assert!(active.is_active());
    assert_eq!(
        fixture.store.activate_governed_approval_replay_source(
            &binding,
            &source,
            &fixture.fence,
            high * 1000
        )?,
        active
    );
    assert_eq!(global_count(&fixture), count + 1);
    Ok(())
}

#[test]
fn expired_scoped_and_wildcard_legacy_markers_never_become_operation_owners() -> AnchoredTestResult
{
    for wildcard in [false, true] {
        let fixture = fixture();
        let source = Source::new(&fixture, true)?;
        let (operation, lease, credential) = setup(&fixture, "historical-marker")?;
        let subject = if wildcard {
            LEGACY_UNSCOPED_GOVERNED_APPROVAL_SUBJECT
        } else {
            credential.subject_id.as_str()
        };
        Connection::open(&source.path)?.execute(
            "INSERT INTO chio_governed_approval_replay_entries VALUES (?1, ?2, ?3, 1, ?4)",
            params![
                subject,
                credential.request_id.as_str(),
                credential.intent_hash.as_str(),
                lease.coordinator_lease_id().as_str()
            ],
        )?;
        let binding = activate(&fixture, &source)?;
        let intent = candidate(
            &operation,
            &binding,
            lease.coordinator_lease_id().as_str(),
            credential,
        )?;
        let count = global_count(&fixture);
        assert!(fixture
            .store
            .claim_governed_approval(&operation, &lease, &intent, now_ms())
            .is_err());
        assert_eq!(global_count(&fixture), count);
    }
    Ok(())
}
