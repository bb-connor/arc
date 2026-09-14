use super::*;

#[test]
fn exact_claim_retry_release_and_successor_preserve_ownership() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, false)?;
    let authority = activate(&fixture, &source)?;
    let (initial, old_lease, credential) = setup(
        &fixture,
        &authority,
        "dpop-owner",
        "private-nonce",
        DpopReplayClaimPhase::Dispatch,
    )?;
    let intent = candidate(
        &initial,
        "first",
        credential.clone(),
        DpopReplayClaimPhase::Dispatch,
    )?;
    let (operation, reference) =
        fixture
            .store
            .claim_dpop_replay(&initial, &old_lease, &intent, now_ms())?;
    assert_eq!(operation.version(), initial.version() + 1);
    assert!(fixture
        .store
        .claim_dpop_replay(&operation, &old_lease, &intent, now_ms())
        .is_err());
    let lease = renew(&fixture, &operation, &old_lease, now_ms())?;
    let count = global_count(&fixture);
    assert_eq!(
        fixture
            .store
            .claim_dpop_replay(&operation, &lease, &intent, now_ms())?,
        (operation.clone(), reference.clone())
    );
    assert_eq!(global_count(&fixture), count);
    fixture
        .store
        .release_dpop_replay(&operation, &lease, &reference, now_ms())?;
    assert!(fixture
        .store
        .claim_dpop_replay(&operation, &lease, &intent, now_ms())
        .is_err());
    let next = candidate(
        &operation,
        "next",
        credential,
        DpopReplayClaimPhase::Dispatch,
    )?;
    let (operation, successor) =
        fixture
            .store
            .claim_dpop_replay(&operation, &lease, &next, now_ms())?;
    assert_ne!(reference, successor);
    let count = global_count(&fixture);
    fixture
        .store
        .release_dpop_replay(&operation, &lease, &reference, now_ms())?;
    assert_eq!(global_count(&fixture), count);
    let (_, history) = fixture
        .store
        .load_dpop_replay_claim_history(
            operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("history absent")?;
    assert_eq!(history.len(), 2);
    assert_eq!(
        history[0].disposition,
        DpopReplayClaimDisposition::ReleasedBeforeDispatch
    );
    assert_eq!(
        history[1].disposition,
        DpopReplayClaimDisposition::ReservedBeforeDispatch
    );
    assert!(!format!("{history:?}").contains("private-nonce"));
    assert_eq!(counts(&fixture), [3, 3, 1]);
    verify_admission_operation_invariants(&*fixture.store.connection()?)?;
    Ok(())
}

#[test]
fn substituted_invocation_generation_grant_or_phase_cannot_claim() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let authority = activate(&fixture, &source)?;
    let (operation, lease, credential) = setup(
        &fixture,
        &authority,
        "dpop-binding",
        "nonce",
        DpopReplayClaimPhase::Dispatch,
    )?;
    let intent = candidate(
        &operation,
        "claim",
        credential,
        DpopReplayClaimPhase::Dispatch,
    )?;
    for change in 0..5 {
        let mut value = serde_json::to_value(&intent)?;
        match change {
            0 => value["credential"]["invocationDigest"] = "b".repeat(64).into(),
            1 => value["credential"]["authority"]["expectation_id"] = "b".repeat(64).into(),
            2 => value["grantIndex"] = 1.into(),
            3 => value["phase"] = "nonce_preflight".into(),
            4 => value["requestBindingHash"] = "b".repeat(64).into(),
            _ => unreachable!(),
        }
        let candidate = serde_json::from_value(value)?;
        let count = global_count(&fixture);
        assert!(
            fixture
                .store
                .claim_dpop_replay(&operation, &lease, &candidate, now_ms())
                .is_err(),
            "{change}"
        );
        assert_eq!(global_count(&fixture), count);
    }
    fixture
        .store
        .claim_dpop_replay(&operation, &lease, &intent, now_ms())?;
    Ok(())
}

#[test]
fn expiry_and_release_cannot_cross_dispatch_commit() -> AnchoredTestResult {
    for released in [false, true] {
        let fixture = fixture();
        let source = Source::new(&fixture, true)?;
        let authority = activate(&fixture, &source)?;
        let (operation, lease, credential) = setup(
            &fixture,
            &authority,
            "dpop-dispatch",
            "nonce",
            DpopReplayClaimPhase::Dispatch,
        )?;
        let expires = credential.valid_through_unix_secs()? + 1;
        let intent = candidate(
            &operation,
            "claim",
            credential,
            DpopReplayClaimPhase::Dispatch,
        )?;
        let (operation, reference) =
            fixture
                .store
                .claim_dpop_replay(&operation, &lease, &intent, now_ms())?;
        let (operation, lease) = capture_pending(&fixture, operation, &lease)?;
        if released {
            fixture
                .store
                .release_dpop_replay(&operation, &lease, &reference, now_ms())?;
        }
        let _clock =
            chio_kernel::scope_fixed_runtime_for_current_thread(expires, std::iter::empty());
        let now = expires * 1000;
        let lease = renew(&fixture, &operation, &lease, now)?;
        let count = global_count(&fixture);
        let error = fixture
            .store
            .compare_and_swap(
                &command(
                    &operation,
                    lease,
                    vec![],
                    AdmissionOperationState::DispatchCommitted,
                    None,
                ),
                now,
            )
            .expect_err("DPoP custody must deny dispatch");
        assert!(
            error
                .to_string()
                .contains(if released { "ownership" } else { "fresh" }),
            "{error}"
        );
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
fn committed_claim_survives_source_loss_expiry_and_restart_without_release() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let authority = activate(&fixture, &source)?;
    let (operation, lease, credential) = setup(
        &fixture,
        &authority,
        "dpop-committed",
        "spent-nonce",
        DpopReplayClaimPhase::Dispatch,
    )?;
    let expires = credential.valid_through_unix_secs()? + 1;
    let intent = candidate(
        &operation,
        "claim",
        credential,
        DpopReplayClaimPhase::Dispatch,
    )?;
    let (operation, reference) =
        fixture
            .store
            .claim_dpop_replay(&operation, &lease, &intent, now_ms())?;
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
        authority: owner,
        store,
        fence: stale,
    } = fixture;
    drop(store);
    drop(owner);
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(expires, std::iter::empty());
    let owner = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let fixture = Fixture {
        store: owner.admission_operation_store(),
        fence: owner.mutation_fence(),
        authority: owner,
        _temp,
        database,
        lock_root,
    };
    let now = expires * 1000;
    assert!(fixture
        .store
        .load_dpop_replay_claim_history(committed.binding().operation_id(), &stale, now)
        .is_err());
    let (restored, history) = fixture
        .store
        .load_dpop_replay_claim_history(committed.binding().operation_id(), &fixture.fence, now)?
        .ok_or("history absent")?;
    assert_eq!(restored, committed);
    assert_eq!(
        history[0].disposition,
        DpopReplayClaimDisposition::RetainedAfterDispatchCommit
    );
    let lease = claim(&fixture, &restored, "new-owner", now);
    assert!(fixture
        .store
        .release_dpop_replay(&restored, &lease, &reference, now)
        .is_err());
    let (other, lease, fresh) = setup(
        &fixture,
        &authority,
        "replay",
        "spent-nonce",
        DpopReplayClaimPhase::Dispatch,
    )?;
    let intent = candidate(&other, "another", fresh, DpopReplayClaimPhase::Dispatch)?;
    let error = fixture
        .store
        .claim_dpop_replay(&other, &lease, &intent, now)
        .expect_err("spent nonce survives expiry");
    assert!(error.to_string().contains("historically spent"), "{error}");
    Ok(())
}

#[test]
fn expired_pre_dispatch_claim_can_be_released_from_recovered_exact_history() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let authority = activate(&fixture, &source)?;
    let (operation, lease, credential) = setup(
        &fixture,
        &authority,
        "dpop-cleanup",
        "nonce",
        DpopReplayClaimPhase::NoncePreflight,
    )?;
    let expires = credential.valid_through_unix_secs()? + 1;
    let intent = candidate(
        &operation,
        "preflight",
        credential,
        DpopReplayClaimPhase::NoncePreflight,
    )?;
    let (operation, reference) =
        fixture
            .store
            .claim_dpop_replay(&operation, &lease, &intent, now_ms())?;
    drop(source);
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(expires, std::iter::empty());
    let now = expires * 1000;
    let lease = renew(&fixture, &operation, &lease, now)?;
    let count = global_count(&fixture);
    fixture
        .store
        .release_dpop_replay(&operation, &lease, &reference, now)?;
    assert_eq!(global_count(&fixture), count + 1);
    let (_, history) = fixture
        .store
        .load_dpop_replay_claim_history(operation.binding().operation_id(), &fixture.fence, now)?
        .ok_or("history absent")?;
    assert_eq!(
        history[0].disposition,
        DpopReplayClaimDisposition::ReleasedBeforeDispatch
    );
    Ok(())
}
