use super::*;

#[test]
fn lost_claim_acknowledgement_recovers_the_exact_new_version_without_reacquisition(
) -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let authority = activate(&fixture, &source)?;
    let (initial, lease, credential) = setup(
        &fixture,
        &authority,
        "lost-claim-ack",
        "nonce",
        DpopReplayClaimPhase::Dispatch,
    )?;
    let intent = candidate(
        &initial,
        "claim",
        credential,
        DpopReplayClaimPhase::Dispatch,
    )?;
    let _ = fixture
        .store
        .claim_dpop_replay(&initial, &lease, &intent, now_ms())?;
    let count = global_count(&fixture);
    assert!(fixture
        .store
        .claim_dpop_replay(&initial, &lease, &intent, now_ms())
        .is_err());
    let (current, history) = fixture
        .store
        .load_dpop_replay_claim_history(initial.binding().operation_id(), &fixture.fence, now_ms())?
        .ok_or("history missing")?;
    assert_eq!(current.version(), initial.version() + 1);
    assert_eq!(history.len(), 1);
    assert_eq!(global_count(&fixture), count);
    let lease = renew(&fixture, &current, &lease, now_ms())?;
    fixture
        .store
        .release_dpop_replay(&current, &lease, &history[0].reference, now_ms())?;
    Ok(())
}

#[test]
fn claim_history_is_immutable_even_without_recursive_triggers() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let authority = activate(&fixture, &source)?;
    let (operation, lease, credential) = setup(
        &fixture,
        &authority,
        "immutable-claim",
        "nonce",
        DpopReplayClaimPhase::Dispatch,
    )?;
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
    let lease = renew(&fixture, &operation, &lease, now_ms())?;
    fixture
        .store
        .release_dpop_replay(&operation, &lease, &reference, now_ms())?;
    let connection = fixture.store.connection()?;
    connection.execute_batch("PRAGMA recursive_triggers = OFF")?;
    for table in [
        "dpop_replay_claim_episodes",
        "dpop_replay_claim_resources",
        "dpop_replay_claim_releases",
    ] {
        assert_eq!(
            connection.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                .get::<_, i64>(0))?,
            1
        );
        for sql in [
            format!("INSERT OR REPLACE INTO {table} SELECT * FROM {table}"),
            format!("UPDATE {table} SET episode_id = episode_id"),
            format!("DELETE FROM {table}"),
        ] {
            assert!(connection.execute(&sql, []).is_err(), "{sql}");
        }
    }
    verify_admission_operation_invariants(&connection)?;
    Ok(())
}

#[test]
fn claim_cutpoints_roll_back_the_operation_history_and_global_commit() -> AnchoredTestResult {
    for (table, predicate) in [
        (
            "admission_operation_commits",
            "WHEN NEW.mutation_kind = 'dpop_replay_claim'",
        ),
        (
            "authority_global_commits",
            "WHEN NEW.mutation_kind = 'dpop_replay_claim'",
        ),
        ("dpop_replay_claim_episodes", ""),
        ("dpop_replay_claim_resources", ""),
    ] {
        let fixture = fixture();
        let source = Source::new(&fixture, true)?;
        let authority = activate(&fixture, &source)?;
        let (operation, lease, credential) = setup(
            &fixture,
            &authority,
            table,
            "nonce",
            DpopReplayClaimPhase::Dispatch,
        )?;
        let intent = candidate(
            &operation,
            "claim",
            credential,
            DpopReplayClaimPhase::Dispatch,
        )?;
        let count = global_count(&fixture);
        fixture.store.connection()?.execute_batch(&format!("CREATE TEMP TRIGGER dpop_cut BEFORE INSERT ON main.{table} {predicate} BEGIN SELECT RAISE(ABORT, 'injected dpop claim failure'); END"))?;
        let error = fixture
            .store
            .claim_dpop_replay(&operation, &lease, &intent, now_ms())
            .expect_err("injected failure");
        assert!(
            error.to_string().contains("injected dpop claim failure"),
            "{error}"
        );
        fixture
            .store
            .connection()?
            .execute_batch("DROP TRIGGER temp.dpop_cut")?;
        assert_eq!(global_count(&fixture), count);
        assert_eq!(
            fixture
                .store
                .load_by_operation_id(operation.binding().operation_id())?,
            Some(operation.clone())
        );
        fixture
            .store
            .claim_dpop_replay(&operation, &lease, &intent, now_ms())?;
    }
    Ok(())
}

#[test]
fn malformed_or_missing_physical_claim_history_denies_readback() -> AnchoredTestResult {
    for damage in [
        "DROP TRIGGER dpop_replay_claim_resources_no_update; UPDATE dpop_replay_claim_resources SET nonce = 'different'",
        "DROP TRIGGER dpop_replay_claim_resources_no_delete; DELETE FROM dpop_replay_claim_resources",
        "DROP TRIGGER dpop_replay_claim_episodes_no_update; PRAGMA ignore_check_constraints = ON; UPDATE dpop_replay_claim_episodes SET claim_json = zeroblob(65537)",
    ] {
        let fixture = fixture();
        let source = Source::new(&fixture, true)?;
        let authority = activate(&fixture, &source)?;
        let (operation, lease, credential) = setup(&fixture, &authority, "dpop-corrupt", "nonce", DpopReplayClaimPhase::Dispatch)?;
        let intent = candidate(&operation, "claim", credential, DpopReplayClaimPhase::Dispatch)?;
        let (operation, _) = fixture.store.claim_dpop_replay(&operation, &lease, &intent, now_ms())?;
        let corrupt = Connection::open(&fixture.database)?;
        corrupt.execute_batch(damage)?;
        assert!(fixture.store.load_dpop_replay_claim_history(operation.binding().operation_id(), &fixture.fence, now_ms()).is_err(), "{damage}");
    }
    Ok(())
}

#[test]
fn release_failure_retains_exact_custody_until_a_successful_retry() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let authority = activate(&fixture, &source)?;
    let (operation, lease, credential) = setup(
        &fixture,
        &authority,
        "dpop-release",
        "nonce",
        DpopReplayClaimPhase::Dispatch,
    )?;
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
    let lease = renew(&fixture, &operation, &lease, now_ms())?;
    let count = global_count(&fixture);
    fixture.store.connection()?.execute_batch("CREATE TEMP TRIGGER dpop_cut BEFORE INSERT ON main.dpop_replay_claim_releases BEGIN SELECT RAISE(ABORT, 'injected release failure'); END")?;
    assert!(fixture
        .store
        .release_dpop_replay(&operation, &lease, &reference, now_ms())
        .is_err());
    fixture
        .store
        .connection()?
        .execute_batch("DROP TRIGGER temp.dpop_cut")?;
    assert_eq!(global_count(&fixture), count);
    let (_, history) = fixture
        .store
        .load_dpop_replay_claim_history(
            operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("history absent")?;
    assert_eq!(
        history[0].disposition,
        DpopReplayClaimDisposition::ReservedBeforeDispatch
    );
    fixture
        .store
        .release_dpop_replay(&operation, &lease, &reference, now_ms())?;
    Ok(())
}
