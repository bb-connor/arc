use super::*;

#[test]
fn claim_insert_failures_roll_back_all_ownership_and_commits() -> AnchoredTestResult {
    for (table, condition) in [
        (
            "admission_operation_commits",
            "WHEN NEW.mutation_kind = 'governed_approval_claim'",
        ),
        (
            "authority_global_commits",
            "WHEN NEW.mutation_kind = 'governed_approval_claim'",
        ),
        ("governed_approval_replay_claim_episodes", ""),
        ("governed_approval_replay_claim_resources", ""),
    ] {
        let fixture = fixture();
        let source = Source::new(&fixture, true)?;
        let binding = activate(&fixture, &source)?;
        let (operation, lease, credential) = setup(&fixture, table)?;
        let intent = candidate(&operation, &binding, "atomic", credential)?;
        let count = global_count(&fixture);
        fixture.store.connection()?.execute_batch(&format!("CREATE TRIGGER inject_approval_cutpoint BEFORE INSERT ON {table} {condition} BEGIN SELECT RAISE(ABORT, 'injected approval cutpoint'); END"))?;
        let error = fixture
            .store
            .claim_governed_approval(&operation, &lease, &intent, now_ms())
            .expect_err("injected claim must fail");
        assert!(
            error.to_string().contains("injected approval cutpoint"),
            "{error}"
        );
        fixture
            .store
            .connection()?
            .execute_batch("DROP TRIGGER inject_approval_cutpoint")?;
        assert_eq!(global_count(&fixture), count);
        assert_eq!(
            fixture
                .store
                .load_by_operation_id(operation.binding().operation_id())?,
            Some(operation.clone())
        );
        fixture
            .store
            .claim_governed_approval(&operation, &lease, &intent, now_ms())?;
    }
    Ok(())
}

#[test]
fn altered_or_missing_approval_history_denies_readback() -> AnchoredTestResult {
    for damage in [
        "DROP TRIGGER governed_approval_replay_claim_episodes_no_delete; DELETE FROM governed_approval_replay_claim_episodes",
        "DROP TRIGGER governed_approval_replay_claim_resources_no_delete; DELETE FROM governed_approval_replay_claim_resources",
        "DROP TRIGGER governed_approval_replay_claim_resources_no_update; UPDATE governed_approval_replay_claim_resources SET request_id = 'forged'",
        "DROP TRIGGER governed_approval_replay_claim_episodes_no_update; PRAGMA ignore_check_constraints = ON; UPDATE governed_approval_replay_claim_episodes SET claim_json = zeroblob(16385)",
    ] {
        let fixture = fixture();
        let source = Source::new(&fixture, true)?;
        let binding = activate(&fixture, &source)?;
        let (operation, lease, credential) = setup(&fixture, "damaged-approval")?;
        let intent = candidate(&operation, &binding, "claim", credential)?;
        let (operation, _) = fixture.store.claim_governed_approval(&operation, &lease, &intent, now_ms())?;
        let corrupt = Connection::open(&fixture.database)?;
        corrupt.execute_batch("PRAGMA foreign_keys = OFF")?;
        corrupt.execute_batch(damage)?;
        assert!(fixture.store.load_governed_approval_claim_history(operation.binding().operation_id(), &fixture.fence, now_ms()).is_err(), "{damage}");
    }
    Ok(())
}

#[test]
fn failed_release_retains_ownership_and_retry_preserves_the_exact_episode() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let binding = activate(&fixture, &source)?;
    let (operation, lease, credential) = setup(&fixture, "release-fault")?;
    let intent = candidate(&operation, &binding, "claim", credential)?;
    let (operation, reference) =
        fixture
            .store
            .claim_governed_approval(&operation, &lease, &intent, now_ms())?;
    let lease = renew(&fixture, &operation, &lease, now_ms())?;
    let count = global_count(&fixture);
    fixture.store.connection()?.execute_batch("CREATE TRIGGER inject_approval_release BEFORE INSERT ON governed_approval_replay_claim_releases BEGIN SELECT RAISE(ABORT, 'injected release failure'); END")?;
    assert!(fixture
        .store
        .release_governed_approval(&operation, &lease, &reference, now_ms())
        .is_err());
    fixture
        .store
        .connection()?
        .execute_batch("DROP TRIGGER inject_approval_release")?;
    assert_eq!(global_count(&fixture), count);
    let (_, history) = fixture
        .store
        .load_governed_approval_claim_history(
            operation.binding().operation_id(),
            &fixture.fence,
            now_ms(),
        )?
        .ok_or("history missing")?;
    assert_eq!(
        history[0].disposition,
        GovernedApprovalClaimDisposition::ReservedBeforeDispatch
    );
    fixture
        .store
        .release_governed_approval(&operation, &lease, &reference, now_ms())?;
    let count = global_count(&fixture);
    fixture
        .store
        .release_governed_approval(&operation, &lease, &reference, now_ms())?;
    assert_eq!(global_count(&fixture), count);
    Ok(())
}

#[test]
fn generic_cas_and_superseded_lease_cannot_fabricate_or_release_ownership() -> AnchoredTestResult {
    let fixture = fixture();
    let source = Source::new(&fixture, true)?;
    let binding = activate(&fixture, &source)?;
    let (operation, lease, credential) = setup(&fixture, "stale-owner")?;
    let forged = command(
        &operation,
        lease.clone(),
        vec![AdmissionAttachment::GovernedApprovalLedgerDigest(digest(
            "forged", 'f',
        ))],
        operation.state(),
        None,
    );
    assert!(fixture.store.compare_and_swap(&forged, now_ms()).is_err());
    let intent = candidate(&operation, &binding, "claim", credential)?;
    let (operation, reference) =
        fixture
            .store
            .claim_governed_approval(&operation, &lease, &intent, now_ms())?;
    assert!(fixture
        .store
        .release_governed_approval(&operation, &lease, &reference, now_ms())
        .is_err());
    let old = renew(&fixture, &operation, &lease, now_ms())?;
    let now = old.expires_at_unix_ms() + 1;
    let current = fixture.store.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &identifier("worker", "successor"),
        now,
        now + 10000,
        &fixture.fence,
    )?;
    assert!(fixture
        .store
        .release_governed_approval(&operation, &old, &reference, now)
        .is_err());
    fixture
        .store
        .release_governed_approval(&operation, &current, &reference, now)?;
    Ok(())
}
