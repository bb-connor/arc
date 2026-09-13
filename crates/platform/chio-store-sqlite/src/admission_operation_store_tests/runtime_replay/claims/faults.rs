use super::*;

#[test]
fn wrong_request_grant_phase_generation_and_resource_order_reject_without_writes() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, true)?;
    let (operation, lease) = setup(&fixture, "wrong-intent")?;
    let candidate = intent(
        &operation,
        &source,
        "intent",
        &[(Kind::DestructiveLease, "resource")],
    )?;
    let baseline = serde_json::to_value(&candidate)?;
    let count = global_count(&fixture.store);
    for (field, value) in [
        ("requestBindingHash", serde_json::json!("a".repeat(64))),
        ("grantIndex", serde_json::json!(1)),
        ("phase", serde_json::json!("nonce_preflight")),
        ("expectationId", serde_json::json!("different-generation")),
        (
            "runtimeAuthorityId",
            serde_json::json!("unconfigured-runtime"),
        ),
        (
            "resources",
            serde_json::json!([baseline["resources"][0], baseline["resources"][0]]),
        ),
    ] {
        let mut altered = baseline.clone();
        altered[field] = value;
        if let Ok(altered) = serde_json::from_value::<RuntimeParticipantClaimIntentV1>(altered) {
            assert!(
                fixture
                    .store
                    .claim_runtime_participants(&operation, &lease, &altered, now_ms())
                    .is_err(),
                "{field}"
            );
        }
        assert_eq!(global_count(&fixture.store), count, "{field}");
    }
    Ok(())
}

#[test]
fn superseded_recovery_lease_cannot_reserve_or_release_runtime_resources() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, true)?;
    let (operation, old) = setup(&fixture, "stale-lease")?;
    let candidate = intent(&operation, &source, "claim", &[])?;
    let (operation, reference) =
        fixture
            .store
            .claim_runtime_participants(&operation, &old, &candidate, now_ms())?;
    let old = renew(&fixture, &operation, &old)?;
    let now = old.expires_at_unix_ms() + 1;
    let current = fixture.store.claim_recovery(
        operation.binding().operation_id(),
        operation.version(),
        &identifier("claimant", "successor"),
        now,
        now + 10000,
        &fixture.fence,
    )?;
    assert!(fixture
        .store
        .claim_runtime_participants(&operation, &old, &candidate, now)
        .is_err());
    assert!(fixture
        .store
        .release_runtime_participants(&operation, &old, &reference, now)
        .is_err());
    fixture
        .store
        .release_runtime_participants(&operation, &current, &reference, now)?;
    Ok(())
}

#[test]
fn generic_cas_cannot_fabricate_runtime_ledger_ownership() -> TestResult {
    let fixture = fixture();
    let (operation, lease) = setup(&fixture, "forged-ledger")?;
    let forged = command(
        &operation,
        lease,
        vec![AdmissionAttachment::RuntimeParticipantLedgerDigest(digest(
            "forged", 'f',
        ))],
        operation.state(),
        None,
    );
    assert!(
        matches!(fixture.store.compare_and_swap(&forged, now_ms()), Err(AdmissionOperationStoreError::Invariant(message)) if message.contains("atomic reservation"))
    );
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(operation.binding().operation_id())?,
        Some(operation)
    );
    Ok(())
}

#[test]
fn claim_insert_cutpoints_roll_back_operation_global_commit_and_all_resources() -> TestResult {
    for (table, condition) in [
        (
            "admission_operation_commits",
            "WHEN NEW.mutation_kind = 'runtime_participant_claim'",
        ),
        (
            "authority_global_commits",
            "WHEN NEW.mutation_kind = 'runtime_participant_claim'",
        ),
        ("runtime_replay_claim_episodes", ""),
        (
            "runtime_replay_claim_resources",
            "WHEN NEW.participant_kind = 'swarm_continuation'",
        ),
    ] {
        let fixture = fixture();
        let source = imported(&fixture, true)?;
        let (operation, lease) = setup(&fixture, table)?;
        let candidate = intent(
            &operation,
            &source,
            "atomic",
            &[
                (Kind::DestructiveLease, "d"),
                (Kind::TreatyContinuation, "t"),
                (Kind::SwarmContinuation, "s"),
            ],
        )?;
        let count = global_count(&fixture.store);
        fixture.store.connection()?.execute_batch(&format!("CREATE TRIGGER inject_runtime_cutpoint BEFORE INSERT ON {table} {condition} BEGIN SELECT RAISE(ABORT, 'injected runtime cutpoint'); END"))?;
        let error = fixture
            .store
            .claim_runtime_participants(&operation, &lease, &candidate, now_ms())
            .expect_err("injected cutpoint must reject");
        assert!(
            error.to_string().contains("injected runtime cutpoint"),
            "{table}: {error}"
        );
        fixture
            .store
            .connection()?
            .execute_batch("DROP TRIGGER inject_runtime_cutpoint")?;
        assert_eq!(global_count(&fixture.store), count);
        assert_eq!(
            fixture
                .store
                .load_by_operation_id(operation.binding().operation_id())?,
            Some(operation.clone())
        );
        fixture
            .store
            .claim_runtime_participants(&operation, &lease, &candidate, now_ms())?;
    }
    Ok(())
}

#[test]
fn failed_release_does_not_free_the_claim_and_missing_release_is_corruption() -> TestResult {
    let fixture = fixture();
    let source = imported(&fixture, true)?;
    let (operation, lease) = setup(&fixture, "release-cutpoint")?;
    let candidate = intent(
        &operation,
        &source,
        "first",
        &[(Kind::DestructiveLease, "resource")],
    )?;
    let (operation, reference) =
        fixture
            .store
            .claim_runtime_participants(&operation, &lease, &candidate, now_ms())?;
    let lease = renew(&fixture, &operation, &lease)?;
    let count = global_count(&fixture.store);
    fixture.store.connection()?.execute_batch("CREATE TRIGGER inject_runtime_release BEFORE INSERT ON runtime_replay_claim_releases BEGIN SELECT RAISE(ABORT, 'injected release cutpoint'); END")?;
    let error = fixture
        .store
        .release_runtime_participants(&operation, &lease, &reference, now_ms())
        .expect_err("injected release must reject");
    assert!(
        error.to_string().contains("injected release cutpoint"),
        "{error}"
    );
    fixture
        .store
        .connection()?
        .execute_batch("DROP TRIGGER inject_runtime_release")?;
    assert_eq!(global_count(&fixture.store), count);
    let next = intent(
        &operation,
        &source,
        "next",
        &[(Kind::DestructiveLease, "resource")],
    )?;
    assert!(fixture
        .store
        .claim_runtime_participants(&operation, &lease, &next, now_ms())
        .is_err());
    fixture
        .store
        .release_runtime_participants(&operation, &lease, &reference, now_ms())?;
    fixture
        .store
        .claim_runtime_participants(&operation, &lease, &next, now_ms())?;
    // Removing an old release must not silently change a current owner's history.
    fixture.store.connection()?.execute_batch("DROP TRIGGER runtime_replay_claim_releases_no_delete; DELETE FROM runtime_replay_claim_releases")?;
    assert!(fixture
        .store
        .load_by_operation_id(operation.binding().operation_id())
        .is_err());
    Ok(())
}
