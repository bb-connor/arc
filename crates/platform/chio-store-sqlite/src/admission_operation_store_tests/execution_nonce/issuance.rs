use super::*;

#[path = "issuance/qualification.rs"]
mod qualification;
#[path = "issuance/recovery.rs"]
mod recovery;

fn command(fixture: &NonceFixture) -> TestResult<AdmissionOperationCommand> {
    nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &fixture.operation,
        &fixture.key,
        vec![AdmissionAttachment::ExecutionNonceIssuanceDigest(
            AdmissionDigest::try_new(
                "issuance",
                sha256_hex(fixture.reservation.canonical_bytes()),
            )?,
        )],
        AdmissionOperationState::Prepared,
    )
}

fn issue(fixture: &mut NonceFixture) -> TestResult {
    fixture.operation = fixture
        .fixture
        .store
        .issue_execution_nonce_and_commit_admission(
            &command(fixture)?,
            &fixture.reservation,
            now_ms(),
        )?
        .into_operation();
    Ok(())
}

fn load(fixture: &NonceFixture) -> TestResult<Option<AdmissionExecutionNonceReservationV1>> {
    Ok(fixture.fixture.store.load_execution_nonce_issuance(
        fixture.operation.binding().operation_id(),
        &fixture.fixture.fence,
        now_ms(),
    )?)
}

pub(super) fn contenders_share_one_identity() -> TestResult {
    let fixture = prepared_nonce_fixture(None)?;
    let binding = fixture.operation.binding().to_persisted();
    let binding = AdmissionOperationBindingV1::new(AdmissionOperationBindingInputV1 {
        kind: binding.kind,
        namespace: AuthenticatedRequestNamespace::for_local_system(identifier(
            "authority",
            "second-coordinator-namespace",
        ))?,
        request_id: binding.request_id,
        capability_id: binding.capability_id,
        authorization_capability_hash: binding.authorization_capability_hash,
        request_binding: binding.request_binding,
        policy_hash: binding.policy_hash,
        effect_class: binding.effect_class,
    })?;
    let second = AdmissionOperationV1::prepare(binding, fixture.fixture.fence.owner_epoch)?;
    fixture.fixture.store.begin_with_retained_tool_request(
        &second,
        &fixture.original,
        &fixture.fixture.fence,
        now_ms(),
    )?;
    let mut signed = fixture.reservation.signed_nonce().clone();
    domain::sign_for(&second, &mut signed, &fixture.key)?;
    let candidate = AdmissionExecutionNonceReservationV1::verify(
        &second,
        &fixture.original,
        &signed,
        &fixture.key.public_key(),
        now_ms(),
    )?;
    let first_command = command(&fixture)?;
    let second_command = nonce_command(
        &fixture.fixture.store,
        &fixture.fixture.fence,
        &second,
        &fixture.key,
        vec![AdmissionAttachment::ExecutionNonceIssuanceDigest(
            AdmissionDigest::try_new("issuance", sha256_hex(candidate.canonical_bytes()))?,
        )],
        AdmissionOperationState::Prepared,
    )?;
    let barrier = std::sync::Barrier::new(2);
    let at = now_ms();
    let results = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            fixture
                .fixture
                .store
                .issue_execution_nonce_and_commit_admission(
                    &first_command,
                    &fixture.reservation,
                    at,
                )
        });
        let second = scope.spawn(|| {
            barrier.wait();
            fixture
                .fixture
                .store
                .issue_execution_nonce_and_commit_admission(&second_command, &candidate, at)
        });
        Ok::<_, Box<dyn Error>>([
            first.join().map_err(|_| "first issuance worker panicked")?,
            second
                .join()
                .map_err(|_| "second issuance worker panicked")?,
        ])
    })?;
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let error = results
        .into_iter()
        .find_map(Result::err)
        .ok_or("missing rejected contender")?;
    assert!(
        error.to_string().contains("UNIQUE constraint failed"),
        "{error}"
    );
    let counts: (i64, i64) = fixture.fixture.store.connection()?.query_row(
        "SELECT (SELECT COUNT(*) FROM admission_execution_nonce_issuances),
                (SELECT COUNT(*) FROM admission_execution_nonce_reservations)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(counts, (1, 0));
    for operation in [&fixture.operation, &second] {
        let stored = fixture
            .fixture
            .store
            .load_by_operation_id(operation.binding().operation_id())?
            .ok_or("lost contender")?;
        assert_eq!(stored.state(), AdmissionOperationState::Prepared);
        assert!(stored.execution_nonce_id().is_none());
    }
    Ok(())
}

#[test]
fn durable_nonce_issuance_is_exact_and_does_not_reserve_or_dispatch() -> TestResult {
    let mut fixture = prepared_nonce_fixture(None)?;
    assert!(load(&fixture)?.is_none());
    let original_command = command(&fixture)?;
    // Lose the acknowledgement. Its old version-bound lease cannot act again;
    // fenced lookup recovers the committed identity before a fresh lease retry.
    let _ = fixture
        .fixture
        .store
        .issue_execution_nonce_and_commit_admission(
            &original_command,
            &fixture.reservation,
            now_ms(),
        )?;
    let stale_retry = fixture
        .fixture
        .store
        .issue_execution_nonce_and_commit_admission(
            &original_command,
            &fixture.reservation,
            now_ms(),
        );
    assert!(matches!(
        stale_retry,
        Err(AdmissionOperationStoreError::Fenced)
    ));
    fixture.operation = fixture
        .fixture
        .store
        .load_by_operation_id(fixture.operation.binding().operation_id())?
        .ok_or("lost operation after acknowledgement loss")?;
    let expected = fixture.operation.clone();
    assert_eq!(expected.state(), AdmissionOperationState::Prepared);
    assert!(expected.execution_nonce_issuance_digest().is_some());
    assert!(expected.execution_nonce_id().is_none());
    assert!(expected.budget_hold_id().is_none());
    assert_eq!(
        load(&fixture)?.ok_or("lost issuance")?.canonical_bytes(),
        fixture.reservation.canonical_bytes()
    );
    let replay = fixture
        .fixture
        .store
        .issue_execution_nonce_and_commit_admission(
            &command(&fixture)?,
            &fixture.reservation,
            now_ms(),
        )?;
    assert!(matches!(replay, AdmissionCommandResult::Idempotent(_)));
    assert_eq!(replay.into_operation(), expected);
    let counts: (i64, i64) = fixture.fixture.store.connection()?.query_row(
        "SELECT (SELECT COUNT(*) FROM admission_execution_nonce_issuances),
                (SELECT COUNT(*) FROM admission_execution_nonce_reservations)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(counts, (1, 0));
    Ok(())
}

#[test]
fn durable_nonce_issuance_cannot_be_replaced_even_after_expiry() -> TestResult {
    let mut fixture = prepared_nonce_fixture(None)?;
    issue(&mut fixture)?;
    let retained = fixture.reservation.canonical_bytes().to_vec();
    let expires = u64::try_from(fixture.reservation.signed_nonce().expires_at())? * 1_000;
    let retry = command(&fixture)?;
    assert!(fixture
        .fixture
        .store
        .issue_execution_nonce_and_commit_admission(&retry, &fixture.reservation, expires,)
        .is_err());
    assert_eq!(
        fixture
            .fixture
            .store
            .load_execution_nonce_issuance(
                fixture.operation.binding().operation_id(),
                &fixture.fixture.fence,
                expires,
            )?
            .ok_or("lost expired issuance")?
            .canonical_bytes(),
        retained
    );
    fixture.reservation = AdmissionExecutionNonceReservationV1::mint_for_operation(
        &fixture.operation,
        &fixture.original,
        &fixture.key,
        &ExecutionNonceConfig::default(),
        now_ms(),
    )?;
    assert_ne!(fixture.reservation.canonical_bytes(), retained);
    assert!(fixture
        .fixture
        .store
        .issue_execution_nonce_and_commit_admission(
            &command(&fixture)?,
            &fixture.reservation,
            now_ms(),
        )
        .is_err());
    assert_eq!(
        load(&fixture)?
            .ok_or("lost original issuance")?
            .canonical_bytes(),
        retained
    );
    Ok(())
}

#[test]
fn durable_nonce_issuance_generic_cas_cannot_forge_evidence() -> TestResult {
    let fixture = prepared_nonce_fixture(None)?;
    let command = command(&fixture)?;
    let error = fixture
        .fixture
        .store
        .compare_and_swap(&command, now_ms())
        .expect_err("generic CAS forged issuance");
    assert!(error.to_string().contains("atomic participant"), "{error}");
    let mut forged = fixture
        .operation
        .apply_command(&command, now_ms())?
        .into_operation()
        .to_persisted();
    forged.version = 1;
    let forged = AdmissionOperationV1::from_persisted(forged)?;
    let error = fixture
        .fixture
        .store
        .begin_with_retained_tool_request(
            &forged,
            &fixture.original,
            &fixture.fixture.fence,
            now_ms(),
        )
        .expect_err("begin forged issuance");
    assert!(
        error
            .to_string()
            .contains("cannot fabricate nonce issuance"),
        "{error}"
    );
    assert!(load(&fixture)?.is_none());
    assert_eq!(
        fixture
            .fixture
            .store
            .load_by_operation_id(fixture.operation.binding().operation_id())?,
        Some(fixture.operation)
    );
    Ok(())
}

#[test]
fn durable_nonce_issuance_rejects_legacy_profiles_and_wrong_issuers() -> TestResult {
    let mut fixture = prepared_nonce_fixture(None)?;
    let signed = mint_execution_nonce(
        &fixture.key,
        fixture.reservation.signed_nonce().nonce.bound_to.clone(),
        &ExecutionNonceConfig::default(),
        i64::try_from(now_ms() / 1_000)?,
    )?;
    fixture.reservation = AdmissionExecutionNonceReservationV1::verify(
        &fixture.operation,
        &fixture.original,
        &signed,
        &fixture.key.public_key(),
        now_ms(),
    )?;
    let error = fixture
        .fixture
        .store
        .issue_execution_nonce_and_commit_admission(
            &command(&fixture)?,
            &fixture.reservation,
            now_ms(),
        )
        .expect_err("legacy profile became issued authority");
    assert!(
        error.to_string().contains("operation-bound profile"),
        "{error}"
    );
    fixture.reservation = AdmissionExecutionNonceReservationV1::mint_for_operation(
        &fixture.operation,
        &fixture.original,
        &Keypair::generate(),
        &ExecutionNonceConfig::default(),
        now_ms(),
    )?;
    let error = fixture
        .fixture
        .store
        .issue_execution_nonce_and_commit_admission(
            &command(&fixture)?,
            &fixture.reservation,
            now_ms(),
        )
        .expect_err("foreign issuer acquired issuance");
    assert!(
        error.to_string().contains("qualified coordinator"),
        "{error}"
    );
    assert!(load(&fixture)?.is_none());
    Ok(())
}

#[test]
fn durable_nonce_issuance_rolls_back_each_sql_cutpoint() -> TestResult {
    for (table, mutation) in [
        ("admission_operations", "UPDATE"),
        ("admission_operation_commits", "INSERT"),
        ("admission_execution_nonce_issuances", "INSERT"),
    ] {
        let mut fixture = prepared_nonce_fixture(None)?;
        let command = command(&fixture)?;
        let before: i64 = fixture.fixture.store.connection()?.query_row(
            "SELECT COUNT(*) FROM admission_operation_commits",
            [],
            |row| row.get(0),
        )?;
        fixture.fixture.store.connection()?.execute_batch(&format!(
            "CREATE TRIGGER fail_issuance BEFORE {mutation} ON {table}
             BEGIN SELECT RAISE(ABORT, 'injected issuance rollback'); END;"
        ))?;
        let error = fixture
            .fixture
            .store
            .issue_execution_nonce_and_commit_admission(&command, &fixture.reservation, now_ms())
            .expect_err("injected issuance write succeeded");
        assert!(
            error.to_string().contains("injected issuance rollback"),
            "{error}"
        );
        fixture
            .fixture
            .store
            .connection()?
            .execute_batch("DROP TRIGGER fail_issuance")?;
        assert!(load(&fixture)?.is_none());
        assert_eq!(
            fixture
                .fixture
                .store
                .load_by_operation_id(fixture.operation.binding().operation_id())?,
            Some(fixture.operation.clone())
        );
        let after: i64 = fixture.fixture.store.connection()?.query_row(
            "SELECT COUNT(*) FROM admission_operation_commits",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(after, before);
        issue(&mut fixture)?;
    }
    Ok(())
}

#[test]
fn durable_nonce_issuance_reopens_with_current_fences_and_migrates_absence() -> TestResult {
    let mut fixture = prepared_nonce_fixture(None)?;
    let original = fixture.original.canonical_bytes().to_vec();
    fixture.fixture.store.connection()?.execute(
        "UPDATE chio_store_schema_versions SET version = 14 WHERE store_key = 'admission_operation'", [],
    )?;
    let old_fence = fixture.fixture.fence.clone();
    fixture = lifecycle::reopen(fixture)?;
    assert_eq!(fixture.original.canonical_bytes(), original);
    assert!(load(&fixture)?.is_none());
    assert!(matches!(
        fixture.fixture.store.load_execution_nonce_issuance(
            fixture.operation.binding().operation_id(),
            &old_fence,
            now_ms(),
        ),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    issue(&mut fixture)?;
    let retained = fixture.reservation.canonical_bytes().to_vec();
    fixture = lifecycle::reopen(fixture)?;
    assert_eq!(
        load(&fixture)?
            .ok_or("lost issued nonce on reopen")?
            .canonical_bytes(),
        retained
    );
    issue(&mut fixture)?;
    assert_eq!(
        load(&fixture)?
            .ok_or("lost issued nonce after retry")?
            .canonical_bytes(),
        retained
    );
    Ok(())
}

#[test]
fn durable_nonce_issuance_reservation_requires_the_exact_retained_artifact() -> TestResult {
    let mut fixture = nonce_fixture()?;
    let retained = fixture.reservation.canonical_bytes().to_vec();
    fixture.reservation = AdmissionExecutionNonceReservationV1::mint_for_operation(
        &fixture.operation,
        &fixture.original,
        &fixture.key,
        &ExecutionNonceConfig::default(),
        now_ms(),
    )?;
    let error = fixture
        .fixture
        .store
        .reserve_execution_nonce_and_commit_admission(
            &reserve_command(&fixture)?,
            &fixture.reservation,
            now_ms(),
        )
        .expect_err("reservation accepted an unissued candidate");
    assert!(
        error.to_string().contains("changed its durable issuance"),
        "{error}"
    );
    assert_eq!(
        load(&fixture)?
            .ok_or("lost retained issuance")?
            .canonical_bytes(),
        retained
    );
    let fixture = advance_nonce_fixture(prepared_nonce_fixture(None)?, false, None, false)?;
    let error = fixture
        .fixture
        .store
        .reserve_execution_nonce_and_commit_admission(
            &reserve_command(&fixture)?,
            &fixture.reservation,
            now_ms(),
        )
        .expect_err("reservation accepted missing issuance");
    assert!(
        error.to_string().contains("requires durable issuance"),
        "{error}"
    );
    let error = fixture
        .fixture
        .store
        .issue_execution_nonce_and_commit_admission(
            &command(&fixture)?,
            &fixture.reservation,
            now_ms(),
        )
        .expect_err("late issuance reopened an executable admission");
    assert!(
        error
            .to_string()
            .contains("must precede executable admission participants"),
        "{error}"
    );
    Ok(())
}

#[test]
fn durable_nonce_issuance_is_permanent_and_detects_corruption() -> TestResult {
    for corrupt in [
        "DELETE FROM admission_execution_nonce_issuances",
        "UPDATE admission_execution_nonce_issuances SET nonce_id = 'different'",
        "UPDATE admission_execution_nonce_issuances SET issuer = printf('%064d', 0)",
        "UPDATE admission_execution_nonce_issuances SET issuance_json = zeroblob(16385)",
        "UPDATE admission_execution_nonce_issuances SET operation_json = zeroblob(262145)",
        "UPDATE admission_execution_nonce_issuances SET issued_at_unix_ms = issued_at_unix_ms + 1",
    ] {
        let mut fixture = prepared_nonce_fixture(None)?;
        issue(&mut fixture)?;
        assert!(fixture
            .fixture
            .store
            .connection()?
            .execute(corrupt, [])
            .is_err());
        fixture.fixture.store.connection()?.execute_batch(
            "DROP TRIGGER admission_execution_nonce_issuances_immutable;
             DROP TRIGGER admission_execution_nonce_issuances_no_delete;
             PRAGMA ignore_check_constraints = ON;",
        )?;
        fixture.fixture.store.connection()?.execute(corrupt, [])?;
        assert!(load(&fixture).is_err(), "{corrupt}");
        assert!(
            fixture
                .fixture
                .store
                .load_by_operation_id(fixture.operation.binding().operation_id())
                .is_err(),
            "{corrupt}"
        );
        assert!(lifecycle::reopen(fixture).is_err(), "{corrupt}");
    }
    Ok(())
}
