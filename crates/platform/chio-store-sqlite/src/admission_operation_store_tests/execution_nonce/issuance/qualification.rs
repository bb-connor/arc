use super::*;

#[test]
fn durable_nonce_issuance_candidates_for_one_operation_have_one_winner() -> TestResult {
    let fixture = prepared_nonce_fixture(None)?;
    let candidate = AdmissionExecutionNonceReservationV1::mint_for_operation(
        &fixture.operation,
        &fixture.original,
        &fixture.key,
        &ExecutionNonceConfig::default(),
        now_ms(),
    )?;
    let first = command(&fixture)?;
    let second = AdmissionOperationCommand::new(
        fixture.operation.binding().operation_id().clone(),
        fixture.operation.version(),
        first.recovery_lease().clone(),
        vec![AdmissionAttachment::ExecutionNonceIssuanceDigest(
            AdmissionDigest::try_new("issuance", sha256_hex(candidate.canonical_bytes()))?,
        )],
        Some(AdmissionOperationState::Prepared),
        None,
        None,
    )?;
    let barrier = std::sync::Barrier::new(2);
    let at = now_ms();
    let results = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            fixture
                .fixture
                .store
                .issue_execution_nonce_and_commit_admission(&first, &fixture.reservation, at)
        });
        let second = scope.spawn(|| {
            barrier.wait();
            fixture
                .fixture
                .store
                .issue_execution_nonce_and_commit_admission(&second, &candidate, at)
        });
        Ok::<_, Box<dyn Error>>([
            first
                .join()
                .map_err(|_| "first issuance candidate panicked")?,
            second
                .join()
                .map_err(|_| "second issuance candidate panicked")?,
        ])
    })?;
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    let retained = load(&fixture)?.ok_or("lost winning issuance")?;
    let winner = results
        .iter()
        .position(Result::is_ok)
        .ok_or("no winning candidate")?;
    assert_eq!(
        retained.canonical_bytes(),
        if winner == 0 {
            fixture.reservation.canonical_bytes()
        } else {
            candidate.canonical_bytes()
        }
    );
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
fn durable_nonce_issuance_rejects_foreign_command_mutations() -> TestResult {
    let fixture = prepared_nonce_fixture(None)?;
    let valid = command(&fixture)?;
    for next in [
        AdmissionOperationState::Prepared,
        AdmissionOperationState::BudgetAuthorized,
    ] {
        let mut attachments = valid.attachments().to_vec();
        if next == AdmissionOperationState::Prepared {
            attachments.push(AdmissionAttachment::ExecutionNonceId(
                fixture.reservation.nonce_id().clone(),
            ));
        }
        let changed = AdmissionOperationCommand::new(
            fixture.operation.binding().operation_id().clone(),
            fixture.operation.version(),
            valid.recovery_lease().clone(),
            attachments,
            Some(next),
            None,
            None,
        )?;
        let error = fixture
            .fixture
            .store
            .issue_execution_nonce_and_commit_admission(&changed, &fixture.reservation, now_ms())
            .expect_err("issuance accepted a foreign command mutation");
        assert!(
            error.to_string().contains("exact Prepared command"),
            "{error}"
        );
        assert!(load(&fixture)?.is_none());
    }
    Ok(())
}

#[test]
fn durable_nonce_issuance_rechecks_fences_and_original_provenance() -> TestResult {
    let fixture = prepared_nonce_fixture(None)?;
    let stale = command(&fixture)?;
    let fixture = lifecycle::reopen(fixture)?;
    assert!(matches!(
        fixture
            .fixture
            .store
            .issue_execution_nonce_and_commit_admission(&stale, &fixture.reservation, now_ms(),),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    assert!(load(&fixture)?.is_none());
    let current = command(&fixture)?;
    fixture.fixture.store.connection()?.execute_batch(
        "DROP TRIGGER admission_operation_tool_requests_no_delete;
         DELETE FROM admission_operation_tool_requests;",
    )?;
    let error = fixture
        .fixture
        .store
        .issue_execution_nonce_and_commit_admission(&current, &fixture.reservation, now_ms())
        .expect_err("issuance accepted missing original provenance");
    assert!(error.to_string().contains("request"), "{error}");
    let count: i64 = fixture.fixture.store.connection()?.query_row(
        "SELECT COUNT(*) FROM admission_execution_nonce_issuances",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}
