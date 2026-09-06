use super::*;

fn reopen(fixture: NonceFixture) -> TestResult<NonceFixture> {
    let NonceFixture {
        fixture:
            Fixture {
                _temp,
                database,
                lock_root,
                authority,
                store,
                ..
            },
        operation,
        original,
        key,
        reservation,
    } = fixture;
    drop(store);
    drop(authority);
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let store = authority.admission_operation_store();
    let fence = authority.mutation_fence();
    let operation = store
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("lost operation")?;
    Ok(NonceFixture {
        fixture: Fixture {
            _temp,
            database,
            lock_root,
            authority,
            store,
            fence,
        },
        operation,
        original,
        key,
        reservation,
    })
}

#[test]
fn durable_nonce_lifecycle_reopens_pending_committed_and_cancelled_with_current_fences(
) -> TestResult {
    for cancel in [false, true] {
        let mut fixture = ready()?;
        prepare(&mut fixture)?;
        let old_command = command(&fixture)?;
        let old_fence = fixture.fixture.fence.clone();
        fixture = reopen(fixture)?;
        assert!(fixture
            .fixture
            .store
            .begin_execution_nonce_capture(&old_command, now_ms())
            .is_err());
        assert!(fixture
            .fixture
            .store
            .load_execution_nonce_reservation(
                fixture.operation.binding().operation_id(),
                &old_fence,
                now_ms(),
            )
            .is_err());
        if cancel {
            release(&fixture)?;
            fixture
                .fixture
                .store
                .commit_terminal_projection(&projection(&fixture)?)?;
        } else {
            capture(&mut fixture)?;
        }
        fixture = reopen(fixture)?;
        assert_eq!(
            fixture.operation.state(),
            if cancel {
                AdmissionOperationState::CompensatedBeforeDispatch
            } else {
                AdmissionOperationState::DispatchCommitted
            }
        );
        assert_eq!(
            state(&fixture)?,
            (
                if cancel {
                    "reversed".into()
                } else {
                    "captured".into()
                },
                2,
                i64::from(!cancel)
            )
        );
        let retained = fixture
            .fixture
            .store
            .load_execution_nonce_reservation(
                fixture.operation.binding().operation_id(),
                &fixture.fixture.fence,
                now_ms(),
            )?
            .ok_or("lost historical nonce")?;
        assert_eq!(
            retained.canonical_bytes(),
            fixture.reservation.canonical_bytes()
        );
    }
    Ok(())
}

#[test]
fn durable_nonce_lifecycle_signed_terminal_paths_preserve_disposition() -> TestResult {
    for cancel in [false, true] {
        let mut fixture = ready()?;
        prepare(&mut fixture)?;
        let projection = if cancel {
            release(&fixture)?;
            projection(&fixture)?
        } else {
            capture(&mut fixture)?;
            let command = command(&fixture)?;
            let lease = command.recovery_lease();
            let context = AdmissionProjectionContext {
                operation_id: fixture.operation.binding().operation_id().clone(),
                request_id: fixture.operation.binding().request_id().clone(),
                expected_operation_version: fixture.operation.version(),
                trusted_time_unix_ms: now_ms(),
                coordinator_lease_id: lease.coordinator_lease_id().clone(),
                coordinator_lease_epoch: lease.coordinator_lease_epoch(),
                store_fence: fixture.fixture.fence.clone(),
            };
            let incident = AdmissionIncident::from_verified(
                &fixture.operation,
                &context,
                AdmissionOperationState::OutcomeUnknownAfterDispatch,
                identifier("incident", "nonce-outcome-unknown"),
                digest("incident", 'e'),
            )?;
            AdmissionTerminalProjection::OutcomeUnknownAfterDispatch {
                context,
                incident: Box::new(incident),
            }
        };
        let signed = SignedAdmissionTerminalProjectionV1::from_verified(
            &fixture.operation,
            &projection,
            &fixture.fixture.store.admission_projection_capabilities(),
            &fixture.key,
        )?;
        let terminal = fixture
            .fixture
            .store
            .commit_signed_terminal_projection(&signed)?;
        assert_eq!(
            terminal.state,
            if cancel {
                AdmissionOperationState::CompensatedBeforeDispatch
            } else {
                AdmissionOperationState::OutcomeUnknownAfterDispatch
            }
        );
        assert_eq!(
            fixture
                .fixture
                .store
                .commit_signed_terminal_projection(&signed)?,
            terminal
        );
        fixture = reopen(fixture)?;
        assert_eq!(fixture.operation.state(), terminal.state);
        assert_eq!(state(&fixture)?.1, 2);
    }
    Ok(())
}

#[test]
fn durable_nonce_lifecycle_expired_capture_rolls_back_budget_and_can_still_cancel() -> TestResult {
    let mut fixture = ready()?;
    prepare(&mut fixture)?;
    let wire: serde_json::Value = serde_json::from_slice(fixture.reservation.canonical_bytes())?;
    let expires = wire["signed_nonce"]["nonce"]["expires_at"]
        .as_u64()
        .ok_or("nonce expiry")?
        * 1_000;
    let command = command(&fixture)?;
    let error = fixture
        .fixture
        .store
        .capture_invocation_and_commit_dispatch(
            &fixture.operation,
            command.recovery_lease(),
            capture_request(&fixture),
            &fixture.fixture.fence,
            expires,
        )
        .expect_err("expired nonce captured a quota");
    assert!(
        error.to_string().contains("execution nonce expired"),
        "{error}"
    );
    assert_eq!(state(&fixture)?, ("authorized".into(), 1, 0));
    release(&fixture)?;
    fixture
        .fixture
        .store
        .commit_terminal_projection(&projection(&fixture)?)?;
    assert_eq!(state(&fixture)?, ("reversed".into(), 2, 0));
    assert!(fixture
        .fixture
        .store
        .load_execution_nonce_reservation(
            fixture.operation.binding().operation_id(),
            &fixture.fixture.fence,
            expires,
        )?
        .is_some());
    Ok(())
}

#[test]
fn durable_nonce_lifecycle_history_rejects_missing_corrupt_and_oversized_phases() -> TestResult {
    for (cancel, mutation) in [
        (false, "DROP TRIGGER admission_execution_nonce_transitions_no_delete;
                 DELETE FROM admission_execution_nonce_transitions WHERE kind = 'committed';"),
        (false, "DROP TRIGGER admission_execution_nonce_transitions_immutable;
                 UPDATE admission_execution_nonce_transitions SET recorded_at_unix_ms = recorded_at_unix_ms + 1 WHERE kind = 'committed';"),
        (false, "DROP TRIGGER admission_execution_nonce_transitions_immutable;
                 PRAGMA ignore_check_constraints = ON;
                 UPDATE admission_execution_nonce_transitions SET operation_json = zeroblob(262145) WHERE kind = 'capture_pending';
                 PRAGMA ignore_check_constraints = OFF;"),
        (true, "DROP TRIGGER admission_execution_nonce_transitions_immutable;
                PRAGMA ignore_check_constraints = ON;
                UPDATE admission_execution_nonce_transitions SET participant_digest = 'bad' WHERE kind = 'cancelled';
                PRAGMA ignore_check_constraints = OFF;"),
    ] {
        let mut fixture = ready()?;
        prepare(&mut fixture)?;
        if cancel {
            release(&fixture)?;
            fixture.fixture.store.commit_terminal_projection(&projection(&fixture)?)?;
        } else {
            capture(&mut fixture)?;
        }
        fixture.fixture.store.connection()?.execute_batch(mutation)?;
        let error = fixture.fixture.store.load_by_operation_id(fixture.operation.binding().operation_id()).expect_err("corrupt history read");
        assert!(error.to_string().contains("nonce"), "{error}");
        let NonceFixture { fixture: Fixture { _temp, database, lock_root, authority, store, .. }, .. } = fixture;
        drop(store);
        drop(authority);
        let error = match SqliteAuthorityStore::open_serving(&database, &lock_root) {
            Ok(_) => return Err("corrupt nonce history reopened".into()), Err(error) => error,
        };
        assert!(error.to_string().contains("nonce"), "{error}");
    }
    Ok(())
}

#[test]
fn durable_nonce_lifecycle_phase_rows_are_permanent_and_immutable() -> TestResult {
    let mut fixture = ready()?;
    prepare(&mut fixture)?;
    capture(&mut fixture)?;
    for statement in ["DELETE FROM admission_execution_nonce_transitions",
        "UPDATE admission_execution_nonce_transitions SET recorded_at_unix_ms = recorded_at_unix_ms + 1"] {
        assert!(fixture.fixture.store.connection()?.execute(statement, []).is_err());
    }
    assert_eq!(state(&fixture)?, ("captured".into(), 2, 1));
    Ok(())
}

#[test]
fn durable_nonce_lifecycle_v12_migration_keeps_ready_history_without_inventing_commit() -> TestResult
{
    let fixture = ready()?;
    let operation_id = fixture.operation.binding().operation_id().clone();
    let expected = fixture.reservation.canonical_bytes().to_vec();
    let NonceFixture {
        fixture:
            Fixture {
                _temp,
                database,
                lock_root,
                authority,
                store,
                ..
            },
        ..
    } = fixture;
    drop(store);
    drop(authority);
    let connection = Connection::open(&database)?;
    connection.execute_batch("DROP TABLE admission_execution_nonce_transitions;
        UPDATE chio_store_schema_versions SET version = 12 WHERE store_key = 'admission_operation';")?;
    drop(connection);
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let reopened = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let store = reopened.admission_operation_store();
    assert_eq!(
        store
            .load_by_operation_id(&operation_id)?
            .ok_or("lost operation")?
            .state(),
        AdmissionOperationState::ReadyToDispatch
    );
    assert_eq!(
        store
            .load_execution_nonce_reservation(&operation_id, &reopened.mutation_fence(), now_ms())?
            .ok_or("lost reservation")?
            .canonical_bytes(),
        expected
    );
    let count: i64 = store.connection()?.query_row(
        "SELECT COUNT(*) FROM admission_execution_nonce_transitions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn durable_nonce_lifecycle_capture_and_cancellation_have_one_atomic_winner() -> TestResult {
    for _ in 0..4 {
        let mut fixture = ready()?;
        prepare(&mut fixture)?;
        let capture_command = command(&fixture)?;
        let projection = projection(&fixture)?;
        let barrier = std::sync::Barrier::new(2);
        let (captured, cancelled) = std::thread::scope(|scope| {
            let capture = scope.spawn(|| {
                barrier.wait();
                fixture
                    .fixture
                    .store
                    .capture_invocation_and_commit_dispatch(
                        &fixture.operation,
                        capture_command.recovery_lease(),
                        capture_request(&fixture),
                        &fixture.fixture.fence,
                        now_ms(),
                    )
                    .map(|(_, operation)| operation.state())
                    .map_err(|error| error.to_string())
            });
            let cancel = scope.spawn(|| {
                barrier.wait();
                release(&fixture).map_err(|error| error.to_string())?;
                fixture
                    .fixture
                    .store
                    .commit_terminal_projection(&projection)
                    .map(|terminal| terminal.state)
                    .map_err(|error| error.to_string())
            });
            (capture.join(), cancel.join())
        });
        let captured = captured.map_err(|_| "capture thread panic")?;
        let cancelled = cancelled.map_err(|_| "cancellation thread panic")?;
        assert_eq!(
            usize::from(captured.is_ok()) + usize::from(cancelled.is_ok()),
            1,
            "capture={captured:?}, cancel={cancelled:?}"
        );
        let expected = if captured.is_ok() {
            AdmissionOperationState::DispatchCommitted
        } else {
            AdmissionOperationState::CompensatedBeforeDispatch
        };
        assert_eq!(
            fixture
                .fixture
                .store
                .load_by_operation_id(fixture.operation.binding().operation_id())?
                .ok_or("operation lost")?
                .state(),
            expected
        );
        assert_eq!(
            state(&fixture)?,
            (
                if captured.is_ok() {
                    "captured".into()
                } else {
                    "reversed".into()
                },
                2,
                i64::from(captured.is_ok())
            )
        );
    }
    Ok(())
}
