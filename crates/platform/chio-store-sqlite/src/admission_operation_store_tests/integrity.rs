use super::*;

/// One independently damaged owner: the committed operation row is advanced
/// past the commit history that authenticated it, through the owner's own
/// connection so its `data_version` fence cannot explain the change away. The
/// retained-row delete guard is proven on the same untainted owner.
fn owner_with_tampered_operation_row() -> (Fixture, AdmissionOperationV1, u64) {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-read-integrity",
        "capability-read-integrity",
    );
    let begun_at = now_ms();
    fixture
        .store
        .begin(&operation, &fixture.fence, begun_at)
        .expect("begin");
    {
        let connection = fixture.store.connection().expect("connection");
        assert!(connection
            .execute(
                "DELETE FROM admission_operations WHERE operation_id = ?1",
                [operation.binding().operation_id().as_str()],
            )
            .is_err());
        connection
            .execute(
                r#"
                UPDATE admission_operations
                SET updated_at_unix_ms = updated_at_unix_ms + 1
                WHERE operation_id = ?1
                "#,
                [operation.binding().operation_id().as_str()],
            )
            .expect("tamper row after open");
    }
    (fixture, operation, begun_at)
}

/// The read path's own first serving transaction must refuse the corrupted
/// row with its exact first-detection invariant: the owner's entry gate
/// authenticates the whole store and the row no longer matches the commit
/// history that recorded it. That refusal permanently poisons the serving
/// owner, and a later read on the same owner is refused by that exact
/// poisoned fence: never reset, bypassed or revalidated into serving damage.
fn assert_read_refuses_tampering_then_stays_fenced(
    read: impl Fn(&Fixture, &AdmissionOperationV1, u64) -> Result<(), AdmissionOperationStoreError>,
) {
    let (fixture, operation, begun_at) = owner_with_tampered_operation_row();
    let refused = read(&fixture, &operation, begun_at);
    assert!(
        matches!(
            &refused,
            Err(AdmissionOperationStoreError::Invariant(detail))
                if detail == "invalid sqlite authority store: admission operation invariant failed: latest admission operation commit does not match its projection"
        ),
        "{refused:?}"
    );
    let fenced = read(&fixture, &operation, begun_at);
    assert!(
        matches!(
            &fenced,
            Err(AdmissionOperationStoreError::OutcomeUnknown(detail))
                if detail == "sqlite authority owner is poisoned after an outcome-unknown anchor sync"
        ),
        "{fenced:?}"
    );
}

#[test]
fn post_open_tampering_is_rejected_by_every_read_path_and_rows_cannot_be_deleted() {
    assert_read_refuses_tampering_then_stays_fenced(|fixture, operation, _| {
        fixture
            .store
            .load_by_operation_id(operation.binding().operation_id())
            .map(|_| ())
    });
    assert_read_refuses_tampering_then_stays_fenced(|fixture, operation, _| {
        fixture
            .store
            .load_by_replay_key(&operation.replay_key())
            .map(|_| ())
    });
    assert_read_refuses_tampering_then_stays_fenced(|fixture, _, begun_at| {
        fixture
            .store
            .list_recoverable(begun_at, None, 10)
            .map(|_| ())
    });
    assert_read_refuses_tampering_then_stays_fenced(|fixture, operation, _| {
        fixture
            .store
            .load_terminal_replay(&operation.replay_key())
            .map(|_| ())
    });
}

/// Foreign-key damage must refuse and fence the serving owner through its own
/// entry gate, whether the orphaned child is an ordinary rowid table or a
/// WITHOUT ROWID table whose `PRAGMA foreign_key_check` row identity is NULL.
/// The NULL identity is reported truthfully, never decoded into an opaque
/// sqlite error, defaulted into a row number, or accepted as pristine.
#[test]
fn foreign_key_damage_in_rowid_and_without_rowid_children_refuses_and_fences_the_owner() {
    // An ordinary rowid child: the diagnostic names the offending rowid.
    {
        let fixture = fixture();
        {
            let connection = fixture.store.connection().expect("connection");
            connection
                .execute_batch("PRAGMA foreign_keys = OFF;")
                .expect("disable foreign keys");
            connection
                .execute(
                    "INSERT INTO admission_operation_tool_requests (operation_id, request_json)
                     VALUES ('orphaned-operation', X'7b7d')",
                    [],
                )
                .expect("insert orphaned rowid child");
            connection
                .execute_batch("PRAGMA foreign_keys = ON;")
                .expect("enable foreign keys");
        }
        let refused = fixture.store.list_recoverable(now_ms(), None, 10);
        assert!(
            matches!(
                &refused,
                Err(AdmissionOperationStoreError::Invariant(detail))
                    if detail == "invalid sqlite authority store: sqlite foreign key violation in `admission_operation_tool_requests` row 1"
            ),
            "{refused:?}"
        );
        let fenced = fixture.store.list_recoverable(now_ms(), None, 10);
        assert!(
            matches!(
                &fenced,
                Err(AdmissionOperationStoreError::OutcomeUnknown(detail))
                    if detail == "sqlite authority owner is poisoned after an outcome-unknown anchor sync"
            ),
            "{fenced:?}"
        );
    }
    // A WITHOUT ROWID child: SQLite reports a NULL row identity, and the
    // diagnostic reports that truth instead of failing to decode it.
    {
        let fixture = fixture();
        {
            let connection = fixture.store.connection().expect("connection");
            connection
                .execute_batch("PRAGMA foreign_keys = OFF;")
                .expect("disable foreign keys");
            connection
                .execute(
                    "INSERT INTO runtime_replay_migration_events
                     (runtime_authority_id, sequence, mutation_kind, expectation_digest,
                      inventory_sha256, event_digest, observed_at_unix_ms, store_uuid,
                      store_lease_id, store_owner_epoch)
                     VALUES ('orphaned-runtime', 1, 'expect_runtime_replay_source',
                             printf('%064d', 0), printf('%064d', 0), printf('%064d', 0),
                             1, ?1, ?2, ?3)",
                    params![
                        &fixture.fence.store_uuid,
                        &fixture.fence.lease_id,
                        i64::try_from(fixture.fence.owner_epoch).expect("epoch")
                    ],
                )
                .expect("insert orphaned without rowid child");
            connection
                .execute_batch("PRAGMA foreign_keys = ON;")
                .expect("enable foreign keys");
        }
        let refused = fixture.store.list_recoverable(now_ms(), None, 10);
        assert!(
            matches!(
                &refused,
                Err(AdmissionOperationStoreError::Invariant(detail))
                    if detail == "invalid sqlite authority store: sqlite foreign key violation in `runtime_replay_migration_events` row NULL (WITHOUT ROWID table)"
            ),
            "{refused:?}"
        );
        let fenced = fixture.store.list_recoverable(now_ms(), None, 10);
        assert!(
            matches!(
                &fenced,
                Err(AdmissionOperationStoreError::OutcomeUnknown(detail))
                    if detail == "sqlite authority owner is poisoned after an outcome-unknown anchor sync"
            ),
            "{fenced:?}"
        );
    }
}

#[test]
fn stale_owner_fences_reads_and_mutations() {
    let fixture = fixture();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-fence",
        "capability-fence",
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, now_ms())
        .expect("begin");

    let connection = Connection::open(&fixture.database).expect("tamper connection");
    connection
        .execute(
            r#"
            UPDATE chio_serving_owner
            SET owner_epoch = ?1, lease_id = 'replacement-lease'
            WHERE singleton = 1
            "#,
            params![i64::try_from(fixture.fence.owner_epoch + 1).expect("epoch")],
        )
        .expect("advance owner");
    assert!(matches!(
        fixture
            .store
            .load_by_operation_id(operation.binding().operation_id()),
        Err(AdmissionOperationStoreError::Fenced)
    ));
    assert!(matches!(
        fixture.store.begin(&operation, &fixture.fence, now_ms()),
        Err(AdmissionOperationStoreError::Fenced)
    ));
}

#[test]
fn a_new_serving_epoch_reclaims_an_unexpired_stale_owner_lease() {
    let temp = tempfile::tempdir().expect("tempdir");
    secure_directory(temp.path());
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    create_lock_root(&lock_root);
    SqliteAuthorityStore::provision(&database, &lock_root).expect("provision");
    let first = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("first owner");
    let first_fence = first.mutation_fence();
    let first_store = first.admission_operation_store();
    let operation = prepared_operation(
        &first_fence,
        AdmissionOperationKind::ToolDispatch,
        "request-owner-rotation",
        "capability-owner-rotation",
    );
    let begun_at = now_ms();
    first_store
        .begin(&operation, &first_fence, begun_at)
        .expect("begin");
    let now = begun_at + 1;
    first_store
        .claim_recovery(
            operation.binding().operation_id(),
            1,
            &identifier("claimant_id", "old-worker"),
            now,
            now + 100_000,
            &first_fence,
        )
        .expect("old claim");
    drop(first_store);
    drop(first);

    let second = SqliteAuthorityStore::open_serving(&database, &lock_root).expect("second owner");
    let second_fence = second.mutation_fence();
    let second_store = second.admission_operation_store();
    assert_eq!(
        second_store
            .list_recoverable(now + 1, None, 10)
            .expect("recover stale owner"),
        vec![operation.clone()]
    );
    let lease = second_store
        .claim_recovery(
            operation.binding().operation_id(),
            1,
            &identifier("claimant_id", "new-worker"),
            now + 1,
            now + 10_000,
            &second_fence,
        )
        .expect("new claim");
    assert_eq!(lease.store_fence(), &second_fence);
    assert_eq!(lease.coordinator_lease_id().as_str(), first_fence.lease_id);
    assert_eq!(lease.coordinator_lease_epoch(), first_fence.owner_epoch);

    let advance = |current: &AdmissionOperationV1,
                   state: AdmissionOperationState,
                   attachments: Vec<AdmissionAttachment>,
                   time: u64| {
        let lease = second_store
            .claim_recovery(
                current.binding().operation_id(),
                current.version(),
                &identifier("claimant_id", "new-worker"),
                time,
                time + 10_000,
                &second_fence,
            )
            .expect("claim next version");
        assert_eq!(lease.coordinator_lease_id().as_str(), first_fence.lease_id);
        assert_eq!(lease.coordinator_lease_epoch(), first_fence.owner_epoch);
        second_store
            .compare_and_swap(&command(current, lease, attachments, state, None), time + 1)
            .expect("advance recovered operation")
            .into_operation()
    };
    let broker_registered = advance(
        &operation,
        AdmissionOperationState::BrokerAttemptRegistered,
        vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
            &operation,
            "attempt-rotated-owner",
        ))],
        now + 2,
    );
    let budget_authorized = advance(
        &broker_registered,
        AdmissionOperationState::BudgetAuthorized,
        vec![AdmissionAttachment::BudgetHoldId(identifier(
            "budget_hold_id",
            "rotated-owner-hold",
        ))],
        now + 4,
    );
    let ready = advance(
        &budget_authorized,
        AdmissionOperationState::ReadyToDispatch,
        Vec::new(),
        now + 6,
    );
    let capture_pending = advance(
        &ready,
        AdmissionOperationState::CapturePending,
        Vec::new(),
        now + 8,
    );
    let dispatched = advance(
        &capture_pending,
        AdmissionOperationState::DispatchCommitted,
        Vec::new(),
        now + 10,
    );
    let finalizing = advance(
        &dispatched,
        AdmissionOperationState::Finalizing,
        vec![AdmissionAttachment::ToolOutcomeId(digest(
            "tool_outcome_id",
            'f',
        ))],
        now + 12,
    );
    let dispatch_commit = finalizing.dispatch_commit().expect("dispatch commit");
    assert_eq!(
        dispatch_commit.coordinator_lease_id.as_str(),
        first_fence.lease_id
    );
    assert_eq!(
        dispatch_commit.coordinator_lease_epoch,
        first_fence.owner_epoch
    );
    assert_eq!(&dispatch_commit.store_fence, &second_fence);
}

#[test]
fn transaction_failures_leave_no_partial_begin_or_cas_commit() {
    let fixture = fixture();
    let begun_at = now_ms();
    let first = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-rollback-begin",
        "capability-rollback-begin",
    );
    {
        let connection = fixture.store.connection().expect("connection");
        connection
            .execute_batch(
                r#"
                CREATE TEMP TRIGGER fail_admission_begin
                BEFORE UPDATE ON admission_operation_commit_meta
                BEGIN
                    SELECT RAISE(ROLLBACK, 'injected begin rollback');
                END;
                "#,
            )
            .expect("install failure");
    }
    assert!(fixture
        .store
        .begin(&first, &fixture.fence, begun_at)
        .is_err());
    {
        let connection = fixture.store.connection().expect("connection");
        connection
            .execute_batch("DROP TRIGGER fail_admission_begin")
            .expect("drop failure");
    }
    assert!(fixture
        .store
        .load_by_operation_id(first.binding().operation_id())
        .expect("load")
        .is_none());

    let second = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-rollback-cas",
        "capability-rollback-cas",
    );
    fixture
        .store
        .begin(&second, &fixture.fence, begun_at)
        .expect("begin second");
    let now = begun_at + 1;
    let lease = claim(&fixture, &second, "worker-rollback", now);
    {
        let connection = fixture.store.connection().expect("connection");
        connection
            .execute_batch(
                r#"
                CREATE TEMP TRIGGER fail_admission_cas
                BEFORE UPDATE ON admission_operation_commit_meta
                BEGIN
                    SELECT RAISE(ROLLBACK, 'injected CAS rollback');
                END;
                "#,
            )
            .expect("install failure");
    }
    assert!(fixture
        .store
        .compare_and_swap(
            &command(
                &second,
                lease,
                vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &second,
                    "attempt-rollback",
                ))],
                AdmissionOperationState::BrokerAttemptRegistered,
                None,
            ),
            now + 1,
        )
        .is_err());
    {
        let connection = fixture.store.connection().expect("connection");
        connection
            .execute_batch("DROP TRIGGER fail_admission_cas")
            .expect("drop failure");
        verify_admission_operation_invariants(&connection).expect("valid projection");
    }
    let loaded = fixture
        .store
        .load_by_operation_id(second.binding().operation_id())
        .expect("load")
        .expect("operation");
    assert_eq!(loaded.state(), AdmissionOperationState::Prepared);
    assert_eq!(loaded.version(), 1);
}

#[test]
fn commit_log_binds_each_mutation_to_the_active_serving_lease() {
    let fixture = fixture();
    let begun_at = now_ms();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-commit-log",
        "capability-commit-log",
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, begun_at)
        .expect("begin");
    let now = begun_at + 1;
    let lease = claim(&fixture, &operation, "worker-log", now);
    assert!(matches!(
        fixture.store.compare_and_swap(
            &command(
                &operation,
                lease.clone(),
                vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &operation,
                    "attempt-log",
                ))],
                AdmissionOperationState::BrokerAttemptRegistered,
                None,
            ),
            now - 1,
        ),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    fixture
        .store
        .compare_and_swap(
            &command(
                &operation,
                lease,
                vec![AdmissionAttachment::BrokerAttempt(provider_attempt(
                    &operation,
                    "attempt-log",
                ))],
                AdmissionOperationState::BrokerAttemptRegistered,
                None,
            ),
            now + 1,
        )
        .expect("CAS");

    let connection = fixture.store.connection().expect("connection");
    let mut statement = connection
        .prepare(
            r#"
            SELECT mutation_kind, operation_version, store_uuid,
                   store_lease_id, store_owner_epoch
            FROM admission_operation_commits
            WHERE operation_id = ?1
            ORDER BY commit_sequence
            "#,
        )
        .expect("prepare");
    let commits = statement
        .query_map([operation.binding().operation_id().as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })
        .expect("query")
        .collect::<Result<Vec<_>, _>>()
        .expect("commits");
    assert_eq!(
        commits
            .iter()
            .map(|commit| (commit.0.as_str(), commit.1))
            .collect::<Vec<_>>(),
        vec![("begin", 1), ("recovery_claim", 1), ("compare_and_swap", 2)]
    );
    assert!(commits.iter().all(|commit| {
        commit.2 == fixture.fence.store_uuid
            && commit.3 == fixture.fence.lease_id
            && u64::try_from(commit.4).ok() == Some(fixture.fence.owner_epoch)
    }));
}

#[test]
fn corrupt_rows_and_partial_current_schema_fail_closed() {
    let fixture = fixture();
    let begun_at = now_ms();
    let operation = prepared_operation(
        &fixture.fence,
        AdmissionOperationKind::ToolDispatch,
        "request-corrupt",
        "capability-corrupt",
    );
    fixture
        .store
        .begin(&operation, &fixture.fence, begun_at)
        .expect("begin");
    {
        let connection = fixture.store.connection().expect("connection");
        connection
            .execute(
                "UPDATE admission_operations SET operation_json = X'7b', version = version + 1 WHERE operation_id = ?1",
                [operation.binding().operation_id().as_str()],
            )
            .expect("inject corrupt row");
    }
    assert!(matches!(
        fixture
            .store
            .load_by_operation_id(operation.binding().operation_id()),
        Err(AdmissionOperationStoreError::Invariant(_))
    ));
    assert!(verify_admission_operation_invariants(
        &fixture.store.connection().expect("connection")
    )
    .is_err());

    let clean = self::fixture();
    {
        let connection = clean.store.connection().expect("connection");
        connection
            .execute_batch("DROP INDEX admission_operation_commits_operation")
            .expect("drop index");
    }
    assert!(
        verify_admission_operation_invariants(&clean.store.connection().expect("connection"))
            .is_err()
    );
    let database = clean.database.clone();
    let lock_root = clean.lock_root.clone();
    drop(clean.store);
    drop(clean.authority);
    assert!(matches!(
        SqliteAuthorityStore::open_serving(database, lock_root),
        Err(SqliteServingOwnerError::Invalid(_))
    ));
}
