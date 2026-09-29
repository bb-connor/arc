use super::*;


#[test]
fn sqlite_worker_claims_simultaneously_due_actions_transactionally_in_deterministic_order() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let now_unix_ms = current_unix_ms();
    let clock = Arc::new(SqliteTestClock(AtomicU64::new(now_unix_ms)));
    let store = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            directory.path().join("response-order.sqlite"),
            Arc::clone(&clock) as Arc<dyn Clock>,
        )
        .unwrap_or_else(|error| panic!("security store: {error}")),
    );
    let due_at_unix_ms = now_unix_ms.saturating_sub(1);
    for action_id in ["action-order-z", "action-order-a", "action-order-m"] {
        install_due_sqlite_plan(&store, action_id, due_at_unix_ms);
    }
    let first_port = sqlite_worker_port(
        Arc::clone(&store),
        Arc::clone(&clock),
        "worker-sqlite-order",
        "incarnation-sqlite-order-first",
        100,
    );

    let claimed = first_port
        .claim(0)
        .unwrap_or_else(|error| panic!("ordered claim: {error}"));
    let claimed_action_ids = claimed
        .iter()
        .map(|work| work.action_id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        claimed_action_ids,
        vec!["action-order-a", "action-order-m", "action-order-z"]
    );
    assert!(claimed
        .array_windows::<2>()
        .all(|pair| pair[0].fencing_token < pair[1].fencing_token));
    for work in &claimed {
        store
            .validate_lease(work)
            .unwrap_or_else(|error| panic!("claimed lease is invalid: {error}"));
    }

    let contender = sqlite_worker_port(
        Arc::clone(&store),
        Arc::clone(&clock),
        "worker-sqlite-order-contender",
        "incarnation-sqlite-order-contender",
        100,
    );
    assert!(contender
        .claim(0)
        .unwrap_or_else(|error| panic!("competing claim: {error}"))
        .is_empty());
    drop(contender);
    drop(first_port);

    clock.set(claimed[0].lease_expires_at_unix_ms.saturating_add(1));
    let restarted_port = sqlite_worker_port(
        Arc::clone(&store),
        Arc::clone(&clock),
        "worker-sqlite-order",
        "incarnation-sqlite-order-takeover",
        100,
    );
    let replayed = restarted_port
        .claim(0)
        .unwrap_or_else(|error| panic!("takeover ordered claim: {error}"));
    assert_eq!(
        replayed
            .iter()
            .map(|work| work.action_id.as_str())
            .collect::<Vec<_>>(),
        claimed_action_ids
    );
    assert!(replayed.iter().zip(&claimed).all(|(successor, stale)| {
        successor.lease_owner_id == stale.lease_owner_id
            && successor.fencing_token > stale.fencing_token
    }));
    let restarted = ProductionResponseWorker::new_for_test(restarted_port)
        .unwrap_or_else(|error| panic!("restarted worker: {error}"));
    restarted
        .complete_shutdown_after_loop()
        .unwrap_or_else(|error| panic!("restarted worker shutdown: {error}"));

    let failure_path = directory
        .path()
        .join("response-order-atomic-failure.sqlite");
    let failure_clock = Arc::new(SqliteTestClock(AtomicU64::new(now_unix_ms)));
    let failure_store = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            &failure_path,
            Arc::clone(&failure_clock) as Arc<dyn Clock>,
        )
        .unwrap_or_else(|error| panic!("failure security store: {error}")),
    );
    for action_id in [
        "action-order-atomic-z",
        "action-order-atomic-a",
        "action-order-atomic-m",
    ] {
        install_due_sqlite_plan(&failure_store, action_id, due_at_unix_ms);
    }
    let connection = rusqlite::Connection::open(&failure_path)
        .unwrap_or_else(|error| panic!("failure trigger connection: {error}"));
    let fence_sequence_before = connection
        .query_row(
            "SELECT COALESCE(MAX(last_fencing_token), 0) FROM security_scheduler_fence_sequences",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or_else(|error| panic!("initial fence sequence: {error}"));
    connection
        .execute_batch(
            r#"
            CREATE TRIGGER fail_scheduler_claim_mid_batch
            BEFORE INSERT ON security_scheduler_leases
            WHEN NEW.action_id = 'action-order-atomic-m'
            BEGIN
                SELECT RAISE(ABORT, 'forced scheduler claim failure');
            END;
            "#,
        )
        .unwrap_or_else(|error| panic!("install claim failure trigger: {error}"));
    drop(connection);
    let failure_port = sqlite_worker_port(
        Arc::clone(&failure_store),
        failure_clock,
        "worker-sqlite-order-atomic-failure",
        "incarnation-sqlite-order-atomic-failure",
        5_000,
    );
    assert!(failure_port.claim(0).is_err());

    let connection = rusqlite::Connection::open(failure_path)
        .unwrap_or_else(|error| panic!("failure readback connection: {error}"));
    let durable_counts = connection
        .query_row(
            r#"
            SELECT
                (SELECT COUNT(*) FROM security_scheduler_leases),
                (SELECT COUNT(*) FROM security_scheduler_claims),
                (SELECT COALESCE(MAX(last_fencing_token), 0)
                   FROM security_scheduler_fence_sequences)
            "#,
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .unwrap_or_else(|error| panic!("claim rollback readback: {error}"));
    assert_eq!(durable_counts, (0, 0, fence_sequence_before));
}
