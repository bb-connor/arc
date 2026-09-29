use super::*;


    #[test]
fn expired_terminal_cleanup_rolls_back_the_batch_on_late_corruption() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("terminal-cleanup-rollback.sqlite");
    let now_unix_ms = current_unix_ms();
    let clock = Arc::new(SqliteTestClock(AtomicU64::new(now_unix_ms)));
    let store = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            &path,
            Arc::clone(&clock) as Arc<dyn Clock>,
        )
        .unwrap_or_else(|error| panic!("rollback security store: {error}")),
    );
    let plans = ["action-cleanup-rollback-a", "action-cleanup-rollback-b"]
        .into_iter()
        .map(|action_id| {
            install_due_sqlite_plan(&store, action_id, now_unix_ms.saturating_sub(1))
        })
        .collect::<Vec<_>>();
    let port = sqlite_worker_port(
        Arc::clone(&store),
        Arc::clone(&clock),
        "worker-cleanup-rollback",
        "incarnation-cleanup-rollback-first",
        100,
    );
    let initial_work = port
        .claim(0)
        .unwrap_or_else(|error| panic!("rollback initial claim: {error}"));
    assert_eq!(initial_work.len(), 2);
    let mut terminal_work = Vec::with_capacity(initial_work.len());
    for (index, work) in initial_work.iter().enumerate() {
        let plan = plans
            .iter()
            .find(|plan| plan.action_id == work.action_id)
            .unwrap_or_else(|| panic!("rollback plan missing"));
        let reclaimed = record_retry_and_reclaim(
            &store,
            &clock,
            &port,
            work,
            u64::try_from(index)
                .unwrap_or_else(|error| panic!("rollback tick conversion: {error}"))
                .saturating_add(1),
            RecordId::new(format!(
                "cleanup-rollback-retry-{}",
                work.action_id.as_str()
            ))
            .unwrap_or_else(|error| panic!("rollback retry transition: {error}")),
        );
        ResponseStateMachine::new(Arc::clone(&store))
            .transition_scheduled(
                plan,
                &reclaimed,
                &ResponseTransitionRequest {
                    expected_generation: plan.generation,
                    target_state: ResponseState::Cancelled,
                    occurred_at_unix_ms: clock.now(),
                    applying_lease_expires_at_unix_ms: None,
                    error_code: None,
                },
            )
            .unwrap_or_else(|error| panic!("rollback terminal transition: {error}"));
        terminal_work.push(reclaimed);
    }
    let cleanup_now = terminal_work
        .iter()
        .map(|work| work.lease_expires_at_unix_ms)
        .max()
        .unwrap_or_else(|| panic!("rollback expiry missing"))
        .saturating_add(1);
    drop(port);
    drop(store);
    clock.set(cleanup_now);

    let reopened = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            &path,
            Arc::clone(&clock) as Arc<dyn Clock>,
        )
        .unwrap_or_else(|error| panic!("rollback store reopen: {error}")),
    );
    let restarted = sqlite_worker_port(
        reopened,
        clock,
        "worker-cleanup-rollback",
        "incarnation-cleanup-rollback-restart",
        100,
    );
    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("rollback corruption connection: {error}"));
    connection
        .execute(
            r#"
            UPDATE security_response_plans
            SET body_hash = zeroblob(32)
            WHERE tenant_id = ?1 AND action_id = ?2
            "#,
            rusqlite::params![
                terminal_work[1].tenant_id.as_str(),
                terminal_work[1].action_id.as_str()
            ],
        )
        .unwrap_or_else(|error| panic!("rollback corruption write: {error}"));
    drop(connection);

    assert!(restarted.claim(0).is_err());
    let connection = rusqlite::Connection::open(path)
        .unwrap_or_else(|error| panic!("rollback readback connection: {error}"));
    let durable_counts = connection
        .query_row(
            r#"
            SELECT
                (SELECT COUNT(*) FROM security_scheduler_leases),
                (SELECT COUNT(*) FROM security_scheduler_retries),
                (SELECT COUNT(*) FROM security_transitions
                 WHERE transition_kind = 'scheduler_expired_terminal_cleanup')
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
        .unwrap_or_else(|error| panic!("rollback durable counts: {error}"));
    assert_eq!(durable_counts, (2, 2, 0));
}
