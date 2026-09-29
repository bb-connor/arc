use crate::security::scheduler_worker::tests::*;
use super::*;


#[test]
fn sqlite_worker_restart_replays_lost_claim_ack_and_shutdown_releases_lease() {
    let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("response-worker.sqlite");
    let now_unix_ms = current_unix_ms();
    let clock = Arc::new(SqliteTestClock(AtomicU64::new(now_unix_ms)));
    let first_store = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            &path,
            Arc::clone(&clock) as Arc<dyn Clock>,
        )
        .unwrap_or_else(|error| panic!("security store: {error}")),
    );
    install_due_sqlite_plan(
        &first_store,
        "action-sqlite-restart",
        now_unix_ms.saturating_sub(1),
    );
    let first_port = sqlite_worker_port(
        Arc::clone(&first_store),
        Arc::clone(&clock),
        "worker-sqlite-restart",
        "incarnation-sqlite-restart-first",
        100,
    );
    let claimed = first_port
        .claim(0)
        .unwrap_or_else(|error| panic!("first claim: {error}"));
    assert_eq!(claimed.len(), 1);
    drop(first_port);
    drop(first_store);

    let reopened_store = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            &path,
            Arc::clone(&clock) as Arc<dyn Clock>,
        )
        .unwrap_or_else(|error| panic!("reopen security store: {error}")),
    );
    let same_owner_port = sqlite_worker_port(
        Arc::clone(&reopened_store),
        Arc::clone(&clock),
        "worker-sqlite-restart",
        "incarnation-sqlite-restart-live",
        100,
    );
    assert!(same_owner_port
        .claim(0)
        .unwrap_or_else(|error| panic!("live same-owner claim: {error}"))
        .is_empty());
    reopened_store
        .validate_lease(&claimed[0])
        .unwrap_or_else(|error| panic!("live restart changed prior lease: {error}"));
    drop(same_owner_port);

    let takeover_now_unix_ms = claimed[0].lease_expires_at_unix_ms.saturating_add(1);
    clock.set(takeover_now_unix_ms);
    let restarted_port = sqlite_worker_port(
        Arc::clone(&reopened_store),
        Arc::clone(&clock),
        "worker-sqlite-restart",
        "incarnation-sqlite-restart-takeover",
        100,
    );
    let takeover = restarted_port
        .claim(0)
        .unwrap_or_else(|error| panic!("takeover claim: {error}"));
    assert_eq!(takeover.len(), 1);
    assert_eq!(takeover[0].action_id, claimed[0].action_id);
    assert_eq!(takeover[0].lease_owner_id, claimed[0].lease_owner_id);
    assert!(takeover[0].fencing_token > claimed[0].fencing_token);
    let plan_key = chio_security_types::ports::ResponsePlanKey {
        tenant_id: claimed[0].tenant_id.clone(),
        action_id: claimed[0].action_id.clone(),
    };
    let before_stale_attempt = reopened_store
        .load_plan(&plan_key)
        .unwrap_or_else(|error| panic!("plan before stale attempt: {error}"));
    assert!(matches!(
        restarted_port
            .scheduler
            .process(&claimed[0], takeover_now_unix_ms),
        Ok(SchedulerWorkOutcome::LeaseLost { action_id })
            if action_id == claimed[0].action_id
    ));
    assert_eq!(
        reopened_store
            .load_plan(&plan_key)
            .unwrap_or_else(|error| panic!("plan after stale attempt: {error}")),
        before_stale_attempt
    );
    let restarted = ProductionResponseWorker::new_for_test(restarted_port)
        .unwrap_or_else(|error| panic!("restarted worker: {error}"));
    restarted
        .complete_shutdown_after_loop()
        .unwrap_or_else(|error| panic!("worker shutdown: {error}"));
    let connection = rusqlite::Connection::open(&path)
        .unwrap_or_else(|error| panic!("restart lease readback: {error}"));
    let remaining_leases = connection
        .query_row(
            "SELECT COUNT(*) FROM security_scheduler_leases WHERE tenant_id = ?1 AND action_id = ?2",
            rusqlite::params![claimed[0].tenant_id.as_str(), claimed[0].action_id.as_str()],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or_else(|error| panic!("restart lease count: {error}"));
    assert_eq!(remaining_leases, 0);

    let terminal_path = directory.path().join("response-worker-terminal.sqlite");
    let terminal_now_unix_ms = current_unix_ms();
    let terminal_clock = Arc::new(SqliteTestClock(AtomicU64::new(terminal_now_unix_ms)));
    let terminal_store = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            &terminal_path,
            Arc::clone(&terminal_clock) as Arc<dyn Clock>,
        )
        .unwrap_or_else(|error| panic!("terminal security store: {error}")),
    );
    let terminal_plan = install_due_sqlite_plan(
        &terminal_store,
        "action-sqlite-restart-terminal",
        terminal_now_unix_ms.saturating_sub(1),
    );
    let terminal_port = sqlite_worker_port(
        Arc::clone(&terminal_store),
        Arc::clone(&terminal_clock),
        "worker-sqlite-restart-terminal",
        "incarnation-sqlite-terminal-first",
        100,
    );
    let initial_terminal_work = terminal_port
        .claim(0)
        .unwrap_or_else(|error| panic!("terminal first claim: {error}"))
        .into_iter()
        .next()
        .unwrap_or_else(|| panic!("terminal first claim missing"));
    let terminal_work = record_retry_and_reclaim(
        &terminal_store,
        &terminal_clock,
        &terminal_port,
        &initial_terminal_work,
        1,
        RecordId::new("terminal-recovery-retry")
            .unwrap_or_else(|error| panic!("terminal retry transition: {error}")),
    );
    ResponseStateMachine::new(Arc::clone(&terminal_store))
        .transition_scheduled(
            &terminal_plan,
            &terminal_work,
            &ResponseTransitionRequest {
                expected_generation: terminal_plan.generation,
                target_state: ResponseState::Cancelled,
                occurred_at_unix_ms: terminal_clock.now(),
                applying_lease_expires_at_unix_ms: None,
                error_code: None,
            },
        )
        .unwrap_or_else(|error| panic!("terminal transition: {error}"));
    drop(terminal_port);
    drop(terminal_store);

    let terminal_reopened = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            &terminal_path,
            Arc::clone(&terminal_clock) as Arc<dyn Clock>,
        )
        .unwrap_or_else(|error| panic!("terminal store reopen: {error}")),
    );
    let terminal_restarted = sqlite_worker_port(
        Arc::clone(&terminal_reopened),
        Arc::clone(&terminal_clock),
        "worker-sqlite-restart-terminal",
        "incarnation-sqlite-terminal-restart",
        100,
    );
    assert!(terminal_restarted
        .claim(0)
        .unwrap_or_else(|error| panic!("live terminal restart claim: {error}"))
        .is_empty());
    let connection = rusqlite::Connection::open(&terminal_path)
        .unwrap_or_else(|error| panic!("live terminal readback: {error}"));
    let live_terminal_counts = connection
        .query_row(
            r#"
            SELECT
                (SELECT COUNT(*) FROM security_scheduler_leases
                 WHERE tenant_id = ?1 AND action_id = ?2),
                (SELECT COUNT(*) FROM security_scheduler_retries
                 WHERE tenant_id = ?1 AND action_id = ?2)
            "#,
            rusqlite::params![
                terminal_work.tenant_id.as_str(),
                terminal_work.action_id.as_str()
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .unwrap_or_else(|error| panic!("live terminal counts: {error}"));
    assert_eq!(live_terminal_counts, (1, 1));
    drop(connection);

    terminal_clock.set(terminal_work.lease_expires_at_unix_ms.saturating_add(1));
    assert!(terminal_restarted
        .claim(1)
        .unwrap_or_else(|error| panic!("expired terminal cleanup: {error}"))
        .is_empty());
    let connection = rusqlite::Connection::open(terminal_path)
        .unwrap_or_else(|error| panic!("terminal cleanup readback: {error}"));
    let terminal_cleanup_counts = connection
        .query_row(
            r#"
            SELECT
                (SELECT COUNT(*) FROM security_scheduler_leases
                 WHERE tenant_id = ?1 AND action_id = ?2),
                (SELECT COUNT(*) FROM security_scheduler_retries
                 WHERE tenant_id = ?1 AND action_id = ?2)
            "#,
            rusqlite::params![
                terminal_work.tenant_id.as_str(),
                terminal_work.action_id.as_str()
            ],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .unwrap_or_else(|error| panic!("terminal cleanup counts: {error}"));
    assert_eq!(terminal_cleanup_counts, (0, 0));

    let batch_path = directory
        .path()
        .join("response-worker-terminal-batch.sqlite");
    let batch_now_unix_ms = current_unix_ms();
    let batch_clock = Arc::new(SqliteTestClock(AtomicU64::new(batch_now_unix_ms)));
    let batch_store = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            &batch_path,
            Arc::clone(&batch_clock) as Arc<dyn Clock>,
        )
        .unwrap_or_else(|error| panic!("terminal batch store: {error}")),
    );
    let batch_plans = (0..9)
        .map(|index| {
            install_due_sqlite_plan(
                &batch_store,
                &format!("action-sqlite-terminal-batch-{index}"),
                batch_now_unix_ms.saturating_sub(1),
            )
        })
        .collect::<Vec<_>>();
    let batch_port = sqlite_worker_port(
        Arc::clone(&batch_store),
        Arc::clone(&batch_clock),
        "worker-sqlite-terminal-batch",
        "incarnation-sqlite-terminal-batch-first",
        100,
    );
    let mut initial_batch_work = batch_port
        .claim(0)
        .unwrap_or_else(|error| panic!("terminal batch first claim: {error}"));
    initial_batch_work.extend(
        batch_port
            .claim(1)
            .unwrap_or_else(|error| panic!("terminal batch second claim: {error}")),
    );
    assert_eq!(initial_batch_work.len(), 9);
    let mut batch_work = Vec::with_capacity(initial_batch_work.len());
    for (index, initial_work) in initial_batch_work.iter().enumerate() {
        let plan = batch_plans
            .iter()
            .find(|plan| plan.action_id == initial_work.action_id)
            .unwrap_or_else(|| panic!("terminal batch plan missing"));
        let tick_sequence = u64::try_from(index)
            .unwrap_or_else(|error| panic!("terminal batch tick conversion: {error}"))
            .saturating_add(10);
        let work = record_retry_and_reclaim(
            &batch_store,
            &batch_clock,
            &batch_port,
            initial_work,
            tick_sequence,
            RecordId::new(format!(
                "terminal-batch-retry-{}",
                initial_work.action_id.as_str()
            ))
            .unwrap_or_else(|error| panic!("terminal batch retry transition: {error}")),
        );
        ResponseStateMachine::new(Arc::clone(&batch_store))
            .transition_scheduled(
                plan,
                &work,
                &ResponseTransitionRequest {
                    expected_generation: plan.generation,
                    target_state: ResponseState::Cancelled,
                    occurred_at_unix_ms: batch_clock.now(),
                    applying_lease_expires_at_unix_ms: None,
                    error_code: None,
                },
            )
            .unwrap_or_else(|error| panic!("terminal batch transition: {error}"));
        batch_work.push(work);
    }
    let batch_expiry = batch_work
        .iter()
        .map(|work| work.lease_expires_at_unix_ms)
        .max()
        .unwrap_or_else(|| panic!("terminal batch expiry missing"));
    drop(batch_port);
    drop(batch_store);

    batch_clock.set(batch_expiry.saturating_add(1));
    let batch_reopened = Arc::new(
        SqliteSecurityStateStore::open_with_trusted_clock(
            &batch_path,
            Arc::clone(&batch_clock) as Arc<dyn Clock>,
        )
        .unwrap_or_else(|error| panic!("terminal batch reopen: {error}")),
    );
    let batch_restarted = sqlite_worker_port(
        batch_reopened,
        batch_clock,
        "worker-sqlite-terminal-batch",
        "incarnation-sqlite-terminal-batch-restart",
        100,
    );
    assert!(matches!(
        batch_restarted.claim(0),
        Err(ResponseWorkerTickError::TerminalSchedulerCleanupPending)
    ));
    let connection = rusqlite::Connection::open(&batch_path)
        .unwrap_or_else(|error| panic!("terminal batch continuation readback: {error}"));
    let continuation_counts = connection
        .query_row(
            r#"
            SELECT
                (SELECT COUNT(*) FROM security_scheduler_leases),
                (SELECT COUNT(*) FROM security_scheduler_retries)
            "#,
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .unwrap_or_else(|error| panic!("terminal batch continuation counts: {error}"));
    assert_eq!(continuation_counts, (1, 1));
    drop(connection);
    assert!(batch_restarted
        .claim(1)
        .unwrap_or_else(|error| panic!("terminal batch final cleanup: {error}"))
        .is_empty());
    let connection = rusqlite::Connection::open(batch_path)
        .unwrap_or_else(|error| panic!("terminal batch cleanup readback: {error}"));
    let batch_cleanup_counts = connection
        .query_row(
            r#"
            SELECT
                (SELECT COUNT(*) FROM security_scheduler_leases),
                (SELECT COUNT(*) FROM security_scheduler_retries)
            "#,
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
        )
        .unwrap_or_else(|error| panic!("terminal batch cleanup counts: {error}"));
    assert_eq!(batch_cleanup_counts, (0, 0));
}
