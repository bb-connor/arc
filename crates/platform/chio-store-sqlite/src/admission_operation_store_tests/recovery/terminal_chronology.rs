//! Native terminal apply time remains sealed as later status events advance.
use super::*;
use chio_kernel::admission_operation::{
    AdmissionRecoveryDeferralClear, AdmissionRecoveryDeferralWrite, AdmissionRecoveryStatusV1,
};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
type SealedProjectionRecord = (String, String, String, Vec<u8>);
type SealedProjection = (Vec<u8>, Vec<u8>, String, i64, Vec<SealedProjectionRecord>);

fn terminal_with_status(
    label: &str,
) -> TestResult<(
    Fixture,
    AdmissionOperationV1,
    AdmissionTerminalProjection,
    AdmissionRecoveryStatusV1,
    u64,
)> {
    let fixture = fixture();
    let at = now_ms();
    let operation = finalizing_tool_operation(&fixture, label, "terminal-history-capability", at);
    let lease = claim(&fixture, &operation, "projection-worker", at + 25);
    let marker = super::deferred_status::deferral(&operation, None, at + 25)?;
    let status = fixture
        .store
        .defer_recovery(AdmissionRecoveryDeferralWrite {
            operation: &operation,
            lease: &lease,
            expected: None,
            deferral: &marker,
            fence: &fixture.fence,
            trusted_now_unix_ms: at + 25,
        })?;
    let projection = unknown_projection(
        &fixture,
        &operation,
        "terminal-history-incident",
        'd',
        at + 30,
    );
    let first = fixture.store.commit_terminal_projection(&projection)?;
    let terminal = fixture
        .store
        .load_by_operation_id(operation.binding().operation_id())?
        .ok_or("original terminal")?;
    assert_eq!(
        terminal.state(),
        AdmissionOperationState::OutcomeUnknownAfterDispatch
    );
    assert_eq!(terminal.version(), operation.version() + 1);
    assert_eq!(terminal.terminal_replay(), Some(&first.replay));
    Ok((fixture, terminal, projection, status, at + 40))
}

fn clear_later(
    fixture: &Fixture,
    terminal: &AdmissionOperationV1,
    status: &AdmissionRecoveryStatusV1,
    at: u64,
) -> TestResult {
    fixture
        .store
        .clear_recovery_deferral(AdmissionRecoveryDeferralClear {
            operation: terminal,
            lease: None,
            expected: status,
            fence: &fixture.fence,
            trusted_now_unix_ms: at,
        })?;
    Ok(())
}

fn sealed_projection(
    fixture: &Fixture,
    terminal: &AdmissionOperationV1,
) -> TestResult<SealedProjection> {
    let connection = fixture.store.connection()?;
    let (body, manifest, digest, at) = connection.query_row(
        "SELECT projection_json,manifest_json,projection_digest,committed_at_unix_ms
         FROM admission_operation_terminal_projections WHERE operation_id=?1",
        [terminal.binding().operation_id().as_str()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    let mut statement = connection.prepare("SELECT record_kind,record_id,record_digest,record_json
        FROM admission_operation_terminal_records WHERE operation_id=?1 ORDER BY record_kind,record_id")?;
    let records = statement
        .query_map([terminal.binding().operation_id().as_str()], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok((body, manifest, digest, at, records))
}

fn require_invariant<T>(result: Result<T, AdmissionOperationStoreError>, expected: &str) {
    match result {
        Err(AdmissionOperationStoreError::Invariant(detail)) => assert_eq!(detail, expected),
        Err(_) => panic!("native corruption must retain its exact invariant family"),
        Ok(_) => panic!("native controlled corruption was accepted"),
    }
}

#[test]
fn native_terminal_later_clear_preserves_sealed_projection_and_fresh_journal_time() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1_800_000_600);
    let (fixture, terminal, projection, status, clear_at) =
        terminal_with_status("terminal-clear-chronology")?;
    let before = sealed_projection(&fixture, &terminal)?;
    clear_later(&fixture, &terminal, &status, clear_at)?;
    let connection = fixture.store.connection()?;
    let (updated, latest, kind): (i64,i64,String) = connection.query_row(
        "SELECT o.updated_at_unix_ms,c.recorded_at_unix_ms,c.mutation_kind
         FROM admission_operations o JOIN admission_operation_commits c ON c.operation_id=o.operation_id
         WHERE o.operation_id=?1 ORDER BY c.commit_sequence DESC LIMIT 1",
        [terminal.binding().operation_id().as_str()], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
    assert_eq!(u64::try_from(updated)?, clear_at);
    assert_eq!(updated, latest);
    assert_eq!(kind, "recovery_deferral_cleared");
    assert!(updated > before.3);
    verify_admission_commit_chain(&connection)?;
    drop(connection);
    assert_eq!(sealed_projection(&fixture, &terminal)?, before);
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(terminal.binding().operation_id())?,
        Some(terminal.clone())
    );
    let cleared = fixture
        .store
        .load_recovery_status(terminal.binding().operation_id(), &fixture.fence, clear_at)?
        .ok_or("retained terminal tombstone")?;
    assert!(!cleared.quarantined);
    assert_eq!(cleared.deferral, status.deferral);
    assert_eq!(
        fixture.store.load_terminal_replay(&terminal.replay_key())?,
        terminal.terminal_replay().cloned()
    );
    assert_eq!(
        fixture
            .store
            .commit_terminal_projection(&projection)?
            .replay,
        terminal
            .terminal_replay()
            .cloned()
            .ok_or("original replay")?
    );
    assert_eq!(sealed_projection(&fixture, &terminal)?, before);
    Ok(())
}

#[test]
fn native_terminal_healthy_replay_survives_new_serving_owner_without_status_time_change(
) -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1_800_000_600);
    let (fixture, terminal, projection, _, _) = terminal_with_status("terminal-healthy-history")?;
    let before = sealed_projection(&fixture, &terminal)?;
    assert_eq!(
        fixture
            .store
            .commit_terminal_projection(&projection)?
            .replay,
        terminal
            .terminal_replay()
            .cloned()
            .ok_or("original replay")?
    );
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        ..
    } = fixture;
    drop(store);
    drop(authority);
    let reopened = crate::test_authority::open_serving(&database, &lock_root)?;
    let store = reopened.admission_operation_store();
    assert_eq!(
        store.load_by_operation_id(terminal.binding().operation_id())?,
        Some(terminal.clone())
    );
    assert_eq!(
        store.load_terminal_replay(&terminal.replay_key())?,
        terminal.terminal_replay().cloned()
    );
    let bytes: (Vec<u8>,Vec<u8>,String,i64) = store.connection()?.query_row(
        "SELECT projection_json,manifest_json,projection_digest,committed_at_unix_ms FROM admission_operation_terminal_projections WHERE operation_id=?1",
        [terminal.binding().operation_id().as_str()], |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?;
    assert_eq!(bytes, (before.0, before.1, before.2, before.3));
    drop(store);
    drop(reopened);
    drop(_temp);
    Ok(())
}

#[test]
fn native_terminal_history_rejects_changed_cas_time_kind_digest_claim_fence_participant_and_version(
) -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1_800_000_600);
    for change in [
        "recorded_at_unix_ms=recorded_at_unix_ms+1",
        "mutation_kind='recovery_claim'",
        "operation_digest='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'",
        "recovery_claim_digest='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'",
        "store_lease_id='changed-terminal-lease'",
        "participant_digest='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'",
        "operation_version=operation_version+1",
    ] {
        let (fixture, terminal, _, status, at) = terminal_with_status("terminal-cas-corruption")?;
        clear_later(&fixture, &terminal, &status, at)?;
        let connection = fixture.store.connection()?;
        verify_admission_commit_chain(&connection)?;
        let trigger: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE name='admission_operation_commits_immutable'",
            [],
            |row| row.get(0),
        )?;
        connection.execute_batch("DROP TRIGGER admission_operation_commits_immutable")?;
        let sql = format!("UPDATE admission_operation_commits SET {change} WHERE operation_id=?1 AND mutation_kind='compare_and_swap' AND operation_version=?2");
        let changed = connection.execute(
            &sql,
            params![
                terminal.binding().operation_id().as_str(),
                i64::try_from(terminal.version())?
            ],
        )?;
        assert_eq!(changed, 1);
        connection.execute_batch(&trigger)?;
        require_invariant(
            verify_admission_commit_chain(&connection),
            "admission operation commit chain digest is invalid",
        );
    }
    Ok(())
}

#[test]
fn native_terminal_history_rejects_removed_terminal_cas_and_reordered_sequence() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1_800_000_600);
    for remove in [true, false] {
        let (fixture, terminal, _, status, at) = terminal_with_status("terminal-cas-gap")?;
        clear_later(&fixture, &terminal, &status, at)?;
        let connection = fixture.store.connection()?;
        verify_admission_commit_chain(&connection)?;
        let name = if remove {
            "admission_operation_commits_no_delete"
        } else {
            "admission_operation_commits_immutable"
        };
        let trigger: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE name=?1",
            [name],
            |row| row.get(0),
        )?;
        connection.execute_batch(&format!("DROP TRIGGER {name}"))?;
        let sql = if remove {
            "DELETE FROM admission_operation_commits WHERE operation_id=?1 AND mutation_kind='compare_and_swap' AND operation_version=?2"
        } else {
            "UPDATE admission_operation_commits SET previous_chain_digest='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' WHERE operation_id=?1 AND mutation_kind='compare_and_swap' AND operation_version=?2"
        };
        assert_eq!(
            connection.execute(
                sql,
                params![
                    terminal.binding().operation_id().as_str(),
                    i64::try_from(terminal.version())?
                ]
            )?,
            1
        );
        connection.execute_batch(&trigger)?;
        require_invariant(
            verify_admission_commit_chain(&connection),
            "admission operation commit chain is invalid",
        );
    }
    Ok(())
}

#[test]
fn native_terminal_history_rejects_authenticated_duplicate_cas_version() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1_800_000_600);
    let (fixture, terminal, _, _, at) = terminal_with_status("terminal-duplicate-cas")?;
    let mut connection = fixture.store.connection()?;
    super::super::super::schema::verify_admission_operation_invariants(&connection)?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    let stored = load_by_operation_id_tx(&transaction, terminal.binding().operation_id())?
        .ok_or("healthy terminal source")?;
    // Fault only the logical CAS transition in this test-owned history. The
    // real append primitive seals this entry, allowing the order check to decide.
    transaction.execute(
        "UPDATE admission_operations SET updated_at_unix_ms=?1 WHERE operation_id=?2",
        params![
            i64::try_from(at)?,
            terminal.binding().operation_id().as_str()
        ],
    )?;
    append_operation_commit(
        &transaction,
        &terminal,
        &encode_operation(&terminal)?,
        stored.recovery_claim.as_ref(),
        "compare_and_swap",
        &fixture.store.serving_owner,
        at,
    )?;
    fixture.store.commit_write(transaction)?;
    fixture.store.sync_after_write(&connection)?;
    verify_admission_commit_chain(&connection)?;
    require_invariant(
        super::super::super::schema::verify_admission_operation_invariants(&connection),
        "admission operation commits regress version or trusted time",
    );
    Ok(())
}

fn append_healthy_terminal_helper(
    fixture: &Fixture,
    terminal: &AdmissionOperationV1,
    at: u64,
) -> TestResult {
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    let stored = load_by_operation_id_tx(&transaction, terminal.binding().operation_id())?
        .ok_or("healthy terminal helper source")?;
    transaction.execute(
        "UPDATE admission_operations SET updated_at_unix_ms=?1 WHERE operation_id=?2",
        params![
            i64::try_from(at)?,
            terminal.binding().operation_id().as_str()
        ],
    )?;
    append_operation_commit_with_participant(
        &transaction,
        terminal,
        &encode_operation(terminal)?,
        stored.recovery_claim.as_ref(),
        "participant_update",
        Some(digest("helper_component", 'e').as_str()),
        &fixture.store.serving_owner,
        at,
    )?;
    fixture.store.commit_write(transaction)?;
    fixture.store.sync_after_write(&connection)?;
    Ok(())
}

#[test]
fn native_terminal_history_accepts_equal_and_later_status_and_helper_tails() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1_800_000_600);
    for later in [false, true] {
        let (fixture, terminal, _, status, at) = terminal_with_status("terminal-helper-tail")?;
        let seal = sealed_projection(&fixture, &terminal)?;
        let time = if later { at } else { u64::try_from(seal.3)? };
        clear_later(&fixture, &terminal, &status, time)?;
        assert_eq!(
            fixture
                .store
                .load_by_operation_id(terminal.binding().operation_id())?,
            Some(terminal.clone())
        );
        append_healthy_terminal_helper(&fixture, &terminal, time)?;
        assert_eq!(
            fixture
                .store
                .load_by_operation_id(terminal.binding().operation_id())?,
            Some(terminal.clone())
        );
        assert_eq!(sealed_projection(&fixture, &terminal)?, seal);
    }
    Ok(())
}

#[test]
fn native_terminal_history_rejects_sealed_apply_time_swapped_to_latest_clear() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1_800_000_600);
    let (fixture, terminal, _, status, at) = terminal_with_status("terminal-swapped-seal")?;
    clear_later(&fixture, &terminal, &status, at)?;
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(terminal.binding().operation_id())?,
        Some(terminal.clone())
    );
    let connection = fixture.store.connection()?;
    let name = "admission_operation_terminal_projections_immutable";
    let trigger: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE name=?1",
        [name],
        |row| row.get(0),
    )?;
    connection.execute_batch(&format!("DROP TRIGGER {name}"))?;
    assert_eq!(connection.execute("UPDATE admission_operation_terminal_projections SET committed_at_unix_ms=?1 WHERE operation_id=?2",
        params![i64::try_from(at)?,terminal.binding().operation_id().as_str()])?,1);
    connection.execute_batch(&trigger)?;
    verify_admission_commit_chain(&connection)?;
    drop(connection);
    require_invariant(
        fixture
            .store
            .load_by_operation_id(terminal.binding().operation_id()),
        "terminal projection lacks one exact authenticated admission CAS",
    );
    Ok(())
}

#[test]
fn native_terminal_checked_scope_rejects_other_connection_and_requalifies_legitimate_head_change(
) -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1_800_000_600);
    let (fixture, terminal, _, _, at) = terminal_with_status("terminal-scope-head")?;
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    let history = CheckedHistoryScope::new(&transaction);
    history.qualify(&transaction)?;
    let other = Connection::open_with_flags(
        &fixture.database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )?;
    require_invariant(
        history.require_connection(&other),
        "checked admission history belongs to another connection",
    );
    let stored = load_by_operation_id_tx_with_history(
        &transaction,
        terminal.binding().operation_id(),
        &history,
    )?
    .ok_or("healthy scoped terminal")?;
    transaction.execute(
        "UPDATE admission_operations SET updated_at_unix_ms=?1 WHERE operation_id=?2",
        params![
            i64::try_from(at)?,
            terminal.binding().operation_id().as_str()
        ],
    )?;
    append_operation_commit_with_participant(
        &transaction,
        &terminal,
        &encode_operation(&terminal)?,
        stored.recovery_claim.as_ref(),
        "participant_update",
        Some(digest("scoped_component", 'e').as_str()),
        &fixture.store.serving_owner,
        at,
    )?;
    require_invariant(
        history.require_connection(&transaction),
        "checked admission history snapshot changed",
    );
    let fresh = CheckedHistoryScope::new(&transaction);
    fresh.qualify(&transaction)?;
    let actual = load_by_operation_id_tx_with_history(
        &transaction,
        terminal.binding().operation_id(),
        &fresh,
    )?
    .ok_or("legitimate requalified terminal")?;
    assert_eq!(actual.operation, terminal);
    drop(fresh);
    drop(history);
    drop(other);
    transaction.rollback()?;
    Ok(())
}

#[test]
fn native_terminal_checked_history_rejects_tampered_terminal_kind_without_using_raw_time(
) -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1_800_000_600);
    let (fixture, terminal, _, _, _) = terminal_with_status("terminal-head-fastpath")?;
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(terminal.binding().operation_id())?,
        Some(terminal.clone())
    );
    let connection = fixture.store.connection()?;
    let trigger: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE name='admission_operation_commits_immutable'",
        [],
        |row| row.get(0),
    )?;
    connection.execute_batch("DROP TRIGGER admission_operation_commits_immutable")?;
    assert_eq!(connection.execute("UPDATE admission_operation_commits SET mutation_kind='recovery_claim' WHERE operation_id=?1 AND operation_version=?2 AND mutation_kind='compare_and_swap'",
        params![terminal.binding().operation_id().as_str(),i64::try_from(terminal.version())?])?,1);
    connection.execute_batch(&trigger)?;
    drop(connection);
    require_invariant(
        fixture
            .store
            .load_by_operation_id(terminal.binding().operation_id()),
        "admission operation commits regress version or trusted time",
    );
    Ok(())
}

#[test]
fn native_terminal_history_rejects_corrupt_current_clear_component_before_time_binding(
) -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1_800_000_600);
    let (fixture, terminal, _, status, at) = terminal_with_status("terminal-clear-component")?;
    clear_later(&fixture, &terminal, &status, at)?;
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(terminal.binding().operation_id())?,
        Some(terminal.clone())
    );
    let connection = fixture.store.connection()?;
    connection.execute("UPDATE admission_operation_recovery_deferrals SET status_digest='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' WHERE operation_id=?1",
        [terminal.binding().operation_id().as_str()])?;
    drop(connection);
    require_invariant(
        fixture
            .store
            .load_by_operation_id(terminal.binding().operation_id()),
        "recovery status does not match its anchored canonical record",
    );
    Ok(())
}

#[test]
fn native_terminal_checked_history_rejects_same_time_authenticated_duplicate_cas() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1_800_000_600);
    let (fixture, terminal, projection, _, _) =
        terminal_with_status("terminal-same-time-duplicate")?;
    let apply_at = projection.context().trusted_time_unix_ms;
    assert_eq!(
        fixture
            .store
            .load_by_operation_id(terminal.binding().operation_id())?,
        Some(terminal.clone())
    );
    let seal = sealed_projection(&fixture, &terminal)?;
    assert_eq!(u64::try_from(seal.3)?, apply_at);
    let mut connection = fixture.store.connection()?;
    let transaction = fixture
        .store
        .begin_write(&mut connection, Some(&fixture.fence))?;
    let stored = load_by_operation_id_tx(&transaction, terminal.binding().operation_id())?
        .ok_or("healthy same-time duplicate source")?;
    // The real append seals this test-owned logical fault with the exact same
    // terminal body, claim, fence and apply time; a head-only proof cannot decide it.
    append_operation_commit(
        &transaction,
        &terminal,
        &encode_operation(&terminal)?,
        stored.recovery_claim.as_ref(),
        "compare_and_swap",
        &fixture.store.serving_owner,
        apply_at,
    )?;
    fixture.store.commit_write(transaction)?;
    fixture.store.sync_after_write(&connection)?;
    verify_admission_commit_chain(&connection)?;
    drop(connection);
    assert_eq!(sealed_projection(&fixture, &terminal)?, seal);
    require_invariant(
        fixture
            .store
            .load_by_operation_id(terminal.binding().operation_id()),
        "admission operation commits regress version or trusted time",
    );
    Ok(())
}

#[test]
fn native_terminal_checked_history_rejects_missing_cas_and_changed_predecessor_on_qualified_read(
) -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(1_800_000_600);
    for remove in [true, false] {
        let (fixture, terminal, _, status, at) =
            terminal_with_status("terminal-qualified-history-gap")?;
        clear_later(&fixture, &terminal, &status, at)?;
        assert_eq!(
            fixture
                .store
                .load_by_operation_id(terminal.binding().operation_id())?,
            Some(terminal.clone())
        );
        let connection = fixture.store.connection()?;
        verify_admission_commit_chain(&connection)?;
        let name = if remove {
            "admission_operation_commits_no_delete"
        } else {
            "admission_operation_commits_immutable"
        };
        let trigger: String = connection.query_row(
            "SELECT sql FROM sqlite_schema WHERE name=?1",
            [name],
            |row| row.get(0),
        )?;
        connection.execute_batch(&format!("DROP TRIGGER {name}"))?;
        let sql = if remove {
            "DELETE FROM admission_operation_commits WHERE operation_id=?1 AND mutation_kind='compare_and_swap' AND operation_version=?2"
        } else {
            "UPDATE admission_operation_commits SET previous_chain_digest='ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' WHERE operation_id=?1 AND mutation_kind='compare_and_swap' AND operation_version=?2"
        };
        assert_eq!(
            connection.execute(
                sql,
                params![
                    terminal.binding().operation_id().as_str(),
                    i64::try_from(terminal.version())?
                ]
            )?,
            1
        );
        connection.execute_batch(&trigger)?;
        drop(connection);
        let expected = if remove {
            "admission operation commit log is not a dense fenced sequence"
        } else {
            "admission operation commit chain is invalid"
        };
        require_invariant(
            fixture
                .store
                .load_by_operation_id(terminal.binding().operation_id()),
            expected,
        );
    }
    Ok(())
}
