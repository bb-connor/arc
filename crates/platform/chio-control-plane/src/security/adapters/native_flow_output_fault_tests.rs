// Failure injection surrounds the actual SQL write, never a substitute journal.
use super::*;
use chio_store_sqlite::admission_operation_store::NativeOutputJoinTestFault as Fault;

#[test]
fn native_output_journal_precommit_failures_roll_back_rows_events_and_global_head() -> TestResult {
    for fault in [Fault::AfterRows, Fault::AfterEvent, Fault::BeforeCommit] {
        let mut fixture = super::super::super::super::public_fixture()?;
        let finalizing = finalizing(&mut fixture, false)?;
        let intent = finalizing.intent(super::super::super::super::restricted_label())?;
        let store = fixture.authority.admission_operation_store();
        let connection =
            rusqlite::Connection::open(fixture._directory.path().join("admission.db"))?;
        let before: (i64,String) = connection.query_row("SELECT head_sequence, head_chain_digest FROM authority_global_commit_meta WHERE singleton = 1", [], |row| Ok((row.get(0)?,row.get(1)?)))?;
        store.inject_native_output_join_failure_for_test(fault)?;
        let failed = finalizing.join(&fixture, &intent);
        store.clear_native_output_join_failure_for_test()?;
        assert!(failed.is_err(), "{fault:?}");
        assert_eq!(counts(&fixture)?, (0, 0, 0));
        assert_eq!(connection.query_row("SELECT head_sequence, head_chain_digest FROM authority_global_commit_meta WHERE singleton = 1", [], |row| Ok((row.get::<_,i64>(0)?,row.get::<_,String>(1)?)))?, before);
        let observed = store.observe_security_participant_flow(
            &fixture.binding,
            intent.key(),
            &fixture.authority.mutation_fence(),
            now_ms()?,
        )?;
        assert_eq!(observed.snapshot(), finalizing.observation.snapshot());
        let output = finalizing.join(&fixture, &intent)?;
        assert_eq!(counts(&fixture)?, (1, 1, 0));
        drop(connection);
        drop(store);
        reopen(fixture, &output)?;
    }
    Ok(())
}

#[test]
fn native_output_journal_lost_acknowledgement_recovers_history_without_release_authority(
) -> TestResult {
    for fault in [Fault::AfterCommit, Fault::AfterAnchor] {
        let mut fixture = super::super::super::super::public_fixture()?;
        let finalizing = finalizing(&mut fixture, false)?;
        let label = super::super::super::super::restricted_label();
        let intent = finalizing.intent(label.clone())?;
        let store = fixture.authority.admission_operation_store();
        store.inject_native_output_join_failure_for_test(fault)?;
        let failed = finalizing.join(&fixture, &intent);
        store.clear_native_output_join_failure_for_test()?;
        assert!(failed.is_err(), "{fault:?}");
        assert_eq!(counts(&fixture)?, (1, 1, 0));
        assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
        drop(store);
        let Fixture {
            kernel,
            authority,
            _directory,
            ..
        } = fixture;
        drop(kernel);
        drop(authority);
        let authority = SqliteAuthorityStore::open_serving(
            _directory.path().join("admission.db"),
            _directory.path().join("locks"),
        )?;
        let store = authority.admission_operation_store();
        let recovered = store
            .load_security_participant_output(
                intent.operation_id(),
                &authority.mutation_fence(),
                now_ms()?,
            )?
            .ok_or("committed output history absent after lost reply")?;
        assert_eq!(recovered.output, intent);
        assert_eq!(recovered.join.snapshot.principal_label, label);
        assert_eq!(recovered.join.snapshot.lineage_label, label);
        assert_eq!(recovered.join.snapshot.session_label, label);
        assert!(store
            .join_security_participant_output(
                &finalizing.operation,
                &finalizing.lease,
                &finalizing.initialized,
                &intent,
                now_ms()?
            )
            .is_err());
        assert_eq!(
            store
                .load_by_operation_id(intent.operation_id())?
                .ok_or("operation")?
                .state(),
            AdmissionOperationState::Finalizing
        );
    }
    Ok(())
}

#[test]
fn native_output_journal_locally_rehashed_history_cannot_replace_the_global_anchor() -> TestResult {
    let mut fixture = super::super::super::super::public_fixture()?;
    let finalizing = finalizing(&mut fixture, false)?;
    let intent = finalizing.intent(InformationLabel::bottom())?;
    finalizing.join(&fixture, &intent)?;
    let Fixture {
        kernel,
        authority,
        _directory,
        ..
    } = fixture;
    drop(kernel);
    drop(authority);
    let database = _directory.path().join("admission.db");
    let connection = rusqlite::Connection::open(&database)?;
    let trigger: String = connection.query_row(
        "SELECT sql FROM sqlite_schema WHERE name = 'security_participant_output_events_no_update'",
        [],
        |row| row.get(0),
    )?;
    let bytes: Vec<u8> = connection.query_row(
        "SELECT canonical_record FROM security_participant_output_events",
        [],
        |row| row.get(0),
    )?;
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let rows = value["current_rows"].as_u64().ok_or("row count")?;
    value["current_rows"] = (rows + 1).into();
    let bytes = chio_core::canonical::canonical_json_bytes(&value)?;
    let mut preimage = b"chio.native-security-output-join.commit.v1\0".to_vec();
    preimage.extend(&bytes);
    connection.execute_batch("DROP TRIGGER security_participant_output_events_no_update")?;
    connection.execute(
        "UPDATE security_participant_output_events SET canonical_record = ?1, event_digest = ?2",
        rusqlite::params![bytes, chio_core::sha256_hex(&preimage)],
    )?;
    connection.execute_batch(&trigger)?;
    drop(connection);
    assert!(
        SqliteAuthorityStore::open_serving(&database, _directory.path().join("locks")).is_err()
    );
    Ok(())
}
