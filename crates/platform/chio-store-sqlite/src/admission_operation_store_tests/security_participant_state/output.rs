use super::*;

#[cfg(unix)]
#[test]
fn missing_current_output_catalog_is_not_repaired() -> AnchoredTestResult {
    for sql in [
        "DROP TABLE security_participant_output_events",
        "DROP TRIGGER security_participant_output_events_no_replace",
    ] {
        let fixture = fixture();
        let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
        fixture.store.connection()?.execute_batch(sql)?;
        assert!(fixture
            .store
            .load_security_participant_state(
                initialized.security_authority_id(),
                &fixture.fence,
                now_ms()
            )
            .is_err());
        let Closed {
            _temp,
            database,
            lock_root,
            fence: _fence,
            _clock,
        } = fixture.close();
        let connection = Connection::open(&database)?;
        let before: (i64,String) = connection.query_row("SELECT head_sequence, head_chain_digest FROM authority_global_commit_meta WHERE singleton = 1", [], |row| Ok((row.get(0)?,row.get(1)?)))?;
        assert!(SqliteAuthorityStore::provision(&database, &lock_root).is_err());
        assert!(SqliteAuthorityStore::open_serving_with_clock(
            &database,
            &lock_root,
            chio_test_support::clock::clock()
        )
        .is_err());
        assert_eq!(connection.query_row("SELECT head_sequence, head_chain_digest FROM authority_global_commit_meta WHERE singleton = 1", [], |row| Ok((row.get::<_,i64>(0)?,row.get::<_,String>(1)?)))?, before);
    }
    Ok(())
}
