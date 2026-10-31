use super::*;

fn global_history(connection: &Connection) -> AnchoredTestResult<Vec<(i64, String)>> {
    let mut statement = connection.prepare("SELECT commit_sequence, chain_digest FROM authority_global_commits ORDER BY commit_sequence")?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[test]
fn missing_current_egress_catalog_is_not_repaired() -> AnchoredTestResult {
    for sql in [
        "DROP TABLE security_participant_egress_events",
        "DROP TRIGGER security_participant_egress_events_no_update",
    ] {
        let fixture = fixture();
        let initialized = hydrate(&fixture, &imported(&fixture, "source")?)?;
        fixture.store.connection()?.execute_batch(sql)?;
        assert!(
            fixture
                .store
                .load_security_participant_state(
                    initialized.security_authority_id(),
                    &fixture.fence,
                    now_ms(),
                )
                .is_err(),
            "live reads must reject a missing current catalog"
        );
        let Closed {
            _temp,
            database,
            lock_root,
            fence: _fence,
            _clock,
        } = fixture.close();
        let connection = Connection::open(&database)?;
        let before = global_history(&connection)?;
        assert!(SqliteAuthorityStore::provision(&database, &lock_root).is_err());
        assert!(SqliteAuthorityStore::open_serving_with_clock(
            &database,
            &lock_root,
            chio_test_support::clock::clock()
        )
        .is_err());
        assert_eq!(global_history(&connection)?, before);
    }
    Ok(())
}
