use super::*;

#[test]
fn sealed_current_source_import_retains_exact_rows_and_seal() -> AnchoredTestResult {
    let fixture = fixture();
    let path = fixture._temp.path().join("security-source.db");
    drop(crate::security_state::seeded_security_history(&path)?);
    let raw = Connection::open(&path)?;
    let actual: i32 = raw.query_row(
        "SELECT version FROM chio_store_schema_versions WHERE store_key = 'security_state'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(actual, 1);
    let source = SqliteSecurityParticipantSource::open(&path)?;
    let expected = pin(&fixture, &source)?;
    source.seal_exact(expected.snapshot())?;
    let seal_before: Vec<u8> = raw.query_row(
        "SELECT canonical_bytes FROM chio_security_participant_source_seal WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    source.verify_seal(expected.snapshot())?;
    let retained = source.read_sealed_rows(expected.snapshot())?;
    let before = global_count(&fixture)?;
    let imported = import(&fixture, &source, &expected)?;
    assert_eq!(
        imported.phase(),
        SecurityParticipantMigrationPhase::ImportedInactive
    );
    assert_eq!(global_count(&fixture)?, before + 1);
    let destination = fixture.store.connection()?;
    for (table, rows) in retained.tables {
        let mut statement = destination.prepare(
            "SELECT canonical_row FROM security_participant_migration_rows \
             WHERE security_authority_id = ?1 AND table_name = ?2 ORDER BY row_index",
        )?;
        let actual = statement
            .query_map(params![authority_id().as_str(), table], |row| {
                row.get::<_, Vec<u8>>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(actual, rows, "retained source row bytes: {table}");
    }
    drop(destination);
    assert_eq!(import(&fixture, &source, &expected)?, imported);
    assert_eq!(global_count(&fixture)?, before + 1);
    assert_eq!(
        raw.query_row(
            "SELECT canonical_bytes FROM chio_security_participant_source_seal WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )?,
        seal_before
    );
    let error = crate::SqliteSecurityStateStore::open(&path)
        .err()
        .ok_or("sealed source was reopened as a writable serving store")?;
    assert_eq!(error, chio_security_types::ports::PortError::retired());
    drop(source);
    let reopened = SqliteSecurityParticipantSource::open(&path)?;
    reopened.verify_seal(expected.snapshot())?;
    assert_eq!(import(&fixture, &reopened, &expected)?, imported);
    assert_eq!(global_count(&fixture)?, before + 1);
    assert_eq!(
        raw.query_row(
            "SELECT canonical_bytes FROM chio_security_participant_source_seal WHERE singleton = 1",
            [],
            |row| row.get::<_, Vec<u8>>(0),
        )?,
        seal_before
    );
    Ok(())
}
