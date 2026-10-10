use super::*;

const LEGACY_SCHEMA_DIGEST: &str =
    "1db878e623b5fe5eb59fb3dc5b31d4eb8e1a7e7ffb3bddb295c7e39077b09658";

#[test]
fn legacy0_and_current1_sources_import_through_the_real_destination_owner() -> AnchoredTestResult {
    for revision in [0, 1] {
        let fixture = fixture();
        let path = fixture._temp.path().join("security-source.db");
        drop(crate::security_state::seeded_security_history(&path)?);
        let raw = Connection::open(&path)?;
        let actual: i32 = raw.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'security_state'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(actual, 1, "this control requires the schema producer");
        if revision == 0 {
            let count: i64 = raw.query_row(
                "SELECT COUNT(*) FROM security_response_effect_finality",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(
                count, 0,
                "legacy fixture cannot discard any removal authority"
            );
            // This lossless fixture inverse removes only the new, EMPTY
            // marker objects and restores stamp0 before the source is sealed.
            // Every genuine critical row remains; the old digest is pinned to
            // the independently retained prechange owning capture.
            raw.execute_batch(
                "DROP TRIGGER security_response_effect_finality_immutable; \
                 DROP TRIGGER security_response_effect_finality_delete_rejected; \
                 DROP TABLE security_response_effect_finality; \
                 UPDATE chio_store_schema_versions SET version = 0 WHERE store_key = 'security_state';",
            )?;
        }
        let source = SqliteSecurityParticipantSource::open(&path)?;
        let expected = pin(&fixture, &source)?;
        let snapshot_bytes = expected.snapshot().canonical_bytes()?;
        let snapshot: serde_json::Value = serde_json::from_slice(&snapshot_bytes)?;
        if revision == 0 {
            assert_eq!(
                snapshot["catalog_digest"].as_str(),
                Some(LEGACY_SCHEMA_DIGEST)
            );
        } else {
            assert_ne!(
                snapshot["catalog_digest"].as_str(),
                Some(LEGACY_SCHEMA_DIGEST)
            );
        }
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
            assert_eq!(
                actual, rows,
                "retained {revision} source row bytes: {table}"
            );
        }
        drop(destination);
        assert_eq!(import(&fixture, &source, &expected)?, imported);
        assert_eq!(global_count(&fixture)?, before + 1);
        assert_eq!(raw.query_row(
            "SELECT canonical_bytes FROM chio_security_participant_source_seal WHERE singleton = 1",
            [], |row| row.get::<_, Vec<u8>>(0),
        )?, seal_before);
        let error = crate::SqliteSecurityStateStore::open(&path)
            .err()
            .ok_or("sealed source was reopened as a writable serving store")?;
        assert_eq!(
            error.kind(),
            chio_security_types::ports::PortErrorKind::Conflict
        );
        assert_eq!(error.code().as_str(), "store.conflict");
        drop(source);
        let reopened = SqliteSecurityParticipantSource::open(&path)?;
        reopened.verify_seal(expected.snapshot())?;
        assert_eq!(import(&fixture, &reopened, &expected)?, imported);
        assert_eq!(global_count(&fixture)?, before + 1);
        assert_eq!(raw.query_row(
            "SELECT canonical_bytes FROM chio_security_participant_source_seal WHERE singleton = 1",
            [], |row| row.get::<_, Vec<u8>>(0),
        )?, seal_before);
    }
    Ok(())
}
