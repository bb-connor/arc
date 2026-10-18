use std::os::unix::fs::MetadataExt;
use std::path::Path;

use chio_core::canonical_json_bytes;

use super::*;

fn file_identity(path: &Path) -> AnchoredTestResult<(u64, u64, u64)> {
    let metadata = fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino(), metadata.nlink()))
}

#[test]
fn owner_restart_preserves_sealed_source_and_idempotent_import() -> AnchoredTestResult {
    let fixture = fixture();
    let source_path = fixture._temp.path().join("security-source.db");
    let source = source(&fixture)?;
    {
        let connection =
            Connection::open_with_flags(&source_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        assert_eq!(
            connection.query_row(
                "SELECT version FROM chio_store_schema_versions WHERE store_key = 'security_state'",
                [],
                |row| row.get::<_, i32>(0),
            )?,
            1
        );
    }
    let before = global_count(&fixture)?;
    let expected = pin(&fixture, &source)?;
    assert_eq!(
        expected.phase(),
        SecurityParticipantMigrationPhase::Expected
    );
    assert_eq!(global_count(&fixture)?, before + 1);
    let binding = expected.snapshot().binding();
    assert_eq!(binding.source_id().as_str(), "private-source");
    assert_eq!(
        binding.security_authority_id().as_str(),
        authority_id().as_str()
    );
    assert_eq!(
        binding.destination_store_uuid().as_str(),
        fixture.fence.store_uuid
    );
    let uuid = uuid::Uuid::parse_str(&fixture.fence.store_uuid)?;
    assert_eq!(uuid.get_version_num(), 7);
    assert_eq!(uuid.to_string(), fixture.fence.store_uuid);
    let snapshot_bytes = expected.snapshot().canonical_bytes()?;
    let seal = source.seal_exact(expected.snapshot())?;
    source.verify_seal(expected.snapshot())?;
    let seal_bytes = seal.snapshot().canonical_bytes()?;
    assert_eq!(seal_bytes, snapshot_bytes);
    assert_eq!(load(&fixture)?, Some(expected.clone()));
    let rows = source.read_sealed_rows(expected.snapshot())?;
    assert!(rows.tables.iter().any(|(_, rows)| !rows.is_empty()));
    let row_bytes = canonical_json_bytes(&rows.tables)?;
    let lock_path = fixture
        .lock_root
        .join(format!("{}.lock", fixture.fence.store_uuid));
    let source_identity = file_identity(&source_path)?;
    let destination_identity = file_identity(&fixture.database)?;
    let lock_identity = file_identity(&lock_path)?;
    let lock_root_identity = file_identity(&fixture.lock_root)?;
    let global_commits = global_count(&fixture)?;
    let anchor_generation = fixture.authority.anchor_generation()?;
    drop(source);
    let Fixture {
        _temp,
        database,
        lock_root,
        store,
        authority,
        fence: previous_fence,
        _clock,
    } = fixture;
    drop(store);
    drop(authority);
    let source_bytes = fs::read(&source_path)?;
    let authority = crate::test_authority::open_serving(&database, &lock_root)?;
    authority.verify_database_path(&database)?;
    let fence = authority.mutation_fence();
    assert_eq!(fence.store_uuid, previous_fence.store_uuid);
    assert!(fence.owner_epoch > previous_fence.owner_epoch);
    assert_ne!(fence.lease_id, previous_fence.lease_id);
    assert!(authority.anchor_generation()? > anchor_generation);
    assert_eq!(file_identity(&source_path)?, source_identity);
    assert_eq!(file_identity(&database)?, destination_identity);
    assert_eq!(file_identity(&lock_path)?, lock_identity);
    assert_eq!(file_identity(&lock_root)?, lock_root_identity);
    let store = authority.admission_operation_store();
    let retained_expected = store
        .load_security_participant_migration(&authority_id(), &fence, now_ms())?
        .ok_or("destination expectation is absent")?;
    assert_eq!(retained_expected, expected);
    assert_eq!(
        retained_expected.snapshot().canonical_bytes()?,
        snapshot_bytes
    );
    let source = SqliteSecurityParticipantSource::open(&source_path)?;
    source.verify_seal(expected.snapshot())?;
    assert_eq!(
        source
            .load_seal()?
            .ok_or("source seal is absent")?
            .snapshot()
            .canonical_bytes()?,
        seal_bytes
    );
    let retained = source.read_sealed_rows(expected.snapshot())?;
    assert_eq!(canonical_json_bytes(&retained.tables)?, row_bytes);
    let global_count = || -> AnchoredTestResult<i64> {
        Ok(store.connection()?.query_row(
            "SELECT COUNT(*) FROM authority_global_commits",
            [],
            |row| row.get(0),
        )?)
    };
    assert_eq!(global_count()?, global_commits);
    let anchored_before = authority.anchor_generation()?;
    let imported = store.import_security_participant_source(
        &authority_id(),
        retained_expected.expectation_id(),
        &source,
        &fence,
        now_ms(),
    )?;
    assert_eq!(
        imported.phase(),
        SecurityParticipantMigrationPhase::ImportedInactive
    );
    assert_eq!(imported.snapshot(), expected.snapshot());
    assert_eq!(global_count()?, global_commits + 1);
    let anchored_after = authority.anchor_generation()?;
    assert!(anchored_after > anchored_before);
    {
        let connection = store.connection()?;
        let mut total = 0_i64;
        for (table, rows) in retained.tables {
            let mut statement = connection.prepare(
                "SELECT canonical_row FROM security_participant_migration_rows \
                 WHERE security_authority_id = ?1 AND table_name = ?2 ORDER BY row_index",
            )?;
            let actual = statement
                .query_map(params![authority_id().as_str(), table], |row| {
                    row.get::<_, Vec<u8>>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(actual, rows, "sealed row bytes: {table}");
            total += i64::try_from(rows.len())?;
        }
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM security_participant_migration_rows",
                [],
                |row| row.get::<_, i64>(0),
            )?,
            total
        );
        assert_eq!(
            connection.query_row("SELECT COUNT(*) FROM admission_operations", [], |row| {
                row.get::<_, i64>(0)
            })?,
            0
        );
        assert_eq!(
            connection.query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'security_flow_contexts'",
                [],
                |row| row.get::<_, i64>(0),
            )?,
            0
        );
    }
    assert_eq!(
        store.import_security_participant_source(
            &authority_id(),
            retained_expected.expectation_id(),
            &source,
            &fence,
            now_ms(),
        )?,
        imported
    );
    assert_eq!(global_count()?, global_commits + 1);
    assert_eq!(authority.anchor_generation()?, anchored_after);
    source.verify_seal(expected.snapshot())?;
    assert_eq!(
        canonical_json_bytes(&source.read_sealed_rows(expected.snapshot())?.tables)?,
        row_bytes
    );
    drop(source);
    drop(store);
    drop(authority);
    assert_eq!(file_identity(&source_path)?, source_identity);
    assert_eq!(file_identity(&database)?, destination_identity);
    assert_eq!(file_identity(&lock_path)?, lock_identity);
    assert_eq!(file_identity(&lock_root)?, lock_root_identity);
    assert_eq!(fs::read(&source_path)?, source_bytes);
    Ok(())
}
