use super::*;

#[test]
fn concurrent_exact_hydration_commits_only_one_initialization() -> AnchoredTestResult {
    let fixture = fixture();
    let source = imported(&fixture, "source")?;
    let key = identifier("security_authority_id", "source");
    let barrier = std::sync::Barrier::new(2);
    let (first, second) = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            fixture.store.hydrate_security_participant_state(
                &key,
                source.expectation_id(),
                &fixture.fence,
                now_ms(),
            )
        });
        barrier.wait();
        let second = fixture.store.hydrate_security_participant_state(
            &key,
            source.expectation_id(),
            &fixture.fence,
            now_ms(),
        );
        (first.join(), second)
    });
    assert_eq!(first.map_err(|_| "hydration thread panicked")??, second?);
    assert_eq!(global_count(&*fixture.store.connection()?)?, 1);
    Ok(())
}

#[test]
fn independently_observed_clock_rollback_denies_hydration_and_readback() -> AnchoredTestResult {
    let fixture = fixture();
    let now = now_ms() / 1_000 * 1_000;
    let _clock =
        chio_kernel::scope_fixed_runtime_for_current_thread(now / 1_000, std::iter::empty());
    let source = imported(&fixture, "source")?;
    let key = identifier("security_authority_id", "source");
    {
        let _rollback = chio_kernel::scope_fixed_runtime_for_current_thread(
            now / 1_000 - 1,
            std::iter::empty(),
        );
        assert!(fixture
            .store
            .hydrate_security_participant_state(&key, source.expectation_id(), &fixture.fence, now)
            .is_err());
        assert!(fixture
            .store
            .load_security_participant_state(&key, &fixture.fence, now)
            .is_err());
    }
    assert_eq!(global_count(&*fixture.store.connection()?)?, 0);
    hydrate(&fixture, &source)?;
    {
        let _rollback = chio_kernel::scope_fixed_runtime_for_current_thread(
            now / 1_000 - 1,
            std::iter::empty(),
        );
        assert!(fixture
            .store
            .load_security_participant_state(&key, &fixture.fence, now)
            .is_err());
    }
    Ok(())
}

#[test]
fn two_authorities_preserve_every_native_row_without_merging_identifiers() -> AnchoredTestResult {
    let fixture = fixture();
    let first = imported(&fixture, "first")?;
    let second = imported(&fixture, "second")?;
    let records = [hydrate(&fixture, &first)?, hydrate(&fixture, &second)?];
    let connection = fixture.store.connection()?;
    assert_eq!(global_count(&connection)?, 2);
    for table in native::schema::TABLES {
        let columns = crate::security_state::retained_security_columns(table.source)?
            .into_iter()
            .map(|column| format!("\"{column}\""))
            .collect::<Vec<_>>()
            .join(",");
        for (source, record) in [(&first, &records[0]), (&second, &records[1])] {
            let mut statement = connection.prepare(&format!(
                "SELECT {columns} FROM {} WHERE security_authority_id = ?1 ORDER BY {columns}",
                table.native
            ))?;
            let count = statement.column_count();
            let mut rows = statement.query([record.security_authority_id().as_str()])?;
            let mut hasher = crate::security_state::TableHasher::new(table.source);
            while let Some(row) = rows.next()? {
                let values = (0..count)
                    .map(|index| row.get_ref(index))
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                hasher.push(&crate::security_state::encode_retained_security_values(
                    table.source,
                    &values,
                )?)?;
            }
            assert_eq!(
                &hasher.finish(),
                source
                    .snapshot()
                    .tables()
                    .iter()
                    .find(|entry| entry.table == table.source)
                    .ok_or("source table absent")?
            );
        }
    }
    assert_eq!(native::verify_all(&connection)?.len(), 2);
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM admission_operations", [], |row| row
            .get::<_, i64>(
            0
        ))?,
        0
    );
    drop(connection);
    assert_eq!(hydrate(&fixture, &first)?, records[0]);
    assert_eq!(hydrate(&fixture, &second)?, records[1]);
    assert_eq!(global_count(&*fixture.store.connection()?)?, 2);
    assert_eq!(
        fixture
            .store
            .load_security_participant_migration(
                records[0].security_authority_id(),
                &fixture.fence,
                now_ms()
            )?
            .ok_or("source absent")?
            .phase(),
        SecurityParticipantMigrationPhase::ImportedInactive
    );
    assert!(!format!("{:?}", records[0]).contains("first"));
    assert!(crate::SqliteSecurityStateStore::open(&fixture.database).is_err());
    Ok(())
}

#[test]
fn retry_and_new_owner_readback_need_no_remaining_source_file() -> AnchoredTestResult {
    let fixture = fixture();
    let imported = imported(&fixture, "source")?;
    let record = hydrate(&fixture, &imported)?;
    // Recoverable fixture-only source removal models a lost retired device.
    fs::rename(
        fixture._temp.path().join("source.db"),
        fixture._temp.path().join("source.offline"),
    )?;
    assert_eq!(hydrate(&fixture, &imported)?, record);
    let Fixture {
        _temp,
        database,
        lock_root,
        authority,
        store,
        fence,
    } = fixture;
    drop(store);
    drop(authority);
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    let store = authority.admission_operation_store();
    assert!(store
        .load_security_participant_state(record.security_authority_id(), &fence, now_ms())
        .is_err());
    assert_eq!(
        store.load_security_participant_state(
            record.security_authority_id(),
            &authority.mutation_fence(),
            now_ms()
        )?,
        Some(record.clone())
    );
    assert_eq!(
        store.hydrate_security_participant_state(
            record.security_authority_id(),
            record.expectation_id(),
            &authority.mutation_fence(),
            now_ms()
        )?,
        record
    );
    assert_eq!(global_count(&*store.connection()?)?, 1);
    Ok(())
}

#[test]
fn unimported_wrong_generation_authority_and_fence_cannot_initialize() -> AnchoredTestResult {
    let fixture = fixture();
    let source_path = fixture._temp.path().join("source.db");
    drop(crate::security_state::seeded_security_history(
        &source_path,
    )?);
    let source = crate::security_state::SqliteSecurityParticipantSource::open(source_path)?;
    let authority = identifier("security_authority_id", "source");
    let expected = fixture.store.expect_security_participant_source(
        &authority,
        &authority,
        &source,
        &fixture.fence,
        now_ms(),
    )?;
    assert!(hydrate(&fixture, &expected).is_err());
    let imported = fixture.store.import_security_participant_source(
        &authority,
        expected.expectation_id(),
        &source,
        &fixture.fence,
        now_ms(),
    )?;
    let mut stale = fixture.fence.clone();
    stale.owner_epoch += 1;
    let mut foreign = fixture.fence.clone();
    foreign.store_uuid = "foreign".into();
    for (authority, expectation, fence) in [
        (
            authority.clone(),
            identifier("expectation_id", "wrong"),
            fixture.fence.clone(),
        ),
        (
            identifier("security_authority_id", "wrong"),
            imported.expectation_id().clone(),
            fixture.fence.clone(),
        ),
        (authority.clone(), imported.expectation_id().clone(), stale),
        (authority, imported.expectation_id().clone(), foreign),
    ] {
        assert!(fixture
            .store
            .hydrate_security_participant_state(&authority, &expectation, &fence, now_ms())
            .is_err());
    }
    let connection = fixture.store.connection()?;
    assert!(native::verify_all(&connection)?.is_empty());
    assert_eq!(global_count(&connection)?, 0);
    drop(connection);
    hydrate(&fixture, &imported)?;
    Ok(())
}
