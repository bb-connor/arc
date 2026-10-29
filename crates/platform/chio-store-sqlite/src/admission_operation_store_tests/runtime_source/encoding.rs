use super::*;

fn round_trip(encoding: &str) -> Result<(), Box<dyn Error>> {
    let clock = fixed_clock();
    let temp = tempfile::tempdir()?;
    secure_directory(temp.path());
    let database = temp.path().join("authority.db");
    let lock_root = temp.path().join("locks");
    create_lock_root(&lock_root);
    {
        let connection = Connection::open(&database)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&database, fs::Permissions::from_mode(0o600))?;
        }
        connection.execute_batch(&format!(
            "PRAGMA encoding = '{encoding}';
             CREATE TABLE encoding_anchor (value TEXT);
             DROP TABLE encoding_anchor;"
        ))?;
    }
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let authority = crate::test_authority::open_serving(&database, &lock_root)?;
    let fixture = Fixture {
        store: authority.admission_operation_store(),
        fence: authority.mutation_fence(),
        authority,
        database,
        lock_root,
        _temp: temp,
        _clock: Some(clock),
    };
    let actual: String =
        fixture
            .store
            .connection()?
            .pragma_query_value(None, "encoding", |row| row.get(0))?;
    assert_eq!(actual, encoding);
    let source = Source::new(&fixture, Behavior::Normal);
    let before = global_count(&fixture.store);
    let installed = install(&fixture, &source)?;
    assert_eq!(load(&fixture)?, Some(installed.clone()));
    assert_eq!(install(&fixture, &source)?, installed);
    assert_eq!(source_count(&fixture.store), 1);
    assert_eq!(global_count(&fixture.store), before + 1);
    let connection = fixture.store.connection()?;
    crate::admission_operation_store::verify_runtime_source_projection_coverage(&connection)?;
    Ok(())
}

#[test]
fn runtime_source_utf8_install_round_trip() -> Result<(), Box<dyn Error>> {
    round_trip("UTF-8")
}

#[test]
fn runtime_source_utf16le_install_round_trip() -> Result<(), Box<dyn Error>> {
    round_trip("UTF-16le")
}

#[test]
fn runtime_source_utf16be_install_round_trip() -> Result<(), Box<dyn Error>> {
    round_trip("UTF-16be")
}

#[test]
fn runtime_source_digest_shape_refuses_before_decoding() -> Result<(), Box<dyn Error>> {
    let fixture = fixture();
    install(&fixture, &Source::new(&fixture, Behavior::Normal))?;
    let mut connection = fixture.store.connection()?;
    connection.execute_batch(
        "DROP TRIGGER runtime_source_qualifications_no_update;
         PRAGMA ignore_check_constraints = ON;",
    )?;
    for column in ["qualification_id", "record_digest"] {
        for malformed in [
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),
            "g".repeat(64),
            format!("{}\0", "a".repeat(64)),
        ] {
            let transaction = connection.transaction()?;
            transaction.execute(
                &format!("UPDATE runtime_source_qualifications SET {column} = ?1"),
                [malformed],
            )?;
            assert_eq!(
                crate::admission_operation_store::runtime_source::verify_all_records(&transaction),
                Err("runtime source row violates storage bounds".into()),
                "{column}",
            );
            transaction.rollback()?;
        }
    }
    Ok(())
}
