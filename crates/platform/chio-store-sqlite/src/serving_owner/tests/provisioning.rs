use super::*;

#[test]
fn pristine_owner_provision_commits_global_custody_before_admission_inventory(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let connection = Connection::open(&database)?;
    let (owner_epoch, global_head, baseline_count, admission_version): (i64, i64, i64, i32) =
        connection.query_row(
            "SELECT (SELECT owner_epoch FROM chio_serving_owner WHERE singleton=1),
             (SELECT head_sequence FROM authority_global_commit_meta WHERE singleton=1),
             (SELECT COUNT(*) FROM authority_global_commits WHERE projection_kind='baseline'),
             (SELECT version FROM chio_store_schema_versions WHERE store_key='admission_operation')",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
    assert_eq!(owner_epoch, 0);
    assert_eq!(global_head, 1);
    assert_eq!(baseline_count, 1);
    assert_eq!(
        admission_version,
        crate::admission_operation_store::ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION
    );
    drop(connection);
    let authority = SqliteAuthorityStore::open_serving(&database, &lock_root)?;
    assert_eq!(authority.mutation_fence().owner_epoch, 1);
    Ok(())
}

#[test]
fn retained_global_metadata_cannot_recreate_a_missing_global_history(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    let connection = Connection::open(&database)?;
    // Genuine provisioning committed a baseline. Removing only its history
    // leaves retained metadata, even though this identity has no serving lease.
    connection.execute_batch("DROP TABLE authority_global_commits")?;
    let retained: (i64, String) = connection.query_row(
        "SELECT head_sequence,head_chain_digest FROM authority_global_commit_meta WHERE singleton=1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(retained.0, 1);
    drop(connection);
    assert!(SqliteAuthorityStore::provision(&database, &lock_root).is_err());
    assert!(SqliteAuthorityStore::open_serving(&database, &lock_root).is_err());
    let connection = Connection::open(&database)?;
    assert!(!connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='authority_global_commits')",
        [],
        |row| row.get::<_, bool>(0),
    )?);
    assert_eq!(
        connection.query_row(
            "SELECT head_sequence,head_chain_digest FROM authority_global_commit_meta WHERE singleton=1",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
        )?,
        retained
    );
    Ok(())
}

#[test]
fn a_retained_serving_lease_cannot_recreate_lost_global_custody(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_temp, database, lock_root) = fixture();
    SqliteAuthorityStore::provision(&database, &lock_root)?;
    drop(SqliteAuthorityStore::open_serving(&database, &lock_root)?);
    let connection = Connection::open(&database)?;
    let lease_count: i64 =
        connection.query_row("SELECT COUNT(*) FROM chio_serving_leases", [], |row| {
            row.get(0)
        })?;
    assert_eq!(lease_count, 1);
    connection.execute_batch(
        "DROP TABLE authority_global_commits; DROP TABLE authority_global_commit_meta",
    )?;
    drop(connection);
    assert!(SqliteAuthorityStore::provision(&database, &lock_root).is_err());
    assert!(SqliteAuthorityStore::open_serving(&database, &lock_root).is_err());
    let connection = Connection::open(&database)?;
    assert_eq!(
        connection.query_row("SELECT COUNT(*) FROM chio_serving_leases", [], |row| {
            row.get::<_, i64>(0)
        })?,
        lease_count
    );
    assert!(!connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name IN ('authority_global_commits','authority_global_commit_meta'))",
        [],
        |row| row.get::<_, bool>(0),
    )?);
    Ok(())
}

#[test]
fn a_transient_lock_root_failure_does_not_wedge_provisioning() {
    let (_temp, database, lock_root) = fixture();
    fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o500))
        .expect("make lock root read only");
    assert!(SqliteAuthorityStore::provision(&database, &lock_root).is_err());
    fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o700))
        .expect("restore lock root mode");

    // The failed attempt cleans up after itself, so the store provisions normally
    // once the transient condition clears instead of wedging as a partial provision.
    SqliteAuthorityStore::provision(&database, &lock_root).expect("reprovision");
    SqliteAuthorityStore::open_serving(&database, &lock_root).expect("open serving");
}

#[test]
fn partial_provision_fails_closed() {
    let (_temp, database, lock_root) = fixture();
    drop(SqliteBudgetStore::open(&database).expect("initialize authority schemas"));
    fs::set_permissions(&database, fs::Permissions::from_mode(0o600))
        .expect("secure database mode");
    // An owner table carrying no owner row is what an interrupted provision leaves
    // behind when its outcome is unknown and the artifacts are kept for inspection.
    let connection = Connection::open(&database).expect("open database");
    connection
        .execute_batch(SERVING_OWNER_SCHEMA)
        .expect("owner table");
    drop(connection);

    assert!(matches!(
        SqliteAuthorityStore::provision(&database, &lock_root),
        Err(SqliteServingOwnerError::PartialProvision(_))
    ));
    assert!(matches!(
        SqliteAuthorityStore::open_serving(&database, &lock_root),
        Err(SqliteServingOwnerError::PartialProvision(_))
    ));
    assert!(SqliteBudgetStore::open(&database).is_err());
    assert!(SqliteRevocationStore::open(&database).is_err());
}
