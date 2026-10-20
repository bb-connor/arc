use super::*;

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
    crate::test_authority::open_serving(&database, &lock_root).expect("open serving");
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
        SqliteAuthorityStore::open_serving_with_clock(
            &database,
            &lock_root,
            chio_test_support::clock::clock()
        ),
        Err(SqliteServingOwnerError::PartialProvision(_))
    ));
    assert!(SqliteBudgetStore::open(&database).is_err());
    assert!(SqliteRevocationStore::open(&database).is_err());
}

fn assert_tool_outcome_preflight_refusal(
    database: &Path,
    lock_root: &Path,
    expected: chio_kernel::tool_outcome::ToolOutcomeStoreError,
) -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open(database)?;
    let catalog = || -> rusqlite::Result<Vec<SchemaCatalogEntry>> {
        connection
            .prepare(
                "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name, tbl_name",
            )?
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect()
    };
    let pragmas = || -> rusqlite::Result<Vec<rusqlite::types::Value>> {
        [
            "application_id",
            "schema_version",
            "user_version",
            "journal_mode",
        ]
        .into_iter()
        .map(|name| connection.pragma_query_value(None, name, |row| row.get(0)))
        .collect()
    };
    let before_catalog = catalog()?;
    let before_data = crate::tests::authority_snapshot(&connection)?;
    let before_pragmas = pragmas()?;
    for serving in [false, true] {
        let result = if serving {
            SqliteAuthorityStore::open_serving_with_clock(
                database,
                lock_root,
                chio_test_support::clock::clock(),
            )
            .map(|_| ())
        } else {
            SqliteAuthorityStore::provision(database, lock_root)
        };
        let Err(error) = result else {
            return Err("tool outcome schema refusal is required".into());
        };
        assert!(matches!(
            &error,
            SqliteServingOwnerError::ToolOutcomeSchema(source) if source == &expected
        ));
        assert_eq!(
            error.to_string(),
            format!("tool outcome schema refused: {expected}")
        );
        assert_eq!(
            std::error::Error::source(&error)
                .and_then(|source| source
                    .downcast_ref::<chio_kernel::tool_outcome::ToolOutcomeStoreError>()),
            Some(&expected)
        );
        assert_eq!(catalog()?, before_catalog);
        assert_eq!(crate::tests::authority_snapshot(&connection)?, before_data);
        assert_eq!(pragmas()?, before_pragmas);
    }
    Ok(())
}

#[test]
fn ownerless_authority_refuses_tool_outcome_stamp_before_initialization(
) -> Result<(), Box<dyn std::error::Error>> {
    let (_temp, database, lock_root) = fixture();
    drop(SqliteBudgetStore::open(&database)?);
    fs::set_permissions(&database, fs::Permissions::from_mode(0o600))?;
    let connection = Connection::open(&database)?;
    for found in [0, 4, i32::MAX] {
        crate::test_schema::write_version(&connection, "tool_outcome", found)?;
        assert_tool_outcome_preflight_refusal(
            &database,
            &lock_root,
            chio_kernel::tool_outcome::ToolOutcomeStoreError::NoncurrentSchema {
                found,
                current: 1,
            },
        )?;
    }
    Ok(())
}

#[test]
fn provisioned_authority_refuses_tool_outcome_stamp_before_initialization(
) -> Result<(), Box<dyn std::error::Error>> {
    for previously_served in [false, true] {
        let (_temp, database, lock_root) = fixture();
        SqliteAuthorityStore::provision(&database, &lock_root)?;
        if previously_served {
            drop(crate::test_authority::open_serving(&database, &lock_root)?);
        }
        let connection = Connection::open(&database)?;
        for found in [0, 4, i32::MAX] {
            crate::test_schema::write_version(&connection, "tool_outcome", found)?;
            assert_tool_outcome_preflight_refusal(
                &database,
                &lock_root,
                chio_kernel::tool_outcome::ToolOutcomeStoreError::NoncurrentSchema {
                    found,
                    current: 1,
                },
            )?;
        }
    }
    Ok(())
}

#[test]
fn authority_refuses_tool_outcome_catalog_before_initialization(
) -> Result<(), Box<dyn std::error::Error>> {
    for (damage, detail) in [
        (
            "DROP TRIGGER tool_outcome_blobs_immutable",
            "tool outcome schema differs from the canonical definition",
        ),
        (
            "DELETE FROM chio_store_schema_versions WHERE store_key = 'tool_outcome'",
            "unstamped tool outcome schema cannot be adopted",
        ),
    ] {
        let (_temp, database, lock_root) = fixture();
        SqliteAuthorityStore::provision(&database, &lock_root)?;
        let connection = Connection::open(&database)?;
        connection.execute_batch(damage)?;
        assert_tool_outcome_preflight_refusal(
            &database,
            &lock_root,
            chio_kernel::tool_outcome::ToolOutcomeStoreError::Invariant(detail.to_owned()),
        )?;
    }
    Ok(())
}
