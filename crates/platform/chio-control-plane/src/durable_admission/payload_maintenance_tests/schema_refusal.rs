use super::*;

#[test]
fn durable_runtime_refuses_stale_damaged_and_future_tool_outcome_catalogs() -> TestResult {
    for (profile, expected_version, detail) in [
        (
            "stale",
            4,
            "database schema version 4 is not the current schema version 1; refusing to open",
        ),
        (
            "future",
            2,
            "database schema version 2 is not the current schema version 1; refusing to open",
        ),
        (
            "damaged",
            1,
            "tool outcome schema differs from the canonical definition",
        ),
    ] {
        let directory = private_tempdir()?;
        let database = directory.path().join(format!("{profile}.db"));
        let runtime =
            DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
        drop(runtime);
        {
            let connection = Connection::open(&database)?;
            if profile == "damaged" {
                connection.execute_batch("DROP INDEX tool_outcomes_raw_digest_owners")?;
            } else {
                connection.execute(
                    "UPDATE chio_store_schema_versions SET version = ?1 WHERE store_key = 'tool_outcome'",
                    [expected_version],
                )?;
            }
        }
        let error =
            DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())
                .err()
                .ok_or("stale, damaged or future catalog must fail closed")?;
        assert!(
            matches!(&error, CliError::SqliteServingOwner(_)),
            "actual catalog refusal: {error:?}"
        );
        assert!(
            error.to_string().contains(detail),
            "{profile} refusal must name its cause: {error}"
        );
        let connection = Connection::open_with_flags(&database, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let version: i64 = connection.query_row(
            "SELECT version FROM chio_store_schema_versions WHERE store_key = 'tool_outcome'",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(
            version,
            i64::from(expected_version),
            "refusal must not restamp"
        );
    }
    Ok(())
}
