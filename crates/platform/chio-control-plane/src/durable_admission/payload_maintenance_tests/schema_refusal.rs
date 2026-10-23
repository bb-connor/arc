use super::*;
use chio_kernel::tool_outcome::ToolOutcomeStoreError;
use chio_store_sqlite::SqliteServingOwnerError;

#[test]
fn durable_runtime_refuses_noncurrent_and_damaged_tool_outcome_catalogs() -> TestResult {
    for (version, damage) in [(4, false), (2, false), (1, true)] {
        let directory = private_tempdir()?;
        let database = directory.path().join("outcome-catalog.db");
        let runtime =
            DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())?;
        drop(runtime);
        let expected = if damage {
            ToolOutcomeStoreError::Invariant(
                "tool outcome schema differs from the canonical definition".to_owned(),
            )
        } else {
            ToolOutcomeStoreError::NoncurrentSchema {
                found: version,
                current: 1,
            }
        };
        {
            let connection = Connection::open(&database)?;
            if damage {
                connection.execute_batch("DROP INDEX tool_outcomes_raw_digest_owners")?;
            } else {
                connection.execute_batch("PRAGMA ignore_check_constraints = ON")?;
                connection.execute(
                    "UPDATE chio_store_schema_versions SET version = ?1 WHERE store_key = 'tool_outcome'",
                    [version],
                )?;
                connection.execute_batch("PRAGMA ignore_check_constraints = OFF")?;
            }
            connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
        }
        let image = std::fs::read(&database)?;
        let error =
            DurableAdmissionRuntime::open_with_clock(&database, chio_test_support::clock::clock())
                .err()
                .ok_or("invalid outcome catalog was accepted")?;
        let CliError::SqliteServingOwner(SqliteServingOwnerError::ToolOutcomeSchema(source)) =
            error
        else {
            return Err(format!("unexpected catalog refusal: {error}").into());
        };
        assert_eq!(source, expected);
        assert_eq!(std::fs::read(&database)?, image);
    }
    Ok(())
}
