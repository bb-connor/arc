//! Durable command aliases require their own exact serving catalog.
use super::*;

pub(super) const SQL: &str = include_str!("../../recovery_command_alias.sql");

/// Claimed predecessor catalogs cannot carry new physical or retained alias
/// custody. The native operation catalog and its signed payloads stay intact.
pub(super) fn verify_predecessor(
    connection: &Connection,
    version: i32,
) -> Result<(), AdmissionOperationStoreError> {
    if !matches!(version, 35..=37) {
        return Ok(());
    }
    verify_admission_operation_schema(connection, version)?;
    require_predecessor_alias_absence(connection)?;
    if version == 37 {
        // Earlier recovery predecessors already receive the exact inventory
        // check in recovery_format_migration before this verifier is called.
        verify_admission_operation_inventory(connection)?;
    }
    Ok(())
}

fn require_predecessor_alias_absence(
    connection: &Connection,
) -> Result<(), AdmissionOperationStoreError> {
    let future: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM admission_operation_recovery_records
                WHERE record_key GLOB 'command-alias:*')
             OR EXISTS(SELECT 1 FROM admission_operation_recovery_events
                WHERE record_key GLOB 'command-alias:*')
             OR EXISTS(SELECT 1 FROM authority_global_commits
                WHERE projection_kind='recovery' AND projection_key GLOB 'command-alias:*')",
            [],
            |row| row.get(0),
        )
        .map_err(sqlite_error)?;
    if future {
        return Err(invariant(
            "predecessor recovery schema contains future command alias custody",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn alias_presence_fixture() -> Result<Connection, rusqlite::Error> {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE admission_operation_recovery_records(record_key TEXT PRIMARY KEY);
             CREATE TABLE admission_operation_recovery_events(record_key TEXT NOT NULL);
             CREATE TABLE authority_global_commits(projection_kind TEXT NOT NULL,projection_key TEXT NOT NULL);",
        )?;
        Ok(connection)
    }

    #[test]
    fn predecessor_alias_absence_is_read_only() -> TestResult {
        let connection = alias_presence_fixture()?;
        let changes = connection.total_changes();
        require_predecessor_alias_absence(&connection)?;
        assert_eq!(connection.total_changes(), changes);
        Ok(())
    }

    #[test]
    fn predecessor_alias_absence_checks_physical_and_retained_custody() -> TestResult {
        for statement in [
            "INSERT INTO admission_operation_recovery_records VALUES ('command-alias:physical')",
            "INSERT INTO admission_operation_recovery_events VALUES ('command-alias:retained')",
            "INSERT INTO authority_global_commits VALUES ('recovery','command-alias:global')",
        ] {
            let connection = alias_presence_fixture()?;
            connection.execute_batch(statement)?;
            let changes = connection.total_changes();
            let error = require_predecessor_alias_absence(&connection)
                .err()
                .ok_or("future alias custody accepted as predecessor")?;
            assert!(error.to_string().contains("future command alias custody"));
            assert_eq!(connection.total_changes(), changes);
        }
        Ok(())
    }

    #[test]
    fn command_alias_index_distinguishes_the_exact_predecessor_catalog() -> TestResult {
        let connection = expected_admission_operation_schema(37)?;
        verify_admission_operation_schema(&connection, 37)?;
        connection.execute_batch(SQL)?;
        assert!(verify_admission_operation_schema(&connection, 37).is_err());
        verify_admission_operation_schema(&connection, 38)?;
        Ok(())
    }

    #[test]
    fn command_alias_index_refuses_a_changed_current_definition() -> TestResult {
        let connection = expected_admission_operation_schema(38)?;
        verify_admission_operation_schema(&connection, 38)?;
        connection.execute_batch(
            "DROP INDEX admission_operation_recovery_command_alias;
             CREATE INDEX admission_operation_recovery_command_alias
             ON admission_operation_recovery_records(record_key,scope_key)
             WHERE kind='command' AND record_key GLOB 'command-alias:*';",
        )?;
        assert!(verify_admission_operation_schema(&connection, 38).is_err());
        Ok(())
    }
}
