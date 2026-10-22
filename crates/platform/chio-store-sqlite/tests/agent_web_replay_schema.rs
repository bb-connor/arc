use chio_store_sqlite::{
    SchemaVersionError, SqliteAgentWebReplayStore, SqliteAgentWebReplayStoreError,
};
use rusqlite::Connection;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn catalog(connection: &Connection) -> rusqlite::Result<Vec<(String, String, Option<String>)>> {
    connection
        .prepare("SELECT type, name, sql FROM sqlite_schema ORDER BY type, name")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect()
}

#[test]
fn fresh_replay_store_is_stamped_v1_and_reopens() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("replays.sqlite");
    drop(SqliteAgentWebReplayStore::open(&path)?);
    let connection = Connection::open(&path)?;
    let application_id: i32 =
        connection.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    assert_eq!(application_id, 0x4348_494f);
    let versions: Vec<(String, i32)> = connection
        .prepare("SELECT store_key, version FROM chio_store_schema_versions ORDER BY store_key")?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<_, _>>()?;
    assert_eq!(versions, vec![("agent_web_replay".to_owned(), 1)]);
    let before = catalog(&connection)?;
    drop(SqliteAgentWebReplayStore::open(&path)?);
    assert_eq!(catalog(&connection)?, before);
    Ok(())
}

#[test]
fn replay_catalog_damage_is_refused_without_repair() -> TestResult {
    for (kind, name) in [
        ("TABLE", "chio_agent_web_replays"),
        ("TABLE", "chio_agent_web_replay_reservations"),
        ("TABLE", "chio_agent_web_replay_reservation_entries"),
        ("TABLE", "chio_agent_web_replay_clock"),
        ("TABLE", "chio_agent_web_replay_limits"),
        ("INDEX", "idx_chio_agent_web_replays_expires_at"),
        ("INDEX", "idx_chio_agent_web_replay_reservations_expires_at"),
        (
            "INDEX",
            "idx_chio_agent_web_replay_reservation_entries_marker",
        ),
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("replays.sqlite");
        drop(SqliteAgentWebReplayStore::open(&path)?);
        let connection = Connection::open(&path)?;
        connection.execute_batch(&format!("DROP {kind} {name}"))?;
        let before = catalog(&connection)?;
        assert!(
            matches!(
                SqliteAgentWebReplayStore::open(&path),
                Err(SqliteAgentWebReplayStoreError::Schema(
                    SchemaVersionError::CatalogMismatch
                ))
            ),
            "{name}"
        );
        assert_eq!(catalog(&connection)?, before, "{name}");
    }
    Ok(())
}

#[test]
fn replay_limits_are_not_reconstructed() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("replays.sqlite");
    drop(SqliteAgentWebReplayStore::open(&path)?);
    let connection = Connection::open(&path)?;
    connection.execute("DELETE FROM chio_agent_web_replay_limits", [])?;
    assert!(matches!(
        SqliteAgentWebReplayStore::open(&path),
        Err(SqliteAgentWebReplayStoreError::MissingLimits)
    ));
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_agent_web_replay_limits",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn populated_unstamped_replay_storage_is_not_adopted() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("replays.sqlite");
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "CREATE TABLE other_state (value TEXT); INSERT INTO other_state VALUES ('retained');",
    )?;
    let before = catalog(&connection)?;
    assert!(matches!(
        SqliteAgentWebReplayStore::open(&path),
        Err(SqliteAgentWebReplayStoreError::Schema(
            SchemaVersionError::ForeignDatabase {
                found: 0,
                expected: 0x4348_494f
            }
        ))
    ));
    assert_eq!(catalog(&connection)?, before);
    let value: String =
        connection.query_row("SELECT value FROM other_state", [], |row| row.get(0))?;
    assert_eq!(value, "retained");
    Ok(())
}

#[test]
fn missing_replay_namespace_is_not_recreated() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("replays.sqlite");
    drop(SqliteAgentWebReplayStore::open(&path)?);
    let connection = Connection::open(&path)?;
    connection.execute("DELETE FROM chio_store_schema_versions", [])?;
    assert!(matches!(SqliteAgentWebReplayStore::open(&path),
        Err(SqliteAgentWebReplayStoreError::Schema(SchemaVersionError::MissingSchema { store_key })) if store_key == "agent_web_replay"));
    let count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM chio_store_schema_versions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn damaged_replay_catalog_refuses_before_pruning_markers() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("replays.sqlite");
    drop(SqliteAgentWebReplayStore::open(&path)?);
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "INSERT INTO chio_agent_web_replays VALUES ('scope', 'retained', 1, 10);
         INSERT INTO chio_agent_web_replay_clock VALUES (1, 1000);
         DROP INDEX idx_chio_agent_web_replays_expires_at;",
    )?;
    assert!(matches!(
        SqliteAgentWebReplayStore::open(&path),
        Err(SqliteAgentWebReplayStoreError::Schema(
            SchemaVersionError::CatalogMismatch
        ))
    ));
    let count: i64 =
        connection.query_row("SELECT COUNT(*) FROM chio_agent_web_replays", [], |row| {
            row.get(0)
        })?;
    assert_eq!(count, 1);
    let high_water: i64 = connection.query_row(
        "SELECT wall_clock_high_water FROM chio_agent_web_replay_clock",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(high_water, 1000);
    Ok(())
}
