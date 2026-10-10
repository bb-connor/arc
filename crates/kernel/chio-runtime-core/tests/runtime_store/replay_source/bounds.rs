use super::*;
use chio_runtime_core::MAX_RUNTIME_REPLAY_SOURCE_BYTES;

type Catalog = Vec<(String, String, String, Option<String>)>;

fn entire_catalog(connection: &Connection) -> TestResult<Catalog> {
    Ok(connection
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name")?
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()?)
}

fn assert_invalid<T: std::fmt::Debug>(result: Result<T, ChioRuntimeError>, required_detail: &str) {
    match result {
        Err(ChioRuntimeError::Rejected { code, detail }) => {
            assert_eq!(code, "runtime_replay_source_invalid");
            assert!(detail.contains(required_detail), "{detail}");
        }
        other => panic!("expected bounded replay-source rejection, got {other:?}"),
    }
}

fn assert_sealed_corruption_rejected(
    corrupt: impl FnOnce(&Connection) -> TestResult,
    required_detail: &str,
) -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("bounded-corruption.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    seed_inventory(&store)?;
    let binding = binding()?;
    let seal = store.seal_legacy_replay_source(&binding)?;
    let raw = Connection::open(&path)?;
    corrupt(&raw)?;
    let before = raw_snapshot(&raw)?;
    // Unlike the shared runtime-prefixed snapshot, include unrelated names on
    // protected tables so these assertions also prove they were not removed.
    let catalog = entire_catalog(&raw)?;
    assert_invalid(
        store.load_legacy_replay_source_seal(&binding),
        required_detail,
    );
    assert_invalid(
        store.verify_legacy_replay_source_seal(&seal),
        required_detail,
    );
    assert_invalid(store.seal_legacy_replay_source(&binding), required_detail);
    assert_eq!(raw_snapshot(&raw)?, before);
    assert_eq!(entire_catalog(&raw)?, catalog);
    drop(store);
    assert_invalid(
        SqliteRuntimeOrchestrationStore::open(&path).map(|_| ()),
        required_detail,
    );
    assert_eq!(raw_snapshot(&raw)?, before);
    assert_eq!(entire_catalog(&raw)?, catalog);
    Ok(())
}

fn corrupt_singleton_value(raw: &Connection, value_sql: &str) -> TestResult {
    let trigger: String = raw.query_row(
        "SELECT sql FROM sqlite_schema WHERE name = 'runtime_replay_source_seal_no_update'",
        [],
        |row| row.get(0),
    )?;
    // Deliberately install corrupt storage without changing its final schema.
    // Read validation must reject it independently of SQLite CHECK enforcement.
    raw.execute_batch(
        "PRAGMA ignore_check_constraints = ON;
         DROP TRIGGER runtime_replay_source_seal_no_update;",
    )?;
    raw.execute(
        &format!("UPDATE runtime_replay_source_seal SET canonical_bytes = {value_sql} WHERE singleton = 1"),
        [],
    )?;
    raw.execute_batch(&trigger)?;
    raw.execute_batch("PRAGMA ignore_check_constraints = OFF")?;
    Ok(())
}

#[test]
fn oversized_singleton_blob_is_rejected_with_canonical_schema_intact() -> TestResult {
    assert_sealed_corruption_rejected(
        |raw| {
            corrupt_singleton_value(
                raw,
                &format!("zeroblob({})", MAX_RUNTIME_REPLAY_SOURCE_BYTES + 1),
            )
        },
        "record has invalid type or size",
    )
}

#[test]
fn canonical_json_stored_as_text_is_not_accepted_as_a_seal_blob() -> TestResult {
    assert_sealed_corruption_rejected(
        |raw| corrupt_singleton_value(raw, "CAST(canonical_bytes AS TEXT)"),
        "record has invalid type or size",
    )
}

#[test]
fn unknown_trigger_names_on_protected_tables_are_not_ignored() -> TestResult {
    let statement = "CREATE TRIGGER unrelated_hook BEFORE INSERT ON runtime_consumed_leases
                     BEGIN SELECT 1; END";
    assert_sealed_corruption_rejected(
        |raw| {
            raw.execute_batch(statement)?;
            Ok(())
        },
        "schema differs from its canonical definition",
    )?;

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("unknown-unsealed-catalog.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let raw = Connection::open(&path)?;
    raw.execute_batch(statement)?;
    let before = raw_snapshot(&raw)?;
    let catalog = entire_catalog(&raw)?;
    let binding = binding()?;
    assert_invalid(
        store.seal_legacy_replay_source(&binding),
        "schema differs from its canonical definition",
    );
    assert!(store.load_legacy_replay_source_seal(&binding)?.is_none());
    store.consume_destructive_lease("still-unsealed", "owner")?;
    store.release_destructive_lease("still-unsealed", "owner")?;
    assert_eq!(raw_snapshot(&raw)?, before);
    assert_eq!(entire_catalog(&raw)?, catalog);
    Ok(())
}

#[test]
fn oversized_catalog_text_and_entry_count_are_rejected_before_catalog_loading() -> TestResult {
    assert_sealed_corruption_rejected(
        |raw| {
            raw.execute_batch(&format!(
                "CREATE TRIGGER oversized_hook BEFORE INSERT ON runtime_consumed_leases
                 BEGIN SELECT '{}'; END",
                "x".repeat(65_537)
            ))?;
            Ok(())
        },
        "schema exceeds its bounds",
    )?;
    assert_sealed_corruption_rejected(
        |raw| {
            for index in 0..65 {
                raw.execute_batch(&format!(
                    "CREATE TRIGGER unrelated_hook_{index} BEFORE INSERT ON runtime_consumed_leases
                     BEGIN SELECT 1; END"
                ))?;
            }
            Ok(())
        },
        "schema exceeds its bounds",
    )
}
