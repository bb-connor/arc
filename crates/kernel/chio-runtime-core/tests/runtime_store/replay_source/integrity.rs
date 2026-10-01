use super::*;
use chio_runtime_core::{MAX_RUNTIME_REPLAY_SOURCE_BYTES, MAX_RUNTIME_REPLAY_SOURCE_MARKERS};

fn replace_under_restored_trigger(
    raw: &Connection,
    trigger: &str,
    mutation: impl FnOnce(&Connection) -> TestResult,
) -> TestResult {
    let definition: String = raw.query_row(
        "SELECT sql FROM sqlite_schema WHERE type = 'trigger' AND name = ?1",
        [trigger],
        |row| row.get(0),
    )?;
    raw.execute_batch(&format!("DROP TRIGGER {trigger}"))?;
    mutation(raw)?;
    raw.execute_batch(&definition)?;
    Ok(())
}

fn assert_corruption_not_repaired(
    corrupt: impl FnOnce(&Connection, &RuntimeReplaySourceSeal) -> TestResult,
) -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("corrupt-seal.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    seed_inventory(&store)?;
    let binding = binding()?;
    let seal = store.seal_legacy_replay_source(&binding)?;
    let raw = Connection::open(&path)?;
    corrupt(&raw, &seal)?;
    let corrupted = raw_snapshot(&raw)?;
    assert_code(
        store.verify_legacy_replay_source_seal(&seal),
        "runtime_replay_source_invalid",
    );
    assert_code(
        store.load_legacy_replay_source_seal(&binding),
        "runtime_replay_source_invalid",
    );
    assert_code(
        store.seal_legacy_replay_source(&binding),
        "runtime_replay_source_invalid",
    );
    assert_eq!(
        raw_snapshot(&raw)?,
        corrupted,
        "seal APIs must not repair corruption"
    );
    drop(store);
    match SqliteRuntimeOrchestrationStore::open(&path) {
        Err(error) => assert_eq!(error.code(), "runtime_replay_source_invalid"),
        Ok(_) => panic!("reopening a corrupt sealed source must fail closed"),
    }
    assert_eq!(
        raw_snapshot(&raw)?,
        corrupted,
        "open must not recreate damaged seal or replay schema"
    );
    Ok(())
}

#[test]
fn missing_or_replaced_barriers_are_rejected_without_repair() -> TestResult {
    for (table, _, name) in TABLES {
        for suffix in ["no_insert", "no_update", "no_delete"] {
            let trigger = format!("runtime_replay_source_{name}_{suffix}");
            assert_corruption_not_repaired(|raw, _| {
                raw.execute_batch(&format!("DROP TRIGGER {trigger}"))?;
                Ok(())
            })?;
        }
        assert_corruption_not_repaired(|raw, _| {
            let trigger = format!("runtime_replay_source_{name}_no_insert");
            raw.execute_batch(&format!(
                "DROP TRIGGER {trigger}; CREATE TRIGGER {trigger} BEFORE INSERT ON {table} BEGIN SELECT 1; END;"
            ))?;
            Ok(())
        })?;
    }
    for suffix in ["no_insert", "no_update", "no_delete"] {
        assert_corruption_not_repaired(|raw, _| {
            raw.execute_batch(&format!("DROP TRIGGER runtime_replay_source_seal_{suffix}"))?;
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn removed_seal_or_replay_tables_are_not_recreated_on_open() -> TestResult {
    for table in [
        "runtime_replay_source_seal",
        "runtime_consumed_leases",
        "runtime_consumed_treaty_continuations",
        "runtime_consumed_swarm_continuations",
    ] {
        assert_corruption_not_repaired(|raw, _| {
            raw.execute_batch(&format!("DROP TABLE {table}"))?;
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn missing_singleton_cannot_be_resealed_as_an_unsealed_source() -> TestResult {
    assert_corruption_not_repaired(|raw, _| {
        replace_under_restored_trigger(raw, "runtime_replay_source_seal_no_delete", |raw| {
            raw.execute(
                "DELETE FROM runtime_replay_source_seal WHERE singleton = 1",
                [],
            )?;
            Ok(())
        })
    })
}

#[test]
fn malformed_noncanonical_and_digest_mismatched_seal_bytes_are_not_repaired() -> TestResult {
    for mutation in 0..3 {
        assert_corruption_not_repaired(|raw, seal| {
            let bytes = match mutation {
                0 => b"{".to_vec(),
                1 => {
                    let mut bytes = seal.canonical_bytes()?;
                    bytes.push(b' ');
                    bytes
                }
                _ => {
                    let mut value: serde_json::Value =
                        serde_json::from_slice(&seal.canonical_bytes()?)?;
                    value["inventorySha256"] = serde_json::Value::String("f".repeat(64));
                    chio_core_types::crypto::canonical_json_bytes(&value)?
                }
            };
            replace_under_restored_trigger(raw, "runtime_replay_source_seal_no_update", |raw| {
                raw.execute("UPDATE runtime_replay_source_seal SET canonical_bytes = ?1 WHERE singleton = 1", [bytes])?;
                Ok(())
            })
        })?;
    }
    Ok(())
}

#[test]
fn changed_inventory_with_restored_valid_barriers_is_detected_for_all_kinds() -> TestResult {
    for (table, key, name) in TABLES {
        assert_corruption_not_repaired(|raw, _| {
            replace_under_restored_trigger(
                raw,
                &format!("runtime_replay_source_{name}_no_update"),
                |raw| {
                    raw.execute(&format!("UPDATE {table} SET admission_id = 'forged-owner' WHERE {key} = 'resource-a'"), [])?;
                    Ok(())
                },
            )
        })?;
    }
    Ok(())
}

fn assert_invalid_inventory_rolls_back(
    populate: impl FnOnce(&mut Connection) -> TestResult,
    expected: &str,
) -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("rejected-inventory.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    let mut raw = Connection::open(&path)?;
    populate(&mut raw)?;
    let before = raw_snapshot(&raw)?;
    let binding = binding()?;
    assert_code(store.seal_legacy_replay_source(&binding), expected);
    assert_eq!(
        raw_snapshot(&raw)?,
        before,
        "failed seal must leave no barriers, seal row, or marker mutations"
    );
    assert!(store.load_legacy_replay_source_seal(&binding)?.is_none());
    // A failed transaction must not have permanently retired this namespace.
    store.consume_swarm_continuation("rollback-probe", "rollback-owner")?;
    store.release_swarm_continuation("rollback-probe", "rollback-owner")?;
    assert_eq!(raw_snapshot(&raw)?, before);
    Ok(())
}

#[test]
fn invalid_inventory_identifiers_roll_back_the_entire_seal() -> TestResult {
    for (table, key, _) in TABLES {
        for (resource, owner) in [
            (
                rusqlite::types::Value::Text(String::new()),
                rusqlite::types::Value::Text("owner".into()),
            ),
            (
                rusqlite::types::Value::Text("x".repeat(513)),
                rusqlite::types::Value::Text("owner".into()),
            ),
            (
                rusqlite::types::Value::Blob(vec![0xff]),
                rusqlite::types::Value::Text("owner".into()),
            ),
            (
                rusqlite::types::Value::Text("valid-resource".into()),
                rusqlite::types::Value::Text(String::new()),
            ),
            (
                rusqlite::types::Value::Text("valid-resource".into()),
                rusqlite::types::Value::Text("x".repeat(513)),
            ),
            (
                rusqlite::types::Value::Text("valid-resource".into()),
                rusqlite::types::Value::Blob(vec![0xff]),
            ),
        ] {
            assert_invalid_inventory_rolls_back(
                |raw| {
                    raw.execute(
                        &format!("INSERT INTO {table}({key}, admission_id) VALUES (?1, ?2)"),
                        params![resource, owner],
                    )?;
                    Ok(())
                },
                "runtime_replay_source_invalid",
            )?;
        }
    }
    Ok(())
}

#[test]
fn overcount_inventory_rolls_back_the_entire_seal() -> TestResult {
    assert_invalid_inventory_rolls_back(
        |raw| {
            // No single table is oversized. The complete three-kind inventory is.
            let count = MAX_RUNTIME_REPLAY_SOURCE_MARKERS / TABLES.len() + 1;
            assert!(count * TABLES.len() > MAX_RUNTIME_REPLAY_SOURCE_MARKERS);
            for (table, key, _) in TABLES {
                let sql = format!(
                    "WITH RECURSIVE ids(id) AS (SELECT 1 UNION ALL SELECT id + 1 FROM ids WHERE id < ?1)
                     INSERT INTO {table}({key}, admission_id)
                     SELECT printf('resource-%05d', id), 'owner' FROM ids"
                );
                raw.execute(&sql, [i64::try_from(count)?])?;
            }
            Ok(())
        },
        "runtime_replay_source_inventory_limit",
    )
}

fn fill_long_inventory(raw: &mut Connection, count: usize) -> TestResult {
    assert!(count <= MAX_RUNTIME_REPLAY_SOURCE_MARKERS);
    let tx = raw.transaction()?;
    {
        let mut statement = tx.prepare(
            "INSERT INTO runtime_consumed_leases(lease_id, admission_id) VALUES (?1, ?2)",
        )?;
        let suffix = "x".repeat(507);
        let owner = "o".repeat(512);
        for index in 0..count {
            let resource = format!("{index:05}{suffix}");
            assert_eq!(resource.len(), 512);
            statement.execute(params![resource, owner])?;
        }
    }
    tx.commit()?;
    Ok(())
}

#[test]
fn encoded_inventory_size_limit_rolls_back_even_when_raw_ids_fit() -> TestResult {
    assert_invalid_inventory_rolls_back(
        |raw| {
            // These valid identifiers fit the aggregate raw-byte bound exactly.
            // Canonical marker field names and seal metadata exceed the wire bound.
            let count = MAX_RUNTIME_REPLAY_SOURCE_BYTES / 1024;
            fill_long_inventory(raw, count)
        },
        "runtime_replay_source_inventory_limit",
    )
}

#[test]
fn raw_inventory_size_limit_rolls_back_before_creating_any_seal_objects() -> TestResult {
    assert_invalid_inventory_rolls_back(
        |raw| fill_long_inventory(raw, MAX_RUNTIME_REPLAY_SOURCE_BYTES / 1024 + 1),
        "runtime_replay_source_inventory_limit",
    )
}

#[test]
fn uppercase_partial_seal_objects_are_not_mistaken_for_an_unsealed_source() -> TestResult {
    for partial_schema in [
        "CREATE TABLE RUNTIME_REPLAY_SOURCE_SEAL(singleton INTEGER, canonical_bytes BLOB)",
        "CREATE TRIGGER RUNTIME_REPLAY_SOURCE_LEASE_NO_INSERT BEFORE INSERT ON runtime_consumed_leases BEGIN SELECT 1; END",
    ] {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("uppercase-partial.sqlite3");
        let store = SqliteRuntimeOrchestrationStore::open(&path)?;
        let raw = Connection::open(&path)?;
        raw.execute_batch(partial_schema)?;
        let before = raw_snapshot(&raw)?;
        let binding = binding()?;
        assert_code(store.load_legacy_replay_source_seal(&binding), "runtime_replay_source_invalid");
        assert_code(store.seal_legacy_replay_source(&binding), "runtime_replay_source_invalid");
        assert_code(store.consume_destructive_lease("late-lease", "late-owner"), "runtime_replay_source_sealed");
        assert_eq!(raw_snapshot(&raw)?, before);
        drop(store);
        match SqliteRuntimeOrchestrationStore::open(&path) {
            Err(error) => assert_eq!(error.code(), "runtime_replay_source_invalid"),
            Ok(_) => panic!("uppercase partial seal schema was silently accepted"),
        }
        assert_eq!(raw_snapshot(&raw)?, before);
    }
    Ok(())
}
