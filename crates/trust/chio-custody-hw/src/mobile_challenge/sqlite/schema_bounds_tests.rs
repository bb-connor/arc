use rusqlite::ffi;
use rusqlite::types::Value;

use super::SqliteMobileChallengeStore;

#[test]
fn app_attest_key_id_refuses_nul_padded_text() -> Result<(), Box<dyn std::error::Error>> {
    let store = SqliteMobileChallengeStore::open_in_memory()?;
    let connection = store.lock()?;
    let insert =
        "INSERT INTO chio_app_attest_counters (key_id, app_id, counter) VALUES (?1, 'app', 0)";
    let padded = connection.execute(
        insert,
        [Value::Text(format!("key\0{}", "a".repeat(1 << 20)))],
    );
    assert!(
        matches!(
            &padded,
            Err(rusqlite::Error::SqliteFailure(error, Some(_)))
                if error.extended_code == ffi::SQLITE_CONSTRAINT_CHECK
        ),
        "{padded:?}"
    );
    assert_eq!(
        connection.execute(insert, [Value::Text("key".to_owned())])?,
        1
    );
    Ok(())
}
