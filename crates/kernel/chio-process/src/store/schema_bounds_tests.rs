use rusqlite::types::Value;
use rusqlite::{ffi, Connection};

#[test]
fn state_blob_digest_refuses_nul_padded_text() -> Result<(), Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(include_str!("../store.sql"))?;
    connection.pragma_update(None, "foreign_keys", "OFF")?;
    let digest = "0".repeat(64);
    let insert =
        "INSERT INTO process_state_blobs (process_id, sha256, data) VALUES ('p', ?1, x'00')";
    let padded = connection.execute(
        insert,
        [Value::Text(format!("{digest}\0{}", "a".repeat(1 << 20)))],
    );
    assert!(
        matches!(
            &padded,
            Err(rusqlite::Error::SqliteFailure(error, Some(_)))
                if error.extended_code == ffi::SQLITE_CONSTRAINT_CHECK
        ),
        "{padded:?}"
    );
    assert_eq!(connection.execute(insert, [Value::Text(digest)])?, 1);
    Ok(())
}
