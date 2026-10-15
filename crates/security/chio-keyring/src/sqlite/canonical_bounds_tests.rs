use rusqlite::types::Value;
use rusqlite::{ffi, Connection};

use super::SCHEMA;
use crate::verifier::VERIFIER_SCHEMA;
use crate::witness::WITNESS_SCHEMA;

fn nul_padded_text() -> Value {
    Value::Text(format!("{{}}\0{}", "a".repeat(1 << 20)))
}

#[test]
fn canonical_blob_columns_refuse_nul_padded_text() -> Result<(), Box<dyn std::error::Error>> {
    for (schema, insert) in [
        (
            SCHEMA,
            "INSERT INTO key_activations (event_id, signing_epoch, canonical_activation) \
             VALUES ('event', 1, ?1)",
        ),
        (
            VERIFIER_SCHEMA,
            "INSERT INTO verifier_events (sequence, canonical_envelope) VALUES (1, ?1)",
        ),
        (
            WITNESS_SCHEMA,
            "INSERT INTO witness_events (sequence, canonical_envelope) VALUES (1, ?1)",
        ),
    ] {
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(schema)?;
        let padded = connection.execute(insert, [nul_padded_text()]);
        assert!(
            matches!(
                &padded,
                Err(rusqlite::Error::SqliteFailure(error, Some(_)))
                    if error.extended_code == ffi::SQLITE_CONSTRAINT_CHECK
            ),
            "{insert}: {padded:?}"
        );
        assert_eq!(
            connection.execute(insert, [Value::Blob(b"{}".to_vec())])?,
            1
        );
    }
    Ok(())
}
