//! Original reader capacity, without pretending a metadata access measures RSS.
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture() -> Result<(Connection, AdmissionOperationId), Box<dyn std::error::Error>> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(
        "CREATE TABLE admission_operation_terminal_records (
             operation_id TEXT NOT NULL,
             record_kind TEXT NOT NULL,
             record_id TEXT NOT NULL,
             record_digest TEXT NOT NULL,
             record_json BLOB NOT NULL,
             PRIMARY KEY (operation_id, record_kind, record_id)
         );",
    )?;
    Ok((
        connection,
        AdmissionOperationId::from_persisted("a".repeat(64))?,
    ))
}

fn insert(
    connection: &Connection,
    operation: &AdmissionOperationId,
    record: usize,
    bytes: &[u8],
) -> rusqlite::Result<usize> {
    connection.execute(
        "INSERT INTO admission_operation_terminal_records
         (operation_id, record_kind, record_id, record_digest, record_json)
         VALUES (?1, 'incident', ?2, ?3, ?4)",
        params![
            operation.as_str(),
            format!("record-{record:03}"),
            sha256_hex(bytes),
            bytes
        ],
    )
}

#[test]
fn rc2_terminal_record_reader_accepts_exact_bytes_and_refuses_one_over() -> TestResult {
    let (connection, operation) = fixture()?;
    let mut exact = vec![b'x'; MAX_TERMINAL_RECORD_BYTES];
    exact[0] = b'"';
    exact[MAX_TERMINAL_RECORD_BYTES - 1] = b'"';
    insert(&connection, &operation, 0, &exact)?;
    let records = load_terminal_records(&connection, &operation)?;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].record_json, exact);
    connection.execute(
        "UPDATE admission_operation_terminal_records SET record_json = zeroblob(?1)",
        [i64::try_from(MAX_TERMINAL_RECORD_BYTES + 1)?],
    )?;
    assert!(
        matches!(load_terminal_records(&connection, &operation), Err(AdmissionOperationStoreError::Invariant(message)) if message.contains("terminal record") && message.contains("bounds")),
        "original reader returned the oversized payload instead of refusing its byte bound"
    );
    Ok(())
}

#[test]
fn rc2_terminal_record_reader_accepts_exact_rows_and_refuses_one_over() -> TestResult {
    let (connection, operation) = fixture()?;
    for record in 0..MAX_TERMINAL_RECORDS {
        insert(&connection, &operation, record, b"{}")?;
    }
    assert_eq!(
        load_terminal_records(&connection, &operation)?.len(),
        MAX_TERMINAL_RECORDS
    );
    insert(&connection, &operation, MAX_TERMINAL_RECORDS, b"{}")?;
    assert!(
        matches!(load_terminal_records(&connection, &operation), Err(AdmissionOperationStoreError::Invariant(message)) if message.contains("terminal record") && message.contains("count")),
        "original reader returned an over-cap collection instead of refusing bounded work"
    );
    Ok(())
}

#[test]
fn rc2_terminal_record_reader_refuses_empty_payload_before_decode() -> TestResult {
    let (connection, operation) = fixture()?;
    insert(&connection, &operation, 0, &[])?;
    assert!(
        matches!(load_terminal_records(&connection, &operation), Err(AdmissionOperationStoreError::Invariant(message)) if message.contains("terminal record") && message.contains("bounds")),
        "original reader accepted an empty terminal payload"
    );
    Ok(())
}

fn check_projection_payload(field: &str, limit: usize) -> TestResult {
    let (connection, operation) = fixture()?;
    connection.execute_batch(
        "CREATE TABLE admission_operation_terminal_projections (
             operation_id TEXT PRIMARY KEY,
             source_operation_version INTEGER,
             terminal_operation_version INTEGER,
             terminal_state TEXT,
             projection_body_digest TEXT,
             projection_digest TEXT,
             projection_json BLOB,
             manifest_json BLOB,
             record_count INTEGER,
             committed_at_unix_ms INTEGER,
             store_uuid TEXT,
             store_lease_id TEXT,
             store_owner_epoch INTEGER
         );",
    )?;
    let document = |size: usize| {
        let mut bytes = vec![b'x'; size];
        bytes[0] = b'"';
        bytes[size - 1] = b'"';
        bytes
    };
    let projection = document(MAX_TERMINAL_PROJECTION_BYTES);
    let manifest = document(MAX_TERMINAL_MANIFEST_BYTES);
    connection.execute(
        "INSERT INTO admission_operation_terminal_projections VALUES
         (?1, 1, 2, 'outcome_unknown_after_dispatch', ?2, ?3, ?4, ?5, 1, 1,
          'fixture-store', 'fixture-lease', 1)",
        params![
            operation.as_str(),
            sha256_hex(&projection),
            sha256_hex(&manifest),
            &projection,
            &manifest
        ],
    )?;
    let loaded = super::super::load_terminal_projection_tx(&connection, &operation)?
        .ok_or("exact projection disappeared")?;
    assert_eq!(loaded.projection_json, projection);
    assert_eq!(loaded.manifest_json, manifest);
    connection.execute(
        &format!("UPDATE admission_operation_terminal_projections SET {field} = zeroblob(?1)"),
        [i64::try_from(limit + 1)?],
    )?;
    assert!(
        matches!(super::super::load_terminal_projection_tx(&connection, &operation), Err(AdmissionOperationStoreError::Invariant(message)) if message.contains("terminal") && message.contains("bounds")),
        "original projection loader copied {field} beyond its native writer ceiling"
    );
    Ok(())
}

#[test]
fn rc2_terminal_projection_reader_accepts_exact_projection_bytes_and_refuses_one_over() -> TestResult
{
    check_projection_payload("projection_json", MAX_TERMINAL_PROJECTION_BYTES)
}

#[test]
fn rc2_terminal_projection_reader_accepts_exact_manifest_bytes_and_refuses_one_over() -> TestResult
{
    check_projection_payload("manifest_json", MAX_TERMINAL_MANIFEST_BYTES)
}

#[test]
fn rc2_metadata_terminal_records_preserve_byte_bounded_ids_and_refuse_oversized_text() -> TestResult
{
    let (connection, operation) = fixture()?;
    insert(&connection, &operation, 0, b"{}")?;
    let exact_id = "\u{00e9}".repeat(256);
    connection.execute(
        "UPDATE admission_operation_terminal_records SET record_id = ?1",
        [&exact_id],
    )?;
    assert_eq!(
        load_terminal_records(&connection, &operation)?[0].record_id,
        exact_id
    );
    let cases = [
        ("record_kind", "incident".to_owned(), 512),
        ("record_id", exact_id, 512),
        ("record_digest", sha256_hex(b"{}"), 64),
    ];
    let mut copied_fields = Vec::new();
    for (field, original, limit) in cases {
        // A 513-byte identifier has only 257 Unicode characters. A SQL
        // character-length ceiling would not enforce the writer's byte limit.
        let oversized = format!("{}x", "\u{00e9}".repeat(limit / 2));
        connection.execute(
            &format!("UPDATE admission_operation_terminal_records SET {field} = ?1"),
            [&oversized],
        )?;
        if !matches!(load_terminal_records(&connection, &operation),
            Err(AdmissionOperationStoreError::Invariant(message))
                if message.contains("terminal metadata") && message.contains("bounds"))
        {
            copied_fields.push(field);
        }
        connection.execute(
            &format!("UPDATE admission_operation_terminal_records SET {field} = ?1"),
            [&original],
        )?;
    }
    assert!(
        copied_fields.is_empty(),
        "original terminal reader accepted oversized metadata fields: {copied_fields:?}"
    );
    Ok(())
}

#[test]
fn rc2_metadata_terminal_projection_refuses_oversized_text_before_owned_payloads() -> TestResult {
    let (connection, operation) = fixture()?;
    connection.execute_batch(
        "CREATE TABLE admission_operation_terminal_projections (
             operation_id TEXT PRIMARY KEY,
             source_operation_version INTEGER,
             terminal_operation_version INTEGER,
             terminal_state TEXT,
             projection_body_digest TEXT,
             projection_digest TEXT,
             projection_json BLOB,
             manifest_json BLOB,
             record_count INTEGER,
             committed_at_unix_ms INTEGER,
             store_uuid TEXT,
             store_lease_id TEXT,
             store_owner_epoch INTEGER
         );",
    )?;
    let exact_fence_id = "\u{00e9}".repeat(256);
    connection.execute(
        "INSERT INTO admission_operation_terminal_projections VALUES
         (?1, 1, 2, 'outcome_unknown_after_dispatch', ?2, ?3, ?4, ?4, 1, 1, ?5, ?5, 1)",
        params![
            operation.as_str(),
            "a".repeat(64),
            "b".repeat(64),
            b"{}".as_slice(),
            &exact_fence_id
        ],
    )?;
    let exact = super::super::load_terminal_projection_tx(&connection, &operation)?
        .ok_or("exact metadata projection disappeared")?;
    assert_eq!(exact.store_uuid, exact_fence_id);
    assert_eq!(exact.store_lease_id, exact_fence_id);
    let cases = [
        (
            "terminal_state",
            "outcome_unknown_after_dispatch".to_owned(),
            512,
        ),
        ("projection_body_digest", "a".repeat(64), 64),
        ("projection_digest", "b".repeat(64), 64),
        ("store_uuid", exact_fence_id.clone(), 512),
        ("store_lease_id", exact_fence_id, 512),
    ];
    let mut copied_fields = Vec::new();
    for (field, original, limit) in cases {
        let oversized = format!("{}x", "\u{00e9}".repeat(limit / 2));
        connection.execute(
            &format!("UPDATE admission_operation_terminal_projections SET {field} = ?1"),
            [&oversized],
        )?;
        if !matches!(super::super::load_terminal_projection_tx(&connection, &operation),
            Err(AdmissionOperationStoreError::Invariant(message))
                if message.contains("terminal metadata") && message.contains("bounds"))
        {
            copied_fields.push(field);
        }
        connection.execute(
            &format!("UPDATE admission_operation_terminal_projections SET {field} = ?1"),
            [&original],
        )?;
    }
    assert!(
        copied_fields.is_empty(),
        "original projection reader accepted oversized metadata fields: {copied_fields:?}"
    );
    Ok(())
}
