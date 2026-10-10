//! Catalog and predecessor controls do not synthesize captured native authority.
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn presence_fixture() -> Result<Connection, rusqlite::Error> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(
        "CREATE TABLE admission_operation_recovery_records(record_key TEXT PRIMARY KEY,payload BLOB);
         CREATE TABLE admission_operation_recovery_events(record_key TEXT);
         CREATE TABLE authority_global_commits(projection_kind TEXT,projection_key TEXT);",
    )?;
    Ok(connection)
}

#[test]
fn knowledge_predecessor_pristine_raw_restore_and_journal_controls_are_read_only() -> TestResult {
    let connection = presence_fixture()?;
    require_predecessor_absence(&connection)?;
    for (key, payload) in [
        ("knowledge-restore:legacy", r#"{"legacy_body":true}"#),
        (
            "knowledge-restore:v2:actor",
            r#"{"actor_binding":{"principal":"old"}}"#,
        ),
        (
            "knowledge-join:legacy",
            r#"{"knowledge_join_encoding":"interned_labels_v1","labels":{"values":[{"kind":"bottom"}]}}"#,
        ),
        ("knowledge-pin:native-operation:v2:original", "{}"),
    ] {
        connection.execute(
            "INSERT INTO admission_operation_recovery_records VALUES (?1,?2)",
            params![key, payload.as_bytes()],
        )?;
    }
    let changed = connection.total_changes();
    require_predecessor_absence(&connection)?;
    assert_eq!(connection.total_changes(), changed);
    Ok(())
}

#[test]
fn knowledge_predecessor_future_markers_refuse_null_types_and_versions_without_writes() -> TestResult
{
    for payload in [
        r#"{"checkpoint_restore_encoding":null}"#,
        r#"{"checkpoint_restore_encoding":false}"#,
        r#"{"checkpoint_restore_encoding":"interned_label_atoms_v1"}"#,
        r#"{"checkpoint_restore_encoding":"chunked_label_atoms_v1"}"#,
        r#"{"knowledge_join_encoding":null}"#,
        r#"{"knowledge_join_encoding":{}}"#,
        r#"{"knowledge_join_encoding":"interned_label_atoms_v1"}"#,
        r#"{"knowledge_join_encoding":"chunked_label_atoms_v1"}"#,
        r#"{"knowledge_chunk_encoding":"label_atoms_v1"}"#,
    ] {
        let connection = presence_fixture()?;
        connection.execute(
            "INSERT INTO admission_operation_recovery_records VALUES ('knowledge-join:marker',?1)",
            [payload.as_bytes()],
        )?;
        let changed = connection.total_changes();
        assert!(
            require_predecessor_absence(&connection).is_err(),
            "future marker accepted: {payload}"
        );
        assert_eq!(connection.total_changes(), changed);
    }
    Ok(())
}

#[test]
fn knowledge_predecessor_checks_physical_event_and_global_successor_ownership() -> TestResult {
    for pattern in SUCCESSOR_KEYS {
        let key = pattern.replace('*', "fixture");
        for source in 0..3 {
            let connection = presence_fixture()?;
            match source {
                0 => {
                    connection.execute(
                        "INSERT INTO admission_operation_recovery_records VALUES (?1,'{}')",
                        [&key],
                    )?;
                }
                1 => {
                    connection.execute(
                        "INSERT INTO admission_operation_recovery_events VALUES (?1)",
                        [&key],
                    )?;
                }
                _ => {
                    connection.execute(
                        "INSERT INTO authority_global_commits VALUES ('recovery',?1)",
                        [&key],
                    )?;
                }
            }
            let changed = connection.total_changes();
            assert!(
                require_predecessor_absence(&connection).is_err(),
                "future family accepted: {key}, source{source}"
            );
            assert_eq!(connection.total_changes(), changed);
        }
    }
    Ok(())
}

#[test]
fn knowledge_successor_functional_catalog_refuses_exact_predecessor_even_with_lowered_stamp(
) -> TestResult {
    let connection = expected_admission_operation_schema(39)?;
    verify_admission_operation_schema(&connection, 39)?;
    install_current(&connection)?;
    assert!(verify_admission_operation_schema(&connection, 39).is_err());
    verify_admission_operation_schema(&connection, 40)?;
    // This checks the actual catalog predicate, independently of the version
    // ledger. Genuine old39 executable refusal has a separate campaign.
    Ok(())
}

#[test]
fn knowledge_successor_codec_catalog_accepts_legacy_and_atoms_but_refuses_bad_marker_shapes(
) -> TestResult {
    let connection = expected_admission_operation_schema(40)?;
    let scope = "0".repeat(64);
    for (key, payload, accepted) in [
        (
            "knowledge-join:old",
            r#"{"knowledge_join_encoding":"interned_labels_v1","labels":{"values":[{"kind":"bottom"}]}}"#,
            true,
        ),
        (
            "knowledge-join:atoms",
            r#"{"knowledge_join_encoding":"interned_label_atoms_v1","labels":{"atoms":[],"readers":[],"policies":[],"values":[{"kind":"bottom"}]}}"#,
            true,
        ),
        (
            "knowledge-restore:v2:atoms",
            r#"{"checkpoint_restore_encoding":"interned_label_atoms_v1","labels":{"atoms":[],"readers":[],"policies":[],"values":[{"kind":"bottom"}]}}"#,
            true,
        ),
        ("knowledge-restore:raw", r#"{"legacy_body":true}"#, true),
        (
            "knowledge-restore:null",
            r#"{"checkpoint_restore_encoding":null}"#,
            false,
        ),
        (
            "knowledge-restore:old-name",
            r#"{"checkpoint_restore_encoding":"interned_labels_v1"}"#,
            false,
        ),
        (
            "knowledge-join:unknown",
            r#"{"knowledge_join_encoding":"future"}"#,
            false,
        ),
        (
            "unrelated:atoms",
            r#"{"knowledge_join_encoding":"interned_label_atoms_v1"}"#,
            false,
        ),
        (
            "knowledge-join:wrong-palette",
            r#"{"knowledge_join_encoding":"interned_label_atoms_v1","labels":null}"#,
            false,
        ),
        (
            "knowledge-encoding-chunk:empty",
            r#"{"knowledge_chunk_encoding":"label_atoms_v1"}"#,
            false,
        ),
    ] {
        let result = connection.execute(
            "INSERT INTO admission_operation_recovery_records(record_key,scope_key,kind,version,payload)
             VALUES (?1,?2,'command',1,?3)", params![key,&scope,payload.as_bytes()],
        );
        assert_eq!(result.is_ok(), accepted, "codec shape {key}: {result:?}");
    }
    Ok(())
}

#[test]
fn knowledge_predecessor_malformed_catalog_refuses_before_successor_installation() -> TestResult {
    let connection = expected_admission_operation_schema(39)?;
    connection
        .execute_batch("CREATE TABLE admission_operation_recovery_untrusted_extra(value TEXT)")?;
    let before: i64 =
        connection.query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))?;
    assert!(verify_predecessor(&connection, 39).is_err());
    assert_eq!(
        connection.query_row("SELECT count(*) FROM sqlite_schema", [], |row| row
            .get::<_, i64>(0))?,
        before
    );
    assert!(!connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='admission_operation_recovery_reference_capacity')", [], |row| row.get::<_, bool>(0))?);
    Ok(())
}
