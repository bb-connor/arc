use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn recovery_install_creates_the_exact_release_lookup_index_on_fresh_stores() -> TestResult {
    let installed =
        expected_admission_operation_schema(ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)?;
    // The same SQL bytes install for the compiled current catalog and for
    // supported migrations: compare the stored statement against a fresh
    // execution of the maintained source file itself.
    let source = Connection::open_in_memory()?;
    source.execute_batch(
        "CREATE TABLE admission_operation_recovery_records (
             record_key TEXT PRIMARY KEY, scope_key TEXT, kind TEXT, version INTEGER,
             payload BLOB, native_namespace TEXT, native_request TEXT);",
    )?;
    source.execute_batch(include_str!(
        "../../../recovery_knowledge_join_release_index.sql"
    ))?;
    let index_sql = |connection: &Connection| {
        connection.query_row(
            "SELECT type,tbl_name,sql FROM sqlite_schema
             WHERE name='idx_recovery_knowledge_join_release'",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
    };
    let (installed_type, installed_table, installed_sql) = index_sql(&installed)?;
    let (_, _, source_sql) = index_sql(&source)?;
    assert_eq!(installed_type, "index");
    assert_eq!(installed_table, "admission_operation_recovery_records");
    assert_eq!(
        installed_sql, source_sql,
        "fresh current stores and migrations share the exact index SQL"
    );
    Ok(())
}

#[test]
fn knowledge_codec_catalog_accepts_current_encodings_and_refuses_experimental_markers() -> TestResult
{
    let connection =
        expected_admission_operation_schema(ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)?;
    let scope = "0".repeat(64);
    for (key, payload, accepted) in [
        (
            "knowledge-join:old",
            r#"{"knowledge_join_encoding":"interned_labels_v1","labels":{"values":[{"kind":"bottom"}]}}"#,
            false,
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

/// One release chunk and root row shaped as the encoded release writer emits.
fn release_rows(
    scope: &str,
    owner_kind: &str,
    body_bytes: u64,
    chunk_count: u64,
) -> (String, String, String, String) {
    let digest = "b".repeat(64);
    let record_key = format!("knowledge-release:v2:{scope}:release");
    let owner = format!(
        r#"{{"kind":"{owner_kind}","record_key":"{record_key}","release":"release-id","scope":{{}}}}"#
    );
    let chunk_key = format!("knowledge-encoding-chunk:{}:{digest}:0000", "a".repeat(64));
    let chunk = format!(
        r#"{{"body_bytes":{body_bytes},"body_digest":"{digest}","chunk_count":{chunk_count},"data":"{}","knowledge_chunk_encoding":"label_atoms_v1","ordinal":0,"owner":{owner}}}"#,
        "0".repeat(131_072)
    );
    let root = format!(
        r#"{{"body":{{"body_bytes":{body_bytes},"body_digest":"{digest}","chunk_count":{chunk_count},"knowledge_chunk_encoding":"label_atoms_v1","owner":{owner}}},"knowledge_release_encoding":"chunked_release_record_v1","original_version":1,"release":{{"release":"release-id"}},"scope":{{}}}}"#
    );
    (chunk_key, chunk, record_key, root)
}

fn insert_row(
    connection: &Connection,
    key: &str,
    scope: &str,
    version: i64,
    payload: &str,
) -> rusqlite::Result<usize> {
    connection.execute(
        "INSERT INTO admission_operation_recovery_records(record_key,scope_key,kind,version,payload)
         VALUES (?1,?2,'command',?3,?4)",
        params![key, scope, version, payload.as_bytes()],
    )
}

#[test]
fn knowledge_codec_catalog_admits_only_exact_release_roots_and_chunks() -> TestResult {
    let scope = "0".repeat(64);
    let foreign = "1".repeat(64);
    for (owner_kind, body_bytes, chunk_count, row_scope, accepted) in [
        ("release", 262_145, 5, scope.as_str(), true),
        ("release", 262_146, 5, scope.as_str(), false),
        ("release", 262_145, 4, scope.as_str(), false),
        ("release", 262_145, 5, foreign.as_str(), false),
        ("checkpoint", 262_145, 5, scope.as_str(), false),
    ] {
        let connection =
            expected_admission_operation_schema(ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)?;
        let (chunk_key, chunk, root_key, root) =
            release_rows(&scope, owner_kind, body_bytes, chunk_count);
        assert_eq!(
            insert_row(&connection, &chunk_key, row_scope, 1, &chunk).is_ok(),
            accepted,
            "release chunk {owner_kind} {body_bytes} {chunk_count} {row_scope}"
        );
        assert_eq!(
            insert_row(&connection, &root_key, row_scope, 2, &root).is_ok(),
            accepted,
            "release root {owner_kind} {body_bytes} {chunk_count} {row_scope}"
        );
    }
    let connection =
        expected_admission_operation_schema(ADMISSION_OPERATION_SUPPORTED_SCHEMA_VERSION)?;
    let (_, _, root_key, root) = release_rows(&scope, "release", 262_145, 5);
    for (key, payload) in [
        (
            root_key.clone(),
            root.replace("\"original_version\":1", "\"original_version\":2"),
        ),
        (
            root_key.clone(),
            root.replace(
                "\"release\":{\"release\":\"release-id\"}",
                "\"release\":{\"release\":\"other\"}",
            ),
        ),
        (format!("{root_key}-other"), root.clone()),
        (
            root_key.replace("knowledge-release", "knowledge-restore"),
            root.clone(),
        ),
        (
            root_key.clone(),
            root.replace(
                "\"knowledge_release_encoding\"",
                "\"checkpoint_restore_encoding\":\"chunked_label_atoms_v1\",\"knowledge_release_encoding\"",
            ),
        ),
    ] {
        assert!(
            insert_row(&connection, &key, &scope, 2, &payload).is_err(),
            "release root shape must refuse: {key}"
        );
    }
    assert!(
        insert_row(&connection, &root_key, &scope, 1, &root).is_err(),
        "a chunked root is never the admitted version"
    );
    insert_row(&connection, &root_key, &scope, 2, &root)?;
    Ok(())
}
