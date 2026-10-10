use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

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
