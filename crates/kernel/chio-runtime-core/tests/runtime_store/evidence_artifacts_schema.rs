use super::*;

#[test]
fn open_refuses_evidence_artifacts_table_without_run_scoped_primary_key(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("runtime-orchestration.sqlite3");
    {
        let connection = rusqlite::Connection::open(&path)?;
        connection.execute_batch(
            "CREATE TABLE runtime_evidence_artifacts (
                run_id TEXT NOT NULL,
                artifact_sha256 TEXT PRIMARY KEY NOT NULL,
                role TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                byte_count INTEGER NOT NULL,
                recorded_at_unix_ms INTEGER NOT NULL
            );",
        )?;
    }
    let original = std::fs::read(&path)?;
    match SqliteRuntimeOrchestrationStore::open(&path) {
        Err(ChioRuntimeError::Rejected { code, detail }) => {
            assert_eq!(code, "runtime_store_schema_mismatch");
            assert_eq!(detail, "runtime store requires the exact v1 schema");
        }
        Err(other) => panic!("unexpected error {other:?}"),
        Ok(_) => panic!("a mismatched evidence artifacts table must be refused"),
    }
    assert_eq!(std::fs::read(&path)?, original);
    assert!(!path.with_extension("sqlite3-wal").exists());
    Ok(())
}
