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
    match SqliteRuntimeOrchestrationStore::open(&path) {
        Err(ChioRuntimeError::Rejected { code, detail }) => {
            assert_eq!(code, "runtime_evidence_artifacts_schema_mismatch");
            assert_eq!(
                detail,
                "runtime_evidence_artifacts primary key must be (run_id, artifact_sha256)"
            );
        }
        Err(other) => panic!("unexpected error {other:?}"),
        Ok(_) => panic!("a mismatched evidence artifacts table must be refused"),
    }
    Ok(())
}
