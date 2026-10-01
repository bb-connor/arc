use super::*;

const CHILD_ROLE: &str = "CHIO_RUNTIME_REPLAY_SEAL_EXIT_CHILD";
const CHILD_DATABASE: &str = "CHIO_RUNTIME_REPLAY_SEAL_EXIT_DATABASE";
const EXIT_AFTER_COMMIT: i32 = 73;

#[test]
fn committed_seal_survives_process_exit_without_acknowledgment() -> TestResult {
    if std::env::var_os(CHILD_ROLE).as_deref() == Some(std::ffi::OsStr::new("seal-and-exit")) {
        let path = std::env::var_os(CHILD_DATABASE).ok_or("child database path missing")?;
        let store = SqliteRuntimeOrchestrationStore::open(std::path::PathBuf::from(path))?;
        let binding = binding()?;
        assert!(store.load_legacy_replay_source_seal(&binding)?.is_none());
        let committed = store.seal_legacy_replay_source(&binding)?;
        assert_inventory(&committed);
        // The caller never receives a seal response. The live store and seal
        // are deliberately not dropped, so no Rust destructor closes SQLite.
        // This is a committed write followed by process loss, not a claim of
        // arbitrary mid-commit power-loss or filesystem-durability qualification.
        std::process::exit(EXIT_AFTER_COMMIT);
    }

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("unacknowledged-seal.sqlite3");
    let store = SqliteRuntimeOrchestrationStore::open(&path)?;
    seed_inventory(&store)?;
    drop(store);

    let module = module_path!()
        .split_once("::")
        .map(|(_, module)| module)
        .ok_or("subprocess test must be registered under its integration-test module")?;
    let test_name =
        format!("{module}::committed_seal_survives_process_exit_without_acknowledgment");
    let child = std::process::Command::new(std::env::current_exe()?)
        .args(["--exact", &test_name, "--nocapture", "--test-threads=1"])
        .env(CHILD_ROLE, "seal-and-exit")
        .env(CHILD_DATABASE, &path)
        .output()?;
    assert_eq!(
        child.status.code(),
        Some(EXIT_AFTER_COMMIT),
        "child did not reach the intentional committed-without-ack exit: stdout={} stderr={}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );

    let recovered = SqliteRuntimeOrchestrationStore::open(&path)?;
    let binding = binding()?;
    let seal = recovered
        .load_legacy_replay_source_seal(&binding)?
        .ok_or("committed seal disappeared after child process loss")?;
    assert_inventory(&seal);
    recovered.verify_legacy_replay_source_seal(&seal)?;
    let raw = Connection::open(&path)?;
    let stored_bytes: Vec<u8> = raw.query_row(
        "SELECT canonical_bytes FROM runtime_replay_source_seal WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(seal.canonical_bytes()?, stored_bytes);
    assert_eq!(
        recovered
            .seal_legacy_replay_source(&binding)?
            .canonical_bytes()?,
        stored_bytes,
        "retry after lost acknowledgment must return the exact retained seal"
    );
    let before = raw_snapshot(&raw)?;
    for (table, key, _) in TABLES {
        for sql in [
            format!("INSERT INTO {table}({key}, admission_id) VALUES ('late-resource', 'late-owner')"),
            format!("INSERT OR IGNORE INTO {table}({key}, admission_id) VALUES ('resource-a', 'late-owner')"),
            format!("INSERT OR REPLACE INTO {table}({key}, admission_id) VALUES ('resource-a', 'late-owner')"),
            format!("UPDATE {table} SET admission_id = 'late-owner' WHERE {key} = 'resource-a'"),
            format!("DELETE FROM {table} WHERE {key} = 'resource-a'"),
        ] {
            match raw.execute(&sql, []) {
                Err(rusqlite::Error::SqliteFailure(error, Some(message))) => {
                    assert_eq!(error.extended_code, rusqlite::ffi::SQLITE_CONSTRAINT_TRIGGER, "{sql}");
                    assert!(message.contains("runtime replay source is sealed"), "{sql}: {message}");
                }
                other => panic!("legacy barrier did not survive child process loss: {sql}: {other:?}"),
            }
        }
    }
    for result in [
        recovered.consume_destructive_lease("late-resource", "late-owner"),
        recovered.release_destructive_lease("resource-a", "admission-lease"),
        recovered.consume_treaty_continuation("late-resource", "late-owner"),
        recovered.release_treaty_continuation("resource-a", "admission-treaty"),
        recovered.consume_swarm_continuation("late-resource", "late-owner"),
        recovered.release_swarm_continuation("resource-a", "admission-swarm"),
    ] {
        assert_code(result, "runtime_replay_source_sealed");
    }
    assert_eq!(raw_snapshot(&raw)?, before);
    recovered.verify_legacy_replay_source_seal(&seal)?;
    Ok(())
}
