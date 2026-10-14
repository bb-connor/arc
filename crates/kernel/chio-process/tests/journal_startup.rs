//! Startup of a held journal against the production Process library and the
//! real native stores: genesis and the supported historical upgrade run only
//! under the native current-write scope, and the compiled layout reopens
//! without a schema write.
mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use chio_kernel::{ChioKernel, KernelError, NestedFlowBridge, ToolServerConnection};
use chio_process::ProcessRuntime;
use chio_security_types::recovery::{ContinuationId, IntentDigest};
use rusqlite::params;
use serde_json::Value;
use support::{kernel, Result};

struct Server;

#[async_trait::async_trait]
impl ToolServerConnection for Server {
    fn server_id(&self) -> &str {
        "tools"
    }
    fn tool_names(&self) -> Vec<String> {
        vec!["append".into(), "read".into()]
    }
    async fn invoke(
        &self,
        _: &str,
        arguments: Value,
        _: Option<&mut dyn NestedFlowBridge>,
    ) -> std::result::Result<Value, KernelError> {
        Ok(arguments)
    }
}

struct Held {
    _directory: tempfile::TempDir,
    kernel: Arc<ChioKernel>,
    path: PathBuf,
    authority: String,
    key: String,
}

fn held() -> Result<Held> {
    let directory = tempfile::tempdir()?;
    let kernel = kernel(directory.path(), Box::new(Server))?;
    let path = directory.path().join("process.db");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(&path)?;
    let authority = kernel
        .durable_admission_store_uuid()
        .ok_or("native authority absent")?
        .to_owned();
    let key = kernel.public_key().to_hex();
    Ok(Held {
        _directory: directory,
        kernel,
        path: std::fs::canonicalize(path)?,
        authority,
        key,
    })
}

fn schema_cookie(path: &Path) -> Result<i64> {
    let connection = rusqlite::Connection::open(path)?;
    Ok(connection.query_row("PRAGMA schema_version", [], |row| row.get(0))?)
}

fn has_object(path: &Path, name: &str) -> Result<bool> {
    let connection = rusqlite::Connection::open(path)?;
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name=?1)",
        [name],
        |row| row.get(0),
    )?)
}

#[test]
fn historical_journal_upgrades_only_under_the_native_scope_keeping_its_data() -> Result {
    let held = held()?;
    let namespace = uuid::Uuid::new_v4().to_string();
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../spec/vectors/recovery/v1/legacy-process-binding.json"
    ))?;
    let request: chio_kernel::ToolCallRequest = serde_json::from_value(fixture["request"].clone())?;
    let capability = serde_json::to_string(&request.capability)?;
    let limits = serde_json::to_string(&chio_process::ProcessLimits {
        max_processes: 8,
        max_depth: 4,
        max_calls: 3,
        state: Default::default(),
    })?;
    let binding = fixture["cases"][0]["binding_hash"]
        .as_str()
        .ok_or("legacy binding")?
        .to_owned();
    {
        let db = rusqlite::Connection::open(&held.path)?;
        db.pragma_update(None, "journal_mode", "WAL")?;
        // Exact predecessor SQL, retained independently of current DDL.
        db.execute_batch(include_str!("fixtures/legacy-process-v1.sql"))?;
        db.execute(
            "INSERT INTO process_runtime VALUES(1,1,?1,?2,?3)",
            params![namespace, held.authority, held.key],
        )?;
        db.execute(
            "INSERT INTO processes(id,root_id,depth,capability,limits,tree_calls) VALUES('root','root',0,?1,?2,1)",
            params![capability, limits],
        )?;
        db.execute(
            "INSERT INTO process_calls(process_id,operation_key,request_hash) VALUES('root','original-call',?1)",
            [&binding],
        )?;
        db.execute(
            "INSERT INTO process_state_blobs(process_id,sha256,data) VALUES('root',?1,?2)",
            params![
                chio_core_types::crypto::sha256_hex(b"retained blob"),
                b"retained blob".to_vec()
            ],
        )?;
    }

    // A caller that cannot present the retained authority never changes it.
    assert!(!has_object(&held.path, "process_recovery_calls")?);

    let runtime = ProcessRuntime::open(&held.path, held.kernel.clone())?;
    assert_eq!(runtime.runtime_id(), namespace);
    let db = rusqlite::Connection::open(&held.path)?;
    let blob: (String, i64, Vec<u8>) = db.query_row(
        "SELECT knowledge_generation,legacy_quarantined,data FROM process_state_blobs",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(blob, ("legacy".to_owned(), 1, b"retained blob".to_vec()));
    let legacy: (String, String, String, i64) = db.query_row(
        "SELECT p.capability,p.limits,c.request_hash,p.tree_calls FROM processes p JOIN process_calls c ON c.process_id=p.id WHERE c.operation_key='original-call'",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(legacy, (capability, limits, binding, 1));
    assert_eq!(
        db.query_row("SELECT version FROM process_runtime", [], |row| row
            .get::<_, i64>(0))?,
        1
    );
    drop(db);
    assert!(has_object(&held.path, "process_recovery_calls")?);

    // The upgraded journal is the compiled layout: a second open writes no
    // schema, and the retained journal still accepts its recovery reservation.
    let cookie = schema_cookie(&held.path)?;
    drop(runtime);
    let runtime = ProcessRuntime::open(&held.path, held.kernel.clone())?;
    assert_eq!(schema_cookie(&held.path)?, cookie);
    let continuation = ContinuationId::new("original-continuation")?;
    let intent = IntentDigest::from_bytes([7; 32]);
    runtime.reserve_recovery_call("root", "recovery-call", &continuation, intent, "tools")?;
    runtime.reserve_recovery_call("root", "recovery-call", &continuation, intent, "tools")?;
    assert_eq!(runtime.process("root")?.tree_calls, 2);
    let db = rusqlite::Connection::open(&held.path)?;
    assert_eq!(
        db.query_row("SELECT version FROM process_runtime", [], |row| row
            .get::<_, i64>(0))?,
        2
    );
    assert!(db
        .execute("UPDATE process_runtime SET version=1", [])
        .is_err());
    assert!(db
        .execute("DELETE FROM process_recovery_calls", [])
        .is_err());
    Ok(())
}

#[test]
fn empty_file_becomes_a_journal_only_under_the_native_scope() -> Result {
    let held = held()?;
    assert_eq!(std::fs::metadata(&held.path)?.len(), 0);
    let runtime = ProcessRuntime::open(&held.path, held.kernel.clone())?;
    let namespace = runtime.runtime_id().to_owned();
    assert!(uuid::Uuid::parse_str(&namespace).is_ok());
    let db = rusqlite::Connection::open(&held.path)?;
    let mode: String = db.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    assert_eq!(mode, "wal");
    let stored: (i64, String, String, String) = db.query_row(
        "SELECT version,namespace,authority,kernel_key FROM process_runtime",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
    )?;
    assert_eq!(stored, (1, namespace.clone(), held.authority, held.key));
    drop(db);

    let cookie = schema_cookie(&held.path)?;
    drop(runtime);
    let reopened = ProcessRuntime::open(&held.path, held.kernel.clone())?;
    assert_eq!(reopened.runtime_id(), namespace);
    assert_eq!(schema_cookie(&held.path)?, cookie);
    Ok(())
}

#[test]
fn unknown_layouts_refuse_without_mutation() -> Result {
    for (name, historical) in [("stray", false), ("historical-with-stray", true)] {
        let held = held()?;
        {
            let db = rusqlite::Connection::open(&held.path)?;
            if historical {
                db.execute_batch(include_str!("fixtures/legacy-process-v1.sql"))?;
                db.execute(
                    "INSERT INTO process_runtime VALUES(1,1,?1,?2,?3)",
                    params![uuid::Uuid::new_v4().to_string(), held.authority, held.key],
                )?;
            }
            db.execute_batch("CREATE TABLE stray(value)")?;
        }
        let before = std::fs::read(&held.path)?;
        assert!(
            ProcessRuntime::open(&held.path, held.kernel.clone()).is_err(),
            "{name} was accepted as a journal"
        );
        assert_eq!(
            std::fs::read(&held.path)?,
            before,
            "{name} was mutated by a refused open"
        );
    }
    Ok(())
}
