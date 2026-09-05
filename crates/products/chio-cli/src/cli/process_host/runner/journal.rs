use std::path::Path;
use std::time::Duration;

use rusqlite::{params, Connection, TransactionBehavior};
use serde::Serialize;

use super::super::state::{error, Host};
use super::plan::Plan;
use crate::CliError;

pub(super) struct Journal {
    db: Connection,
}

#[derive(Serialize)]
pub(super) struct Snapshot {
    pub process: String,
    pub state: String,
    pub attempts: u32,
    pub outcome: Option<String>,
}

impl Journal {
    pub fn open(host: &Host, plan: &Plan) -> Result<Self, CliError> {
        let directory = &host.lease.directory;
        let path = directory.path().join("runner.db");
        if !path.try_exists()? {
            directory.write_new_secret(Path::new("runner.db"), &[])?;
        }
        // The host lock and private parent own this file. Reject links and broad modes.
        directory.validate_path_identity()?;
        use std::os::unix::fs::PermissionsExt;
        let metadata = path.symlink_metadata()?;
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o077 != 0 {
            return Err(error("runner journal must be a private regular file"));
        }
        let mut db = Connection::open(&path).map_err(error)?;
        db.busy_timeout(Duration::from_secs(5)).map_err(error)?;
        db.pragma_update(None, "journal_mode", "WAL")
            .map_err(error)?;
        db.pragma_update(None, "synchronous", "FULL")
            .map_err(error)?;
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(error)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS run_binding(singleton INTEGER PRIMARY KEY CHECK(singleton=1), binding TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS run_workers(process TEXT PRIMARY KEY, state TEXT NOT NULL CHECK(state IN ('pending','running','completed','failed')), attempts INTEGER NOT NULL DEFAULT 0, outcome TEXT);").map_err(error)?;
        let binding = chio_core_types::crypto::canonical_json_bytes(&serde_json::json!({
            "version": 1, "authority": host.kernel.durable_admission_store_uuid(),
            "kernel_key": host.kernel.public_key().to_hex(), "plan": plan,
        }))
        .map_err(error)?;
        let binding = chio_core_types::crypto::sha256_hex(&binding);
        tx.execute(
            "INSERT OR IGNORE INTO run_binding VALUES(1, ?1)",
            [&binding],
        )
        .map_err(error)?;
        let stored: String = tx
            .query_row(
                "SELECT binding FROM run_binding WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(error)?;
        if stored != binding {
            return Err(error(
                "run plan or authority changed; restore the original configuration",
            ));
        }
        for worker in &plan.workers {
            tx.execute(
                "INSERT OR IGNORE INTO run_workers(process,state) VALUES(?1,'pending')",
                [&worker.process],
            )
            .map_err(error)?;
            tx.execute("UPDATE run_workers SET state=CASE WHEN attempts>=?1 THEN 'failed' ELSE 'pending' END, outcome='host_interrupted' WHERE process=?2 AND state='running'",
                params![worker.max_attempts, worker.process]).map_err(error)?;
        }
        tx.commit().map_err(error)?;
        Ok(Self { db })
    }

    pub fn snapshots(&self) -> Result<Vec<Snapshot>, CliError> {
        self.db
            .prepare("SELECT process,state,attempts,outcome FROM run_workers ORDER BY process")
            .map_err(error)?
            .query_map([], |r| {
                Ok(Snapshot {
                    process: r.get(0)?,
                    state: r.get(1)?,
                    attempts: r.get(2)?,
                    outcome: r.get(3)?,
                })
            })
            .map_err(error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(error)
    }

    pub fn start(&mut self, process: &str, maximum: u32) -> Result<u32, CliError> {
        let changed = self.db.execute("UPDATE run_workers SET state='running',attempts=attempts+1,outcome=NULL WHERE process=?1 AND state='pending' AND attempts<?2", params![process,maximum]).map_err(error)?;
        if changed != 1 {
            return Err(error("worker attempt cannot be admitted"));
        }
        self.db
            .query_row(
                "SELECT attempts FROM run_workers WHERE process=?1",
                [process],
                |r| r.get(0),
            )
            .map_err(error)
    }

    pub fn finish(
        &mut self,
        process: &str,
        maximum: u32,
        success: bool,
        outcome: &str,
    ) -> Result<(), CliError> {
        let changed = self.db.execute("UPDATE run_workers SET state=CASE WHEN ?1 THEN 'completed' WHEN attempts>=?2 THEN 'failed' ELSE 'pending' END,outcome=?3 WHERE process=?4 AND state='running'", params![success,maximum,outcome,process]).map_err(error)?;
        if changed != 1 {
            return Err(error("worker completion does not match its active attempt"));
        }
        Ok(())
    }
}
