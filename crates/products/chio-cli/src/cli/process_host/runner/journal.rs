use std::path::Path;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, TransactionBehavior};
use serde::Serialize;

use super::super::diagnostics::{RunStatus, WorkerStatus, RUN_SCHEMA, STATUS_FILE};
use super::super::state::{error, Host};
use super::plan::{Plan, Worker};
use crate::CliError;

pub(super) struct Journal<'a> {
    db: Connection,
    directory: &'a chio_control_plane::PreparedPrivateDirectory,
    plan: &'a Plan,
    run_id: String,
    binding: String,
    pub workers: Vec<Worker>,
    registry: chio_process::ProcessRegistry,
}

#[derive(Serialize)]
pub(super) struct Snapshot {
    pub process: String,
    pub state: String,
    pub attempts: u32,
    pub outcome: Option<String>,
}

impl<'a> Journal<'a> {
    pub fn open(host: &'a Host, plan: &'a Plan) -> Result<Self, CliError> {
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
        let mut workers = plan.workers.clone();
        let registry = host.runtime.registry();
        for child in registry.child_work().map_err(error)? {
            let template = plan
                .templates
                .iter()
                .find(|t| t.id == child.template)
                .ok_or_else(|| error("child work has no pinned run template"))?;
            workers.push(template.worker(child.process, child.input));
        }
        if workers.len() > 128 {
            return Err(error("run exceeds 128 total workers"));
        }
        for worker in &workers {
            tx.execute(
                "INSERT OR IGNORE INTO run_workers(process,state) VALUES(?1,'pending')",
                [&worker.process],
            )
            .map_err(error)?;
            tx.execute("UPDATE run_workers SET state=CASE WHEN attempts>=?1 THEN 'failed' ELSE 'pending' END, outcome='host_interrupted' WHERE process=?2 AND state='running'",
                params![worker.max_attempts, worker.process]).map_err(error)?;
        }
        tx.commit().map_err(error)?;
        let journal = Self {
            db,
            directory,
            plan,
            run_id: uuid::Uuid::new_v4().to_string(),
            binding,
            workers,
            registry,
        };
        journal.publish_status()?;
        Ok(journal)
    }

    fn publish_status(&self) -> Result<(), CliError> {
        let snapshots = self.snapshots()?;
        let completed: std::collections::BTreeSet<_> = snapshots
            .iter()
            .filter(|s| s.state == "completed")
            .map(|s| s.process.as_str())
            .collect();
        let workers = snapshots
            .iter()
            .map(|snapshot| {
                let worker = self
                    .workers
                    .iter()
                    .find(|w| w.process == snapshot.process)
                    .ok_or_else(|| error("worker journal does not match its plan"))?;
                Ok(WorkerStatus {
                    process: snapshot.process.clone(),
                    state: snapshot.state.clone(),
                    attempts: snapshot.attempts,
                    max_attempts: worker.max_attempts,
                    outcome: snapshot.outcome.clone(),
                    waiting_on: self
                        .dependencies(worker)?
                        .into_iter()
                        .filter(|id| !completed.contains(id.as_str()))
                        .collect(),
                })
            })
            .collect::<Result<Vec<_>, CliError>>()?;
        let status = RunStatus {
            schema: RUN_SCHEMA.to_owned(),
            run_id: self.run_id.clone(),
            observed_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(error)?
                .as_millis()
                .try_into()
                .map_err(error)?,
            plan_binding: self.binding.clone(),
            max_parallel: self.plan.max_parallel,
            workers,
        };
        let bytes = serde_json::to_vec(&status).map_err(error)?;
        if bytes.len() as u64 > super::super::state::MAX_CONFIG_BYTES {
            return Err(error("run status exceeds one MiB"));
        }
        self.directory.validate_path_identity()?;
        let temporary = format!(".run-status-{}.tmp", uuid::Uuid::new_v4());
        self.directory
            .write_new_secret(Path::new(&temporary), &bytes)?;
        let result = (|| {
            self.directory.validate_path_identity()?;
            std::fs::rename(
                self.directory.path().join(&temporary),
                self.directory.path().join(STATUS_FILE),
            )?;
            std::fs::File::open(self.directory.path())?.sync_all()?;
            self.directory.validate_path_identity()
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(self.directory.path().join(&temporary));
        }
        result.map_err(error)
    }

    pub fn dependencies(&self, worker: &Worker) -> Result<Vec<String>, CliError> {
        let mut dependencies = worker.depends_on.clone();
        if let Some(wait) = self
            .registry
            .worker_waits()
            .map_err(error)?
            .get(&worker.process)
        {
            dependencies.extend(wait.iter().cloned());
        }
        dependencies.sort();
        dependencies.dedup();
        Ok(dependencies)
    }

    pub fn discover(&mut self) -> Result<(), CliError> {
        let mut changed = false;
        for child in self.registry.child_work().map_err(error)? {
            if self
                .workers
                .iter()
                .any(|worker| worker.process == child.process)
            {
                continue;
            }
            if self.workers.len() >= 128 {
                return Err(error("run exceeds 128 total workers"));
            }
            let template = self
                .plan
                .templates
                .iter()
                .find(|t| t.id == child.template)
                .ok_or_else(|| error("child work has no pinned run template"))?;
            let worker = template.worker(child.process, child.input);
            self.db
                .execute(
                    "INSERT INTO run_workers(process,state) VALUES(?1,'pending')",
                    [&worker.process],
                )
                .map_err(error)?;
            self.workers.push(worker);
            changed = true;
        }
        if changed {
            self.publish_status()?;
        }
        Ok(())
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
        let attempt = self
            .db
            .query_row(
                "SELECT attempts FROM run_workers WHERE process=?1",
                [process],
                |r| r.get(0),
            )
            .map_err(error)?;
        self.publish_status()?;
        Ok(attempt)
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
        self.publish_status()?;
        Ok(())
    }
}
