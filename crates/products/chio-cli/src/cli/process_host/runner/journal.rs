use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, TransactionBehavior};
use serde::Serialize;

use super::super::diagnostics::{RunStatus, WorkerStatus, RUN_SCHEMA, STATUS_FILE};
use super::super::state::{error, Host};
use super::child::Usage;
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
    pub suspensions: u32,
    pub outcome: Option<String>,
    pub peak_resident_bytes: u64,
    pub cpu_ms: u64,
}

/// How a launch ended, as the runner observed it.
pub(super) enum Completion<'s> {
    Completed(&'s str),
    Suspended,
    Failed(&'s str),
    Terminal(&'s str),
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
            CREATE TABLE IF NOT EXISTS run_workers(process TEXT PRIMARY KEY, state TEXT NOT NULL CHECK(state IN ('pending','running','completed','failed')), attempts INTEGER NOT NULL DEFAULT 0, suspensions INTEGER NOT NULL DEFAULT 0 CHECK(suspensions <= attempts), outcome TEXT, peak_resident_bytes INTEGER NOT NULL DEFAULT 0, cpu_ms INTEGER NOT NULL DEFAULT 0);").map_err(error)?;
        // Journals written before suspensions were counted gain the column; their
        // recorded attempts all count as failures, as they did when recorded.
        // Journals written before resource use was accounted gain those columns
        // at zero.
        let columns = tx
            .prepare("PRAGMA table_info(run_workers)")
            .map_err(error)?
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(error)?
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(error)?;
        if !columns.contains("suspensions") {
            tx.execute_batch("ALTER TABLE run_workers ADD COLUMN suspensions INTEGER NOT NULL DEFAULT 0 CHECK(suspensions <= attempts)").map_err(error)?;
        }
        if !columns.contains("cpu_ms") {
            tx.execute_batch("ALTER TABLE run_workers ADD COLUMN peak_resident_bytes INTEGER NOT NULL DEFAULT 0; ALTER TABLE run_workers ADD COLUMN cpu_ms INTEGER NOT NULL DEFAULT 0").map_err(error)?;
        }
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
            tx.execute("UPDATE run_workers SET state=CASE WHEN attempts-suspensions>=?1 THEN 'failed' ELSE 'pending' END, outcome='host_interrupted' WHERE process=?2 AND state='running'",
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
        let completed: BTreeSet<_> = snapshots
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
                    suspensions: snapshot.suspensions,
                    max_suspensions: worker.max_suspensions(),
                    outcome: snapshot.outcome.clone(),
                    peak_resident_bytes: snapshot.peak_resident_bytes,
                    cpu_ms: snapshot.cpu_ms,
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
            .prepare("SELECT process,state,attempts,suspensions,outcome,peak_resident_bytes,cpu_ms FROM run_workers ORDER BY process")
            .map_err(error)?
            .query_map([], |r| {
                Ok(Snapshot {
                    process: r.get(0)?,
                    state: r.get(1)?,
                    attempts: r.get(2)?,
                    suspensions: r.get(3)?,
                    outcome: r.get(4)?,
                    peak_resident_bytes: accounted(r.get(5)?, 5)?,
                    cpu_ms: accounted(r.get(6)?, 6)?,
                })
            })
            .map_err(error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(error)
    }

    /// Reserve the next launch. Launches that ended in a recorded cooperative
    /// suspension do not count against the failure ceiling.
    pub fn start(&mut self, worker: &Worker) -> Result<u32, CliError> {
        let changed = self.db.execute("UPDATE run_workers SET state='running',attempts=attempts+1,outcome=NULL WHERE process=?1 AND state='pending' AND attempts-suspensions<?2", params![worker.process,worker.max_attempts]).map_err(error)?;
        if changed != 1 {
            return Err(error("worker attempt cannot be admitted"));
        }
        let attempt = self
            .db
            .query_row(
                "SELECT attempts FROM run_workers WHERE process=?1",
                [&worker.process],
                |r| r.get(0),
            )
            .map_err(error)?;
        self.publish_status()?;
        Ok(attempt)
    }

    /// Record how the active launch ended and what it used. A recorded
    /// suspension spends the suspension ceiling; any other unsuccessful end
    /// spends the failure ceiling. A terminal end fails the worker regardless
    /// of budget. The attempt's resource use joins the worker's peak and total.
    pub fn finish(
        &mut self,
        worker: &Worker,
        end: Completion<'_>,
        usage: Usage,
    ) -> Result<(), CliError> {
        let (success, suspended, terminal, outcome) = match end {
            Completion::Completed(outcome) => (true, false, false, outcome),
            Completion::Suspended => (false, true, false, "suspended"),
            Completion::Failed(outcome) => (false, false, false, outcome),
            Completion::Terminal(outcome) => (false, false, true, outcome),
        };
        let changed = self
            .db
            .execute(
                "UPDATE run_workers SET suspensions=suspensions+?2,
                state=CASE WHEN ?1 THEN 'completed'
                    WHEN ?3 THEN 'failed'
                    WHEN ?2 THEN CASE WHEN suspensions+1>?5 THEN 'failed' ELSE 'pending' END
                    WHEN attempts-suspensions>=?4 THEN 'failed' ELSE 'pending' END,
                outcome=?6,
                peak_resident_bytes=MAX(peak_resident_bytes,?8),
                cpu_ms=cpu_ms+?9
             WHERE process=?7 AND state='running'",
                params![
                    success,
                    suspended,
                    terminal,
                    worker.max_attempts,
                    worker.max_suspensions(),
                    outcome,
                    worker.process,
                    stored(usage.peak_resident_bytes),
                    stored(usage.cpu_ms),
                ],
            )
            .map_err(error)?;
        if changed != 1 {
            return Err(error("worker completion does not match its active attempt"));
        }
        self.publish_status()?;
        Ok(())
    }
}

/// Accounted values are stored as SQLite integers; a value the column cannot
/// hold saturates rather than failing the attempt.
fn stored(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn accounted(value: i64, column: usize) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
}
