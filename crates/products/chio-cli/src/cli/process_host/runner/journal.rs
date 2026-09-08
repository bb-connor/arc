use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection, TransactionBehavior};
use serde::Serialize;

use super::super::diagnostics::{RunStatus, WorkerStatus, RUN_SCHEMA, STATUS_FILE};
use super::super::state::{error, Host};
use super::child::Usage;
use super::container::Lease;
use super::plan::{FailurePolicy, Plan, Worker};
use crate::CliError;

pub(super) struct Journal<'a> {
    db: Connection,
    directory: &'a chio_control_plane::PreparedPrivateDirectory,
    plan: &'a Plan,
    run_id: String,
    binding: String,
    pub workers: Vec<Worker>,
    /// The parent each adaptive child was submitted by.
    parents: BTreeMap<String, String>,
    registry: chio_process::ProcessRegistry,
}

/// Each active container owns a connection so engine I/O cannot block the
/// scheduler while preserving the durable create/start boundary.
pub(super) struct ContainerWriter(Connection);

impl ContainerWriter {
    pub fn created(&mut self, lease: &mut Lease, id: String) -> Result<(), CliError> {
        let changed = self
            .0
            .execute(
                "UPDATE run_containers SET container_id=?1 WHERE owner=?2 AND container_id IS NULL",
                params![id, lease.owner],
            )
            .map_err(error)?;
        if changed != 1 {
            return Err(error(
                "container creation does not match its durable intent",
            ));
        }
        lease.id = Some(id);
        Ok(())
    }

    pub fn removed(&mut self, lease: &Lease) -> Result<(), CliError> {
        self.0
            .execute("DELETE FROM run_containers WHERE owner=?1", [&lease.owner])
            .map_err(error)?;
        Ok(())
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_accounting: Option<&'static str>,
}

/// How a launch ended, as the runner observed it.
pub(super) enum Completion<'s> {
    Completed(&'s str),
    Suspended,
    Failed(&'s str),
    Terminal(&'s str),
}

impl<'a> Journal<'a> {
    pub fn socket_endpoint(&self) -> Result<super::socket::Endpoint, CliError> {
        super::socket::Endpoint::prepare(&self.db)
    }

    pub fn socket_bound(&self, endpoint: &super::socket::Endpoint) -> Result<(), CliError> {
        endpoint.bound(&self.db)
    }

    pub fn socket_cleanup(&self, endpoint: &super::socket::Endpoint) -> Result<(), CliError> {
        endpoint.cleanup(&self.db)
    }

    pub fn abandoned_socket_intents(&self) -> Result<i64, CliError> {
        self.db
            .query_row(
                "SELECT COUNT(*) FROM run_socket_leases WHERE singleton>1",
                [],
                |row| row.get(0),
            )
            .map_err(error)
    }

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
        tx.execute_batch("CREATE TABLE IF NOT EXISTS run_containers(owner TEXT PRIMARY KEY, process TEXT NOT NULL, attempt INTEGER NOT NULL, engine TEXT NOT NULL, container_id TEXT, UNIQUE(process,attempt));").map_err(error)?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS run_child_settlements(parent TEXT NOT NULL, child TEXT NOT NULL, request_id TEXT NOT NULL, PRIMARY KEY(parent,child));").map_err(error)?;
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
        let mut parents = BTreeMap::new();
        let registry = host.runtime.registry();
        for child in registry.child_work().map_err(error)? {
            let template = plan
                .templates
                .iter()
                .find(|t| t.id == child.template)
                .ok_or_else(|| error("child work has no pinned run template"))?;
            parents.insert(child.process.clone(), child.parent);
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
            parents,
            registry,
        };
        journal.publish_status()?;
        Ok(journal)
    }

    fn publish_status(&self) -> Result<(), CliError> {
        let snapshots = self.snapshots()?;
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
                    resource_accounting: snapshot.resource_accounting.map(str::to_owned),
                    waiting_on: self.unresolved(worker, &snapshots)?,
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
        Ok(self.dependency_groups(worker)?.0)
    }

    fn dependency_groups(&self, worker: &Worker) -> Result<(Vec<String>, Vec<String>), CliError> {
        let mut dependencies = worker.depends_on.clone();
        let mut terminal = Vec::new();
        if let Some(wait) = self.registry.worker_wait(&worker.process).map_err(error)? {
            if wait.settled {
                if self.plan.failure_policy != FailurePolicy::Supervised {
                    return Err(error("settled joins require a supervised run plan"));
                }
                terminal = wait.children;
            } else {
                dependencies.extend(wait.children);
            }
        }
        dependencies.sort();
        dependencies.dedup();
        Ok((dependencies, terminal))
    }

    pub fn unresolved(
        &self,
        worker: &Worker,
        snapshots: &[Snapshot],
    ) -> Result<Vec<String>, CliError> {
        let (strict, settled) = self.dependency_groups(worker)?;
        let mut unresolved: BTreeSet<_> = strict
            .into_iter()
            .filter(|id| {
                !snapshots
                    .iter()
                    .any(|s| s.process == *id && s.state == "completed")
            })
            .collect();
        unresolved.extend(settled.into_iter().filter(|id| {
            !snapshots
                .iter()
                .any(|s| s.process == *id && matches!(s.state.as_str(), "completed" | "failed"))
        }));
        Ok(unresolved.into_iter().collect())
    }

    pub fn completion(&self) -> Result<super::supervision::Completion, CliError> {
        let snapshots = self.snapshots()?;
        if self.plan.failure_policy != FailurePolicy::Supervised {
            return Ok(super::supervision::Completion {
                complete: snapshots.iter().all(|s| s.state == "completed"),
                handled_failures: Vec::new(),
                unhandled_failures: Vec::new(),
            });
        }
        let settlements = self
            .db
            .prepare(
                "SELECT parent,child,request_id FROM run_child_settlements ORDER BY parent,child",
            )
            .map_err(error)?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(error)?;
        super::supervision::evaluate(&snapshots, &self.plan.workers, &self.parents, &settlements)
    }

    /// Pending work whose prerequisite failed cannot run. Propagate through
    /// declared dependencies and recorded joins without spending an attempt or
    /// changing completed or active work. Parentage alone is not a dependency.
    pub fn fail_dependents(&mut self) -> Result<(), CliError> {
        let snapshots = self.snapshots()?;
        let mut failed: BTreeSet<_> = snapshots
            .iter()
            .filter(|s| s.state == "failed")
            .map(|s| s.process.clone())
            .collect();
        if failed.is_empty() {
            return Ok(());
        }
        let mut pending = BTreeMap::new();
        for worker in &self.workers {
            if snapshots
                .iter()
                .any(|s| s.process == worker.process && s.state == "pending")
            {
                pending.insert(worker.process.clone(), self.dependencies(worker)?);
            }
        }
        let mut blocked = BTreeSet::new();
        loop {
            let next: BTreeSet<_> = pending
                .iter()
                .filter(|(_, dependencies)| dependencies.iter().any(|id| failed.contains(id)))
                .map(|(id, _)| id.clone())
                .collect();
            if next.is_empty() {
                break;
            }
            pending.retain(|id, _| !next.contains(id));
            failed.extend(next.iter().cloned());
            blocked.extend(next);
        }
        if !blocked.is_empty() {
            let tx = self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(error)?;
            for id in blocked {
                let changed = tx.execute(
                    "UPDATE run_workers SET state='failed',outcome='dependency_failed' WHERE process=?1 AND state='pending'",
                    [&id],
                ).map_err(error)?;
                if changed != 1 {
                    return Err(error(
                        "failed dependency does not match pending worker state",
                    ));
                }
            }
            tx.commit().map_err(error)?;
            self.publish_status()?;
        }
        Ok(())
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
            self.parents.insert(worker.process.clone(), child.parent);
            self.workers.push(worker);
            changed = true;
        }
        if changed {
            self.publish_status()?;
        }
        Ok(())
    }

    /// The declared worker a process descends from: itself for a declared
    /// worker, the top of its submission chain for an adaptive child.
    pub fn root<'p>(&'p self, process: &'p str) -> &'p str {
        let mut current = process;
        // The registry rejects cycles; the bound only guards a corrupt chain.
        for _ in 0..=self.parents.len() {
            match self.parents.get(current) {
                Some(parent) => current = parent,
                None => break,
            }
        }
        current
    }

    pub fn snapshots(&self) -> Result<Vec<Snapshot>, CliError> {
        self.db
            .prepare("SELECT process,state,attempts,suspensions,outcome,peak_resident_bytes,cpu_ms FROM run_workers ORDER BY process")
            .map_err(error)?
            .query_map([], |r| {
                let process: String = r.get(0)?;
                let container = self.workers.iter().any(|worker| worker.container.is_some() && worker.process == process);
                Ok(Snapshot {
                    process,
                    state: r.get(1)?,
                    attempts: r.get(2)?,
                    suspensions: r.get(3)?,
                    outcome: r.get(4)?,
                    peak_resident_bytes: accounted(r.get(5)?, 5)?,
                    cpu_ms: accounted(r.get(6)?, 6)?,
                    resource_accounting: container.then_some("unavailable_container_cgroup"),
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

    /// Record a create-only intent before contacting the engine. Until an exact
    /// ID is committed, no start request may be sent for this container.
    pub fn reserve_container(
        &self,
        process: &str,
        attempt: u32,
        engine: String,
    ) -> Result<Lease, CliError> {
        let lease = Lease {
            owner: uuid::Uuid::new_v4().simple().to_string(),
            engine,
            id: None,
        };
        let changed = self.db.execute("INSERT INTO run_containers(owner,process,attempt,engine) SELECT ?1,process,attempts,?2 FROM run_workers WHERE process=?3 AND attempts=?4 AND state='running'", params![lease.owner, lease.engine, process, attempt]).map_err(error)?;
        if changed != 1 {
            return Err(error("container has no reserved worker attempt"));
        }
        Ok(lease)
    }

    pub fn container_writer(&self) -> Result<ContainerWriter, CliError> {
        self.directory.validate_path_identity()?;
        let db = Connection::open(self.directory.path().join("runner.db")).map_err(error)?;
        db.busy_timeout(Duration::from_secs(5)).map_err(error)?;
        db.pragma_update(None, "synchronous", "FULL")
            .map_err(error)?;
        Ok(ContainerWriter(db))
    }

    pub fn containers(&self) -> Result<Vec<Lease>, CliError> {
        self.db
            .prepare("SELECT owner,engine,container_id FROM run_containers ORDER BY owner")
            .map_err(error)?
            .query_map([], |row| {
                Ok(Lease {
                    owner: row.get(0)?,
                    engine: row.get(1)?,
                    id: row.get(2)?,
                })
            })
            .map_err(error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(error)
    }

    pub fn container_removed(&self, lease: &Lease) -> Result<(), CliError> {
        self.db
            .execute("DELETE FROM run_containers WHERE owner=?1", [&lease.owner])
            .map_err(error)?;
        Ok(())
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
