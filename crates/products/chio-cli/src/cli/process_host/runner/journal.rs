use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use chio_process::run_journal::{
    Completion, ContainerIntent, ResourceUsage, WorkerSeed, WorkerState, WorkerTransition,
};
use chio_store_sqlite::process_run_store::{SqliteContainerJournal, SqliteRunJournal};
use serde::Serialize;

use super::super::diagnostics::{RunStatus, WorkerStatus, RUN_SCHEMA, STATUS_FILE};
use super::super::state::{error, Host};
use super::plan::{FailurePolicy, Plan, Worker};
use crate::CliError;

pub(super) struct Journal<'a> {
    clock: std::sync::Arc<dyn chio_security_types::clock::Clock>,
    store: SqliteRunJournal,
    directory: &'a chio_control_plane::PreparedPrivateDirectory,
    plan: &'a Plan,
    run_id: String,
    binding: String,
    pub workers: Vec<Worker>,
    /// The parent each adaptive child was submitted by.
    parents: BTreeMap<String, String>,
    registry: chio_process::ProcessRegistry,
    publication_failure: std::cell::RefCell<Option<String>>,
}

/// Each active container owns a connection so engine I/O cannot block the
/// scheduler while preserving the durable create/start boundary.
pub(super) struct ContainerWriter(SqliteContainerJournal);

impl ContainerWriter {
    pub fn create_rejected(&mut self, lease: &mut ContainerIntent) -> Result<(), CliError> {
        self.0.create_rejected(&lease.owner).map_err(error)?;
        lease.create_rejected = true;
        Ok(())
    }
    pub fn created(&mut self, lease: &mut ContainerIntent, id: String) -> Result<(), CliError> {
        self.0.created(&lease.owner, &id).map_err(error)?;
        lease.id = Some(id);
        Ok(())
    }

    /// At most one signed launch record exists per worker attempt.
    pub fn launch_recorded(
        &mut self,
        signed: &chio_process::SignedContainerLaunchRecord,
    ) -> Result<(), CliError> {
        self.0.launch_recorded(signed).map_err(error)
    }

    pub fn removed(&mut self, lease: &ContainerIntent) -> Result<(), CliError> {
        self.0.removed(&lease.owner).map_err(error)
    }
}

#[derive(Serialize)]
pub(super) struct Snapshot {
    pub process: String,
    pub state: WorkerState,
    pub attempts: u32,
    pub suspensions: u32,
    pub outcome: Option<String>,
    pub peak_resident_bytes: u64,
    pub cpu_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_accounting: Option<&'static str>,
}

impl<'a> Journal<'a> {
    pub fn socket_endpoint(&self) -> Result<super::socket::Endpoint, CliError> {
        super::socket::Endpoint::prepare(&self.store)
    }

    pub fn socket_bound(&self, endpoint: &super::socket::Endpoint) -> Result<(), CliError> {
        endpoint.bound(&self.store)
    }

    pub fn socket_cleanup(&self, endpoint: &super::socket::Endpoint) -> Result<(), CliError> {
        endpoint.cleanup(&self.store)
    }

    pub fn abandoned_socket_intents(&self) -> Result<u32, CliError> {
        self.store.abandoned_socket_intents().map_err(error)
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
        let binding = chio_core_types::crypto::canonical_json_bytes(&serde_json::json!({
            "version": 1, "authority": host.kernel.durable_admission_store_uuid(),
            "kernel_key": host.kernel.public_key().to_hex(), "plan": plan,
        }))
        .map_err(error)?;
        let binding = chio_core_types::crypto::sha256_hex(&binding);
        let mut store = SqliteRunJournal::open(&path, &binding).map_err(error)?;
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
        let seeds = workers
            .iter()
            .map(|worker| WorkerSeed {
                process: &worker.process,
                max_attempts: worker.max_attempts,
            })
            .collect::<Vec<_>>();
        store.recover(&seeds).map_err(error)?;
        let journal = Self {
            clock: host.kernel.authority_clock(),
            store,
            directory,
            plan,
            run_id: uuid::Uuid::new_v4().to_string(),
            binding,
            workers,
            parents,
            registry,
            publication_failure: std::cell::RefCell::new(None),
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
                    state: snapshot.state.as_str().to_owned(),
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
            observed_at_ms: self.clock.unix_millis().map_err(error)?.get(),
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

    fn publish_observation(&self) {
        if let Err(failure) = self.publish_status() {
            self.publication_failure
                .borrow_mut()
                .get_or_insert_with(|| failure.to_string());
        }
    }

    pub fn check_publication(&self) -> Result<(), CliError> {
        if let Some(failure) = self.publication_failure.borrow().as_ref() {
            return Err(error(format!(
                "worker state committed but status publication failed: {failure}"
            )));
        }
        Ok(())
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
                    .any(|s| s.process == *id && s.state == WorkerState::Completed)
            })
            .collect();
        unresolved.extend(settled.into_iter().filter(|id| {
            !snapshots
                .iter()
                .any(|s| s.process == *id && s.state.is_terminal())
        }));
        Ok(unresolved.into_iter().collect())
    }

    pub fn completion(&self) -> Result<super::supervision::Completion, CliError> {
        let snapshots = self.snapshots()?;
        if self.plan.failure_policy != FailurePolicy::Supervised {
            return Ok(super::supervision::Completion {
                complete: snapshots.iter().all(|s| s.state == WorkerState::Completed),
                handled_failures: Vec::new(),
                unhandled_failures: Vec::new(),
            });
        }
        let settlements = self.store.settlements().map_err(error)?;
        super::supervision::evaluate(&snapshots, &self.plan.workers, &self.parents, &settlements)
    }

    pub fn has_stop_failure(
        &self,
        snapshots: &[Snapshot],
        cancelled: &BTreeSet<String>,
    ) -> Result<bool, CliError> {
        let failed: BTreeSet<_> = snapshots
            .iter()
            .filter(|s| s.state == WorkerState::Failed)
            .map(|s| s.process.as_str())
            .collect();
        let mut scoped: BTreeSet<_> = snapshots
            .iter()
            .filter(|s| {
                s.state == WorkerState::Failed
                    && s.outcome.as_deref() == Some("process_cancelled")
                    && cancelled.contains(&s.process)
            })
            .map(|s| s.process.as_str())
            .collect();
        loop {
            let before = scoped.len();
            for snapshot in snapshots.iter().filter(|s| {
                s.state == WorkerState::Failed && s.outcome.as_deref() == Some("dependency_failed")
            }) {
                let worker = self
                    .workers
                    .iter()
                    .find(|w| w.process == snapshot.process)
                    .ok_or_else(|| error("worker journal does not match its plan"))?;
                let dependencies = self.dependencies(worker)?;
                if dependencies.iter().any(|id| scoped.contains(id.as_str()))
                    && dependencies
                        .iter()
                        .filter(|id| failed.contains(id.as_str()))
                        .all(|id| scoped.contains(id.as_str()))
                {
                    scoped.insert(snapshot.process.as_str());
                }
            }
            if scoped.len() == before {
                break;
            }
        }
        Ok(failed.iter().any(|id| !scoped.contains(id)))
    }

    /// Pending work whose prerequisite failed cannot run. Propagate through
    /// declared dependencies and recorded joins without spending an attempt or
    /// changing completed or active work. Parentage alone is not a dependency.
    pub fn fail_dependents(&mut self) -> Result<(), CliError> {
        let snapshots = self.snapshots()?;
        let mut failed: BTreeSet<_> = snapshots
            .iter()
            .filter(|s| s.state == WorkerState::Failed)
            .map(|s| s.process.clone())
            .collect();
        if failed.is_empty() {
            return Ok(());
        }
        let mut pending = BTreeMap::new();
        for worker in &self.workers {
            if snapshots
                .iter()
                .any(|s| s.process == worker.process && s.state == WorkerState::Pending)
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
            let processes = blocked.iter().map(String::as_str).collect::<Vec<_>>();
            self.store.fail_dependents(&processes).map_err(error)?;
            self.publish_observation();
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
            let template = self
                .plan
                .templates
                .iter()
                .find(|t| t.id == child.template)
                .ok_or_else(|| error("child work has no pinned run template"))?;
            let worker = template.worker(child.process, child.input);
            self.store.insert_worker(&worker.process).map_err(error)?;
            self.parents.insert(worker.process.clone(), child.parent);
            self.workers.push(worker);
            changed = true;
        }
        if changed {
            self.publish_observation();
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
        Ok(self
            .store
            .snapshots()
            .map_err(error)?
            .into_iter()
            .map(|record| {
                let container = self
                    .workers
                    .iter()
                    .any(|worker| worker.container.is_some() && worker.process == record.process);
                Snapshot {
                    process: record.process,
                    state: record.state,
                    attempts: record.attempts,
                    suspensions: record.suspensions,
                    outcome: record.outcome,
                    peak_resident_bytes: record.peak_resident_bytes,
                    cpu_ms: record.cpu_ms,
                    resource_accounting: container.then_some("unavailable_container_cgroup"),
                }
            })
            .collect())
    }

    /// Reserve the next launch. Launches that ended in a recorded cooperative
    /// suspension do not count against the failure ceiling.
    pub fn start(&mut self, worker: &Worker) -> Result<u32, CliError> {
        let record = self
            .store
            .transition(
                &worker.process,
                WorkerTransition::Start {
                    max_attempts: worker.max_attempts,
                },
            )
            .map_err(error)?;
        self.publish_observation();
        Ok(record.attempts)
    }

    pub fn cancel_pending(&mut self, worker: &Worker) -> Result<(), CliError> {
        self.store
            .transition(&worker.process, WorkerTransition::CancelPending)
            .map_err(error)?;
        self.publish_observation();
        Ok(())
    }

    /// Record a create-only intent before contacting the engine. Until an exact
    /// ID is committed, no start request may be sent for this container.
    pub fn reserve_container(
        &self,
        process: &str,
        attempt: u32,
        engine: String,
    ) -> Result<ContainerIntent, CliError> {
        let lease = ContainerIntent {
            owner: uuid::Uuid::new_v4().simple().to_string(),
            engine,
            id: None,
            create_rejected: false,
        };
        self.store
            .reserve_container(process, attempt, &lease.owner, &lease.engine)
            .map_err(error)?;
        Ok(lease)
    }

    /// Only Command::spawn's definite pre-exec refusal authorizes this rollback.
    pub fn unreserve(&self, worker: &Worker) -> Result<(), CliError> {
        self.store
            .transition(&worker.process, WorkerTransition::Unreserve)
            .map_err(error)?;
        self.publish_observation();
        Ok(())
    }

    pub fn container_writer(&self) -> Result<ContainerWriter, CliError> {
        self.directory.validate_path_identity()?;
        Ok(ContainerWriter(
            SqliteContainerJournal::open(&self.directory.path().join("runner.db"))
                .map_err(error)?,
        ))
    }

    pub fn containers(&self) -> Result<Vec<ContainerIntent>, CliError> {
        self.store.containers().map_err(error)
    }

    pub fn container_removed(&self, lease: &ContainerIntent) -> Result<(), CliError> {
        self.store.container_removed(&lease.owner).map_err(error)
    }

    /// Record how the active launch ended and what it used. A recorded
    /// suspension spends the suspension ceiling; any other unsuccessful end
    /// spends the failure ceiling. A terminal end fails the worker regardless
    /// of budget. The attempt's resource use joins the worker's peak and total.
    pub fn finish(
        &mut self,
        worker: &Worker,
        end: Completion<'_>,
        usage: ResourceUsage,
    ) -> Result<(), CliError> {
        self.store
            .transition(
                &worker.process,
                WorkerTransition::Finish {
                    completion: end,
                    max_attempts: worker.max_attempts,
                    max_suspensions: worker.max_suspensions(),
                    usage,
                },
            )
            .map_err(error)?;
        self.publish_observation();
        Ok(())
    }
}

#[cfg(test)]
#[path = "journal_tests.rs"]
mod tests;
