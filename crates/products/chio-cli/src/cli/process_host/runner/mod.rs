mod child;
mod journal;
mod plan;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use chio_process::worker::{WorkerServer, WorkerService};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::Instant;

use super::state::{error, read_json, Host};
use crate::CliError;
use journal::Journal;
use plan::Plan;

pub(super) fn run(state: &Path, plan: &Path) -> Result<(), CliError> {
    let plan: Plan = read_json(plan)?;
    let host = Host::open(state, true)?;
    plan.validate(&host)?;
    let mut journal = Journal::open(&host, &plan)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let sockets = chio_control_plane::prepare_private_directory(&host.lease.directory.path().join("run-sockets"))?;
        let logs = chio_control_plane::prepare_private_directory(&host.lease.directory.path().join("run-logs"))?;
        let socket = sockets.path().join(format!("{}.sock", &uuid::Uuid::new_v4().simple().to_string()[..12]));
        let service = WorkerService::new(host.runtime.clone());
        for worker in &plan.workers { service.revoke_credentials(&worker.process).map_err(error)?; }
        let listener = WorkerServer::bind(&socket, service.clone())?;
        let (stop, stopped) = oneshot::channel();
        let server = tokio::spawn(listener.serve(async { let _ = stopped.await; }));
        let result = drive(&host, &plan, &mut journal, &socket, &logs, &service, &server).await;
        let mut revoke_error = None;
        for worker in &plan.workers {
            if let Err(failure) = service.revoke_credentials(&worker.process) { revoke_error = Some(error(failure)); }
        }
        let _ = stop.send(());
        let drained = server.await.map_err(error)?;
        host.lease.directory.validate_path_identity()?;
        println!("{}", serde_json::json!({"schema": "chio.process.run-report.v1", "complete": result.is_ok() && drained.is_ok() && revoke_error.is_none(), "workers": journal.snapshots()?}));
        result?;
        drained?;
        if let Some(failure) = revoke_error { return Err(failure); }
        Ok(())
    })
}

async fn drive(
    host: &Host,
    plan: &Plan,
    journal: &mut Journal<'_>,
    socket: &Path,
    logs: &chio_control_plane::PreparedPrivateDirectory,
    service: &WorkerService,
    server: &tokio::task::JoinHandle<std::io::Result<()>>,
) -> Result<(), CliError> {
    let mut active = JoinSet::new();
    let mut active_ids = BTreeSet::new();
    let mut retry_at = BTreeMap::new();
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let result = async {
        loop {
            if server.is_finished() { return Err(error("worker listener stopped")); }
            let snapshots = journal.snapshots()?;
            for worker in &plan.workers {
                if host.runtime.process(&worker.process).map_err(error)?.state != chio_process::ProcessState::Running {
                    return Err(error("run worker was cancelled"));
                }
            }
            if snapshots.iter().any(|s| s.state == "failed") { return Err(error("worker restart budget exhausted; preserve state and inspect with chio process status and chio process logs")); }
            if snapshots.iter().all(|s| s.state == "completed") { return Ok(()); }
            let completed: BTreeSet<_> = snapshots.iter().filter(|s| s.state == "completed").map(|s| s.process.as_str()).collect();
            for (index, worker) in plan.workers.iter().enumerate() {
                if active.len() >= plan.max_parallel || active_ids.contains(&index) || completed.contains(worker.process.as_str())
                    || !worker.depends_on.iter().all(|id| completed.contains(id.as_str()))
                    || retry_at.get(&index).is_some_and(|when| *when > Instant::now()) { continue; }
                let attempt = journal.start(&worker.process, worker.max_attempts)?;
                service.revoke_credentials(&worker.process).map_err(error)?;
                let connection = super::provision::connection(host, &worker.process, socket)?;
                let secret = connection["credential"].as_str().ok_or_else(|| error("missing worker credential"))?.to_owned();
                let mut input = serde_json::to_vec(&serde_json::json!({"schema": "chio.process.worker-bootstrap.v1", "connection": connection, "attempt": attempt, "input": worker.input})).map_err(error)?;
                input.push(b'\n');
                let spawned = child::spawn(worker);
                let timeout = Duration::from_secs(worker.timeout_seconds);
                active_ids.insert(index);
                active.spawn(async move {
                    let result = match spawned {
                        Ok(child) => child::wait(child, input, timeout).await,
                        Err(failure) => Err(failure),
                    };
                    (index, attempt, secret, result)
                });
            }
            tokio::select! {
                biased;
                _ = terminate.recv() => return Err(error("worker run interrupted; resume with the same plan and state")),
                _ = interrupt.recv() => return Err(error("worker run interrupted; resume with the same plan and state")),
                Some(result) = active.join_next(), if !active.is_empty() => {
                    let (index, attempt, secret, result) = result.map_err(error)?;
                    active_ids.remove(&index);
                    let worker = &plan.workers[index];
                    service.revoke_credentials(&worker.process).map_err(error)?;
                    let (success, reason) = match result {
                        Ok(outcome) => {
                            child::write_log(logs, &format!("{}-{attempt}.stdout", worker.process), &outcome.stdout, &secret)?;
                            child::write_log(logs, &format!("{}-{attempt}.stderr", worker.process), &outcome.stderr, &secret)?;
                            (outcome.success, outcome.reason)
                        },
                        Err(_) => (false, "worker_start_or_io_failed".to_owned()),
                    };
                    journal.finish(&worker.process, worker.max_attempts, success, &reason)?;
                    retry_at.insert(index, Instant::now() + Duration::from_secs(1));
                },
                _ = tokio::time::sleep(Duration::from_millis(100)) => {},
            }
        }
    }.await;
    active.shutdown().await;
    for snapshot in journal.snapshots()? {
        if snapshot.state != "running" {
            continue;
        }
        let worker = plan
            .workers
            .iter()
            .find(|w| w.process == snapshot.process)
            .ok_or_else(|| error("worker journal does not match its plan"))?;
        let cancelled = host.runtime.process(&worker.process).map_err(error)?.state
            == chio_process::ProcessState::Cancelled;
        journal.finish(
            &worker.process,
            if cancelled { 0 } else { worker.max_attempts },
            false,
            if cancelled {
                "process_cancelled"
            } else {
                "runner_interrupted"
            },
        )?;
    }
    result
}
