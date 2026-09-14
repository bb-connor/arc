mod child;
mod container;
mod journal;
mod plan;
mod socket;
mod supervision;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

use chio_process::worker::{WorkerServer, WorkerService};
use tokio::sync::oneshot;
use tokio::task::JoinSet;
use tokio::time::Instant;

use super::state::{error, read_json, Host};
use crate::CliError;
use child::Usage;
use journal::{Completion, Journal};
use plan::{FailurePolicy, Plan};

struct Attempt {
    index: usize,
    attempt: u32,
    secret: String,
    result: std::io::Result<child::Outcome>,
    cleanup: Option<container::Cleanup>,
}

enum Supervised {
    Worker(Attempt),
    Cleaned(usize, Result<(), String>),
}

enum Event<T> {
    Completed(Result<T, tokio::task::JoinError>),
    Interrupted,
    Tick,
}

async fn next_event<T: 'static>(
    active: &mut JoinSet<T>,
    interruption: impl std::future::Future<Output = ()>,
) -> Event<T> {
    tokio::select! {
        biased;
        Some(result) = active.join_next(), if !active.is_empty() => Event::Completed(result),
        _ = interruption => Event::Interrupted,
        _ = tokio::time::sleep(Duration::from_millis(100)) => Event::Tick,
    }
}

pub(super) fn cleanup_socket_for_export(db: &rusqlite::Connection) -> Result<(), CliError> {
    socket::cleanup_for_export(db)
}

pub(super) fn run(state: &Path, plan: &Path) -> Result<(), CliError> {
    let plan: Plan = read_json(plan)?;
    let host = Host::open(state, true)?;
    plan.validate(&host)?;
    child::preflight()?;
    let mut journal = Journal::open(&host, &plan)?;
    if let Some(service) = &host.lifecycle {
        service
            .activate(
                plan.workers
                    .iter()
                    .map(|w| (w.process.clone(), w.depends_on.clone()))
                    .collect(),
            )
            .map_err(error)?;
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let logs = chio_control_plane::prepare_private_directory(&host.lease.directory.path().join("run-logs"))?;
        let service = WorkerService::new(host.runtime.clone());
        for worker in &journal.workers { service.revoke_credentials(&worker.process).map_err(error)?; }
        container::reconcile(&journal).await?;
        if !journal.containers()?.is_empty() {
            return Err(error("unresolved container ownership blocks worker replacement; preserve state and reconcile the original engine"));
        }
        let endpoint = journal.socket_endpoint()?;
        let socket = endpoint.path().to_owned();
        let listener = WorkerServer::bind(&socket, service.clone())?;
        journal.socket_bound(&endpoint)?;
        let (stop, stopped) = oneshot::channel();
        let server = tokio::spawn(listener.serve(async { let _ = stopped.await; }));
        let result = drive(&host, &plan, &mut journal, &socket, &logs, &service, &server).await;
        let mut revoke_error = None;
        for worker in &journal.workers {
            if let Err(failure) = service.revoke_credentials(&worker.process) { revoke_error = Some(error(failure)); }
        }
        let cleaned = container::reconcile(&journal).await;
        let _ = stop.send(());
        let drained = server.await.map_err(error)?;
        let socket_cleaned = if cleaned.is_ok() { journal.socket_cleanup(&endpoint) } else { Ok(()) };
        journal.discover()?;
        let completion = journal.completion()?;
        let mut cancelled = false;
        for worker in &journal.workers {
            cancelled |= host.runtime.process(&worker.process).map_err(error)?.state != chio_process::ProcessState::Running;
        }
        let pending_container_records = journal.containers()?.len();
        let abandoned_socket_intents = journal.abandoned_socket_intents()?;
        let publication = journal.check_publication();
        host.lease.directory.validate_path_identity()?;
        let mut report = serde_json::json!({"schema": "chio.process.run-report.v1", "complete": result.is_ok() && publication.is_ok() && drained.is_ok() && cleaned.is_ok() && socket_cleaned.is_ok() && revoke_error.is_none() && !cancelled && completion.complete && pending_container_records == 0, "pending_container_records": pending_container_records, "abandoned_socket_intents": abandoned_socket_intents, "workers": journal.snapshots()?});
        if plan.failure_policy == FailurePolicy::Supervised {
            report["schema"] = serde_json::json!("chio.process.run-report.v2");
            report["failure_policy"] = serde_json::json!(plan.failure_policy);
            report["handled_failures"] = serde_json::json!(completion.handled_failures);
            report["unhandled_failures"] = serde_json::json!(completion.unhandled_failures);
        }
        println!("{report}");
        cleaned?;
        socket_cleaned?;
        result?;
        publication?;
        drained?;
        if let Some(failure) = revoke_error { return Err(failure); }
        if cancelled { return Err(error("run worker was cancelled during shutdown")); }
        if pending_container_records != 0 { return Err(error("container creation remains uncertain; preserve the host state and original engine for reconciliation")); }
        if !completion.complete { return Err(error("unfinished or unhandled child work remains after shutdown; inspect status and resume with the same plan and state")); }
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
    let mut active_ids: BTreeSet<usize> = BTreeSet::new();
    let mut retry_at = BTreeMap::new();
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut engines = BTreeMap::new();
    if !journal.completion()?.complete {
        for profile in plan
            .workers
            .iter()
            .filter_map(|worker| worker.container.as_ref())
            .chain(
                plan.templates
                    .iter()
                    .filter_map(|template| template.container.as_ref()),
            )
        {
            if !engines.contains_key(&profile.image) {
                engines.insert(
                    profile.image.clone(),
                    container::qualify(&profile.image).await?,
                );
            }
        }
    }
    let result = async {
        loop {
            if server.is_finished() { return Err(error("worker listener stopped")); }
            journal.discover()?;
            if plan.failure_policy != FailurePolicy::Stop {
                journal.fail_dependents()?;
            }
            let snapshots = journal.snapshots()?;
            for worker in &journal.workers {
                if host.runtime.process(&worker.process).map_err(error)?.state != chio_process::ProcessState::Running {
                    return Err(error("run worker was cancelled"));
                }
            }
            if snapshots.iter().any(|s| s.state == "failed") {
                if plan.failure_policy == FailurePolicy::Stop {
                    return Err(error("worker restart budget exhausted; preserve state and inspect with chio process status and chio process logs"));
                }
                if snapshots.iter().all(|s| s.state == "completed" || s.state == "failed") {
                    if plan.failure_policy == FailurePolicy::Supervised {
                        return if journal.completion()?.complete { Ok(()) } else {
                            Err(error("run contains unhandled child failures or failed declared workers; inspect status and logs"))
                        };
                    }
                    return Err(error("independent work finished; run contains failed workers or failed dependencies; inspect with chio process status and chio process logs"));
                }
            }
            if snapshots.iter().all(|s| s.state == "completed") && active.is_empty() { return journal.check_publication(); }
            let pending: BTreeSet<_> = snapshots.iter().filter(|s| s.state == "pending").map(|s| s.process.as_str()).collect();
            let mut ready = Vec::new();
            for (index, worker) in journal.workers.iter().enumerate() {
                if active_ids.contains(&index) || !pending.contains(worker.process.as_str())
                    || !journal.unresolved(worker, &snapshots)?.is_empty()
                    || retry_at.get(&index).is_some_and(|when| *when > Instant::now()) { continue; }
                ready.push(index);
            }
            // Slots are shared across declared subtrees: the next launch goes to
            // the ready worker whose root has the fewest active workers, then the
            // fewest recorded attempts, then the earliest plan position, so one
            // parent's children cannot starve another's and the balance survives
            // a restart.
            let mut root_active: BTreeMap<String, usize> = BTreeMap::new();
            for index in &active_ids {
                *root_active.entry(journal.root(&journal.workers[*index].process).to_owned()).or_default() += 1;
            }
            let mut root_attempts: BTreeMap<String, u32> = BTreeMap::new();
            for snapshot in &snapshots {
                *root_attempts.entry(journal.root(&snapshot.process).to_owned()).or_default() += snapshot.attempts;
            }
            while active.len() < plan.max_parallel {
                let Some(position) = (0..ready.len()).min_by_key(|&position| {
                    let root = journal.root(&journal.workers[ready[position]].process);
                    (root_active.get(root).copied().unwrap_or(0), root_attempts.get(root).copied().unwrap_or(0), ready[position])
                }) else { break };
                let index = ready.swap_remove(position);
                let worker = journal.workers[index].clone();
                if worker.container.is_none() { worker.validate_launch()?; }
                *root_active.entry(journal.root(&worker.process).to_owned()).or_default() += 1;
                let attempt = journal.start(&worker)?;
                service.revoke_credentials(&worker.process).map_err(error)?;
                let mut connection = super::provision::connection(host, &worker.process, socket)?;
                let secret = connection["credential"].as_str().ok_or_else(|| error("missing worker credential"))?.to_owned();
                let container = if let Some(profile) = &worker.container {
                    let engine = engines.get(&profile.image).ok_or_else(|| error("container image was not qualified"))?.clone();
                    let lease = journal.reserve_container(&worker.process, attempt, engine)?;
                    let writer = journal.container_writer()?;
                    connection["socket_path"] = serde_json::json!("/run/chio/process.sock");
                    Some((lease, writer))
                } else { None };
                let spawned = container.is_none().then(|| child::spawn(&worker));
                let socket = socket.to_owned();
                let mut input = serde_json::to_vec(&serde_json::json!({"schema": "chio.process.worker-bootstrap.v1", "connection": connection, "attempt": attempt, "input": worker.input})).map_err(error)?;
                input.push(b'\n');
                let timeout = Duration::from_secs(worker.timeout_seconds);
                let resident_ceiling = worker.resources.and_then(|resources| resources.max_resident_bytes);
                active_ids.insert(index);
                active.spawn(async move {
                    let (result, cleanup) = if let Some((lease, writer)) = container {
                        let (result, cleanup) = container::run(writer, lease, worker, socket, input).await;
                        (result.map_err(|failure| std::io::Error::other(failure.to_string())), Some(cleanup))
                    } else { (match spawned {
                        Some(Ok(child)) => child::wait(child, input, timeout, resident_ceiling).await,
                        Some(Err(failure)) => Err(failure),
                        None => Err(std::io::Error::other("missing direct worker launch")),
                    }, None) };
                    Supervised::Worker(Attempt { index, attempt, secret, result, cleanup })
                });
            }
            match next_event(&mut active, async {
                tokio::select! { _ = terminate.recv() => {}, _ = interrupt.recv() => {} }
            }).await {
                Event::Interrupted => return Err(error("worker run interrupted; resume with the same plan and state")),
                Event::Completed(result) => {
                    match result.map_err(error)? {
                        Supervised::Worker(attempt) => {
                            let index = attempt.index;
                            let recorded = record_attempt(host, journal, logs, service, &attempt);
                            if let Some(cleanup) = attempt.cleanup {
                                active.spawn(async move { Supervised::Cleaned(index, cleanup.run().await.map_err(|failure| failure.to_string())) });
                            } else { active_ids.remove(&index); }
                            recorded?;
                            retry_at.insert(index, Instant::now() + Duration::from_secs(1));
                        }
                        Supervised::Cleaned(index, result) => {
                            active_ids.remove(&index);
                            result.map_err(error)?;
                        }
                    }
                },
                Event::Tick => {},
            }
        }
    }.await;
    // Preserve results already observed by supervision even when another worker
    // or diagnostic has stopped scheduling. Only unfinished tasks are aborted.
    let mut result = result;
    while let Some(completed) = active.try_join_next() {
        let recorded = completed.map_err(error).and_then(|event| match event {
            Supervised::Worker(attempt) => record_attempt(host, journal, logs, service, &attempt),
            Supervised::Cleaned(_, result) => result.map_err(error),
        });
        if let Err(failure) = recorded {
            if result.is_ok() {
                result = Err(failure);
            }
        }
    }
    active.shutdown().await;
    for snapshot in journal.snapshots()? {
        if snapshot.state != "running" {
            continue;
        }
        let worker = journal
            .workers
            .iter()
            .find(|w| w.process == snapshot.process)
            .ok_or_else(|| error("worker journal does not match its plan"))?
            .clone();
        let cancelled = host.runtime.process(&worker.process).map_err(error)?.state
            == chio_process::ProcessState::Cancelled;
        journal.finish(
            &worker,
            if cancelled {
                Completion::Terminal("process_cancelled")
            } else {
                Completion::Failed("runner_interrupted")
            },
            Usage::default(),
        )?;
    }
    result
}

fn record_attempt(
    host: &Host,
    journal: &mut Journal<'_>,
    logs: &chio_control_plane::PreparedPrivateDirectory,
    service: &WorkerService,
    attempt: &Attempt,
) -> Result<(), CliError> {
    let worker = journal.workers[attempt.index].clone();
    let outcome = match &attempt.result {
        Ok(outcome) => outcome,
        Err(failure) => {
            if child::definitely_unexecuted(failure) {
                journal.unreserve(&worker)?;
            } else {
                journal.finish(
                    &worker,
                    Completion::Terminal("worker_launch_or_wait_uncertain"),
                    Usage::default(),
                )?;
            }
            service.revoke_credentials(&worker.process).map_err(error)?;
            return Err(error(failure));
        }
    };
    let end = if outcome.success {
        Completion::Completed(&outcome.reason)
    } else if matches!(
        outcome.reason.as_str(),
        "container_attachment_lost" | "container_state_unknown"
    ) {
        Completion::Terminal(&outcome.reason)
    } else if outcome.reason == "exit_75"
        && host
            .runtime
            .registry()
            .worker_waits()
            .map_err(error)?
            .contains_key(&worker.process)
    {
        Completion::Suspended
    } else {
        Completion::Failed(&outcome.reason)
    };
    journal.finish(&worker, end, outcome.usage)?;
    service.revoke_credentials(&worker.process).map_err(error)?;
    child::write_log(
        logs,
        &format!("{}-{}.stdout", worker.process, attempt.attempt),
        &outcome.stdout,
        &attempt.secret,
    )?;
    child::write_log(
        logs,
        &format!("{}-{}.stderr", worker.process, attempt.attempt),
        &outcome.stderr,
        &attempt.secret,
    )?;
    if let Some(diagnostic) = &outcome.diagnostic {
        return Err(error(diagnostic));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn known_completion_precedes_ready_interruption() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut active = JoinSet::new();
        let completed = active.spawn(async { "exit_0" });
        while !completed.is_finished() {
            tokio::task::yield_now().await;
        }
        match next_event(&mut active, std::future::ready(())).await {
            Event::Completed(result) => assert_eq!(result?, "exit_0"),
            _ => panic!("ready completion was discarded by interruption"),
        }
        Ok(())
    }
}
