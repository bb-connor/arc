//! Fixed local Docker profile with durable ownership before create and start.
//!
//! Docker is part of the trusted host. Only the worker socket inode crosses into
//! the image. No Docker socket, host directory or administrative state is mounted.

use std::collections::BTreeMap;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use serde::Deserialize;

use chio_cage::CageEnforcementState;
use chio_process::run_journal::{ContainerIntent, ResourceUsage};
use chio_process::{ContainerLaunchFailure, ContainerLaunchRecord, SignedContainerLaunchRecord};

use super::super::state::error;
use super::child::{self, Outcome, Spawned};
use super::container_profile::{self, EffectiveConfig, PROCESS_SOCKET};
use super::journal::{ContainerWriter, Journal};
use super::plan::Worker;
use crate::CliError;

const OWNER: &str = "chio.runner.owner";
const START_CONFIRMATION_POLLS: u32 = 100;
const START_CONFIRMATION_INTERVAL: Duration = Duration::from_millis(50);

/// The host authority that signs container launch records and attributes the
/// confirmed launch to the worker's tool calls.
pub(super) struct LaunchAuthority {
    pub key: chio_core::crypto::Keypair,
    pub clock: std::sync::Arc<dyn chio_security_types::clock::Clock>,
    pub runtime: chio_process::ProcessRuntime,
}

pub(super) struct AttemptControl {
    pub authority: std::sync::Arc<LaunchAuthority>,
    pub cancellation: Option<tokio::sync::watch::Receiver<bool>>,
}

impl AttemptControl {
    fn cancelled(&self) -> bool {
        self.cancellation
            .as_ref()
            .is_some_and(|receiver| *receiver.borrow() || receiver.has_changed().is_err())
    }
}

// The unit suite replaces only the engine executable. All supervision, durable
// transitions, ownership validation and completion classification remain real.
#[cfg(test)]
static ENGINE_COMMAND: std::sync::Mutex<Option<std::path::PathBuf>> = std::sync::Mutex::new(None);

#[cfg(test)]
static ENGINE_FIXTURE: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
type AttachmentTransport = fn(&ContainerIntent) -> Result<Spawned, CliError>;
#[cfg(test)]
static ATTACHMENT_TRANSPORT: std::sync::Mutex<Option<AttachmentTransport>> =
    std::sync::Mutex::new(None);

fn container_name(intent: &ContainerIntent) -> String {
    format!("chio-run-{}", intent.owner)
}

fn command(arguments: &[String]) -> Command {
    #[cfg(not(test))]
    let mut command = Command::new("/usr/bin/docker");
    #[cfg(test)]
    let mut command = Command::new(
        ENGINE_COMMAND
            .lock()
            .ok()
            .and_then(|path| path.clone())
            .unwrap_or_else(|| "/usr/bin/docker".into()),
    );
    command
        .args(["--host", "unix:///var/run/docker.sock"])
        .args(arguments)
        .current_dir("/")
        .env_clear()
        .env("PATH", "/usr/bin:/bin");
    command
}

fn strings(arguments: &[&str]) -> Vec<String> {
    arguments.iter().map(|value| (*value).to_owned()).collect()
}

async fn control(arguments: &[&str]) -> Result<Vec<u8>, CliError> {
    control_attempt(arguments).await.map_err(error)
}

#[derive(Debug)]
enum ControlFailure {
    Exited { reason: String, stderr: Vec<u8> },
    Uncertain(String),
}

impl std::fmt::Display for ControlFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (kind, reason) = match self {
            Self::Exited { reason, .. } => ("client exited", reason),
            Self::Uncertain(reason) => ("uncertain", reason),
        };
        write!(
            formatter,
            "local Docker control {kind} ({reason}); preserve state and engine for recovery"
        )
    }
}

impl ControlFailure {
    fn rejects_image(&self, image: &str) -> bool {
        // A client exit can also mean a lost response. Recognize only this
        // positive daemon refusal, bound to the exact requested image. Other
        // failures retain uncertainty even when immediate inventory is empty.
        matches!(self, Self::Exited { stderr, .. }
            if std::str::from_utf8(stderr).is_ok_and(|message|
                message.trim() == format!("Error response from daemon: No such image: {image}")))
    }
}

async fn control_attempt(arguments: &[&str]) -> Result<Vec<u8>, ControlFailure> {
    let child = child::spawn_command(command(&strings(arguments)), None)
        .map_err(|failure| ControlFailure::Uncertain(failure.to_string()))?;
    let outcome = child::wait_bounded(
        child,
        Vec::new(),
        None,
        Duration::from_secs(30),
        None,
        Some(65_536),
        None,
    )
    .await
    .map_err(|failure| ControlFailure::Uncertain(failure.to_string()))?;
    if let Some(diagnostic) = outcome.diagnostic {
        return Err(ControlFailure::Uncertain(diagnostic));
    }
    if !outcome.success {
        return Err(if outcome.reason.starts_with("exit_") {
            ControlFailure::Exited {
                reason: outcome.reason,
                stderr: outcome.stderr,
            }
        } else {
            ControlFailure::Uncertain(outcome.reason)
        });
    }
    Ok(outcome.stdout)
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, CliError> {
    Ok(crate::input::decode(
        bytes,
        crate::input::MAX_DOCUMENT_BYTES,
    )?)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Engine {
    #[serde(rename = "ID")]
    id: String,
    security_options: Vec<String>,
    memory_limit: bool,
    swap_limit: bool,
    cpu_cfs_quota: bool,
    pids_limit: bool,
    cgroup_version: String,
}

async fn engine() -> Result<Engine, CliError> {
    let engine: Engine = decode(&control(&["info", "--format", "{{json .}}"]).await?)?;
    if engine.id.is_empty() {
        return Err(error("local Docker engine has no stable identity"));
    }
    Ok(engine)
}

pub(super) async fn qualify(image: &str) -> Result<String, CliError> {
    // SAFETY: getuid/getgid are read-only process queries.
    if unsafe { libc::getuid() } == 0 {
        return Err(error("container workers require a non-root operator"));
    }
    let engine = engine().await?;
    if !engine.memory_limit
        || !engine.swap_limit
        || !engine.cpu_cfs_quota
        || !engine.pids_limit
        || engine.cgroup_version != "2"
    {
        return Err(error(
            "container workers require cgroup v2 with memory, swap, CPU quota and PID limits",
        ));
    }
    if !engine
        .security_options
        .iter()
        .any(|s| s == "name=seccomp,profile=builtin")
        || engine
            .security_options
            .iter()
            .any(|s| s == "name=rootless" || s == "name=userns")
    {
        return Err(error("container workers require local Docker with built-in seccomp and without user remapping"));
    }
    let record: serde_json::Value =
        decode(&control(&["image", "inspect", "--format", "{{json .}}", image]).await?)?;
    if record["Id"].as_str() != Some(image)
        || !matches!(&record["Config"]["Volumes"], serde_json::Value::Null)
            && !record["Config"]["Volumes"]
                .as_object()
                .is_some_and(|v| v.is_empty())
    {
        return Err(error(
            "container image differs from its pinned ID or declares writable volumes",
        ));
    }
    Ok(engine.id)
}

pub(super) async fn create(
    journal: &mut ContainerWriter,
    lease: &mut ContainerIntent,
    worker: &Worker,
    socket: &Path,
) -> Result<(), CliError> {
    let socket_text = socket
        .to_str()
        .ok_or_else(|| error("container socket path must be UTF-8"))?;
    let metadata = socket.symlink_metadata()?;
    // The runner prepared and owns this socket's private ancestry.
    let uid = rustix::process::getuid().as_raw();
    let gid = rustix::process::getgid().as_raw();
    if socket_text.contains([',', '\n', '\r', '\0'])
        || !socket.is_absolute()
        || !metadata.file_type().is_socket()
        || metadata.uid() != uid
        || metadata.mode() & 0o077 != 0
    {
        return Err(error(
            "container socket must be a private operator-owned socket with a literal mount path",
        ));
    }
    let image = &worker
        .container
        .as_ref()
        .ok_or_else(|| error("missing container profile"))?
        .image;
    let mut args = strings(&[
        "create",
        "--pull=never",
        "--interactive",
        "--name",
        &container_name(lease),
        "--label",
        &format!("{OWNER}={}", lease.owner),
        "--network=none",
        "--ipc=private",
        "--cgroupns=private",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "--user",
        &format!("{uid}:{gid}"),
        "--memory=512m",
        "--memory-swap=512m",
        "--cpus=1",
        "--pids-limit=64",
        "--shm-size=8m",
        "--init",
        "--restart=no",
        "--log-driver=none",
        "--no-healthcheck",
        "--ulimit=core=0",
        "--ulimit=nofile=128:128",
        "--ulimit=fsize=16777216:16777216",
        "--workdir=/work",
        "--tmpfs",
        &format!("/work:rw,noexec,nosuid,nodev,size=64m,uid={uid},gid={gid},mode=0700"),
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777",
        "--env=HOME=/work",
        "--env=TMPDIR=/tmp",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--env=HTTP_PROXY=",
        "--env=HTTPS_PROXY=",
        "--env=ALL_PROXY=",
        "--env=NO_PROXY=",
        "--env=http_proxy=",
        "--env=https_proxy=",
        "--env=all_proxy=",
        "--env=no_proxy=",
        "--mount",
        &format!("type=bind,src={socket_text},dst={PROCESS_SOCKET},readonly"),
        "--entrypoint",
        &worker.command[0],
        image,
    ]);
    args.extend(worker.command[1..].iter().cloned());
    let references: Vec<_> = args.iter().map(String::as_str).collect();
    let response = match control_attempt(&references).await {
        Ok(response) => response,
        Err(failure) => {
            if failure.rejects_image(image) {
                journal.create_rejected(lease)?;
            }
            return Err(error(failure));
        }
    };
    let id = String::from_utf8(response)
        .map_err(error)?
        .trim()
        .to_owned();
    if !valid_id(&id) {
        return Err(error("Docker create did not return an exact container ID"));
    }
    // This commit must precede both inspection and start. An interrupted commit
    // leaves only a create-only intent; that container cannot execute worker code.
    journal.created(lease, id)?;
    let record = inspect(
        lease
            .id
            .as_deref()
            .ok_or_else(|| error("container ID not committed"))?,
    )
    .await?;
    owned(lease, &record)?;
    if record.running {
        return Err(error("new container is unexpectedly running"));
    }
    Ok(())
}

pub(super) fn attach(lease: &ContainerIntent) -> Result<Spawned, CliError> {
    #[cfg(test)]
    if let Some(transport) = *ATTACHMENT_TRANSPORT
        .lock()
        .map_err(|_| error("attachment transport lock poisoned"))?
    {
        return transport(lease);
    }
    let id = lease
        .id
        .as_deref()
        .ok_or_else(|| error("container start requires a committed ID"))?;
    Ok(child::spawn_command(
        command(&strings(&["start", "--attach", "--interactive", id])),
        None,
    )?)
}

fn valid_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[derive(Deserialize)]
struct Record {
    id: String,
    name: String,
    labels: BTreeMap<String, String>,
    running: bool,
    status: String,
    started_at: String,
    exit_code: i32,
    oom_killed: bool,
}

async fn effective_config(id: &str) -> Result<EffectiveConfig, CliError> {
    let config: EffectiveConfig = decode(
        &control(&[
            "container",
            "inspect",
            "--format",
            container_profile::INSPECT_TEMPLATE,
            id,
        ])
        .await?,
    )?;
    Ok(config.normalized())
}

async fn inspect(id: &str) -> Result<Record, CliError> {
    decode(&control(&["container", "inspect", "--format",
        r#"{"id":{{json .Id}},"name":{{json .Name}},"labels":{{json .Config.Labels}},"running":{{json .State.Running}},"status":{{json .State.Status}},"started_at":{{json .State.StartedAt}},"exit_code":{{json .State.ExitCode}},"oom_killed":{{json .State.OOMKilled}}}"#, id]).await?)
}

fn owned(lease: &ContainerIntent, record: &Record) -> Result<(), CliError> {
    if !valid_id(&record.id)
        || record.name != format!("/{}", container_name(lease))
        || record.labels.get(OWNER) != Some(&lease.owner)
        || lease.id.as_ref().is_some_and(|id| *id != record.id)
    {
        return Err(error(
            "refusing container operation: durable owner, name or ID differs",
        ));
    }
    Ok(())
}

/// Authoritative inventory avoids interpreting arbitrary daemon errors as absence.
async fn inventory(lease: &ContainerIntent) -> Result<Vec<String>, CliError> {
    let bytes = control(&[
        "container",
        "ls",
        "--all",
        "--no-trunc",
        "--quiet",
        "--filter",
        &format!("name=^/{}$", container_name(lease)),
    ])
    .await?;
    let text = std::str::from_utf8(&bytes).map_err(error)?;
    let ids: Vec<_> = text.lines().map(str::to_owned).collect();
    if ids.iter().any(|id| !valid_id(id)) || ids.len() > 1 {
        return Err(error("invalid Docker ownership inventory"));
    }
    Ok(ids)
}

async fn remove(lease: &ContainerIntent) -> Result<bool, CliError> {
    if engine().await?.id != lease.engine {
        return Err(error("container journal belongs to another Docker engine"));
    }
    let ids = inventory(lease).await?;
    if let Some(id) = ids.first() {
        let record = inspect(id).await?;
        owned(lease, &record)?;
        control(&["container", "rm", "--force", "--volumes", id]).await?;
        if !inventory(lease).await?.is_empty() {
            return Err(error("container remains after removal"));
        }
        return Ok(true);
    } else if let Some(id) = &lease.id {
        // The name could have been changed administratively. Query the exact ID
        // too, and refuse to drop the durable record while that object exists.
        let remaining = control(&[
            "container",
            "ls",
            "--all",
            "--no-trunc",
            "--quiet",
            "--filter",
            &format!("id={id}"),
        ])
        .await?;
        if !remaining.is_empty() {
            return Err(error(
                "owned container was renamed; restore its recorded name before recovery",
            ));
        }
        return Ok(true);
    }
    // No ID was committed and no object is visible: an in-flight create may
    // still finish, but no start was issued. Retain its intent for later sweeps.
    Ok(lease.create_rejected)
}

pub(super) async fn reconcile(journal: &Journal<'_>) -> Result<(), CliError> {
    for lease in journal.containers()? {
        if remove(&lease).await? {
            journal.container_removed(&lease)?;
        }
    }
    Ok(())
}

pub(super) async fn outcome(
    lease: &ContainerIntent,
    outcome: &mut Outcome,
) -> Result<(), CliError> {
    let record = inspect(
        lease
            .id
            .as_deref()
            .ok_or_else(|| error("missing container ID"))?,
    )
    .await?;
    owned(lease, &record)?;
    classify(&record, outcome);
    Ok(())
}

fn classify(record: &Record, outcome: &mut Outcome) {
    // Docker attachment exit status alone cannot prove that worker execution ended.
    if record.running {
        outcome.success = false;
        if outcome.diagnostic.as_deref() == Some("output_ceiling")
            && matches!(outcome.reason.as_str(), "timeout" | "output_ceiling")
        {
            outcome
                .stderr
                .extend_from_slice(b"\nattachment output_ceiling\n");
            outcome.diagnostic = None;
        } else if outcome.diagnostic.as_deref() == Some("output_ceiling")
            && outcome.reason.starts_with("exit_")
        {
            outcome.reason = "output_ceiling".to_owned();
            outcome.diagnostic = None;
        } else if !matches!(outcome.reason.as_str(), "timeout" | "output_ceiling") {
            // First in the private log, so the log byte bound cannot drop it.
            let (reason, client) = attachment_client(&outcome.reason)
                .map_or(("unclassified", "unclassified"), |client| {
                    (outcome.reason.as_str(), client)
                });
            let mut stderr = format!(
                "chio container still running after attachment ended: reason {reason}, client {client}\n"
            )
            .into_bytes();
            stderr.append(&mut outcome.stderr);
            outcome.stderr = stderr;
            outcome.reason = "container_attachment_lost".to_owned();
        }
    } else if record.status == "created" && record.started_at.starts_with("0001-") {
        outcome.success = false;
        outcome.reason = "container_never_started".to_owned();
    } else if record.status == "exited"
        && chrono::DateTime::parse_from_rfc3339(&record.started_at)
            .is_ok_and(|started| chrono::Datelike::year(&started) > 1)
    {
        if !outcome.reason.starts_with("exit_") {
            outcome.diagnostic.get_or_insert_with(|| {
                format!(
                    "container worker exit observed after attachment {}",
                    outcome.reason
                )
            });
        }
        outcome.success = record.exit_code == 0 && !record.oom_killed;
        outcome.reason = if record.oom_killed {
            "container_memory_ceiling".to_owned()
        } else {
            format!("exit_{}", record.exit_code)
        };
    } else {
        outcome.success = false;
        outcome.reason = "container_state_unknown".to_owned();
    }
    // wait4 accounted the Docker client, not the worker cgroup. Do not publish
    // those host-side numbers as worker resource measurements.
    outcome.usage = ResourceUsage::default();
}

/// Fixed category of how the Docker attach client ended. Only exact fixed
/// reasons are named; any other reason text is reported as unclassified.
fn attachment_client(reason: &str) -> Option<&'static str> {
    Some(match reason {
        "exit_0" => "exit_zero",
        "exit_1" => "exit_error",
        "exit_125" => "exit_engine",
        "signal" => "signal",
        "worker_io_failed" => "killed_bootstrap",
        "runner_interrupted" => "killed_interrupt",
        "container_attachment_error" => "unobserved",
        _ => {
            let code: u8 = reason.strip_prefix("exit_")?.parse().ok()?;
            if reason != format!("exit_{code}") {
                return None;
            }
            "exit_other"
        }
    })
}

#[cfg(test)]
#[path = "container_tests.rs"]
mod tests;

/// One attempt's launch evidence. Exactly one signed record is committed per
/// `(process, attempt)`, and the worker bootstrap, which alone carries the
/// attempt's credential, is written only after a `FullyEnforced` record.
struct LaunchEvidence<'a> {
    authority: &'a LaunchAuthority,
    process: &'a str,
    attempt: u32,
    image: &'a str,
    engine: &'a str,
    container_id: String,
    expected: EffectiveConfig,
}

impl LaunchEvidence<'_> {
    fn record(
        &self,
        state: CageEnforcementState,
        inspected_config_digest: Option<String>,
        started_at: Option<String>,
        failure_class: Option<ContainerLaunchFailure>,
    ) -> Result<ContainerLaunchRecord, CliError> {
        let failed_at_unix_ms = match failure_class {
            Some(_) => Some(self.authority.clock.unix_millis().map_err(error)?.get()),
            None => None,
        };
        Ok(ContainerLaunchRecord {
            schema: chio_process::CONTAINER_LAUNCH_RECORD_SCHEMA.to_owned(),
            process_id: self.process.to_owned(),
            attempt: self.attempt,
            image_id: self.image.to_owned(),
            container_id: self.container_id.clone(),
            engine_identity: self.engine.to_owned(),
            profile_digest: self.expected.digest()?,
            inspected_config_digest,
            state,
            started_at,
            failed_at_unix_ms,
            failure_class,
        })
    }

    fn commit(
        &self,
        writer: &mut ContainerWriter,
        record: ContainerLaunchRecord,
    ) -> Result<SignedContainerLaunchRecord, CliError> {
        let signed =
            SignedContainerLaunchRecord::sign(record, &self.authority.key).map_err(error)?;
        writer.launch_recorded(&signed)?;
        Ok(signed)
    }

    fn fail(
        &self,
        writer: &mut ContainerWriter,
        state: CageEnforcementState,
        failure: ContainerLaunchFailure,
        inspected_config_digest: Option<String>,
    ) -> Result<(), CliError> {
        let record = self.record(state, inspected_config_digest, None, Some(failure))?;
        self.commit(writer, record).map(|_| ())
    }

    /// Require the started object to be the exact owned container, running,
    /// with an engine start time and the configuration inspected before start.
    async fn confirm_start(&self, lease: &ContainerIntent) -> Result<(String, String), CliError> {
        for _ in 0..START_CONFIRMATION_POLLS {
            let record = inspect(&self.container_id).await?;
            owned(lease, &record)?;
            if record.running {
                let started = chrono::DateTime::parse_from_rfc3339(&record.started_at)
                    .is_ok_and(|started| chrono::Datelike::year(&started) > 1);
                let observed = effective_config(&self.container_id).await?;
                if !started || observed != self.expected {
                    return Err(error("started container differs from its inspected launch"));
                }
                return Ok((record.started_at, observed.digest()?));
            }
            if record.status != "created" {
                return Err(error("container stopped before its launch was confirmed"));
            }
            tokio::time::sleep(START_CONFIRMATION_INTERVAL).await;
        }
        Err(error("container start was not confirmed"))
    }

    async fn confirm_and_release(
        &self,
        writer: &mut ContainerWriter,
        lease: &ContainerIntent,
        release: tokio::sync::oneshot::Sender<()>,
        control: &AttemptControl,
    ) -> Result<(), CliError> {
        if control.cancelled() {
            return Ok(());
        }
        let (started_at, digest) = match self.confirm_start(lease).await {
            Ok(confirmed) => confirmed,
            Err(failure) => {
                self.fail(
                    writer,
                    CageEnforcementState::BootstrapFailed,
                    ContainerLaunchFailure::StartUnconfirmed,
                    None,
                )?;
                if control.cancelled() {
                    return Ok(());
                }
                return Err(failure);
            }
        };
        if control.cancelled() {
            return Ok(());
        }
        let record = self.record(
            CageEnforcementState::FullyEnforced,
            Some(digest),
            Some(started_at),
            None,
        )?;
        let signed = self.commit(writer, record)?;
        self.authority
            .runtime
            .bind_worker_profile(self.process, signed.worker_profile().map_err(error)?)
            .map_err(error)?;
        if control.cancelled() {
            return Ok(());
        }
        release
            .send(())
            .map_err(|()| error("worker attachment ended before its bootstrap"))
    }
}

/// Supervision, including removal on timeout, runs in its own scheduler slot.
/// Cancelling the task kills the Docker client; the runner then reconciles all
/// durable container records before releasing its host lock.
pub(super) async fn run(
    mut writer: ContainerWriter,
    mut lease: ContainerIntent,
    worker: Worker,
    socket: std::path::PathBuf,
    input: Vec<u8>,
    attempt: u32,
    control: AttemptControl,
) -> (Result<Outcome, CliError>, Cleanup) {
    let result: Result<Outcome, CliError> = async {
        if control.cancelled() {
            writer.create_rejected(&mut lease)?;
            return Ok(cancelled_outcome());
        }
        create(&mut writer, &mut lease, &worker, &socket).await?;
        if control.cancelled() {
            if !remove(&lease).await? {
                return Err(error("cancelled container cleanup is unconfirmed"));
            }
            writer.removed(&lease)?;
            return Ok(cancelled_outcome());
        }
        let image = &worker
            .container
            .as_ref()
            .ok_or_else(|| error("missing container profile"))?
            .image;
        let evidence = LaunchEvidence {
            authority: &control.authority,
            process: &worker.process,
            attempt,
            image,
            engine: &lease.engine,
            container_id: lease
                .id
                .clone()
                .ok_or_else(|| error("container ID not committed"))?,
            expected: container_profile::fixed(
                image,
                rustix::process::getuid().as_raw(),
                rustix::process::getgid().as_raw(),
                socket
                    .to_str()
                    .ok_or_else(|| error("container socket path must be UTF-8"))?,
            ),
        };
        let observed = effective_config(&evidence.container_id).await?;
        if observed != evidence.expected {
            evidence.fail(
                &mut writer,
                CageEnforcementState::Rejected,
                ContainerLaunchFailure::ProfileMismatch,
                Some(observed.digest()?),
            )?;
            return Err(error(
                "container configuration differs from the fixed worker profile; it was not started",
            ));
        }
        let (release, released) = tokio::sync::oneshot::channel();
        let spawned = match attach(&lease) {
            Ok(spawned) => spawned,
            Err(failure) => {
                evidence.fail(
                    &mut writer,
                    CageEnforcementState::BootstrapFailed,
                    ContainerLaunchFailure::StartFailed,
                    None,
                )?;
                return observe_attachment(&lease, Err(failure)).await;
            }
        };
        let (attachment, confirmed) = tokio::join!(
            child::wait_bounded(
                spawned,
                input,
                Some(released),
                Duration::from_secs(worker.timeout_seconds),
                None,
                Some(2 * 1024 * 1024),
                control.cancellation.clone(),
            ),
            evidence.confirm_and_release(&mut writer, &lease, release, &control),
        );
        control
            .authority
            .runtime
            .clear_worker_profile(&worker.process)
            .map_err(error)?;
        confirmed?;
        let mut outcome = observe_attachment(&lease, attachment.map_err(CliError::from)).await?;
        if control.cancelled()
            && !outcome.success
            && matches!(
                outcome.reason.as_str(),
                "container_attachment_lost" | "container_never_started" | "runner_interrupted"
            )
        {
            if !remove(&lease).await? {
                return Err(error("cancelled container cleanup is unconfirmed"));
            }
            writer.removed(&lease)?;
            outcome.reason = "process_cancelled".into();
        }
        Ok(outcome)
    }
    .await;
    let result = result.or_else(|failure| {
        if lease.create_rejected {
            Ok(Outcome {
                success: false,
                reason: "container_create_rejected".into(),
                usage: ResourceUsage::default(),
                stdout: vec![],
                stderr: failure.to_string().into_bytes(),
                diagnostic: None,
            })
        } else {
            Err(failure)
        }
    });
    (result, Cleanup { writer, lease })
}

fn cancelled_outcome() -> Outcome {
    Outcome {
        success: false,
        reason: "process_cancelled".into(),
        usage: ResourceUsage::default(),
        stdout: vec![],
        stderr: vec![],
        diagnostic: None,
    }
}

async fn observe_attachment(
    lease: &ContainerIntent,
    attachment: Result<Outcome, CliError>,
) -> Result<Outcome, CliError> {
    let client_failed = attachment.is_err();
    let mut result = attachment.unwrap_or_else(|failure| {
        let diagnostic = failure.to_string();
        Outcome {
            success: false,
            reason: "container_attachment_error".into(),
            usage: ResourceUsage::default(),
            stdout: vec![],
            stderr: diagnostic.as_bytes().to_vec(),
            diagnostic: Some(diagnostic),
        }
    });
    // Inspection uses the same bounded control path and exact owned identity.
    // A client error neither establishes absence nor makes cleanup an exit oracle.
    if let Err(failure) = outcome(lease, &mut result).await {
        if !client_failed {
            return Err(failure);
        }
        let diagnostic = format!(
            "{}; authoritative inspection failed: {failure}",
            result.diagnostic.as_deref().unwrap_or("attachment failed")
        );
        result.stderr = diagnostic.as_bytes().to_vec();
        result.diagnostic = Some(diagnostic);
        result.reason = "container_state_unknown".into();
    } else if client_failed
        && !result.reason.starts_with("exit_")
        && result.reason != "container_memory_ceiling"
    {
        result.reason = "container_state_unknown".into();
    }
    Ok(result)
}

pub(super) struct Cleanup {
    writer: ContainerWriter,
    lease: ContainerIntent,
}

impl Cleanup {
    pub(super) async fn run(mut self) -> Result<(), CliError> {
        if remove(&self.lease).await? {
            self.writer.removed(&self.lease)?;
            Ok(())
        } else {
            Err(error(
                "container creation remains uncertain; retain its ownership record",
            ))
        }
    }
}
