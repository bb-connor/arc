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

use super::super::state::error;
use super::child::{self, Outcome, Spawned, Usage};
use super::journal::{ContainerWriter, Journal};
use super::plan::Worker;
use crate::CliError;

const OWNER: &str = "chio.runner.owner";

pub(super) struct Lease {
    pub owner: String,
    pub engine: String,
    pub id: Option<String>,
}

impl Lease {
    fn name(&self) -> String {
        format!("chio-run-{}", self.owner)
    }
}

fn command(arguments: &[String]) -> Command {
    let mut command = Command::new("/usr/bin/docker");
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
    let child = child::spawn_command(command(&strings(arguments)), None)?;
    let outcome = child::wait_bounded(
        child,
        Vec::new(),
        Duration::from_secs(30),
        None,
        Some(65_536),
    )
    .await?;
    if !outcome.success {
        return Err(error("local Docker control failed or timed out; preserve the host state and engine for recovery"));
    }
    Ok(outcome.stdout)
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, CliError> {
    serde_json::from_slice(bytes).map_err(|_| error("invalid local Docker response"))
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
    lease: &mut Lease,
    worker: &Worker,
    socket: &Path,
) -> Result<(), CliError> {
    let socket_text = socket
        .to_str()
        .ok_or_else(|| error("container socket path must be UTF-8"))?;
    let metadata = socket.symlink_metadata()?;
    // The runner prepared and owns this socket's private ancestry.
    // SAFETY: getuid/getgid are read-only process queries.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
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
        &lease.name(),
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
        &format!("type=bind,src={socket_text},dst=/run/chio/process.sock,readonly"),
        "--entrypoint",
        &worker.command[0],
        image,
    ]);
    args.extend(worker.command[1..].iter().cloned());
    let references: Vec<_> = args.iter().map(String::as_str).collect();
    let response = control(&references).await?;
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

pub(super) fn attach(lease: &Lease) -> Result<Spawned, CliError> {
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
    exit_code: i32,
    oom_killed: bool,
}

async fn inspect(id: &str) -> Result<Record, CliError> {
    decode(&control(&["container", "inspect", "--format",
        r#"{"id":{{json .Id}},"name":{{json .Name}},"labels":{{json .Config.Labels}},"running":{{json .State.Running}},"exit_code":{{json .State.ExitCode}},"oom_killed":{{json .State.OOMKilled}}}"#, id]).await?)
}

fn owned(lease: &Lease, record: &Record) -> Result<(), CliError> {
    if !valid_id(&record.id)
        || record.name != format!("/{}", lease.name())
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
async fn inventory(lease: &Lease) -> Result<Vec<String>, CliError> {
    let bytes = control(&[
        "container",
        "ls",
        "--all",
        "--no-trunc",
        "--quiet",
        "--filter",
        &format!("name=^/{}$", lease.name()),
    ])
    .await?;
    let text = std::str::from_utf8(&bytes).map_err(error)?;
    let ids: Vec<_> = text.lines().map(str::to_owned).collect();
    if ids.iter().any(|id| !valid_id(id)) || ids.len() > 1 {
        return Err(error("invalid Docker ownership inventory"));
    }
    Ok(ids)
}

async fn remove(lease: &Lease) -> Result<bool, CliError> {
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
    Ok(false)
}

pub(super) async fn reconcile(journal: &Journal<'_>) -> Result<(), CliError> {
    for lease in journal.containers()? {
        if remove(&lease).await? {
            journal.container_removed(&lease)?;
        }
    }
    Ok(())
}

pub(super) async fn outcome(lease: &Lease, outcome: &mut Outcome) -> Result<(), CliError> {
    let record = inspect(
        lease
            .id
            .as_deref()
            .ok_or_else(|| error("missing container ID"))?,
    )
    .await?;
    owned(lease, &record)?;
    // Docker attachment exit status alone cannot prove that worker execution ended.
    if record.running {
        outcome.success = false;
        if outcome.reason.starts_with("exit_") {
            outcome.reason = "container_attachment_lost".to_owned();
        }
    } else if outcome.reason.starts_with("exit_") {
        outcome.success = record.exit_code == 0 && !record.oom_killed;
        outcome.reason = if record.oom_killed {
            "container_memory_ceiling".to_owned()
        } else {
            format!("exit_{}", record.exit_code)
        };
    }
    // wait4 accounted the Docker client, not the worker cgroup. Do not publish
    // those host-side numbers as worker resource measurements.
    outcome.usage = Usage::default();
    Ok(())
}

/// Supervision, including removal on timeout, runs in its own scheduler slot.
/// Cancelling the task kills the Docker client; the runner then reconciles all
/// durable container records before releasing its host lock.
pub(super) async fn run(
    mut writer: ContainerWriter,
    mut lease: Lease,
    worker: Worker,
    socket: std::path::PathBuf,
    input: Vec<u8>,
) -> Result<Outcome, CliError> {
    let result = async {
        create(&mut writer, &mut lease, &worker, &socket).await?;
        let spawned = attach(&lease)?;
        let mut result = child::wait_bounded(
            spawned,
            input,
            Duration::from_secs(worker.timeout_seconds),
            None,
            Some(2 * 1024 * 1024),
        )
        .await?;
        outcome(&lease, &mut result).await?;
        Ok(result)
    }
    .await;
    if remove(&lease).await? {
        writer.removed(&lease)?;
    }
    result
}
