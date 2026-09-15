//! Operator-owned Git worktrees and bounded review output.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    sync::watch,
};

const MAX_OUTPUT: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitSnapshot {
    pub repository: PathBuf,
    pub source_workspace: PathBuf,
    pub worktree: PathBuf,
    pub base_revision: String,
}

#[derive(Debug, Serialize)]
pub struct Changes {
    pub snapshot: GitSnapshot,
    pub patch: String,
    pub patch_sha256: String,
    pub untracked_files: Vec<String>,
}

pub(crate) async fn prepare(
    source: &Path,
    worktree: &Path,
    state: &Path,
    stop: watch::Receiver<bool>,
) -> Result<(PathBuf, GitSnapshot)> {
    let repository = PathBuf::from(
        command(source, &["rev-parse", "--show-toplevel"], stop.clone())
            .await?
            .trim(),
    )
    .canonicalize()?;
    if state.starts_with(&repository) {
        return Err(Error::Invalid(
            "Git task state must be outside the source repository; choose another --state-dir"
                .into(),
        ));
    }
    if !command(
        &repository,
        &["status", "--porcelain=v1", "--untracked-files=no"],
        stop.clone(),
    )
    .await?
    .is_empty()
    {
        return Err(Error::Invalid("commit or stash tracked changes before starting a Git task; untracked and ignored files are not copied".into()));
    }
    let revision = command(
        &repository,
        &["rev-parse", "--verify", "HEAD^{commit}"],
        stop.clone(),
    )
    .await?;
    let revision = revision.trim();
    if !matches!(revision.len(), 40 | 64) || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(Error::Invalid(
            "Git returned an invalid base revision".into(),
        ));
    }
    let destination = worktree
        .to_str()
        .ok_or_else(|| Error::Invalid("Git task path must be UTF-8".into()))?;
    command(
        &repository,
        &["worktree", "add", "--detach", destination, revision],
        stop,
    )
    .await?;
    let relative = source
        .strip_prefix(&repository)
        .map_err(|_| Error::Invalid("workspace is outside the Git repository".into()))?;
    let workspace = worktree.join(relative).canonicalize()?;
    Ok((
        workspace,
        GitSnapshot {
            repository,
            source_workspace: source.into(),
            worktree: worktree.into(),
            base_revision: revision.into(),
        },
    ))
}

pub(crate) async fn changes(snapshot: &GitSnapshot) -> Result<Changes> {
    let (_sender, stop) = watch::channel(false);
    let top = command(
        &snapshot.worktree,
        &["rev-parse", "--show-toplevel"],
        stop.clone(),
    )
    .await?;
    if Path::new(top.trim()).canonicalize()? != snapshot.worktree.canonicalize()? {
        return Err(Error::Invalid(
            "the task worktree no longer matches its recorded location".into(),
        ));
    }
    let patch = command(
        &snapshot.worktree,
        &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--binary",
            "--no-color",
            "--no-renames",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            &snapshot.base_revision,
            "--",
        ],
        stop.clone(),
    )
    .await?;
    let files = command(
        &snapshot.worktree,
        &["ls-files", "--others", "--exclude-standard", "-z"],
        stop,
    )
    .await?;
    let untracked_files: Vec<String> = files.split_terminator('\0').map(str::to_owned).collect();
    if untracked_files.len() > 1024 {
        return Err(Error::Invalid(
            "task has more than 1024 untracked files; inspect its worktree directly".into(),
        ));
    }
    Ok(Changes {
        snapshot: snapshot.clone(),
        patch_sha256: chio_core::crypto::sha256_hex(patch.as_bytes()),
        patch,
        untracked_files,
    })
}

struct Group(rustix::process::Pid);
impl Drop for Group {
    fn drop(&mut self) {
        let _ = rustix::process::kill_process_group(self.0, rustix::process::Signal::KILL);
    }
}

async fn read(reader: impl AsyncRead + Unpin, limit: usize) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut output)
        .await?;
    if output.len() > limit {
        return Err(std::io::Error::other(
            "Git output exceeded its limit; inspect the worktree directly",
        ));
    }
    Ok(output)
}

async fn command(
    directory: &Path,
    args: &[&str],
    mut stop: watch::Receiver<bool>,
) -> Result<String> {
    if *stop.borrow() {
        return Err(Error::Invalid("Git task preparation was stopped".into()));
    }
    let mut child = Command::new("git")
        .args([
            "--no-pager",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.quotePath=false",
        ])
        .args(args)
        .current_dir(directory)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0)
        .spawn()?;
    let group = Group(
        child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .and_then(rustix::process::Pid::from_raw)
            .ok_or_else(|| Error::Invalid("Git process group unavailable".into()))?,
    );
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::Invalid("Git stdout unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| Error::Invalid("Git stderr unavailable".into()))?;
    let execution =
        async { tokio::try_join!(child.wait(), read(stdout, MAX_OUTPUT), read(stderr, 32768)) };
    let result = tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(30), execution) => result
            .map_err(|_| Error::Invalid("Git operation exceeded 30 seconds".into()))?.map_err(Error::from),
        _ = stop.wait_for(|value| *value) => Err(Error::Invalid("Git operation stopped".into())),
    };
    drop(group);
    if result.is_err() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    let (status, stdout, _) = result?;
    if !status.success() {
        return Err(Error::Invalid("Git operation failed; use a committed repository and inspect the retained task directory".into()));
    }
    String::from_utf8(stdout).map_err(|_| Error::Invalid("Git output is not UTF-8".into()))
}
