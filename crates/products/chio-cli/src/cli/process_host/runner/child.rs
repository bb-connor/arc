use std::io;
use std::path::Path;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::task::JoinSet;

use super::plan::{Ceiling, Worker};

const LOG_BYTES: usize = 65_536;
type Capture = Arc<Mutex<Vec<u8>>>;

pub(super) struct Outcome {
    pub success: bool,
    pub reason: String,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub(super) fn spawn(worker: &Worker) -> io::Result<Child> {
    let mut command = Command::new(&worker.command[0]);
    command
        .args(&worker.command[1..])
        .current_dir(&worker.cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let parent = std::process::id() as libc::pid_t;
    let ceilings = worker
        .resources
        .map(|resources| resources.ceilings())
        .unwrap_or_default();
    // SAFETY: after fork, only prctl/getppid/setrlimit and nonallocating errno
    // conversion run over a vector allocated before the fork. No locks, heap
    // operations, environment reads or Rust destructors. Spawn is called by the
    // block_on thread that owns the runner's lifetime.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                return Err(io::Error::from_raw_os_error(libc::ECHILD));
            }
            for (ceiling, value) in &ceilings {
                let resource = match ceiling {
                    Ceiling::CpuSeconds => libc::RLIMIT_CPU,
                    Ceiling::OpenFiles => libc::RLIMIT_NOFILE,
                    Ceiling::FileBytes => libc::RLIMIT_FSIZE,
                    Ceiling::AddressSpaceBytes => libc::RLIMIT_AS,
                };
                let limit = libc::rlimit {
                    rlim_cur: *value,
                    rlim_max: *value,
                };
                if libc::setrlimit(resource, &limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    command.spawn()
}

async fn capture(mut reader: impl AsyncRead + Unpin, data: Capture) -> io::Result<()> {
    let mut buffer = [0; 8192];
    loop {
        let count = reader.read(&mut buffer).await?;
        if count == 0 {
            return Ok(());
        }
        let mut data = data
            .lock()
            .map_err(|_| io::Error::other("worker log capture poisoned"))?;
        let keep = count.min(LOG_BYTES.saturating_sub(data.len()));
        data.extend_from_slice(&buffer[..keep]);
    }
}

pub(super) async fn wait(
    mut child: Child,
    input: Vec<u8>,
    timeout: Duration,
) -> io::Result<Outcome> {
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let stderr = Arc::new(Mutex::new(Vec::new()));
    let mut readers = JoinSet::new();
    readers.spawn(capture(
        child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("missing stdout"))?,
        stdout.clone(),
    ));
    readers.spawn(capture(
        child
            .stderr
            .take()
            .ok_or_else(|| io::Error::other("missing stderr"))?,
        stderr.clone(),
    ));
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("missing stdin"))?;
    let execution = async {
        tokio::time::timeout(Duration::from_secs(5), stdin.write_all(&input))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "worker bootstrap timed out"))??;
        drop(stdin);
        child.wait().await
    };
    let (success, reason) = match tokio::time::timeout(timeout, execution).await {
        Ok(Ok(status)) => (
            status.success(),
            status
                .code()
                .map_or_else(|| "signal".to_owned(), |code| format!("exit_{code}")),
        ),
        Ok(Err(_)) => {
            child.kill().await?;
            (false, "worker_io_failed".to_owned())
        }
        Err(_) => {
            child.kill().await?;
            (false, "timeout".to_owned())
        }
    };
    // Descendants can inherit stdio. They cannot hold the runner open forever.
    let _ = tokio::time::timeout(Duration::from_secs(1), async {
        while readers.join_next().await.is_some() {}
    })
    .await;
    readers.shutdown().await;
    let copy = |data: Capture| {
        data.lock()
            .map(|v| v.clone())
            .map_err(|_| io::Error::other("worker log capture poisoned"))
    };
    Ok(Outcome {
        success,
        reason,
        stdout: copy(stdout)?,
        stderr: copy(stderr)?,
    })
}

pub(super) fn write_log(
    directory: &chio_control_plane::PreparedPrivateDirectory,
    name: &str,
    bytes: &[u8],
    credential: &str,
) -> io::Result<()> {
    let mut content = String::from_utf8_lossy(bytes).replace(credential, "[REDACTED]");
    if content.len() > LOG_BYTES {
        let mut end = LOG_BYTES;
        while !content.is_char_boundary(end) {
            end -= 1;
        }
        content.truncate(end);
    }
    directory.write_new_secret(Path::new(name), content.as_bytes())
}
