use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{ChildStderr, ChildStdin, ChildStdout};
use tokio::task::JoinSet;

use super::plan::{Ceiling, Worker};

const LOG_BYTES: usize = 65_536;
/// How often a resident-memory ceiling is compared with the worker's peak
/// resident set. A worker can exceed the ceiling for up to one interval
/// before it is terminated; the exact peak is still accounted at exit.
const RESIDENT_SAMPLE_INTERVAL: Duration = Duration::from_millis(50);
type Capture = Arc<Mutex<Vec<u8>>>;

/// Resource use of one reaped attempt from the kernel's process accounting:
/// the worker process and the descendants it waited for.
#[derive(Clone, Copy, Default)]
pub(super) struct Usage {
    pub peak_resident_bytes: u64,
    pub cpu_ms: u64,
}

pub(super) struct Outcome {
    pub success: bool,
    pub reason: String,
    pub usage: Usage,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// A spawned worker and a descriptor naming exactly that process. Signals go
/// through the descriptor, so a process id reused after the worker is reaped
/// can never receive one meant for the worker.
pub(super) struct Spawned {
    child: Child,
    process: ProcessFd,
}

struct ProcessFd(OwnedFd);

impl ProcessFd {
    fn open(pid: libc::pid_t) -> io::Result<Self> {
        // SAFETY: pidfd_open takes a process id and flags and returns a new
        // descriptor, or -1 with errno set.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        let fd = libc::c_int::try_from(fd).map_err(io::Error::other)?;
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the kernel just returned this descriptor and nothing else owns it.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }

    /// Kill the process the descriptor names. A process that already exited
    /// is not an error: it can no longer act.
    fn kill(&self) -> io::Result<()> {
        // SAFETY: pidfd_send_signal takes the descriptor, a signal, an optional
        // siginfo and flags; a null siginfo selects the kernel's default.
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.0.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result == 0 {
            return Ok(());
        }
        let failure = io::Error::last_os_error();
        if failure.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        Err(failure)
    }
}

pub(super) fn spawn(worker: &Worker) -> io::Result<Spawned> {
    let mut command = Command::new(&worker.command[0]);
    command
        .args(&worker.command[1..])
        .current_dir(&worker.cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
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
    let mut child = command.spawn()?;
    // Nothing reaps the child before it is waited for, so its id names it here.
    let pid = libc::pid_t::try_from(child.id()).map_err(io::Error::other)?;
    match ProcessFd::open(pid) {
        Ok(process) => Ok(Spawned { child, process }),
        Err(failure) => {
            child.kill()?;
            child.wait()?;
            Err(failure)
        }
    }
}

/// Reap the worker and read the kernel's accounting of the attempt.
fn reap(pid: libc::pid_t) -> io::Result<(ExitStatus, Usage)> {
    let mut status = 0;
    // SAFETY: rusage is plain data that wait4 fills in completely.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    loop {
        // SAFETY: wait4 writes only the status and usage locations passed to it.
        let reaped = unsafe { libc::wait4(pid, &mut status, 0, &mut usage) };
        if reaped == pid {
            break;
        }
        if reaped != -1 {
            return Err(io::Error::other("wait4 returned another process"));
        }
        let failure = io::Error::last_os_error();
        if failure.raw_os_error() != Some(libc::EINTR) {
            return Err(failure);
        }
    }
    let peak_resident_bytes = u64::try_from(usage.ru_maxrss)
        .unwrap_or(0)
        .saturating_mul(1024);
    let cpu_ms = millis(usage.ru_utime).saturating_add(millis(usage.ru_stime));
    Ok((
        ExitStatus::from_raw(status),
        Usage {
            peak_resident_bytes,
            cpu_ms,
        },
    ))
}

fn millis(time: libc::timeval) -> u64 {
    u64::try_from(time.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1000)
        .saturating_add(u64::try_from(time.tv_usec).unwrap_or(0) / 1000)
}

/// The worker's peak resident set so far. None once the process has exited
/// or when procfs does not report it.
fn peak_resident(pid: libc::pid_t) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let value = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))?;
    let kib: u64 = value.trim().strip_suffix("kB")?.trim().parse().ok()?;
    Some(kib.saturating_mul(1024))
}

/// Kills the worker if supervision ends before the worker was reaped, so a
/// cancelled supervision never leaves a worker running.
struct Guard {
    process: ProcessFd,
    reaped: bool,
}

impl Drop for Guard {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.process.kill();
        }
    }
}

enum End {
    Exited,
    BootstrapFailed,
    Timeout,
    ResidentCeiling,
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
    spawned: Spawned,
    input: Vec<u8>,
    timeout: Duration,
    resident_ceiling: Option<u64>,
) -> io::Result<Outcome> {
    let Spawned { mut child, process } = spawned;
    let pid = libc::pid_t::try_from(child.id()).map_err(io::Error::other)?;
    let mut guard = Guard {
        process,
        reaped: false,
    };
    // One blocking thread waits for each active worker so the kernel's
    // accounting of the attempt arrives with its exit status. The plan's
    // concurrency ceiling bounds these threads.
    let mut reaping = tokio::task::spawn_blocking(move || reap(pid));
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let stderr = Arc::new(Mutex::new(Vec::new()));
    let mut readers = JoinSet::new();
    readers.spawn(capture(
        ChildStdout::from_std(
            child
                .stdout
                .take()
                .ok_or_else(|| io::Error::other("missing stdout"))?,
        )?,
        stdout.clone(),
    ));
    readers.spawn(capture(
        ChildStderr::from_std(
            child
                .stderr
                .take()
                .ok_or_else(|| io::Error::other("missing stderr"))?,
        )?,
        stderr.clone(),
    ));
    let mut stdin = ChildStdin::from_std(
        child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("missing stdin"))?,
    )?;
    let bootstrap = tokio::time::timeout(Duration::from_secs(5), stdin.write_all(&input)).await;
    drop(stdin);
    let mut samples = tokio::time::interval(RESIDENT_SAMPLE_INTERVAL);
    samples.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut reaped = None;
    let end = if matches!(bootstrap, Ok(Ok(()))) {
        loop {
            tokio::select! {
                biased;
                result = &mut reaping => {
                    reaped = Some(result);
                    break End::Exited;
                }
                _ = &mut deadline => break End::Timeout,
                _ = samples.tick(), if resident_ceiling.is_some() => {
                    if let Some(ceiling) = resident_ceiling {
                        if peak_resident(pid).is_some_and(|peak| peak > ceiling) {
                            break End::ResidentCeiling;
                        }
                    }
                }
            }
        }
    } else {
        End::BootstrapFailed
    };
    let result = match reaped {
        Some(result) => result,
        None => {
            guard.process.kill()?;
            (&mut reaping).await
        }
    };
    guard.reaped = true;
    let (status, usage) = result.map_err(io::Error::other)??;
    let (success, reason) = match end {
        End::Exited => (
            status.success(),
            status
                .code()
                .map_or_else(|| "signal".to_owned(), |code| format!("exit_{code}")),
        ),
        End::BootstrapFailed => (false, "worker_io_failed".to_owned()),
        End::Timeout => (false, "timeout".to_owned()),
        End::ResidentCeiling => (false, "resident_memory_ceiling".to_owned()),
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
        usage,
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
