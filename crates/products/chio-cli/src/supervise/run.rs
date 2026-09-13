//! Run one service under supervision.
//!
//! The service starts with its credentials in its environment. Until it is
//! ready the supervisor watches three things at once: the readiness probe,
//! the service exiting early, and a stop signal. Once ready it reports to
//! the manager and waits for either the service to exit or a stop signal,
//! which it forwards, granting the service a bounded drain before SIGKILL.
//! The outcome is the service's own exit status, so a supervisor that ends
//! because its service was terminated by a signal ends the same way.

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::Duration;

use tokio::process::{Child, Command};
use tokio::signal::unix::{signal, Signal, SignalKind};

use super::notify::Notifier;
use super::readiness::{http_client, Readiness};

const READINESS_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Everything one supervised run needs.
pub struct Supervision {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub environment: Vec<(String, String)>,
    pub readiness: Readiness,
    pub ready_timeout: Duration,
    pub stop_grace: Duration,
    pub notifier: Notifier,
}

/// How the service ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Code(i32),
    Signal(i32),
}

impl From<ExitStatus> for Exit {
    fn from(status: ExitStatus) -> Self {
        match status.signal() {
            Some(number) => Self::Signal(number),
            None => Self::Code(status.code().unwrap_or(1)),
        }
    }
}

impl fmt::Display for Exit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Code(code) => write!(f, "exit code {code}"),
            Self::Signal(number) => write!(f, "signal {number}"),
        }
    }
}

/// Why a supervised run did not end with the service's own exit.
#[derive(Debug)]
pub enum SuperviseError {
    Spawn(io::Error),
    Signals(io::Error),
    HttpClient(reqwest::Error),
    Wait(io::Error),
    /// The service did not become ready in time; it was stopped and ended as recorded.
    ReadinessTimeout(Exit),
    /// The service ended before it became ready.
    ExitedBeforeReady(Exit),
}

impl fmt::Display for SuperviseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(error) => write!(f, "the service could not be started: {error}"),
            Self::Signals(error) => write!(f, "stop signals could not be installed: {error}"),
            Self::HttpClient(error) => write!(f, "the readiness client could not be built: {error}"),
            Self::Wait(error) => write!(f, "waiting for the service failed: {error}"),
            Self::ReadinessTimeout(exit) => {
                write!(f, "the service did not become ready in time and was stopped ({exit})")
            }
            Self::ExitedBeforeReady(exit) => write!(f, "the service ended before it was ready ({exit})"),
        }
    }
}

impl std::error::Error for SuperviseError {}

struct StopSignals {
    terminate: Signal,
    interrupt: Signal,
    hangup: Signal,
}

impl StopSignals {
    fn install() -> io::Result<Self> {
        Ok(Self {
            terminate: signal(SignalKind::terminate())?,
            interrupt: signal(SignalKind::interrupt())?,
            hangup: signal(SignalKind::hangup())?,
        })
    }

    /// The next stop signal to forward. A stream that closes can deliver
    /// nothing more, so it is parked rather than polled again.
    async fn next(&mut self) -> i32 {
        loop {
            let received = tokio::select! {
                received = self.terminate.recv() => received.map(|()| libc::SIGTERM),
                received = self.interrupt.recv() => received.map(|()| libc::SIGINT),
                received = self.hangup.recv() => received.map(|()| libc::SIGHUP),
            };
            match received {
                Some(number) => return number,
                None => tokio::time::sleep(Duration::from_secs(1)).await,
            }
        }
    }
}

/// Supervise the service until it exits or a stop signal ends it.
pub async fn supervise(supervision: Supervision) -> Result<Exit, SuperviseError> {
    let Supervision {
        program,
        args,
        environment,
        readiness,
        ready_timeout,
        stop_grace,
        notifier,
    } = supervision;
    let http = http_client().map_err(SuperviseError::HttpClient)?;
    let mut signals = StopSignals::install().map_err(SuperviseError::Signals)?;
    let mut child = Command::new(&program)
        .args(&args)
        .envs(environment)
        .kill_on_drop(true)
        .spawn()
        .map_err(SuperviseError::Spawn)?;
    report(&notifier, |notifier| {
        notifier.status(&format!("starting, waiting for {}", readiness.describe()))
    });

    if !readiness.is_immediate() {
        let deadline = tokio::time::Instant::now() + ready_timeout;
        let mut next_probe = tokio::time::Instant::now();
        loop {
            tokio::select! {
                status = child.wait() => {
                    let exit = Exit::from(status.map_err(SuperviseError::Wait)?);
                    return Err(SuperviseError::ExitedBeforeReady(exit));
                }
                number = signals.next() => {
                    report(&notifier, Notifier::stopping);
                    return stop(&mut child, number, stop_grace).await;
                }
                () = tokio::time::sleep_until(deadline) => {
                    report(&notifier, |notifier| notifier.status("readiness timed out, stopping"));
                    let exit = stop(&mut child, libc::SIGTERM, stop_grace).await?;
                    return Err(SuperviseError::ReadinessTimeout(exit));
                }
                () = tokio::time::sleep_until(next_probe) => {
                    if readiness.probe(&http).await {
                        break;
                    }
                    next_probe = tokio::time::Instant::now() + READINESS_POLL_INTERVAL;
                }
            }
        }
    }
    report(&notifier, Notifier::ready);
    report(&notifier, |notifier| notifier.status("ready"));

    tokio::select! {
        status = child.wait() => status.map(Exit::from).map_err(SuperviseError::Wait),
        number = signals.next() => {
            report(&notifier, Notifier::stopping);
            stop(&mut child, number, stop_grace).await
        }
    }
}

/// Forward `number` to the service, grant it `grace` to drain, then SIGKILL.
async fn stop(child: &mut Child, number: i32, grace: Duration) -> Result<Exit, SuperviseError> {
    if let Some(pid) = child.id().and_then(|pid| libc::pid_t::try_from(pid).ok()) {
        // SAFETY: kill(2) takes a process id and a signal number and touches
        // no memory. The id belongs to a child this supervisor has not yet
        // reaped, so it cannot have been reused; ESRCH only means the child
        // already ended, which the wait below reports.
        let _ = unsafe { libc::kill(pid, number) };
    }
    match tokio::time::timeout(grace, child.wait()).await {
        Ok(status) => status.map(Exit::from).map_err(SuperviseError::Wait),
        Err(_elapsed) => {
            child.start_kill().map_err(SuperviseError::Wait)?;
            child
                .wait()
                .await
                .map(Exit::from)
                .map_err(SuperviseError::Wait)
        }
    }
}

fn report(notifier: &Notifier, send: impl FnOnce(&Notifier) -> io::Result<()>) {
    if let Err(error) = send(notifier) {
        eprintln!("chio security supervise: notify send failed: {error}");
    }
}

/// Replace this process with the service, credentials in its environment.
/// Returns only when the replacement failed.
pub fn exec_with_credentials(
    program: &Path,
    args: &[OsString],
    environment: Vec<(String, String)>,
) -> io::Error {
    use std::os::unix::process::CommandExt;
    std::process::Command::new(program)
        .args(args)
        .envs(environment)
        .exec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shell(script: &str) -> Supervision {
        Supervision {
            program: PathBuf::from("/bin/sh"),
            args: vec![OsString::from("-c"), OsString::from(script)],
            environment: vec![("CHIO_TEST_SECRET".to_string(), "from-credential".to_string())],
            readiness: Readiness::Immediate,
            ready_timeout: Duration::from_secs(5),
            stop_grace: Duration::from_secs(5),
            notifier: Notifier::disabled(),
        }
    }

    #[tokio::test]
    async fn the_service_exit_code_and_environment_are_preserved() {
        let outcome = supervise(shell("[ \"$CHIO_TEST_SECRET\" = from-credential ] && exit 7"))
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(outcome, Exit::Code(7));
    }

    #[tokio::test]
    async fn a_service_that_ends_before_readiness_is_a_failure() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let mut supervision = shell("exit 0");
        supervision.readiness = Readiness::UnixSocket(directory.path().join("never.sock"));
        assert!(matches!(
            supervise(supervision).await,
            Err(SuperviseError::ExitedBeforeReady(Exit::Code(0)))
        ));
    }

    #[tokio::test]
    async fn readiness_timeout_stops_the_service() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let mut supervision = shell("sleep 30");
        supervision.readiness = Readiness::UnixSocket(directory.path().join("never.sock"));
        supervision.ready_timeout = Duration::from_millis(300);
        let started = std::time::Instant::now();
        assert!(matches!(
            supervise(supervision).await,
            Err(SuperviseError::ReadinessTimeout(Exit::Signal(libc::SIGTERM)))
        ));
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn readiness_is_reported_once_the_service_listens() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("{error}"));
        let socket = directory.path().join("service.sock");
        let notify = directory.path().join("notify.sock");
        let manager = std::os::unix::net::UnixDatagram::bind(&notify)
            .unwrap_or_else(|error| panic!("{error}"));
        manager
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap_or_else(|error| panic!("{error}"));
        let listener_path = socket.clone();
        let listener = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(400)).await;
            tokio::net::UnixListener::bind(&listener_path).unwrap_or_else(|error| panic!("{error}"))
        });
        let mut supervision = shell("sleep 0.9; exit 3");
        supervision.readiness = Readiness::UnixSocket(socket);
        supervision.notifier = Notifier::for_socket(notify.as_os_str());
        let outcome = supervise(supervision)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(outcome, Exit::Code(3));
        drop(listener.await.unwrap_or_else(|error| panic!("{error}")));
        let mut messages = Vec::new();
        let mut buffer = [0_u8; 256];
        while let Ok(length) = manager.recv(&mut buffer) {
            messages.push(String::from_utf8_lossy(&buffer[..length]).into_owned());
            if messages.last().is_some_and(|message| message == "STATUS=ready") {
                break;
            }
        }
        assert!(messages.iter().any(|message| message.starts_with("STATUS=starting")));
        assert!(messages.contains(&"READY=1".to_string()));
        assert!(messages.contains(&"STATUS=ready".to_string()));
    }
}
