use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chio_test_support::prelude::*;

use super::*;
use crate::native_mcp::refused;

struct Probe(Mutex<Child>);

impl Probe {
    #[allow(
        unsafe_code,
        reason = "Test child must arm the actual Linux parent-death signal before exec."
    )]
    fn spawn() -> Result<Self, KernelError> {
        let mut command = Command::new("/bin/cat");
        command.stdin(Stdio::piped()).stdout(Stdio::piped());
        let arm_custody = || {
            // SAFETY: prctl uses only scalar arguments here. SIGKILL models
            // the cage's thread-bound parent custody in the test child.
            if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        };
        // SAFETY: only the async-signal-safe prctl syscall and errno access
        // run between fork and exec; the closure allocates and locks nothing.
        unsafe { command.pre_exec(arm_custody) };
        let probe = Self(Mutex::new(command.spawn().map_err(|_| refused())?));
        probe.echo()?;
        Ok(probe)
    }

    #[allow(
        unsafe_code,
        reason = "Test pipe readiness must have a finite kernel-enforced timeout."
    )]
    fn echo(&self) -> Result<(), KernelError> {
        let mut child = self.0.lock().map_err(|_| refused())?;
        child
            .stdin
            .as_mut()
            .ok_or_else(refused)?
            .write_all(b"p")
            .map_err(|_| refused())?;
        let stdout = child.stdout.as_mut().ok_or_else(refused)?;
        let mut poll = libc::pollfd {
            fd: stdout.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll names one live descriptor and has a bounded timeout.
        if unsafe { libc::poll(&mut poll, 1, 2_000) } != 1 {
            return Err(refused());
        }
        let mut output = [0];
        stdout.read_exact(&mut output).map_err(|_| refused())?;
        if output != *b"p" {
            return Err(refused());
        }
        Ok(())
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        let child = self.0.get_mut().test_unwrap();
        let _ = child.kill();
        child.wait().test_unwrap();
    }
}

#[test]
fn prepared_child_survives_retirement_of_the_callers_async_runtime() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .thread_keep_alive(Duration::from_millis(10))
        .build()
        .test_unwrap();
    let owner = runtime
        .block_on(LaunchOwner::prepare(Probe::spawn))
        .test_unwrap();
    owner.echo().test_unwrap();
    // All of this runtime's workers have now exited. The child's independent
    // launch owner must still be present, with parent-death protection armed.
    drop(runtime);
    owner
        .echo()
        .test_expect("a live owner must retain its child's creating thread");
    let pid = owner.0.lock().test_unwrap().id();
    drop(owner);
    assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
}

fn wait_for_reaped(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while std::path::Path::new(&format!("/proc/{pid}")).exists() {
        assert!(
            Instant::now() < deadline,
            "launch owner left a child unreaped"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn cancellation_during_preparation_reaps_the_child_on_its_live_launch_thread() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .test_unwrap();
    let (created, receive_pid) = mpsc::channel();
    let (resume, paused) = mpsc::channel();
    let preparation = runtime.spawn(LaunchOwner::prepare(move || {
        let probe = Probe::spawn()?;
        created
            .send(probe.0.lock().test_unwrap().id())
            .test_unwrap();
        paused.recv_timeout(Duration::from_secs(5)).test_unwrap();
        probe.echo()?;
        Ok(probe)
    }));
    runtime.block_on(tokio::task::yield_now());
    let pid = receive_pid
        .recv_timeout(Duration::from_secs(5))
        .test_unwrap();
    preparation.abort();
    assert!(runtime
        .block_on(preparation)
        .is_err_and(|error| error.is_cancelled()));
    drop(runtime);
    resume.send(()).test_unwrap();
    wait_for_reaped(pid);
}

#[test]
fn preparation_failure_reaps_the_child_before_releasing_its_launch_thread() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .test_unwrap();
    let (created, receive_pid) = mpsc::channel();
    let result = runtime.block_on(LaunchOwner::<Probe>::prepare(move || {
        let probe = Probe::spawn()?;
        created
            .send(probe.0.lock().test_unwrap().id())
            .test_unwrap();
        Err(refused_at("injected post-launch failure"))
    }));
    assert!(
        matches!(result, Err(KernelError::ToolServerError(message)) if message.contains("injected post-launch failure"))
    );
    wait_for_reaped(
        receive_pid
            .recv_timeout(Duration::from_secs(5))
            .test_unwrap(),
    );
}

#[test]
fn capacity_remains_reserved_until_prepared_ownership_ends() {
    static CAPACITY: Semaphore = Semaphore::const_new(1);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .test_unwrap();
    let owner = runtime
        .block_on(LaunchOwner::prepare_with_capacity(&CAPACITY, Probe::spawn))
        .test_unwrap();
    let result = runtime.block_on(LaunchOwner::<Probe>::prepare_with_capacity(
        &CAPACITY,
        || panic!("exhausted launch capacity must refuse before preparing a child"),
    ));
    assert!(
        matches!(result, Err(KernelError::ToolServerError(message)) if message.contains("launch thread capacity"))
    );
    owner.echo().test_unwrap();
    drop(owner);
    let deadline = Instant::now() + Duration::from_secs(5);
    while CAPACITY.available_permits() == 0 {
        assert!(
            Instant::now() < deadline,
            "ended owner leaked launch capacity"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let next = runtime
        .block_on(LaunchOwner::prepare_with_capacity(&CAPACITY, Probe::spawn))
        .test_unwrap();
    next.echo().test_unwrap();
}
