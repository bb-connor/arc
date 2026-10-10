mod runner_death;

use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::mpsc;
use std::time::Instant;

use tokio::sync::Semaphore;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn task_present(tid: libc::pid_t) -> bool {
    Path::new(&format!("/proc/self/task/{tid}")).exists()
}

/// Linux removes an exited thread's task entry only after exit_notify, which
/// is where it sends the parent-death signal of every child that thread forked.
async fn thread_released(tid: libc::pid_t) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while task_present(tid) {
        if Instant::now() >= deadline {
            return Err(format!(
                "precondition: launching thread {tid} was never released"
            ));
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    Ok(())
}

/// A worker that exits 0 once `marker` exists and never exits on its own
/// before that.
fn awaiting(marker: &Path) -> Command {
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", r#"until [ -e "$0" ]; do sleep 0.01; done"#])
        .arg(marker);
    command
}

#[tokio::test]
async fn supervised_worker_outlives_the_thread_that_launched_it() -> TestResult {
    let root = tempfile::tempdir()?;
    let marker = root.path().join("launching-thread-released");
    let command = awaiting(&marker);
    let (launched, receive_launch) = mpsc::channel();
    let (release, released) = mpsc::channel::<()>();
    // Stands in for a runtime worker that forks a child, gives its core away
    // and retires while the child is still supervised.
    let launcher = std::thread::spawn(move || {
        // SAFETY: gettid takes no arguments and returns the calling thread's id.
        let tid = unsafe { libc::gettid() };
        let present = task_present(tid);
        let _ = launched.send((tid, present, spawn_command(command, None)));
        let _ = released.recv();
    });
    let (tid, present, spawned) = receive_launch.recv_timeout(Duration::from_secs(10))?;
    assert!(
        present,
        "precondition: launching thread {tid} was not visible"
    );
    let mut supervision = Box::pin(wait(spawned?, Vec::new(), Duration::from_secs(30), None));
    tokio::select! {
        biased;
        _ = &mut supervision => {
            return Err("precondition: worker ended before its launching thread exited".into());
        }
        () = std::future::ready(()) => {}
    }
    release.send(())?;
    launcher.join().map_err(|_| "launching thread panicked")?;
    thread_released(tid).await?;
    std::fs::write(&marker, b"")?;
    let outcome = supervision.await?;
    assert_eq!(
        (outcome.reason.as_str(), outcome.success),
        ("exit_0", true),
        "supervised worker did not survive release of launching thread {tid}"
    );
    Ok(())
}

fn sleeper() -> Command {
    let mut command = Command::new("/usr/bin/sleep");
    command.arg("30");
    command
}

fn launched(capacity: &'static Semaphore, command: Command) -> io::Result<Spawned> {
    owner::launch(capacity, move || start(command, None))?
        .recv()
        .map_err(io::Error::other)?
}

/// A second descriptor naming exactly the worker, for checks after its reap.
fn worker_descriptor(spawned: &Spawned) -> io::Result<OwnedFd> {
    spawned.guard.process.0.try_clone()
}

/// Whether nothing remains to wait for: the worker was reaped. WNOWAIT leaves
/// an unreaped worker to its owner thread.
fn reaped(worker: &OwnedFd) -> io::Result<bool> {
    let id = libc::id_t::try_from(worker.as_raw_fd()).map_err(io::Error::other)?;
    // SAFETY: siginfo_t is plain data that waitid fills in.
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: waitid writes only the siginfo passed to it and never blocks
    // with WNOHANG.
    let result = unsafe {
        libc::waitid(
            libc::P_PIDFD,
            id,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result == 0 {
        return Ok(false);
    }
    let failure = io::Error::last_os_error();
    if failure.raw_os_error() == Some(libc::ECHILD) {
        return Ok(true);
    }
    Err(failure)
}

/// Every permit returns only after each owner thread has reaped its worker
/// and returned.
async fn owners_returned(capacity: &'static Semaphore, permits: usize) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while capacity.available_permits() != permits {
        if Instant::now() >= deadline {
            return Err("an owner thread kept its capacity".to_owned());
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    Ok(())
}

async fn published(observation: &Observation) -> Result<Outcome, String> {
    tokio::time::timeout(Duration::from_secs(5), observation.settled())
        .await
        .map_err(|_| "owner thread never published the worker's end".to_owned())?;
    observation
        .outcome()
        .ok_or_else(|| "owner thread failed to reap the worker".to_owned())
}

#[tokio::test]
async fn normal_exit_is_reaped_once_by_its_owner() -> TestResult {
    static CAPACITY: Semaphore = Semaphore::const_new(1);
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "exit 7"]);
    let spawned = launched(&CAPACITY, command)?;
    let worker = worker_descriptor(&spawned)?;
    assert_eq!(CAPACITY.available_permits(), 0);
    let outcome = wait(spawned, Vec::new(), Duration::from_secs(10), None).await?;
    assert_eq!(
        (outcome.reason.as_str(), outcome.success),
        ("exit_7", false)
    );
    owners_returned(&CAPACITY, 1).await?;
    assert!(
        reaped(&worker)?,
        "a reaped worker left something to wait for"
    );
    Ok(())
}

#[tokio::test]
async fn cancelled_observation_kills_and_reaps_its_worker() -> TestResult {
    static CAPACITY: Semaphore = Semaphore::const_new(1);
    let spawned = launched(&CAPACITY, sleeper())?;
    let worker = worker_descriptor(&spawned)?;
    let observation = spawned.observation();
    let mut observing = Box::pin(wait(spawned, Vec::new(), Duration::from_secs(30), None));
    // One poll arms the owner thread; dropping the future then cancels it.
    tokio::select! {
        biased;
        _ = &mut observing => return Err("observation ended before cancellation".into()),
        () = std::future::ready(()) => {}
    }
    assert!(
        !reaped(&worker)?,
        "precondition: worker ended before cancellation"
    );
    drop(observing);
    let outcome = published(&observation).await?;
    assert_eq!(
        (outcome.reason.as_str(), outcome.success),
        ("runner_interrupted", false)
    );
    owners_returned(&CAPACITY, 1).await?;
    assert!(reaped(&worker)?, "cancelled worker left unreaped");
    Ok(())
}

#[tokio::test]
async fn abandoned_launch_is_killed_and_reaped() -> TestResult {
    static CAPACITY: Semaphore = Semaphore::const_new(1);
    let spawned = launched(&CAPACITY, sleeper())?;
    let worker = worker_descriptor(&spawned)?;
    let observation = spawned.observation();
    assert!(
        !reaped(&worker)?,
        "precondition: worker ended before abandonment"
    );
    drop(spawned);
    let outcome = published(&observation).await?;
    assert_eq!(
        (outcome.reason.as_str(), outcome.success),
        ("runner_interrupted", false)
    );
    owners_returned(&CAPACITY, 1).await?;
    assert!(reaped(&worker)?, "abandoned worker left unreaped");
    Ok(())
}

#[tokio::test]
async fn unpolled_observation_kills_and_reaps_its_worker() -> TestResult {
    static CAPACITY: Semaphore = Semaphore::const_new(1);
    let spawned = launched(&CAPACITY, sleeper())?;
    let worker = worker_descriptor(&spawned)?;
    let observation = spawned.observation();
    // Dropping the future before its first poll must still close supervision.
    let observing = wait(spawned, Vec::new(), Duration::from_secs(30), None);
    drop(observing);
    let outcome = published(&observation).await?;
    assert_eq!(
        (outcome.reason.as_str(), outcome.success),
        ("runner_interrupted", false)
    );
    owners_returned(&CAPACITY, 1).await?;
    assert!(
        reaped(&worker)?,
        "unpolled observation left its worker unreaped"
    );
    Ok(())
}

#[tokio::test]
async fn undelivered_launch_is_killed_and_reaped_by_its_owner() -> TestResult {
    static CAPACITY: Semaphore = Semaphore::const_new(1);
    let (descriptor, receive_descriptor) = mpsc::channel();
    let (release, released) = mpsc::channel::<()>();
    let handover = owner::launch(&CAPACITY, move || {
        let started = start(sleeper(), None)?;
        let _ = descriptor.send(started.process.0.try_clone());
        // Hand over only after the caller has stopped waiting.
        let _ = released.recv();
        Ok(started)
    })?;
    let worker = receive_descriptor.recv_timeout(Duration::from_secs(10))??;
    drop(handover);
    release.send(())?;
    // The worker sleeps for 30 seconds unless its owner kills it.
    owners_returned(&CAPACITY, 1).await?;
    assert!(reaped(&worker)?, "undelivered worker left unreaped");
    Ok(())
}

#[tokio::test]
async fn failed_start_is_definite_and_returns_its_owner() -> TestResult {
    static CAPACITY: Semaphore = Semaphore::const_new(1);
    let failure = match owner::launch(&CAPACITY, || {
        start(Command::new("/nonexistent/chio-runner-worker"), None)
    })?
    .recv()?
    {
        Ok(_) => return Err("a missing executable started".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.kind(), io::ErrorKind::NotFound);
    assert!(definitely_unexecuted(&failure));
    owners_returned(&CAPACITY, 1).await?;
    Ok(())
}

#[tokio::test]
async fn owner_capacity_refuses_before_starting_and_recovers_after_reap() -> TestResult {
    static CAPACITY: Semaphore = Semaphore::const_new(1);
    let first = launched(&CAPACITY, sleeper())?;
    let refused = match owner::launch(&CAPACITY, || {
        panic!("exhausted owner capacity must refuse before starting a worker")
    }) {
        Ok(_) => return Err("exhausted owner capacity started a thread".into()),
        Err(failure) => failure,
    };
    assert_eq!(
        refused.to_string(),
        "worker did not execute: worker owner capacity exhausted"
    );
    assert!(definitely_unexecuted(&refused));
    drop(first);
    owners_returned(&CAPACITY, 1).await?;
    let next = launched(&CAPACITY, Command::new("/usr/bin/true"))?;
    let outcome = wait(next, Vec::new(), Duration::from_secs(10), None).await?;
    assert_eq!((outcome.reason.as_str(), outcome.success), ("exit_0", true));
    owners_returned(&CAPACITY, 1).await?;
    Ok(())
}
