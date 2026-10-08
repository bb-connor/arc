use std::sync::mpsc;
use std::time::Instant;

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
    assert!(present, "precondition: launching thread {tid} was not visible");
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
