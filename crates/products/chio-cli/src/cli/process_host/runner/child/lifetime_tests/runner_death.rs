//! Runner process death must retain the kernel's parent-death cleanup.
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::mpsc;

use super::super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const DEATH_FIXTURE: &str = "CHIO_RUNNER_DEATH_FIXTURE";
const DEATH_FIXTURE_WORKER: &str = "chio-runner-death-fixture worker ";

/// Test-only owner that also cleans up when a precondition or assertion fails.
struct FixtureProcess {
    child: Child,
    reaped: bool,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl FixtureProcess {
    fn new(child: Child) -> Self {
        Self {
            child,
            reaped: false,
            reader: None,
        }
    }

    fn kill_and_wait(&mut self) -> io::Result<ExitStatus> {
        self.child.kill()?;
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }
}

impl Drop for FixtureProcess {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn sleeper() -> Command {
    let mut command = Command::new("/usr/bin/sleep");
    command.arg("30");
    command
}

fn parent_of(pid: libc::pid_t) -> io::Result<libc::pid_t> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let fields = stat
        .rsplit_once(") ")
        .map(|(_, fields)| fields)
        .ok_or_else(|| io::Error::other("unparsable process status"))?;
    fields
        .split(' ')
        .nth(1)
        .and_then(|parent| parent.parse().ok())
        .ok_or_else(|| io::Error::other("unparsable parent process"))
}

/// Whether the descriptor's process terminates within `milliseconds`.
fn terminates(worker: &ProcessFd, milliseconds: libc::c_int) -> io::Result<bool> {
    let mut poll = libc::pollfd {
        fd: worker.0.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll names one live descriptor and has a bounded timeout.
    let ready = unsafe { libc::poll(&mut poll, 1, milliseconds) };
    if ready < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ready == 1)
}

fn death_fixture() -> TestResult {
    // The launching thread exits at once, so only the owner thread anchors
    // the worker's parent-death signal.
    let spawned = std::thread::spawn(|| spawn_command(sleeper(), None))
        .join()
        .map_err(|_| "launching thread panicked")??;
    let mut stdout = std::io::stdout();
    writeln!(stdout, "{DEATH_FIXTURE_WORKER}{}", spawned.child.id())?;
    stdout.flush()?;
    // Hold the worker until this process is killed or its parent disappears.
    std::io::stdin().read_to_end(&mut Vec::new())?;
    drop(spawned);
    Ok(())
}

#[test]
fn runner_death_still_kills_live_workers() -> TestResult {
    if std::env::var_os(DEATH_FIXTURE).is_some() {
        return death_fixture();
    }
    let name = format!("{}::runner_death_still_kills_live_workers", module_path!());
    let name = name
        .split_once("::")
        .map_or(name.as_str(), |(_, tail)| tail);
    let mut fixture = FixtureProcess::new(
        Command::new(std::env::current_exe()?)
            .args(["--exact", name, "--nocapture"])
            .env(DEATH_FIXTURE, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let output = fixture
        .child
        .stdout
        .take()
        .ok_or("missing fixture stdout")?;
    let (report, receive_report) = mpsc::channel();
    fixture.reader = Some(std::thread::spawn(move || {
        let worker = BufReader::new(output).lines().find_map(|line| {
            line.ok()?
                .strip_prefix(DEATH_FIXTURE_WORKER)?
                .parse::<libc::pid_t>()
                .ok()
        });
        let _ = report.send(worker);
    }));
    let reported = receive_report.recv_timeout(Duration::from_secs(30));
    let Ok(Some(pid)) = reported else {
        return Err("fixture never reported its worker".into());
    };
    // The worker is the fixture's live, unreaped child, so its id names it.
    let worker = ProcessFd::open(pid)?;
    let fixture_pid = libc::pid_t::try_from(fixture.child.id())?;
    assert_eq!(
        parent_of(pid)?,
        fixture_pid,
        "precondition: worker belongs to the fixture runner"
    );
    assert!(
        !terminates(&worker, 0)?,
        "precondition: worker ended before runner death"
    );
    let status = fixture.kill_and_wait()?;
    assert_eq!(status.signal(), Some(libc::SIGKILL));
    if !terminates(&worker, 10_000)? {
        let _ = worker.kill();
        return Err("runner death left its worker running".into());
    }
    Ok(())
}
