//! `chio security supervise` end to end: credentials reach the service and
//! nothing else does, readiness is reported once the service answers, stop
//! signals are forwarded with a bounded grace, and the supervisor ends the
//! way its service did.

#![allow(clippy::expect_used, clippy::unwrap_used)]
#![cfg(unix)]

use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixDatagram;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn chio() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_chio"))
}

fn write_credential(directory: &Path, name: &str, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(name))
        .expect("create credential");
    std::io::Write::write_all(&mut file, bytes).expect("write credential");
}

fn supervise(directory: &Path) -> Command {
    let mut command = Command::new(chio());
    command
        .args(["security", "supervise", "--credentials-dir"])
        .arg(directory)
        .env_remove("CHIO_AUTH_TOKEN")
        .env_remove("NOTIFY_SOCKET")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn wait_with_deadline(child: &mut Child, deadline: Duration) -> std::process::ExitStatus {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().expect("poll supervisor") {
            return status;
        }
        assert!(
            started.elapsed() < deadline,
            "the supervisor did not exit within {deadline:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn terminate(child: &Child) {
    let status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(status.success());
}

fn notify_messages(manager: &UnixDatagram, until: &str, deadline: Duration) -> Vec<String> {
    manager
        .set_read_timeout(Some(deadline))
        .expect("notify read timeout");
    let mut messages = Vec::new();
    let mut buffer = [0_u8; 512];
    loop {
        let length = manager
            .recv(&mut buffer)
            .unwrap_or_else(|error| panic!("waiting for {until}: {error}; seen {messages:?}"));
        let message = String::from_utf8_lossy(&buffer[..length]).into_owned();
        let done = message == until;
        messages.push(message);
        if done {
            return messages;
        }
    }
}

#[test]
fn exec_delivers_the_credential_and_only_the_credential() {
    let directory = tempfile::tempdir().expect("tempdir");
    write_credential(directory.path(), "session-token", b"s3cret-session\n");
    let output = supervise(directory.path())
        .args([
            "--credential-env",
            "CHIO_AUTH_TOKEN=session-token",
            "--exec",
            "--",
            "/bin/sh",
            "-c",
        ])
        .arg("printf '%s|%s' \"$CHIO_AUTH_TOKEN\" \"${CHIO_ADMIN_TOKEN-unset}\"")
        .env_remove("CHIO_ADMIN_TOKEN")
        .output()
        .expect("run supervise --exec");
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "s3cret-session|unset"
    );
}

#[test]
fn a_padded_credential_or_a_shadowed_variable_refuses_the_launch() {
    let directory = tempfile::tempdir().expect("tempdir");
    write_credential(directory.path(), "padded", b"token \n");
    write_credential(directory.path(), "clean", b"token");
    let padded = supervise(directory.path())
        .args([
            "--credential-env",
            "CHIO_AUTH_TOKEN=padded",
            "--exec",
            "--",
            "/bin/true",
        ])
        .output()
        .expect("run supervise");
    assert!(!padded.status.success());
    assert!(stderr(&padded).contains("padding"), "{}", stderr(&padded));

    let shadowed = supervise(directory.path())
        .args([
            "--credential-env",
            "CHIO_AUTH_TOKEN=clean",
            "--exec",
            "--",
            "/bin/true",
        ])
        .env("CHIO_AUTH_TOKEN", "already-set")
        .output()
        .expect("run supervise");
    assert!(!shadowed.status.success());
    assert!(
        stderr(&shadowed).contains("already set"),
        "{}",
        stderr(&shadowed)
    );

    let exposed_path = directory.path().join("exposed");
    std::fs::write(&exposed_path, b"token").expect("write exposed");
    std::fs::set_permissions(&exposed_path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
    let exposed = supervise(directory.path())
        .args([
            "--credential-env",
            "CHIO_AUTH_TOKEN=exposed",
            "--exec",
            "--",
            "/bin/true",
        ])
        .output()
        .expect("run supervise");
    assert!(!exposed.status.success());
    assert!(
        stderr(&exposed).contains("readable by its group"),
        "{}",
        stderr(&exposed)
    );
}

#[test]
fn the_service_exit_code_is_the_supervisor_exit_code() {
    let directory = tempfile::tempdir().expect("tempdir");
    let output = supervise(directory.path())
        .args(["--", "/bin/sh", "-c", "exit 5"])
        .output()
        .expect("run supervise");
    assert_eq!(output.status.code(), Some(5));
}

#[test]
fn readiness_reaches_the_manager_and_a_stop_signal_reaches_the_service() {
    let directory = tempfile::tempdir().expect("tempdir");
    let socket = directory.path().join("service.sock");
    let notify = directory.path().join("notify.sock");
    let manager = UnixDatagram::bind(&notify).expect("bind notify socket");
    let mut supervisor = supervise(directory.path())
        .args(["--ready-unix-socket"])
        .arg(&socket)
        .args([
            "--ready-timeout",
            "20",
            "--stop-grace",
            "5",
            "--",
            "/bin/sh",
            "-c",
            "exec sleep 60",
        ])
        .env("NOTIFY_SOCKET", &notify)
        .spawn()
        .expect("spawn supervisor");
    std::thread::sleep(Duration::from_millis(600));
    let _listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind service socket");
    let messages = notify_messages(&manager, "STATUS=ready", Duration::from_secs(20));
    assert!(
        messages
            .iter()
            .any(|message| message.starts_with("STATUS=starting")),
        "{messages:?}"
    );
    assert!(messages.contains(&"READY=1".to_string()), "{messages:?}");
    assert!(
        supervisor.try_wait().expect("poll").is_none(),
        "the supervisor must keep running while the service runs"
    );
    terminate(&supervisor);
    let stopping = notify_messages(&manager, "STOPPING=1", Duration::from_secs(10));
    assert_eq!(stopping.last().map(String::as_str), Some("STOPPING=1"));
    let status = wait_with_deadline(&mut supervisor, Duration::from_secs(15));
    assert_eq!(
        status.signal(),
        Some(libc::SIGTERM),
        "the supervisor ends by the signal that ended its service: {status:?}"
    );
}

#[test]
fn a_service_that_ignores_the_stop_signal_is_killed_after_the_grace() {
    let directory = tempfile::tempdir().expect("tempdir");
    let mut supervisor = supervise(directory.path())
        .args([
            "--stop-grace",
            "1",
            "--",
            "/bin/sh",
            "-c",
            "trap '' TERM; sleep 60 & wait",
        ])
        .spawn()
        .expect("spawn supervisor");
    std::thread::sleep(Duration::from_millis(500));
    let started = Instant::now();
    terminate(&supervisor);
    let status = wait_with_deadline(&mut supervisor, Duration::from_secs(15));
    assert_eq!(status.signal(), Some(libc::SIGKILL), "{status:?}");
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn a_service_that_never_becomes_ready_is_stopped_and_the_unit_fails() {
    let directory = tempfile::tempdir().expect("tempdir");
    let started = Instant::now();
    let output = supervise(directory.path())
        .args(["--ready-unix-socket"])
        .arg(directory.path().join("never.sock"))
        .args([
            "--ready-timeout",
            "1",
            "--stop-grace",
            "2",
            "--",
            "/bin/sh",
            "-c",
            "exec sleep 60",
        ])
        .output()
        .expect("run supervise");
    assert_eq!(output.status.code(), Some(1), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("did not become ready"),
        "{}",
        stderr(&output)
    );
    assert!(started.elapsed() < Duration::from_secs(15));
}
