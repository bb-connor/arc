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

#[test]
fn inherited_credentials_preserve_binary_bytes_and_distinct_descriptors() {
    let directory = tempfile::tempdir().expect("credential directory");
    let master = [0_u8, 255, b'\n', b' '];
    let signing = [254_u8, 0, b'\r', 1];
    write_credential(directory.path(), "master", &master);
    write_credential(directory.path(), "signing", &signing);
    let output = supervise(directory.path())
        .args([
            "--credential-fd", "master-key-fd=master",
            "--credential-fd", "signing-key-fd=signing",
            "--", "/bin/sh", "-c",
            "test \"$1\" = --master-key-fd && test \"$3\" = --signing-key-fd && test \"$2\" != \"$4\" && cat /dev/fd/\"$2\" /dev/fd/\"$4\"",
            "service",
        ])
        .output()
        .expect("run descriptor service");
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(output.stdout, [master, signing].concat());
}

#[test]
fn unsafe_or_ambiguous_descriptor_credentials_refuse_service_start() {
    let directory = tempfile::tempdir().expect("credential directory");
    let marker = directory.path().join("started");
    write_credential(directory.path(), "private", b"private test key");
    write_credential(directory.path(), "exposed", b"exposed test key");
    std::fs::set_permissions(
        directory.path().join("exposed"),
        std::fs::Permissions::from_mode(0o644),
    )
    .expect("expose fixture");
    std::os::unix::fs::symlink("private", directory.path().join("alias")).expect("symlink");
    std::fs::hard_link(
        directory.path().join("private"),
        directory.path().join("linked"),
    )
    .expect("hard link");
    for binding in [
        "signing-key-fd=exposed",
        "signing-key-fd=alias",
        "signing-key-fd=linked",
        "signing-key-fd=../private",
    ] {
        let output = supervise(directory.path())
            .args(["--credential-fd", binding, "--", "/usr/bin/touch"])
            .arg(&marker)
            .output()
            .expect("refused descriptor launch");
        assert!(!output.status.success());
        assert!(!marker.exists(), "invalid credential started the service");
    }
    std::fs::remove_file(directory.path().join("linked")).expect("remove alias");
    for supplied in ["--signing-key-fd", "--signing-key-fd=3"] {
        let output = supervise(directory.path())
            .args([
                "--credential-fd",
                "signing-key-fd=private",
                "--",
                "/usr/bin/touch",
            ])
            .arg(&marker)
            .arg(supplied)
            .output()
            .expect("refused duplicate option");
        assert!(!output.status.success());
        assert!(stderr(&output).contains("already supplied"));
        assert!(!marker.exists());
    }
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
fn invalid_http_readiness_refuses_to_start_the_service() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let marker = directory.path().join("started");
    for url in [
        "file:///tmp/chio-readiness-invalid",
        "http://operator:secret@127.0.0.1/health",
    ] {
        let output = supervise(directory.path())
            .args(["--ready-http", url, "--", "/usr/bin/touch"])
            .arg(&marker)
            .output()?;
        assert!(!output.status.success());
        assert!(stderr(&output).contains("readiness requires an HTTP(S) URL"));
        assert!(!stderr(&output).contains("operator:secret"));
        assert!(
            !marker.exists(),
            "invalid readiness must reject before service launch"
        );
    }
    Ok(())
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
#[ignore = "subprocess entry point exercised by the supervision process test"]
fn supervised_socket_child() {
    let path = std::env::var_os("CHIO_SUPERVISE_TEST_SOCKET").expect("child socket path");
    let listener = std::os::unix::net::UnixListener::bind(path).expect("child binds socket");
    for stream in listener.incoming() {
        drop(stream.expect("readiness connection"));
    }
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
        .args(["--ready-timeout", "20", "--stop-grace", "5", "--"])
        .arg(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "supervised_socket_child",
            "--ignored",
            "--nocapture",
        ])
        .env("CHIO_SUPERVISE_TEST_SOCKET", &socket)
        .env("NOTIFY_SOCKET", &notify)
        .spawn()
        .expect("spawn supervisor");
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
fn a_stop_signal_interrupts_a_stalled_readiness_probe() {
    let directory = tempfile::tempdir().expect("tempdir");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("health listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let address = listener.local_addr().expect("health address");
    let mut supervisor = supervise(directory.path())
        .args([
            "--ready-http",
            &format!("http://{address}/health"),
            "--ready-timeout",
            "30",
            "--stop-grace",
            "1",
            "--",
            "/bin/sh",
            "-c",
            "exec sleep 60",
        ])
        .spawn()
        .expect("spawn supervisor");
    let connected = Instant::now();
    let _stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    connected.elapsed() < Duration::from_secs(5),
                    "probe never connected"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("health accept: {error}"),
        }
    };
    terminate(&supervisor);
    let status = wait_with_deadline(&mut supervisor, Duration::from_secs(1));
    assert_eq!(status.signal(), Some(libc::SIGTERM));
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
