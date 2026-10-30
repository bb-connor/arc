#![allow(clippy::expect_used, clippy::unwrap_used)]

#[path = "support/trust_access.rs"]
mod trust_access;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::Duration;

use chio_test_support::loopback::{reserve_listen_addr, skip_when_loopback_bind_denied};
use reqwest::blocking::Client;
use serde_json::{json, Value};

/// Exit class of `chio` when trust-control refuses the admin credential.
const EXIT_UNAUTHORIZED: i32 = 77;
/// Exit class of `chio` when no trust-control endpoint answers.
const EXIT_UNREACHABLE: i32 = 69;
const TOKEN: &str = "emergency-control-token";

struct ServerGuard {
    child: Child,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("workspace root")
        .to_path_buf()
}

fn db(dir: &Path, name: &str) -> String {
    dir.join(name).to_str().expect("db path").to_string()
}

fn spawn_trust_service(dir: &Path, listen: std::net::SocketAddr) -> ServerGuard {
    let child = Command::new(env!("CARGO_BIN_EXE_chio"))
        .current_dir(workspace_root())
        .args([
            "--receipt-db",
            &db(dir, "receipts.sqlite3"),
            "--authority-db",
            &db(dir, "authority.sqlite3"),
            "--session-db",
            &db(dir, "joint-authority.sqlite3"),
            "trust",
            "serve",
            "--listen",
            &listen.to_string(),
            "--access-config",
            &trust_access::write_access_config(TOKEN, &[]),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn trust service");
    ServerGuard { child }
}

/// The stderr of a trust service that has exited or been killed.
fn exited_stderr(service: &mut ServerGuard) -> String {
    let _ = service.child.wait();
    let mut stderr = String::new();
    if let Some(pipe) = service.child.stderr.as_mut() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    stderr
}

fn wait_for_trust_service(base_url: &str, service: &mut ServerGuard) {
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("build reqwest client");
    for _ in 0..300 {
        if let Some(status) = service.child.try_wait().expect("poll trust service") {
            let stderr = exited_stderr(service);
            panic!(
                "trust service exited before becoming ready (status {status})\nstderr:\n{stderr}"
            );
        }
        match client.get(format!("{base_url}/health")).send() {
            Ok(response) if response.status() == reqwest::StatusCode::OK => return,
            Ok(_) | Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    let _ = service.child.kill();
    let stderr = exited_stderr(service);
    panic!("trust service did not become ready\nstderr:\n{stderr}");
}

/// Run `chio trust emergency ...` with the admin token in `CHIO_CONTROL_TOKEN`.
fn emergency(control_url: &str, token: Option<&str>, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_chio"));
    command
        .args(["--json", "--control-url", control_url, "trust", "emergency"])
        .args(args)
        .env_remove("CHIO_CONTROL_TOKEN")
        .stdin(Stdio::null());
    if let Some(token) = token {
        command.env("CHIO_CONTROL_TOKEN", token);
    }
    command.output().expect("run chio trust emergency")
}

fn stdout_json(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "chio trust emergency failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("chio trust emergency json")
}

/// A wrong token exits with the unauthorized class and leaves the node
/// running; stop, status and resume at the reported head round-trip, and a
/// token file stands in for the environment.
#[test]
fn chio_trust_emergency_stops_reports_and_resumes() {
    if skip_when_loopback_bind_denied("chio_trust_emergency_stops_reports_and_resumes") {
        return;
    }
    let dir = chio_test_support::private_tempdir().expect("private test dir");
    let listen = reserve_listen_addr();
    let control_url = format!("http://{listen}");
    let mut service = spawn_trust_service(dir.path(), listen);
    wait_for_trust_service(&control_url, &mut service);

    let refused = emergency(
        &control_url,
        Some("wrong-token"),
        &["stop", "--reason", "drill"],
    );
    assert_eq!(
        refused.status.code(),
        Some(EXIT_UNAUTHORIZED),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    let running = stdout_json(&emergency(&control_url, Some(TOKEN), &["status"]));
    assert_eq!(running["stopped"], json!(false));

    let stopped = stdout_json(&emergency(
        &control_url,
        Some(TOKEN),
        &["stop", "--reason", "drill"],
    ));
    assert_eq!(stopped["stopped"], json!(true));
    assert_eq!(stopped["durability"], json!("durable"));

    let token_file = dir.path().join("admin-token");
    std::fs::write(&token_file, format!("{TOKEN}\n")).expect("write token file");
    let status = stdout_json(&emergency(
        &control_url,
        None,
        &[
            "--token-file",
            token_file.to_str().expect("token file path"),
            "status",
        ],
    ));
    assert_eq!(status["stopped"], json!(true));
    assert_eq!(status["readiness"]["state"], json!("ready_stopped"));
    let generation = status["head"]["chain_generation"].to_string();
    let epoch = status["head"]["epoch"].to_string();

    let resumed = stdout_json(&emergency(
        &control_url,
        Some(TOKEN),
        &[
            "resume",
            "--expected-generation",
            &generation,
            "--expected-epoch",
            &epoch,
        ],
    ));
    assert_eq!(resumed["stopped"], json!(false));
}

/// No reachable endpoint exits with the unreachable class; a token on the
/// command line is refused before any request.
#[test]
fn chio_trust_emergency_refuses_unreachable_control_and_argv_tokens() {
    if skip_when_loopback_bind_denied(
        "chio_trust_emergency_refuses_unreachable_control_and_argv_tokens",
    ) {
        return;
    }
    let closed = format!("http://{}", reserve_listen_addr());
    let unreachable = emergency(&closed, Some(TOKEN), &["status"]);
    assert_eq!(
        unreachable.status.code(),
        Some(EXIT_UNREACHABLE),
        "{}",
        String::from_utf8_lossy(&unreachable.stderr)
    );

    let argv = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args([
            "--control-url",
            &closed,
            "--control-token",
            TOKEN,
            "trust",
            "emergency",
            "status",
        ])
        .env_remove("CHIO_CONTROL_TOKEN")
        .stdin(Stdio::null())
        .output()
        .expect("run chio trust emergency status");
    assert_eq!(argv.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&argv.stderr).contains("CHIO_CONTROL_TOKEN"),
        "argv token refusal: {}",
        String::from_utf8_lossy(&argv.stderr)
    );
}
