#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::process::{Command, Output};

fn chio() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_chio"))
}

fn report(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "preflight did not emit the doctor envelope: {error}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn probe<'a>(envelope: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    envelope["reports"]
        .as_array()
        .expect("reports array")
        .iter()
        .find(|entry| entry["probe"] == name)
        .unwrap_or_else(|| panic!("no probe {name} in {envelope}"))
}

#[test]
fn reused_bearer_roles_fail_the_preflight() {
    let temporary = tempfile::tempdir().expect("create test directory");
    let output = Command::new(chio())
        .env("CHIO_AUTH_TOKEN", "shared-secret")
        .env("CHIO_ADMIN_TOKEN", "shared-secret")
        .env("CHIO_CONTROL_TOKEN", "control-secret")
        .arg("--receipt-db")
        .arg(temporary.path().join("receipts.sqlite3"))
        .args(["security", "preflight", "--json"])
        .output()
        .expect("run the preflight");
    let envelope = report(&output);
    assert_eq!(output.status.code(), Some(1));
    let roles = probe(&envelope, "security.bearer_roles");
    assert_eq!(roles["severity"], "error", "{roles}");
    assert!(roles["message"]
        .as_str()
        .expect("roles message")
        .contains("session and admin"));
    assert_eq!(
        probe(&envelope, "security.native_launch")["severity"],
        "info"
    );
}
