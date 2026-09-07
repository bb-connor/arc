#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn chio() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_chio"))
}

fn conformance_fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/conformance/fixtures/mcp_core")
        .join(name)
        .canonicalize()
        .expect("canonical conformance fixture path")
}

/// The interpreter behind `python3`, asked of the interpreter itself so a
/// version-manager shim on PATH does not stand in for it.
fn python3() -> PathBuf {
    let output = Command::new("python3")
        .args(["-c", "import sys; print(sys.executable)"])
        .output()
        .expect("run python3");
    assert!(
        output.status.success(),
        "python3 is not a working interpreter"
    );
    PathBuf::from(String::from_utf8_lossy(&output.stdout).trim())
        .canonicalize()
        .expect("canonical python3 path")
}

struct Provision {
    directory: PathBuf,
    manifest_public_key: String,
    cage_policy_signer: String,
}

fn provision(root: &Path) -> Provision {
    let directory = root.join("security");
    let output = Command::new(chio())
        .args(["security", "provision-native-mcp-demo", "--output-dir"])
        .arg(&directory)
        .arg("--discover-tools")
        .arg("--target")
        .arg(python3())
        .arg("--target-arg")
        .arg(conformance_fixture("mock_mcp_server.py"))
        .args([
            "--execution-uid",
            "10001",
            "--execution-gid",
            "10001",
            "--server-id",
            "conformance-mcp-core",
            "--server-name",
            "Conformance Fixture",
            "--server-version",
            "0.1.0",
        ])
        .output()
        .expect("run the provisioner");
    assert!(
        output.status.success(),
        "provisioner failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let read = |name: &str| {
        std::fs::read_to_string(directory.join(name))
            .expect("read provisioned key")
            .trim()
            .to_string()
    };
    Provision {
        manifest_public_key: read("manifest-public-key"),
        cage_policy_signer: read("cage-policy-signer"),
        directory,
    }
}

fn preflight(root: &Path, provision: &Provision, extra: &[&str], script: &Path) -> Output {
    let mut command = Command::new(chio());
    command
        .env_remove("CHIO_AUTH_TOKEN")
        .env_remove("CHIO_ADMIN_TOKEN")
        .env_remove("CHIO_CONTROL_TOKEN")
        .env_remove("CHIO_REMOTE_AUTHORITY_WORKLOAD_TOKEN")
        .arg("--receipt-db")
        .arg(root.join("receipts.sqlite3"))
        .args(["security", "preflight", "--json"])
        .args(extra)
        .arg("--signed-manifest")
        .arg(provision.directory.join("signed-manifest.json"))
        .args(["--manifest-public-key", &provision.manifest_public_key])
        .arg("--cage-policy")
        .arg(provision.directory.join("cage-launch-policy.json"))
        .args(["--cage-policy-signer", &provision.cage_policy_signer])
        .args(["--server-id", "conformance-mcp-core", "--"])
        .arg(python3())
        .arg(script);
    command.output().expect("run the preflight")
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

fn context<'a>(entry: &'a serde_json::Value, key: &str) -> &'a str {
    entry["context"]
        .as_array()
        .expect("context array")
        .iter()
        .find(|item| item["key"] == key)
        .and_then(|item| item["value"].as_str())
        .unwrap_or_else(|| panic!("no context {key} in {entry}"))
}

#[test]
fn a_provisioned_demo_launch_passes_without_enforcement_and_fails_with_it() {
    let temporary = tempfile::tempdir().expect("create test directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical test directory");
    let provision = provision(&root);
    let script = conformance_fixture("mock_mcp_server.py");

    let advisory = preflight(&root, &provision, &[], &script);
    let envelope = report(&advisory);
    assert_eq!(envelope["schema"], "chio.doctor.v1");
    assert_eq!(
        envelope["exit_code"], 0,
        "advisory preflight must exit zero: {envelope}"
    );
    assert!(advisory.status.success());
    let launch = probe(&envelope, "security.native_launch");
    assert_eq!(launch["severity"], "warning", "{launch}");
    assert_eq!(context(launch, "launch"), "legacy_authorized");
    assert_eq!(context(launch, "server_id"), "conformance-mcp-core");
    assert_eq!(
        probe(&envelope, "security.bearer_roles")["severity"],
        "info"
    );
    let stores = probe(&envelope, "security.durable_stores");
    assert_eq!(stores["severity"], "info", "{stores}");
    let platform = probe(&envelope, "security.platform");
    assert!(
        platform["severity"] == "ok" || platform["severity"] == "warning",
        "{platform}"
    );

    let enforced = preflight(&root, &provision, &["--require-enforcement"], &script);
    let envelope = report(&enforced);
    assert_eq!(envelope["exit_code"], 1, "{envelope}");
    assert_eq!(enforced.status.code(), Some(1));
    let launch = probe(&envelope, "security.native_launch");
    assert_eq!(launch["severity"], "error", "{launch}");
    assert!(launch["message"]
        .as_str()
        .expect("launch message")
        .contains("migration stage Disabled"));
}

#[test]
fn an_unbound_wrapped_command_is_refused_before_the_launch() {
    let temporary = tempfile::tempdir().expect("create test directory");
    let root = temporary
        .path()
        .canonicalize()
        .expect("canonical test directory");
    let provision = provision(&root);
    let other_script = root.join("other-server.py");
    std::fs::copy(conformance_fixture("mock_mcp_server.py"), &other_script)
        .expect("copy the mock server");

    let refused = preflight(&root, &provision, &[], &other_script);
    let envelope = report(&refused);
    assert_eq!(refused.status.code(), Some(1));
    let launch = probe(&envelope, "security.native_launch");
    assert_eq!(launch["severity"], "error", "{launch}");
    assert!(launch["message"]
        .as_str()
        .expect("launch message")
        .contains("would refuse this launch"));
    assert_eq!(context(launch, "launch"), "refused");
}

#[test]
fn reused_bearer_roles_fail_the_preflight() {
    let temporary = tempfile::tempdir().expect("create test directory");
    let output = Command::new(chio())
        .env("CHIO_AUTH_TOKEN", "shared-secret")
        .env("CHIO_ADMIN_TOKEN", "shared-secret")
        .env("CHIO_CONTROL_TOKEN", "control-secret")
        .env_remove("CHIO_REMOTE_AUTHORITY_WORKLOAD_TOKEN")
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
