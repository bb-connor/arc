#![allow(clippy::expect_used, clippy::unwrap_used)]
#![cfg(unix)]

use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::process::{Command, Output};

struct Fixture {
    root: tempfile::TempDir,
    client: PathBuf,
    original: Value,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let client = root.path().join("client.json");
        let original = json!({
            "preferences": {"theme": "dark"},
            "mcpServers": {
                "alpha": {"command": "never-start-this-tool", "args": ["private-argument"], "env": {"TOKEN": "private-credential"}},
                "beta": {"command": "never-start-this-tool", "args": ["beta"]},
                "remote": {"url": "https://example.invalid/mcp"}
            }
        });
        fs::write(&client, serde_json::to_vec_pretty(&original).unwrap()).unwrap();
        let policy = root.path().join("policy.yaml");
        fs::write(&policy, "kernel:\n  durable_admission_mode: all\ncapabilities:\n  default:\n    tools:\n      - server: alpha\n        tool: append_note\n").unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_chio"))
            .args(["mcp", "adopt", "--config"])
            .arg(&client)
            .arg("--policy")
            .arg(&policy)
            .arg("--output")
            .arg(root.path().join("adopted"))
            .args(["--server", "alpha", "--server", "beta"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        Self {
            root,
            client,
            original,
        }
    }

    fn run(&self, operation: &str, extra: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_chio"))
            .args(["--format", "json", "mcp", operation, "--adoption"])
            .arg(self.root.path().join("adopted"))
            .arg("--config")
            .arg(&self.client)
            .args(extra)
            .output()
            .unwrap()
    }

    fn success(&self, operation: &str, extra: &[&str]) -> Value {
        let output = self.run(operation, extra);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        for bytes in [&output.stdout, &output.stderr] {
            let text = String::from_utf8_lossy(bytes);
            assert!(!text.contains("private-credential"));
            assert!(!text.contains("private-argument"));
        }
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn read(&self) -> Value {
        serde_json::from_slice(&fs::read(&self.client).unwrap()).unwrap()
    }
    fn write(&self, value: &Value) {
        fs::write(&self.client, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    }
}

#[test]
fn activation_and_restore_preserve_other_servers_and_later_client_settings() {
    let fixture = Fixture::new();
    let backup = fixture.root.path().join("adopted/original.json");
    let backup_bytes = fs::read(&backup).unwrap();
    let mut current = fixture.read();
    current["preferences"]["theme"] = json!("light");
    current["mcpServers"]["remote"]["url"] = json!("https://changed.example.invalid/mcp");
    current["mcpServers"]["added"] = json!({"command":"another-tool"});
    fixture.write(&current);
    let report = fixture.success("activate", &[]);
    assert_eq!(report["servers_changed"], json!(["alpha", "beta"]));
    assert_eq!(report["configuration_changed"], true);
    assert_eq!(report["client_restart_required"], true);
    let generated: Value =
        serde_json::from_slice(&fs::read(fixture.root.path().join("adopted/mcp.json")).unwrap())
            .unwrap();
    let activated = fixture.read();
    assert_eq!(
        activated["mcpServers"]["alpha"],
        generated["mcpServers"]["alpha"]
    );
    assert_eq!(activated["preferences"], current["preferences"]);
    assert_eq!(
        activated["mcpServers"]["added"],
        current["mcpServers"]["added"]
    );
    assert_eq!(
        activated["mcpServers"]["remote"],
        current["mcpServers"]["remote"]
    );
    assert_eq!(
        fs::metadata(&fixture.client).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let mut latest = activated;
    latest["newSetting"] = json!("keep this after restore");
    fixture.write(&latest);
    fixture.success("restore", &[]);
    let restored = fixture.read();
    assert_eq!(
        restored["mcpServers"]["alpha"],
        fixture.original["mcpServers"]["alpha"]
    );
    assert_eq!(
        restored["mcpServers"]["beta"],
        fixture.original["mcpServers"]["beta"]
    );
    assert_eq!(restored["preferences"], current["preferences"]);
    assert_eq!(
        restored["mcpServers"]["remote"],
        current["mcpServers"]["remote"]
    );
    assert_eq!(
        restored["mcpServers"]["added"],
        current["mcpServers"]["added"]
    );
    assert_eq!(restored["newSetting"], latest["newSetting"]);
    assert_eq!(fs::read(&backup).unwrap(), backup_bytes);
    for state in fs::read_dir(fixture.root.path().join("adopted/state")).unwrap() {
        assert_eq!(
            fs::read_dir(state.unwrap().path()).unwrap().count(),
            0,
            "commands must not launch tools"
        );
    }
}

#[test]
fn dry_runs_and_repeat_invocations_do_not_rewrite_the_client_file() {
    let fixture = Fixture::new();
    for operation in ["activate", "restore"] {
        let before = fs::read(&fixture.client).unwrap();
        let inode = fs::metadata(&fixture.client).unwrap().ino();
        let preview = fixture.success(operation, &["--dry-run"]);
        assert_eq!(preview["configuration_changed"], false);
        assert_eq!(preview["client_restart_required"], false);
        assert_eq!(preview["servers_changed"], json!(["alpha", "beta"]));
        assert_eq!(fs::read(&fixture.client).unwrap(), before);
        assert_eq!(fs::metadata(&fixture.client).unwrap().ino(), inode);
        fixture.success(operation, &[]);
        let before = fs::read(&fixture.client).unwrap();
        let inode = fs::metadata(&fixture.client).unwrap().ino();
        let repeated = fixture.success(operation, &[]);
        assert_eq!(repeated["configuration_changed"], false);
        assert_eq!(
            repeated["servers_already_configured"],
            json!(["alpha", "beta"])
        );
        assert_eq!(fs::read(&fixture.client).unwrap(), before);
        assert_eq!(fs::metadata(&fixture.client).unwrap().ino(), inode);
    }
}

#[test]
fn any_selected_conflict_aborts_the_entire_activation_or_restore() {
    for operation in ["activate", "restore"] {
        let fixture = Fixture::new();
        if operation == "restore" {
            fixture.success("activate", &[]);
        }
        let mut current = fixture.read();
        current["mcpServers"]["beta"]["args"] = json!(["private-credential"]);
        fixture.write(&current);
        let before = fs::read(&fixture.client).unwrap();
        let result = fixture.run(operation, &[]);
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("changed since adoption"));
        assert!(!String::from_utf8_lossy(&result.stderr).contains("private-credential"));
        assert_eq!(fs::read(&fixture.client).unwrap(), before);
    }
}

#[test]
fn missing_selected_entries_are_not_reintroduced() {
    let fixture = Fixture::new();
    let mut current = fixture.read();
    current["mcpServers"]
        .as_object_mut()
        .unwrap()
        .remove("beta");
    fixture.write(&current);
    assert!(!fixture.run("activate", &[]).status.success());
    assert_eq!(fixture.read(), current);
}

#[test]
fn modified_bundle_payloads_cannot_silently_change_the_original_command_or_environment() {
    for field in ["args", "env"] {
        let fixture = Fixture::new();
        let path = fixture.root.path().join("adopted/mcp.json");
        let mut template: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        if field == "args" {
            template["mcpServers"]["alpha"]["args"]
                .as_array_mut()
                .unwrap()
                .push(json!("injected"));
        } else {
            template["mcpServers"]["alpha"]["env"]["TOKEN"] = json!("injected");
        }
        fs::write(path, serde_json::to_vec(&template).unwrap()).unwrap();
        let before = fs::read(&fixture.client).unwrap();
        assert!(!fixture.run("activate", &[]).status.success());
        assert_eq!(fs::read(&fixture.client).unwrap(), before);
    }
}

#[test]
fn activation_requires_a_policy_but_restore_can_recover_without_policy_or_kernel() {
    let fixture = Fixture::new();
    fixture.success("activate", &[]);
    fs::remove_file(fixture.root.path().join("policy.yaml")).unwrap();
    let template_path = fixture.root.path().join("adopted/mcp.json");
    let mut template: Value = serde_json::from_slice(&fs::read(&template_path).unwrap()).unwrap();
    let mut current = fixture.read();
    for name in ["alpha", "beta"] {
        let missing = json!(fixture.root.path().join("missing-chio"));
        template["mcpServers"][name]["command"] = missing.clone();
        current["mcpServers"][name]["command"] = missing;
    }
    fs::write(template_path, serde_json::to_vec(&template).unwrap()).unwrap();
    fixture.write(&current);
    assert!(!fixture.run("activate", &[]).status.success());
    fixture.success("restore", &[]);
    assert_eq!(fixture.read(), fixture.original);
}

#[test]
fn activation_rejects_a_policy_that_disables_durable_admission() {
    let fixture = Fixture::new();
    fs::write(
        fixture.root.path().join("policy.yaml"),
        "kernel:\n  durable_admission_mode: off\n",
    )
    .unwrap();
    let result = fixture.run("activate", &[]);
    assert!(!result.status.success());
    assert_eq!(fixture.read(), fixture.original);
}

#[test]
fn client_symlinks_and_hardlinks_are_rejected_without_changing_the_target() {
    for hardlink in [false, true] {
        let fixture = Fixture::new();
        let real = fixture.root.path().join("real-client.json");
        fs::rename(&fixture.client, &real).unwrap();
        if hardlink {
            fs::hard_link(&real, &fixture.client).unwrap();
        } else {
            symlink(&real, &fixture.client).unwrap();
        }
        let before = fs::read(&real).unwrap();
        assert!(!fixture.run("activate", &[]).status.success());
        assert_eq!(fs::read(&real).unwrap(), before);
    }
}

#[test]
fn another_chio_writer_prevents_configuration_changes() {
    let fixture = Fixture::new();
    let directory = fs::File::open(fixture.root.path()).unwrap();
    directory.try_lock().unwrap();
    let result = fixture.run("activate", &[]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("another configuration update"));
    assert_eq!(fixture.read(), fixture.original);
}

#[test]
fn writable_client_files_or_directories_are_rejected_before_replacement() {
    for directory in [false, true] {
        let fixture = Fixture::new();
        let path = if directory {
            fixture.root.path()
        } else {
            &fixture.client
        };
        let mode = if directory { 0o770 } else { 0o664 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        let result = fixture.run("activate", &[]);
        assert!(!result.status.success());
        assert_eq!(fixture.read(), fixture.original);
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains("--dry-run"));
        assert!(!stderr.contains("migrate the call site"));
    }
}

#[test]
fn bundle_files_cannot_be_used_as_the_client_destination() {
    let mut fixture = Fixture::new();
    fixture.client = fixture.root.path().join("adopted/original.json");
    let before = fs::read(&fixture.client).unwrap();
    assert!(!fixture.run("activate", &[]).status.success());
    assert_eq!(fs::read(&fixture.client).unwrap(), before);
}

#[test]
fn malformed_client_json_is_rejected_without_echoing_values_or_rewriting_it() {
    let fixture = Fixture::new();
    let bytes =
        br#"{"mcpServers":{"alpha":{"command":"private-credential","command":"conflict"}}}"#;
    fs::write(&fixture.client, bytes).unwrap();
    let result = fixture.run("activate", &[]);
    assert!(!result.status.success());
    assert!(!String::from_utf8_lossy(&result.stderr).contains("private-credential"));
    assert_eq!(fs::read(&fixture.client).unwrap(), bytes);
}
