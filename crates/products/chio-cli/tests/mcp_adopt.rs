#![allow(clippy::expect_used, clippy::unwrap_used)]
#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{json, Value};

fn policy(directory: &Path) -> PathBuf {
    let path = directory.join("policy.yaml");
    fs::write(&path, "kernel:\n  durable_admission_mode: all\ncapabilities:\n  default:\n    tools:\n      - server: fs\n        tool: append_note\n        max_invocations: 2\n").unwrap();
    path
}

fn adopt(directory: &Path, source: &str, extra: &[&str]) -> Output {
    let config = directory.join("original.json");
    fs::write(&config, source).unwrap();
    Command::new(env!("CARGO_BIN_EXE_chio"))
        .args(["mcp", "adopt", "--config"])
        .arg(config)
        .arg("--policy")
        .arg(policy(directory))
        .arg("--output")
        .arg(directory.join("adopted"))
        .args(extra)
        .output()
        .unwrap()
}

#[test]
fn adoption_preserves_client_settings_and_literally_wraps_selected_commands() {
    let temp = tempfile::tempdir().unwrap();
    let input = json!({
        "preferences": {"theme": "dark"},
        "mcpServers": {
            "fs": {"command":"python3", "args":["server.py", "space and $literal", "--receipt-db", "child.sqlite"],
                   "env":{"TOKEN":"secret-kept-in-config", "COUNT":"2"}, "cwd":"/workspace", "disabled":false},
            "remote": {"url":"https://example.invalid/mcp", "headers":{"Authorization":"private-token"}}
        }
    }).to_string();
    let result = adopt(temp.path(), &input, &["--server", "fs"]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["installed"], false);
    assert_eq!(
        fs::read_to_string(report["backup_config_path"].as_str().unwrap()).unwrap(),
        input
    );
    assert_eq!(report["unchanged_servers"], json!(["remote"]));
    assert_eq!(report["wrapped_servers"].as_array().unwrap().len(), 1);
    assert!(!String::from_utf8_lossy(&result.stdout).contains("secret-kept-in-config"));
    assert!(!String::from_utf8_lossy(&result.stdout).contains("private-token"));
    assert_eq!(
        fs::read_to_string(temp.path().join("original.json")).unwrap(),
        input
    );
    let generated: Value =
        serde_json::from_slice(&fs::read(temp.path().join("adopted/mcp.json")).unwrap()).unwrap();
    let original: Value = serde_json::from_str(&input).unwrap();
    assert_eq!(generated["preferences"], original["preferences"]);
    assert_eq!(
        generated["mcpServers"]["remote"],
        original["mcpServers"]["remote"]
    );
    let server = &generated["mcpServers"]["fs"];
    assert_eq!(server["env"], original["mcpServers"]["fs"]["env"]);
    assert_eq!(server["cwd"], "/workspace");
    assert_eq!(server["disabled"], false);
    assert!(Path::new(server["command"].as_str().unwrap()).is_absolute());
    let args = server["args"].as_array().unwrap();
    assert_eq!(&args[4..6], &[json!("mcp"), json!("serve")]);
    assert_eq!(
        &args[10..],
        &[
            json!("--"),
            json!("python3"),
            json!("server.py"),
            json!("space and $literal"),
            json!("--receipt-db"),
            json!("child.sqlite")
        ]
    );
    for field in ["session_db", "receipt_db", "kernel_public_key_file"] {
        let path = Path::new(report["wrapped_servers"][0][field].as_str().unwrap());
        assert!(path.is_absolute());
        assert!(path.parent().unwrap().is_dir());
        assert!(
            !path.exists(),
            "import must not start a kernel or tool server"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for file in ["mcp.json", "original.json", "adoption.json"] {
            assert_eq!(
                fs::metadata(temp.path().join("adopted").join(file))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600,
                "{file} must be private from creation",
            );
        }
        assert_eq!(
            fs::metadata(temp.path().join("adopted"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}

#[test]
fn invalid_or_ambiguous_imports_fail_before_writing_a_bundle() {
    let cases = [
        r#"{"mcpServers":{"fs":{"command":"python3","command":"malicious"}}}"#,
        r#"{"mcpServers":{"fs":{"command":"python3","args":[1]}}}"#,
        r#"{"mcpServers":{"fs":{"url":"https://example.invalid/mcp"}}}"#,
        r#"{"mcpServers":{"fs":{"command":"python3","type":"http"}}}"#,
        r#"{"mcpServers":{"fs":{"command":"chio"}}}"#,
        r#"{"mcpServers":{"fs":{"command":"python3","env":{"TOKEN":123}}}}"#,
        r#"{"mcpServers":{"*":{"command":"python3"}}}"#,
        r#"{"mcpServers":[]}"#,
        r#"{"mcpServers":{}}"#,
    ];
    for source in cases {
        let temp = tempfile::tempdir().unwrap();
        let result = adopt(temp.path(), source, &[]);
        assert!(!result.status.success(), "accepted {source}");
        assert!(!temp.path().join("adopted").exists());
    }
}

#[test]
fn existing_output_is_never_overwritten() {
    let temp = tempfile::tempdir().unwrap();
    let source = r#"{"mcpServers":{"fs":{"command":"python3"}}}"#;
    assert!(adopt(temp.path(), source, &[]).status.success());
    let target = temp.path().join("adopted/mcp.json");
    fs::write(&target, b"operator-owned contents").unwrap();
    let result = adopt(temp.path(), source, &[]);
    assert!(!result.status.success());
    assert_eq!(fs::read(&target).unwrap(), b"operator-owned contents");
}

#[test]
fn multiple_servers_have_separate_state_and_unknown_selections_reject() {
    let temp = tempfile::tempdir().unwrap();
    let source = r#"{"mcpServers":{"fs":{"command":"python3"},"Fs":{"command":"node"}}}"#;
    assert!(!adopt(temp.path(), source, &["--server", "absent"])
        .status
        .success());
    assert!(!temp.path().join("adopted").exists());
    let result = adopt(temp.path(), source, &[]);
    assert!(result.status.success());
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    let entries = report["wrapped_servers"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_ne!(entries[0]["session_db"], entries[1]["session_db"]);
    assert_ne!(
        entries[0]["kernel_public_key_file"],
        entries[1]["kernel_public_key_file"]
    );
}

#[cfg(unix)]
#[test]
fn output_symlink_cannot_redirect_private_config_writes() {
    let temp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), temp.path().join("adopted")).unwrap();
    let result = adopt(
        temp.path(),
        r#"{"mcpServers":{"fs":{"command":"python3"}}}"#,
        &[],
    );
    assert!(!result.status.success());
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
}

#[test]
fn invalid_policy_and_oversized_config_leave_no_generated_config() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("original.json");
    fs::write(&config, r#"{"mcpServers":{"fs":{"command":"python3"}}}"#).unwrap();
    let policy_path = temp.path().join("invalid-policy.yaml");
    fs::write(&policy_path, "kernel:\n  unrecognized_setting: true\n").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args(["mcp", "adopt", "--config"])
        .arg(&config)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--output")
        .arg(temp.path().join("adopted"))
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!temp.path().join("adopted").exists());
    let huge = " ".repeat(1024 * 1024 + 1);
    assert!(!adopt(temp.path(), &huge, &[]).status.success());
    assert!(!temp.path().join("adopted").exists());
}
