#![allow(clippy::expect_used)]

use std::process::Command;

#[test]
fn trust_serve_help_names_the_access_config_and_no_shared_secret_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args(["trust", "serve", "--help"])
        .output()
        .expect("spawn chio trust serve --help");
    assert!(
        output.status.success(),
        "trust serve --help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("help output is utf8");
    assert!(stdout.contains("--access-config"), "{stdout}");
    for removed in [
        "--service-token",
        "--tenant-read-token",
        "--authority-workload-token",
        "--peer-url",
        "CHIO_TRUST_SERVICE_TOKEN",
    ] {
        assert!(!stdout.contains(removed), "{removed} in help: {stdout}");
    }
}

#[test]
fn trust_serve_refuses_the_removed_shared_secret_flags() {
    for (flag, value) in [
        ("--service-token", "secret"),
        ("--tenant-read-token", "tenant-a=secret"),
        ("--authority-workload-token", "secret"),
        ("--peer-url", "https://peer.example"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_chio"))
            .args(["trust", "serve", flag, value])
            .output()
            .expect("spawn chio trust serve");
        assert!(!output.status.success(), "{flag} was accepted");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!("unexpected argument '{flag}'")),
            "{flag}: {stderr}"
        );
    }
}

#[test]
fn trust_config_check_refuses_a_document_naming_removed_keys() {
    let directory =
        std::env::temp_dir().join(format!("chio-trust-config-check-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("create directory");
    for key in ["service_token", "tenant_read_tokens"] {
        let path = directory.join(format!("{key}.toml"));
        std::fs::write(
            &path,
            format!("{key} = \"x\"\ndeployment = \"d\"\ninternal_listen = \"127.0.0.1:0\"\n"),
        )
        .expect("write access config");
        let output = Command::new(env!("CARGO_BIN_EXE_chio"))
            .args(["trust", "config", "check", "--access-config"])
            .arg(&path)
            .output()
            .expect("spawn chio trust config check");
        assert!(!output.status.success(), "{key} was accepted");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!(
                "trust-control configuration key \"{key}\" is removed; declare [[credentials]] entries with scopes and tenant authority instead"
            )),
            "{key}: {stderr}"
        );
    }
    let _ = std::fs::remove_dir_all(&directory);
}
