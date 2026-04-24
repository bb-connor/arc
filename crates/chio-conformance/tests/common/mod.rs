#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::Path;
use std::process::{Command, Stdio};

use chio_conformance::{default_run_options, unique_run_dir, ConformanceAuthMode, PeerTarget};
use serde_json::Value;

pub fn command_available(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

pub fn python3_supports_chio_sdk() -> bool {
    let Ok(output) = Command::new("python3")
        .arg("-c")
        .arg("import sys; print(f'{sys.version_info[0]}.{sys.version_info[1]}')")
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let version = String::from_utf8_lossy(&output.stdout);
    let mut parts = version.trim().split('.');
    let major = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    let minor = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    (major, minor) >= (3, 11)
}

pub fn ensure_chio_binary(repo_root: &Path) {
    let chio_binary = repo_root.join("target/debug/chio");
    if chio_binary.exists() {
        return;
    }

    let status = Command::new("cargo")
        .current_dir(repo_root)
        .arg("build")
        .arg("-q")
        .arg("-p")
        .arg("chio-cli")
        .status()
        .expect("build chio-cli");
    assert!(status.success(), "cargo build -p chio-cli must succeed");
}

pub fn scenario_passed(results_json: &str, scenario_id: &str) -> bool {
    let Ok(results) = serde_json::from_str::<Vec<Value>>(results_json) else {
        return false;
    };
    results.iter().any(|result| {
        result["scenarioId"].as_str() == Some(scenario_id)
            && result["status"].as_str() == Some("pass")
    })
}

pub fn cpp_options(
    wave: &str,
    auth_mode: ConformanceAuthMode,
) -> chio_conformance::ConformanceRunOptions {
    let mut options = default_run_options();
    ensure_chio_binary(&options.repo_root);
    options.peers = vec![PeerTarget::Cpp];
    options.auth_mode = auth_mode;
    options.scenarios_dir = options
        .repo_root
        .join(format!("tests/conformance/scenarios/{wave}"));
    let run_dir = unique_run_dir(&format!("chio-conformance-{wave}-cpp"));
    options.results_dir = run_dir.join("results");
    options.report_output = run_dir.join(format!("reports/{wave}-cpp-live.md"));
    options
}
