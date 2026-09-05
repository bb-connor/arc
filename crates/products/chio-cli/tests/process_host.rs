#![cfg(unix)]

use std::path::Path;
use std::process::Command;

use chio_core_types::receipt::body::ChioReceipt;

#[test]
fn process_host_runs_existing_mcp_tools_and_recovers_after_host_death(
) -> Result<(), Box<dyn std::error::Error>> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let output = Command::new("python3")
        .arg(repository.join("crates/products/chio-cli/tests/process_host/recovery.py"))
        .arg(env!("CARGO_BIN_EXE_chio"))
        .env(
            "PYTHONPATH",
            repository.join("sdks/python/chio-process/src"),
        )
        .output()?;
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let evidence: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let receipt: ChioReceipt =
        serde_json::from_str(evidence["receipt_json"].as_str().ok_or("missing receipt")?)?;
    assert!(receipt.verify_signature()?);
    assert_eq!(receipt.kernel_key.to_hex(), evidence["kernel_key"]);
    assert_eq!(evidence["publications"], 1);
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn process_runner_recovers_workers_and_host_without_repeating_effects(
) -> Result<(), Box<dyn std::error::Error>> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let output = Command::new("python3")
        .arg(repository.join("crates/products/chio-cli/tests/process_host/runner.py"))
        .arg(env!("CARGO_BIN_EXE_chio"))
        .env(
            "PYTHONPATH",
            repository.join("sdks/python/chio-process/src"),
        )
        .output()?;
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn process_host_runs_native_mailboxes_without_mcp_servers() -> Result<(), Box<dyn std::error::Error>>
{
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let output = Command::new("python3")
        .arg(repository.join("crates/products/chio-cli/tests/process_host/mailboxes.py"))
        .arg(env!("CARGO_BIN_EXE_chio"))
        .env(
            "PYTHONPATH",
            repository.join("sdks/python/chio-process/src"),
        )
        .output()?;
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn adaptive_processes_delegate_and_join_across_python_node_and_host_death(
) -> Result<(), Box<dyn std::error::Error>> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let output = Command::new("python3")
        .arg(repository.join("crates/products/chio-cli/tests/process_host/adaptive.py"))
        .arg(env!("CARGO_BIN_EXE_chio"))
        .env(
            "PYTHONPATH",
            repository.join("sdks/python/chio-process/src"),
        )
        .output()?;
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let evidence: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(evidence["adaptive_children"], 4);
    assert_eq!(evidence["max_parallel"], 1);
    Ok(())
}
