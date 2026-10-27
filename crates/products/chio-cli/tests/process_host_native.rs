//! Native recovery campaigns require the enforcing-host fixture.
#![cfg(all(unix, target_os = "linux"))]
use chio_core_types::receipt::body::ChioReceipt;
use std::path::Path;
use std::process::Command;

#[test]
#[cfg(target_os = "linux")]
fn process_administration_preserves_files_and_releases_diagnostic_locks(
) -> Result<(), Box<dyn std::error::Error>> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let output = Command::new("python3")
        .arg(repository.join("crates/products/chio-cli/tests/process_host/administration.py"))
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
#[cfg(target_os = "linux")]
fn process_host_survives_os_death_at_each_dispatch_cutpoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let output = Command::new("python3")
        .arg(repository.join("crates/products/chio-cli/tests/process_host/os_death.py"))
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
    let cases = evidence["cases"].as_array().ok_or("missing cases")?;
    let expected = [("C1", 0), ("C2", 1), ("C4", 1)];
    assert_eq!(cases.len(), expected.len());
    for (case, (cutpoint, publications)) in cases.iter().zip(expected) {
        assert_eq!(case["cutpoint"], cutpoint);
        let receipt: ChioReceipt =
            serde_json::from_str(case["receipt_json"].as_str().ok_or("missing receipt")?)?;
        assert!(receipt.verify_signature()?, "{cutpoint}");
        assert_eq!(
            receipt.kernel_key.to_hex(),
            case["kernel_key"],
            "{cutpoint}"
        );
        assert_eq!(case["publications"], publications, "{cutpoint}");
    }
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn process_host_keeps_a_durable_stop_across_os_death() -> Result<(), Box<dyn std::error::Error>> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let output = Command::new("python3")
        .arg(repository.join("crates/products/chio-cli/tests/process_host/stop_os_death.py"))
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
    let cases = evidence["cases"].as_array().ok_or("missing cases")?;
    let expected = [("hold", 1), ("C7", 0), ("C6", 1), ("C8", 1)];
    assert_eq!(cases.len(), expected.len());
    for (case, (cutpoint, publications)) in cases.iter().zip(expected) {
        assert_eq!(case["cutpoint"], cutpoint);
        for raw in case["receipts"].as_array().ok_or("missing receipts")? {
            let receipt: ChioReceipt = serde_json::from_str(raw.as_str().ok_or("receipt")?)?;
            assert!(receipt.verify_signature()?, "{cutpoint}");
            assert_eq!(
                receipt.kernel_key.to_hex(),
                case["kernel_key"],
                "{cutpoint}"
            );
        }
        assert_eq!(case["publications"], publications, "{cutpoint}");
    }
    Ok(())
}
