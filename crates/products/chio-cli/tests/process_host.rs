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
