//! `mcp wrap` has no attestation self-test flag.
use std::process::Command;

#[test]
fn self_test_attestation_flag_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args(["mcp", "wrap", "--self-test-attestation", "echo"])
        .output()?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--self-test-attestation"), "{stderr}");
    assert!(!stderr.contains("Chio-verified"));
    Ok(())
}
