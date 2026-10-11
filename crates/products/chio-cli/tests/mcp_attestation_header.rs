//! The legacy public self-test flag cannot manufacture verification evidence.
use std::process::Command;

#[test]
fn self_test_attestation_explicitly_refuses_unbound_verification(
) -> Result<(), Box<dyn std::error::Error>> {
    for tool in [
        "echo",
        "read_file",
        "fs.write",
        "tool/with/slash",
        "emoji-ok",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_chio"))
            .args(["mcp", "wrap", "--self-test-attestation", tool])
            .output()?;
        assert!(
            !output.status.success(),
            "unbound self-test succeeded for {tool}"
        );
        let diagnostic = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            diagnostic.contains("--self-test-attestation is unsupported"),
            "legacy flag needs an explicit evidence-contract reason: {diagnostic}"
        );
        assert!(diagnostic.contains("no receipt-bound verification is available"));
        assert!(!diagnostic.contains("Chio-verified"));
        assert!(!diagnostic.contains("urn:chio:attest:tool-call/v1"));
    }
    Ok(())
}
