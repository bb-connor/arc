#![cfg(test)]
use chio_core::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::ToolCallAction,
    kinds::*,
};
use chio_test_support::prelude::*;
use serde_json::json;
use std::process::Command;

#[path = "support/private_fixture.rs"]
mod private_fixture;

fn receipt(signer: &chio_core::Keypair, sequence: u64) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: String::new(),
            timestamp: sequence,
            capability_id: "enforced-capability".into(),
            tool_server: "acp-proxy".into(),
            tool_name: "read".into(),
            action: ToolCallAction::from_parameters(json!({"path":"/example","sequence":sequence}))
                .test_unwrap(),
            decision: None,
            receipt_kind: ReceiptKind::TraceObservation,
            boundary_class: BoundaryClass::DetectOnly,
            observation_outcome: Some(ObservationOutcome::Observed),
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            content_hash: "content".into(),
            policy_hash: "policy".into(),
            evidence: Vec::new(),
            metadata: Some(json!({"acp":{"sessionId":"target_%"}})),
            trust_level: TrustLevel::Verified,
            kernel_key: signer.public_key(),
            bbs_projection_version: None,
            tenant_id: None,
        },
        signer,
    )
    .test_unwrap()
}

#[test]
fn long_session_generates_and_fully_verifies_then_refuses_incomplete_input(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let database = root.path().join("receipts.sqlite3");
    let seed = root.path().join("signer.seed");
    let public_key = root.path().join("signer.pub");
    let certificate = root.path().join("certificate.json");
    let rejected = root.path().join("rejected.json");
    let signer = chio_core::Keypair::from_seed(&[42; 32]);
    private_fixture::write_private_file(&seed, "2a".repeat(32).as_bytes())?;
    std::fs::write(&public_key, signer.public_key().to_hex())?;
    let mut db = rusqlite::Connection::open(&database)?;
    db.execute(
        "CREATE TABLE chio_receipts (capability_id TEXT, json_data TEXT)",
        [],
    )?;
    let transaction = db.transaction()?;
    for sequence in 1..=4_097 {
        transaction.execute(
            "INSERT INTO chio_receipts VALUES ('enforced-capability', ?1)",
            [serde_json::to_string(&receipt(&signer, sequence))?],
        )?;
    }
    transaction.commit()?;
    let generate = |path: &std::path::Path| {
        Command::new(env!("CARGO_BIN_EXE_chio"))
            .args(["--json", "--authority-seed-file"])
            .arg(&seed)
            .args([
                "cert",
                "generate",
                "--session-id",
                "target_%",
                "--receipt-db",
            ])
            .arg(&database)
            .arg("--output")
            .arg(path)
            .output()
    };
    let generated = generate(&certificate)?;
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let artifact: chio_acp_proxy::ComplianceCertificate =
        serde_json::from_slice(&std::fs::read(&certificate)?)?;
    assert_eq!(artifact.body.receipt_count, 4_097);
    let verified = Command::new(env!("CARGO_BIN_EXE_chio"))
        .args(["--json", "cert", "verify", "--certificate"])
        .arg(&certificate)
        .arg("--trusted-kernel-pubkey")
        .arg(&public_key)
        .args(["--full", "--receipt-db"])
        .arg(&database)
        .output()?;
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&verified.stdout)?;
    assert_eq!(result["receipts_reverified"], 4_097);
    assert_eq!(result["passed"], true);
    db.execute(
        "INSERT INTO chio_receipts VALUES ('acp-session:other', '{bad')",
        [],
    )?;
    let failure = generate(&rejected)?;
    assert!(!failure.status.success());
    assert!(
        !rejected.exists(),
        "incomplete input must not publish a certificate"
    );
    Ok(())
}
