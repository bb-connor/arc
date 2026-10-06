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

#[path = "support/session_certificate_corruption.rs"]
mod session_certificate_corruption;

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
    let store = chio_store_sqlite::SqliteReceiptStore::open(&database)?;
    for sequence in 1..=4_097 {
        store.append_chio_receipt_returning_seq(&receipt(&signer, sequence))?;
    }
    store.create_next_receipt_checkpoint(4_097, &signer)?;
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
    assert_eq!(artifact.body.invocation_count, Some(0));
    assert!(!artifact.body.scope_compliant && !artifact.body.guards_compliant);
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
    assert_eq!(
        result["verification_scope"],
        "authenticated_retained_tool_snapshot"
    );
    session_certificate_corruption::corrupt_temporary_tool_receipt(
        &database,
        "UPDATE chio_tool_receipts SET raw_json='{bad' WHERE seq=1",
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

#[test]
fn explicit_profile_checks_are_bound_at_the_binary_entrypoint(
) -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::tempdir()?;
    let database = root.path().join("receipts.sqlite3");
    let seed = root.path().join("signer.seed");
    let public_key = root.path().join("signer.pub");
    let certificate = root.path().join("certificate.json");
    let profile = root.path().join("profile.json");
    let signer = chio_core::Keypair::from_seed(&[42; 32]);
    private_fixture::write_private_file(&seed, "2a".repeat(32).as_bytes())?;
    std::fs::write(&public_key, signer.public_key().to_hex())?;
    let store = chio_store_sqlite::SqliteReceiptStore::open(&database)?;
    let mut body = receipt(&signer, 1).body();
    body.id.clear();
    body.decision = Some(chio_core::receipt::decision::Decision::Allow);
    body.receipt_kind = ReceiptKind::MediatedDecision;
    body.boundary_class = BoundaryClass::Prevent;
    body.observation_outcome = None;
    body.trust_level = TrustLevel::Mediated;
    body.evidence = vec![chio_core::receipt::metadata::GuardEvidence {
        guard_name: "required-guard".into(),
        verdict: true,
        details: None,
    }];
    store.append_chio_receipt_returning_seq(&ChioReceipt::sign(body, &signer)?)?;
    store.create_next_receipt_checkpoint(1, &signer)?;
    let write_profile = |server: &str| {
        std::fs::write(&profile, json!({"budget_limit":1,"required_guards":["required-guard"],"tool_targets":[{"server_id":server,"tool_name":"read"}]}).to_string())
    };
    write_profile("acp-proxy")?;
    let generated = Command::new(env!("CARGO_BIN_EXE_chio"))
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
        .arg("--profile")
        .arg(&profile)
        .arg("--output")
        .arg(&certificate)
        .output()?;
    assert!(
        generated.status.success(),
        "{}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let artifact: chio_acp_proxy::ComplianceCertificate =
        serde_json::from_slice(&std::fs::read(&certificate)?)?;
    assert!(
        artifact.body.scope_compliant
            && artifact.body.guards_compliant
            && artifact.body.budget_compliant
    );
    assert_eq!(artifact.body.invocation_count, Some(1));
    let verify = || {
        Command::new(env!("CARGO_BIN_EXE_chio"))
            .args(["--json", "cert", "verify", "--certificate"])
            .arg(&certificate)
            .arg("--trusted-kernel-pubkey")
            .arg(&public_key)
            .args(["--full", "--receipt-db"])
            .arg(&database)
            .arg("--profile")
            .arg(&profile)
            .output()
    };
    let verified = verify()?;
    assert!(
        verified.status.success(),
        "{}",
        String::from_utf8_lossy(&verified.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&verified.stdout)?;
    assert_eq!(
        result["verification_scope"],
        "authenticated_retained_tool_snapshot"
    );
    write_profile("different-server")?;
    let mismatch = verify()?;
    assert!(
        !mismatch.status.success(),
        "a changed profile passed the binary full verification path"
    );
    Ok(())
}
