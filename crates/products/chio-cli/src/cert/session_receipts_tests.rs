#![cfg(test)]
use super::*;
use chio_core::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::ToolCallAction,
    kinds::*,
};
use chio_test_support::prelude::*;
use serde_json::json;

fn database() -> rusqlite::Connection {
    let db = rusqlite::Connection::open_in_memory().test_unwrap();
    db.execute(
        "CREATE TABLE chio_receipts (capability_id TEXT, json_data TEXT)",
        [],
    )
    .test_unwrap();
    db
}

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

fn insert(db: &rusqlite::Connection, bytes: &str) {
    db.execute(
        "INSERT INTO chio_receipts VALUES ('enforced-capability', ?1)",
        [bytes],
    )
    .test_unwrap();
}

#[test]
fn certificate_collection_certifies_a_session_beyond_the_proof_artifact_limit() {
    let mut db = database();
    let signer = chio_core::Keypair::from_seed(&[42; 32]);
    let transaction = db.transaction().test_unwrap();
    for sequence in 1..=4_097 {
        insert(
            &transaction,
            &serde_json::to_string(&receipt(&signer, sequence)).test_unwrap(),
        );
    }
    transaction.commit().test_unwrap();
    let entries = load_session_receipts(&db, "target_%").test_unwrap();
    assert_eq!(entries.len(), 4_097);
    assert_eq!(entries.first().test_unwrap().seq, 1);
    assert_eq!(entries.last().test_unwrap().seq, 4_097);
    let config = ComplianceConfig {
        budget_limit: 10_000,
        required_guards: Vec::new(),
        authorized_scopes: Vec::new(),
        expected_tenant_id: None,
        trusted_kernel_keys: BTreeSet::from([signer.public_key().to_hex()]),
    };
    let certificate = generate_compliance_certificate(
        "target_%",
        &entries,
        &config,
        &signer,
        &chio_acp_proxy::AcpClock::default(),
    )
    .test_unwrap();
    assert_eq!(certificate.body.session_id, "target_%");
    assert_eq!(certificate.body.receipt_count, 4_097);
    assert!(certificate.body.all_signatures_valid);
    assert!(certificate.body.chain_continuous);
    let verified = verify_compliance_certificate(
        &certificate,
        VerificationMode::FullBundle,
        Some(&entries),
        &config,
    );
    assert!(verified.passed, "{}", verified.summary);
    assert_eq!(verified.receipts_reverified, 4_097);
}

#[test]
fn certificate_collection_isolates_unrelated_oversized_receipt_bodies() {
    let db = database();
    insert(&db, &json!({"metadata":{"acp":{"sessionId":"another-session"}},"invalidReceiptBody":"x".repeat(1024 * 1024 + 1)}).to_string());
    assert!(load_session_receipts(&db, "target_%")
        .test_unwrap()
        .is_empty());
    assert!(load_session_receipts(&db, "another-session").is_err());
}

#[test]
fn certificate_collection_cannot_hide_membership_behind_duplicate_or_conflicting_fields() {
    for bytes in [
        r#"{"metadata":{"acp":{"sessionId":"other"}},"metadata":{"acp":{"sessionId":"target_%"}}}"#,
        r#"{"metadata":{"acp":{"sessionId":"other","sessionId":"target_%"}}}"#,
        r#"{"metadata":{"acp":{"sessionId":"other"},"receipt_context":{"session_id":"target_%"}}}"#,
    ] {
        let db = database();
        insert(&db, bytes);
        assert!(
            load_session_receipts(&db, "target_%").is_err(),
            "ambiguous membership was omitted"
        );
    }
}

#[test]
fn certificate_collection_refuses_unknown_membership_without_trusting_capability_id() {
    let db = database();
    db.execute(
        "INSERT INTO chio_receipts VALUES ('acp-session:other', 'malformed')",
        [],
    )
    .test_unwrap();
    assert!(load_session_receipts(&db, "target_%").is_err());
}

#[test]
fn certificate_collection_reports_private_row_context_and_preserves_gaps() {
    let db = database();
    let signer = chio_core::Keypair::from_seed(&[42; 32]);
    insert(
        &db,
        &serde_json::to_string(&receipt(&signer, 1)).test_unwrap(),
    );
    insert(&db, r#"{"metadata":{"acp":{"sessionId":"other"}}}"#);
    insert(
        &db,
        &serde_json::to_string(&receipt(&signer, 3)).test_unwrap(),
    );
    let entries = load_session_receipts(&db, "target_%").test_unwrap();
    assert_eq!(
        entries.iter().map(|entry| entry.seq).collect::<Vec<_>>(),
        [1, 3]
    );
    let config = ComplianceConfig {
        budget_limit: 0,
        required_guards: Vec::new(),
        authorized_scopes: Vec::new(),
        expected_tenant_id: None,
        trusted_kernel_keys: BTreeSet::from([signer.public_key().to_hex()]),
    };
    assert!(generate_compliance_certificate(
        "target_%",
        &entries,
        &config,
        &signer,
        &chio_acp_proxy::AcpClock::default()
    )
    .is_err());
    insert(
        &db,
        r#"{"metadata":{"acp":{"sessionId":true}},"private":"secret-marker"}"#,
    );
    let error = load_session_receipts(&db, "target_%").test_unwrap_err();
    let context = std::error::Error::source(&error)
        .and_then(std::error::Error::source)
        .test_unwrap()
        .to_string();
    assert_eq!(
        context,
        "certificate receipt row 4: session identifier must be text"
    );
    assert!(!format!("{error} {error:?} {:?}", error.report()).contains("secret-marker"));
}

#[test]
fn certificate_collection_rejects_uninspectable_rows_before_allocation() {
    for expression in [
        "zeroblob(16777217)",
        "NULL",
        "42",
        "CAST(zeroblob(16777217) AS TEXT)",
    ] {
        let db = database();
        db.execute(
            &format!("INSERT INTO chio_receipts VALUES ('other', {expression})"),
            [],
        )
        .test_unwrap();
        assert!(load_session_receipts(&db, "target_%").is_err());
    }
}
