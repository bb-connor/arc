use super::*;

use chio_core::receipt::kinds::{
    BoundaryClass, ReceiptKind, RedactionMode, ToolOrigin, TrustLevel,
};
use chio_http_core::{HttpMethod, HttpReceipt, HttpReceiptBody, Verdict};

fn http_receipt(verdict: Verdict) -> HttpReceipt {
    let keypair = package_keypair();
    HttpReceipt::sign(
        HttpReceiptBody {
            id: String::new(),
            request_id: "http-export-1".into(),
            route_pattern: "/pets/{petId}".into(),
            method: HttpMethod::Get,
            caller_identity_hash: sha256_hex(b"caller"),
            session_id: Some("http-session-1".into()),
            response_status: if verdict.is_allowed() { 200 } else { 403 },
            verdict,
            receipt_kind: ReceiptKind::MediatedDecision,
            boundary_class: BoundaryClass::Prevent,
            observation_outcome: None,
            tool_origin: ToolOrigin::CallerExecuted,
            redaction_mode: RedactionMode::None,
            actor_chain: Vec::new(),
            evidence: Vec::new(),
            timestamp: 1_775_137_626,
            content_hash: sha256_hex(b"request"),
            policy_hash: sha256_hex(b"policy"),
            trust_level: TrustLevel::Mediated,
            capability_id: None,
            metadata: Some(chio_http_core::http_status_metadata_decision()),
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .test_unwrap()
}

fn http_package(receipt: ChioReceipt) -> tempfile::TempDir {
    assert!(receipt
        .verify_signature_with_floor(&receipt.kernel_key, ReceiptCryptoFloor::AllowHybrid)
        .test_unwrap());
    assert!(receipt.action.verify_hash().test_unwrap());
    let directory = chio_test_support::private_tempdir().test_unwrap();
    let mut bundle = sample_bundle();
    bundle.query = EvidenceExportQuery::admin_all();
    bundle.child_receipt_scope = EvidenceChildReceiptScope::FullQueryWindow;
    bundle.uncheckpointed_receipts = vec![chio_kernel::EvidenceUncheckpointedReceipt {
        seq: 1,
        receipt_id: receipt.id.clone(),
    }];
    bundle.tool_receipts = vec![EvidenceToolReceiptRecord { seq: 1, receipt }];
    bundle.checkpoints.clear();
    bundle.inclusion_proofs.clear();
    write_evidence_package(
        directory.path(),
        bundle,
        None,
        None,
        None,
        &package_keypair(),
    )
    .test_unwrap();
    directory
}

fn assert_http_rejection(
    receipt: ChioReceipt,
    expected_message: &str,
    policy: &EvidenceVerificationPolicy,
) {
    let directory = http_package(receipt);
    let error = load_verified_evidence_package_summary(directory.path(), policy).test_unwrap_err();
    assert_registry_error(&error, "urn:chio:error:attest:provenance-missing", "attest");
    match error {
        CliError::Chio(error) => assert_eq!(error.message(), expected_message),
        other => panic!("expected attestation refusal, received {other:?}"),
    }
}

#[test]
fn package_accepts_authenticated_http_allow_and_deny() {
    for verdict in [
        Verdict::Allow,
        Verdict::deny("outside capability scope", "scope"),
    ] {
        let http = http_receipt(verdict);
        let projected = http
            .to_chio_receipt_with_keypair(&package_keypair())
            .test_unwrap();
        let directory = http_package(projected.clone());
        let verified = load_verified_evidence_package_summary(directory.path(), &package_policy())
            .test_unwrap();
        assert_eq!(verified.bundle.tool_receipts.len(), 1);
        assert_eq!(verified.bundle.tool_receipts[0].receipt.id, projected.id);
    }
}

#[test]
fn package_rejects_tampered_embedded_http_receipt() {
    let mut http = http_receipt(Verdict::Allow);
    let projected = http
        .to_chio_receipt_with_keypair(&package_keypair())
        .test_unwrap();
    http.response_status = 503;
    assert!(!http.verify_signature().test_unwrap());
    let receipt = resign_embedded_http(projected.body(), http);
    let expected = format!(
        "HTTP receipt projection verification failed: {}",
        receipt.id
    );
    assert_http_rejection(receipt, &expected, &package_policy());
}

fn resign_embedded_http(mut body: ChioReceiptBody, http: HttpReceipt) -> ChioReceipt {
    body.id = http.id.clone();
    body.content_hash = http.content_hash.clone();
    let metadata = body
        .metadata
        .as_mut()
        .test_unwrap()
        .as_object_mut()
        .test_unwrap();
    metadata.remove("chio_receipt_signing_nonce");
    metadata.insert(
        "chio_http_receipt_v1".into(),
        serde_json::to_value(http).test_unwrap(),
    );
    body.content_hash = sha256_hex(&canonical_json_bytes(&body).test_unwrap());
    ChioReceipt::sign(body, &package_keypair()).test_unwrap()
}

#[test]
fn package_rejects_forged_embedded_http_signature_with_valid_id() {
    let mut http = http_receipt(Verdict::Allow);
    let projected = http
        .to_chio_receipt_with_keypair(&package_keypair())
        .test_unwrap();
    http.signature = http_receipt(Verdict::deny("outside capability scope", "scope")).signature;
    assert!(http.receipt_id_valid().test_unwrap());
    assert!(!http.verify_signature().test_unwrap());
    let receipt = resign_embedded_http(projected.body(), http);
    let expected = format!(
        "HTTP receipt projection verification failed: {}",
        receipt.id
    );
    assert_http_rejection(receipt, &expected, &package_policy());
}

#[test]
fn package_rejects_http_receipt_without_embedded_evidence() {
    let mut body = http_receipt(Verdict::Allow)
        .to_chio_receipt_with_keypair(&package_keypair())
        .test_unwrap()
        .body();
    body.metadata
        .as_mut()
        .test_unwrap()
        .as_object_mut()
        .test_unwrap()
        .remove("chio_http_receipt_v1");
    let receipt = ChioReceipt::sign(body, &package_keypair()).test_unwrap();
    let expected = format!("HTTP receipt evidence missing: {}", receipt.id);
    assert_http_rejection(receipt, &expected, &package_policy());
}

#[test]
fn package_rejects_null_embedded_http_evidence() {
    let mut body = http_receipt(Verdict::Allow)
        .to_chio_receipt_with_keypair(&package_keypair())
        .test_unwrap()
        .body();
    body.metadata.as_mut().test_unwrap()["chio_http_receipt_v1"] = serde_json::Value::Null;
    let receipt = ChioReceipt::sign(body, &package_keypair()).test_unwrap();
    let expected = format!(
        "HTTP receipt evidence decoding failed: {}: invalid type: null, expected struct HttpReceipt",
        receipt.id
    );
    assert_http_rejection(receipt, &expected, &package_policy());
}

#[test]
fn package_rejects_http_projection_under_another_server() {
    let http = http_receipt(Verdict::Allow);
    let mut body = http
        .to_chio_receipt_with_keypair(&package_keypair())
        .test_unwrap()
        .body();
    body.id = http.id;
    body.tool_server = "export".into();
    let receipt = ChioReceipt::sign(body, &package_keypair()).test_unwrap();
    let expected = format!(
        "HTTP receipt projection verification failed: {}",
        receipt.id
    );
    assert_http_rejection(receipt, &expected, &package_policy());
}

#[test]
fn package_rejects_unknown_embedded_http_fields() {
    let http = http_receipt(Verdict::Allow);
    let mut body = http
        .to_chio_receipt_with_keypair(&package_keypair())
        .test_unwrap()
        .body();
    body.id = http.id;
    body.metadata.as_mut().test_unwrap()["chio_http_receipt_v1"]["authority_override"] =
        serde_json::json!(true);
    let receipt = ChioReceipt::sign(body, &package_keypair()).test_unwrap();
    let expected = format!(
        "HTTP receipt projection verification failed: {}",
        receipt.id
    );
    assert_http_rejection(receipt, &expected, &package_policy());
}

#[test]
fn package_preserves_signed_http_metadata() {
    for metadata in [
        serde_json::Value::Null,
        serde_json::json!("source-metadata"),
        serde_json::json!({
            "chio_http_receipt_v1": {"source": "opaque"},
            "chio_receipt_signing_nonce": "source-nonce",
        }),
    ] {
        let mut body = http_receipt(Verdict::Allow).body();
        body.metadata = Some(metadata.clone());
        let http = HttpReceipt::sign(body, &package_keypair()).test_unwrap();
        let projected = http
            .to_chio_receipt_with_keypair(&package_keypair())
            .test_unwrap();
        let directory = http_package(projected);
        let verified = load_verified_evidence_package_summary(directory.path(), &package_policy())
            .test_unwrap();
        assert_eq!(
            verified.bundle.tool_receipts[0]
                .receipt
                .metadata
                .as_ref()
                .test_unwrap()["chio_http_receipt_v1"]["metadata"],
            metadata
        );
    }
}

#[test]
fn package_rejects_distinct_trusted_http_and_outer_signers() {
    let foreign = Keypair::from_seed(&[73; 32]);
    let mut body = http_receipt(Verdict::Allow).body();
    body.kernel_key = foreign.public_key();
    let http = HttpReceipt::sign(body, &foreign).test_unwrap();
    assert!(http.verify_signature().test_unwrap());
    let mut body = http
        .to_chio_receipt_with_keypair(&foreign)
        .test_unwrap()
        .body();
    body.id = http.id;
    body.kernel_key = package_keypair().public_key();
    let receipt = ChioReceipt::sign(body, &package_keypair()).test_unwrap();
    let policy = EvidenceVerificationPolicy::new(
        vec![package_keypair().public_key(), foreign.public_key()],
        None,
    )
    .test_unwrap();
    let expected = format!(
        "HTTP receipt projection verification failed: {}",
        receipt.id
    );
    assert_http_rejection(receipt, &expected, &policy);
}

#[test]
fn package_rejects_outer_allow_for_http_deny() {
    let http = http_receipt(Verdict::deny("outside capability scope", "scope"));
    let mut body = http
        .to_chio_receipt_with_keypair(&package_keypair())
        .test_unwrap()
        .body();
    body.id = http.id;
    body.decision = Some(Decision::Allow);
    let receipt = ChioReceipt::sign(body, &package_keypair()).test_unwrap();
    let expected = format!(
        "HTTP receipt projection verification failed: {}",
        receipt.id
    );
    assert_http_rejection(receipt, &expected, &package_policy());
}

#[test]
fn package_preserves_non_authorizing_http_observation() {
    let mut body = http_receipt(Verdict::Allow).body();
    body.verdict = Verdict::Incomplete {
        reason: "observation".into(),
    };
    body.receipt_kind = ReceiptKind::AdvisoryEvaluation;
    body.boundary_class = BoundaryClass::AdvisoryOnly;
    body.observation_outcome = Some(chio_core::receipt::kinds::ObservationOutcome::Observed);
    body.trust_level = TrustLevel::Advisory;
    body.tool_origin = ToolOrigin::HostExecutedUnmediated;
    let http = HttpReceipt::sign(body, &package_keypair()).test_unwrap();
    let projected = http
        .to_chio_receipt_with_keypair(&package_keypair())
        .test_unwrap();
    let directory = http_package(projected);
    let verified =
        load_verified_evidence_package_summary(directory.path(), &package_policy()).test_unwrap();
    let receipt = &verified.bundle.tool_receipts[0].receipt;
    assert_eq!(receipt.decision, None);
    assert_eq!(receipt.trust_level, TrustLevel::Advisory);
    assert_eq!(receipt.boundary_class, BoundaryClass::AdvisoryOnly);
    assert_eq!(receipt.receipt_kind, ReceiptKind::AdvisoryEvaluation);
}
