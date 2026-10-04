//! EV15 baseline-compatible RED cases followed by post-repair controls
//! exercising independently pinned receipts and the dispatch authenticity API.
use super::*;
use chio_core::receipt::body::chio_receipt_id;

const SECRET: &str = "ev15-denied-secret-31ba";

fn signed_deny(key: &Keypair) -> ChioReceipt {
    let mut body = deny_receipt("ev15-auth", "SecretLeakGuard").body();
    body.kernel_key = key.public_key();
    body.action = ToolCallAction::from_parameters(serde_json::json!({"secret": SECRET})).unwrap();
    body.decision = Some(Decision::Deny {
        guard: "SecretLeakGuard".into(),
        reason: SECRET.into(),
    });
    body.evidence[0].details = Some(SECRET.into());
    body.metadata = Some(serde_json::json!({"secret": SECRET}));
    ChioReceipt::sign(body, key).unwrap()
}

fn event_with_forged_flags(receipt: ChioReceipt) -> SiemEvent {
    let mut event = SiemEvent::from_receipt(receipt);
    event.authoritative = true;
    event.signature_valid = true;
    event.receipt_id_valid = true;
    event.parameter_hash_valid = true;
    event.signer_trusted = true;
    event.authorized = true;
    event.receipt_kind = "mediated_decision".into();
    event.boundary_class = "prevent".into();
    event.result = "Authorized".into();
    event
}

async fn receiving_server() -> MockServer {
    let server = MockServer::start().await;
    // No expectation count here: assert the actual captured requests explicitly.
    for endpoint in ["/v2/enqueue", "/v2/alerts"] {
        Mock::given(method("POST"))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(202))
            .mount(&server)
            .await;
    }
    server
}

fn receiving_exporter_builder(server: &MockServer) -> chio_siem::AlertingExporterBuilder {
    let authority = test_server_authority(server);
    AlertingExporter::builder(AlertingConfig::default())
        .with_backend(Box::new(
            PagerDutyBackend::with_endpoint_and_contract(
                "ev15-test-routing-key".into(),
                server.uri(),
                HttpEgressContract::permissive_for_tests(&authority),
            )
            .unwrap(),
        ))
        .with_backend(Box::new(
            OpsGenieBackend::with_endpoint_and_contract(
                "ev15-test-api-key".into(),
                server.uri(),
                HttpEgressContract::permissive_for_tests(&authority),
            )
            .unwrap(),
        ))
}

async fn assert_no_unpinned_dispatch(event: SiemEvent) {
    let server = receiving_server().await;
    let exporter = receiving_exporter_builder(&server).build();
    // Filtered notifications count as processed, without generating backend traffic.
    assert_eq!(exporter.export_batch(&[event]).await.unwrap(), 1);
    let requests = server.received_requests().await.unwrap();
    assert!(
        requests.is_empty(),
        "unpinned receipt paged {} backends",
        requests.len()
    );
}

#[tokio::test]
async fn default_exporter_does_not_page_valid_unpinned_receipt() {
    let key = Keypair::generate();
    let receipt = signed_deny(&key);
    assert!(receipt.verify_signature().unwrap());
    assert!(receipt.action.verify_hash().unwrap());
    assert_eq!(chio_receipt_id(&receipt.body()).unwrap(), receipt.id);
    assert_no_unpinned_dispatch(SiemEvent::from_receipt(receipt)).await;
}

#[tokio::test]
async fn attacker_controlled_public_flags_cannot_enable_unpinned_paging() {
    let key = Keypair::generate();
    assert_no_unpinned_dispatch(event_with_forged_flags(signed_deny(&key))).await;
}

#[tokio::test]
async fn forged_signature_and_flags_do_not_page() {
    let key = Keypair::generate();
    let mut receipt = signed_deny(&key);
    receipt.signature = Keypair::generate().sign(b"not a receipt");
    assert!(!receipt.verify_signature().unwrap());
    assert_eq!(chio_receipt_id(&receipt.body()).unwrap(), receipt.id);
    assert_no_unpinned_dispatch(event_with_forged_flags(receipt)).await;
}

#[tokio::test]
async fn mutated_receipt_id_and_flags_do_not_page() {
    let key = Keypair::generate();
    let mut receipt = signed_deny(&key);
    receipt.id = "attacker-controlled-id".into();
    assert_ne!(chio_receipt_id(&receipt.body()).unwrap(), receipt.id);
    assert_no_unpinned_dispatch(event_with_forged_flags(receipt)).await;
}

#[tokio::test]
async fn signed_inconsistent_action_hash_and_flags_do_not_page() {
    let key = Keypair::generate();
    let mut body = signed_deny(&key).body();
    body.action.parameter_hash = "0".repeat(64);
    let receipt = ChioReceipt::sign(body, &key).unwrap();
    assert!(receipt.verify_signature().unwrap());
    assert_eq!(chio_receipt_id(&receipt.body()).unwrap(), receipt.id);
    assert!(!receipt.action.verify_hash().unwrap());
    assert_no_unpinned_dispatch(event_with_forged_flags(receipt)).await;
}

// These cases require the approved additive pin API and are intentionally not
// part of the baseline RED patch.
#[tokio::test]
async fn pinned_valid_receipt_pages_real_backends_and_omits_secrets() {
    let key = Keypair::generate();
    // Derive the verifier policy from fixture-owned key material BEFORE reading
    // an event. Never derive an accepted key from event.receipt.kernel_key.
    let pins = vec![key.public_key()];
    let server = receiving_server().await;
    let exporter = receiving_exporter_builder(&server)
        .with_trusted_kernel_keys(pins)
        .build();
    let receipt = signed_deny(&key);
    let id = receipt.id.clone();
    let hash = receipt.action.parameter_hash.clone();
    let mut event = SiemEvent::from_receipt(receipt);
    // Even false/stale cached flags must not override valid pinned receipt bytes.
    event.authoritative = false;
    event.signature_valid = false;
    event.receipt_id_valid = false;
    event.parameter_hash_valid = false;
    event.signer_trusted = false;
    event.authorized = false;
    event.result = "untrusted caller label".into();
    assert_eq!(exporter.export_batch(&[event]).await.unwrap(), 1);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    let endpoints: std::collections::BTreeSet<_> = requests
        .iter()
        .map(|request| request.url.path().to_string())
        .collect();
    assert_eq!(
        endpoints,
        std::collections::BTreeSet::from(["/v2/enqueue".to_string(), "/v2/alerts".to_string(),])
    );
    for request in requests {
        let wire = String::from_utf8(request.body.clone()).unwrap();
        assert!(!wire.contains(SECRET));
        let payload: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let details = if request.url.path() == "/v2/enqueue" {
            assert_eq!(payload["payload"]["severity"], "critical");
            &payload["payload"]["custom_details"]
        } else {
            assert_eq!(payload["priority"], "P1");
            &payload["details"]
        };
        assert_eq!(details["receipt_id"], id);
        assert_eq!(details["parameter_hash"], hash);
        assert!(details.get("parameters").is_none());
        assert!(details.get("evidence").is_none());
        assert!(details.get("metadata").is_none());
    }
}

#[tokio::test]
async fn configured_pin_rechecks_every_receipt_component_and_ignores_public_flags() {
    let trusted = Keypair::generate();
    let attacker = Keypair::generate();
    let pins = vec![trusted.public_key()];
    let server = receiving_server().await;
    let exporter = receiving_exporter_builder(&server)
        .with_trusted_kernel_keys(pins)
        .build();
    let valid = signed_deny(&trusted);
    let untrusted = signed_deny(&attacker);
    assert!(untrusted.verify_signature().unwrap());
    assert!(untrusted.action.verify_hash().unwrap());
    let mut bad_signature = valid.clone();
    bad_signature.signature = attacker.sign(b"different message");
    assert!(!bad_signature.verify_signature().unwrap());
    assert_eq!(
        chio_receipt_id(&bad_signature.body()).unwrap(),
        bad_signature.id
    );
    let mut bad_id = valid.clone();
    bad_id.id = "forged-id".into();
    assert_ne!(chio_receipt_id(&bad_id.body()).unwrap(), bad_id.id);
    let mut body = valid.body();
    body.action.parameter_hash = "0".repeat(64);
    let bad_hash = ChioReceipt::sign(body, &trusted).unwrap();
    assert!(bad_hash.verify_signature().unwrap());
    assert_eq!(chio_receipt_id(&bad_hash.body()).unwrap(), bad_hash.id);
    assert!(!bad_hash.action.verify_hash().unwrap());
    // Mutate after event construction to exercise stale previously true flags.
    let trusted_hex = std::collections::BTreeSet::from([trusted.public_key().to_hex()]);
    let mut stale = SiemEvent::from_receipt_with_trusted_kernel_keys(valid, Some(&trusted_hex));
    assert!(stale.authoritative && stale.signer_trusted);
    stale.receipt = untrusted.clone();
    let events = vec![
        event_with_forged_flags(untrusted),
        event_with_forged_flags(bad_signature),
        event_with_forged_flags(bad_id),
        event_with_forged_flags(bad_hash),
        stale,
    ];
    assert_eq!(exporter.export_batch(&events).await.unwrap(), events.len());
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn mixed_batch_pages_only_valid_pinned_denial() {
    let trusted = Keypair::generate();
    let server = receiving_server().await;
    let exporter = receiving_exporter_builder(&server)
        .with_trusted_kernel_keys(vec![trusted.public_key()])
        .build();
    let valid = signed_deny(&trusted);
    let id = valid.id.clone();
    let mut tampered = valid.clone();
    tampered.id = "wrong-id".into();
    let events = vec![
        event_with_forged_flags(signed_deny(&Keypair::generate())),
        SiemEvent::from_receipt(valid),
        event_with_forged_flags(tampered),
    ];
    assert_eq!(exporter.export_batch(&events).await.unwrap(), 3);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests {
        let wire = String::from_utf8(request.body).unwrap();
        assert!(wire.contains(&id));
        assert!(!wire.contains("wrong-id"));
        assert!(!wire.contains(SECRET));
    }
}

// Independently signed with Python cryptography, ECDSA P-256/SHA-256, public
// test scalar 7. Canonical integer/string JSON was signed outside Chio; the
// execution evidence retains the generator, signing bytes and verification.
const P256_PIN: &str = "p256:048e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a373eb1dbde03318366d069f83a6f5900053c73633cb041b21c55e1a86c1f400b4";
const P256_RECEIPT: &str = r#"{
  "id": "0bc79cf44e8d9c2f296511d328080a353dd346a3c82ae3ec9699a2a86a51ccc0",
  "timestamp": 1700000001,
  "capability_id": "ev15-p256-fixture",
  "tool_server": "fixture",
  "tool_name": "test",
  "action": {
    "parameters": {
      "operation": "test-only"
    },
    "parameter_hash": "4c65c6b91b32097148a6e7b24752b95628230900421b5370d65dd8d05053f5eb"
  },
  "decision": {
    "verdict": "deny",
    "guard": "SecretLeakGuard",
    "reason": "fixture refusal"
  },
  "receipt_kind": "mediated_decision",
  "boundary_class": "prevent",
  "tool_origin": "caller_executed",
  "redaction_mode": "none",
  "content_hash": "f16d05ec6b29248d2c61adb1e9263f78e4f7bace1b955014a2d17872cfe4064d",
  "policy_hash": "57ccec5e5c18d08dc1f94b16a500d29307748a022709cf0291bc368b5f01178b",
  "trust_level": "mediated",
  "kernel_key": "p256:048e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a373eb1dbde03318366d069f83a6f5900053c73633cb041b21c55e1a86c1f400b4",
  "signature": "p256:304602210097339e29632f83af89ef1a9511f3af24bc72dbcbaa22823613fddc3313d5a75c022100e317fb64ed4d43d72f5dad9da28f3babafcc3763056d0fa8e5401e25b18fba67",
  "algorithm": "p256"
}"#;

#[tokio::test]
#[ignore = "requires: cargo test -p chio-siem --features chio-core/fips --test alerting_dispatch authentication::pinned_p256_receipt_pages -- --ignored"]
async fn pinned_p256_receipt_pages() {
    let pin = chio_core::crypto::PublicKey::from_hex(P256_PIN).unwrap();
    let server = receiving_server().await;
    let exporter = receiving_exporter_builder(&server)
        .with_trusted_kernel_keys(vec![pin])
        .build();
    let receipt: ChioReceipt = serde_json::from_str(P256_RECEIPT).unwrap();
    assert_eq!(chio_receipt_id(&receipt.body()).unwrap(), receipt.id);
    assert!(receipt.action.verify_hash().unwrap());
    assert!(
        receipt.verify_signature().unwrap(),
        "P-256 verifier feature must be enabled"
    );
    assert_eq!(
        exporter
            .export_batch(&[SiemEvent::from_receipt(receipt)])
            .await
            .unwrap(),
        1
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn nonverifying_p256_signature_never_pages() {
    let pin = chio_core::crypto::PublicKey::from_hex(P256_PIN).unwrap();
    let server = receiving_server().await;
    let exporter = receiving_exporter_builder(&server)
        .with_trusted_kernel_keys(vec![pin])
        .build();
    let mut receipt: ChioReceipt = serde_json::from_str(P256_RECEIPT).unwrap();
    receipt.signature = chio_core::crypto::Signature::from_p256_der(&[0]);
    assert!(!receipt.verify_signature().unwrap());
    assert_eq!(
        exporter
            .export_batch(&[event_with_forged_flags(receipt)])
            .await
            .unwrap(),
        1
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}
