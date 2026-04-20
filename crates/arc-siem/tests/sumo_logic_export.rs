// Integration tests for SumoLogicExporter against a wiremock mock server.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use arc_core::crypto::Keypair;
use arc_core::receipt::{ArcReceipt, ArcReceiptBody, Decision, ToolCallAction};
use arc_siem::event::SiemEvent;
use arc_siem::exporters::sumo_logic::{SumoLogicConfig, SumoLogicExporter, SumoLogicFormat};
use arc_siem::Exporter;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn sample_receipt(id: &str) -> ArcReceipt {
    let keypair = Keypair::generate();
    ArcReceipt::sign(
        ArcReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_000,
            capability_id: "cap-sumo".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"cmd": "ls"}))
                .expect("action parameters serialize"),
            decision: Decision::Allow,
            content_hash: "c".to_string(),
            policy_hash: "p".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: arc_core::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .expect("sign")
}

#[tokio::test]
async fn sumo_json_posts_ndjson_with_sumo_headers() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/receiver"))
        .and(header("Content-Type", "application/json"))
        .and(header("X-Sumo-Category", "security/arc"))
        .and(header("X-Sumo-Name", "arc"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let config = SumoLogicConfig {
        http_source_url: format!("{}/receiver", server.uri()),
        source_category: "security/arc".to_string(),
        source_name: "arc".to_string(),
        source_host: Some("test-host".to_string()),
        format: SumoLogicFormat::Json,
        ..SumoLogicConfig::default()
    };
    let exporter = SumoLogicExporter::new_plaintext_for_tests(config).expect("builds");

    let events = vec![
        SiemEvent::from_receipt(sample_receipt("sumo-001")),
        SiemEvent::from_receipt(sample_receipt("sumo-002")),
    ];
    let result = exporter.export_batch(&events).await;
    assert!(result.is_ok(), "export_batch ok: {result:?}");
    assert_eq!(result.unwrap(), 2);

    let received = server.received_requests().await.unwrap();
    let body = String::from_utf8(received[0].body.clone()).expect("utf8");
    let lines: Vec<&str> = body.split('\n').filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 2, "should be 2 NDJSON lines");
    let parsed: serde_json::Value = serde_json::from_str(lines[0]).expect("valid json");
    assert_eq!(
        parsed
            .get("receipt")
            .and_then(|r| r.get("id"))
            .and_then(|v| v.as_str()),
        Some("sumo-001")
    );
}

#[tokio::test]
async fn sumo_keyvalue_emits_kv_lines() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/receiver"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let config = SumoLogicConfig {
        http_source_url: format!("{}/receiver", server.uri()),
        format: SumoLogicFormat::KeyValue,
        ..SumoLogicConfig::default()
    };
    let exporter = SumoLogicExporter::new_plaintext_for_tests(config).expect("builds");
    let events = vec![SiemEvent::from_receipt(sample_receipt("sumo-kv-1"))];
    let _ = exporter.export_batch(&events).await.expect("ok");

    let received = server.received_requests().await.unwrap();
    let body = String::from_utf8(received[0].body.clone()).expect("utf8");
    assert!(body.contains("receipt_id=sumo-kv-1"));
    assert!(body.contains("decision=allow"));
}

#[tokio::test]
async fn sumo_rejects_plaintext_http_in_production_new() {
    let cfg = SumoLogicConfig {
        http_source_url: "http://collectors.sumologic.com/receiver/v1/xyz".to_string(),
        ..SumoLogicConfig::default()
    };
    assert!(SumoLogicExporter::new(cfg).is_err());
}
