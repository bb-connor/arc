// Integration tests for SplunkHecExporter against a wiremock mock server.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use arc_core::crypto::Keypair;
use arc_core::receipt::{
    ArcReceipt, ArcReceiptBody, Decision, FinancialReceiptMetadata, SettlementStatus,
    ToolCallAction,
};
use arc_siem::event::SiemEvent;
use arc_siem::exporter::ExportError;
use arc_siem::exporters::splunk::{SplunkConfig, SplunkHecExporter};
use arc_siem::Exporter;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// -- Helpers ------------------------------------------------------------------

fn sample_receipt(id: &str) -> ArcReceipt {
    let keypair = Keypair::generate();
    ArcReceipt::sign(
        ArcReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_000,
            capability_id: "cap-splunk-test".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: ToolCallAction {
                parameters: serde_json::json!({"cmd": "ls"}),
                parameter_hash: "abc123".to_string(),
            },
            decision: Decision::Allow,
            content_hash: "content-hash-test".to_string(),
            policy_hash: "policy-hash-test".to_string(),
            evidence: Vec::new(),
            metadata: None,
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .expect("ArcReceipt::sign must succeed in tests")
}

fn sample_receipt_with_financial(id: &str) -> ArcReceipt {
    let keypair = Keypair::generate();
    let financial = FinancialReceiptMetadata {
        grant_index: 0,
        cost_charged: 500,
        currency: "USD".to_string(),
        budget_remaining: 9_500,
        budget_total: 10_000,
        delegation_depth: 1,
        root_budget_holder: "org-root".to_string(),
        payment_reference: None,
        settlement_status: SettlementStatus::Pending,
        cost_breakdown: None,
        attempted_cost: None,
    };
    let metadata = serde_json::json!({
        "financial": serde_json::to_value(&financial).expect("financial metadata serializes")
    });
    ArcReceipt::sign(
        ArcReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_001,
            capability_id: "cap-splunk-financial".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: ToolCallAction {
                parameters: serde_json::json!({"cmd": "echo hi"}),
                parameter_hash: "def456".to_string(),
            },
            decision: Decision::Allow,
            content_hash: "content-hash-financial".to_string(),
            policy_hash: "policy-hash-financial".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .expect("ArcReceipt::sign must succeed in tests")
}

// -- Tests --------------------------------------------------------------------

/// SplunkHecExporter sends correctly formatted event envelopes and receives 200 OK.
#[tokio::test]
async fn splunk_hec_sends_correct_envelope() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/services/collector/event"))
        .and(header("Authorization", "Splunk test-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(r#"{"text":"Success","code":0}"#, "application/json"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let config = SplunkConfig {
        endpoint: server.uri(),
        hec_token: "test-token".to_string(),
        sourcetype: "arc:receipt".to_string(),
        index: None,
        host: None,
    };
    // Use plaintext constructor -- wiremock runs on plain http:// for tests.
    let exporter = SplunkHecExporter::new_plaintext_for_tests(config).expect("exporter builds");

    let receipt1 = sample_receipt("splunk-rcpt-001");
    let receipt2 = sample_receipt_with_financial("splunk-rcpt-002");
    let events = vec![
        SiemEvent::from_receipt(receipt1),
        SiemEvent::from_receipt(receipt2),
    ];

    let result = exporter.export_batch(&events).await;
    assert!(result.is_ok(), "export_batch should return Ok: {result:?}");
    assert_eq!(result.unwrap(), 2, "should report 2 events exported");

    // Verify the request body: one HTTP request containing 2 JSON objects (newline-separated).
    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1, "should receive exactly 1 HTTP request");

    let body_str = String::from_utf8(received[0].body.clone()).expect("body is valid UTF-8");
    let lines: Vec<&str> = body_str.split('\n').filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        2,
        "should have 2 newline-separated JSON objects in payload"
    );

    // Parse first object: plain receipt (no financial metadata).
    let obj0: serde_json::Value = serde_json::from_str(lines[0]).expect("line 0 is valid JSON");
    assert!(
        obj0.get("time").and_then(|v| v.as_f64()).is_some(),
        "time field must be a number"
    );
    assert_eq!(
        obj0.get("sourcetype").and_then(|v| v.as_str()),
        Some("arc:receipt"),
        "sourcetype must be arc:receipt"
    );
    let event0 = obj0.get("event").expect("event field must exist");
    assert_eq!(
        event0.get("id").and_then(|v| v.as_str()),
        Some("splunk-rcpt-001"),
        "event.id must match receipt id"
    );

    // Parse second object: receipt with financial metadata.
    let obj1: serde_json::Value = serde_json::from_str(lines[1]).expect("line 1 is valid JSON");
    let event1 = obj1.get("event").expect("event field must exist");
    assert_eq!(
        event1.get("id").and_then(|v| v.as_str()),
        Some("splunk-rcpt-002"),
        "event.id must match receipt id"
    );
    let cost = event1
        .get("metadata")
        .and_then(|m| m.get("financial"))
        .and_then(|f| f.get("cost_charged"))
        .and_then(|c| c.as_u64());
    assert_eq!(cost, Some(500), "financial.cost_charged must be 500");
}

/// SplunkHecExporter returns ExportError::HttpError when the server responds 401.
#[tokio::test]
async fn splunk_hec_returns_error_on_401() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/services/collector/event"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_raw(r#"{"text":"Invalid token","code":4}"#, "application/json"),
        )
        .mount(&server)
        .await;

    let config = SplunkConfig {
        endpoint: server.uri(),
        hec_token: "bad-token".to_string(),
        sourcetype: "arc:receipt".to_string(),
        index: None,
        host: None,
    };
    // Use plaintext constructor -- wiremock runs on plain http:// for tests.
    let exporter = SplunkHecExporter::new_plaintext_for_tests(config).expect("exporter builds");

    let events = vec![SiemEvent::from_receipt(sample_receipt("splunk-rcpt-401"))];
    let result = exporter.export_batch(&events).await;

    assert!(result.is_err(), "export_batch should return Err for 401");
    match result.unwrap_err() {
        ExportError::HttpError(msg) => {
            assert!(
                msg.contains("401"),
                "HttpError message should contain '401', got: {msg}"
            );
        }
        other => panic!("expected ExportError::HttpError, got: {other:?}"),
    }
}

/// SplunkHecExporter::new rejects plaintext http:// endpoints to protect HEC tokens.
#[test]
fn splunk_hec_rejects_plaintext_http_endpoint() {
    let config = SplunkConfig {
        endpoint: "http://splunk.example.com:8088".to_string(),
        hec_token: "secret-token".to_string(),
        sourcetype: "arc:receipt".to_string(),
        index: None,
        host: None,
    };
    let result = SplunkHecExporter::new(config);
    assert!(
        result.is_err(),
        "SplunkHecExporter::new must reject http:// endpoints"
    );
    match result.err().expect("checked is_err above") {
        ExportError::HttpError(msg) => {
            assert!(
                msg.contains("https://"),
                "error message should mention https://, got: {msg}"
            );
        }
        other => panic!("expected ExportError::HttpError, got: {other:?}"),
    }
}

/// SplunkHecExporter::new accepts https:// endpoints (build-time check only; no network call).
#[test]
fn splunk_hec_accepts_https_endpoint() {
    let config = SplunkConfig {
        endpoint: "https://splunk.example.com:8088".to_string(),
        hec_token: "secret-token".to_string(),
        sourcetype: "arc:receipt".to_string(),
        index: None,
        host: None,
    };
    // Construction should succeed; no network call is made here.
    let result = SplunkHecExporter::new(config);
    assert!(
        result.is_ok(),
        "SplunkHecExporter::new must accept https:// endpoints"
    );
}
