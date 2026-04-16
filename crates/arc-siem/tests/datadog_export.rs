// Integration tests for DatadogExporter against a wiremock mock server.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use arc_core::crypto::Keypair;
use arc_core::receipt::{ArcReceipt, ArcReceiptBody, Decision, GuardEvidence, ToolCallAction};
use arc_siem::event::SiemEvent;
use arc_siem::exporter::ExportError;
use arc_siem::exporters::datadog::{DatadogConfig, DatadogExporter};
use arc_siem::Exporter;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn allow_receipt(id: &str) -> ArcReceipt {
    let keypair = Keypair::generate();
    ArcReceipt::sign(
        ArcReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_000,
            capability_id: "cap-dd-allow".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: ToolCallAction {
                parameters: serde_json::json!({"cmd": "ls"}),
                parameter_hash: "h1".to_string(),
            },
            decision: Decision::Allow,
            content_hash: "c1".to_string(),
            policy_hash: "p1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: arc_core::TrustLevel::default(),
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .expect("sign allow")
}

fn deny_receipt(id: &str, guard: &str) -> ArcReceipt {
    let keypair = Keypair::generate();
    ArcReceipt::sign(
        ArcReceiptBody {
            id: id.to_string(),
            timestamp: 1_700_000_001,
            capability_id: "cap-dd-deny".to_string(),
            tool_server: "shell".to_string(),
            tool_name: "bash".to_string(),
            action: ToolCallAction {
                parameters: serde_json::json!({"cmd": "cat /etc/shadow"}),
                parameter_hash: "h2".to_string(),
            },
            decision: Decision::Deny {
                reason: "file not permitted".to_string(),
                guard: guard.to_string(),
            },
            content_hash: "c2".to_string(),
            policy_hash: "p2".to_string(),
            evidence: vec![GuardEvidence {
                guard_name: guard.to_string(),
                verdict: false,
                details: Some("forbidden path match".to_string()),
            }],
            metadata: None,
            trust_level: arc_core::TrustLevel::default(),
            kernel_key: keypair.public_key(),
        },
        &keypair,
    )
    .expect("sign deny")
}

#[tokio::test]
async fn datadog_posts_log_array_with_api_key_header() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v2/logs"))
        .and(header("DD-API-KEY", "dd-key-test"))
        .and(header("Content-Type", "application/json"))
        .respond_with(ResponseTemplate::new(202))
        .expect(1)
        .mount(&server)
        .await;

    let config = DatadogConfig {
        api_key: "dd-key-test".to_string(),
        site: "datadoghq.com".to_string(),
        service: "arc".to_string(),
        source: "arc".to_string(),
        tags: vec!["env:test".to_string()],
        hostname: Some("test-host".to_string()),
        ..DatadogConfig::default()
    };
    let exporter =
        DatadogExporter::new_with_base_url_for_tests(config, &server.uri()).expect("builds");

    let events = vec![
        SiemEvent::from_receipt(allow_receipt("dd-001")),
        SiemEvent::from_receipt(deny_receipt("dd-002", "ForbiddenPathGuard")),
    ];

    let result = exporter.export_batch(&events).await;
    assert!(result.is_ok(), "export_batch ok: {result:?}");
    assert_eq!(result.unwrap(), 2);

    let received = server.received_requests().await.unwrap();
    assert_eq!(received.len(), 1);
    let body: serde_json::Value = serde_json::from_slice(&received[0].body).expect("json");
    let arr = body.as_array().expect("array");
    assert_eq!(arr.len(), 2);

    // First entry is an allow.
    assert_eq!(arr[0].get("status").and_then(|v| v.as_str()), Some("info"));
    assert_eq!(arr[0].get("ddsource").and_then(|v| v.as_str()), Some("arc"));
    assert_eq!(arr[0].get("service").and_then(|v| v.as_str()), Some("arc"));
    let tags0 = arr[0]
        .get("ddtags")
        .and_then(|v| v.as_str())
        .expect("ddtags str");
    assert!(tags0.contains("env:test"));
    assert!(tags0.contains("outcome:allow"));

    // Second entry is a deny on a High-severity guard.
    assert_eq!(arr[1].get("status").and_then(|v| v.as_str()), Some("error"));
    let tags1 = arr[1]
        .get("ddtags")
        .and_then(|v| v.as_str())
        .expect("ddtags str");
    assert!(tags1.contains("outcome:deny"));
    assert!(tags1.contains("severity:high"));
    assert!(tags1.contains("guard:ForbiddenPathGuard"));
    assert!(tags1.contains("evidence_guard:ForbiddenPathGuard"));
}

#[tokio::test]
async fn datadog_returns_http_error_on_500() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v2/logs"))
        .respond_with(ResponseTemplate::new(500).set_body_raw("upstream", "text/plain"))
        .mount(&server)
        .await;

    let config = DatadogConfig {
        api_key: "dd-key".to_string(),
        ..DatadogConfig::default()
    };
    let exporter =
        DatadogExporter::new_with_base_url_for_tests(config, &server.uri()).expect("builds");

    let events = vec![SiemEvent::from_receipt(allow_receipt("dd-500"))];
    let result = exporter.export_batch(&events).await;

    match result.unwrap_err() {
        ExportError::HttpError(msg) => {
            assert!(msg.contains("500"), "should mention 500, got {msg}");
        }
        other => panic!("expected HttpError, got {other:?}"),
    }
}

#[tokio::test]
async fn datadog_rejects_empty_api_key() {
    let config = DatadogConfig {
        api_key: "".to_string(),
        ..DatadogConfig::default()
    };
    assert!(DatadogExporter::new(config).is_err());
}
