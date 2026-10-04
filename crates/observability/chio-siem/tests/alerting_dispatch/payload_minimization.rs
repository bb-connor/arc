//! Sensitive denied inputs must not become paging payloads.
use super::*;

#[tokio::test]
async fn p0p1_paging_omits_arguments_denial_text_evidence_and_metadata() {
    const SECRET: &str = "blocked-secret-sentinel-71a9";
    let server = MockServer::start().await;
    for endpoint in ["/v2/enqueue", "/v2/alerts"] {
        Mock::given(method("POST"))
            .and(path(endpoint))
            .respond_with(ResponseTemplate::new(202))
            .expect(1)
            .mount(&server)
            .await;
    }
    let authority = test_server_authority(&server);
    let exporter = AlertingExporter::builder(AlertingConfig::default())
        .with_backend(Box::new(
            PagerDutyBackend::with_endpoint_and_contract(
                "routing-key".into(),
                server.uri(),
                HttpEgressContract::permissive_for_tests(&authority),
            )
            .unwrap(),
        ))
        .with_backend(Box::new(
            OpsGenieBackend::with_endpoint_and_contract(
                "api-key".into(),
                server.uri(),
                HttpEgressContract::permissive_for_tests(&authority),
            )
            .unwrap(),
        ))
        .build();
    let key = Keypair::generate();
    let mut body = deny_receipt("private", "SecretLeakGuard").body();
    body.action = ToolCallAction::from_parameters(serde_json::json!({"token":SECRET})).unwrap();
    body.decision = Some(Decision::Deny {
        guard: "SecretLeakGuard".into(),
        reason: SECRET.into(),
    });
    body.evidence[0].details = Some(SECRET.into());
    body.metadata = Some(serde_json::json!({"request":SECRET}));
    body.kernel_key = key.public_key();
    let receipt = ChioReceipt::sign(body, &key).unwrap();
    let receipt_id = receipt.id.clone();
    let parameter_hash = receipt.action.parameter_hash.clone();
    let event = SiemEvent::from_receipt(receipt);
    assert_eq!(exporter.export_batch(&[event]).await.unwrap(), 1);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    for request in requests {
        let wire = String::from_utf8(request.body.clone()).unwrap();
        assert!(
            !wire.contains(SECRET),
            "{} leaked blocked content",
            request.url.path()
        );
        let payload: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let details = if request.url.path() == "/v2/enqueue" {
            assert_eq!(payload["payload"]["severity"], "critical");
            &payload["payload"]["custom_details"]
        } else {
            assert_eq!(payload["priority"], "P1");
            &payload["details"]
        };
        assert_eq!(details["receipt_id"], receipt_id);
        assert_eq!(details["parameter_hash"], parameter_hash);
        assert!(details.get("parameters").is_none());
        assert!(details.get("evidence").is_none());
        assert!(details.get("metadata").is_none());
    }
}
