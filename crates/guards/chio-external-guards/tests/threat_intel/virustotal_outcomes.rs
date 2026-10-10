#![cfg(test)]
use super::*;
use chio_external_guards::external::{CircuitOpenVerdict, CircuitState, VirusTotalUnseenPolicy};

#[tokio::test]
async fn definitive_unseen_results_are_cached_without_opening_the_failure_circuit(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("^/urls/"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {"code": "NotFoundError", "message": "URL not found"}
        })))
        .expect(6)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/files/{KNOWN_BAD_HASH}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0}}}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let guard = VirusTotalGuard::new(VirusTotalConfig::new("vt-key").with_base_url(server.uri()))?;
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 100)
        .cache_ttl(Duration::from_secs(30))
        .build();
    for number in 0..6 {
        let ctx = make_ctx(
            "visit",
            json!({"url": format!("https://unseen.example/{number}")}),
        );
        assert_eq!(adapter.evaluate(&ctx).await, Verdict::Deny);
        assert_eq!(adapter.evaluate(&ctx).await, Verdict::Deny);
        assert_eq!(adapter.circuit_state(), CircuitState::Closed);
    }
    assert_eq!(
        adapter
            .evaluate(&make_ctx("scan", json!({"hash": KNOWN_BAD_HASH})))
            .await,
        Verdict::Allow
    );
    Ok(())
}

#[tokio::test]
async fn provider_failures_still_deny_and_open_the_configured_failure_circuit(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401).set_body_json(json!({
            "error": {"code": "AuthenticationRequiredError", "message": "private-provider-detail"}
        })))
        .expect(5)
        .mount(&server)
        .await;
    let guard = VirusTotalGuard::new(VirusTotalConfig::new("vt-key").with_base_url(server.uri()))?;
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 100)
        .build();
    for number in 0..6 {
        assert_eq!(
            adapter
                .evaluate(&make_ctx(
                    "visit",
                    json!({"url": format!("https://failure.example/{number}")})
                ))
                .await,
            Verdict::Deny
        );
    }
    assert_eq!(adapter.circuit_state(), CircuitState::Open);
    Ok(())
}

#[tokio::test]
async fn explicit_unseen_allow_cannot_bypass_a_later_malicious_result(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex("^/urls/"))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({
            "error": {"code": "NotFoundError", "message": "not found"}
        })))
        .expect(6)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/files/{KNOWN_BAD_HASH}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"attributes": {"last_analysis_stats": {"malicious": 45, "suspicious": 3}}}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let guard = VirusTotalGuard::new(
        VirusTotalConfig::new("vt-key")
            .with_base_url(server.uri())
            .with_unseen_policy(VirusTotalUnseenPolicy::Allow),
    )?;
    let adapter = AsyncGuardAdapter::builder(Arc::new(guard))
        .retry(fast_retry())
        .rate_limit(100.0, 100)
        .circuit_open_verdict(CircuitOpenVerdict::Allow)
        .build();
    for number in 0..6 {
        let ctx = make_ctx(
            "visit",
            json!({"url": format!("https://unseen.example/{number}")}),
        );
        assert_eq!(adapter.evaluate(&ctx).await, Verdict::Allow);
        assert_eq!(adapter.circuit_state(), CircuitState::Closed);
    }
    assert_eq!(
        adapter
            .evaluate(&make_ctx("scan", json!({"hash": KNOWN_BAD_HASH})))
            .await,
        Verdict::Deny
    );
    Ok(())
}

#[tokio::test]
async fn unseen_allow_requires_the_bounded_documented_error_shape(
) -> Result<(), Box<dyn std::error::Error>> {
    let unseen = r#"{"error":{"code":"NotFoundError","message":"private-provider-detail"}}"#;
    for (status, body) in [
        (404, "not found".to_owned()),
        (404, r#"{"error":{"code":"NotFoundError"}}"#.to_owned()),
        (404, r#"{"error":{"code":"OtherError","message":"private-provider-detail"}}"#.to_owned()),
        (404, r#"{"error":{"code":"OtherError","code":"NotFoundError","message":"private-provider-detail"}}"#.to_owned()),
        (404, r#"{"error":{"code":"NotFoundError","message":false}}"#.to_owned()),
        (404, r#"{"error":{"code":"NotFoundError","message":"private-provider-detail"},"data":{}}"#.to_owned()),
        (404, format!(r#"{{"error":{{"code":"NotFoundError","message":"{}"}}}}"#, "x".repeat(1024 * 1024))),
        (401, unseen.to_owned()), (429, unseen.to_owned()), (500, unseen.to_owned()),
        (200, unseen.to_owned()),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(status).set_body_raw(body, "application/json"))
            .expect(1).mount(&server).await;
        let guard = VirusTotalGuard::new(VirusTotalConfig::new("vt-key")
            .with_base_url(server.uri()).with_unseen_policy(VirusTotalUnseenPolicy::Allow))?;
        let result = guard.eval(&make_ctx("scan", json!({"hash": KNOWN_BAD_HASH}))).await;
        let Err(error) = result else { panic!("status {status} incorrectly became a policy decision") };
        assert!(!error.to_string().contains("private-provider-detail"));
    }
    Ok(())
}
