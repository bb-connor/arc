//! Real HTTP responses must carry an unambiguous and complete guard decision.
use chio_external_guards::external::*;
use chio_kernel::Verdict;
use wiremock::matchers::any;
use wiremock::{Mock, MockServer, ResponseTemplate};

fn guard(kind: usize, endpoint: &str) -> Result<Box<dyn ExternalGuard>, ExternalGuardError> {
    Ok(match kind {
        0 => Box::new(BedrockGuardrailGuard::new(
            BedrockGuardrailConfig::new("token", "region", "guard", "1").with_endpoint(endpoint),
        )?),
        1 => Box::new(AzureContentSafetyGuard::new(
            AzureContentSafetyConfig::new("token", endpoint),
        )?),
        2 => Box::new(VertexSafetyGuard::new(
            VertexSafetyConfig::new("token", "project", "location", "model")
                .with_endpoint(endpoint),
        )?),
        3 => Box::new(VirusTotalGuard::new(
            VirusTotalConfig::new("token").with_base_url(endpoint),
        )?),
        4 => Box::new(SnykGuard::new(
            SnykConfig::new("token", "org").with_base_url(endpoint),
        )?),
        _ => Box::new(SafeBrowsingGuard::new(
            SafeBrowsingConfig::new("token").with_base_url(endpoint),
        )?),
    })
}

fn context() -> GuardCallContext {
    GuardCallContext {
        arguments_json:
            r#"{"url":"https://example.com","package":"p","version":"1","ecosystem":"npm"}"#.into(),
        ..Default::default()
    }
}

#[tokio::test]
async fn original_response_duplicates_reject_before_all_six_provider_projections(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(r#"{"ignored":{"sentinel-private":1,"sentinel-private":2}}"#),
        )
        .mount(&server)
        .await;
    for kind in 0..6 {
        let error = match guard(kind, &server.uri())?.eval(&context()).await {
            Err(error) => error,
            Ok(verdict) => panic!("ambiguous input produced {verdict:?}"),
        };
        assert!(matches!(error, ExternalGuardError::InvalidResponse(_)));
        assert!(!format!("{error:?} {error}").contains("sentinel-private"));
        assert!(std::error::Error::source(&error).is_some());
    }
    Ok(())
}

#[tokio::test]
async fn missing_guard_verdicts_cannot_become_allow() -> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
        .mount(&server)
        .await;
    for kind in 0..5 {
        assert!(matches!(
            guard(kind, &server.uri())?.eval(&context()).await,
            Err(ExternalGuardError::InvalidResponse(_) | ExternalGuardError::Permanent(_))
        ));
    }
    // Safe Browsing's empty matches document is its explicit no-threat response.
    assert_eq!(
        guard(5, &server.uri())?.eval(&context()).await?,
        Verdict::Allow
    );
    Ok(())
}

#[tokio::test]
async fn unknown_bedrock_action_and_vertex_probability_reject(
) -> Result<(), Box<dyn std::error::Error>> {
    for (kind, body) in [
        (0, r#"{"action":"unexpected"}"#),
        (
            2,
            r#"{"candidates":[{"safetyRatings":[{"category":"harm","probability":"NEW_UNKNOWN"}]}]}"#,
        ),
        (
            1,
            r#"{"categoriesAnalysis":[{"category":"Hate","severity":0}]}"#,
        ),
    ] {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        assert!(matches!(
            guard(kind, &server.uri())?.eval(&context()).await,
            Err(ExternalGuardError::Permanent(_))
        ));
    }
    Ok(())
}

#[tokio::test]
async fn explicit_vertex_blocks_override_low_probabilities(
) -> Result<(), Box<dyn std::error::Error>> {
    for candidate in [
        r#"{"finishReason":"SAFETY","safetyRatings":[{"category":"harm","probability":"LOW"}]}"#,
        r#"{"finishReason":"STOP","safetyRatings":[{"category":"harm","probability":"LOW","blocked":true}]}"#,
    ] {
        let server = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(format!("{{\"candidates\":[{candidate}]}}")),
            )
            .mount(&server)
            .await;
        assert_eq!(
            guard(2, &server.uri())?.eval(&context()).await?,
            Verdict::Deny
        );
    }
    Ok(())
}

#[tokio::test]
async fn invalid_arguments_cannot_reuse_an_allow_cache_key_or_make_a_request(
) -> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start().await;
    for kind in 3..6 {
        let guard = guard(kind, &server.uri())?;
        let ctx = GuardCallContext {
            arguments_json: r#"{"url":"first","url":"second"}"#.into(),
            ..Default::default()
        };
        assert_eq!(guard.cache_key(&ctx), None);
        assert!(matches!(
            guard.eval(&ctx).await,
            Err(ExternalGuardError::InvalidInput(_))
        ));
    }
    assert_eq!(
        server
            .received_requests()
            .await
            .ok_or("request capture missing")?
            .len(),
        0
    );
    Ok(())
}

#[tokio::test]
async fn http_failure_does_not_expose_response_body() -> Result<(), Box<dyn std::error::Error>> {
    let server = MockServer::start().await;
    Mock::given(any())
        .respond_with(ResponseTemplate::new(500).set_body_string("sentinel-private"))
        .mount(&server)
        .await;
    for kind in 0..6 {
        let error = match guard(kind, &server.uri())?.eval(&context()).await {
            Err(error) => error,
            Ok(_) => return Err("HTTP failure accepted".into()),
        };
        assert!(matches!(error, ExternalGuardError::Transient(_)));
        assert!(!format!("{error:?} {error}").contains("sentinel-private"));
    }
    Ok(())
}
