//! Exercise the shipped router, including method selection and retained stores.
use super::*;
use axum::body::Body;
use axum::http::Request;
use tower::ServiceExt;

#[path = "ingress_tests/authentication.rs"]
mod authentication;

#[path = "ingress_tests/wallet_credentials.rs"]
mod wallet_credentials;

fn certification() -> Result<SignedCertificationCheck, Box<dyn std::error::Error>> {
    let body: crate::certify::CertificationCheckBody = serde_json::from_value(serde_json::json!({
        "schema": "chio.certify.check.v1",
        "criteriaProfile": "conformance-all-pass-v1",
        "checkedAt": 1,
        "target": { "toolServerId": "ingress-tool" },
        "verdict": "pass",
        "summary": {
            "scenarioCount": 1, "resultCount": 1, "evaluatedPeerCount": 1,
            "passCount": 1, "failCount": 0, "unsupportedCount": 0,
            "skippedCount": 0, "xfailCount": 0, "missingScenariosCount": 0,
            "unknownResultsCount": 0
        },
        "criteria": [], "findings": [],
        "evidence": {
            "evidenceProfile": "conformance-report-bundle-v1",
            "scenariosDir": "scenarios", "resultsDir": "results",
            "normalizedScenariosSha256": "a".repeat(64),
            "normalizedResultsSha256": "b".repeat(64),
            "generatedReportSha256": "c".repeat(64), "generatedReportBytes": 1,
            "generatedReportMediaType": "text/markdown", "provenanceMode": "artifact-signer-key"
        }
    }))?;
    let signer = Keypair::from_seed(&[74; 32]);
    let (signature, _) = signer.sign_canonical(&body)?;
    Ok(SignedCertificationCheck {
        body,
        signer_public_key: signer.public_key(),
        signature,
    })
}

fn policy() -> Result<SignedPassportVerifierPolicy, Box<dyn std::error::Error>> {
    Ok(chio_credentials::create_signed_passport_verifier_policy(
        &Keypair::from_seed(&[75; 32]),
        "ingress-policy",
        "https://verifier.example",
        1,
        u64::MAX,
        PassportVerifierPolicy {
            min_composite_score: Some(0.1),
            ..Default::default()
        },
    )?)
}

async fn send(
    router: &Router,
    method: &str,
    path: &str,
    content_type: &str,
    token: &str,
    body: String,
) -> Result<Response, Box<dyn std::error::Error>> {
    Ok(router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header(CONTENT_TYPE, content_type)
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::from(body))?,
        )
        .await?)
}

#[tokio::test]
async fn ingress_certification_rejects_duplicate_original_keys_without_store_changes(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("certifications.json");
    let mut state = metrics_state("service-secret");
    state.config.certification_registry_file = Some(path.clone());
    let router = super::super::build_router(state);
    let honest = serde_json::to_string(&certification()?)?;
    let response = send(
        &router,
        "POST",
        CERTIFICATIONS_PATH,
        "application/json",
        "service-secret",
        honest.clone(),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let before = std::fs::read(&path)?;
    let duplicates = [
        honest.replacen('{', "{\"ignored\":1,\"ignored\":2,", 1),
        honest.replace("\"target\":{", "\"target\":{\"ignored\":1,\"ignored\":2,"),
    ];
    for body in duplicates {
        let response = send(
            &router,
            "POST",
            CERTIFICATIONS_PATH,
            "application/json",
            "service-secret",
            body,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(std::fs::read(&path)?, before);
    }
    Ok(())
}

#[tokio::test]
async fn ingress_nested_routers_preserve_original_input_validation(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("nested-certifications.json");
    let mut state = metrics_state("service-secret");
    state.config.certification_registry_file = Some(path.clone());
    let inner = Router::new().nest("/{tenant}", super::super::build_router(state));
    let router = Router::new().nest("/mounted", inner);
    let uri = format!("/mounted/team{CERTIFICATIONS_PATH}");
    let honest = serde_json::to_string(&certification()?)?;
    let response = send(
        &router,
        "POST",
        &uri,
        "application/json",
        "service-secret",
        honest.clone(),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let before = std::fs::read(&path)?;
    let duplicate = honest.replacen('{', "{\"ignored\":1,\"ignored\":2,", 1);
    let response = send(
        &router,
        "POST",
        &uri,
        "application/json",
        "service-secret",
        duplicate,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(std::fs::read(&path)?, before);
    Ok(())
}

#[tokio::test]
async fn ingress_verifier_policy_rejects_lossy_numbers_and_invalid_signatures_without_writes(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("policies.json");
    let mut state = metrics_state("service-secret");
    state.config.verifier_policies_file = Some(path.clone());
    let router = super::super::build_router(state);
    let uri = PASSPORT_VERIFIER_POLICY_PATH.replace("{policy_id}", "ingress-policy");
    let honest = serde_json::to_string(&policy()?)?;
    assert!(honest.contains("\"minCompositeScore\":0.1"));
    let response = send(
        &router,
        "PUT",
        &uri,
        "application/json",
        "service-secret",
        honest.clone(),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let before = std::fs::read(&path)?;
    for body in [
        honest.replace(
            "\"minCompositeScore\":0.1",
            "\"minCompositeScore\":0.10000000000000001",
        ),
        honest.replace("\"minCompositeScore\":0.1", "\"minCompositeScore\":0.10"),
        honest.replace("https://verifier.example", "https://attacker.example"),
    ] {
        let response = send(
            &router,
            "PUT",
            &uri,
            "application/json",
            "service-secret",
            body,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(std::fs::read(&path)?, before);
    }
    Ok(())
}

#[tokio::test]
async fn ingress_router_preserves_media_auth_method_and_enforces_body_bound(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("certifications.json");
    let mut state = metrics_state("service-secret");
    state.config.certification_registry_file = Some(path.clone());
    let router = super::super::build_router(state);
    let honest = serde_json::to_string(&certification()?)?;
    for (method, media, token, body, expected) in [
        (
            "POST",
            "application/json",
            "wrong-token",
            honest.clone(),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "PUT",
            "application/json",
            "service-secret",
            honest.clone(),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            "POST",
            "text/plain",
            "service-secret",
            honest.clone(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        (
            "POST",
            "application/json",
            "service-secret",
            "{".to_owned(),
            StatusCode::BAD_REQUEST,
        ),
        (
            "POST",
            "application/json",
            "service-secret",
            format!("{}{honest}", " ".repeat(1024 * 1024)),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ] {
        let response = send(&router, method, CERTIFICATIONS_PATH, media, token, body).await?;
        assert_eq!(response.status(), expected);
        assert!(!path.exists(), "refused request created a registry");
    }
    let response = send(
        &router,
        "POST",
        CERTIFICATIONS_PATH,
        "application/vnd.chio+json",
        "service-secret",
        honest,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(CertificationRegistry::load(&path)?.artifacts.len(), 1);
    Ok(())
}

#[tokio::test]
async fn ingress_nested_signed_certification_is_checked_before_network_dispatch(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("network.json");
    crate::enterprise_federation::CertificationDiscoveryNetwork::default().save(&path)?;
    let before = std::fs::read(&path)?;
    let mut state = metrics_state("service-secret");
    state.config.certification_discovery_file = Some(path.clone());
    let router = super::super::build_router(state);
    let honest = serde_json::to_string(&CertificationNetworkPublishRequest {
        artifact: certification()?,
        operator_ids: Vec::new(),
    })?;
    let response = send(
        &router,
        "POST",
        CERTIFICATION_DISCOVERY_PATH,
        "application/json",
        "service-secret",
        honest.clone(),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    for body in [
        honest.replace("\"target\":{", "\"target\":{\"ignored\":1,\"ignored\":2,"),
        honest.replace(
            "\"target\":{",
            "\"target\":{\"ignored\":0.10000000000000001,",
        ),
        honest.replace("ingress-tool", "tampered-tool"),
    ] {
        let response = send(
            &router,
            "POST",
            CERTIFICATION_DISCOVERY_PATH,
            "application/json",
            "service-secret",
            body,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(std::fs::read(&path)?, before);
    }
    Ok(())
}

#[tokio::test]
async fn ingress_unsigned_simulation_accepts_ordinary_decimals_and_rejects_duplicates(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let path = temp.path().join("receipts.sqlite3");
    drop(SqliteReceiptStore::open(&path)?);
    let mut state = metrics_state("service-secret");
    state.config.receipt_db_path = Some(path);
    let router = super::super::build_router(state);
    let request = UnderwritingSimulationRequest {
        query: UnderwritingPolicyInputQuery {
            agent_subject: Some("ingress-agent".into()),
            ..Default::default()
        },
        policy: UnderwritingDecisionPolicy::default(),
    };
    let ordinary = serde_json::to_string(&request)?.replace(
        "\"reduceCeilingFactor\":0.5",
        "\"reduceCeilingFactor\":0.50",
    );
    assert!(ordinary.contains("0.50"));
    let response = send(
        &router,
        "POST",
        UNDERWRITING_SIMULATION_PATH,
        "application/json",
        "service-secret",
        ordinary.clone(),
    )
    .await?;
    let status = response.status();
    let response_body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&response_body)
    );
    let report: UnderwritingSimulationReport = serde_json::from_slice(&response_body)?;
    assert_eq!(
        report.input.filters.agent_subject.as_deref(),
        Some("ingress-agent")
    );
    let body = ordinary.replace(
        "\"policy\":{",
        "\"policy\":{\"ignored\":0.10,\"ignored\":1.0,",
    );
    let response = send(
        &router,
        "POST",
        UNDERWRITING_SIMULATION_PATH,
        "application/json",
        "service-secret",
        body,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn ingress_body_limits_preserve_route_exceptions_and_stop_streams(
) -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let router = super::super::build_router(metrics_state("service-secret"));
    // The special receipt/import caps still reach typed validation above 1 MiB.
    // The body is deliberately an invalid DTO, so no receipt or import is written.
    for path in [
        TOOL_RECEIPTS_PATH,
        CHILD_RECEIPTS_PATH,
        EVIDENCE_IMPORT_PATH,
    ] {
        let response = send(
            &router,
            "POST",
            path,
            "application/json",
            "service-secret",
            format!("{}{{}}", " ".repeat(1024 * 1024)),
        )
        .await?;
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "{path}"
        );
    }
    let response = send(
        &router,
        "POST",
        AUTHORITY_KEY_LOG_SYNC_PATH,
        "application/json",
        "service-secret",
        format!("{}{{}}", " ".repeat(4096)),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let polls = Arc::new(AtomicUsize::new(0));
    let observed = polls.clone();
    let stream = futures_util::stream::repeat_with(move || {
        observed.fetch_add(1, Ordering::SeqCst);
        Ok::<_, std::io::Error>(axum::body::Bytes::from(vec![b' '; 256 * 1024]))
    });
    let request = Request::builder()
        .method("POST")
        .uri(CERTIFICATIONS_PATH)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, "Bearer service-secret")
        .body(Body::from_stream(stream))?;
    let response = router.clone().oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(polls.load(Ordering::SeqCst), 5);
    let failed_stream = futures_util::stream::once(async {
        Err::<axum::body::Bytes, _>(std::io::Error::other("untrusted transport details"))
    });
    let request = Request::builder()
        .method("POST")
        .uri(CERTIFICATIONS_PATH)
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, "Bearer service-secret")
        .body(Body::from_stream(failed_stream))?;
    let response = router.oneshot(request).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let error = axum::body::to_bytes(response.into_body(), 4096).await?;
    assert!(!String::from_utf8_lossy(&error).contains("untrusted transport details"));
    Ok(())
}
