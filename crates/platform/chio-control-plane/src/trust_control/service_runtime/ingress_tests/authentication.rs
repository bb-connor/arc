//! Protected JSON contracts must reject credentials without polling the upload.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn body_with_poll_counter(bytes: &'static [u8]) -> (Body, Arc<AtomicUsize>) {
    let polls = Arc::new(AtomicUsize::new(0));
    let observed = polls.clone();
    let stream = futures_util::stream::once(async move {
        observed.fetch_add(1, Ordering::SeqCst);
        Ok::<_, std::io::Error>(axum::body::Bytes::from_static(bytes))
    });
    (Body::from_stream(stream), polls)
}

async fn submit(
    router: &Router,
    method: &str,
    path: &str,
    credential: Option<&str>,
    body: Body,
) -> TestResult<Response> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(CONTENT_TYPE, "application/json");
    if let Some(credential) = credential {
        builder = builder.header(AUTHORIZATION, credential);
    }
    Ok(router.clone().oneshot(builder.body(body)?).await?)
}

#[tokio::test]
async fn f047_service_credentials_reject_before_polling_large_contract_uploads() -> TestResult {
    let mut state = metrics_state("service-secret");
    state.config.authority_workload_token = Some("workload-secret".into());
    state
        .config
        .tenant_read_tokens
        .insert("tenant-a".into(), "tenant-read-secret".into());
    let router = super::super::super::build_router(state);
    for path in [
        TOOL_RECEIPTS_PATH,
        CHILD_RECEIPTS_PATH,
        EVIDENCE_IMPORT_PATH,
    ] {
        for credential in [
            None,
            Some("Bearer forged-service-secret"),
            Some("Bearer workload-secret"),
            Some("Bearer tenant-read-secret"),
            Some("Basic service-secret"),
        ] {
            let (body, polls) = body_with_poll_counter(b"{");
            let response = submit(&router, "POST", path, credential, body).await?;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(polls.load(Ordering::SeqCst), 0, "{path}");
            assert_eq!(response.headers()[WWW_AUTHENTICATE], "Bearer");
        }
    }
    Ok(())
}

#[tokio::test]
async fn f047_pending_unauthorized_upload_is_never_polled() -> TestResult {
    let router = super::super::super::build_router(metrics_state("service-secret"));
    for credential in [None, Some("Bearer forged-secret")] {
        let polls = Arc::new(AtomicUsize::new(0));
        let observed = polls.clone();
        let stream = futures_util::stream::poll_fn(move |_| {
            observed.fetch_add(1, Ordering::SeqCst);
            std::task::Poll::<Option<Result<axum::body::Bytes, std::io::Error>>>::Pending
        });
        let response = tokio::time::timeout(
            Duration::from_millis(250),
            submit(
                &router,
                "POST",
                TOOL_RECEIPTS_PATH,
                credential,
                Body::from_stream(stream),
            ),
        )
        .await??;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(polls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}

#[tokio::test]
async fn f047_authorized_body_keeps_original_byte_validation() -> TestResult {
    let router = super::super::super::build_router(metrics_state("service-secret"));
    for bytes in [
        b"{".as_slice(),
        br#"{"ignored":1,"ignored":2}"#.as_slice(),
        br#"{"ignored":0.10000000000000001}"#.as_slice(),
    ] {
        let (body, polls) = body_with_poll_counter(bytes);
        let response = submit(
            &router,
            "POST",
            TOOL_RECEIPTS_PATH,
            Some("Bearer service-secret"),
            body,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(polls.load(Ordering::SeqCst), 1);
    }
    let (body, polls) = body_with_poll_counter(b"{}");
    let response = submit(
        &router,
        "POST",
        TOOL_RECEIPTS_PATH,
        Some("Bearer service-secret"),
        body,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn f047_workload_and_tenant_credentials_keep_their_dedicated_contracts() -> TestResult {
    let mut state = metrics_state("service-secret");
    state.config.authority_workload_token = Some("workload-secret".into());
    state
        .config
        .tenant_read_tokens
        .insert("tenant-a".into(), "tenant-read-secret".into());
    let router = super::super::super::build_router(state);
    for (path, credential, expected, expected_polls) in [
        (
            ISSUE_CAPABILITY_PATH,
            "Bearer workload-secret",
            StatusCode::BAD_REQUEST,
            1,
        ),
        (
            ISSUE_CAPABILITY_PATH,
            "Bearer tenant-read-secret",
            StatusCode::UNAUTHORIZED,
            0,
        ),
        (
            EVIDENCE_EXPORT_PATH,
            "Bearer tenant-read-secret",
            StatusCode::BAD_REQUEST,
            1,
        ),
        (
            FISCAL_MARKETPLACE_CREDIT_LIMIT_PATH,
            "Bearer tenant-read-secret",
            StatusCode::BAD_REQUEST,
            1,
        ),
        (
            UNDERWRITING_SIMULATION_PATH,
            "Bearer tenant-read-secret",
            StatusCode::FORBIDDEN,
            0,
        ),
        (
            CREDIT_BONDED_EXECUTION_SIMULATION_PATH,
            "Bearer tenant-read-secret",
            StatusCode::FORBIDDEN,
            0,
        ),
    ] {
        let (body, polls) = body_with_poll_counter(br#"{"ignored":1,"ignored":2}"#);
        let response = submit(&router, "POST", path, Some(credential), body).await?;
        assert_eq!(response.status(), expected, "{path}");
        assert_eq!(polls.load(Ordering::SeqCst), expected_polls, "{path}");
    }
    Ok(())
}

#[tokio::test]
async fn f047_public_json_contracts_keep_their_existing_authentication() -> TestResult {
    let router = super::super::super::build_router(metrics_state("service-secret"));
    for path in [
        PASSPORT_ISSUANCE_TOKEN_PATH,
        PUBLIC_PASSPORT_CHALLENGE_VERIFY_PATH,
        FINDINGS_SEARCH_PATH,
    ] {
        let path = path.replace("{challenge_id}", "challenge-test");
        let (body, polls) = body_with_poll_counter(br#"{"ignored":1,"ignored":2}"#);
        let response = submit(&router, "POST", &path, None, body).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(polls.load(Ordering::SeqCst), 1, "{path}");
    }
    Ok(())
}

#[tokio::test]
async fn f047_nested_service_contract_rejects_before_body_polling() -> TestResult {
    let inner = Router::new().nest(
        "/{tenant}",
        super::super::super::build_router(metrics_state("service-secret")),
    );
    let router = Router::new().nest("/mounted", inner);
    let path = format!("/mounted/team{TOOL_RECEIPTS_PATH}");
    let (body, polls) = body_with_poll_counter(b"{");
    let response = submit(&router, "POST", &path, None, body).await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn f047_invalid_service_configuration_rejects_before_body_polling() -> TestResult {
    let router = super::super::super::build_router(metrics_state(""));
    let (body, polls) = body_with_poll_counter(b"{");
    let response = submit(&router, "POST", TOOL_RECEIPTS_PATH, None, body).await?;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    Ok(())
}
