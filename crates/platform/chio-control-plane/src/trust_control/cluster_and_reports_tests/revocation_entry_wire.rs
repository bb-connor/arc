use super::*;
use chio_core_types::root_authority::{RevocationReason, RevocationTarget};

fn admin_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, "Bearer token".parse().test_unwrap());
    headers
}

fn leader() -> TrustServiceState {
    state_with_cluster(
        "https://node-a",
        &[],
        None,
        Some(unique_temp_path("revocation-entry-wire", "sqlite3")),
        None,
    )
}

async fn json_body(response: Response) -> (StatusCode, Value) {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX)
        .await
        .test_unwrap();
    let text = String::from_utf8(bytes.to_vec()).test_unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

async fn revoke(
    state: &TrustServiceState,
    capability_id: &str,
    reason: RevocationReason,
) -> (StatusCode, Value) {
    json_body(
        handle_revoke_capability(
            State(state.clone()),
            admin_headers(),
            Json(RevokeCapabilityRequest {
                capability_id: capability_id.to_string(),
                reason,
            }),
        )
        .await,
    )
    .await
}

async fn list(state: &TrustServiceState, query: RevocationQuery) -> (StatusCode, Value) {
    json_body(handle_list_revocations(State(state.clone()), Query(query), admin_headers()).await)
        .await
}

#[tokio::test]
async fn revoke_capability_returns_the_entry_and_its_reason() {
    let state = leader();
    let (status, first) =
        revoke(&state, "cap-wire-1", RevocationReason::CredentialCompromise).await;
    assert_eq!(status, StatusCode::OK, "{first}");
    let target = RevocationTarget::capability("cap-wire-1").test_unwrap();
    assert_eq!(first["entry"]["entry_id"], target.id().to_string());
    assert_eq!(first["entry"]["reason"], "credential_compromise");
    assert_eq!(first["newly_revoked"], true);
    assert_eq!(first["roots_revoked"], 1);
    assert_eq!(first["roots_matched"], 1);
    assert!(first.get("newlyRevoked").is_none(), "{first}");
    let (status, again) = revoke(&state, "cap-wire-1", RevocationReason::OperatorRequest).await;
    assert_eq!(status, StatusCode::OK, "{again}");
    assert_eq!(again["newly_revoked"], false);
    assert_eq!(again["entry"], first["entry"]);
}

#[tokio::test]
async fn revocation_status_names_the_entry() {
    let state = leader();
    revoke(&state, "cap-wire-2", RevocationReason::OperatorRequest).await;
    let (status, revoked) = list(
        &state,
        RevocationQuery {
            capability_id: Some("cap-wire-2".into()),
            ..RevocationQuery::default()
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{revoked}");
    assert_eq!(
        revoked,
        json!({
            "capability_id": "cap-wire-2",
            "revoked": true,
            "entry_id": RevocationTarget::capability("cap-wire-2").test_unwrap().id().to_string()
        })
    );
    let (_, live) = list(
        &state,
        RevocationQuery {
            capability_id: Some("cap-wire-3".into()),
            ..RevocationQuery::default()
        },
    )
    .await;
    assert_eq!(
        live,
        json!({"capability_id": "cap-wire-3", "revoked": false, "entry_id": null})
    );
}

#[tokio::test]
async fn revocation_listing_pages_through_next_after() {
    let state = leader();
    for id in ["cap-page-1", "cap-page-2", "cap-page-3"] {
        revoke(&state, id, RevocationReason::OperatorRequest).await;
    }
    let (status, first) = list(
        &state,
        RevocationQuery {
            limit: Some(2),
            ..RevocationQuery::default()
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{first}");
    assert_eq!(first["entries"][0]["entry_seq"], 1);
    assert_eq!(first["entries"][1]["entry"]["target_value"], "cap-page-2");
    assert_eq!(first["next_after"], 2);
    assert_eq!(first["head"], 3);
    let (_, rest) = list(
        &state,
        RevocationQuery {
            after: Some(2),
            kind: Some(chio_core_types::root_authority::RevocationTargetKind::CapabilityId),
            ..RevocationQuery::default()
        },
    )
    .await;
    assert_eq!(rest["entries"][0]["entry"]["target_value"], "cap-page-3");
    assert_eq!(rest["next_after"], 3);
}

#[tokio::test]
async fn malformed_revocation_queries_answer_the_fixed_body() {
    let state = leader();
    for query in [
        RevocationQuery {
            limit: Some(0),
            ..RevocationQuery::default()
        },
        RevocationQuery {
            limit: Some(501),
            ..RevocationQuery::default()
        },
        RevocationQuery {
            capability_id: Some("cap-wire-4".into()),
            after: Some(1),
            ..RevocationQuery::default()
        },
    ] {
        let (status, body) = list(&state, query).await;
        assert_eq!(
            (status, body),
            (
                StatusCode::BAD_REQUEST,
                json!({"error": "invalid revocation request"})
            )
        );
    }
}

fn revocation_router(state: &TrustServiceState) -> axum::Router {
    axum::Router::new()
        .route(
            REVOCATIONS_PATH,
            get(handle_list_revocations).post(handle_revoke_capability),
        )
        .with_state(state.clone())
}

async fn raw(
    state: &TrustServiceState,
    method: &str,
    uri: &str,
    bearer: Option<&str>,
    body: &str,
) -> (StatusCode, Value) {
    use tower::ServiceExt;
    let mut request = axum::http::Request::builder().method(method).uri(uri);
    if let Some(bearer) = bearer {
        request = request.header(AUTHORIZATION, format!("Bearer {bearer}"));
    }
    if !body.is_empty() {
        request = request.header(axum::http::header::CONTENT_TYPE, "application/json");
    }
    let response = revocation_router(state)
        .oneshot(
            request
                .body(axum::body::Body::from(body.to_string()))
                .test_unwrap(),
        )
        .await
        .test_unwrap();
    json_body(response).await
}

#[tokio::test]
async fn authentication_precedes_every_revocation_extractor() {
    let state = leader();
    for (method, uri, body) in [
        ("GET", format!("{REVOCATIONS_PATH}?limit=x"), ""),
        ("GET", format!("{REVOCATIONS_PATH}?unknown=1"), ""),
        (
            "POST",
            REVOCATIONS_PATH.to_string(),
            "{\"capability_id\": \"cap\", \"reason\": \"bogus\"}",
        ),
    ] {
        for bearer in [None, Some("wrong-token")] {
            let (status, body) = raw(&state, method, &uri, bearer, body).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{method} {uri} {bearer:?}: {body}"
            );
        }
    }
}

#[tokio::test]
async fn malformed_raw_revocation_requests_answer_the_fixed_body() {
    let state = leader();
    let fixed = json!({"error": INVALID_REVOCATION_REQUEST});
    for (method, uri, body) in [
        ("GET", format!("{REVOCATIONS_PATH}?limit=x"), ""),
        ("GET", format!("{REVOCATIONS_PATH}?unknown=1"), ""),
        ("GET", format!("{REVOCATIONS_PATH}?kind=not_a_kind"), ""),
        ("GET", format!("{REVOCATIONS_PATH}?capabilityId=cap"), ""),
        (
            "POST",
            REVOCATIONS_PATH.to_string(),
            "{\"capability_id\": \"cap\", \"reason\": \"bogus\"}",
        ),
        (
            "POST",
            REVOCATIONS_PATH.to_string(),
            "{\"capability_id\": \"cap\"}",
        ),
        (
            "POST",
            REVOCATIONS_PATH.to_string(),
            "{\"capabilityId\": \"cap\", \"reason\": \"operator_request\"}",
        ),
        ("POST", REVOCATIONS_PATH.to_string(), "not json"),
    ] {
        let (status, response) = raw(&state, method, &uri, Some("token"), body).await;
        assert_eq!(
            (status, &response),
            (StatusCode::BAD_REQUEST, &fixed),
            "{method} {uri} {body}"
        );
    }
    let (status, response) = raw(
        &state,
        "GET",
        &format!("{REVOCATIONS_PATH}?capability_id=cap-raw-1"),
        Some("token"),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["capability_id"], "cap-raw-1");
}

#[test]
fn revocation_store_failures_map_to_fixed_bodies() {
    use chio_kernel::RevocationStoreError as R;
    let restart = "revocation outcome unknown; restart the provider, then retry the same request";
    for (error, expected) in [
        (
            R::Sync("/private/path".into()),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "revocation store unavailable",
            ),
        ),
        (
            R::Fenced {
                expected_epoch: 1,
                actual_epoch: None,
            },
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "revocation store unavailable",
            ),
        ),
        (
            R::OutcomeUnknown("/private/path".into()),
            (StatusCode::SERVICE_UNAVAILABLE, restart),
        ),
    ] {
        assert_eq!(revocation_store_failure(&error), expected, "{error}");
    }
}
