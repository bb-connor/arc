//! `/admin/revocations` on the local serving-owner store: capability
//! revocation with a closed reason, the entry listing, the per-capability
//! check and every fixed refusal.

use crate::*;
use axum::body::Body;
use chio_core::root_authority::RevocationTarget;
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const ADMIN_TOKEN: &str = "revocation-admin-token";
const INVALID: &str = "invalid revocation request";

fn config(directory: &FsPath) -> TestResult<RemoteServeHttpConfig> {
    let mut config = super::support::base_remote_config(directory, "127.0.0.1:0".parse()?);
    config.auth_token = Some("revocation-agent".into());
    config.admin_token = Some(ADMIN_TOKEN.into());
    Ok(config)
}

fn state(config: RemoteServeHttpConfig) -> TestResult<RemoteAppState> {
    let factory = Arc::new(RemoteSessionFactory::new(config.clone())?);
    let sessions = Arc::new(RemoteSessionLedger::new(
        config.clock.clone(),
        config.lifecycle_policy()?,
        config.session_db_path.clone(),
        factory.resume_hmac_keyring.clone(),
    )?);
    Ok(RemoteAppState {
        sessions,
        factory,
        auth_mode: Arc::new(RemoteAuthMode::StaticBearer {
            token: "revocation-agent".into(),
        }),
        enterprise_provider_registry: None,
        admin_token: Some(ADMIN_TOKEN.into()),
        protected_resource_metadata: None,
        authorization_server_metadata: None,
        local_auth_server: None,
    })
}

async fn send(state: &RemoteAppState, request: Request<Body>) -> TestResult<(StatusCode, String)> {
    let router =
        crate::remote_mcp_admin::install_admin_routes(Router::new()).with_state(state.clone());
    let response = router.oneshot(request).await?;
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024).await?;
    Ok((status, String::from_utf8(bytes.to_vec())?))
}

async fn post_raw(state: &RemoteAppState, body: Vec<u8>) -> TestResult<(StatusCode, String)> {
    send(
        state,
        Request::builder()
            .method("POST")
            .uri("/admin/revocations")
            .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(body))?,
    )
    .await
}

async fn post(state: &RemoteAppState, body: Value) -> TestResult<(StatusCode, Value)> {
    let (status, text) = post_raw(state, serde_json::to_vec(&body)?).await?;
    Ok((
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    ))
}

async fn get(state: &RemoteAppState, query: &str) -> TestResult<(StatusCode, String)> {
    send(
        state,
        Request::builder()
            .method("GET")
            .uri(format!("/admin/revocations{query}"))
            .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
            .body(Body::empty())?,
    )
    .await
}

fn revoke_body(capability_id: &str, reason: &str) -> Value {
    json!({
        "target": {"kind": "capability_id", "capability_id": capability_id},
        "reason": reason
    })
}

#[tokio::test]
async fn capability_revocation_returns_the_entry_and_denies_through_the_store() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let state = state(config(directory.path())?)?;
    let (status, body) = post(&state, revoke_body("cap-admin-1", "principal_offboarded")).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let target = RevocationTarget::capability("cap-admin-1")?;
    assert_eq!(body["entry"]["entry_id"], target.id().to_string());
    assert_eq!(body["entry"]["schema"], "chio.revocation-entry.v1");
    assert_eq!(body["entry"]["target_kind"], "capability_id");
    assert_eq!(body["entry"]["target_value"], "cap-admin-1");
    assert_eq!(body["entry"]["reason"], "principal_offboarded");
    assert_eq!(body["newly_revoked"], true);
    assert_eq!(body["roots_matched"], 1);
    assert_eq!(body["roots_revoked"], 1);
    assert_eq!(body["reason_conflict"], false);
    let store = state
        .factory
        .durable_admission
        .as_ref()
        .and_then(|runtime| runtime.local_revocation_store())
        .ok_or("local revocation store")?;
    assert_eq!(store.revocation_entry("cap-admin-1")?, Some(target.id()));
    Ok(())
}

#[tokio::test]
async fn retry_with_another_reason_reports_conflict() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let state = state(config(directory.path())?)?;
    let (status, first) = post(&state, revoke_body("cap-admin-2", "operator_request")).await?;
    assert_eq!(status, StatusCode::OK, "{first}");
    let (status, same) = post(&state, revoke_body("cap-admin-2", "operator_request")).await?;
    assert_eq!(status, StatusCode::OK, "{same}");
    assert_eq!(same["newly_revoked"], false);
    assert_eq!(same["reason_conflict"], false);
    assert_eq!(same["entry"], first["entry"]);
    let (status, other) = post(&state, revoke_body("cap-admin-2", "incident_response")).await?;
    assert_eq!(status, StatusCode::OK, "{other}");
    assert_eq!(other["newly_revoked"], false);
    assert_eq!(other["reason_conflict"], true);
    assert_eq!(other["entry"]["reason"], "operator_request");
    Ok(())
}

#[tokio::test]
async fn malformed_revocation_requests_answer_the_fixed_body() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let state = state(config(directory.path())?)?;
    let target = json!({"kind": "capability_id", "capability_id": "cap-admin-3"});
    let cases = [
        json!({"target": target, "reason": "operator_request", "extra": 1}),
        json!({"target": {"kind": "capability_id", "capability_id": "cap-admin-3", "extra": 1}, "reason": "operator_request"}),
        json!({"target": {"kind": "not_a_kind", "capability_id": "cap-admin-3"}, "reason": "operator_request"}),
        json!({"target": target, "reason": "because"}),
        json!({"target": target}),
        json!({"reason": "operator_request"}),
        json!({"target": {"kind": "capability_id", "capability_id": ""}, "reason": "operator_request"}),
        json!({"target": {"kind": "capability_id", "capability_id": "cap\u{0}nul"}, "reason": "operator_request"}),
        json!({"capability_id": "cap-admin-3"}),
    ];
    for case in cases {
        let (status, body) = post_raw(&state, serde_json::to_vec(&case)?).await?;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::BAD_REQUEST, INVALID),
            "{case}"
        );
    }
    for raw in [
        b"not json".to_vec(),
        serde_json::to_vec(&revoke_body(&"c".repeat(64 * 1024), "operator_request"))?,
    ] {
        let (status, body) = post_raw(&state, raw).await?;
        assert_eq!((status, body.as_str()), (StatusCode::BAD_REQUEST, INVALID));
    }
    let (status, body) = get(&state, "").await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listing: Value = serde_json::from_str(&body)?;
    assert_eq!(listing["entries"], json!([]));
    Ok(())
}

#[tokio::test]
async fn listing_pages_through_next_after() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let state = state(config(directory.path())?)?;
    for id in ["cap-page-1", "cap-page-2", "cap-page-3"] {
        let (status, body) = post(&state, revoke_body(id, "operator_request")).await?;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let page = |text: String| -> TestResult<Value> { Ok(serde_json::from_str(&text)?) };
    let (status, first) = get(&state, "?limit=2").await?;
    assert_eq!(status, StatusCode::OK, "{first}");
    let first = page(first)?;
    let values: Vec<_> = first["entries"]
        .as_array()
        .ok_or("entries")?
        .iter()
        .map(|item| item["entry"]["target_value"].clone())
        .collect();
    assert_eq!(values, vec![json!("cap-page-1"), json!("cap-page-2")]);
    assert_eq!(first["entries"][0]["entry_seq"], 1);
    assert_eq!(first["next_after"], 2);
    assert_eq!(first["head"], 3);
    let (_, second) = get(&state, "?after=2&limit=2").await?;
    let second = page(second)?;
    assert_eq!(second["entries"][0]["entry"]["target_value"], "cap-page-3");
    assert_eq!(second["next_after"], 3);
    let (_, last) = get(&state, "?after=3").await?;
    let last = page(last)?;
    assert_eq!(last["entries"], json!([]));
    assert_eq!(last["next_after"], 3);
    let (_, by_kind) = get(&state, "?kind=root_policy_rule").await?;
    assert_eq!(page(by_kind)?["entries"], json!([]));
    let (_, capabilities) = get(&state, "?kind=capability_id").await?;
    assert_eq!(
        page(capabilities)?["entries"].as_array().map(Vec::len),
        Some(3)
    );
    Ok(())
}

#[tokio::test]
async fn listing_refuses_out_of_range_or_unknown_queries() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let state = state(config(directory.path())?)?;
    for query in [
        "?limit=0",
        "?limit=501",
        "?limit=x",
        "?after=-1",
        "?kind=not_a_kind",
        "?unknown=1",
    ] {
        let (status, body) = get(&state, query).await?;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::BAD_REQUEST, INVALID),
            "{query}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn capability_check_names_the_entry() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let state = state(config(directory.path())?)?;
    let (status, body) = post(&state, revoke_body("cap-check-1", "credential_compromise")).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, revoked) = get(&state, "?capability_id=cap-check-1").await?;
    assert_eq!(status, StatusCode::OK, "{revoked}");
    assert_eq!(
        serde_json::from_str::<Value>(&revoked)?,
        json!({
            "capability_id": "cap-check-1",
            "revoked": true,
            "entry_id": RevocationTarget::capability("cap-check-1")?.id().to_string()
        })
    );
    let (_, live) = get(&state, "?capability_id=cap-check-2").await?;
    assert_eq!(
        serde_json::from_str::<Value>(&live)?,
        json!({"capability_id": "cap-check-2", "revoked": false, "entry_id": null})
    );
    Ok(())
}

#[tokio::test]
async fn a_path_opened_revocation_database_is_not_an_admin_store() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let mut config = config(directory.path())?;
    std::fs::write(
        &config.policy_path,
        "kernel:\n  allow_ephemeral_receipt_log: true\n  durable_admission_mode: off\n  allow_unsafe_durable_admission_off: true\n",
    )?;
    config.revocation_db_path = Some(directory.path().join("revocations.db"));
    let state = state(config)?;
    let refusal = "remote trust admin requires durable revocation state";
    let (status, body) = post_raw(
        &state,
        serde_json::to_vec(&revoke_body("cap-path-1", "operator_request"))?,
    )
    .await?;
    assert_eq!((status, body.as_str()), (StatusCode::CONFLICT, refusal));
    let (status, body) = get(&state, "").await?;
    assert_eq!((status, body.as_str()), (StatusCode::CONFLICT, refusal));
    assert!(!directory.path().join("revocations.db").exists());
    Ok(())
}

#[tokio::test]
async fn an_outcome_unknown_store_answers_the_restart_body() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let config = config(directory.path())?;
    let session_db = config.session_db_path.clone().ok_or("session database")?;
    let state = state(config)?;
    let (status, body) = post(&state, revoke_body("cap-unknown-1", "operator_request")).await?;
    assert_eq!(status, StatusCode::OK, "{body}");
    rusqlite::Connection::open(durable_admission_sidecar_path(&session_db)?)?
        .execute_batch("CREATE TABLE outside_writer (value INTEGER)")?;
    let restart = "revocation outcome unknown; restart the provider, then retry the same request";
    for _ in 0..2 {
        let (status, body) = post_raw(
            &state,
            serde_json::to_vec(&revoke_body("cap-unknown-2", "operator_request"))?,
        )
        .await?;
        assert_eq!(
            (status, body.as_str()),
            (StatusCode::SERVICE_UNAVAILABLE, restart)
        );
    }
    Ok(())
}

#[tokio::test]
async fn store_failures_map_to_the_fixed_unavailable_bodies() -> TestResult {
    use chio_kernel::RevocationStoreError as R;
    let unavailable = "revocation store unavailable";
    let restart = "revocation outcome unknown; restart the provider, then retry the same request";
    for (error, expected) in [
        (R::Sync("private detail".into()), unavailable),
        (
            R::Fenced {
                expected_epoch: 1,
                actual_epoch: Some(2),
            },
            unavailable,
        ),
        (R::OutcomeUnknown("private detail".into()), restart),
    ] {
        let response = crate::remote_mcp_admin::revocation_store_failure(error);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = axum::body::to_bytes(response.into_body(), 4096).await?;
        assert_eq!(std::str::from_utf8(&body)?, expected);
    }
    Ok(())
}
