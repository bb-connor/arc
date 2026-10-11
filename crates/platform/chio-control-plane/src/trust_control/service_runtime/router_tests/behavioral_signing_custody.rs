//! An authenticated report request cannot repair lost authority signing custody.

use super::*;
use tower::ServiceExt;

type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn report(
    state: &TrustServiceState,
) -> Result<(StatusCode, Vec<u8>), Box<dyn std::error::Error>> {
    let response = super::super::build_router(state.clone())
        .oneshot(
            axum::http::Request::builder()
                .uri(BEHAVIORAL_FEED_PATH)
                .header(AUTHORIZATION, "Bearer service-secret")
                .body(axum::body::Body::empty())?,
        )
        .await?;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
    Ok((status, body.to_vec()))
}

async fn issue(
    state: &TrustServiceState,
) -> Result<(StatusCode, Vec<u8>), Box<dyn std::error::Error>> {
    let payload = IssueCapabilityRequest {
        subject_public_key: Keypair::generate().public_key().to_hex(),
        scope: ChioScope::default(),
        ttl_seconds: 60,
        runtime_attestation: None,
    };
    let response = super::super::build_router(state.clone())
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri(ISSUE_CAPABILITY_PATH)
                .header(AUTHORIZATION, "Bearer workload-secret")
                .header(CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(serde_json::to_vec(&payload)?))?,
        )
        .await?;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await?;
    Ok((status, body.to_vec()))
}

fn with_receipts(directory: &Path) -> Result<TrustServiceState, Box<dyn std::error::Error>> {
    let mut state = metrics_state("service-secret");
    state.finding_challenge_clock = chio_test_support::clock::clock();
    state.config.authority_workload_token = Some("workload-secret".to_string());
    let receipts = directory.join("receipts.sqlite3");
    state.config.receipt_db_path = Some(receipts.clone());
    state.receipt_store = Some(Arc::new(SqliteReceiptStore::open(&receipts)?));
    Ok(state)
}

#[tokio::test]
async fn behavioral_report_after_seed_loss_leaves_following_issuance_refused() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let seed = directory.path().join("authority.seed");
    let mut state = with_receipts(directory.path())?;
    state.config.authority_seed_path = Some(seed.clone());
    super::super::super::provision_service_authority(
        &state.config,
        state.finding_challenge_clock.clone(),
    )?;
    let signer = crate::load_existing_authority_keypair(&seed)?;
    let (status, body) = report(&state).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "healthy report: {}",
        String::from_utf8_lossy(&body)
    );
    let feed: SignedBehavioralFeed = serde_json::from_slice(&body)?;
    assert_eq!(feed.signer_key, signer.public_key());
    assert!(feed.verify_signature()?);
    let (status, body) = issue(&state).await?;
    assert_eq!(
        status,
        StatusCode::OK,
        "healthy issue: {}",
        String::from_utf8_lossy(&body)
    );
    let issued: IssueCapabilityResponse = serde_json::from_slice(&body)?;
    assert_eq!(issued.capability.issuer, signer.public_key());
    assert!(issued.capability.verify_signature()?);

    std::fs::remove_file(&seed)?;
    let (report_status, report_body) = report(&state).await?;
    let report_recreated_seed = seed.exists();
    let (issue_status, issue_body) = issue(&state).await?;
    eprintln!(
        "seed-loss report={report_status}, recreated_seed={report_recreated_seed}, following issue={issue_status}, final seed exists={}",
        seed.exists()
    );
    assert_eq!(report_status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(
        !report_recreated_seed && !seed.exists(),
        "report request recreated authority custody"
    );
    assert_eq!(issue_status, StatusCode::SERVICE_UNAVAILABLE);
    let expected = crate::load_existing_authority_keypair(&seed).test_unwrap_err();
    assert!(
        matches!(&expected, CliError::Io(error) if error.kind() == std::io::ErrorKind::NotFound)
    );
    for body in [report_body, issue_body] {
        let refusal: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(
            refusal["error"].as_str(),
            Some(expected.to_string().as_str())
        );
    }
    Ok(())
}

#[tokio::test]
async fn behavioral_report_refuses_a_missing_database_without_provisioning_it() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let authority_parent = directory.path().join("missing-authority");
    let authority_db = authority_parent.join("authority.sqlite3");
    let mut state = with_receipts(directory.path())?;
    state.config.authority_db_path = Some(authority_db.clone());
    let (status, body) = report(&state).await?;
    eprintln!(
        "missing-database report={status}, parent exists={}",
        authority_parent.exists()
    );
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "{}",
        String::from_utf8_lossy(&body)
    );
    assert!(!authority_parent.exists() && !authority_db.exists());
    let refusal: serde_json::Value = serde_json::from_slice(&body)?;
    assert!(refusal["error"]
        .as_str()
        .is_some_and(|reason| reason.contains("initialized")));
    Ok(())
}
