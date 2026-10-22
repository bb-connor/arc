//! Approval binding and storage failures answer fixed URN bodies. Each cause
//! can name policy parse or store schema detail, so it stays in the server log.
use super::fixture::{config, headers, open, stop, submit, TestResult};
use crate::*;
use std::sync::atomic::AtomicUsize;

const STORAGE_FAILED: &str = "urn:chio:error:transport:approval-storage-failed";
const INTENT_UNBOUND: &str = "urn:chio:error:transport:approval-intent-unbound";

async fn text(response: Response, status: StatusCode) -> TestResult<String> {
    let actual = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
    let body = String::from_utf8(bytes.to_vec())?;
    assert_eq!(actual, status, "{body}");
    Ok(body)
}

#[tokio::test]
async fn an_unbindable_approval_request_answers_the_fixed_urn_without_its_cause() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let approver = Keypair::generate();
    let config = config(directory.path(), &approver, Arc::new(AtomicUsize::new(0)))?;
    let (state, session) = open(config.clone(), None).await?;
    std::fs::write(&config.policy_path, "capabilities: [\n")?;
    let capability = session
        .issued_capabilities
        .first()
        .ok_or("session capability")?;
    let request = serde_json::from_value(json!({
        "session_id":session.session_id, "capability_id":capability.id,
        "request_id":"ap23-unbindable", "tool_name":"echo_json", "arguments":{"message":"exact"},
        "purpose":"operator-approved native test", "ttl_seconds":120,
    }))?;
    let body = text(
        crate::remote_mcp_approvals::submit(State(state.clone()), headers()?, BoundedJson(request))
            .await,
        StatusCode::CONFLICT,
    )
    .await?;
    assert_eq!(body, INTENT_UNBOUND);
    assert!(!body.contains("YAML"));
    assert!(!body.contains(&directory.path().to_string_lossy().into_owned()));
    stop(state, session).await
}

#[tokio::test]
async fn an_approval_store_failure_answers_the_fixed_urn_without_its_schema_detail() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let approver = Keypair::generate();
    let config = config(directory.path(), &approver, Arc::new(AtomicUsize::new(0)))?;
    let (state, session) = open(config.clone(), None).await?;
    let session_db = config
        .session_db_path
        .as_deref()
        .ok_or("session database")?;
    rusqlite::Connection::open(session_db)?
        .execute_batch("CREATE TABLE remote_operator_approvals (id TEXT PRIMARY KEY NOT NULL);")?;
    let body = text(
        crate::remote_mcp_approvals::get_record(
            State(state.clone()),
            AxumPath("ap23-missing-column".into()),
            headers()?,
        )
        .await,
        StatusCode::INTERNAL_SERVER_ERROR,
    )
    .await?;
    assert_eq!(body, STORAGE_FAILED);
    assert!(!body.contains("signed_record"));
    assert!(!body.contains(&directory.path().to_string_lossy().into_owned()));
    stop(state, session).await
}

#[tokio::test]
async fn a_moved_approval_record_answers_the_fixed_integrity_conflict() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let approver = Keypair::generate();
    let config = config(directory.path(), &approver, Arc::new(AtomicUsize::new(0)))?;
    let (state, session) = open(config.clone(), None).await?;
    let pending = submit(&state, &session, "ap23-integrity").await?;
    let original = pending["record"]["id"].as_str().ok_or("approval id")?;
    let session_db = config
        .session_db_path
        .as_deref()
        .ok_or("session database")?;
    let moved = rusqlite::Connection::open(session_db)?.execute(
        "UPDATE remote_operator_approvals SET id = 'ap23-moved-record' WHERE id = ?1",
        [original],
    )?;
    assert_eq!(moved, 1);
    let body = text(
        crate::remote_mcp_approvals::get_record(
            State(state.clone()),
            AxumPath("ap23-moved-record".into()),
            headers()?,
        )
        .await,
        StatusCode::CONFLICT,
    )
    .await?;
    assert_eq!(body, "approval record integrity check failed");
    assert!(!body.contains(original));
    assert!(!body.contains("ap23-moved-record"));
    stop(state, session).await
}
