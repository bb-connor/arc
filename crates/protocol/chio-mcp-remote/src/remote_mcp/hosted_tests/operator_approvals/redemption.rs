//! A roster signature alone cannot bypass the retained operator decision.
use super::*;
use chio_core::capability::governance::GovernedApprovalDecision;

fn parameters(pending: &Value, token: &GovernedApprovalToken) -> Value {
    json!({"name": pending["record"]["intent"]["tool_name"],
    "arguments": pending["record"]["arguments"], "_meta": {
        "chioRequestId": pending["record"]["request_id"],
        "chioGovernedIntent": pending["record"]["intent"], "chioApprovalToken": token,
    }})
}

pub(super) fn require_denial(result: TestResult<Value>) -> TestResult {
    match result {
        Ok(response) => assert!(
            response.get("error").is_some() || response["result"]["isError"] == true,
            "unrecorded approval must not dispatch: {response}",
        ),
        Err(error) if error.to_string().contains("approval redemption") => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

#[tokio::test]
async fn ap23_mcp_redemption_refuses_direct_signed_token_while_pending() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let approver = Keypair::generate();
    let calls = Arc::new(AtomicUsize::new(0));
    let (state, session) = open(config(directory.path(), &approver, calls.clone())?, None).await?;
    let pending = submit(&state, &session, "ap23-pending-bypass").await?;
    let approved = token(&pending, &approver)?;
    require_denial(call(&session, parameters(&pending, &approved), 30).await)?;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    stop(state, session).await
}

#[tokio::test]
async fn ap23_mcp_redemption_refuses_signed_approval_after_retained_denial() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let approver = Keypair::generate();
    let calls = Arc::new(AtomicUsize::new(0));
    let (state, session) = open(config(directory.path(), &approver, calls.clone())?, None).await?;
    let pending = submit(&state, &session, "ap23-denied-bypass").await?;
    let approved = token(&pending, &approver)?;
    let mut denied_body = approved.body();
    denied_body.decision = GovernedApprovalDecision::Denied;
    let denied = GovernedApprovalToken::sign(denied_body, &approver)?;
    body(decide(&state, &pending, &denied).await?, StatusCode::OK).await?;
    assert_eq!(
        decide(&state, &pending, &approved).await?.status(),
        StatusCode::CONFLICT
    );
    require_denial(call(&session, parameters(&pending, &approved), 31).await)?;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    stop(state, session).await
}

#[tokio::test]
async fn ap23_mcp_redemption_refuses_lifetime_beyond_expired_pending_record() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let approver = Keypair::generate();
    let calls = Arc::new(AtomicUsize::new(0));
    let (state, session) = open(config(directory.path(), &approver, calls.clone())?, None).await?;
    let pending = fixture::submit_with_ttl(&state, &session, "ap23-expired-bypass", 1).await?;
    let mut approved_body = token(&pending, &approver)?.body();
    approved_body.expires_at += 60;
    let approved = GovernedApprovalToken::sign(approved_body, &approver)?;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        decide(&state, &pending, &approved).await?.status(),
        StatusCode::CONFLICT
    );
    require_denial(call(&session, parameters(&pending, &approved), 32).await)?;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    stop(state, session).await
}

#[tokio::test]
async fn ap23_mcp_redemption_refuses_ambiguous_ordinary_approval_aliases() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let approver = Keypair::generate();
    let calls = Arc::new(AtomicUsize::new(0));
    let (state, session) = open(config(directory.path(), &approver, calls.clone())?, None).await?;
    let pending = submit(&state, &session, "ap23-ambiguous-bypass").await?;
    let approved = token(&pending, &approver)?;
    body(decide(&state, &pending, &approved).await?, StatusCode::OK).await?;
    let mut params = parameters(&pending, &approved);
    params["_meta"]["approvalToken"] = serde_json::to_value(&approved)?;
    params["_meta"]["chioApprovalToken"] = Value::Null;
    require_denial(call(&session, params, 33).await)?;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    stop(state, session).await
}
