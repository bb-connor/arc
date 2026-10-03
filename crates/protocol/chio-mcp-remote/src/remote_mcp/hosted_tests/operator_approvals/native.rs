use crate::*;
use chio_core::capability::governance::GovernedApprovalToken;
use std::sync::atomic::AtomicUsize;

#[path = "fixture.rs"]
mod fixture;
#[path = "redemption.rs"]
mod redemption;
use fixture::{body, call, config, decide, open, stop, submit, token, TestResult};

#[tokio::test]
async fn ap23_mcp_signed_approval_executes_once_and_replay_survives_restart() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let approver = Keypair::generate();
    let calls = Arc::new(AtomicUsize::new(0));
    let config = config(directory.path(), &approver, calls.clone())?;
    let (state, session) = open(config.clone(), None).await?;
    // A rejected request retains its own authoritative lineage. Exercise the
    // argument substitution under a distinct logical operation from the success.
    let tamper_pending = submit(&state, &session, "ap23-tampered-native-call").await?;
    let tamper_signed = token(&tamper_pending, &approver)?;
    let tamper_approved = body(
        decide(&state, &tamper_pending, &tamper_signed).await?,
        StatusCode::OK,
    )
    .await?;
    let mut changed = tamper_approved["toolCallParams"].clone();
    changed["arguments"]["message"] = json!("not approved");
    redemption::require_denial(call(&session, changed, 20).await)?;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let pending = submit(&state, &session, "ap23-one-native-call").await?;
    let signed = token(&pending, &approver)?;
    assert_ne!(
        signed.approver,
        state
            .factory
            .durable_admission
            .as_ref()
            .ok_or("runtime")?
            .kernel_keypair()
            .public_key()
    );
    let approved = body(decide(&state, &pending, &signed).await?, StatusCode::OK).await?;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        approved["record"]["decision"],
        serde_json::to_value(&signed)?
    );
    let params = approved["toolCallParams"].clone();
    let result = call(&session, params.clone(), 21).await?;
    assert!(result.get("error").is_none(), "{result}");
    assert_ne!(result["result"]["isError"], true, "{result}");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let _repeated = call(&session, params.clone(), 22).await?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let resume = session.resume_record()?.ok_or("resume record")?;
    stop(state, session).await?;

    let (state, session) = open(config, Some(&resume)).await?;
    let id = pending["record"]["id"].as_str().ok_or("approval id")?;
    let restored = body(
        crate::remote_mcp_approvals::get_record(
            State(state.clone()),
            AxumPath(id.into()),
            fixture::headers()?,
        )
        .await,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        restored["record"]["decision"],
        serde_json::to_value(&signed)?
    );
    let _repeated = call(&session, params.clone(), 23).await?;
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "restart must retain consumption"
    );
    let mut other_request = params;
    other_request["_meta"]["chioRequestId"] = json!("ap23-other-request");
    redemption::require_denial(call(&session, other_request, 24).await)?;
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    stop(state, session).await
}

#[tokio::test]
async fn ap23_mcp_rejects_unconfigured_signers_and_altered_decision_bindings() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let approver = Keypair::generate();
    let calls = Arc::new(AtomicUsize::new(0));
    let (state, session) = open(config(directory.path(), &approver, calls.clone())?, None).await?;
    let pending = submit(&state, &session, "ap23-bindings").await?;
    let good = token(&pending, &approver)?;
    let receipt_key = state
        .factory
        .durable_admission
        .as_ref()
        .ok_or("runtime")?
        .kernel_keypair();
    for signer in [Keypair::generate(), receipt_key] {
        let wrong = token(&pending, &signer)?;
        assert_eq!(
            decide(&state, &pending, &wrong).await?.status(),
            StatusCode::CONFLICT
        );
    }
    for mutation in 0..6 {
        let mut altered = good.body();
        match mutation {
            0 => altered.subject = Keypair::generate().public_key(),
            1 => altered.request_id = "changed-request".into(),
            2 => altered.governed_intent_hash = "ab".repeat(32),
            3 => altered.expires_at += 1,
            4 => altered.issued_at = altered.expires_at,
            _ => altered.threshold_proposal_hash = Some("cd".repeat(32)),
        }
        let altered = GovernedApprovalToken::sign(altered, &approver)?;
        assert_eq!(
            decide(&state, &pending, &altered).await?.status(),
            StatusCode::CONFLICT
        );
    }
    let mut invalid_signature = good.clone();
    invalid_signature.signature = Keypair::generate().sign(b"unrelated message");
    assert_eq!(
        decide(&state, &pending, &invalid_signature).await?.status(),
        StatusCode::BAD_REQUEST
    );
    let approved = body(decide(&state, &pending, &good).await?, StatusCode::OK).await?;
    let repeated = body(decide(&state, &pending, &good).await?, StatusCode::OK).await?;
    assert_eq!(approved, repeated);
    let mut denied = good.body();
    denied.decision = chio_core::capability::governance::GovernedApprovalDecision::Denied;
    let denied = GovernedApprovalToken::sign(denied, &approver)?;
    assert_eq!(
        decide(&state, &pending, &denied).await?.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    stop(state, session).await
}

#[tokio::test]
async fn ap23_mcp_pending_decision_rechecks_current_policy_and_revocation() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let approver = Keypair::generate();
    let calls = Arc::new(AtomicUsize::new(0));
    let config = config(directory.path(), &approver, calls.clone())?;
    let original = std::fs::read(&config.policy_path)?;
    let (state, session) = open(config.clone(), None).await?;
    let pending = submit(&state, &session, "ap23-current-authority").await?;
    let good = token(&pending, &approver)?;
    let changed = std::str::from_utf8(&original)?
        .replace("max_capability_ttl: 3600", "max_capability_ttl: 3500");
    std::fs::write(&config.policy_path, changed)?;
    assert_eq!(
        decide(&state, &pending, &good).await?.status(),
        StatusCode::CONFLICT
    );
    std::fs::write(&config.policy_path, original)?;
    let runtime = state.factory.durable_admission.as_ref().ok_or("runtime")?;
    let revocations = runtime.local_revocation_store().ok_or("revocation store")?;
    let capability = session.issued_capabilities.first().ok_or("capability")?;
    revocations.revoke(&capability.id)?;
    assert_eq!(
        decide(&state, &pending, &good).await?.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    stop(state, session).await
}

#[test]
fn ap23_mcp_startup_rejects_invalid_roster_or_unactivated_replay_source() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let approver = Keypair::generate();
    let mut config = config(directory.path(), &approver, Arc::new(AtomicUsize::new(0)))?;
    let good = config.approval.clone().ok_or("approval config")?;
    config
        .approval
        .as_mut()
        .ok_or("approval config")?
        .approvers
        .clear();
    assert!(RemoteSessionFactory::new(config.clone()).is_err());
    config.approval = Some(good.clone());
    config
        .approval
        .as_mut()
        .ok_or("approval config")?
        .approvers
        .push(approver.public_key());
    assert!(RemoteSessionFactory::new(config.clone()).is_err());
    config.approval = Some(good.clone());
    config.approval.as_mut().ok_or("approval config")?.tenant_id = " ".into();
    assert!(RemoteSessionFactory::new(config.clone()).is_err());
    config.approval = Some(good);
    let unrelated = directory.path().join("unactivated.sqlite3");
    drop(
        chio_store_sqlite::SqliteGovernedApprovalReplayStore::open_with_capacity(&unrelated, 128)?,
    );
    config
        .approval
        .as_mut()
        .ok_or("approval config")?
        .replay_source_path = unrelated;
    assert!(RemoteSessionFactory::new(config).is_err());
    Ok(())
}

#[test]
fn ap23_mcp_approval_config_uses_bounded_duplicate_aware_parser() -> TestResult {
    let directory = chio_test_support::private_tempdir()?;
    let config = config(
        directory.path(),
        &Keypair::generate(),
        Arc::new(AtomicUsize::new(0)),
    )?;
    let valid = serde_json::to_string(&config.approval.ok_or("approval config")?)?;
    let path = directory.path().join("approval-config.json");
    std::fs::write(&path, &valid)?;
    assert!(RemoteApprovalConfig::load(&path).is_ok());
    let duplicate = valid.replacen('{', "{\"tenant_id\":\"injected\",", 1);
    std::fs::write(&path, duplicate)?;
    assert!(RemoteApprovalConfig::load(&path).is_err());
    std::fs::write(&path, vec![b' '; 64 * 1024 + 1])?;
    assert!(RemoteApprovalConfig::load(&path).is_err());
    Ok(())
}
