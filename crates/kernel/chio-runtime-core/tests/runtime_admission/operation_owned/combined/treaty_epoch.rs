use super::*;
use chio_core_types::crypto::Ed25519Backend;
use chio_kernel::admission_operation::runtime_participant::RuntimeParticipantPhase;
use chio_kernel::execution_nonce::{ExecutionNonceConfig, InMemoryExecutionNonceStore};
use chio_runtime_core::treaty_epoch::{
    sign_treaty_epoch_record, TreatyEpochStatusV1, VerifiedTreatyEpochUpdate,
};

fn revocable_fixture() -> TestResult<(CombinedFixture, Ed25519Backend, VerifiedTreatyEpochUpdate)> {
    let mut authority = None;
    let fixture = CombinedFixture::with_treaty_input(|treaty, _, _| {
        authority = Some((
            Ed25519Backend::new(treaty.epoch_key.clone()),
            treaty.epoch_update.clone(),
        ));
        Ok(())
    })?;
    let (backend, update) = authority.ok_or("signed treaty epoch fixture")?;
    Ok((fixture, backend, update))
}

fn revoke(
    fixture: &CombinedFixture,
    backend: &Ed25519Backend,
    active: &VerifiedTreatyEpochUpdate,
) -> TestResult {
    let mut body = active.body().clone();
    body.sequence = body
        .sequence
        .checked_add(1)
        .ok_or("epoch sequence exhausted")?;
    body.previous_record_sha256 = Some(active.body_digest().clone());
    body.status = TreatyEpochStatusV1::Revoked;
    let revoked = sign_treaty_epoch_record(body, backend, active.authority())?;
    fixture
        .inner
        .source
        .apply_treaty_epoch_update(Some(active.body_digest()), &revoked)?;
    Ok(())
}

#[test]
fn revoked_epoch_after_nonce_preflight_refuses_fresh_dispatch_and_releases_claim() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let (fixture, backend, active) = revocable_fixture()?;
    let mut kernel = fixture.kernel(fixture.hook()?)?;
    let config = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 64,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        config.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&config)),
    );
    let preflight = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.inner.request,
        Some(swarm_route_metadata()),
    )?;
    assert_eq!(preflight.verdict, Verdict::Allow, "{preflight:#?}");
    assert!(preflight.receipt.verify_integrity_embedded_key()?);
    assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 0);
    let before = faults::history(&fixture.inner)?;
    assert_eq!(before.len(), 1);
    assert_eq!(
        before[0].intent.phase(),
        RuntimeParticipantPhase::NoncePreflight
    );
    assert_eq!(
        before[0].disposition,
        RuntimeParticipantDisposition::ReleasedBeforeDispatch
    );
    let mut execution = fixture.inner.request.clone();
    execution.execution_nonce = Some(*preflight.execution_nonce.ok_or("valid preflight nonce")?);

    revoke(&fixture, &backend, &active)?;

    let denied = kernel
        .evaluate_tool_call_blocking_with_metadata(&execution, Some(swarm_route_metadata()))?;
    assert_eq!(denied.verdict, Verdict::Deny, "{denied:#?}");
    assert!(denied.receipt.verify_integrity_embedded_key()?);
    let metadata = denied
        .receipt
        .metadata
        .as_ref()
        .ok_or("signed denial metadata")?;
    assert_eq!(metadata["chio_runtime"]["failure_code"], "treaty_revoked");
    assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 0);
    let (operation, after) = fixture.history(&before[0].reference)?;
    assert!(operation.dispatch_commit().is_none());
    assert_eq!(after.len(), 2);
    assert!(after.contains(&before[0]));
    let dispatch = after
        .iter()
        .find(|claim| claim.reference != before[0].reference)
        .ok_or("fresh refused dispatch claim")?;
    assert_eq!(dispatch.intent.phase(), RuntimeParticipantPhase::Dispatch);
    assert_eq!(dispatch.intent.resources(), before[0].intent.resources());
    assert_eq!(
        dispatch.disposition,
        RuntimeParticipantDisposition::ReleasedBeforeDispatch
    );
    Ok(())
}

#[test]
fn completed_treaty_replay_after_revocation_keeps_original_authorization() -> TestResult {
    let _clock = chio_test_support::clock::scope_unix_secs(NOW / 1000);
    let (fixture, backend, active) = revocable_fixture()?;
    let kernel = fixture.kernel(fixture.hook()?)?;
    let completed = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.inner.request,
        Some(swarm_route_metadata()),
    )?;
    assert_eq!(completed.verdict, Verdict::Allow, "{completed:#?}");
    assert!(completed.receipt.verify_integrity_embedded_key()?);
    assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 1);
    let history = faults::history(&fixture.inner)?;
    assert_eq!(history.len(), 1);
    let before = fixture.history(&history[0].reference)?;
    assert!(before.0.dispatch_commit().is_some());

    revoke(&fixture, &backend, &active)?;

    let replay = kernel.evaluate_tool_call_blocking_with_metadata(
        &fixture.inner.request,
        Some(swarm_route_metadata()),
    )?;
    assert_eq!(replay.verdict, Verdict::Allow, "{replay:#?}");
    assert!(replay.receipt.verify_integrity_embedded_key()?);
    assert_eq!(fixture.inner.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.history(&history[0].reference)?, before);
    Ok(())
}
