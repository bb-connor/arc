use super::*;
use chio_kernel::admission_operation::runtime_participant::{
    RuntimeParticipantClaimReferenceV1, RuntimeParticipantPhase,
};
use chio_kernel::execution_nonce::{ExecutionNonceConfig, InMemoryExecutionNonceStore};

#[test]
fn owned_nonce_preflight_releases_before_issuance_and_dispatch_claims_a_new_episode() -> TestResult
{
    let _clock = chio_kernel::scope_fixed_runtime_for_current_thread(NOW / 1000, []);
    let fixture = Fixture::new(true)?;
    let mut kernel = fixture.kernel(fixture.hook()?, true, false)?;
    let config = ExecutionNonceConfig {
        nonce_ttl_secs: 30,
        nonce_store_capacity: 64,
        require_nonce: true,
    };
    kernel.set_execution_nonce_store(
        config.clone(),
        Box::new(InMemoryExecutionNonceStore::from_config(&config)),
    );
    let preflight = kernel.evaluate_tool_call_blocking(&fixture.request)?;
    assert_eq!(preflight.verdict, Verdict::Allow, "{:?}", preflight.reason);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    let reference: RuntimeParticipantClaimReferenceV1 = serde_json::from_value(
        preflight
            .receipt
            .metadata
            .as_ref()
            .ok_or("preflight metadata")?["chio_runtime"]["operation_owned_replay"]["reference"]
            .clone(),
    )?;
    let store = fixture.authority.admission_operation_store();
    let fence = fixture.authority.mutation_fence();
    let (prepared, history) = store
        .load_runtime_participant_history(reference.operation_id(), &fence, NOW)?
        .ok_or("preflight ownership")?;
    assert!(prepared.execution_nonce_preflight_digest().is_some());
    assert!(prepared.execution_nonce_issuance_digest().is_some());
    assert!(prepared.dispatch_commit().is_none());
    assert_eq!(history.len(), 1);
    assert_eq!(
        history[0].intent.phase(),
        RuntimeParticipantPhase::NoncePreflight
    );
    assert_eq!(
        history[0].disposition,
        RuntimeParticipantDisposition::ReleasedBeforeDispatch
    );

    let mut execution = fixture.request.clone();
    execution.execution_nonce = Some(*preflight.execution_nonce.ok_or("issued nonce")?);
    let dispatched = kernel.evaluate_tool_call_blocking(&execution)?;
    assert_eq!(
        dispatched.verdict,
        Verdict::Allow,
        "{:?}",
        dispatched.reason
    );
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    let (completed, history) = store
        .load_runtime_participant_history(reference.operation_id(), &fence, NOW)?
        .ok_or("dispatch ownership")?;
    assert!(completed.dispatch_commit().is_some());
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].reference, reference);
    assert_eq!(
        history[0].disposition,
        RuntimeParticipantDisposition::ReleasedBeforeDispatch
    );
    assert_ne!(history[1].reference, reference);
    assert_eq!(history[1].intent.phase(), RuntimeParticipantPhase::Dispatch);
    assert_eq!(
        history[1].disposition,
        RuntimeParticipantDisposition::RetainedAfterDispatchCommit
    );
    assert_eq!(history[0].intent.resources(), history[1].intent.resources());
    let replay = kernel.evaluate_tool_call_blocking(&execution)?;
    assert_eq!(replay.verdict, Verdict::Allow, "{:?}", replay.reason);
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 1);
    assert_eq!(
        store
            .load_runtime_participant_history(reference.operation_id(), &fence, NOW)?
            .ok_or("replay history")?
            .1,
        history
    );
    Ok(())
}
