//! Cancellation completes before the actual dropped-claim restoration attempt.
use super::*;

#[test]
fn cancellation_at_restore_checkpoint_completes_threshold_ownership() -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session(&fixture)?;
    fixture.approve(proposal)?;
    let SessionOperation::ToolCall(operation) = operation(&fixture.request) else {
        return Err("tool operation missing".into());
    };
    let checkpoint_ran = AtomicBool::new(false);
    fixture
        .kernel
        .drop_threshold_claim_with_restore_checkpoint(&context, &operation, || {
            // The hook is per claim and runs after the original snapshot read,
            // before restoration acquires the original request-map write lock.
            // A complete real cancellation here fixes the ordering without
            // sleeps, scheduler fairness or a replica state machine.
            let cancelled = fixture
                .kernel
                .request_session_cancellation(&context.session_id, &context.request_id);
            assert!(cancelled.is_ok(), "{cancelled:?}");
            checkpoint_ran.store(true, Ordering::SeqCst);
        })?;
    assert!(checkpoint_ran.load(Ordering::SeqCst));
    let session = fixture
        .kernel
        .session(&context.session_id)
        .ok_or("session missing")?;
    assert!(
        session.inflight().is_empty(),
        "cancellation completed before restore, but the request stayed in flight"
    );
    assert!(matches!(
        session.terminal().get(&context.request_id),
        Some(OperationTerminalState::Cancelled { .. })
    ));
    assert!(matches!(
        session
            .request_lineage(&context.request_id)
            .ok_or("original request lineage missing")?
            .terminal_state,
        Some(OperationTerminalState::Cancelled { .. })
    ));
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    Ok(())
}
