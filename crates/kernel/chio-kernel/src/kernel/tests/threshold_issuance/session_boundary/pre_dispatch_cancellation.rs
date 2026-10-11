//! A host cancellation that wins the pre-dispatch boundary is a cancelled outcome.

use super::*;

const PRE_DISPATCH_CANCELLATION: &str = "session request cancelled before dispatch";

/// Parks the approved retry at its first threshold policy lookup. The retry has
/// already claimed the wait there and has not reached the dispatch-start boundary.
fn hold_policy_lookup(fixture: &mut Fixture) -> TestResult<CheckpointControl> {
    let resolver = fixture
        .kernel
        .threshold_approval_requirement_resolver
        .clone()
        .ok_or("policy resolver missing")?;
    let (checkpoint, control) = checkpoint();
    fixture
        .kernel
        .set_threshold_approval_requirement_resolver(StdArc::new(
            move |policy: &str, server: &str, tool: &str| {
                checkpoint.hold()?;
                resolver.resolve_requirement(policy, server, tool)
            },
        ));
    Ok(control)
}

fn host_cancel_before_dispatch(entry: EntryPoint) -> TestResult {
    let mut fixture = Fixture::new()?;
    let (context, proposal) = pending_session_using(&fixture, entry)?;
    fixture.approve(proposal)?;
    let control = hold_policy_lookup(&mut fixture)?;
    let fixture = &fixture;
    let context = &context;
    let response = std::thread::scope(|scope| -> TestResult<ToolCallResponse> {
        let retry =
            scope.spawn(move || evaluate(fixture, context, entry).map_err(|e| e.to_string()));
        control.entered.recv_timeout(HOLD_TIMEOUT)?;
        assert_eq!(
            RequestState::read(fixture, context)?,
            RequestState::claimed()
        );
        fixture
            .kernel
            .request_session_cancellation(&context.session_id, &context.request_id)?;
        assert_eq!(
            RequestState::read(fixture, context)?,
            RequestState {
                cancellation_requested: true,
                ..RequestState::claimed()
            }
        );
        control.release.send(())?;
        Ok(retry.join().map_err(|_| "retry thread panicked")??)
    })?;

    // The dispatch-start boundary observed the host cancellation before any effect.
    assert_eq!(fixture.invocations.load(Ordering::SeqCst), 0);
    assert_eq!(response.verdict, Verdict::Deny);
    let observed = KernelError::RequestCancelled {
        request_id: context.request_id.clone(),
        reason: PRE_DISPATCH_CANCELLATION.into(),
    }
    .to_string();
    assert!(
        matches!(
            response.reason.as_deref(),
            Some(reason) if reason == PRE_DISPATCH_CANCELLATION || reason == observed
        ),
        "{:?}",
        response.reason
    );

    let cancelled = OperationTerminalState::Cancelled {
        reason: PRE_DISPATCH_CANCELLATION.into(),
    };
    assert_eq!(response.terminal_state, cancelled);
    assert_eq!(
        response.receipt.decision,
        Some(Decision::Cancelled {
            reason: PRE_DISPATCH_CANCELLATION.into(),
        })
    );
    assert!(response.receipt.verify_signature()?);
    assert_eq!(
        RequestState::read(fixture, context)?,
        RequestState::finished(cancelled, 0)
    );
    Ok(())
}

#[test]
fn session_host_cancel_before_dispatch_records_cancelled_outcome() -> TestResult {
    host_cancel_before_dispatch(EntryPoint::Session)
}

#[test]
fn nested_sync_host_cancel_before_dispatch_records_cancelled_outcome() -> TestResult {
    host_cancel_before_dispatch(EntryPoint::NestedSync)
}

#[test]
fn nested_async_host_cancel_before_dispatch_records_cancelled_outcome() -> TestResult {
    host_cancel_before_dispatch(EntryPoint::NestedAsync)
}
