use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn seed(harness: &RecordingHarness, count: u64) -> TestResult {
    for sequence in 0..count {
        let receipt = positive_receipt(&harness.keypair, sequence);
        harness
            .store
            .append_chio_receipt_with_pending_observation_and_timeout(
                &receipt,
                &PendingSettlementObservation {
                    next_visible_at_ms: 0,
                },
                Duration::from_secs(1),
            )?;
    }
    Ok(())
}

#[test]
fn drain_batches_more_than_256_claims_without_point_reads() -> TestResult {
    let harness = recording_harness(
        ClaimMode::Claim,
        RouteMode::Contract,
        HookBehavior::Accepted,
    );
    seed(&harness, 257)?;
    let report = harness.kernel.drain_settlement_attempts(257)?;
    assert_eq!(report.completed, 257);
    assert_eq!(report.lost_leases, 0);
    assert_eq!(harness.hook.calls(), 257);
    let state = harness.store.state();
    assert_eq!(state.batch_sizes, [256, 1]);
    assert_eq!(state.point_reads, 0);
    assert!(state.attempts.is_empty());
    Ok(())
}

#[test]
fn drain_batch_error_uses_point_reads_for_healthy_claims() -> TestResult {
    let harness = recording_harness(
        ClaimMode::Claim,
        RouteMode::Contract,
        HookBehavior::Accepted,
    );
    seed(&harness, 2)?;
    harness.store.state().batch_mode = BatchMode::Error;
    assert_eq!(harness.kernel.drain_settlement_attempts(2)?.completed, 2);
    assert_eq!(harness.hook.calls(), 2);
    let state = harness.store.state();
    assert_eq!(state.batch_sizes, [2]);
    assert_eq!(state.point_reads, 2);
    assert!(state
        .inputs
        .iter()
        .all(|input| matches!(input, SettlementRoutingInput::Accepted)));
    Ok(())
}

#[test]
fn drain_short_batch_refuses_every_claim_without_hook_or_point_fallback() -> TestResult {
    let harness = recording_harness(
        ClaimMode::Claim,
        RouteMode::Contract,
        HookBehavior::Accepted,
    );
    seed(&harness, 2)?;
    harness.store.state().batch_mode = BatchMode::Short;
    assert_eq!(harness.kernel.drain_settlement_attempts(2)?.completed, 2);
    assert_eq!(harness.hook.calls(), 0);
    let state = harness.store.state();
    assert_eq!(state.batch_sizes, [2]);
    assert_eq!(state.point_reads, 0);
    assert_eq!(state.inputs.len(), 2);
    for input in &state.inputs {
        assert!(matches!(input, SettlementRoutingInput::Permanent { reason }
            if *reason == SettlementFailureReason::from_detail(
                SettlementFailureCode::InvalidObservation,
                "settlement receipt batch length does not match the claimed rows")));
    }
    Ok(())
}

#[test]
fn drain_reordered_batch_refuses_misassociated_receipts() -> TestResult {
    let harness = recording_harness(
        ClaimMode::Claim,
        RouteMode::Contract,
        HookBehavior::Accepted,
    );
    seed(&harness, 2)?;
    harness.store.state().batch_mode = BatchMode::Reversed;
    assert_eq!(harness.kernel.drain_settlement_attempts(2)?.completed, 2);
    assert_eq!(harness.hook.calls(), 0);
    let state = harness.store.state();
    assert_eq!(state.point_reads, 0);
    assert_eq!(state.inputs.len(), 2);
    for input in &state.inputs {
        assert!(matches!(input, SettlementRoutingInput::Permanent { reason }
            if *reason == SettlementFailureReason::from_detail(
                SettlementFailureCode::InvalidObservation,
                "stored receipt does not match the claimed settlement row")));
    }
    Ok(())
}
