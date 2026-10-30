use super::*;
use crate::kernel::settlement_observer::SettlementObserverStatus;

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
fn drain_malformed_batches_fall_back_to_verified_point_reads() -> TestResult {
    for mode in [
        BatchMode::Short,
        BatchMode::Reversed,
        BatchMode::WrongTime,
        BatchMode::MissingFirst,
    ] {
        let harness = recording_harness(
            ClaimMode::Claim,
            RouteMode::Contract,
            HookBehavior::Accepted,
        );
        seed(&harness, 2)?;
        harness.store.state().batch_mode = mode;
        assert_eq!(harness.kernel.drain_settlement_attempts(2)?.completed, 2);
        assert_eq!(harness.hook.calls(), 2);
        let state = harness.store.state();
        assert_eq!(state.batch_sizes, [2]);
        assert!(state.point_reads > 0);
        assert_eq!(
            state.inputs,
            [
                SettlementRoutingInput::Accepted,
                SettlementRoutingInput::Accepted
            ]
        );
        assert!(state.attempts.is_empty());
    }
    Ok(())
}

#[test]
fn drain_install_refuses_missing_current_key_without_replacing_runtime() -> TestResult {
    let mut harness = recording_harness(
        ClaimMode::Claim,
        RouteMode::Contract,
        HookBehavior::Accepted,
    );
    let historical = Keypair::from_seed(&[116; 32]);
    let result = harness.kernel.set_settlement_observer_runtime(
        harness.hook.clone(),
        harness.store.clone(),
        RetryPolicy::default(),
        crate::SettlementDrainTrust::from(historical.public_key()),
    );
    assert!(matches!(
        result,
        Err(KernelError::SettlementConfiguration(
            crate::SettlementRuntimeConfigError::MissingCurrentReceiptKey
        ))
    ));
    seed(&harness, 1)?;
    assert_eq!(harness.kernel.drain_settlement_attempts(1)?.completed, 1);
    assert_eq!(harness.hook.calls(), 1);
    Ok(())
}

fn seed_receipt(harness: &RecordingHarness, receipt: &ChioReceipt) -> TestResult {
    harness
        .store
        .append_chio_receipt_with_pending_observation_and_timeout(
            receipt,
            &PendingSettlementObservation {
                next_visible_at_ms: 0,
            },
            Duration::from_secs(1),
        )?;
    Ok(())
}

fn trust(harness: &mut RecordingHarness, keys: Vec<chio_core::crypto::PublicKey>) -> TestResult {
    harness.kernel.set_settlement_observer_runtime(
        harness.hook.clone(),
        harness.store.clone(),
        RetryPolicy::default(),
        crate::SettlementDrainTrust::new(keys)?,
    )?;
    Ok(())
}

#[test]
fn drain_accepts_explicit_historical_key_but_fresh_observation_refuses_it() -> TestResult {
    let mut harness = recording_harness(
        ClaimMode::Claim,
        RouteMode::Contract,
        HookBehavior::Accepted,
    );
    let historical = Keypair::from_seed(&[112; 32]);
    let receipt = positive_receipt(&historical, 1);
    seed_receipt(&harness, &receipt)?;
    let keys = vec![harness.keypair.public_key(), historical.public_key()];
    trust(&mut harness, keys)?;
    let fresh = harness.kernel.run_settlement_observer(
        &receipt,
        &chio_settle_types::SettlementIdempotencyKey {
            receipt_id: receipt.id.clone(),
            row_version: 1,
        },
    );
    assert!(
        matches!(fresh, SettlementObserverStatus::HookFailed { reason, .. }
        if reason.code() == SettlementFailureCode::UntrustedReceiptSigner)
    );
    assert_eq!(harness.hook.calls(), 0);
    assert_eq!(harness.kernel.drain_settlement_attempts(1)?.completed, 1);
    assert_eq!(harness.hook.calls(), 1);
    assert_eq!(
        harness.store.state().inputs,
        [SettlementRoutingInput::Accepted]
    );
    assert_eq!(harness.kernel.drain_settlement_attempts(1)?.completed, 0);
    assert_eq!(harness.hook.calls(), 1);
    Ok(())
}

#[test]
fn drain_refuses_historical_signer_without_explicit_trust() -> TestResult {
    let harness = recording_harness(
        ClaimMode::Claim,
        RouteMode::Contract,
        HookBehavior::Accepted,
    );
    seed_receipt(
        &harness,
        &positive_receipt(&Keypair::from_seed(&[113; 32]), 1),
    )?;
    assert_eq!(harness.kernel.drain_settlement_attempts(1)?.completed, 1);
    assert_eq!(harness.hook.calls(), 0);
    assert!(
        matches!(&harness.store.state().inputs[..], [SettlementRoutingInput::Permanent { reason }]
        if reason.code() == SettlementFailureCode::UntrustedReceiptSigner)
    );
    Ok(())
}

#[test]
fn drain_trust_replacement_does_not_retain_the_previous_signer() -> TestResult {
    let mut harness = recording_harness(
        ClaimMode::Claim,
        RouteMode::Contract,
        HookBehavior::Accepted,
    );
    let historical = Keypair::from_seed(&[114; 32]);
    let current = harness.keypair.public_key();
    trust(&mut harness, vec![current.clone(), historical.public_key()])?;
    trust(&mut harness, vec![current])?;
    seed_receipt(&harness, &positive_receipt(&historical, 1))?;
    assert_eq!(harness.kernel.drain_settlement_attempts(1)?.completed, 1);
    assert_eq!(harness.hook.calls(), 0);
    assert!(
        matches!(&harness.store.state().inputs[..], [SettlementRoutingInput::Permanent { reason }]
        if reason.code() == SettlementFailureCode::UntrustedReceiptSigner)
    );
    Ok(())
}

#[test]
fn drain_trusted_historical_key_does_not_accept_an_invalid_signature() -> TestResult {
    let mut harness = recording_harness(
        ClaimMode::Claim,
        RouteMode::Contract,
        HookBehavior::Accepted,
    );
    let historical = Keypair::from_seed(&[115; 32]);
    let current = harness.keypair.public_key();
    trust(&mut harness, vec![current, historical.public_key()])?;
    let mut receipt = positive_receipt(&historical, 1);
    receipt.signature = historical.sign_exempt(
        chio_core::crypto::ExemptFormat::JwsSigningInput,
        b"not the receipt signing body",
    );
    seed_receipt(&harness, &receipt)?;
    assert_eq!(harness.kernel.drain_settlement_attempts(1)?.completed, 1);
    assert_eq!(harness.hook.calls(), 0);
    assert!(
        matches!(&harness.store.state().inputs[..], [SettlementRoutingInput::Permanent { reason }]
        if reason.code() == SettlementFailureCode::InvalidReceiptSignature)
    );
    Ok(())
}

#[test]
fn drain_refuses_mismatched_claim_time_before_the_hook() -> TestResult {
    let harness = recording_harness(
        ClaimMode::Claim,
        RouteMode::Contract,
        HookBehavior::Accepted,
    );
    seed(&harness, 1)?;
    {
        let mut state = harness.store.state();
        state.batch_mode = BatchMode::Error;
        state.point_wrong_time = true;
    }
    assert_eq!(harness.kernel.drain_settlement_attempts(1)?.completed, 1);
    assert_eq!(harness.hook.calls(), 0);
    assert!(
        matches!(&harness.store.state().inputs[..], [SettlementRoutingInput::Permanent { reason }]
        if *reason == SettlementFailureReason::from_detail(SettlementFailureCode::InvalidObservation,
            "stored receipt does not match the claimed settlement row"))
    );
    Ok(())
}

#[test]
fn drain_missing_receipt_does_not_block_a_healthy_neighbor() -> TestResult {
    let harness = recording_harness(
        ClaimMode::Claim,
        RouteMode::Contract,
        HookBehavior::Accepted,
    );
    seed(&harness, 2)?;
    {
        let mut state = harness.store.state();
        let first = state
            .receipts
            .keys()
            .min()
            .cloned()
            .ok_or("missing seeded receipt")?;
        state.batch_mode = BatchMode::MissingFirst;
        state.point_missing = Some(first);
    }
    assert_eq!(harness.kernel.drain_settlement_attempts(2)?.completed, 2);
    assert_eq!(harness.hook.calls(), 1);
    let state = harness.store.state();
    assert_eq!(state.point_reads, 1);
    assert!(
        matches!(&state.inputs[..], [SettlementRoutingInput::Permanent { reason }, SettlementRoutingInput::Accepted]
        if *reason == SettlementFailureReason::from_detail(SettlementFailureCode::InvalidObservation,
            "claimed settlement receipt is not stored"))
    );
    Ok(())
}

#[test]
fn drain_batch_error_isolates_a_point_failure_from_a_healthy_neighbor() -> TestResult {
    let harness = recording_harness(
        ClaimMode::Claim,
        RouteMode::Contract,
        HookBehavior::Accepted,
    );
    seed(&harness, 2)?;
    {
        let mut state = harness.store.state();
        state.batch_mode = BatchMode::Error;
        state.point_failure = state.receipts.keys().min().cloned();
    }
    assert_eq!(harness.kernel.drain_settlement_attempts(2)?.completed, 2);
    assert_eq!(harness.hook.calls(), 1);
    let state = harness.store.state();
    assert_eq!(state.point_reads, 2);
    let detail = ReceiptStoreError::Conflict("forced point failure".to_owned()).to_string();
    assert!(
        matches!(&state.inputs[..], [SettlementRoutingInput::Retryable { reason }, SettlementRoutingInput::Accepted]
        if *reason == SettlementFailureReason::from_detail(SettlementFailureCode::Backend, detail))
    );
    Ok(())
}

#[test]
fn drain_lost_lease_is_counted_separately_without_deleting_the_attempt() -> TestResult {
    let harness = recording_harness(
        ClaimMode::Claim,
        RouteMode::LostLease,
        HookBehavior::Accepted,
    );
    seed(&harness, 1)?;
    let report = harness.kernel.drain_settlement_attempts(1)?;
    assert_eq!(report.completed, 0);
    assert_eq!(report.lost_leases, 1);
    assert_eq!(harness.hook.calls(), 1);
    assert_eq!(harness.store.state().attempts.len(), 1);
    Ok(())
}
