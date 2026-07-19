fn validate_finality(bundle: &PublicSettlementProofBundle) -> Result<(), Web3ContractError> {
    if bundle.observed_confirmations < bundle.required_confirmations {
        return Err(Web3ContractError::InvalidProof(
            "settlement finality below threshold".to_string(),
        ));
    }
    let snapshot_confirmations = bundle
        .chain_snapshot
        .latest_block_number
        .saturating_sub(bundle.chain_snapshot.observed_block_number)
        .saturating_add(1);
    if u64::from(bundle.observed_confirmations) > snapshot_confirmations {
        return Err(Web3ContractError::InvalidProof(
            "public settlement observed confirmations exceed chain snapshot".to_string(),
        ));
    }
    Ok(())
}

fn validate_dispute_posture(
    bundle: &PublicSettlementProofBundle,
    trust: &PublicSettlementVerifierTrust,
) -> Result<(), Web3ContractError> {
    let dispute = required_dispute_snapshot(bundle)?;
    match bundle.dispute_posture {
        PublicSettlementDisputePosture::Refunded
            if !matches!(
                bundle.settlement_receipt.lifecycle_state,
                Web3SettlementLifecycleState::Reversed | Web3SettlementLifecycleState::TimedOut
            ) =>
        {
            Err(Web3ContractError::InvalidSettlement(
                "refunded dispute posture requires reversed or timed out settlement".to_string(),
            ))
        }
        PublicSettlementDisputePosture::Slashed
            if !matches!(
                bundle.settlement_receipt.lifecycle_state,
                Web3SettlementLifecycleState::ChargedBack | Web3SettlementLifecycleState::Reversed
            ) =>
        {
            Err(Web3ContractError::InvalidSettlement(
                "slashed dispute posture requires charged back or reversed settlement".to_string(),
            ))
        }
        _ => Ok(()),
    }?;
    validate_dispute_snapshot(bundle, dispute, trust)?;
    if dispute.open_dispute_count > 0 {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement active dispute blocks finality".to_string(),
        ));
    }
    Ok(())
}

fn validate_finality_settlement_state(
    bundle: &PublicSettlementProofBundle,
) -> Result<(), Web3ContractError> {
    if matches!(
        bundle.settlement_receipt.lifecycle_state,
        Web3SettlementLifecycleState::Failed
            | Web3SettlementLifecycleState::Reorged
            | Web3SettlementLifecycleState::EscrowLocked
    ) {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement finality requires successful settlement state".to_string(),
        ));
    }
    Ok(())
}

fn active_dispute_posture(posture: PublicSettlementDisputePosture) -> bool {
    matches!(
        posture,
        PublicSettlementDisputePosture::Challenged
            | PublicSettlementDisputePosture::Bonded
            | PublicSettlementDisputePosture::Appealed
    )
}

fn finality_report_status(bundle: &PublicSettlementProofBundle) -> &'static str {
    match bundle.settlement_receipt.lifecycle_state {
        Web3SettlementLifecycleState::Settled => match bundle.dispute_posture {
            PublicSettlementDisputePosture::Closed => "closed",
            _ => "final",
        },
        Web3SettlementLifecycleState::PartiallySettled => "partially_settled",
        Web3SettlementLifecycleState::Reversed => match bundle.dispute_posture {
            PublicSettlementDisputePosture::Refunded => "refunded",
            PublicSettlementDisputePosture::Slashed => "slashed",
            _ => "reversed",
        },
        Web3SettlementLifecycleState::ChargedBack => match bundle.dispute_posture {
            PublicSettlementDisputePosture::Slashed => "slashed",
            _ => "charged_back",
        },
        Web3SettlementLifecycleState::TimedOut => match bundle.dispute_posture {
            PublicSettlementDisputePosture::Refunded => "refunded",
            _ => "timed_out",
        },
        Web3SettlementLifecycleState::Failed => "failed",
        Web3SettlementLifecycleState::Reorged => "reorged",
        Web3SettlementLifecycleState::PendingDispatch
        | Web3SettlementLifecycleState::EscrowLocked => "not_final",
    }
}

fn validate_dispute_snapshot(
    bundle: &PublicSettlementProofBundle,
    dispute: &PublicSettlementDisputeSnapshot,
    trust: &PublicSettlementVerifierTrust,
) -> Result<(), Web3ContractError> {
    if dispute.schema != CHIO_WEB3_SETTLEMENT_DISPUTE_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(dispute.schema.clone()));
    }
    ensure_non_empty(&dispute.dispute_id, "public_settlement.dispute.dispute_id")?;
    if dispute.posture != bundle.dispute_posture {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement dispute posture mismatch".to_string(),
        ));
    }
    if dispute.challenge_window_secs == 0 {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute challenge window missing".to_string(),
        ));
    }
    let Some(expected_window_close) = bundle
        .settlement_receipt
        .observed_execution
        .observed_at
        .checked_add(dispute.challenge_window_secs)
    else {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute window overflow".to_string(),
        ));
    };
    if dispute.window_closed_at < expected_window_close {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute window closes before challenge period".to_string(),
        ));
    }
    if dispute.observed_at < dispute.window_closed_at {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute snapshot before challenge window close".to_string(),
        ));
    }
    let verifier_now = trust.verifier_now_unix_seconds.ok_or_else(|| {
        Web3ContractError::InvalidProof(
            "public settlement dispute verifier time missing".to_string(),
        )
    })?;
    if dispute.window_closed_at > verifier_now || dispute.observed_at > verifier_now {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute snapshot is from the future".to_string(),
        ));
    }
    for receipt_id in &dispute.linked_receipt_ids {
        ensure_non_empty(receipt_id, "public_settlement.dispute.linked_receipt_ids")?;
    }
    if dispute.posture != PublicSettlementDisputePosture::Undisputed
        && !dispute
            .linked_receipt_ids
            .iter()
            .any(|receipt_id| receipt_id == &bundle.settlement_receipt.execution_receipt_id)
    {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute not linked to settlement receipt".to_string(),
        ));
    }
    validate_dispute_event_blocks(bundle, dispute, &trust.trusted_dispute_event_blocks)?;
    if dispute.posture == PublicSettlementDisputePosture::Undisputed
        && dispute.open_dispute_count != 0
    {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement open dispute count mismatch".to_string(),
        ));
    }
    if active_dispute_posture(dispute.posture) && dispute.open_dispute_count == 0 {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement active dispute missing".to_string(),
        ));
    }
    Ok(())
}

fn settlement_state_id(state: Web3SettlementLifecycleState) -> &'static str {
    match state {
        Web3SettlementLifecycleState::PendingDispatch => "pending_dispatch",
        Web3SettlementLifecycleState::EscrowLocked => "escrow_locked",
        Web3SettlementLifecycleState::PartiallySettled => "partially_settled",
        Web3SettlementLifecycleState::Settled => "settled",
        Web3SettlementLifecycleState::Reversed => "reversed",
        Web3SettlementLifecycleState::ChargedBack => "charged_back",
        Web3SettlementLifecycleState::TimedOut => "timed_out",
        Web3SettlementLifecycleState::Failed => "failed",
        Web3SettlementLifecycleState::Reorged => "reorged",
    }
}

fn push_claim_once(target: &mut Vec<String>, claim: &str) {
    if !target.iter().any(|existing| existing == claim) {
        target.push(claim.to_string());
    }
}
