//! Public settlement proofs refuse finality claims that disputes, failures or reorgs contradict.

use super::*;

#[test]
fn public_settlement_proof_rejects_failed_settlement_before_finality_claims() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.settlement_receipt.lifecycle_state = Web3SettlementLifecycleState::Failed;
    bundle.settlement_receipt.failure_reason = Some("provider execution failed".to_string());

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement finality requires successful settlement state")
    ));
}

#[test]
fn public_settlement_proof_rejects_reorged_settlement_before_finality_claims() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.settlement_receipt.lifecycle_state = Web3SettlementLifecycleState::Reorged;
    bundle.settlement_receipt.failure_reason = Some("settlement transaction reorged".to_string());

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement finality requires successful settlement state")
    ));
}

#[test]
fn public_settlement_proof_rejects_escrow_locked_before_finality_claims() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.settlement_receipt.lifecycle_state = Web3SettlementLifecycleState::EscrowLocked;
    bundle.settlement_receipt.observed_execution.amount.units = 0;
    bundle.settlement_receipt.settled_amount.units = 0;
    bundle.settlement_receipt.reconciled_anchor_proof = None;
    bundle.settlement_receipt.oracle_evidence = None;
    bundle.chain_snapshot.escrow.released_amount.units = 0;

    let result = verify_sample_public_settlement_proof(&bundle);
    assert!(
        matches!(
            result,
            Err(Web3ContractError::InvalidSettlement(ref message))
                if message.contains("public settlement finality requires successful settlement state")
        ),
        "{result:?}"
    );
}

#[test]
fn public_settlement_proof_rejects_missing_observed_execution_reference() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle
        .settlement_receipt
        .observed_execution
        .external_reference_id
        .clear();

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::MissingField(
            "web3_settlement_receipt.observed_execution.external_reference_id"
        ))
    ));
}

#[test]
fn public_settlement_proof_rejects_malformed_observed_execution_tx_hash() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle
        .settlement_receipt
        .observed_execution
        .external_reference_id = "settlement-web3-reference".to_string();

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("observed execution reference must be an eip155 transaction hash")
    ));
}

#[test]
fn public_settlement_proof_rejects_finality_with_active_dispute() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.dispute_posture = PublicSettlementDisputePosture::Challenged;
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Challenged;
    dispute_snapshot.dispute_id = "dispute-public-settlement-challenged".to_string();
    dispute_snapshot.open_dispute_count = 1;
    dispute_snapshot
        .linked_receipt_ids
        .push(bundle.settlement_receipt.execution_receipt_id.clone());
    let event_block = add_public_settlement_dispute_event_evidence(&mut bundle);

    assert!(matches!(
        verify_sample_public_settlement_proof_with_dispute_event_evidence(&bundle, event_block),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement active dispute blocks finality")
    ));
}

#[test]
fn public_settlement_proof_rejects_dispute_not_linked_to_settlement_receipt() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.dispute_posture = PublicSettlementDisputePosture::Challenged;
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Challenged;
    dispute_snapshot.dispute_id = "dispute-public-settlement-challenged".to_string();
    dispute_snapshot.open_dispute_count = 1;
    dispute_snapshot
        .linked_receipt_ids
        .push("receipt-web3-unrelated".to_string());

    assert!(matches!(
        verify_sample_public_settlement_proof(&bundle),
        Err(Web3ContractError::InvalidProof(message))
            if message.contains("public settlement dispute not linked to settlement receipt")
    ));
}

#[test]
fn public_settlement_proof_rejects_closed_posture_with_open_dispute() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.dispute_posture = PublicSettlementDisputePosture::Closed;
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Closed;
    dispute_snapshot.dispute_id = "dispute-public-settlement-closed".to_string();
    dispute_snapshot.open_dispute_count = 1;
    dispute_snapshot
        .linked_receipt_ids
        .push(bundle.settlement_receipt.execution_receipt_id.clone());
    let event_block = add_public_settlement_dispute_event_evidence(&mut bundle);

    assert!(matches!(
        verify_sample_public_settlement_proof_with_dispute_event_evidence(&bundle, event_block),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("public settlement active dispute blocks finality")
    ));
}

#[test]
fn public_settlement_proof_rejects_refunded_posture_without_reversal() {
    let mut bundle = sample_public_settlement_proof_bundle();
    bundle.dispute_posture = PublicSettlementDisputePosture::Refunded;
    let Some(dispute_snapshot) = bundle.dispute_snapshot.as_mut() else {
        panic!("sample public settlement proof bundle has dispute snapshot");
    };
    dispute_snapshot.posture = PublicSettlementDisputePosture::Refunded;
    dispute_snapshot.dispute_id = "dispute-public-settlement-refunded".to_string();
    dispute_snapshot
        .linked_receipt_ids
        .push(bundle.settlement_receipt.execution_receipt_id.clone());
    let event_block = add_public_settlement_dispute_event_evidence(&mut bundle);

    assert!(matches!(
        verify_sample_public_settlement_proof_with_dispute_event_evidence(&bundle, event_block),
        Err(Web3ContractError::InvalidSettlement(message))
            if message.contains("refunded dispute posture requires reversed or timed out settlement")
    ));
}
