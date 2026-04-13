use arc_core::web3::{
    validate_web3_settlement_execution_receipt, AnchorInclusionProof, OracleConversionEvidence,
    Web3SettlementDispatchArtifact, Web3SettlementExecutionReceiptArtifact,
    Web3SettlementLifecycleState, ARC_WEB3_SETTLEMENT_RECEIPT_SCHEMA,
};
use serde::{Deserialize, Serialize};

use crate::evm::{
    confirm_transaction, read_bond_snapshot, read_escrow_snapshot,
    scale_token_minor_units_to_arc_amount, EscrowSnapshot, EvmBondSnapshot, EvmTransactionReceipt,
};
use crate::{SettlementChainConfig, SettlementError};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EscrowLifecycleStatus {
    Locked,
    PartiallyReleased,
    Released,
    Refunded,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BondLifecycleStatus {
    Active,
    Released,
    Impaired,
    Expired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SettlementFinalityStatus {
    AwaitingConfirmations,
    AwaitingDisputeWindow,
    Finalized,
    Reorged,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SettlementRecoveryAction {
    WaitForConfirmations,
    WaitForDisputeWindow,
    RetrySubmission,
    ResubmitAfterReorg,
    ExecuteRefund,
    ManualReview,
    ExpireBond,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SettlementFinalityAssessment {
    pub chain_id: String,
    pub required_confirmations: u32,
    pub current_confirmations: u32,
    pub dispute_window_secs: u64,
    pub dispute_window_closes_at: u64,
    pub status: SettlementFinalityStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscrowExecutionProjection {
    pub receipt: Web3SettlementExecutionReceiptArtifact,
    pub finality: SettlementFinalityAssessment,
    pub escrow_snapshot: EscrowSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_action: Option<SettlementRecoveryAction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BondLifecycleObservation {
    pub chain_id: String,
    pub vault_id: String,
    pub snapshot: EvmBondSnapshot,
    pub status: BondLifecycleStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_action: Option<SettlementRecoveryAction>,
}

#[derive(Debug, Clone)]
pub struct ExecutionProjectionInput<'a> {
    pub dispatch: &'a Web3SettlementDispatchArtifact,
    pub tx_hash: &'a str,
    pub execution_receipt_id: String,
    pub settlement_reference: String,
    pub observed_at: Option<u64>,
    pub observed_amount: arc_core::capability::MonetaryAmount,
    pub anchor_proof: Option<&'a AnchorInclusionProof>,
    pub oracle_evidence: Option<&'a OracleConversionEvidence>,
    pub failure_reason: Option<String>,
    pub reversal_of: Option<String>,
    pub note: Option<String>,
}

pub async fn inspect_finality(
    config: &SettlementChainConfig,
    tx_hash: &str,
    amount_units: u64,
    now_override: Option<u64>,
) -> Result<(EvmTransactionReceipt, SettlementFinalityAssessment), SettlementError> {
    let receipt = confirm_transaction(config, tx_hash).await?;
    let assessment =
        inspect_finality_for_receipt(config, &receipt, amount_units, now_override).await?;
    Ok((receipt, assessment))
}

pub async fn inspect_finality_for_receipt(
    config: &SettlementChainConfig,
    receipt: &EvmTransactionReceipt,
    amount_units: u64,
    now_override: Option<u64>,
) -> Result<SettlementFinalityAssessment, SettlementError> {
    let latest_block_number = latest_block_number(config).await?;
    let current_confirmations = latest_block_number
        .saturating_sub(receipt.block_number)
        .saturating_add(1) as u32;
    let current_hash = block_hash_at_number_optional(config, receipt.block_number).await?;
    let tier = config.policy.tier_for_amount(amount_units);
    let dispute_window_closes_at = receipt.observed_at.saturating_add(tier.dispute_window_secs);
    let status = if current_hash.as_deref() != Some(receipt.block_hash.as_str()) {
        SettlementFinalityStatus::Reorged
    } else if current_confirmations < tier.min_confirmations {
        SettlementFinalityStatus::AwaitingConfirmations
    } else if now_override
        .unwrap_or(receipt.observed_at)
        .lt(&dispute_window_closes_at)
    {
        SettlementFinalityStatus::AwaitingDisputeWindow
    } else {
        SettlementFinalityStatus::Finalized
    };
    Ok(SettlementFinalityAssessment {
        chain_id: config.chain_id.clone(),
        required_confirmations: tier.min_confirmations,
        current_confirmations,
        dispute_window_secs: tier.dispute_window_secs,
        dispute_window_closes_at,
        status,
    })
}

pub async fn project_escrow_execution_receipt(
    config: &SettlementChainConfig,
    input: ExecutionProjectionInput<'_>,
) -> Result<EscrowExecutionProjection, SettlementError> {
    let escrow_snapshot = read_escrow_snapshot(config, &input.dispatch.escrow_id).await?;
    let (_, finality) = inspect_finality(
        config,
        input.tx_hash,
        input.dispatch.settlement_amount.units,
        input.observed_at,
    )
    .await?;

    let lifecycle_state = if finality.status == SettlementFinalityStatus::Reorged {
        Web3SettlementLifecycleState::Reorged
    } else if escrow_snapshot.refunded {
        Web3SettlementLifecycleState::TimedOut
    } else if escrow_snapshot.released_minor_units == 0 {
        Web3SettlementLifecycleState::Failed
    } else if escrow_snapshot.released_minor_units < escrow_snapshot.deposited_minor_units {
        Web3SettlementLifecycleState::PartiallySettled
    } else {
        Web3SettlementLifecycleState::Settled
    };

    let failure_reason = match lifecycle_state {
        Web3SettlementLifecycleState::TimedOut => Some(
            input
                .failure_reason
                .clone()
                .unwrap_or_else(|| "escrow refunded after deadline".to_string()),
        ),
        Web3SettlementLifecycleState::Failed => {
            Some(input.failure_reason.clone().unwrap_or_else(|| {
                "settlement submission failed before a durable on-chain release".to_string()
            }))
        }
        Web3SettlementLifecycleState::Reorged => {
            Some(input.failure_reason.clone().unwrap_or_else(|| {
                "transaction receipt disappeared from the canonical chain".to_string()
            }))
        }
        _ => input.failure_reason.clone(),
    };

    let settled_amount = if lifecycle_state == Web3SettlementLifecycleState::TimedOut {
        scale_token_minor_units_to_arc_amount(
            escrow_snapshot.remaining_minor_units,
            &input.dispatch.settlement_amount.currency,
            config,
        )?
    } else {
        input.observed_amount.clone()
    };

    let observed_execution = arc_core::credit::CapitalExecutionObservation {
        observed_at: input.observed_at.unwrap_or_else(|| {
            finality
                .dispute_window_closes_at
                .saturating_sub(finality.dispute_window_secs)
        }),
        external_reference_id: input.tx_hash.to_string(),
        amount: settled_amount.clone(),
    };

    let receipt = Web3SettlementExecutionReceiptArtifact {
        schema: ARC_WEB3_SETTLEMENT_RECEIPT_SCHEMA.to_string(),
        execution_receipt_id: input.execution_receipt_id,
        issued_at: observed_execution.observed_at,
        dispatch: input.dispatch.clone(),
        observed_execution,
        lifecycle_state,
        settlement_reference: input.settlement_reference,
        reconciled_anchor_proof: input.anchor_proof.cloned(),
        oracle_evidence: input.oracle_evidence.cloned(),
        settled_amount,
        reversal_of: input.reversal_of.clone(),
        failure_reason,
        note: input.note.clone(),
    };
    validate_web3_settlement_execution_receipt(&receipt)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;

    let recovery_action = recovery_action_for_projection(finality.status, lifecycle_state);

    Ok(EscrowExecutionProjection {
        receipt,
        finality,
        escrow_snapshot,
        recovery_action,
    })
}

pub async fn observe_bond(
    config: &SettlementChainConfig,
    vault_id: &str,
) -> Result<BondLifecycleObservation, SettlementError> {
    let snapshot = read_bond_snapshot(config, vault_id).await?;
    let status = if snapshot.expired {
        BondLifecycleStatus::Expired
    } else if snapshot.released {
        BondLifecycleStatus::Released
    } else if snapshot.slashed_minor_units > 0 {
        BondLifecycleStatus::Impaired
    } else {
        BondLifecycleStatus::Active
    };
    let recovery_action = if matches!(
        status,
        BondLifecycleStatus::Active | BondLifecycleStatus::Expired
    ) {
        None
    } else {
        Some(SettlementRecoveryAction::ManualReview)
    };
    Ok(BondLifecycleObservation {
        chain_id: config.chain_id.clone(),
        vault_id: vault_id.to_string(),
        snapshot,
        status,
        recovery_action,
    })
}

async fn latest_block_number(config: &SettlementChainConfig) -> Result<u64, SettlementError> {
    let block = reqwest::Client::new()
        .post(&config.rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": "eth_getBlockByNumber",
            "params": ["latest", false],
        }))
        .send()
        .await
        .map_err(|error| SettlementError::Rpc(error.to_string()))?
        .json::<serde_json::Value>()
        .await
        .map_err(|error| SettlementError::Rpc(error.to_string()))?;
    let result = block.get("result").ok_or_else(|| {
        SettlementError::Rpc("eth_getBlockByNumber returned no result".to_string())
    })?;
    parse_hex_u64(
        result
            .get("number")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| SettlementError::Rpc("latest block missing number".to_string()))?,
    )
}

async fn block_hash_at_number_optional(
    config: &SettlementChainConfig,
    block_number: u64,
) -> Result<Option<String>, SettlementError> {
    let block = reqwest::Client::new()
        .post(&config.rpc_url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": "eth_getBlockByNumber",
            "params": [format!("0x{block_number:x}"), false],
        }))
        .send()
        .await
        .map_err(|error| SettlementError::Rpc(error.to_string()))?
        .json::<serde_json::Value>()
        .await
        .map_err(|error| SettlementError::Rpc(error.to_string()))?;
    let Some(result) = block.get("result") else {
        return Err(SettlementError::Rpc(
            "eth_getBlockByNumber returned no result".to_string(),
        ));
    };
    if result.is_null() {
        return Ok(None);
    }
    Ok(result
        .get("hash")
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string))
}

fn parse_hex_u64(value: &str) -> Result<u64, SettlementError> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16)
        .map_err(|error| SettlementError::Rpc(error.to_string()))
}

fn recovery_action_for_projection(
    finality_status: SettlementFinalityStatus,
    lifecycle_state: Web3SettlementLifecycleState,
) -> Option<SettlementRecoveryAction> {
    match finality_status {
        SettlementFinalityStatus::AwaitingConfirmations => {
            Some(SettlementRecoveryAction::WaitForConfirmations)
        }
        SettlementFinalityStatus::AwaitingDisputeWindow => {
            Some(SettlementRecoveryAction::WaitForDisputeWindow)
        }
        SettlementFinalityStatus::Reorged => Some(SettlementRecoveryAction::ResubmitAfterReorg),
        SettlementFinalityStatus::Finalized => match lifecycle_state {
            Web3SettlementLifecycleState::Failed => Some(SettlementRecoveryAction::RetrySubmission),
            Web3SettlementLifecycleState::TimedOut => Some(SettlementRecoveryAction::ExecuteRefund),
            _ => None,
        },
    }
}
