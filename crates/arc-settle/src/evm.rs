use std::str::FromStr;
use std::thread;
use std::time::Duration;

use alloy_primitives::{keccak256, Address, FixedBytes, B256, U256};
use alloy_sol_types::{sol, SolCall};
use arc_core::canonical::canonical_json_bytes;
use arc_core::capability::MonetaryAmount;
use arc_core::credit::{
    CapitalExecutionInstructionAction, CapitalExecutionRailKind, CreditBondLifecycleState,
    SignedCapitalExecutionInstruction, SignedCreditBond,
};
use arc_core::hashing::Hash;
use arc_core::merkle::leaf_hash;
use arc_core::receipt::ArcReceipt;
use arc_core::web3::{
    validate_web3_settlement_dispatch, validate_web3_settlement_execution_receipt,
    verify_anchor_inclusion_proof, verify_web3_identity_binding, AnchorInclusionProof,
    SignedWeb3IdentityBinding, Web3KeyBindingPurpose, Web3SettlementDispatchArtifact,
    Web3SettlementExecutionReceiptArtifact, Web3SettlementLifecycleState, Web3SettlementPath,
    Web3SettlementSupportBoundary, ARC_WEB3_SETTLEMENT_DISPATCH_SCHEMA,
    ARC_WEB3_SETTLEMENT_RECEIPT_SCHEMA,
};
use arc_web3_bindings::{ArcMerkleProof, IArcBondVault, IArcEscrow};
use reqwest::Client;
use secp256k1::ecdsa::RecoverableSignature;
use secp256k1::{Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{SettlementChainConfig, SettlementCommitment, SettlementError};

sol! {
    interface IERC20ApproveOnly {
        function approve(address spender, uint256 amount) external returns (bool);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedEvmCall {
    pub from_address: String,
    pub to_address: String,
    pub data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gas_limit: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedErc20Approval {
    pub owner_address: String,
    pub token_address: String,
    pub spender_address: String,
    pub amount_minor_units: u128,
    pub call: PreparedEvmCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscrowDispatchRequest {
    pub dispatch_id: String,
    pub issued_at: u64,
    pub trust_profile_id: String,
    pub contract_package_id: String,
    pub capability_id: String,
    pub depositor_address: String,
    pub beneficiary_address: String,
    pub capital_instruction: SignedCapitalExecutionInstruction,
    pub settlement_path: Web3SettlementPath,
    pub oracle_evidence_required_for_fx: bool,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedEscrowCreate {
    pub expected_escrow_id: String,
    pub capability_commitment: String,
    pub settlement_amount_minor_units: u128,
    pub dispatch: Web3SettlementDispatchArtifact,
    pub call: PreparedEvmCall,
}

impl PreparedEscrowCreate {
    #[must_use]
    pub fn commitment(&self) -> SettlementCommitment {
        SettlementCommitment {
            chain_id: self.dispatch.chain_id.clone(),
            lane_kind: match self.dispatch.settlement_path {
                Web3SettlementPath::DualSignature => "evm_dual_signature",
                Web3SettlementPath::MerkleProof => "evm_merkle_proof",
            }
            .to_string(),
            capability_commitment: self.capability_commitment.clone(),
            receipt_reference: self.dispatch.escrow_id.clone(),
            operator_identity: self.dispatch.beneficiary_address.clone(),
            settlement_amount: self.dispatch.settlement_amount.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EscrowExecutionAmount {
    Full,
    Partial(MonetaryAmount),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedMerkleRelease {
    pub escrow_id: String,
    pub chain_id: String,
    pub receipt_leaf_hash: String,
    pub merkle_root: String,
    pub partial: bool,
    pub settlement_amount_minor_units: u128,
    pub observed_amount: MonetaryAmount,
    pub call: PreparedEvmCall,
}

impl PreparedMerkleRelease {
    #[must_use]
    pub fn commitment(
        &self,
        capability_commitment: String,
        operator_identity: String,
    ) -> SettlementCommitment {
        SettlementCommitment {
            chain_id: self.chain_id.clone(),
            lane_kind: "evm_merkle_proof".to_string(),
            capability_commitment,
            receipt_reference: self.receipt_leaf_hash.clone(),
            operator_identity,
            settlement_amount: self.observed_amount.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvmSignature {
    pub v: u8,
    pub r: String,
    pub s: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DualSignReleaseInput {
    pub operator_private_key_hex: String,
    pub observed_amount: MonetaryAmount,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedDualSignRelease {
    pub escrow_id: String,
    pub chain_id: String,
    pub receipt_hash: String,
    pub digest: String,
    pub settlement_amount_minor_units: u128,
    pub observed_amount: MonetaryAmount,
    pub signature: EvmSignature,
    pub call: PreparedEvmCall,
}

impl PreparedDualSignRelease {
    #[must_use]
    pub fn commitment(
        &self,
        capability_commitment: String,
        operator_identity: String,
    ) -> SettlementCommitment {
        SettlementCommitment {
            chain_id: self.chain_id.clone(),
            lane_kind: "evm_dual_signature".to_string(),
            capability_commitment,
            receipt_reference: self.receipt_hash.clone(),
            operator_identity,
            settlement_amount: self.observed_amount.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedEscrowRefund {
    pub escrow_id: String,
    pub chain_id: String,
    pub call: PreparedEvmCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BondLockRequest {
    pub principal_address: String,
    pub bond: SignedCreditBond,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedBondLock {
    pub vault_id: String,
    pub bond_id_hash: String,
    pub facility_id_hash: String,
    pub collateral_minor_units: u128,
    pub reserve_requirement_minor_units: u128,
    pub call: PreparedEvmCall,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedBondRelease {
    pub vault_id: String,
    pub chain_id: String,
    pub evidence_hash: String,
    pub call: PreparedEvmCall,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedBondImpair {
    pub vault_id: String,
    pub chain_id: String,
    pub evidence_hash: String,
    pub slash_amount_minor_units: u128,
    pub call: PreparedEvmCall,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedBondExpiry {
    pub vault_id: String,
    pub chain_id: String,
    pub call: PreparedEvmCall,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvmLogEntry {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_index: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvmTransactionReceipt {
    pub tx_hash: String,
    pub block_number: u64,
    pub block_hash: String,
    pub status: bool,
    pub from_address: String,
    pub to_address: String,
    pub gas_used: u64,
    pub observed_at: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub logs: Vec<EvmLogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EscrowSnapshot {
    pub escrow_id: String,
    pub depositor_address: String,
    pub beneficiary_address: String,
    pub deadline: u64,
    pub deposited_minor_units: u128,
    pub released_minor_units: u128,
    pub refunded: bool,
    pub remaining_minor_units: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvmBondSnapshot {
    pub vault_id: String,
    pub principal_address: String,
    pub expires_at: u64,
    pub locked_minor_units: u128,
    pub reserve_requirement_minor_units: u128,
    pub reserve_requirement_ratio_bps: u16,
    pub slashed_minor_units: u128,
    pub released: bool,
    pub expired: bool,
}

#[derive(Debug, Deserialize)]
struct JsonRpcEnvelope {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: u64,
    result: Option<Value>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

pub fn scale_arc_amount_to_token_minor_units(
    amount: &MonetaryAmount,
    config: &SettlementChainConfig,
) -> Result<u128, SettlementError> {
    config.validate()?;
    let arc_decimals = u32::from(config.policy.arc_minor_unit_decimals);
    let token_decimals = u32::from(config.policy.token_minor_unit_decimals);
    let amount_units = u128::from(amount.units);
    if token_decimals >= arc_decimals {
        let scale = 10_u128
            .checked_pow(token_decimals - arc_decimals)
            .ok_or_else(|| {
                SettlementError::InvalidInput("amount scaling overflowed".to_string())
            })?;
        amount_units
            .checked_mul(scale)
            .ok_or_else(|| SettlementError::InvalidInput("scaled amount overflowed".to_string()))
    } else {
        let divisor = 10_u128
            .checked_pow(arc_decimals - token_decimals)
            .ok_or_else(|| {
                SettlementError::InvalidInput("amount scaling overflowed".to_string())
            })?;
        if amount_units % divisor != 0 {
            return Err(SettlementError::InvalidInput(
                "ARC amount cannot be represented exactly in settlement token units".to_string(),
            ));
        }
        Ok(amount_units / divisor)
    }
}

pub(crate) fn scale_token_minor_units_to_arc_amount(
    units: u128,
    currency: &str,
    config: &SettlementChainConfig,
) -> Result<MonetaryAmount, SettlementError> {
    let arc_decimals = u32::from(config.policy.arc_minor_unit_decimals);
    let token_decimals = u32::from(config.policy.token_minor_unit_decimals);
    let arc_units = if token_decimals >= arc_decimals {
        let divisor = 10_u128
            .checked_pow(token_decimals - arc_decimals)
            .ok_or_else(|| {
                SettlementError::InvalidInput("amount scaling overflowed".to_string())
            })?;
        if !units.is_multiple_of(divisor) {
            return Err(SettlementError::InvalidInput(
                "token amount cannot be represented exactly in ARC units".to_string(),
            ));
        }
        units / divisor
    } else {
        let scale = 10_u128
            .checked_pow(arc_decimals - token_decimals)
            .ok_or_else(|| {
                SettlementError::InvalidInput("amount scaling overflowed".to_string())
            })?;
        units
            .checked_mul(scale)
            .ok_or_else(|| SettlementError::InvalidInput("scaled amount overflowed".to_string()))?
    };
    let amount = u64::try_from(arc_units)
        .map_err(|_| SettlementError::InvalidInput("ARC amount does not fit u64".to_string()))?;
    Ok(MonetaryAmount {
        units: amount,
        currency: currency.to_string(),
    })
}

pub fn prepare_erc20_approval(
    token_address: &str,
    owner_address: &str,
    spender_address: &str,
    amount_minor_units: u128,
) -> Result<PreparedErc20Approval, SettlementError> {
    let spender = parse_address(spender_address, "spender_address")?;
    let amount = U256::from(amount_minor_units);
    let call = IERC20ApproveOnly::approveCall { spender, amount };
    Ok(PreparedErc20Approval {
        owner_address: owner_address.to_string(),
        token_address: token_address.to_string(),
        spender_address: spender_address.to_string(),
        amount_minor_units,
        call: PreparedEvmCall {
            from_address: owner_address.to_string(),
            to_address: token_address.to_string(),
            data: encode_call(call),
            gas_limit: None,
        },
    })
}

pub async fn prepare_web3_escrow_dispatch(
    config: &SettlementChainConfig,
    request: &EscrowDispatchRequest,
    binding: &SignedWeb3IdentityBinding,
) -> Result<PreparedEscrowCreate, SettlementError> {
    config.validate()?;
    ensure_instruction_ready(
        config,
        &request.capital_instruction,
        &request.beneficiary_address,
    )?;
    ensure_settlement_binding(config, binding, Web3KeyBindingPurpose::Settle)?;

    if request.dispatch_id.trim().is_empty() {
        return Err(SettlementError::InvalidInput(
            "dispatch_id is required".to_string(),
        ));
    }
    if request.capability_id.trim().is_empty() {
        return Err(SettlementError::InvalidInput(
            "capability_id is required".to_string(),
        ));
    }

    let settlement_amount = request
        .capital_instruction
        .body
        .amount
        .clone()
        .ok_or_else(|| {
            SettlementError::InvalidDispatch("capital instruction amount is required".to_string())
        })?;
    let amount_minor_units = scale_arc_amount_to_token_minor_units(&settlement_amount, config)?;
    let operator_key_hash = keccak256(binding.certificate.arc_public_key.as_bytes());
    let terms = IArcEscrow::EscrowTerms {
        capabilityId: hash_string_id(&request.capability_id),
        depositor: parse_address(&request.depositor_address, "depositor_address")?,
        beneficiary: parse_address(&request.beneficiary_address, "beneficiary_address")?,
        token: parse_address(&config.settlement_token_address, "settlement_token_address")?,
        maxAmount: U256::from(amount_minor_units),
        deadline: U256::from(request.capital_instruction.body.execution_window.not_after),
        operator: parse_address(&config.operator_address, "operator_address")?,
        operatorKeyHash: operator_key_hash,
    };

    let derive_call = IArcEscrow::deriveEscrowIdCall {
        terms: terms.clone(),
    };
    let static_result = eth_call_raw(
        config,
        &PreparedEvmCall {
            from_address: request.depositor_address.clone(),
            to_address: config.escrow_contract.clone(),
            data: encode_call(derive_call),
            gas_limit: None,
        },
    )
    .await?;
    let result_bytes = decode_hex_bytes(&static_result)?;
    let expected_escrow_id = IArcEscrow::deriveEscrowIdCall::abi_decode_returns(&result_bytes)
        .map_err(|error| {
            SettlementError::Serialization(format!("deriveEscrowId decode failed: {error}"))
        })?;
    let expected_escrow_id = format_b256(expected_escrow_id);
    let create_call_data = encode_call(IArcEscrow::createEscrowCall { terms });

    let dispatch = Web3SettlementDispatchArtifact {
        schema: ARC_WEB3_SETTLEMENT_DISPATCH_SCHEMA.to_string(),
        dispatch_id: request.dispatch_id.clone(),
        issued_at: request.issued_at,
        trust_profile_id: request.trust_profile_id.clone(),
        contract_package_id: request.contract_package_id.clone(),
        chain_id: config.chain_id.clone(),
        capital_instruction: request.capital_instruction.clone(),
        bond: None,
        settlement_path: request.settlement_path,
        settlement_amount: settlement_amount.clone(),
        escrow_id: expected_escrow_id.clone(),
        escrow_contract: config.escrow_contract.clone(),
        bond_vault_contract: config.bond_vault_contract.clone(),
        beneficiary_address: request.beneficiary_address.clone(),
        support_boundary: Web3SettlementSupportBoundary {
            real_dispatch_supported: true,
            anchor_proof_required: request.settlement_path == Web3SettlementPath::MerkleProof,
            oracle_evidence_required_for_fx: request.oracle_evidence_required_for_fx,
            custody_boundary_explicit: true,
            reversal_supported: true,
        },
        note: request.note.clone(),
    };
    validate_web3_settlement_dispatch(&dispatch)
        .map_err(|error| SettlementError::InvalidDispatch(error.to_string()))?;

    Ok(PreparedEscrowCreate {
        expected_escrow_id,
        capability_commitment: format_b256(hash_string_id(&request.capability_id)),
        settlement_amount_minor_units: amount_minor_units,
        dispatch,
        call: PreparedEvmCall {
            from_address: request.depositor_address.clone(),
            to_address: config.escrow_contract.clone(),
            data: create_call_data,
            gas_limit: None,
        },
    })
}

pub fn prepare_merkle_release(
    config: &SettlementChainConfig,
    dispatch: &Web3SettlementDispatchArtifact,
    anchor_proof: &AnchorInclusionProof,
    amount: EscrowExecutionAmount,
) -> Result<PreparedMerkleRelease, SettlementError> {
    config.validate()?;
    validate_web3_settlement_dispatch(dispatch)
        .map_err(|error| SettlementError::InvalidDispatch(error.to_string()))?;
    if dispatch.chain_id != config.chain_id {
        return Err(SettlementError::InvalidDispatch(format!(
            "dispatch chain_id {} does not match config {}",
            dispatch.chain_id, config.chain_id
        )));
    }
    if dispatch.settlement_path != Web3SettlementPath::MerkleProof {
        return Err(SettlementError::Unsupported(
            "dispatch is not configured for the Merkle settlement path".to_string(),
        ));
    }
    verify_anchor_inclusion_proof(anchor_proof)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    if let Some(chain_anchor) = anchor_proof.chain_anchor.as_ref() {
        if chain_anchor.chain_id != dispatch.chain_id {
            return Err(SettlementError::InvalidDispatch(
                "anchor proof chain does not match the settlement dispatch".to_string(),
            ));
        }
    }

    let proof = ArcMerkleProof {
        audit_path: anchor_proof
            .receipt_inclusion
            .proof
            .audit_path
            .iter()
            .map(hash_to_b256)
            .collect(),
        leaf_index: U256::from(anchor_proof.receipt_inclusion.proof.leaf_index as u64),
        tree_size: U256::from(anchor_proof.receipt_inclusion.proof.tree_size as u64),
    };
    let receipt_bytes = canonical_json_bytes(&anchor_proof.receipt.body())
        .map_err(|error| SettlementError::Serialization(error.to_string()))?;
    let leaf = leaf_hash(&receipt_bytes);
    let observed_amount = match amount {
        EscrowExecutionAmount::Full => dispatch.settlement_amount.clone(),
        EscrowExecutionAmount::Partial(amount) => amount,
    };
    let amount_minor_units = scale_arc_amount_to_token_minor_units(&observed_amount, config)?;
    let escrow_id = parse_b256_hex(&dispatch.escrow_id, "dispatch.escrow_id")?;
    let call = if observed_amount == dispatch.settlement_amount {
        IArcEscrow::releaseWithProofDetailedCall {
            escrowId: escrow_id,
            proof: (&proof).into(),
            root: hash_to_b256(&anchor_proof.receipt_inclusion.merkle_root),
            receiptHash: hash_to_b256(&leaf),
            settledAmount: U256::from(amount_minor_units),
        }
        .abi_encode()
    } else {
        IArcEscrow::partialReleaseWithProofDetailedCall {
            escrowId: escrow_id,
            proof: (&proof).into(),
            root: hash_to_b256(&anchor_proof.receipt_inclusion.merkle_root),
            receiptHash: hash_to_b256(&leaf),
            amount: U256::from(amount_minor_units),
        }
        .abi_encode()
    };

    Ok(PreparedMerkleRelease {
        escrow_id: dispatch.escrow_id.clone(),
        chain_id: dispatch.chain_id.clone(),
        receipt_leaf_hash: leaf.to_hex_prefixed(),
        merkle_root: anchor_proof.receipt_inclusion.merkle_root.to_hex_prefixed(),
        partial: observed_amount != dispatch.settlement_amount,
        settlement_amount_minor_units: amount_minor_units,
        observed_amount,
        call: PreparedEvmCall {
            from_address: dispatch.beneficiary_address.clone(),
            to_address: config.escrow_contract.clone(),
            data: format!("0x{}", hex::encode(call)),
            gas_limit: None,
        },
    })
}

pub fn prepare_dual_sign_release(
    config: &SettlementChainConfig,
    dispatch: &Web3SettlementDispatchArtifact,
    receipt: &ArcReceipt,
    input: &DualSignReleaseInput,
) -> Result<PreparedDualSignRelease, SettlementError> {
    config.validate()?;
    validate_web3_settlement_dispatch(dispatch)
        .map_err(|error| SettlementError::InvalidDispatch(error.to_string()))?;
    if dispatch.settlement_path != Web3SettlementPath::DualSignature {
        return Err(SettlementError::Unsupported(
            "dispatch is not configured for the dual-signature path".to_string(),
        ));
    }
    let verified = receipt
        .verify_signature()
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    if !verified {
        return Err(SettlementError::Verification(
            "receipt signature verification failed".to_string(),
        ));
    }
    if input.observed_amount != dispatch.settlement_amount {
        return Err(SettlementError::Unsupported(
            "dual-signature release is bounded to full settlement on the official stack"
                .to_string(),
        ));
    }
    let amount_minor_units = scale_arc_amount_to_token_minor_units(&input.observed_amount, config)?;
    let receipt_hash = keccak256(
        canonical_json_bytes(&receipt.body())
            .map_err(|error| SettlementError::Serialization(error.to_string()))?,
    );
    let escrow_id = parse_b256_hex(&dispatch.escrow_id, "dispatch.escrow_id")?;
    let digest = dual_sign_digest(
        config,
        &config.escrow_contract,
        &escrow_id,
        &receipt_hash,
        amount_minor_units,
    )?;
    let signature = sign_digest(&input.operator_private_key_hex, &digest)?;

    let call = IArcEscrow::releaseWithSignatureCall {
        escrowId: escrow_id,
        receiptHash: receipt_hash,
        settledAmount: U256::from(amount_minor_units),
        v: signature.v,
        r: parse_b256_hex(&signature.r, "signature.r")?,
        s: parse_b256_hex(&signature.s, "signature.s")?,
    };

    Ok(PreparedDualSignRelease {
        escrow_id: dispatch.escrow_id.clone(),
        chain_id: dispatch.chain_id.clone(),
        receipt_hash: format_b256(receipt_hash),
        digest: format_b256(digest),
        settlement_amount_minor_units: amount_minor_units,
        observed_amount: input.observed_amount.clone(),
        signature,
        call: PreparedEvmCall {
            from_address: dispatch.beneficiary_address.clone(),
            to_address: config.escrow_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    })
}

pub fn prepare_escrow_refund(
    config: &SettlementChainConfig,
    dispatch: &Web3SettlementDispatchArtifact,
    caller_address: &str,
) -> Result<PreparedEscrowRefund, SettlementError> {
    config.validate()?;
    let call = IArcEscrow::refundCall {
        escrowId: parse_b256_hex(&dispatch.escrow_id, "dispatch.escrow_id")?,
    };
    Ok(PreparedEscrowRefund {
        escrow_id: dispatch.escrow_id.clone(),
        chain_id: config.chain_id.clone(),
        call: PreparedEvmCall {
            from_address: caller_address.to_string(),
            to_address: config.escrow_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    })
}

pub async fn prepare_bond_lock(
    config: &SettlementChainConfig,
    request: &BondLockRequest,
) -> Result<PreparedBondLock, SettlementError> {
    config.validate()?;
    let verified = request
        .bond
        .verify_signature()
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    if !verified {
        return Err(SettlementError::Verification(
            "credit bond signature verification failed".to_string(),
        ));
    }
    if request.bond.body.lifecycle_state != CreditBondLifecycleState::Active {
        return Err(SettlementError::InvalidDispatch(
            "bond lifecycle must be active before on-chain lock".to_string(),
        ));
    }
    let terms = request.bond.body.report.terms.clone().ok_or_else(|| {
        SettlementError::InvalidDispatch("credit bond terms are required".to_string())
    })?;
    let collateral_minor_units =
        scale_arc_amount_to_token_minor_units(&terms.collateral_amount, config)?;
    let reserve_requirement_minor_units =
        scale_arc_amount_to_token_minor_units(&terms.reserve_requirement_amount, config)?;
    let bond_terms = IArcBondVault::BondTerms {
        bondId: hash_string_id(&request.bond.body.bond_id),
        facilityId: hash_string_id(&terms.facility_id),
        principal: parse_address(&request.principal_address, "principal_address")?,
        token: parse_address(&config.settlement_token_address, "settlement_token_address")?,
        collateralAmount: U256::from(collateral_minor_units),
        reserveRequirementAmount: U256::from(reserve_requirement_minor_units),
        expiresAt: U256::from(request.bond.body.expires_at),
        reserveRequirementRatioBps: terms.reserve_ratio_bps,
        operator: parse_address(&config.operator_address, "operator_address")?,
    };
    let derive_call = IArcBondVault::deriveVaultIdCall {
        terms: bond_terms.clone(),
    };
    let static_result = eth_call_raw(
        config,
        &PreparedEvmCall {
            from_address: request.principal_address.clone(),
            to_address: config.bond_vault_contract.clone(),
            data: encode_call(derive_call),
            gas_limit: None,
        },
    )
    .await?;
    let result_bytes = decode_hex_bytes(&static_result)?;
    let vault_id =
        IArcBondVault::deriveVaultIdCall::abi_decode_returns(&result_bytes).map_err(|error| {
            SettlementError::Serialization(format!("deriveVaultId decode failed: {error}"))
        })?;
    let call_data = encode_call(IArcBondVault::lockBondCall { terms: bond_terms });

    Ok(PreparedBondLock {
        vault_id: format_b256(vault_id),
        bond_id_hash: format_b256(hash_string_id(&request.bond.body.bond_id)),
        facility_id_hash: format_b256(hash_string_id(&terms.facility_id)),
        collateral_minor_units,
        reserve_requirement_minor_units,
        call: PreparedEvmCall {
            from_address: request.principal_address.clone(),
            to_address: config.bond_vault_contract.clone(),
            data: call_data,
            gas_limit: None,
        },
    })
}

pub fn prepare_bond_release(
    config: &SettlementChainConfig,
    vault_id: &str,
    operator_address: &str,
    anchor_proof: &AnchorInclusionProof,
) -> Result<PreparedBondRelease, SettlementError> {
    config.validate()?;
    verify_anchor_inclusion_proof(anchor_proof)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    let (proof, root, evidence_hash) = proof_components(anchor_proof)?;
    let call = IArcBondVault::releaseBondDetailedCall {
        vaultId: parse_b256_hex(vault_id, "vault_id")?,
        proof: proof.into(),
        root,
        evidenceHash: evidence_hash,
    };
    Ok(PreparedBondRelease {
        vault_id: vault_id.to_string(),
        chain_id: config.chain_id.clone(),
        evidence_hash: format_b256(evidence_hash),
        call: PreparedEvmCall {
            from_address: operator_address.to_string(),
            to_address: config.bond_vault_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    })
}

pub fn prepare_bond_impair(
    config: &SettlementChainConfig,
    vault_id: &str,
    operator_address: &str,
    slash_amount: &MonetaryAmount,
    beneficiaries: &[String],
    shares: &[MonetaryAmount],
    anchor_proof: &AnchorInclusionProof,
) -> Result<PreparedBondImpair, SettlementError> {
    config.validate()?;
    if beneficiaries.is_empty() || beneficiaries.len() != shares.len() {
        return Err(SettlementError::InvalidInput(
            "beneficiaries and shares must be non-empty and aligned".to_string(),
        ));
    }
    verify_anchor_inclusion_proof(anchor_proof)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    let slash_amount_minor_units = scale_arc_amount_to_token_minor_units(slash_amount, config)?;
    let mut share_units = Vec::with_capacity(shares.len());
    let mut total = 0_u128;
    for share in shares {
        let scaled = scale_arc_amount_to_token_minor_units(share, config)?;
        total = total
            .checked_add(scaled)
            .ok_or_else(|| SettlementError::InvalidInput("slash shares overflowed".to_string()))?;
        share_units.push(U256::from(scaled));
    }
    if total != slash_amount_minor_units {
        return Err(SettlementError::InvalidInput(
            "slash shares must sum to slash_amount".to_string(),
        ));
    }
    let (proof, root, evidence_hash) = proof_components(anchor_proof)?;
    let call = IArcBondVault::impairBondDetailedCall {
        vaultId: parse_b256_hex(vault_id, "vault_id")?,
        slashAmount: U256::from(slash_amount_minor_units),
        beneficiaries: beneficiaries
            .iter()
            .map(|value| parse_address(value, "beneficiary"))
            .collect::<Result<Vec<_>, _>>()?,
        shares: share_units,
        proof: proof.into(),
        root,
        evidenceHash: evidence_hash,
    };
    Ok(PreparedBondImpair {
        vault_id: vault_id.to_string(),
        chain_id: config.chain_id.clone(),
        evidence_hash: format_b256(evidence_hash),
        slash_amount_minor_units,
        call: PreparedEvmCall {
            from_address: operator_address.to_string(),
            to_address: config.bond_vault_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    })
}

pub fn prepare_bond_expiry(
    config: &SettlementChainConfig,
    vault_id: &str,
    caller_address: &str,
) -> Result<PreparedBondExpiry, SettlementError> {
    config.validate()?;
    let call = IArcBondVault::expireReleaseCall {
        vaultId: parse_b256_hex(vault_id, "vault_id")?,
    };
    Ok(PreparedBondExpiry {
        vault_id: vault_id.to_string(),
        chain_id: config.chain_id.clone(),
        call: PreparedEvmCall {
            from_address: caller_address.to_string(),
            to_address: config.bond_vault_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    })
}

pub fn finalize_escrow_dispatch(
    prepared: &PreparedEscrowCreate,
    receipt: &EvmTransactionReceipt,
) -> Result<PreparedEscrowCreate, SettlementError> {
    if !receipt.status {
        return Err(SettlementError::InvalidDispatch(format!(
            "transaction {} failed before escrow identity could be finalized",
            receipt.tx_hash
        )));
    }
    let escrow_id = extract_escrow_created_id(receipt, &prepared.call.to_address)?;
    let mut finalized = prepared.clone();
    finalized.expected_escrow_id = escrow_id.clone();
    finalized.dispatch.escrow_id = escrow_id;
    Ok(finalized)
}

pub fn finalize_bond_lock(
    prepared: &PreparedBondLock,
    receipt: &EvmTransactionReceipt,
) -> Result<PreparedBondLock, SettlementError> {
    if !receipt.status {
        return Err(SettlementError::InvalidDispatch(format!(
            "transaction {} failed before bond identity could be finalized",
            receipt.tx_hash
        )));
    }
    let (vault_id, bond_id_hash, facility_id_hash) =
        extract_bond_locked_identity(receipt, &prepared.call.to_address)?;
    if bond_id_hash != prepared.bond_id_hash {
        return Err(SettlementError::InvalidDispatch(format!(
            "bond receipt identity mismatch: expected bond {}, observed {}",
            prepared.bond_id_hash, bond_id_hash
        )));
    }
    if facility_id_hash != prepared.facility_id_hash {
        return Err(SettlementError::InvalidDispatch(format!(
            "bond receipt identity mismatch: expected facility {}, observed {}",
            prepared.facility_id_hash, facility_id_hash
        )));
    }
    let mut finalized = prepared.clone();
    finalized.vault_id = vault_id;
    Ok(finalized)
}

pub async fn static_validate_call(
    config: &SettlementChainConfig,
    call: &PreparedEvmCall,
) -> Result<String, SettlementError> {
    eth_call_raw(config, call).await
}

pub async fn estimate_call_gas(
    config: &SettlementChainConfig,
    call: &PreparedEvmCall,
) -> Result<u64, SettlementError> {
    let result = rpc_call(
        &config.rpc_url,
        "eth_estimateGas",
        json!([request_value(call)]),
    )
    .await?;
    parse_hex_u64(
        result.as_str().ok_or_else(|| {
            SettlementError::Rpc("eth_estimateGas returned non-string".to_string())
        })?,
    )
}

pub async fn submit_call(
    config: &SettlementChainConfig,
    call: &PreparedEvmCall,
) -> Result<String, SettlementError> {
    let mut request = request_value(call);
    let gas_limit = match call.gas_limit {
        Some(gas_limit) => gas_limit,
        None => estimate_call_gas(config, call)
            .await?
            .saturating_mul(12)
            .saturating_div(10)
            .saturating_add(50_000),
    };
    request["gas"] = Value::String(format!("0x{gas_limit:x}"));
    let result = rpc_call(&config.rpc_url, "eth_sendTransaction", json!([request])).await?;
    result
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| SettlementError::Rpc("eth_sendTransaction returned non-string".to_string()))
}

pub async fn confirm_transaction(
    config: &SettlementChainConfig,
    tx_hash: &str,
) -> Result<EvmTransactionReceipt, SettlementError> {
    for _ in 0..100 {
        let result = rpc_call(
            &config.rpc_url,
            "eth_getTransactionReceipt",
            json!([tx_hash]),
        )
        .await?;
        if result.is_null() {
            thread::sleep(Duration::from_millis(100));
            continue;
        }
        let block_hash = result
            .get("blockHash")
            .and_then(Value::as_str)
            .ok_or_else(|| SettlementError::Rpc("receipt missing blockHash".to_string()))?
            .to_string();
        let block_number = parse_hex_u64(
            result
                .get("blockNumber")
                .and_then(Value::as_str)
                .ok_or_else(|| SettlementError::Rpc("receipt missing blockNumber".to_string()))?,
        )?;
        let status = result
            .get("status")
            .and_then(Value::as_str)
            .map(|value| value == "0x1")
            .unwrap_or(false);
        let gas_used = parse_hex_u64(
            result
                .get("gasUsed")
                .and_then(Value::as_str)
                .ok_or_else(|| SettlementError::Rpc("receipt missing gasUsed".to_string()))?,
        )?;
        let from_address = result
            .get("from")
            .and_then(Value::as_str)
            .ok_or_else(|| SettlementError::Rpc("receipt missing from".to_string()))?
            .to_string();
        let to_address = result
            .get("to")
            .and_then(Value::as_str)
            .ok_or_else(|| SettlementError::Rpc("receipt missing to".to_string()))?
            .to_string();
        let logs = result
            .get("logs")
            .and_then(Value::as_array)
            .ok_or_else(|| SettlementError::Rpc("receipt missing logs".to_string()))?
            .iter()
            .map(parse_log_entry)
            .collect::<Result<Vec<_>, _>>()?;
        let block = rpc_call(
            &config.rpc_url,
            "eth_getBlockByHash",
            json!([block_hash, false]),
        )
        .await?;
        let observed_at = parse_hex_u64(
            block
                .get("timestamp")
                .and_then(Value::as_str)
                .ok_or_else(|| SettlementError::Rpc("block missing timestamp".to_string()))?,
        )?;
        return Ok(EvmTransactionReceipt {
            tx_hash: tx_hash.to_string(),
            block_number,
            block_hash,
            status,
            from_address,
            to_address,
            gas_used,
            observed_at,
            logs,
        });
    }
    Err(SettlementError::Rpc(format!(
        "timed out waiting for transaction receipt {tx_hash}"
    )))
}

pub async fn read_escrow_snapshot(
    config: &SettlementChainConfig,
    escrow_id: &str,
) -> Result<EscrowSnapshot, SettlementError> {
    let call = IArcEscrow::getEscrowCall {
        escrowId: parse_b256_hex(escrow_id, "escrow_id")?,
    };
    let raw = eth_call_raw(
        config,
        &PreparedEvmCall {
            from_address: config.operator_address.clone(),
            to_address: config.escrow_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    )
    .await?;
    let bytes = decode_hex_bytes(&raw)?;
    let decoded = IArcEscrow::getEscrowCall::abi_decode_returns(&bytes).map_err(|error| {
        SettlementError::Serialization(format!("getEscrow decode failed: {error}"))
    })?;
    let deposited_minor_units = u256_to_u128(decoded.deposited, "escrow.deposited")?;
    let released_minor_units = u256_to_u128(decoded.released, "escrow.released")?;
    Ok(EscrowSnapshot {
        escrow_id: escrow_id.to_string(),
        depositor_address: format!("{:?}", decoded.terms.depositor),
        beneficiary_address: format!("{:?}", decoded.terms.beneficiary),
        deadline: decoded.terms.deadline.to::<u64>(),
        deposited_minor_units,
        released_minor_units,
        refunded: decoded.refunded,
        remaining_minor_units: deposited_minor_units.saturating_sub(released_minor_units),
    })
}

pub async fn read_bond_snapshot(
    config: &SettlementChainConfig,
    vault_id: &str,
) -> Result<EvmBondSnapshot, SettlementError> {
    let call = IArcBondVault::getBondCall {
        vaultId: parse_b256_hex(vault_id, "vault_id")?,
    };
    let raw = eth_call_raw(
        config,
        &PreparedEvmCall {
            from_address: config.operator_address.clone(),
            to_address: config.bond_vault_contract.clone(),
            data: encode_call(call),
            gas_limit: None,
        },
    )
    .await?;
    let bytes = decode_hex_bytes(&raw)?;
    let decoded = IArcBondVault::getBondCall::abi_decode_returns(&bytes).map_err(|error| {
        SettlementError::Serialization(format!("getBond decode failed: {error}"))
    })?;
    Ok(EvmBondSnapshot {
        vault_id: vault_id.to_string(),
        principal_address: format!("{:?}", decoded.terms.principal),
        expires_at: decoded.terms.expiresAt.to::<u64>(),
        locked_minor_units: u256_to_u128(decoded.lockedAmount, "bond.lockedAmount")?,
        reserve_requirement_minor_units: u256_to_u128(
            decoded.terms.reserveRequirementAmount,
            "bond.terms.reserveRequirementAmount",
        )?,
        reserve_requirement_ratio_bps: decoded.terms.reserveRequirementRatioBps,
        slashed_minor_units: u256_to_u128(decoded.slashedAmount, "bond.slashedAmount")?,
        released: decoded.released,
        expired: decoded.expired,
    })
}

pub fn build_failure_receipt(
    dispatch: &Web3SettlementDispatchArtifact,
    execution_receipt_id: String,
    settlement_reference: String,
    failure_reference: String,
    failure_reason: String,
) -> Result<Web3SettlementExecutionReceiptArtifact, SettlementError> {
    let amount = dispatch.settlement_amount.clone();
    let receipt = Web3SettlementExecutionReceiptArtifact {
        schema: ARC_WEB3_SETTLEMENT_RECEIPT_SCHEMA.to_string(),
        execution_receipt_id,
        issued_at: dispatch.issued_at,
        dispatch: dispatch.clone(),
        observed_execution: arc_core::credit::CapitalExecutionObservation {
            observed_at: dispatch.issued_at,
            external_reference_id: failure_reference,
            amount: amount.clone(),
        },
        lifecycle_state: Web3SettlementLifecycleState::Failed,
        settlement_reference,
        reconciled_anchor_proof: None,
        oracle_evidence: None,
        settled_amount: amount,
        reversal_of: None,
        failure_reason: Some(failure_reason),
        note: Some(
            "Runtime-marked failure after bounded retry or validation exhaustion.".to_string(),
        ),
    };
    validate_web3_settlement_execution_receipt(&receipt)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    Ok(receipt)
}

pub fn build_reversal_receipt(
    dispatch: &Web3SettlementDispatchArtifact,
    execution_receipt_id: String,
    settlement_reference: String,
    tx_hash: String,
    observed_amount: MonetaryAmount,
    reversal_of: String,
    charged_back: bool,
) -> Result<Web3SettlementExecutionReceiptArtifact, SettlementError> {
    let receipt = Web3SettlementExecutionReceiptArtifact {
        schema: ARC_WEB3_SETTLEMENT_RECEIPT_SCHEMA.to_string(),
        execution_receipt_id,
        issued_at: dispatch.issued_at,
        dispatch: dispatch.clone(),
        observed_execution: arc_core::credit::CapitalExecutionObservation {
            observed_at: dispatch.issued_at,
            external_reference_id: tx_hash,
            amount: observed_amount.clone(),
        },
        lifecycle_state: if charged_back {
            Web3SettlementLifecycleState::ChargedBack
        } else {
            Web3SettlementLifecycleState::Reversed
        },
        settlement_reference,
        reconciled_anchor_proof: None,
        oracle_evidence: None,
        settled_amount: observed_amount,
        reversal_of: Some(reversal_of),
        failure_reason: None,
        note: Some(
            "Runtime-projected compensating settlement after dispute or operator recovery."
                .to_string(),
        ),
    };
    validate_web3_settlement_execution_receipt(&receipt)
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    Ok(receipt)
}

fn ensure_instruction_ready(
    config: &SettlementChainConfig,
    instruction: &SignedCapitalExecutionInstruction,
    beneficiary_address: &str,
) -> Result<(), SettlementError> {
    let verified = instruction
        .verify_signature()
        .map_err(|error| SettlementError::Verification(error.to_string()))?;
    if !verified {
        return Err(SettlementError::Verification(
            "capital execution instruction signature verification failed".to_string(),
        ));
    }
    if instruction.body.action != CapitalExecutionInstructionAction::TransferFunds {
        return Err(SettlementError::InvalidDispatch(
            "only transfer_funds is supported by the official settlement runtime".to_string(),
        ));
    }
    if instruction.body.rail.kind != CapitalExecutionRailKind::Web3 {
        return Err(SettlementError::InvalidDispatch(
            "capital instruction rail.kind must be web3".to_string(),
        ));
    }
    if instruction.body.rail.jurisdiction.as_deref() != Some(config.chain_id.as_str()) {
        return Err(SettlementError::InvalidDispatch(format!(
            "capital instruction jurisdiction {:?} does not match {}",
            instruction.body.rail.jurisdiction, config.chain_id
        )));
    }
    if instruction.body.amount.is_none() {
        return Err(SettlementError::InvalidDispatch(
            "capital instruction amount is required".to_string(),
        ));
    }
    if !instruction
        .body
        .support_boundary
        .automatic_dispatch_supported
    {
        return Err(SettlementError::InvalidDispatch(
            "capital instruction must explicitly enable automatic dispatch".to_string(),
        ));
    }
    let destination = instruction
        .body
        .rail
        .destination_account_ref
        .as_deref()
        .ok_or_else(|| {
            SettlementError::InvalidDispatch(
                "capital instruction destination_account_ref is required".to_string(),
            )
        })?;
    if destination != beneficiary_address {
        return Err(SettlementError::InvalidDispatch(
            "beneficiary address must match capital instruction destination_account_ref"
                .to_string(),
        ));
    }
    parse_address(beneficiary_address, "beneficiary_address")?;
    Ok(())
}

fn ensure_settlement_binding(
    config: &SettlementChainConfig,
    binding: &SignedWeb3IdentityBinding,
    purpose: Web3KeyBindingPurpose,
) -> Result<(), SettlementError> {
    verify_web3_identity_binding(binding)
        .map_err(|error| SettlementError::InvalidBinding(error.to_string()))?;
    if !binding.certificate.purpose.contains(&purpose) {
        return Err(SettlementError::InvalidBinding(format!(
            "binding does not include {:?} purpose",
            purpose
        )));
    }
    if !binding
        .certificate
        .chain_scope
        .iter()
        .any(|chain| chain == &config.chain_id)
    {
        return Err(SettlementError::InvalidBinding(format!(
            "binding does not cover {}",
            config.chain_id
        )));
    }
    if binding.certificate.settlement_address != config.operator_address {
        return Err(SettlementError::InvalidBinding(
            "binding settlement address does not match the configured operator".to_string(),
        ));
    }
    Ok(())
}

fn proof_components(
    anchor_proof: &AnchorInclusionProof,
) -> Result<(ArcMerkleProof, B256, B256), SettlementError> {
    let proof = ArcMerkleProof {
        audit_path: anchor_proof
            .receipt_inclusion
            .proof
            .audit_path
            .iter()
            .map(hash_to_b256)
            .collect(),
        leaf_index: U256::from(anchor_proof.receipt_inclusion.proof.leaf_index as u64),
        tree_size: U256::from(anchor_proof.receipt_inclusion.proof.tree_size as u64),
    };
    let receipt_bytes = canonical_json_bytes(&anchor_proof.receipt.body())
        .map_err(|error| SettlementError::Serialization(error.to_string()))?;
    let evidence_hash = hash_to_b256(&leaf_hash(&receipt_bytes));
    let root = hash_to_b256(&anchor_proof.receipt_inclusion.merkle_root);
    Ok((proof, root, evidence_hash))
}

fn dual_sign_digest(
    config: &SettlementChainConfig,
    escrow_contract: &str,
    escrow_id: &B256,
    receipt_hash: &B256,
    amount_minor_units: u128,
) -> Result<B256, SettlementError> {
    let chain_id = parse_eip155_chain_id(&config.chain_id)?;
    let mut packed = Vec::with_capacity(32 + 20 + 32 + 32 + 32);
    packed.extend_from_slice(&u256_to_bytes32(U256::from(chain_id)));
    packed.extend_from_slice(parse_address(escrow_contract, "escrow_contract")?.as_slice());
    packed.extend_from_slice(escrow_id.as_slice());
    packed.extend_from_slice(receipt_hash.as_slice());
    packed.extend_from_slice(&u256_to_bytes32(U256::from(amount_minor_units)));
    Ok(keccak256(packed))
}

fn sign_digest(private_key_hex: &str, digest: &B256) -> Result<EvmSignature, SettlementError> {
    let secp = Secp256k1::new();
    let raw = hex::decode(private_key_hex.trim_start_matches("0x"))
        .map_err(|error| SettlementError::Signature(error.to_string()))?;
    let secret =
        SecretKey::from_byte_array(raw.try_into().map_err(|_| {
            SettlementError::Signature("expected a 32-byte private key".to_string())
        })?)
        .map_err(|error| SettlementError::Signature(error.to_string()))?;
    let message = Message::from_digest(*digest.as_ref());
    let signature: RecoverableSignature = secp.sign_ecdsa_recoverable(message, &secret);
    let (recovery_id, bytes) = signature.serialize_compact();
    let v = 27 + i32::from(recovery_id) as u8;
    let r = format!("0x{}", hex::encode(&bytes[..32]));
    let s = format!("0x{}", hex::encode(&bytes[32..]));
    Ok(EvmSignature { v, r, s })
}

fn parse_log_entry(value: &Value) -> Result<EvmLogEntry, SettlementError> {
    let address = value
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| SettlementError::Rpc("log missing address".to_string()))?;
    parse_address(address, "log.address")?;
    let topics = value
        .get("topics")
        .and_then(Value::as_array)
        .ok_or_else(|| SettlementError::Rpc("log missing topics".to_string()))?
        .iter()
        .map(|topic| {
            topic
                .as_str()
                .ok_or_else(|| SettlementError::Rpc("log topic was not a string".to_string()))
                .and_then(|topic| {
                    parse_b256_hex(topic, "log.topic")?;
                    Ok(topic.to_string())
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let data = value
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| SettlementError::Rpc("log missing data".to_string()))?
        .to_string();
    decode_hex_bytes(&data)?;
    let log_index = value
        .get("logIndex")
        .and_then(Value::as_str)
        .map(parse_hex_u64)
        .transpose()?;
    Ok(EvmLogEntry {
        address: address.to_string(),
        topics,
        data,
        log_index,
    })
}

fn extract_escrow_created_id(
    receipt: &EvmTransactionReceipt,
    escrow_contract: &str,
) -> Result<String, SettlementError> {
    extract_event_topic(
        receipt,
        escrow_contract,
        "EscrowCreated(bytes32,bytes32,address,address,address,uint256,uint256,address)",
        1,
        "escrow_id",
    )
}

fn extract_bond_locked_identity(
    receipt: &EvmTransactionReceipt,
    bond_vault_contract: &str,
) -> Result<(String, String, String), SettlementError> {
    let log = find_single_contract_event(
        receipt,
        bond_vault_contract,
        "BondLocked(bytes32,bytes32,bytes32,address,address,uint256,uint256)",
    )?;
    Ok((
        extract_topic_hex(log, 1, "vault_id")?,
        extract_topic_hex(log, 2, "bond_id")?,
        extract_topic_hex(log, 3, "facility_id")?,
    ))
}

fn extract_event_topic(
    receipt: &EvmTransactionReceipt,
    contract_address: &str,
    event_signature: &str,
    topic_index: usize,
    field: &str,
) -> Result<String, SettlementError> {
    let log = find_single_contract_event(receipt, contract_address, event_signature)?;
    extract_topic_hex(log, topic_index, field)
}

fn find_single_contract_event<'a>(
    receipt: &'a EvmTransactionReceipt,
    contract_address: &str,
    event_signature: &str,
) -> Result<&'a EvmLogEntry, SettlementError> {
    let contract = normalize_address(contract_address);
    let signature_hash = event_signature_hash(event_signature);
    let mut matches = receipt.logs.iter().filter(|log| {
        normalize_address(&log.address) == contract
            && log.topics.first().map(|topic| normalize_b256(topic)) == Some(signature_hash.clone())
    });
    let first = matches.next().ok_or_else(|| {
        SettlementError::InvalidDispatch(format!(
            "transaction {} did not emit {event_signature} from {contract_address}",
            receipt.tx_hash
        ))
    })?;
    if matches.next().is_some() {
        return Err(SettlementError::InvalidDispatch(format!(
            "transaction {} emitted multiple {event_signature} events from {contract_address}",
            receipt.tx_hash
        )));
    }
    Ok(first)
}

fn extract_topic_hex(
    log: &EvmLogEntry,
    index: usize,
    field: &str,
) -> Result<String, SettlementError> {
    let topic = log.topics.get(index).ok_or_else(|| {
        SettlementError::InvalidDispatch(format!("{field} missing from contract event topics"))
    })?;
    Ok(format_b256(parse_b256_hex(topic, field)?))
}

fn event_signature_hash(signature: &str) -> String {
    format_b256(keccak256(signature.as_bytes()))
}

fn normalize_address(value: &str) -> String {
    value.to_ascii_lowercase()
}

fn normalize_b256(value: &str) -> String {
    value.to_ascii_lowercase()
}

async fn eth_call_raw(
    config: &SettlementChainConfig,
    call: &PreparedEvmCall,
) -> Result<String, SettlementError> {
    let result = rpc_call(
        &config.rpc_url,
        "eth_call",
        json!([request_value(call), "latest"]),
    )
    .await?;
    result
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| SettlementError::Rpc("eth_call returned non-string".to_string()))
}

async fn rpc_call(rpc_url: &str, method: &str, params: Value) -> Result<Value, SettlementError> {
    let response = Client::new()
        .post(rpc_url)
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1u64,
            "method": method,
            "params": params,
        }))
        .send()
        .await
        .map_err(|error| SettlementError::Rpc(error.to_string()))?;
    let envelope: JsonRpcEnvelope = response
        .json()
        .await
        .map_err(|error| SettlementError::Rpc(error.to_string()))?;
    if let Some(error) = envelope.error {
        return Err(SettlementError::Rpc(format!(
            "{} (code {})",
            error.message, error.code
        )));
    }
    envelope
        .result
        .ok_or_else(|| SettlementError::Rpc(format!("{method} returned no result")))
}

fn request_value(call: &PreparedEvmCall) -> Value {
    let mut value = json!({
        "from": call.from_address,
        "to": call.to_address,
        "data": call.data,
    });
    if let Some(gas_limit) = call.gas_limit {
        value["gas"] = Value::String(format!("0x{gas_limit:x}"));
    }
    value
}

fn parse_eip155_chain_id(chain_id: &str) -> Result<u64, SettlementError> {
    let raw = chain_id
        .strip_prefix("eip155:")
        .ok_or_else(|| SettlementError::Unsupported(format!("unsupported chain id {chain_id}")))?;
    raw.parse::<u64>()
        .map_err(|error| SettlementError::InvalidInput(error.to_string()))
}

fn encode_call<C: SolCall>(call: C) -> String {
    format!("0x{}", hex::encode(call.abi_encode()))
}

fn parse_address(value: &str, field: &str) -> Result<Address, SettlementError> {
    Address::from_str(value)
        .map_err(|error| SettlementError::InvalidInput(format!("{field}: {error}")))
}

fn parse_b256_hex(value: &str, field: &str) -> Result<B256, SettlementError> {
    let hash = Hash::from_hex(value)
        .map_err(|error| SettlementError::InvalidInput(format!("{field}: {error}")))?;
    Ok(hash_to_b256(&hash))
}

fn hash_to_b256(hash: &Hash) -> B256 {
    FixedBytes::from(*hash.as_bytes())
}

fn hash_string_id(value: &str) -> B256 {
    keccak256(value.as_bytes())
}

fn format_b256(value: B256) -> String {
    format!("0x{}", hex::encode(value.as_slice()))
}

fn decode_hex_bytes(value: &str) -> Result<Vec<u8>, SettlementError> {
    hex::decode(value.trim_start_matches("0x"))
        .map_err(|error| SettlementError::Serialization(error.to_string()))
}

fn parse_hex_u64(value: &str) -> Result<u64, SettlementError> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16)
        .map_err(|error| SettlementError::Rpc(error.to_string()))
}

fn u256_to_u128(value: U256, field: &str) -> Result<u128, SettlementError> {
    let limbs = value.into_limbs();
    if limbs[2] != 0 || limbs[3] != 0 {
        return Err(SettlementError::InvalidInput(format!(
            "{field} does not fit u128"
        )));
    }
    Ok((u128::from(limbs[1]) << 64) | u128::from(limbs[0]))
}

fn u256_to_bytes32(value: U256) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    value.to_be_bytes::<32>().clone_into(&mut bytes);
    bytes
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::SettlementPolicyConfig;
    use arc_core::web3::{Web3SettlementDispatchArtifact, Web3SettlementLifecycleState};
    use secp256k1::ecdsa::RecoveryId;
    use secp256k1::PublicKey as SecpPublicKey;

    fn sample_config() -> SettlementChainConfig {
        SettlementChainConfig {
            chain_id: "eip155:31337".to_string(),
            network_name: "Ganache".to_string(),
            rpc_url: "http://127.0.0.1:8545".to_string(),
            escrow_contract: "0x69011eD3D9792Ea93595EeBd919EE621764B19e0".to_string(),
            bond_vault_contract: "0x621c302d6EC93b7186bEF18dF5D6436C6ea30125".to_string(),
            identity_registry_contract: "0x0eAFb60DD4F4b3863eb5490752238aC37A625dc6".to_string(),
            root_registry_contract: "0x3a167ACFC3348a8f8df11BF383aF3cA86a8A2B42".to_string(),
            operator_address: "0x8d6d63c22D114C18C2a0dA6Db0A8972Ed9C40343".to_string(),
            settlement_token_symbol: "mUSDC".to_string(),
            settlement_token_address: "0x735F1Ba389D9D350501dB8FBbB5b52477DcaddA8".to_string(),
            oracle: crate::SettlementOracleConfig::default(),
            evidence_substrate: crate::SettlementEvidenceConfig::default(),
            policy: SettlementPolicyConfig::default(),
        }
    }

    fn sample_dispatch() -> Web3SettlementDispatchArtifact {
        serde_json::from_str(include_str!(
            "../../../docs/standards/ARC_WEB3_SETTLEMENT_DISPATCH_EXAMPLE.json"
        ))
        .unwrap()
    }

    fn hex_dispatch() -> Web3SettlementDispatchArtifact {
        let mut dispatch = sample_dispatch();
        dispatch.escrow_id =
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        dispatch.settlement_path = Web3SettlementPath::DualSignature;
        dispatch.support_boundary.anchor_proof_required = false;
        dispatch.support_boundary.oracle_evidence_required_for_fx = false;
        dispatch
    }

    #[test]
    fn amount_scaling_matches_usdc_convention() {
        let config = sample_config();
        let scaled = scale_arc_amount_to_token_minor_units(
            &MonetaryAmount {
                units: 150,
                currency: "USD".to_string(),
            },
            &config,
        )
        .unwrap();
        assert_eq!(scaled, 1_500_000);
        let restored = scale_token_minor_units_to_arc_amount(scaled, "USD", &config).unwrap();
        assert_eq!(restored.units, 150);
    }

    #[test]
    fn dual_sign_digest_and_signature_are_recoverable() {
        let config = sample_config();
        let escrow_id = parse_b256_hex(
            "0x9e7e9d75ef18f8924a938f06c9838a8d6c6b9600dba88b35d28f6d54e2a71803",
            "escrow_id",
        )
        .unwrap();
        let receipt_hash = parse_b256_hex(
            "0x8d4f1c4eff7a6ec4cb9f3d5347ea50ccaa43d562e2eb06b1e0dab0633d14c0e3",
            "receipt_hash",
        )
        .unwrap();
        let digest = dual_sign_digest(
            &config,
            &config.escrow_contract,
            &escrow_id,
            &receipt_hash,
            1_500_000,
        )
        .unwrap();
        let signature = sign_digest(
            "0x1000000000000000000000000000000000000000000000000000000000000002",
            &digest,
        )
        .unwrap();
        let message = Message::from_digest(*digest.as_ref());
        let secp = Secp256k1::new();
        let recovery_id = RecoveryId::try_from((signature.v - 27) as i32).unwrap();
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&hex::decode(signature.r.trim_start_matches("0x")).unwrap());
        bytes[32..].copy_from_slice(&hex::decode(signature.s.trim_start_matches("0x")).unwrap());
        let recoverable = RecoverableSignature::from_compact(&bytes, recovery_id).unwrap();
        let recovered = secp.recover_ecdsa(message, &recoverable).unwrap();
        let expected = SecpPublicKey::from_secret_key(
            &secp,
            &SecretKey::from_byte_array(
                hex::decode("1000000000000000000000000000000000000000000000000000000000000002")
                    .unwrap()
                    .try_into()
                    .unwrap(),
            )
            .unwrap(),
        );
        assert_eq!(recovered, expected);
    }

    #[test]
    fn prepares_erc20_approval_call_payloads() {
        let prepared = prepare_erc20_approval(
            "0x735F1Ba389D9D350501dB8FBbB5b52477DcaddA8",
            "0x1000000000000000000000000000000000000001",
            "0x1000000000000000000000000000000000000002",
            42_000,
        )
        .unwrap();

        assert_eq!(prepared.amount_minor_units, 42_000);
        assert_eq!(prepared.call.from_address, prepared.owner_address);
        assert_eq!(prepared.call.to_address, prepared.token_address);
        assert!(prepared.call.data.starts_with("0x095ea7b3"));
    }

    #[test]
    fn prepares_refund_and_bond_expiry_calls() {
        let config = sample_config();
        let dispatch = hex_dispatch();

        let refund = prepare_escrow_refund(
            &config,
            &dispatch,
            "0x1000000000000000000000000000000000000009",
        )
        .unwrap();
        assert_eq!(refund.escrow_id, dispatch.escrow_id);
        assert_eq!(refund.call.to_address, config.escrow_contract);
        assert!(refund.call.data.starts_with("0x"));

        let expiry = prepare_bond_expiry(
            &config,
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "0x1000000000000000000000000000000000000009",
        )
        .unwrap();
        assert_eq!(expiry.chain_id, config.chain_id);
        assert_eq!(expiry.call.to_address, config.bond_vault_contract);
    }

    #[test]
    fn builds_failure_and_reversal_receipts() {
        let dispatch = hex_dispatch();

        let failure = build_failure_receipt(
            &dispatch,
            "exec-failed".to_string(),
            "settlement-ref".to_string(),
            "tx-failed".to_string(),
            "node rejected tx".to_string(),
        )
        .unwrap();
        assert_eq!(
            failure.lifecycle_state,
            Web3SettlementLifecycleState::Failed
        );
        assert_eq!(failure.failure_reason.as_deref(), Some("node rejected tx"));

        let reversal = build_reversal_receipt(
            &dispatch,
            "exec-reversed".to_string(),
            "settlement-ref".to_string(),
            "tx-reverse".to_string(),
            dispatch.settlement_amount.clone(),
            "exec-failed".to_string(),
            true,
        )
        .unwrap();
        assert_eq!(
            reversal.lifecycle_state,
            Web3SettlementLifecycleState::ChargedBack
        );
        assert_eq!(reversal.reversal_of.as_deref(), Some("exec-failed"));
    }

    #[test]
    fn finalize_escrow_dispatch_reads_the_created_id_from_receipt_logs() {
        let dispatch = hex_dispatch();
        let prepared = PreparedEscrowCreate {
            expected_escrow_id: "0xdeadbeef".to_string(),
            capability_commitment: "0xfeedface".to_string(),
            settlement_amount_minor_units: 1_500_000,
            dispatch: dispatch.clone(),
            call: PreparedEvmCall {
                from_address: dispatch
                    .capital_instruction
                    .body
                    .rail
                    .destination_account_ref
                    .clone()
                    .unwrap_or_default(),
                to_address: dispatch.escrow_contract.clone(),
                data: "0x".to_string(),
                gas_limit: None,
            },
        };
        let observed_id = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let receipt = EvmTransactionReceipt {
            tx_hash: "0xabc".to_string(),
            block_number: 1,
            block_hash: "0x01".to_string(),
            status: true,
            from_address: "0x1000000000000000000000000000000000000001".to_string(),
            to_address: dispatch.escrow_contract.clone(),
            gas_used: 21_000,
            observed_at: 1_744_000_000,
            logs: vec![EvmLogEntry {
                address: dispatch.escrow_contract.clone(),
                topics: vec![
                    event_signature_hash(
                        "EscrowCreated(bytes32,bytes32,address,address,address,uint256,uint256,address)",
                    ),
                    observed_id.to_string(),
                ],
                data: "0x".to_string(),
                log_index: Some(0),
            }],
        };

        let finalized = finalize_escrow_dispatch(&prepared, &receipt).unwrap();

        assert_eq!(finalized.expected_escrow_id, observed_id);
        assert_eq!(finalized.dispatch.escrow_id, observed_id);
    }

    #[test]
    fn finalize_bond_lock_reads_identity_topics_from_receipt_logs() {
        let bond_id_hash = format_b256(hash_string_id("bond-1"));
        let facility_id_hash = format_b256(hash_string_id("facility-1"));
        let prepared = PreparedBondLock {
            vault_id: "0xold".to_string(),
            bond_id_hash: bond_id_hash.clone(),
            facility_id_hash: facility_id_hash.clone(),
            collateral_minor_units: 5,
            reserve_requirement_minor_units: 2,
            call: PreparedEvmCall {
                from_address: "0x1000000000000000000000000000000000000001".to_string(),
                to_address: "0x621c302d6EC93b7186bEF18dF5D6436C6ea30125".to_string(),
                data: "0x".to_string(),
                gas_limit: None,
            },
        };
        let vault_id = "0x2222222222222222222222222222222222222222222222222222222222222222";
        let receipt = EvmTransactionReceipt {
            tx_hash: "0xdef".to_string(),
            block_number: 1,
            block_hash: "0x02".to_string(),
            status: true,
            from_address: "0x1000000000000000000000000000000000000001".to_string(),
            to_address: prepared.call.to_address.clone(),
            gas_used: 21_000,
            observed_at: 1_744_000_000,
            logs: vec![EvmLogEntry {
                address: prepared.call.to_address.clone(),
                topics: vec![
                    event_signature_hash(
                        "BondLocked(bytes32,bytes32,bytes32,address,address,uint256,uint256)",
                    ),
                    vault_id.to_string(),
                    bond_id_hash,
                    facility_id_hash,
                ],
                data: "0x".to_string(),
                log_index: Some(0),
            }],
        };

        let finalized = finalize_bond_lock(&prepared, &receipt).unwrap();

        assert_eq!(finalized.vault_id, vault_id);
    }

    #[test]
    fn helper_parsers_and_request_serialization_fail_closed() {
        let request = request_value(&PreparedEvmCall {
            from_address: "0x1000000000000000000000000000000000000001".to_string(),
            to_address: "0x1000000000000000000000000000000000000002".to_string(),
            data: "0xdeadbeef".to_string(),
            gas_limit: Some(21_000),
        });
        assert_eq!(request["gas"], serde_json::json!("0x5208"));

        let chain_error = parse_eip155_chain_id("solana:mainnet").expect_err("unsupported id");
        assert!(matches!(chain_error, SettlementError::Unsupported(_)));

        let log_error = parse_log_entry(&serde_json::json!({
            "address": "0x1000000000000000000000000000000000000001",
            "topics": ["0x1111111111111111111111111111111111111111111111111111111111111111"],
            "data": "not-hex"
        }))
        .expect_err("bad log payload");
        assert!(matches!(log_error, SettlementError::Serialization(_)));

        let overflow =
            u256_to_u128(U256::from_limbs([0, 0, 1, 0]), "field").expect_err("overflowed u128");
        assert!(matches!(overflow, SettlementError::InvalidInput(_)));
    }
}
