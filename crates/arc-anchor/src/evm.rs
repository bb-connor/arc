use std::str::FromStr;

use alloy_primitives::{keccak256, Address, FixedBytes, B256, U256};
use alloy_sol_types::SolCall;
use arc_core::canonical::canonical_json_bytes;
use arc_core::merkle::leaf_hash;
use arc_core::web3::{
    verify_anchor_inclusion_proof, AnchorInclusionProof, SignedWeb3IdentityBinding,
    Web3ChainAnchorRecord, Web3KeyBindingPurpose,
};
use arc_kernel::checkpoint::KernelCheckpoint;
use arc_web3_bindings::{ArcMerkleProof, IArcRootRegistry};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::AnchorError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvmAnchorTarget {
    pub chain_id: String,
    pub rpc_url: String,
    pub contract_address: String,
    pub operator_address: String,
    pub publisher_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedEvmRootPublication {
    pub chain_id: String,
    pub rpc_url: String,
    pub contract_address: String,
    pub operator_address: String,
    pub publisher_address: String,
    pub checkpoint_seq: u64,
    pub batch_start_seq: u64,
    pub batch_end_seq: u64,
    pub tree_size: u64,
    pub merkle_root: arc_core::hashing::Hash,
    pub operator_key_hash: String,
    pub call_data: String,
    pub requires_delegate_authorization: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedDelegateRegistration {
    pub chain_id: String,
    pub rpc_url: String,
    pub contract_address: String,
    pub operator_address: String,
    pub delegate_address: String,
    pub expires_at: u64,
    pub call_data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvmPublicationReceipt {
    pub tx_hash: String,
    pub block_number: u64,
    pub block_hash: String,
    pub published_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvmPublicationGuard {
    pub chain_id: String,
    pub operator_address: String,
    pub publisher_address: String,
    pub latest_checkpoint_seq: u64,
    pub next_checkpoint_seq_min: u64,
    pub publisher_authorized: bool,
    pub requires_delegate_authorization: bool,
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

pub fn operator_key_hash(binding: &SignedWeb3IdentityBinding) -> B256 {
    keccak256(binding.certificate.arc_public_key.as_bytes())
}

pub fn operator_key_hash_hex(binding: &SignedWeb3IdentityBinding) -> String {
    format!("0x{}", hex::encode(operator_key_hash(binding).as_slice()))
}

pub fn prepare_root_publication(
    target: &EvmAnchorTarget,
    checkpoint: &KernelCheckpoint,
    binding: &SignedWeb3IdentityBinding,
) -> Result<PreparedEvmRootPublication, AnchorError> {
    if !binding
        .certificate
        .purpose
        .contains(&Web3KeyBindingPurpose::Anchor)
    {
        return Err(AnchorError::InvalidBinding(
            "binding certificate does not include anchor purpose".to_string(),
        ));
    }
    if !binding
        .certificate
        .chain_scope
        .iter()
        .any(|chain| chain == &target.chain_id)
    {
        return Err(AnchorError::InvalidBinding(format!(
            "binding certificate does not cover {}",
            target.chain_id
        )));
    }
    if binding.certificate.settlement_address != target.operator_address {
        return Err(AnchorError::InvalidBinding(format!(
            "binding settlement address {} does not match operator address {}",
            binding.certificate.settlement_address, target.operator_address
        )));
    }
    let operator = Address::from_str(&target.operator_address)
        .map_err(|error| AnchorError::InvalidInput(error.to_string()))?;
    let call = IArcRootRegistry::publishRootCall {
        operator,
        merkleRoot: hash_to_b256(&checkpoint.body.merkle_root),
        checkpointSeq: checkpoint.body.checkpoint_seq,
        batchStartSeq: checkpoint.body.batch_start_seq,
        batchEndSeq: checkpoint.body.batch_end_seq,
        treeSize: checkpoint.body.tree_size as u64,
        operatorKeyHash: operator_key_hash(binding),
    };

    Ok(PreparedEvmRootPublication {
        chain_id: target.chain_id.clone(),
        rpc_url: target.rpc_url.clone(),
        contract_address: target.contract_address.clone(),
        operator_address: target.operator_address.clone(),
        publisher_address: target.publisher_address.clone(),
        checkpoint_seq: checkpoint.body.checkpoint_seq,
        batch_start_seq: checkpoint.body.batch_start_seq,
        batch_end_seq: checkpoint.body.batch_end_seq,
        tree_size: checkpoint.body.tree_size as u64,
        merkle_root: checkpoint.body.merkle_root,
        operator_key_hash: operator_key_hash_hex(binding),
        call_data: format!("0x{}", hex::encode(call.abi_encode())),
        requires_delegate_authorization: target.publisher_address != target.operator_address,
    })
}

pub fn prepare_delegate_registration(
    target: &EvmAnchorTarget,
    delegate_address: &str,
    expires_at: u64,
) -> Result<PreparedDelegateRegistration, AnchorError> {
    if delegate_address.trim().is_empty() {
        return Err(AnchorError::InvalidInput(
            "delegate address is required".to_string(),
        ));
    }
    if expires_at == 0 {
        return Err(AnchorError::InvalidInput(
            "delegate expiry must be non-zero".to_string(),
        ));
    }

    let delegate = Address::from_str(delegate_address)
        .map_err(|error| AnchorError::InvalidInput(error.to_string()))?;
    let call = IArcRootRegistry::registerDelegateCall {
        delegate,
        expiresAt: expires_at,
    };
    Ok(PreparedDelegateRegistration {
        chain_id: target.chain_id.clone(),
        rpc_url: target.rpc_url.clone(),
        contract_address: target.contract_address.clone(),
        operator_address: target.operator_address.clone(),
        delegate_address: delegate_address.to_string(),
        expires_at,
        call_data: format!("0x{}", hex::encode(call.abi_encode())),
    })
}

pub async fn publish_root(publication: &PreparedEvmRootPublication) -> Result<String, AnchorError> {
    let gas_limit = estimate_publication_gas(publication)
        .await?
        .saturating_mul(12)
        .saturating_div(10)
        .saturating_add(50_000);
    let result = rpc_call(
        &publication.rpc_url,
        "eth_sendTransaction",
        json!([{
            "from": publication.publisher_address,
            "to": publication.contract_address,
            "data": publication.call_data,
            "gas": format!("0x{gas_limit:x}"),
        }]),
    )
    .await?;

    result
        .as_str()
        .map(ToString::to_string)
        .ok_or_else(|| AnchorError::Rpc("eth_sendTransaction did not return a tx hash".to_string()))
}

async fn estimate_publication_gas(
    publication: &PreparedEvmRootPublication,
) -> Result<u64, AnchorError> {
    let result = rpc_call(
        &publication.rpc_url,
        "eth_estimateGas",
        json!([{
            "from": publication.publisher_address,
            "to": publication.contract_address,
            "data": publication.call_data,
        }]),
    )
    .await?;
    parse_hex_u64(
        result.as_str().ok_or_else(|| {
            AnchorError::Rpc("eth_estimateGas did not return a string".to_string())
        })?,
    )
}

pub async fn confirm_root_publication(
    target: &EvmAnchorTarget,
    checkpoint: &KernelCheckpoint,
    binding: &SignedWeb3IdentityBinding,
    tx_hash: &str,
) -> Result<EvmPublicationReceipt, AnchorError> {
    let receipt = rpc_call(
        &target.rpc_url,
        "eth_getTransactionReceipt",
        json!([tx_hash]),
    )
    .await?;
    let block_number = parse_hex_u64(
        receipt
            .get("blockNumber")
            .and_then(Value::as_str)
            .ok_or_else(|| AnchorError::Rpc("receipt missing blockNumber".to_string()))?,
    )?;
    let block_hash = receipt
        .get("blockHash")
        .and_then(Value::as_str)
        .ok_or_else(|| AnchorError::Rpc("receipt missing blockHash".to_string()))?
        .to_string();
    let status = receipt
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| AnchorError::Rpc("receipt missing status".to_string()))?;
    if status != "0x1" {
        return Err(AnchorError::Rpc(format!(
            "publication transaction {} failed with status {}",
            tx_hash, status
        )));
    }

    let operator = Address::from_str(&target.operator_address)
        .map_err(|error| AnchorError::InvalidInput(error.to_string()))?;
    let get_root = IArcRootRegistry::getRootCall {
        operator,
        checkpointSeq: checkpoint.body.checkpoint_seq,
    };
    let root_result = rpc_call(
        &target.rpc_url,
        "eth_call",
        json!([
            {
                "to": target.contract_address,
                "data": format!("0x{}", hex::encode(get_root.abi_encode()))
            },
            "latest"
        ]),
    )
    .await?;
    let entry_hex = root_result
        .as_str()
        .ok_or_else(|| AnchorError::Rpc("eth_call getRoot did not return data".to_string()))?;
    let entry_bytes = hex::decode(entry_hex.trim_start_matches("0x"))
        .map_err(|error| AnchorError::Rpc(error.to_string()))?;
    let stored = IArcRootRegistry::getRootCall::abi_decode_returns(&entry_bytes)
        .map_err(|error| AnchorError::Serialization(error.to_string()))?;
    if stored.checkpointSeq != checkpoint.body.checkpoint_seq
        || stored.batchStartSeq != checkpoint.body.batch_start_seq
        || stored.batchEndSeq != checkpoint.body.batch_end_seq
        || stored.treeSize != checkpoint.body.tree_size as u64
        || stored.merkleRoot != hash_to_b256(&checkpoint.body.merkle_root)
        || stored.operatorKeyHash != operator_key_hash(binding)
    {
        return Err(AnchorError::Verification(
            "root registry entry does not match the checkpoint being confirmed".to_string(),
        ));
    }

    Ok(EvmPublicationReceipt {
        tx_hash: tx_hash.to_string(),
        block_number,
        block_hash,
        published_at: stored.publishedAt,
    })
}

pub async fn inspect_publication_guard(
    target: &EvmAnchorTarget,
) -> Result<EvmPublicationGuard, AnchorError> {
    let operator = Address::from_str(&target.operator_address)
        .map_err(|error| AnchorError::InvalidInput(error.to_string()))?;
    let publisher = Address::from_str(&target.publisher_address)
        .map_err(|error| AnchorError::InvalidInput(error.to_string()))?;

    let auth_call = IArcRootRegistry::isAuthorizedPublisherCall {
        operator,
        publisher,
    };
    let auth_response = rpc_call(
        &target.rpc_url,
        "eth_call",
        json!([
            {
                "to": target.contract_address,
                "data": format!("0x{}", hex::encode(auth_call.abi_encode()))
            },
            "latest"
        ]),
    )
    .await?;
    let auth_raw = auth_response.as_str().ok_or_else(|| {
        AnchorError::Rpc("eth_call isAuthorizedPublisher did not return data".to_string())
    })?;
    let auth_bytes = hex::decode(auth_raw.trim_start_matches("0x"))
        .map_err(|error| AnchorError::Rpc(error.to_string()))?;
    let publisher_authorized =
        IArcRootRegistry::isAuthorizedPublisherCall::abi_decode_returns(&auth_bytes)
            .map_err(|error| AnchorError::Serialization(error.to_string()))?;

    let seq_call = IArcRootRegistry::getLatestSeqCall { operator };
    let seq_response = rpc_call(
        &target.rpc_url,
        "eth_call",
        json!([
            {
                "to": target.contract_address,
                "data": format!("0x{}", hex::encode(seq_call.abi_encode()))
            },
            "latest"
        ]),
    )
    .await?;
    let seq_raw = seq_response
        .as_str()
        .ok_or_else(|| AnchorError::Rpc("eth_call getLatestSeq did not return data".to_string()))?;
    let seq_bytes = hex::decode(seq_raw.trim_start_matches("0x"))
        .map_err(|error| AnchorError::Rpc(error.to_string()))?;
    let latest_checkpoint_seq = IArcRootRegistry::getLatestSeqCall::abi_decode_returns(&seq_bytes)
        .map_err(|error| AnchorError::Serialization(error.to_string()))?;

    Ok(EvmPublicationGuard {
        chain_id: target.chain_id.clone(),
        operator_address: target.operator_address.clone(),
        publisher_address: target.publisher_address.clone(),
        latest_checkpoint_seq,
        next_checkpoint_seq_min: latest_checkpoint_seq.saturating_add(1),
        publisher_authorized,
        requires_delegate_authorization: target.publisher_address != target.operator_address,
    })
}

pub async fn ensure_publication_ready(
    target: &EvmAnchorTarget,
    checkpoint_seq: u64,
) -> Result<EvmPublicationGuard, AnchorError> {
    let guard = inspect_publication_guard(target).await?;
    if !guard.publisher_authorized {
        return Err(AnchorError::Verification(format!(
            "publisher {} is not authorized for operator {} on {}",
            guard.publisher_address, guard.operator_address, guard.chain_id
        )));
    }
    if checkpoint_seq < guard.next_checkpoint_seq_min {
        return Err(AnchorError::Verification(format!(
            "checkpoint sequence {} must be >= {} on {}",
            checkpoint_seq, guard.next_checkpoint_seq_min, guard.chain_id
        )));
    }
    Ok(guard)
}

pub async fn verify_inclusion_onchain(
    target: &EvmAnchorTarget,
    proof: &AnchorInclusionProof,
) -> Result<bool, AnchorError> {
    verify_anchor_inclusion_proof(proof)
        .map_err(|error| AnchorError::Verification(error.to_string()))?;
    let operator = Address::from_str(&proof.key_binding_certificate.certificate.settlement_address)
        .map_err(|error| AnchorError::InvalidInput(error.to_string()))?;
    let receipt_bytes = canonical_json_bytes(&proof.receipt.body())
        .map_err(|error| AnchorError::Serialization(error.to_string()))?;
    let leaf = leaf_hash(&receipt_bytes);
    let evm_proof = ArcMerkleProof {
        audit_path: proof
            .receipt_inclusion
            .proof
            .audit_path
            .iter()
            .map(hash_to_b256)
            .collect(),
        leaf_index: U256::from(proof.receipt_inclusion.proof.leaf_index as u64),
        tree_size: U256::from(proof.receipt_inclusion.proof.tree_size as u64),
    };
    let call = IArcRootRegistry::verifyInclusionDetailedCall {
        proof: evm_proof.into(),
        root: hash_to_b256(&proof.receipt_inclusion.merkle_root),
        leafHash: hash_to_b256(&leaf),
        operator,
    };
    let response = rpc_call(
        &target.rpc_url,
        "eth_call",
        json!([
            {
                "to": target.contract_address,
                "data": format!("0x{}", hex::encode(call.abi_encode()))
            },
            "latest"
        ]),
    )
    .await?;
    let raw = response.as_str().ok_or_else(|| {
        AnchorError::Rpc("eth_call verifyInclusionDetailed did not return data".to_string())
    })?;
    let bytes = hex::decode(raw.trim_start_matches("0x"))
        .map_err(|error| AnchorError::Rpc(error.to_string()))?;
    let verified = IArcRootRegistry::verifyInclusionDetailedCall::abi_decode_returns(&bytes)
        .map_err(|error| AnchorError::Serialization(error.to_string()))?;
    Ok(verified)
}

pub fn build_chain_anchor_record(
    target: &EvmAnchorTarget,
    checkpoint: &KernelCheckpoint,
    confirmed: &EvmPublicationReceipt,
) -> Web3ChainAnchorRecord {
    Web3ChainAnchorRecord {
        chain_id: target.chain_id.clone(),
        contract_address: target.contract_address.clone(),
        operator_address: target.operator_address.clone(),
        tx_hash: confirmed.tx_hash.clone(),
        block_number: confirmed.block_number,
        block_hash: confirmed.block_hash.clone(),
        anchored_merkle_root: checkpoint.body.merkle_root,
        anchored_checkpoint_seq: checkpoint.body.checkpoint_seq,
    }
}

async fn rpc_call(rpc_url: &str, method: &str, params: Value) -> Result<Value, AnchorError> {
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
        .map_err(|error| AnchorError::Rpc(error.to_string()))?;
    let envelope: JsonRpcEnvelope = response
        .json()
        .await
        .map_err(|error| AnchorError::Rpc(error.to_string()))?;
    if let Some(error) = envelope.error {
        return Err(AnchorError::Rpc(format!(
            "{} (code {})",
            error.message, error.code
        )));
    }
    envelope
        .result
        .ok_or_else(|| AnchorError::Rpc(format!("{} returned no result", method)))
}

fn hash_to_b256(hash: &arc_core::hashing::Hash) -> B256 {
    FixedBytes::from(*hash.as_bytes())
}

fn parse_hex_u64(value: &str) -> Result<u64, AnchorError> {
    u64::from_str_radix(value.trim_start_matches("0x"), 16)
        .map_err(|error| AnchorError::Rpc(error.to_string()))
}
