use std::str::FromStr;

use alloy_primitives::{keccak256, Address};
use alloy_sol_types::SolCall;
use chio_kernel::checkpoint::KernelCheckpoint;
use chio_web3_bindings::IChioRootRegistry;
use reqwest::Url;

use crate::AnchorError;

use super::hashing::hash_to_b256;
use super::types::{EvmAnchorTarget, PreparedEvmRootPublication, ValidatedEvmAnchorTarget};

pub(crate) fn parse_validated_evm_anchor_target(
    target: &EvmAnchorTarget,
) -> Result<ValidatedEvmAnchorTarget, AnchorError> {
    validate_evm_chain_id(&target.chain_id)?;
    validate_evm_rpc_url(&target.rpc_url)?;
    let _contract = parse_nonzero_evm_address("contract address", &target.contract_address)?;
    let operator = parse_nonzero_evm_address("operator address", &target.operator_address)?;
    let publisher = parse_nonzero_evm_address("publisher address", &target.publisher_address)?;
    Ok(ValidatedEvmAnchorTarget {
        operator,
        publisher,
    })
}

fn validate_evm_chain_id(chain_id: &str) -> Result<(), AnchorError> {
    let suffix = chain_id.strip_prefix("eip155:").ok_or_else(|| {
        AnchorError::InvalidInput(
            "EVM anchor chain_id must use the eip155:<decimal-chain-id> format".to_string(),
        )
    })?;
    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(AnchorError::InvalidInput(
            "EVM anchor chain_id must use a non-empty decimal eip155 chain id".to_string(),
        ));
    }
    if suffix.len() > 1 && suffix.starts_with('0') {
        return Err(AnchorError::InvalidInput(
            "EVM anchor chain_id must be canonical and omit leading zeroes".to_string(),
        ));
    }
    Ok(())
}

fn validate_evm_rpc_url(rpc_url: &str) -> Result<(), AnchorError> {
    if rpc_url.trim() != rpc_url {
        return Err(AnchorError::InvalidInput(
            "anchor EVM RPC URL must not include surrounding whitespace".to_string(),
        ));
    }
    let url = Url::parse(rpc_url).map_err(|error| {
        AnchorError::InvalidInput(format!("invalid anchor EVM RPC URL: {error}"))
    })?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(AnchorError::InvalidInput(
            "anchor EVM RPC URL must use http or https".to_string(),
        ));
    }
    if url.host_str().is_none() {
        return Err(AnchorError::InvalidInput(
            "anchor EVM RPC URL must include a host".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn parse_nonzero_evm_address(
    label: &str,
    address: &str,
) -> Result<Address, AnchorError> {
    if address.trim() != address {
        return Err(AnchorError::InvalidInput(format!(
            "{label} must not include surrounding whitespace"
        )));
    }
    let parsed = Address::from_str(address).map_err(|error| {
        AnchorError::InvalidInput(format!("{label} is not a valid EVM address: {error}"))
    })?;
    if parsed == Address::from([0_u8; 20]) {
        return Err(AnchorError::InvalidInput(format!(
            "{label} must not be the zero address"
        )));
    }
    Ok(parsed)
}

/// Bind a publication envelope EVM address to its expected trusted-target value.
///
/// Both sides are parsed to a canonical [`Address`] before comparison so a
/// checksum-case difference is not a false mismatch, and an unparseable address on
/// either side fails closed (the publication can never be confirmed against the
/// trusted target). `field` names the envelope slot for the error message.
fn bind_evm_address_to_target(
    actual: &str,
    expected: &str,
    field: &str,
) -> Result<(), AnchorError> {
    let actual_address = Address::from_str(actual).map_err(|error| {
        AnchorError::InvalidInput(format!(
            "prepared publication {field} is not an EVM address: {error}"
        ))
    })?;
    let expected_address = Address::from_str(expected).map_err(|error| {
        AnchorError::InvalidInput(format!(
            "expected anchor target {field} is not an EVM address: {error}"
        ))
    })?;
    if actual_address != expected_address {
        return Err(AnchorError::InvalidInput(format!(
            "prepared publication {field} does not match the expected anchor target"
        )));
    }
    Ok(())
}

/// Re-decode a prepared publication's broadcastable `call_data` and confirm it
/// would publish EXACTLY the supplied checkpoint's root, sequence, range, and
/// tree size under that checkpoint's own operator key, AND that it would broadcast
/// to the expected, registered root-registry target (`expected_target`).
///
/// A [`PreparedEvmRootPublication`] carries both display scalar fields
/// (`merkle_root`, `checkpoint_seq`, ...) AND the ABI-encoded `call_data` that an
/// operator actually broadcasts. A consumer that trusts only the display scalars
/// (or only the publication root) can be handed a publication whose `call_data`
/// encodes a DIFFERENT root, sequence, range, or operator-key-hash, so the
/// broadcast publishes something other than what was displayed. This re-decodes
/// the broadcast payload and binds every field it would publish to the trusted,
/// independently validated `checkpoint` (and re-checks the publication's own
/// display scalars against that same checkpoint), failing closed on any
/// disagreement. It performs no network IO and moves no value.
///
/// The transaction envelope (`chain_id`, `rpc_url` = the broadcast endpoint,
/// `contract_address` = the `to` target, `operator_address`, `publisher_address`
/// = the `from`) lives OUTSIDE the ABI `call_data` payload, so a call_data/root-
/// consistent publication can still be tampered to broadcast to a DIFFERENT
/// contract, chain, or RPC endpoint. `publish_root` (and `estimate_publication_gas`)
/// use the mutable `publication.contract_address` as the broadcast target and post
/// to the mutable `publication.rpc_url`, so a tampered target/endpoint would seal a
/// publication that never reaches the intended root registry (or reaches a
/// different chain via a different RPC). The expected envelope cannot be derived
/// from the checkpoint (neither the registry address nor the RPC URL is committed
/// in any signed artifact); it comes from the trusted, independently supplied
/// `expected_target` (the registered anchor target/binding config). This binds the
/// publication's envelope to that target, failing closed on a mismatch or an
/// unparseable address.
///
/// # Errors
///
/// Returns [`AnchorError::InvalidInput`] when `call_data` is not a decodable
/// `publishRoot` call, when any decoded broadcast field or displayed scalar
/// disagrees with the checkpoint's root, sequence, range, tree size, operator
/// address, or operator key hash, or when the publication's broadcast envelope
/// (chain, RPC endpoint, target contract, operator, or publisher) disagrees with
/// `expected_target` (or is not a parseable EVM address).
pub fn validate_publication_call_data_against_checkpoint(
    publication: &PreparedEvmRootPublication,
    checkpoint: &KernelCheckpoint,
    expected_target: &EvmAnchorTarget,
) -> Result<(), AnchorError> {
    let expected_tree_size = u64::try_from(checkpoint.body.tree_size)
        .map_err(|_| AnchorError::InvalidInput("checkpoint tree_size overflows u64".to_string()))?;

    // (a0) Bind the broadcast envelope to the trusted, registered target. These
    // fields ride OUTSIDE the ABI `call_data` payload, so they cannot be bound to
    // the checkpoint; they are bound here to the independently supplied
    // `expected_target`. `publish_root` broadcasts to `publication.contract_address`
    // (the `to`) from `publication.publisher_address` (the `from`) on
    // `publication.chain_id`, AND posts that transaction to `publication.rpc_url`
    // (the actual network endpoint, used by both gas estimation and the broadcast),
    // so a tampered target/chain/rpc_url would seal a publication that never reaches
    // the intended root registry (or reaches a different RPC endpoint/chain). Fail
    // closed on any mismatch.
    if publication.chain_id != expected_target.chain_id {
        return Err(AnchorError::InvalidInput(
            "prepared publication chain_id does not match the expected anchor target".to_string(),
        ));
    }
    // The `rpc_url` is the broadcast/gas-estimation endpoint. It is not committed
    // in any signed artifact and cannot be derived from the checkpoint, so a
    // tampered `rpc_url` can redirect the publishRoot broadcast to a different RPC
    // endpoint (and thus a different chain) while every other field still seals.
    // Bind it to the trusted target by exact match: the prepared publication's
    // `rpc_url` is cloned verbatim from the registered target in
    // `prepare_root_publication`, so any divergence is tampering. Fail closed.
    if publication.rpc_url != expected_target.rpc_url {
        return Err(AnchorError::InvalidInput(
            "prepared publication rpc_url does not match the expected anchor target".to_string(),
        ));
    }
    bind_evm_address_to_target(
        &publication.contract_address,
        &expected_target.contract_address,
        "contract_address (broadcast target)",
    )?;
    bind_evm_address_to_target(
        &publication.operator_address,
        &expected_target.operator_address,
        "operator_address",
    )?;
    bind_evm_address_to_target(
        &publication.publisher_address,
        &expected_target.publisher_address,
        "publisher_address (broadcast sender)",
    )?;

    // (a) The display scalars the panel surfaces must themselves match the
    // checkpoint, so a tampered display field cannot ride a consistent call_data.
    if publication.merkle_root != checkpoint.body.merkle_root {
        return Err(AnchorError::InvalidInput(
            "prepared publication merkle_root does not match the checkpoint".to_string(),
        ));
    }
    if publication.checkpoint_seq != checkpoint.body.checkpoint_seq
        || publication.batch_start_seq != checkpoint.body.batch_start_seq
        || publication.batch_end_seq != checkpoint.body.batch_end_seq
        || publication.tree_size != expected_tree_size
    {
        return Err(AnchorError::InvalidInput(
            "prepared publication sequence/range/tree-size does not match the checkpoint"
                .to_string(),
        ));
    }
    let expected_operator_key_hash = keccak256(checkpoint.body.kernel_key.as_bytes());
    let expected_operator_key_hash_hex =
        format!("0x{}", hex::encode(expected_operator_key_hash.as_slice()));
    if publication.operator_key_hash != expected_operator_key_hash_hex {
        return Err(AnchorError::InvalidInput(
            "prepared publication operator_key_hash does not match the checkpoint kernel key"
                .to_string(),
        ));
    }

    // (b) Decode the actual broadcast payload and bind every published field to
    // the checkpoint (the trust anchor), not to the publication's display fields.
    let hex_body = publication
        .call_data
        .strip_prefix("0x")
        .unwrap_or(&publication.call_data);
    let raw = hex::decode(hex_body).map_err(|error| {
        AnchorError::InvalidInput(format!("publication call_data is not valid hex: {error}"))
    })?;
    let call = IChioRootRegistry::publishRootCall::abi_decode(&raw).map_err(|error| {
        AnchorError::InvalidInput(format!(
            "publication call_data is not a publishRoot call: {error}"
        ))
    })?;
    if call.merkleRoot != hash_to_b256(&checkpoint.body.merkle_root) {
        return Err(AnchorError::InvalidInput(
            "publication call_data would publish a root that disagrees with the checkpoint"
                .to_string(),
        ));
    }
    if call.checkpointSeq != checkpoint.body.checkpoint_seq
        || call.batchStartSeq != checkpoint.body.batch_start_seq
        || call.batchEndSeq != checkpoint.body.batch_end_seq
        || call.treeSize != expected_tree_size
    {
        return Err(AnchorError::InvalidInput(
            "publication call_data would publish a sequence/range/tree-size that disagrees with the checkpoint"
                .to_string(),
        ));
    }
    if call.operatorKeyHash != expected_operator_key_hash {
        return Err(AnchorError::InvalidInput(
            "publication call_data operator key hash does not match the checkpoint kernel key"
                .to_string(),
        ));
    }
    let operator = Address::from_str(&publication.operator_address).map_err(|error| {
        AnchorError::InvalidInput(format!(
            "publication operator_address is not an EVM address: {error}"
        ))
    })?;
    if call.operator != operator {
        return Err(AnchorError::InvalidInput(
            "publication call_data operator does not match the publication operator address"
                .to_string(),
        ));
    }
    Ok(())
}
