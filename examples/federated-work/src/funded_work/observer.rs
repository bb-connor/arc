use super::allocation::{self, AbiWork, Terms};
use crate::common::{digest, Result};
use alloy_primitives::{keccak256, B256, U256};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};

pub const PROFILE: &str = "chio.experimental.local-confirmed-funding.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Domain {
    pub profile: String,
    pub chain_id: String,
    pub genesis_hash: String,
    pub escrow: String,
    pub escrow_code_hash: String,
    pub token: String,
    pub token_code_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Block {
    pub number: u64,
    pub hash: String,
    pub parent_hash: String,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Log {
    pub address: String,
    pub topics: Vec<String>,
    pub data: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Receipt {
    pub transaction_hash: String,
    pub from: String,
    pub to: String,
    pub status: u8,
    pub block_number: u64,
    pub block_hash: String,
    pub logs: Vec<Log>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Read {
    pub contract: String,
    pub block_number: u64,
    pub block_hash: String,
    pub call_data: String,
    pub return_data: String,
}

/// Receiver-owned RPC transcript. This is never accepted from a work request.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    pub chain_id: String,
    pub genesis_hash: String,
    pub escrow_code: String,
    pub token_code: String,
    pub receipt: Receipt,
    pub ancestry: Vec<Block>,
    pub independent_head: Block,
    pub work: Read,
    pub balance: Read,
}

pub trait FundingSource: Send + Sync {
    fn observe(&self, allocation: &str) -> Result<Observation>;
    fn prepare(
        &self,
        _request: &super::settlement::ActionRequest,
    ) -> Result<super::settlement::Prepared> {
        Err("settlement transaction preparation unavailable".into())
    }
    fn transact(&self, _prepared: &super::settlement::Prepared) -> Result<()> {
        Err("settlement transport unavailable".into())
    }
    fn observe_transaction(&self, _prepared: &super::settlement::Prepared) -> Result<Observation> {
        Err("settlement observation unavailable".into())
    }
}

/// Construction is restricted to the verifier. Persisted JSON is not authority.
#[derive(Debug)]
pub struct VerifiedAllocation {
    pub(super) id: String,
    pub(super) observation_digest: String,
    pub(super) observed_at: u64,
}

impl Domain {
    pub fn validate(&self) -> Result<()> {
        if self.profile != PROFILE || self.chain_id != "31337" {
            return Err("unsupported funding finality profile".into());
        }
        allocation::hash(&self.genesis_hash)?;
        allocation::hash(&self.escrow_code_hash)?;
        allocation::hash(&self.token_code_hash)?;
        allocation::address(&self.escrow)?;
        allocation::address(&self.token)?;
        if self.escrow == self.token {
            return Err("escrow and token must differ".into());
        }
        Ok(())
    }
}

pub(super) fn data(value: &str, limit: usize) -> Result<Vec<u8>> {
    if value.len() < 2 || value.len() > 2 + 2 * limit || !value.len().is_multiple_of(2) {
        return Err("invalid bounded ABI data".into());
    }
    allocation::hex_bytes(value, (value.len() - 2) / 2)
}

pub(super) fn check_read(
    read: &Read,
    head: &Block,
    contract: &str,
    call: &[u8],
) -> Result<Vec<u8>> {
    if read.contract != contract
        || read.block_number != head.number
        || read.block_hash != head.hash
        || data(&read.call_data, 1024)? != call
    {
        return Err("state read changed pinned block, contract or call".into());
    }
    data(&read.return_data, 1024)
}

pub fn verify(
    domain: &Domain,
    terms: &Terms,
    observation: &Observation,
    started_at: u64,
    now: u64,
) -> Result<VerifiedAllocation> {
    Ok(verify_snapshot(domain, terms, observation, started_at, now, true)?.0)
}

/// The local lifecycle also reads original funding and current state after
/// fixture time advances. Only fresh admission applies wall-clock eligibility;
/// deadline recovery uses the receiver's current private-chain time.
pub(super) fn verify_snapshot(
    domain: &Domain,
    terms: &Terms,
    observation: &Observation,
    started_at: u64,
    now: u64,
    admission: bool,
) -> Result<(VerifiedAllocation, AbiWork)> {
    domain.validate()?;
    let elapsed = now
        .checked_sub(started_at)
        .ok_or("receiver clock moved backwards")?;
    if elapsed > 30 {
        return Err("funding observation exceeded receiver age limit".into());
    }
    let id = allocation::allocation_id(&domain.chain_id, &domain.escrow, terms)?;
    if observation.chain_id != domain.chain_id
        || observation.genesis_hash != domain.genesis_hash
        || terms.token != domain.token
        || keccak256(data(&observation.escrow_code, 32 * 1024)?)
            != allocation::hash(&domain.escrow_code_hash)?
        || keccak256(data(&observation.token_code, 32 * 1024)?)
            != allocation::hash(&domain.token_code_hash)?
    {
        return Err("funding chain or deployment changed".into());
    }
    // Two descendants on the owned private chain. This is deliberately not a
    // public-chain finality assertion or a payer-supplied finalized flag.
    if !(3..=128).contains(&observation.ancestry.len()) {
        return Err("funding lacks bounded confirmed ancestry".into());
    }
    let first = observation
        .ancestry
        .first()
        .ok_or("funding block missing")?;
    let head = observation.ancestry.last().ok_or("funding head missing")?;
    for block in &observation.ancestry {
        allocation::hash(&block.hash)?;
        allocation::hash(&block.parent_hash)?;
        if block.number == 0
            || block.number > allocation::MAX_UNITS
            || block.timestamp > allocation::MAX_UNITS
            || (admission && block.timestamp > now.saturating_add(5))
        {
            return Err("invalid funding block".into());
        }
    }
    for pair in observation.ancestry.windows(2) {
        if pair[0].number.checked_add(1) != Some(pair[1].number)
            || pair[1].parent_hash != pair[0].hash
            || pair[1].timestamp < pair[0].timestamp
        {
            return Err("funding ancestry is discontinuous".into());
        }
    }
    if &observation.independent_head != head
        || (admission
            && (now.saturating_sub(head.timestamp) > 90
                || head.timestamp > terms.submit_by
                || now > terms.submit_by))
    {
        return Err("funding head is stale, changed or ineligible".into());
    }
    let receipt = &observation.receipt;
    allocation::hash(&receipt.transaction_hash)?;
    if receipt.status != 1
        || receipt.from != terms.payer
        || receipt.to != domain.escrow
        || receipt.block_number != first.number
        || receipt.block_hash != first.hash
        || receipt.logs.len() > 32
    {
        return Err("funding transaction or inclusion mismatch".into());
    }
    let topic_address = |value: &str| -> Result<String> {
        Ok(format!(
            "0x{}",
            alloy_primitives::hex::encode(allocation::address(value)?.abi_encode())
        ))
    };
    let funded_topics = vec![
        format!("{:#x}", keccak256(b"Funded(bytes32,bytes32,address)")),
        id.clone(),
        terms.agreement_digest.clone(),
        topic_address(&terms.payer)?,
    ];
    let transfer_topics = vec![
        format!("{:#x}", keccak256(b"Transfer(address,address,uint256)")),
        topic_address(&terms.payer)?,
        topic_address(&domain.escrow)?,
    ];
    let amount = U256::from(allocation::units(&terms.amount)?);
    let transfer_data = format!("0x{}", alloy_primitives::hex::encode(amount.abi_encode()));
    let funded = receipt
        .logs
        .iter()
        .filter(|log| {
            log.address == domain.escrow && log.topics == funded_topics && log.data == "0x"
        })
        .count();
    let transfers = receipt
        .logs
        .iter()
        .filter(|log| {
            log.address == domain.token
                && log.topics == transfer_topics
                && log.data == transfer_data
        })
        .count();
    if funded != 1 || transfers != 1 {
        return Err("funding event or exact token transfer missing".into());
    }
    let work_call = [
        &keccak256(b"getWork(bytes32)")[..4],
        allocation::hash(&id)?.as_slice(),
    ]
    .concat();
    let work_bytes = check_read(&observation.work, head, &domain.escrow, &work_call)?;
    let work = AbiWork::abi_decode_validate(&work_bytes)?;
    if work.abi_encode() != work_bytes
        || work.terms.abi_encode() != terms.abi(&domain.escrow)?.abi_encode()
        || (admission
            && (work.state != 1
                || work.commitment != B256::ZERO
                || work.decisionDigest != B256::ZERO
                || work.accepted
                || work.paid != U256::ZERO
                || work.refunded != U256::ZERO))
    {
        return Err("allocation is not exactly funded and unclaimed".into());
    }
    let balance_call = [
        &keccak256(b"balanceOf(address)")[..4],
        &allocation::address(&domain.escrow)?.abi_encode(),
    ]
    .concat();
    let balance_bytes = check_read(&observation.balance, head, &domain.token, &balance_call)?;
    let balance = U256::abi_decode_validate(&balance_bytes)?;
    if balance.abi_encode() != balance_bytes || (admission && balance < amount) {
        return Err("escrow token backing is insufficient".into());
    }
    Ok((
        VerifiedAllocation {
            id,
            observation_digest: digest(observation)?,
            observed_at: now,
        },
        work,
    ))
}
