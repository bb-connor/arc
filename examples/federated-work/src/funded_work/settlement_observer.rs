//! Receiver-owned private-chain inclusion checks. Fixture time may advance to
//! exercise contractual deadlines; this is not a wall-clock/public finality proof.
use super::{
    agreement::Policy,
    allocation::{self, AbiWork},
    observer::{self, Observation},
    settlement::{Action, ActionRequest, Prepared},
};
use crate::common::{digest, Result};
use alloy_primitives::{keccak256, B256, U256};
use alloy_sol_types::SolValue;

pub struct Verified {
    pub(super) allocation_id: String,
    pub(super) commitment: Option<String>,
    pub(super) state: u8,
    pub(super) action: Action,
    pub(super) transaction_hash: String,
    pub(super) observation_sha256: String,
    pub(super) block_hash: String,
    pub(super) block_number: u64,
    pub(super) chain_time: u64,
}

pub fn verify(
    policy: &Policy,
    request: &ActionRequest,
    prepared: &Prepared,
    observation: &Observation,
    started_at: u64,
    now: u64,
) -> Result<Verified> {
    let domain = &policy.domain;
    domain.validate()?;
    super::settlement::validate(prepared, request, policy)?;
    let terms = &request.terms;
    if now.checked_sub(started_at).is_none_or(|age| age > 30)
        || request.allocation_id
            != allocation::allocation_id(&domain.chain_id, &domain.escrow, terms)?
        || observation.chain_id != domain.chain_id
        || observation.genesis_hash != domain.genesis_hash
        || terms.token != domain.token
        || keccak256(observer::data(&observation.escrow_code, 32768)?)
            != allocation::hash(&domain.escrow_code_hash)?
        || keccak256(observer::data(&observation.token_code, 32768)?)
            != allocation::hash(&domain.token_code_hash)?
    {
        return Err("settlement observer age, allocation or deployment mismatch".into());
    }
    if !(3..=128).contains(&observation.ancestry.len()) {
        return Err("settlement lacks two confirmed descendants".into());
    }
    let first = observation
        .ancestry
        .first()
        .ok_or("settlement inclusion missing")?;
    let head = observation
        .ancestry
        .last()
        .ok_or("settlement head missing")?;
    for block in &observation.ancestry {
        allocation::hash(&block.hash)?;
        allocation::hash(&block.parent_hash)?;
        if block.number == 0
            || block.number > allocation::MAX_UNITS
            || block.timestamp > allocation::MAX_UNITS
        {
            return Err("invalid settlement block".into());
        }
    }
    for pair in observation.ancestry.windows(2) {
        if pair[0].number.checked_add(1) != Some(pair[1].number)
            || pair[1].parent_hash != pair[0].hash
            || pair[1].timestamp < pair[0].timestamp
        {
            return Err("settlement ancestry changed".into());
        }
    }
    if observation.independent_head != *head {
        return Err("settlement head changed during reads".into());
    }
    let receipt = &observation.receipt;
    if receipt.transaction_hash != prepared.transaction_hash
        || receipt.from != request.action.actor(terms)
        || receipt.to != domain.escrow
        || receipt.status != 1
        || receipt.block_number != first.number
        || receipt.block_hash != first.hash
        || receipt.logs.len() > 32
    {
        return Err("settlement receipt identity or inclusion mismatch".into());
    }
    let call = [
        &keccak256(b"getWork(bytes32)")[..4],
        allocation::hash(&request.allocation_id)?.as_slice(),
    ]
    .concat();
    let bytes = observer::check_read(&observation.work, head, &domain.escrow, &call)?;
    let work = AbiWork::abi_decode_validate(&bytes)?;
    if work.abi_encode() != bytes
        || work.terms.abi_encode() != terms.abi(&domain.escrow)?.abi_encode()
    {
        return Err("settlement substituted original immutable terms".into());
    }
    let commitment = request
        .commitment
        .as_deref()
        .map(allocation::hash)
        .transpose()?
        .unwrap_or(B256::ZERO);
    if work.commitment != commitment
        && !(request.action == Action::Refund && work.commitment == B256::ZERO)
    {
        return Err("observed claim differs from retained submission".into());
    }
    let amount = U256::from(allocation::units(&terms.amount)?);
    let topic = |name: &[u8]| format!("{:#x}", keccak256(name));
    let encoded = |bytes: Vec<u8>| format!("0x{}", alloy_primitives::hex::encode(bytes));
    let actor_topic = |address: &str| -> Result<String> {
        Ok(encoded(allocation::address(address)?.abi_encode()))
    };
    let expected_decision = request
        .decision
        .as_ref()
        .map(|d| digest(&d.body))
        .transpose()?
        .map(|hash| format!("0x{hash}"));
    let expected_hash = expected_decision
        .as_deref()
        .map(allocation::hash)
        .transpose()?
        .unwrap_or(B256::ZERO);
    let accepted = request.decision.as_ref().is_some_and(|d| d.body.accepted);
    let (event, topics, event_data) = match request.action {
        Action::Submit => {
            if first.timestamp > terms.submit_by || !matches!(work.state, 2..=7) {
                return Err("claim was not timely or is absent".into());
            }
            (
                b"ClaimSubmitted(bytes32,bytes32)".as_slice(),
                vec![request.allocation_id.clone()],
                commitment.abi_encode(),
            )
        }
        Action::Record => {
            if first.timestamp <= terms.challenge_until
                || first.timestamp > terms.resolve_by
                || !matches!(work.state, 3..=5 | 7)
                || expected_hash == B256::ZERO
                || work.decisionDigest != expected_hash
                || work.accepted != accepted
            {
                return Err("decision outcome, identity or resolution window mismatch".into());
            }
            (
                b"DecisionRecorded(bytes32,bytes32,bool)".as_slice(),
                vec![request.allocation_id.clone()],
                (expected_hash, accepted).abi_encode(),
            )
        }
        Action::Pay => {
            if !accepted
                || expected_hash == B256::ZERO
                || work.decisionDigest != expected_hash
                || !work.accepted
                || work.state != 4
                || work.paid != amount
                || work.refunded != U256::ZERO
            {
                return Err("allocation was not paid exactly once".into());
            }
            (
                b"Paid(bytes32,address,uint256)".as_slice(),
                vec![
                    request.allocation_id.clone(),
                    actor_topic(&terms.beneficiary)?,
                ],
                amount.abi_encode(),
            )
        }
        Action::Refund => {
            if work.accepted
                || work.state != 7
                || work.refunded != amount
                || work.paid != U256::ZERO
                || (work.decisionDigest != B256::ZERO
                    && (accepted || work.decisionDigest != expected_hash))
            {
                return Err("allocation was not refunded exactly once".into());
            }
            // Public expire() may already have emitted TimedOut in another
            // transaction. The pinned contract, confirmed Refunded event,
            // zero decision and due deadline also cover that valid sequence.
            if work.decisionDigest == B256::ZERO && first.timestamp <= terms.refund_after {
                return Err("refund lacks due timeout evidence".into());
            }
            (
                b"Refunded(bytes32,address,uint256)".as_slice(),
                vec![request.allocation_id.clone(), actor_topic(&terms.payer)?],
                amount.abi_encode(),
            )
        }
    };
    let expected_topics = [vec![topic(event)], topics].concat();
    let data = encoded(event_data);
    if receipt
        .logs
        .iter()
        .filter(|log| {
            log.address == domain.escrow && log.topics == expected_topics && log.data == data
        })
        .count()
        != 1
    {
        return Err("exact settlement event missing".into());
    }
    if matches!(request.action, Action::Pay | Action::Refund) {
        let recipient = if request.action == Action::Pay {
            &terms.beneficiary
        } else {
            &terms.payer
        };
        let topics = vec![
            topic(b"Transfer(address,address,uint256)"),
            actor_topic(&domain.escrow)?,
            actor_topic(recipient)?,
        ];
        let data = encoded(amount.abi_encode());
        if receipt
            .logs
            .iter()
            .filter(|log| log.address == domain.token && log.topics == topics && log.data == data)
            .count()
            != 1
        {
            return Err("exact outgoing token transfer missing".into());
        }
    }
    Ok(Verified {
        allocation_id: request.allocation_id.clone(),
        commitment: request.commitment.clone(),
        state: work.state,
        action: request.action,
        transaction_hash: prepared.transaction_hash.clone(),
        observation_sha256: digest(observation)?,
        block_hash: first.hash.clone(),
        block_number: first.number,
        chain_time: head.timestamp,
    })
}
