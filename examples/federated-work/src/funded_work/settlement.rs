//! Original-identity intents and insert-once signed transactions.
use super::{
    agreement::Policy,
    allocation::{self, Terms},
    evidence,
    journal::{Entry, Journal},
    observer::FundingSource,
    settlement_observer,
    verification::{self, Decision},
};
use crate::common::{digest, Result};
use alloy_primitives::keccak256;
use alloy_sol_types::{sol, SolCall};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

sol! {
    function submitClaim(bytes32 allocationId, bytes32 commitment);
    function recordDecision(bytes32 allocationId, bytes32 decisionDigest, bool accepted, bytes signature);
    function withdrawPayment(bytes32 allocationId);
    function withdrawRefund(bytes32 allocationId);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Submit,
    Record,
    Pay,
    Refund,
}
impl Action {
    pub fn key(self) -> &'static str {
        match self {
            Self::Submit => "submit",
            Self::Record => "record",
            Self::Pay => "pay",
            Self::Refund => "refund",
        }
    }
    pub fn observation_key(self) -> &'static str {
        match self {
            Self::Submit => "submit-observed",
            Self::Record => "record-observed",
            Self::Pay => "pay-observed",
            Self::Refund => "refund-observed",
        }
    }
    fn rail_action(self) -> &'static str {
        if self == Self::Record {
            "decision"
        } else {
            self.key()
        }
    }
    pub fn actor(self, terms: &Terms) -> &str {
        match self {
            Self::Submit | Self::Pay => &terms.beneficiary,
            Self::Record => &terms.verifier,
            Self::Refund => &terms.payer,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActionRequest {
    pub action: Action,
    pub allocation_id: String,
    pub terms: Terms,
    pub commitment: Option<String>,
    pub decision: Option<Decision>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Prepared {
    pub intent: Value,
    pub nonce: String,
    pub raw_transaction: String,
    pub transaction_hash: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Inclusion {
    transaction_hash: String,
    block_hash: String,
    block_number: u64,
}

pub fn retain_observation(
    journal: &Journal,
    allocation: &str,
    verified: &settlement_observer::Verified,
) -> Result<()> {
    journal.retain(
        allocation,
        verified.action.observation_key(),
        &Inclusion {
            transaction_hash: verified.transaction_hash.clone(),
            block_hash: verified.block_hash.clone(),
            block_number: verified.block_number,
        },
    )
}

pub fn request(
    entry: &Entry,
    action: Action,
    policy: &Policy,
    journal: &Journal,
) -> Result<ActionRequest> {
    let terms = entry.agreement.validate(policy, &entry.request)?;
    if entry.operation.is_none() || entry.hold.is_none() {
        return Err("settlement lacks original operation and hold".into());
    }
    let submission: Option<evidence::Submission> =
        journal.retained(&entry.allocation, "submission")?;
    let decision: Option<Decision> = journal.retained(&entry.allocation, "decision")?;
    if let Some(submission) = &submission {
        let b = &submission.body.binding;
        if b.allocation_id != entry.allocation
            || b.operation_id
                != entry
                    .operation
                    .as_deref()
                    .ok_or("original operation missing")?
            || b.hold_id != entry.hold.as_deref().ok_or("original hold missing")?
            || b.authorization_id != super::rail::authorization_id(&entry.allocation)?
            || b.agreement_sha256 != digest(&entry.agreement.body)?
            || b.request_sha256 != digest(&entry.request)?
            || b.authority_uuid != policy.authority_uuid
            || !policy.provider_key.verify_strict(
                &chio_core_types::canonical_json_bytes(&submission.body)?,
                &submission.signature,
            )
        {
            return Err("retained submission changed native identities".into());
        }
    }
    if let Some(decision) = &decision {
        verification::verify_decision(
            decision,
            submission.as_ref().ok_or("decision has no submission")?,
            policy,
        )?;
    }
    if matches!(action, Action::Submit | Action::Record | Action::Pay) && submission.is_none() {
        return Err("claim requires original submission".into());
    }
    if matches!(action, Action::Record | Action::Pay) && decision.is_none() {
        return Err("verified decision unavailable".into());
    }
    if action == Action::Pay && !decision.as_ref().is_some_and(|d| d.body.accepted) {
        return Err("payment requires acceptance".into());
    }
    // A local signed decision can miss its recording deadline. Only an
    // observed on-chain acceptance earns payment; the contract and observer
    // distinguish that from an unrecorded decision eligible for timeout.
    Ok(ActionRequest {
        action,
        allocation_id: entry.allocation.clone(),
        terms,
        commitment: submission
            .as_ref()
            .map(digest)
            .transpose()?
            .map(|hash| format!("0x{hash}")),
        decision,
    })
}

/// Ethers independently decodes the raw signed transaction at the transport
/// boundary. Rust pins its hash and exact ABI call/intent before any broadcast.
pub fn validate(prepared: &Prepared, request: &ActionRequest, policy: &Policy) -> Result<()> {
    let raw = super::observer::data(&prepared.raw_transaction, 8192)?;
    if format!("{:#x}", keccak256(&raw)) != prepared.transaction_hash {
        return Err("signed transaction hash mismatch".into());
    }
    allocation::hash(&prepared.transaction_hash)?;
    if prepared.nonce != "0" {
        allocation::units(&prepared.nonce)?;
    }
    let call_hex = prepared.intent["callData"]
        .as_str()
        .ok_or("transaction call missing")?;
    let call = super::observer::data(call_hex, 1024)?;
    let allocation = allocation::hash(&request.allocation_id)?;
    let exact = match request.action {
        Action::Submit => submitClaimCall {
            allocationId: allocation,
            commitment: allocation::hash(
                request.commitment.as_deref().ok_or("commitment missing")?,
            )?,
        }
        .abi_encode(),
        Action::Record => {
            let decoded = recordDecisionCall::abi_decode_validate(&call)?;
            let decision = request.decision.as_ref().ok_or("decision missing")?;
            if decoded.allocationId != allocation
                || decoded.decisionDigest
                    != allocation::hash(&format!("0x{}", digest(&decision.body)?))?
                || decoded.accepted != decision.body.accepted
                || decoded.signature.len() != 65
            {
                return Err("transaction changed verifier decision".into());
            }
            decoded.abi_encode()
        }
        Action::Pay => withdrawPaymentCall {
            allocationId: allocation,
        }
        .abi_encode(),
        Action::Refund => withdrawRefundCall {
            allocationId: allocation,
        }
        .abi_encode(),
    };
    if call != exact {
        return Err("noncanonical or substituted settlement call".into());
    }
    let body = json!({"schema":"chio.experimental.rail-intent.v1", "allocationId": request.allocation_id,
        "agreementDigest":request.terms.agreement_digest,"action":request.action.rail_action(),
        "actor":request.action.actor(&request.terms),"domain":{"chainId":policy.domain.chain_id,"genesisHash":policy.domain.genesis_hash,
        "escrow":policy.domain.escrow,"runtimeKeccak256":policy.domain.escrow_code_hash},"callData":call_hex,
        "gasLimit":"1000000","maxFeePerGas":"2000000000","maxPriorityFeePerGas":"1000000000"});
    let operation = format!("0x{}", digest(&body)?);
    let mut expected = body;
    expected["operationId"] = json!(operation);
    if expected != prepared.intent {
        return Err("settlement intent changed pinned domain or authority".into());
    }
    Ok(())
}

pub fn drive(
    entry: &Entry,
    action: Action,
    policy: &Policy,
    journal: &Journal,
    source: &dyn FundingSource,
    checkpoint: &super::Checkpoint,
) -> Result<settlement_observer::Verified> {
    let request = request(entry, action, policy, journal)?;
    let prepared = match journal.retained(&entry.allocation, action.key())? {
        Some(prepared) => prepared,
        None => {
            let prepared = source.prepare(&request)?;
            validate(&prepared, &request, policy)?;
            journal.retain(&entry.allocation, action.key(), &prepared)?;
            prepared
        }
    };
    validate(&prepared, &request, policy)?;
    checkpoint("after-prepare")?;
    source.transact(&prepared)?;
    checkpoint("after-broadcast")?;
    let verified = observe(&prepared, &request, policy, source)?;
    retain_observation(journal, &entry.allocation, &verified)?;
    checkpoint("after-observation")?;
    Ok(verified)
}

pub fn observe(
    prepared: &Prepared,
    request: &ActionRequest,
    policy: &Policy,
    source: &dyn FundingSource,
) -> Result<settlement_observer::Verified> {
    validate(prepared, request, policy)?;
    let started = crate::common::now()?;
    let observation = source.observe_transaction(prepared)?;
    settlement_observer::verify(
        policy,
        request,
        prepared,
        &observation,
        started,
        crate::common::now()?,
    )
}
