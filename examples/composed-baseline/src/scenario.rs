//! The fixture: the same call, the same counterparties and the same agreement
//! configuration the Chio cross-organization corpus uses, expressed in what the
//! composed parts carry.
//!
//! A buyer organization asks a vendor organization to issue a refund. The
//! vendor is the receiver. It has pinned the buyer's channel key and the
//! buyer's policy-engine key, provisioned two agreements with that buyer (a
//! production agreement and a pilot agreement with a lower ceiling), retired an
//! earlier version of the production agreement, written one approval record,
//! and installed one rule for the refund action.

use crate::receiver_state::{
    AgreementRecord, ApprovalRecord, PinnedPeer, PolicyRule, ReceiverState,
};
use crate::request::{ComposedEnvelope, ComposedRequest, PolicyDecision, AUTHORIZATION_SCHEMA};
use chio_core_types::crypto::{canonical_json_bytes, sha256_hex, Keypair};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const BUYER: &str = "spiffe://buyer.example/kernel";
pub const VENDOR: &str = "spiffe://vendor.example/kernel";
pub const OTHER_VENDOR: &str = "spiffe://vendor-two.example/kernel";
pub const AGREEMENT: &str = "treaty-buyer-vendor";
pub const AGREEMENT_PILOT: &str = "treaty-buyer-vendor-pilot";
pub const AGREEMENT_RETIRED: &str = "treaty-buyer-vendor-v1";
pub const ACTION: &str = "refund.issue";
pub const APPROVAL: &str = "approval-refund-0001";
pub const NOW_MS: u64 = 1_760_000_000_000;

/// Deterministic seeds, so a rerun of the corpus produces the same keys and the
/// same bytes.
const SEED_BUYER_CHANNEL: [u8; 32] = [0x11; 32];
const SEED_BUYER_POLICY: [u8; 32] = [0x22; 32];
const SEED_VENDOR_DECISION: [u8; 32] = [0x33; 32];
const SEED_ADVERSARY: [u8; 32] = [0x44; 32];

pub struct Keys {
    pub buyer_channel: Keypair,
    pub buyer_policy: Keypair,
    pub vendor_decision: Keypair,
    pub adversary: Keypair,
}

impl Keys {
    pub fn fixed() -> Self {
        Self {
            buyer_channel: Keypair::from_seed(&SEED_BUYER_CHANNEL),
            buyer_policy: Keypair::from_seed(&SEED_BUYER_POLICY),
            vendor_decision: Keypair::from_seed(&SEED_VENDOR_DECISION),
            adversary: Keypair::from_seed(&SEED_ADVERSARY),
        }
    }
}

/// Build the vendor's state. `collapse_keys` pins one key for both the buyer's
/// channel and the buyer's policy engine, which is the one-party-holds-both
/// case.
pub fn vendor_state(keys: &Keys, collapse_keys: bool) -> ReceiverState {
    let policy_key = if collapse_keys {
        keys.buyer_channel.public_key()
    } else {
        keys.buyer_policy.public_key()
    };
    let mut pins = BTreeMap::new();
    pins.insert(
        BUYER.to_string(),
        PinnedPeer {
            principal: BUYER.to_string(),
            channel_key: keys.buyer_channel.public_key(),
            policy_key,
        },
    );

    let mut agreements = BTreeMap::new();
    agreements.insert(
        AGREEMENT.to_string(),
        AgreementRecord {
            agreement_id: AGREEMENT.to_string(),
            version: 2,
            superseded: false,
            participants: vec![BUYER.to_string(), VENDOR.to_string()],
            allowed_actions: vec![ACTION.to_string()],
            max_amount_minor: 10_000,
            assurance_level: "attested".to_string(),
        },
    );
    agreements.insert(
        AGREEMENT_PILOT.to_string(),
        AgreementRecord {
            agreement_id: AGREEMENT_PILOT.to_string(),
            version: 1,
            superseded: false,
            participants: vec![BUYER.to_string(), VENDOR.to_string()],
            allowed_actions: vec![ACTION.to_string()],
            max_amount_minor: 100_000,
            assurance_level: "attested".to_string(),
        },
    );
    agreements.insert(
        AGREEMENT_RETIRED.to_string(),
        AgreementRecord {
            agreement_id: AGREEMENT_RETIRED.to_string(),
            version: 1,
            superseded: true,
            participants: vec![BUYER.to_string(), VENDOR.to_string()],
            allowed_actions: vec![ACTION.to_string()],
            max_amount_minor: 10_000,
            assurance_level: "attested".to_string(),
        },
    );

    let mut approvals = BTreeMap::new();
    approvals.insert(
        APPROVAL.to_string(),
        ApprovalRecord {
            approval_id: APPROVAL.to_string(),
            agreement_id: AGREEMENT.to_string(),
            action: ACTION.to_string(),
            max_amount_minor: 10_000,
        },
    );

    ReceiverState {
        receiver_id: VENDOR.to_string(),
        pins,
        agreements,
        approvals,
        rules: vec![PolicyRule {
            rule_id: "rule-refund-issue".to_string(),
            action: ACTION.to_string(),
            required_assurance: "attested".to_string(),
            max_amount_minor: 10_000,
            requires_local_approval: true,
        }],
        policy_id: "vendor.refund-policy".to_string(),
        policy_version: "v1.4.0".to_string(),
    }
}

/// The arguments of the call under test.
pub fn refund_args() -> Value {
    json!({
        "amount_minor": 2500u64,
        "currency": "USD",
        "order_id": "order-9001",
        "approval_id": APPROVAL,
    })
}

pub fn args_digest(args: &Value) -> Result<String, String> {
    let bytes = canonical_json_bytes(args).map_err(|error| error.to_string())?;
    Ok(sha256_hex(&bytes))
}

/// The decision the buyer's policy engine signs for this call.
pub fn base_decision(request_id: &str, args: &Value) -> Result<PolicyDecision, String> {
    Ok(PolicyDecision {
        schema: AUTHORIZATION_SCHEMA.to_string(),
        decision_id: format!("decision-{request_id}"),
        agreement_id: AGREEMENT.to_string(),
        principal: BUYER.to_string(),
        audience: VENDOR.to_string(),
        action: ACTION.to_string(),
        resource: "order-9001".to_string(),
        tool_args_sha256: args_digest(args)?,
        verdict: "allow".to_string(),
        policy_id: "buyer.refund-policy".to_string(),
        policy_version: "v2.1.0".to_string(),
        issued_at_unix_ms: NOW_MS - 1_000,
        expires_at_unix_ms: NOW_MS + 40_000,
    })
}

/// Seal a request: encode the decision, sign it with `policy_signer`, then sign
/// the whole request with `channel_signer`. `raw_authorization` overrides the
/// encoded decision bytes, so a case can transmit bytes that parse to something
/// other than their canonical form.
pub struct SealInputs<'a> {
    pub request_id: &'a str,
    pub caller: &'a str,
    pub tool_name: &'a str,
    pub tool_args: Value,
    pub context: BTreeMap<String, Value>,
    pub decision: PolicyDecision,
    pub raw_authorization: Option<String>,
    pub policy_signer: &'a Keypair,
    pub channel_signer: Option<&'a Keypair>,
}

pub fn seal(inputs: SealInputs<'_>) -> Result<ComposedEnvelope, String> {
    let authorization_json = match inputs.raw_authorization {
        Some(raw) => raw,
        None => {
            let bytes =
                canonical_json_bytes(&inputs.decision).map_err(|error| error.to_string())?;
            String::from_utf8(bytes).map_err(|error| error.to_string())?
        }
    };
    let authorization_sig = inputs
        .policy_signer
        .sign(authorization_json.as_bytes())
        .to_hex();
    let request = ComposedRequest {
        request_id: inputs.request_id.to_string(),
        tool_name: inputs.tool_name.to_string(),
        tool_args: inputs.tool_args,
        caller: inputs.caller.to_string(),
        context: inputs.context,
        authorization_json,
        authorization_sig,
    };
    let peer_sig = match inputs.channel_signer {
        Some(signer) => {
            let bytes = canonical_json_bytes(&request).map_err(|error| error.to_string())?;
            Some(signer.sign(&bytes).to_hex())
        }
        None => None,
    };
    Ok(ComposedEnvelope { request, peer_sig })
}

/// The unmodified admissible call, which every case starts from.
pub fn admissible(keys: &Keys, request_id: &str) -> Result<ComposedEnvelope, String> {
    let args = refund_args();
    let decision = base_decision(request_id, &args)?;
    seal(SealInputs {
        request_id,
        caller: BUYER,
        tool_name: ACTION,
        tool_args: args,
        context: BTreeMap::new(),
        decision,
        raw_authorization: None,
        policy_signer: &keys.buyer_policy,
        channel_signer: Some(&keys.buyer_channel),
    })
}
