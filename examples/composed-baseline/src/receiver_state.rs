//! What the composed receiver holds before a request arrives.
//!
//! Three tables, each the natural product of one off-the-shelf part: the pin
//! set a federated trust bundle installs, the agreement records an operator
//! provisions per counterparty, and the approval records a governance workflow
//! writes. The rule set the policy engine evaluates is here too.

use chio_core_types::crypto::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One pinned workload identity: the public key a federated trust bundle, or
/// plain out-of-band pinning, binds to a name.
#[derive(Debug, Clone)]
pub struct PinnedPeer {
    pub principal: String,
    pub channel_key: PublicKey,
    /// Key the counterparty's policy engine signs decisions with.
    pub policy_key: PublicKey,
}

/// An operator-provisioned bilateral agreement. The nearest thing the composed
/// parts have to the receiver-side record a treaty identifier resolves to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementRecord {
    pub agreement_id: String,
    /// Monotone version. Present in the receiver's own record; the composed
    /// request carries nothing that pins which version the sender decided
    /// under, which is the hole the superseded-agreement case exercises.
    pub version: u64,
    pub superseded: bool,
    pub participants: Vec<String>,
    pub allowed_actions: Vec<String>,
    /// Ceiling on a single call, in minor units. Two agreements with the same
    /// counterparty commonly carry different ceilings.
    pub max_amount_minor: u64,
    /// Assurance level the receiver itself assigns to this counterparty. The
    /// hardened profile reads the policy context from here; the composed
    /// wiring reads it from the request.
    pub assurance_level: String,
}

/// A governance approval the receiver wrote before the request arrived.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub approval_id: String,
    pub agreement_id: String,
    pub action: String,
    pub max_amount_minor: u64,
}

/// One rule of the receiver's local policy set. Deliberately small: an
/// attribute-based policy engine evaluating a handful of conditions over a
/// principal, an action, a resource and a context is what the composition
/// provides, and enlarging the rule language would not change which facts the
/// request carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub rule_id: String,
    /// Action this rule governs.
    pub action: String,
    /// Assurance level the caller must present for this action.
    pub required_assurance: String,
    /// Ceiling the rule enforces on `tool_args.amount_minor`.
    pub max_amount_minor: u64,
    /// When set, the rule requires an approval record the receiver already
    /// holds, named by `tool_args.approval_id`.
    pub requires_local_approval: bool,
}

/// The receiver's state before any request arrives.
#[derive(Debug, Clone)]
pub struct ReceiverState {
    pub receiver_id: String,
    pub pins: BTreeMap<String, PinnedPeer>,
    pub agreements: BTreeMap<String, AgreementRecord>,
    pub approvals: BTreeMap<String, ApprovalRecord>,
    pub rules: Vec<PolicyRule>,
    pub policy_id: String,
    pub policy_version: String,
}

impl ReceiverState {
    pub fn pin(&self, principal: &str) -> Option<&PinnedPeer> {
        self.pins.get(principal)
    }

    pub fn agreement(&self, agreement_id: &str) -> Option<&AgreementRecord> {
        self.agreements.get(agreement_id)
    }

    pub fn approval(&self, approval_id: &str) -> Option<&ApprovalRecord> {
        self.approvals.get(approval_id)
    }

    pub fn rule_for(&self, action: &str) -> Option<&PolicyRule> {
        self.rules.iter().find(|rule| rule.action == action)
    }
}
