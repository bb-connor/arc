//! What the composed receiver holds before a request arrives.
//!
//! Each table is the natural product of one part of the composition: the trust
//! bundle a SPIFFE federation installs, the agreement records an operator
//! provisions per counterparty, the approval records a governance workflow
//! writes, and the tasks this receiver itself created and handed back. The rule
//! set the policy engine evaluates is here too.

use chio_core_types::crypto::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One entry of the federated trust bundle: what the receiver knows about a
/// counterparty before it calls.
#[derive(Debug, Clone)]
pub struct TrustBundleEntry {
    /// The SPIFFE ID of the counterparty's calling workload, as it appears in
    /// the URI SAN of the X509-SVID it presents.
    pub spiffe_id: String,
    /// The key in that SVID.
    pub svid_key: PublicKey,
    /// Issuer identifier of the authorization server that performs the
    /// counterparty's token exchange, as the `iss` claim states it.
    pub issuer: String,
    /// The key that issuer signs with.
    pub issuer_key: PublicKey,
}

/// An operator-provisioned bilateral agreement. The nearest thing the composed
/// parts have to the receiver-side record a treaty identifier resolves to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgreementRecord {
    pub agreement_id: String,
    /// Monotone version of the receiver's own record.
    pub version: u64,
    /// When this version took effect on this receiver. Nothing the caller
    /// presents is derived from it; it is here because the only timestamp the
    /// credential carries is one the issuer chose, and comparing the two is
    /// the closest a check over shipped fields can come to pinning a version.
    pub version_effective_at_unix_ms: u64,
    pub superseded: bool,
    /// Participants, as SPIFFE IDs.
    pub participants: Vec<String>,
    pub allowed_actions: Vec<String>,
    /// Ceiling on a single call, in minor units. Two agreements with the same
    /// counterparty commonly carry different ceilings.
    pub max_amount_minor: u64,
    /// Assurance level the receiver itself assigns to this counterparty.
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

/// A task this receiver created and named. Its identifier is the one
/// receiver-minted value that crosses back: the caller echoes it in
/// `Message.task_id` on later messages of the same task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskRecord {
    pub task_id: String,
    pub context_id: String,
    /// The counterparty the task belongs to.
    pub counterparty: String,
}

/// One rule of the receiver's local policy set. Deliberately small: an
/// attribute-based policy engine evaluating a handful of conditions over a
/// principal, an action, a resource and a context is what the composition
/// provides, and enlarging the rule language would not change which facts the
/// request carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub rule_id: String,
    pub action: String,
    pub required_assurance: String,
    pub max_amount_minor: u64,
    /// When set, the rule requires an approval record the receiver already
    /// holds, named by an argument of the tool call.
    pub requires_local_approval: bool,
}

/// The receiver's state before any request arrives.
#[derive(Debug, Clone)]
pub struct ReceiverState {
    /// The receiver's own SPIFFE ID.
    pub receiver_id: String,
    /// The canonical URI of this receiver as a protected resource, which is
    /// what an audience-restricted token has to name.
    pub receiver_uri: String,
    pub bundle: BTreeMap<String, TrustBundleEntry>,
    pub agreements: BTreeMap<String, AgreementRecord>,
    pub approvals: BTreeMap<String, ApprovalRecord>,
    pub tasks: BTreeMap<String, TaskRecord>,
    pub rules: Vec<PolicyRule>,
    pub policy_id: String,
    pub policy_version: String,
}

impl ReceiverState {
    pub fn peer(&self, spiffe_id: &str) -> Option<&TrustBundleEntry> {
        self.bundle.get(spiffe_id)
    }

    pub fn agreement(&self, agreement_id: &str) -> Option<&AgreementRecord> {
        self.agreements.get(agreement_id)
    }

    pub fn approval(&self, approval_id: &str) -> Option<&ApprovalRecord> {
        self.approvals.get(approval_id)
    }

    pub fn task(&self, task_id: &str) -> Option<&TaskRecord> {
        self.tasks.get(task_id)
    }

    pub fn rule_for(&self, action: &str) -> Option<&PolicyRule> {
        self.rules.iter().find(|rule| rule.action == action)
    }
}
