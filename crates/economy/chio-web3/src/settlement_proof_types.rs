use serde::{Deserialize, Serialize};

use crate::capability::scope::{Operation, ToolGrant};
use crate::crypto::PublicKey;
use crate::identity::SignedWeb3IdentityBinding;
use crate::settlement::Web3SettlementExecutionReceiptArtifact;
use crate::trust_profile::Web3SettlementPath;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementProofBundle {
    pub schema: String,
    pub bundle_id: String,
    pub transaction_passport_id: String,
    pub commerce_order_id: String,
    pub order_binding: PublicSettlementOrderBinding,
    pub chain_id: String,
    pub settlement_receipt: Web3SettlementExecutionReceiptArtifact,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_provenance: Option<PublicSettlementDeploymentProvenance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_witness: Option<PublicSettlementWitnessReport>,
    pub chain_snapshot: PublicSettlementChainSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispute_snapshot: Option<PublicSettlementDisputeSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collateral_position_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guarantee_decision_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sla_remedy_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slash_authority_ref: Option<String>,
    pub required_confirmations: u32,
    pub observed_confirmations: u32,
    pub dispute_posture: PublicSettlementDisputePosture,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_signature: Option<PublicSettlementBundleSignature>,
}

impl PublicSettlementProofBundle {
    pub fn has_trust_market_refs(&self) -> bool {
        self.collateral_position_ref.is_some()
            || self.guarantee_decision_ref.is_some()
            || self.sla_remedy_ref.is_some()
            || self.slash_authority_ref.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementBundleSignature {
    pub algorithm: String,
    pub signer_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementOrderBinding {
    pub transaction_passport_id: String,
    pub commerce_order_id: String,
    pub chain_id: String,
    pub settlement_rail_id: String,
    pub custody_provider_id: String,
    pub settlement_reference: String,
    pub settlement_tx_hash: String,
    pub beneficiary_address: String,
    pub escrow_id: String,
    pub settlement_amount: crate::capability::scope::MonetaryAmount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementDeploymentProvenance {
    pub provenance_id: String,
    pub chain_id: String,
    pub contract_package_id: String,
    pub reviewed_manifest_hash: String,
    pub approval_hash: String,
    pub create2_factory: String,
    pub salt_namespace: String,
    pub settlement_token_address: String,
    pub root_registry_address: String,
    pub root_registry_runtime_codehash: String,
    pub identity_registry_address: String,
    pub identity_registry_runtime_codehash: String,
    pub escrow_contract: String,
    pub escrow_runtime_codehash: String,
    pub bond_vault_contract: String,
    pub bond_vault_runtime_codehash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementWitnessReport {
    pub witness_id: String,
    pub mode: PublicSettlementWitnessMode,
    pub body_hash: String,
    pub chain_id: String,
    pub registry_root: String,
    pub root_registry_address: String,
    pub root_registry_runtime_codehash: String,
    pub identity_registry_address: String,
    pub identity_registry_runtime_codehash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_registry_operator: Option<PublicSettlementIdentityRegistryOperatorSnapshot>,
    pub escrow_contract: String,
    pub escrow_runtime_codehash: String,
    pub settlement_token_address: String,
    pub bond_vault_contract: String,
    pub bond_vault_runtime_codehash: String,
    pub anchor_tx_hash: String,
    pub anchored_merkle_root: String,
    pub anchored_checkpoint_seq: u64,
    pub observed_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicSettlementWitnessMode {
    Live,
    VerifiedCache,
    Advisory,
}

#[derive(Debug, Clone, Default)]
pub struct PublicSettlementVerifierTrust {
    pub trusted_bundle_signer_keys: Vec<PublicKey>,
    pub trusted_capital_signer_keys: Vec<PublicKey>,
    pub trusted_anchor_kernel_keys: Vec<PublicKey>,
    pub trusted_beneficiary_identity_keys: Vec<PublicKey>,
    pub trusted_oracle_keys: Vec<PublicKey>,
    pub allowed_chain_ids: Vec<String>,
    pub mainnet_blocked: bool,
    pub minimum_confirmations: Option<u32>,
    pub expected_trust_market_context: Option<PublicSettlementTrustMarketContext>,
    pub independent_chain_head: Option<PublicSettlementIndependentChainHead>,
    pub trusted_dispute_event_blocks: Vec<PublicSettlementBlockSnapshot>,
    pub trusted_release_event_blocks: Vec<PublicSettlementBlockSnapshot>,
    pub trusted_release_event_logs: Vec<PublicSettlementReleaseEventLog>,
    pub trusted_refund_event_logs: Vec<PublicSettlementRefundEventLog>,
    pub verifier_now_unix_seconds: Option<u64>,
    pub trusted_runtime_codehashes: Option<PublicSettlementRuntimeCodehashTrust>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementRuntimeCodehashTrust {
    pub contract_package_id: String,
    pub reviewed_manifest_hash: String,
    pub root_registry_runtime_codehash: String,
    pub identity_registry_runtime_codehash: String,
    pub escrow_runtime_codehash: String,
    pub bond_vault_runtime_codehash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementIndependentChainHead {
    pub chain_id: String,
    pub observed_block_number: u64,
    pub observed_block_hash: String,
    pub latest_block_number: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementChainSnapshot {
    pub chain_id: String,
    pub observed_block_number: u64,
    pub latest_block_number: u64,
    pub max_block_lag: u64,
    pub root_registry_address: String,
    pub root_registry_runtime_codehash: String,
    pub identity_registry_address: String,
    pub identity_registry_runtime_codehash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_registry_operator: Option<PublicSettlementIdentityRegistryOperatorSnapshot>,
    pub registry_root: String,
    pub escrow: PublicSettlementEscrowSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond: Option<PublicSettlementBondSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block: Option<PublicSettlementBlockSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beneficiary_identity_binding: Option<SignedWeb3IdentityBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementIdentityRegistryOperatorSnapshot {
    pub identity_registry_contract: String,
    pub operator_address: String,
    pub operator_key_hash: String,
    pub settlement_key: String,
    pub operator_epoch: u64,
    pub active: bool,
    pub block_number: u64,
    pub block_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementEscrowSnapshot {
    pub escrow_id: String,
    pub escrow_contract: String,
    pub escrow_runtime_codehash: String,
    pub settlement_token_address: String,
    pub beneficiary_address: String,
    pub locked_amount: crate::capability::scope::MonetaryAmount,
    pub released_amount: crate::capability::scope::MonetaryAmount,
    pub refunded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_event: Option<PublicSettlementReleaseEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refund_event: Option<PublicSettlementRefundEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementReleaseEvent {
    pub escrow_id: String,
    pub release_tx_hash: String,
    pub receipt_hash: String,
    pub amount: crate::capability::scope::MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_amount: Option<crate::capability::scope::MonetaryAmount>,
    pub partial: bool,
    pub block: PublicSettlementBlockSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicSettlementReleaseEventKind {
    EscrowReleased,
    EscrowPartialRelease,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementReleaseEventLog {
    pub contract_address: String,
    pub event: PublicSettlementReleaseEventKind,
    pub escrow_id: String,
    pub release_tx_hash: String,
    pub receipt_hash: String,
    pub amount: crate::capability::scope::MonetaryAmount,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remaining_amount: Option<crate::capability::scope::MonetaryAmount>,
    pub block_number: u64,
    pub block_hash: String,
    pub log_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementRefundEvent {
    pub escrow_id: String,
    pub refund_tx_hash: String,
    pub amount: crate::capability::scope::MonetaryAmount,
    pub block: PublicSettlementBlockSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementRefundEventLog {
    pub contract_address: String,
    pub escrow_id: String,
    pub refund_tx_hash: String,
    pub amount: crate::capability::scope::MonetaryAmount,
    pub block_number: u64,
    pub block_hash: String,
    pub log_index: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementBondSnapshot {
    pub bond_vault_contract: String,
    pub bond_vault_runtime_codehash: String,
    pub posted_amount: crate::capability::scope::MonetaryAmount,
    pub minimum_required_amount: crate::capability::scope::MonetaryAmount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementBlockSnapshot {
    pub block_number: u64,
    pub block_hash: String,
    pub transaction_hashes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementDisputeSnapshot {
    pub schema: String,
    pub dispute_id: String,
    pub posture: PublicSettlementDisputePosture,
    pub observed_at: u64,
    pub challenge_window_secs: u64,
    pub window_closed_at: u64,
    pub open_dispute_count: u32,
    pub linked_receipt_ids: Vec<String>,
    pub chain_event_tx_hashes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chain_event_blocks: Vec<PublicSettlementBlockSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicSettlementDisputePosture {
    Undisputed,
    Challenged,
    Bonded,
    Slashed,
    Refunded,
    Appealed,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementVerifierReport {
    pub schema: String,
    pub id: String,
    pub verdict: String,
    pub bundle_id: String,
    pub transaction_passport_id: String,
    pub commerce_order_id: String,
    pub recomputed_settlement_state: String,
    pub chain_context: PublicSettlementChainContext,
    pub public_witness: PublicSettlementWitnessContext,
    pub finality_decision: PublicSettlementFinalityDecision,
    pub dispute_context: PublicSettlementDisputeContext,
    pub dispute_posture: PublicSettlementDisputePosture,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_market_context: Option<PublicSettlementTrustMarketContext>,
    pub verified_claims: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementChainContext {
    pub chain_id: String,
    pub settlement_path: Web3SettlementPath,
    pub settlement_reference: String,
    pub observed_block_number: u64,
    pub registry_root: String,
    pub escrow_id: String,
    pub bond_vault_contract: String,
    pub posted_bond_amount: crate::capability::scope::MonetaryAmount,
    pub minimum_bond_amount: crate::capability::scope::MonetaryAmount,
    pub block_hash: String,
    pub anchor_tx_hash: String,
    pub settlement_tx_hash: String,
    pub beneficiary_address: String,
    pub beneficiary_chio_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementWitnessContext {
    pub witness_id: String,
    pub mode: PublicSettlementWitnessMode,
    pub body_hash: String,
    pub observed_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementDisputeContext {
    pub dispute_id: String,
    pub posture: PublicSettlementDisputePosture,
    pub observed_at: u64,
    pub challenge_window_secs: u64,
    pub window_closed_at: u64,
    pub open_dispute_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementFinalityDecision {
    pub status: String,
    pub required_confirmations: u32,
    pub observed_confirmations: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementTrustMarketContext {
    pub collateral_position_ref: String,
    pub guarantee_decision_ref: String,
    pub sla_remedy_ref: String,
    pub slash_authority_ref: String,
}

/// A tool-call authorization decision: the type that occupies the
/// "may this tool call proceed?" position in the kernel capability lane.
///
/// This type is fail-closed BY CONSTRUCTION. It carries a single private flag,
/// so an authorized state is unrepresentable outside this module:
///
/// - [`Default`] and [`ToolCallAuthorization::denied`] both yield DENY.
/// - The only constructor that can yield an authorized decision is
///   [`ToolCallAuthorization::from_capability_grant`], which requires an
///   explicit positive capability grant (a [`ToolGrant`] that targets the tool
///   and carries the `Invoke` operation).
/// - There is deliberately NO `From`/`Into`, no `Deserialize`, and no other
///   constructor that maps a settlement or payment verdict (such as a
///   [`PublicSettlementVerifierReport`]) into this type. Payment success is
///   therefore STRUCTURALLY incapable of producing a tool-call grant: it is not
///   a runtime check that could be forgotten or weakened, it is the absence of
///   any reachable code path from a settlement verdict to a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ToolCallAuthorization {
    /// Private by design: `false` (DENY) unless minted from a capability grant.
    granted: bool,
}

impl ToolCallAuthorization {
    /// The fail-closed default: the tool call is NOT authorized.
    #[must_use]
    pub const fn denied() -> Self {
        Self { granted: false }
    }

    /// Mint a tool-call authorization from an explicit positive capability
    /// grant. This is the ONLY path to an authorized decision.
    ///
    /// DENY-BY-DEFAULT POSTURE. This argument-less helper sees ONLY the static
    /// grant plus the `(server_id, tool_name)` being invoked. It has NO request
    /// arguments, NO running usage/budget, NO per-call cost, and NO DPoP/sender
    /// proof. It may therefore authorize ONLY a grant whose EVERY
    /// authorization-relevant field is FULLY satisfiable from those static inputs.
    /// Any field that gates authorization but requires runtime, usage, proof, or
    /// request context to evaluate MUST fail closed (DENY) here and route through
    /// the lane that holds that context (the kernel capability/budget lane, the
    /// edge DPoP lane). This helper has repeatedly grown gaps as `ToolGrant` gained
    /// new gating fields (a zero invocation cap, monetary caps, a DPoP requirement),
    /// each silently authorized until patched; the posture below closes that class
    /// definitively. When a NEW field is added to `ToolGrant`, this helper MUST
    /// treat it as deny-by-default until it is explicitly proven fully evaluable
    /// from the static inputs above and added to the positive checks below.
    ///
    /// Concretely, the decision is authorized only when the grant targets this
    /// `server_id`/`tool_name` (honoring `*` wildcards), carries the `Invoke`
    /// operation, carries NO parameter constraints, carries NO invocation cap
    /// (`max_invocations` is `None`), carries NO monetary cap
    /// (`max_cost_per_invocation` and `max_total_cost` are both `None`), and does
    /// NOT require a DPoP proof (`dpop_required` is `None` or `Some(false)`). Every
    /// other case fails closed to DENY.
    ///
    /// Why each non-identity field is deny-by-default here:
    ///
    /// - Parameter CONSTRAINTS (`grant.constraints`) narrow the tool's input space,
    ///   and the kernel's `constraints_match` evaluates them against the actual
    ///   request arguments. This helper never sees the request, so a constrained
    ///   grant could authorize EVERY invocation; only an unconstrained grant is
    ///   evaluable.
    /// - INVOCATION cap (`max_invocations`) gates on the grant's running call
    ///   count, which lives in the kernel budget lane, not here. `Some(0)` permits
    ///   zero calls outright, and even a positive cap (`Some(n)`) cannot be
    ///   confirmed unexhausted without the usage count, so ANY `Some(_)` fails
    ///   closed; only an uncapped grant (`None`, bounded by the budget lane
    ///   elsewhere) is evaluable.
    /// - MONETARY caps (`max_cost_per_invocation`, `max_total_cost`) gate on the
    ///   call's cost and the grant's running spend, neither of which this helper
    ///   holds. `Some(0)` per-invocation denies every non-zero-cost call and an
    ///   exhausted total denies further calls, and even a positive cap is
    ///   unconfirmable, so any `Some(_)` fails closed; only `None`/`None` is
    ///   evaluable.
    /// - DPoP (`dpop_required`) requires a valid DPoP proof on every invocation
    ///   when `Some(true)`, and this helper holds no proof. The ACP/edge lane denies
    ///   a DPoP-required grant without a proof, so authorizing it here would
    ///   advertise a capability the edge lane would deny; `Some(true)` fails closed.
    ///   `None`/`Some(false)` require no proof and are evaluable.
    #[must_use]
    pub fn from_capability_grant(grant: &ToolGrant, server_id: &str, tool_name: &str) -> Self {
        // Identity + operation: fully evaluable from the static inputs.
        let server_ok = grant.server_id == "*" || grant.server_id == server_id;
        let tool_ok = grant.tool_name == "*" || grant.tool_name == tool_name;
        let can_invoke = grant.operations.contains(&Operation::Invoke);

        // Parameter constraints are checked against the request this helper never
        // sees: only an unconstrained grant is evaluable here.
        let unconstrained = grant.constraints.is_empty();

        // Budget caps (invocation count + monetary) gate authorization on running
        // usage and per-call cost that live in the kernel budget lane, not here. A
        // capped grant (any `Some`) - even a positive one - is unconfirmable from
        // static inputs, so authorize ONLY an uncapped grant (every cap `None`).
        let uncapped = grant.max_invocations.is_none()
            && grant.max_cost_per_invocation.is_none()
            && grant.max_total_cost.is_none();

        // A grant that requires a DPoP proof cannot be authorized without one, and
        // this helper holds no proof. `Some(true)` fails closed; `None`/`Some(false)`
        // require no proof and are evaluable.
        let dpop_not_required = grant.dpop_required != Some(true);

        // Deny-by-default: authorize ONLY when every authorization-relevant field
        // above is fully satisfiable from the static inputs. A new gating field
        // must be added as a fresh `&&` term here, defaulting to DENY until proven
        // evaluable.
        Self {
            granted: server_ok
                && tool_ok
                && can_invoke
                && unconstrained
                && uncapped
                && dpop_not_required,
        }
    }

    /// Whether this decision authorizes the tool call. `false` for every
    /// decision except one minted from a matching capability grant.
    #[must_use]
    pub const fn is_authorized(&self) -> bool {
        self.granted
    }
}

impl PublicSettlementVerifierReport {
    /// The tool-call authorization carried by a settlement verifier report:
    /// always [`ToolCallAuthorization::denied`].
    ///
    /// This is STRUCTURAL, not a runtime check. The body returns the
    /// fail-closed DENY decision without reading any field of the report, so no
    /// value of `verdict` (not even `"verified"`, nor a forged `"authorized"`),
    /// no `verified_claims` entry, and no other field can flip it. A verified
    /// settlement report proves a payment settled and that the settlement
    /// evidence recomputes; tool-call authority comes ONLY from the
    /// capability/governance lane via
    /// [`ToolCallAuthorization::from_capability_grant`].
    #[must_use]
    pub const fn tool_call_authorization(&self) -> ToolCallAuthorization {
        ToolCallAuthorization::denied()
    }

    /// Convenience guard: `false` for every settlement report, by construction.
    #[must_use]
    pub const fn authorizes_tool_call(&self) -> bool {
        self.tool_call_authorization().is_authorized()
    }
}
