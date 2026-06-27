use serde::{Deserialize, Serialize};

use crate::anchors::verify_oracle_conversion_evidence_signature;
use crate::canonical::canonical_json_bytes;
use crate::capability::scope::{Operation, ToolGrant};
use crate::credit::CapitalBookEvidenceKind;
use crate::crypto::sha256_hex;
use crate::crypto::PublicKey;
use crate::error::Web3ContractError;
use crate::hashing::Hash;
use crate::identity::{
    verify_web3_identity_binding, SignedWeb3IdentityBinding, Web3KeyBindingPurpose,
};
use crate::settlement::{
    validate_web3_settlement_execution_receipt, Web3SettlementExecutionReceiptArtifact,
    Web3SettlementLifecycleState,
};
use crate::trust_profile::Web3SettlementPath;
use crate::validation::{ensure_money, ensure_non_empty};

pub const CHIO_WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA: &str = "chio.web3-settlement-proof-bundle.v1";
pub const CHIO_WEB3_SETTLEMENT_DISPUTE_SCHEMA: &str = "chio.web3-settlement-dispute.v1";
pub const CHIO_PUBLIC_SETTLEMENT_VERIFIER_REPORT_SCHEMA: &str =
    "chio.public-settlement-verifier-report.v1";

pub const CLAIM_PUBLIC_SETTLEMENT_ORDER_BINDING_VERIFIED: &str =
    "claim.public_settlement.order_binding_verified";
pub const CLAIM_PUBLIC_SETTLEMENT_CHAIN_CONTEXT_VERIFIED: &str =
    "claim.public_settlement.chain_context_verified";
pub const CLAIM_PUBLIC_SETTLEMENT_FINALITY_VERIFIED: &str =
    "claim.public_settlement.finality_verified";
pub const CLAIM_PUBLIC_SETTLEMENT_ORACLE_CONVERSION_BOUND: &str =
    "claim.public_settlement.oracle_conversion_bound";
pub const CLAIM_PUBLIC_SETTLEMENT_DISPUTE_POSTURE_BOUND: &str =
    "claim.public_settlement.dispute_posture_bound";
pub const CLAIM_PUBLIC_SETTLEMENT_TRUST_MARKET_REFS_BOUND: &str =
    "claim.public_settlement.trust_market_refs_bound";
pub const CLAIM_PUBLIC_SETTLEMENT_PUBLIC_WITNESS_VERIFIED: &str =
    "claim.public_settlement.public_witness_verified";

pub(crate) const MAX_VERIFIED_CACHE_WITNESS_AGE_SECONDS: u64 = 3_600;

#[cfg(test)]
pub(crate) const PUBLIC_SETTLEMENT_FINALITY_REPORT_STATUSES: &[&str] = &[
    "final",
    "closed",
    "partially_settled",
    "refunded",
    "slashed",
    "reversed",
    "charged_back",
    "timed_out",
    "failed",
    "reorged",
    "not_final",
    // RPI-1: emitted in place of an affirmative-finality status when finality is
    // not independently grounded (no independent chain head).
    "ungrounded",
];

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
pub struct PublicSettlementOrderBinding {
    pub transaction_passport_id: String,
    pub commerce_order_id: String,
    pub chain_id: String,
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
    pub root_registry_address: String,
    pub escrow_contract: String,
    pub bond_vault_contract: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementWitnessReport {
    pub witness_id: String,
    pub mode: PublicSettlementWitnessMode,
    pub body_hash: String,
    pub chain_id: String,
    pub registry_root: String,
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
    pub trusted_capital_signer_keys: Vec<PublicKey>,
    pub trusted_anchor_kernel_keys: Vec<PublicKey>,
    pub trusted_beneficiary_identity_keys: Vec<PublicKey>,
    pub trusted_oracle_keys: Vec<PublicKey>,
    pub allowed_chain_ids: Vec<String>,
    pub mainnet_blocked: bool,
    pub minimum_confirmations: Option<u32>,
    pub expected_trust_market_context: Option<PublicSettlementTrustMarketContext>,
    pub independent_chain_head: Option<PublicSettlementIndependentChainHead>,
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
    pub registry_root: String,
    pub escrow: PublicSettlementEscrowSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond: Option<PublicSettlementBondSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block: Option<PublicSettlementBlockSnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beneficiary_identity_binding: Option<SignedWeb3IdentityBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementEscrowSnapshot {
    pub escrow_id: String,
    pub escrow_contract: String,
    pub beneficiary_address: String,
    pub locked_amount: crate::capability::scope::MonetaryAmount,
    pub released_amount: crate::capability::scope::MonetaryAmount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicSettlementBondSnapshot {
    pub bond_vault_contract: String,
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

/// Verify a public settlement proof bundle through the recompute lane.
///
/// Settlement state is recomputed from the kernel-signed checkpoint anchor
/// and the chain snapshot, not trusted from any producer-asserted or
/// witnessed on-chain value: the public witness must agree with the
/// recomputed `chain_anchor` (root, checkpoint sequence, anchor tx), and the
/// snapshot registry root must equal the anchored Merkle root. The returned
/// [`PublicSettlementVerifierReport`] binds settlement and payment claims
/// ONLY (`claim.public_settlement.*`). A "verified" verdict here means the
/// payment settled and the settlement evidence recomputes; it does NOT
/// authorize a tool call. Payment success is not authorization: tool-call
/// authority comes from the capability/governance lane, never from a
/// settlement receipt, so this report carries no capability grant and emits
/// no tool-call authorization claim.
///
/// # Errors
///
/// Returns [`Web3ContractError`] when the bundle fails header, trust,
/// verifier-policy, provenance, order-binding, chain-binding, snapshot,
/// independent-head, finality, dispute, trust-market, or public-witness
/// validation, or when any carried signature fails to verify.
pub fn verify_public_settlement_proof(
    bundle: &PublicSettlementProofBundle,
    trust: &PublicSettlementVerifierTrust,
) -> Result<PublicSettlementVerifierReport, Web3ContractError> {
    validate_bundle_header(bundle)?;
    validate_web3_settlement_execution_receipt(&bundle.settlement_receipt)?;
    validate_public_settlement_trust(bundle, trust)?;
    validate_public_settlement_verifier_policy(bundle, trust)?;
    validate_deployment_provenance(bundle)?;
    validate_order_binding(bundle)?;
    validate_chain_binding(bundle)?;
    validate_chain_snapshot(bundle)?;
    validate_independent_chain_head(bundle, trust)?;
    validate_finality(bundle)?;
    validate_dispute_posture(bundle)?;
    let trust_market_context = validate_trust_market_refs(bundle)?;
    let trust_market_context_verified =
        validate_expected_trust_market_context(&trust_market_context, trust)?;
    validate_finality_settlement_state(bundle)?;
    let bond = required_bond_snapshot(bundle)?;
    let block = required_block_snapshot(bundle)?;
    let chain_anchor = required_chain_anchor(bundle)?;
    let public_witness = validate_public_witness(bundle, chain_anchor)?;
    let beneficiary_binding = required_beneficiary_identity_binding(bundle)?;
    let dispute_snapshot = required_dispute_snapshot(bundle)?;

    let mut verified_claims = Vec::new();
    push_claim_once(
        &mut verified_claims,
        CLAIM_PUBLIC_SETTLEMENT_ORDER_BINDING_VERIFIED,
    );
    push_claim_once(
        &mut verified_claims,
        CLAIM_PUBLIC_SETTLEMENT_CHAIN_CONTEXT_VERIFIED,
    );
    // Fail-closed finality grounding (RPI-1): finality is asserted ONLY when an
    // INDEPENDENT chain head is supplied. `validate_finality` checks the
    // producer-supplied `chain_snapshot.latest_block_number` /
    // `observed_confirmations`, which are UNSIGNED bundle fields a malicious
    // producer can fabricate to manufacture confirmation depth. Without
    // `trust.independent_chain_head` (validated above by
    // `validate_independent_chain_head`) there is no source the verifier
    // independently observed, so the finality claim is WITHHELD rather than
    // emitted from producer-asserted depth. Downstream verifier policy that
    // requires `finality_verified` then fails closed; nothing here vouches for
    // finality it cannot independently ground.
    if trust.independent_chain_head.is_some() {
        push_claim_once(
            &mut verified_claims,
            CLAIM_PUBLIC_SETTLEMENT_FINALITY_VERIFIED,
        );
    }
    if let Some(oracle_evidence) = &bundle.settlement_receipt.oracle_evidence {
        verify_oracle_conversion_evidence_signature(oracle_evidence, &trust.trusted_oracle_keys)?;
        push_claim_once(
            &mut verified_claims,
            CLAIM_PUBLIC_SETTLEMENT_ORACLE_CONVERSION_BOUND,
        );
    }
    push_claim_once(
        &mut verified_claims,
        CLAIM_PUBLIC_SETTLEMENT_DISPUTE_POSTURE_BOUND,
    );
    if trust_market_context_verified {
        push_claim_once(
            &mut verified_claims,
            CLAIM_PUBLIC_SETTLEMENT_TRUST_MARKET_REFS_BOUND,
        );
    }
    push_claim_once(
        &mut verified_claims,
        CLAIM_PUBLIC_SETTLEMENT_PUBLIC_WITNESS_VERIFIED,
    );

    Ok(PublicSettlementVerifierReport {
        schema: CHIO_PUBLIC_SETTLEMENT_VERIFIER_REPORT_SCHEMA.to_string(),
        id: format!("public-settlement-verifier-report-{}", bundle.bundle_id),
        verdict: "verified".to_string(),
        bundle_id: bundle.bundle_id.clone(),
        transaction_passport_id: bundle.transaction_passport_id.clone(),
        commerce_order_id: bundle.commerce_order_id.clone(),
        recomputed_settlement_state: settlement_state_id(bundle.settlement_receipt.lifecycle_state)
            .to_string(),
        chain_context: PublicSettlementChainContext {
            chain_id: bundle.chain_id.clone(),
            settlement_path: bundle.settlement_receipt.dispatch.settlement_path,
            settlement_reference: bundle.settlement_receipt.settlement_reference.clone(),
            observed_block_number: bundle.chain_snapshot.observed_block_number,
            registry_root: bundle.chain_snapshot.registry_root.clone(),
            escrow_id: bundle.chain_snapshot.escrow.escrow_id.clone(),
            bond_vault_contract: bond.bond_vault_contract.clone(),
            posted_bond_amount: bond.posted_amount.clone(),
            minimum_bond_amount: bond.minimum_required_amount.clone(),
            block_hash: block.block_hash.clone(),
            anchor_tx_hash: chain_anchor.tx_hash.clone(),
            settlement_tx_hash: bundle
                .settlement_receipt
                .observed_execution
                .external_reference_id
                .clone(),
            beneficiary_address: beneficiary_binding.certificate.settlement_address.clone(),
            beneficiary_chio_identity: beneficiary_binding.certificate.chio_identity.clone(),
        },
        public_witness,
        finality_decision: PublicSettlementFinalityDecision {
            // RPI-1 (fail-closed finality grounding): the `status` field must never
            // ASSERT grounded finality without an independent chain head. The raw
            // lifecycle-derived status can read `final`/`closed` from the
            // producer-supplied settlement state and confirmation depth, so a
            // consumer keying off the STATUS field (rather than the withheld
            // `finality_verified` claim) could still accept ungrounded finality.
            // Downgrade those affirmative-finality statuses to `ungrounded` when no
            // independent head grounds the depth; the non-final dispute/reversal
            // outcomes are not finality assertions and pass through unchanged.
            status: grounded_finality_report_status(bundle, trust.independent_chain_head.is_some())
                .to_string(),
            required_confirmations: bundle.required_confirmations,
            observed_confirmations: bundle.observed_confirmations,
        },
        dispute_context: PublicSettlementDisputeContext {
            dispute_id: dispute_snapshot.dispute_id.clone(),
            posture: dispute_snapshot.posture,
            observed_at: dispute_snapshot.observed_at,
            challenge_window_secs: dispute_snapshot.challenge_window_secs,
            window_closed_at: dispute_snapshot.window_closed_at,
            open_dispute_count: dispute_snapshot.open_dispute_count,
        },
        dispute_posture: bundle.dispute_posture,
        trust_market_context,
        verified_claims,
    })
}

fn validate_deployment_provenance(
    bundle: &PublicSettlementProofBundle,
) -> Result<(), Web3ContractError> {
    let provenance = bundle.deployment_provenance.as_ref().ok_or_else(|| {
        Web3ContractError::InvalidProof(
            "public settlement deployment provenance missing".to_string(),
        )
    })?;

    for (field, value) in [
        (
            "public_settlement.deployment_provenance.provenance_id",
            &provenance.provenance_id,
        ),
        (
            "public_settlement.deployment_provenance.chain_id",
            &provenance.chain_id,
        ),
        (
            "public_settlement.deployment_provenance.contract_package_id",
            &provenance.contract_package_id,
        ),
        (
            "public_settlement.deployment_provenance.reviewed_manifest_hash",
            &provenance.reviewed_manifest_hash,
        ),
        (
            "public_settlement.deployment_provenance.approval_hash",
            &provenance.approval_hash,
        ),
        (
            "public_settlement.deployment_provenance.create2_factory",
            &provenance.create2_factory,
        ),
        (
            "public_settlement.deployment_provenance.salt_namespace",
            &provenance.salt_namespace,
        ),
        (
            "public_settlement.deployment_provenance.root_registry_address",
            &provenance.root_registry_address,
        ),
        (
            "public_settlement.deployment_provenance.escrow_contract",
            &provenance.escrow_contract,
        ),
        (
            "public_settlement.deployment_provenance.bond_vault_contract",
            &provenance.bond_vault_contract,
        ),
    ] {
        ensure_non_empty(value, field)?;
    }

    Hash::from_hex(&provenance.reviewed_manifest_hash)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    Hash::from_hex(&provenance.approval_hash)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;

    let dispatch = &bundle.settlement_receipt.dispatch;
    if provenance.chain_id != bundle.chain_id {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement deployment provenance chain mismatch".to_string(),
        ));
    }
    if provenance.contract_package_id != dispatch.contract_package_id {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement deployment contract package mismatch".to_string(),
        ));
    }
    if provenance.root_registry_address != bundle.chain_snapshot.root_registry_address {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement deployment root registry mismatch".to_string(),
        ));
    }
    if provenance.escrow_contract != dispatch.escrow_contract {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement deployment escrow contract mismatch".to_string(),
        ));
    }
    if provenance.bond_vault_contract != dispatch.bond_vault_contract {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement deployment bond vault mismatch".to_string(),
        ));
    }
    Ok(())
}

fn validate_public_witness(
    bundle: &PublicSettlementProofBundle,
    chain_anchor: &crate::anchors::Web3ChainAnchorRecord,
) -> Result<PublicSettlementWitnessContext, Web3ContractError> {
    let witness = bundle.public_witness.as_ref().ok_or_else(|| {
        Web3ContractError::InvalidProof("public settlement witness report missing".to_string())
    })?;

    for (field, value) in [
        (
            "public_settlement.public_witness.witness_id",
            &witness.witness_id,
        ),
        (
            "public_settlement.public_witness.body_hash",
            &witness.body_hash,
        ),
        (
            "public_settlement.public_witness.chain_id",
            &witness.chain_id,
        ),
        (
            "public_settlement.public_witness.registry_root",
            &witness.registry_root,
        ),
        (
            "public_settlement.public_witness.anchor_tx_hash",
            &witness.anchor_tx_hash,
        ),
        (
            "public_settlement.public_witness.anchored_merkle_root",
            &witness.anchored_merkle_root,
        ),
    ] {
        ensure_non_empty(value, field)?;
    }

    if witness.mode == PublicSettlementWitnessMode::Advisory {
        return Err(Web3ContractError::InvalidProof(
            "public settlement witness mode advisory".to_string(),
        ));
    }
    if witness.mode == PublicSettlementWitnessMode::VerifiedCache {
        let valid_until = witness
            .observed_at
            .checked_add(MAX_VERIFIED_CACHE_WITNESS_AGE_SECONDS)
            .ok_or_else(|| {
                Web3ContractError::InvalidProof(
                    "public settlement verified-cache witness age overflow".to_string(),
                )
            })?;
        if valid_until < bundle.settlement_receipt.observed_execution.observed_at {
            return Err(Web3ContractError::InvalidProof(
                "public settlement verified-cache witness is stale".to_string(),
            ));
        }
    }

    Hash::from_hex(&witness.body_hash)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    Hash::from_hex(&witness.registry_root)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    Hash::from_hex(&witness.anchor_tx_hash)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    Hash::from_hex(&witness.anchored_merkle_root)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;

    if witness.chain_id != bundle.chain_id {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement witness chain mismatch".to_string(),
        ));
    }
    if witness.registry_root != bundle.chain_snapshot.registry_root {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement witness registry root mismatch".to_string(),
        ));
    }
    if witness.anchor_tx_hash != chain_anchor.tx_hash {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement witness anchor tx mismatch".to_string(),
        ));
    }
    if witness.anchored_merkle_root != chain_anchor.anchored_merkle_root.to_hex_prefixed() {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement witness merkle root mismatch".to_string(),
        ));
    }
    if witness.anchored_checkpoint_seq != chain_anchor.anchored_checkpoint_seq {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement witness checkpoint mismatch".to_string(),
        ));
    }

    let expected_body_hash = public_settlement_witness_body_hash(witness)?;
    if witness.body_hash != expected_body_hash {
        return Err(Web3ContractError::InvalidProof(
            "public settlement witness body hash mismatch".to_string(),
        ));
    }

    Ok(PublicSettlementWitnessContext {
        witness_id: witness.witness_id.clone(),
        mode: witness.mode,
        body_hash: witness.body_hash.clone(),
        observed_at: witness.observed_at,
    })
}

#[derive(Serialize)]
struct PublicSettlementWitnessBody<'a> {
    witness_id: &'a str,
    mode: PublicSettlementWitnessMode,
    chain_id: &'a str,
    registry_root: &'a str,
    anchor_tx_hash: &'a str,
    anchored_merkle_root: &'a str,
    anchored_checkpoint_seq: u64,
    observed_at: u64,
}

pub(crate) fn public_settlement_witness_body_hash(
    witness: &PublicSettlementWitnessReport,
) -> Result<String, Web3ContractError> {
    let body = PublicSettlementWitnessBody {
        witness_id: &witness.witness_id,
        mode: witness.mode,
        chain_id: &witness.chain_id,
        registry_root: &witness.registry_root,
        anchor_tx_hash: &witness.anchor_tx_hash,
        anchored_merkle_root: &witness.anchored_merkle_root,
        anchored_checkpoint_seq: witness.anchored_checkpoint_seq,
        observed_at: witness.observed_at,
    };
    let canonical = canonical_json_bytes(&body).map_err(|error| {
        Web3ContractError::InvalidProof(format!(
            "public settlement witness canonicalization failed: {error}"
        ))
    })?;
    Ok(sha256_hex(&canonical))
}

fn validate_trust_market_refs(
    bundle: &PublicSettlementProofBundle,
) -> Result<Option<PublicSettlementTrustMarketContext>, Web3ContractError> {
    match (
        bundle.collateral_position_ref.as_deref(),
        bundle.guarantee_decision_ref.as_deref(),
        bundle.sla_remedy_ref.as_deref(),
        bundle.slash_authority_ref.as_deref(),
    ) {
        (None, None, None, None) => Ok(None),
        (Some(collateral), Some(guarantee), Some(remedy), Some(slash_authority)) => {
            ensure_non_empty(collateral, "public_settlement.collateral_position_ref")?;
            ensure_non_empty(guarantee, "public_settlement.guarantee_decision_ref")?;
            ensure_non_empty(remedy, "public_settlement.sla_remedy_ref")?;
            ensure_non_empty(slash_authority, "public_settlement.slash_authority_ref")?;
            Ok(Some(PublicSettlementTrustMarketContext {
                collateral_position_ref: collateral.to_string(),
                guarantee_decision_ref: guarantee.to_string(),
                sla_remedy_ref: remedy.to_string(),
                slash_authority_ref: slash_authority.to_string(),
            }))
        }
        _ => Err(Web3ContractError::InvalidProof(
            "public settlement trust-market refs incomplete".to_string(),
        )),
    }
}

fn validate_expected_trust_market_context(
    actual: &Option<PublicSettlementTrustMarketContext>,
    trust: &PublicSettlementVerifierTrust,
) -> Result<bool, Web3ContractError> {
    match (actual, trust.expected_trust_market_context.as_ref()) {
        (None, None) | (Some(_), None) => Ok(false),
        (Some(actual), Some(expected)) if actual == expected => Ok(true),
        _ => Err(Web3ContractError::InvalidProof(
            "public settlement trust-market ref mismatch".to_string(),
        )),
    }
}

fn validate_public_settlement_trust(
    bundle: &PublicSettlementProofBundle,
    trust: &PublicSettlementVerifierTrust,
) -> Result<(), Web3ContractError> {
    require_trusted_public_settlement_key(
        "capital signer",
        &bundle
            .settlement_receipt
            .dispatch
            .capital_instruction
            .signer_key,
        &trust.trusted_capital_signer_keys,
    )?;

    let chain_anchor = required_chain_anchor(bundle)?;
    let anchor_proof = bundle
        .settlement_receipt
        .reconciled_anchor_proof
        .as_ref()
        .ok_or_else(|| {
            Web3ContractError::InvalidProof(
                "public settlement trust requires an anchor proof".to_string(),
            )
        })?;
    if chain_anchor.anchored_checkpoint_seq != anchor_proof.checkpoint_statement.checkpoint_seq {
        return Err(Web3ContractError::InvalidProof(
            "public settlement anchor checkpoint mismatch".to_string(),
        ));
    }
    require_trusted_public_settlement_key(
        "anchor kernel",
        &anchor_proof.checkpoint_statement.kernel_key,
        &trust.trusted_anchor_kernel_keys,
    )?;

    let beneficiary_binding = required_beneficiary_identity_binding(bundle)?;
    require_trusted_public_settlement_key(
        "beneficiary identity",
        &beneficiary_binding.certificate.chio_public_key,
        &trust.trusted_beneficiary_identity_keys,
    )
}

fn require_trusted_public_settlement_key(
    label: &'static str,
    key: &PublicKey,
    trusted_keys: &[PublicKey],
) -> Result<(), Web3ContractError> {
    if trusted_keys.is_empty() {
        return Err(Web3ContractError::InvalidProof(format!(
            "trusted public settlement {label} keys missing"
        )));
    }
    if trusted_keys.iter().any(|trusted_key| trusted_key == key) {
        Ok(())
    } else {
        Err(Web3ContractError::InvalidProof(format!(
            "public settlement {label} key is not trusted"
        )))
    }
}

fn validate_public_settlement_verifier_policy(
    bundle: &PublicSettlementProofBundle,
    trust: &PublicSettlementVerifierTrust,
) -> Result<(), Web3ContractError> {
    if trust.allowed_chain_ids.is_empty() {
        return Err(Web3ContractError::InvalidProof(
            "public settlement verifier chain allow-list missing".to_string(),
        ));
    }
    if !trust
        .allowed_chain_ids
        .iter()
        .any(|chain_id| chain_id == &bundle.chain_id)
    {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement chain id is not allowed".to_string(),
        ));
    }
    if trust.mainnet_blocked && public_settlement_chain_is_mainnet(&bundle.chain_id) {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement mainnet chain is blocked by verifier policy".to_string(),
        ));
    }
    if let Some(minimum_confirmations) = trust.minimum_confirmations {
        if bundle.required_confirmations < minimum_confirmations {
            return Err(Web3ContractError::InvalidProof(
                "public settlement verifier minimum confirmations not met".to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn public_settlement_chain_is_mainnet(chain_id: &str) -> bool {
    matches!(
        chain_id,
        "eip155:1"
            | "eip155:10"
            | "eip155:56"
            | "eip155:137"
            | "eip155:324"
            | "eip155:8453"
            | "eip155:42161"
            | "eip155:43114"
            | "eip155:59144"
    )
}

/// Whether `chain_id` is a KNOWN public testnet. This is a positive allow-list,
/// not the inverse of [`public_settlement_chain_is_mainnet`]: an unknown or
/// unverified chain is NOT a testnet here, so a testnet-gated path that requires
/// this predicate fails closed for any chain the protocol cannot positively
/// confirm is a testnet (the mainnet deny-list alone is partial and would let an
/// unenumerated mainnet through).
pub(crate) fn public_settlement_chain_is_testnet(chain_id: &str) -> bool {
    matches!(
        chain_id,
        // Ethereum testnets.
        "eip155:11155111"   // Sepolia
            | "eip155:17000"    // Holesky
            // Base / OP-stack testnets.
            | "eip155:84532"    // Base Sepolia
            | "eip155:11155420" // OP Sepolia
            // Arbitrum testnet.
            | "eip155:421614"   // Arbitrum Sepolia
            // Polygon testnet.
            | "eip155:80002"    // Polygon Amoy
            // Avalanche testnet.
            | "eip155:43113"    // Fuji
            // BNB Smart Chain testnet.
            | "eip155:97"       // BSC testnet
            // zkSync Era testnet.
            | "eip155:300"      // zkSync Sepolia
            // Linea testnet.
            | "eip155:59141"    // Linea Sepolia
            // Scroll testnet.
            | "eip155:534351" // Scroll Sepolia
    )
}

fn validate_bundle_header(bundle: &PublicSettlementProofBundle) -> Result<(), Web3ContractError> {
    if bundle.schema != CHIO_WEB3_SETTLEMENT_PROOF_BUNDLE_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(bundle.schema.clone()));
    }
    ensure_non_empty(&bundle.bundle_id, "public_settlement.bundle_id")?;
    ensure_non_empty(
        &bundle.transaction_passport_id,
        "public_settlement.transaction_passport_id",
    )?;
    ensure_non_empty(
        &bundle.commerce_order_id,
        "public_settlement.commerce_order_id",
    )?;
    ensure_non_empty(&bundle.chain_id, "public_settlement.chain_id")?;
    if bundle.required_confirmations == 0 {
        return Err(Web3ContractError::InvalidProof(
            "public settlement proof requires a positive finality threshold".to_string(),
        ));
    }
    Ok(())
}

fn validate_chain_binding(bundle: &PublicSettlementProofBundle) -> Result<(), Web3ContractError> {
    if bundle.settlement_receipt.dispatch.chain_id != bundle.chain_id {
        return Err(Web3ContractError::InvalidSettlement(
            "settlement chain id mismatch".to_string(),
        ));
    }
    Ok(())
}

fn validate_chain_snapshot(bundle: &PublicSettlementProofBundle) -> Result<(), Web3ContractError> {
    let snapshot = &bundle.chain_snapshot;
    ensure_non_empty(
        &snapshot.chain_id,
        "public_settlement.chain_snapshot.chain_id",
    )?;
    ensure_non_empty(
        &snapshot.root_registry_address,
        "public_settlement.chain_snapshot.root_registry_address",
    )?;
    ensure_non_empty(
        &snapshot.registry_root,
        "public_settlement.chain_snapshot.registry_root",
    )?;
    if snapshot.chain_id != bundle.chain_id {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement chain snapshot chain id mismatch".to_string(),
        ));
    }
    if snapshot.max_block_lag == 0 {
        return Err(Web3ContractError::InvalidProof(
            "public settlement chain snapshot max_block_lag must be non-zero".to_string(),
        ));
    }
    if snapshot.latest_block_number < snapshot.observed_block_number {
        return Err(Web3ContractError::InvalidProof(
            "public settlement chain snapshot latest block precedes observed block".to_string(),
        ));
    }
    if snapshot.latest_block_number - snapshot.observed_block_number > snapshot.max_block_lag {
        return Err(Web3ContractError::InvalidProof(
            "public settlement chain snapshot is stale".to_string(),
        ));
    }

    let chain_anchor = required_chain_anchor(bundle)?;
    if snapshot.observed_block_number < chain_anchor.block_number {
        return Err(Web3ContractError::InvalidProof(
            "public settlement chain snapshot predates anchored settlement block".to_string(),
        ));
    }
    if snapshot.root_registry_address != chain_anchor.contract_address {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement root registry address mismatch".to_string(),
        ));
    }
    let registry_root = Hash::from_hex(&snapshot.registry_root)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    if registry_root != chain_anchor.anchored_merkle_root {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement registry root mismatch".to_string(),
        ));
    }

    validate_escrow_snapshot(bundle, &snapshot.escrow)?;
    validate_bond_snapshot(bundle, required_bond_snapshot(bundle)?)?;
    validate_block_snapshot(bundle, required_block_snapshot(bundle)?, chain_anchor)?;
    validate_beneficiary_identity_binding(bundle, required_beneficiary_identity_binding(bundle)?)?;
    Ok(())
}

fn validate_independent_chain_head(
    bundle: &PublicSettlementProofBundle,
    trust: &PublicSettlementVerifierTrust,
) -> Result<(), Web3ContractError> {
    let Some(head) = &trust.independent_chain_head else {
        return Ok(());
    };
    ensure_non_empty(
        &head.chain_id,
        "public_settlement.independent_head.chain_id",
    )?;
    ensure_non_empty(
        &head.observed_block_hash,
        "public_settlement.independent_head.observed_block_hash",
    )?;
    Hash::from_hex(&head.observed_block_hash)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    if head.chain_id != bundle.chain_id {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement independent head chain id mismatch".to_string(),
        ));
    }
    if head.observed_block_number != bundle.chain_snapshot.observed_block_number {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement independent head observed block mismatch".to_string(),
        ));
    }
    let block = required_block_snapshot(bundle)?;
    if head.observed_block_hash != block.block_hash {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement independent head block hash mismatch".to_string(),
        ));
    }
    if head.latest_block_number < head.observed_block_number {
        return Err(Web3ContractError::InvalidProof(
            "public settlement independent head precedes observed block".to_string(),
        ));
    }
    let independent_confirmations = head
        .latest_block_number
        .saturating_sub(head.observed_block_number)
        .saturating_add(1);
    if independent_confirmations < u64::from(bundle.required_confirmations) {
        return Err(Web3ContractError::InvalidProof(
            "public settlement independent head finality below threshold".to_string(),
        ));
    }
    if u64::from(bundle.observed_confirmations) > independent_confirmations {
        return Err(Web3ContractError::InvalidProof(
            "public settlement observed confirmations exceed independent head".to_string(),
        ));
    }
    Ok(())
}

fn required_chain_anchor(
    bundle: &PublicSettlementProofBundle,
) -> Result<&crate::anchors::Web3ChainAnchorRecord, Web3ContractError> {
    bundle
        .settlement_receipt
        .reconciled_anchor_proof
        .as_ref()
        .and_then(|proof| proof.chain_anchor.as_ref())
        .ok_or_else(|| {
            Web3ContractError::InvalidProof(
                "public settlement chain snapshot requires a chain anchor".to_string(),
            )
        })
}

fn required_bond_snapshot(
    bundle: &PublicSettlementProofBundle,
) -> Result<&PublicSettlementBondSnapshot, Web3ContractError> {
    bundle.chain_snapshot.bond.as_ref().ok_or_else(|| {
        Web3ContractError::InvalidProof("public settlement bond snapshot missing".to_string())
    })
}

fn required_block_snapshot(
    bundle: &PublicSettlementProofBundle,
) -> Result<&PublicSettlementBlockSnapshot, Web3ContractError> {
    bundle.chain_snapshot.block.as_ref().ok_or_else(|| {
        Web3ContractError::InvalidProof("public settlement block snapshot missing".to_string())
    })
}

fn required_beneficiary_identity_binding(
    bundle: &PublicSettlementProofBundle,
) -> Result<&SignedWeb3IdentityBinding, Web3ContractError> {
    bundle
        .chain_snapshot
        .beneficiary_identity_binding
        .as_ref()
        .ok_or_else(|| {
            Web3ContractError::InvalidProof(
                "public settlement beneficiary identity binding missing".to_string(),
            )
        })
}

fn required_dispute_snapshot(
    bundle: &PublicSettlementProofBundle,
) -> Result<&PublicSettlementDisputeSnapshot, Web3ContractError> {
    bundle.dispute_snapshot.as_ref().ok_or_else(|| {
        Web3ContractError::InvalidProof("public settlement dispute snapshot missing".to_string())
    })
}

fn validate_beneficiary_identity_binding(
    bundle: &PublicSettlementProofBundle,
    binding: &SignedWeb3IdentityBinding,
) -> Result<(), Web3ContractError> {
    verify_web3_identity_binding(binding)?;
    let certificate = &binding.certificate;
    if !certificate.purpose.contains(&Web3KeyBindingPurpose::Settle) {
        return Err(Web3ContractError::InvalidBinding(
            "public settlement beneficiary identity binding requires settle purpose".to_string(),
        ));
    }
    if !certificate
        .chain_scope
        .iter()
        .any(|chain_id| chain_id == &bundle.chain_id)
    {
        return Err(Web3ContractError::InvalidBinding(
            "public settlement beneficiary identity binding chain mismatch".to_string(),
        ));
    }
    if certificate.settlement_address != bundle.settlement_receipt.dispatch.beneficiary_address {
        return Err(Web3ContractError::InvalidBinding(
            "public settlement beneficiary identity binding address mismatch".to_string(),
        ));
    }
    let settlement_observed_at = bundle.settlement_receipt.observed_execution.observed_at;
    if certificate.issued_at > settlement_observed_at
        || certificate.expires_at <= settlement_observed_at
    {
        return Err(Web3ContractError::InvalidBinding(
            "public settlement beneficiary identity binding not valid at settlement time"
                .to_string(),
        ));
    }
    Ok(())
}

fn validate_escrow_snapshot(
    bundle: &PublicSettlementProofBundle,
    escrow: &PublicSettlementEscrowSnapshot,
) -> Result<(), Web3ContractError> {
    ensure_non_empty(
        &escrow.escrow_id,
        "public_settlement.chain_snapshot.escrow.escrow_id",
    )?;
    ensure_non_empty(
        &escrow.escrow_contract,
        "public_settlement.chain_snapshot.escrow.escrow_contract",
    )?;
    ensure_non_empty(
        &escrow.beneficiary_address,
        "public_settlement.chain_snapshot.escrow.beneficiary_address",
    )?;
    let dispatch = &bundle.settlement_receipt.dispatch;
    if escrow.escrow_id != dispatch.escrow_id {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement escrow id mismatch".to_string(),
        ));
    }
    if escrow.escrow_contract != dispatch.escrow_contract {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement escrow contract mismatch".to_string(),
        ));
    }
    if escrow.beneficiary_address != dispatch.beneficiary_address {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement escrow beneficiary mismatch".to_string(),
        ));
    }
    if escrow.locked_amount.currency != dispatch.settlement_amount.currency
        || escrow.released_amount.currency != dispatch.settlement_amount.currency
    {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement escrow currency mismatch".to_string(),
        ));
    }
    if escrow.locked_amount.units < dispatch.settlement_amount.units {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement escrow balance below required amount".to_string(),
        ));
    }
    if escrow.released_amount.units != bundle.settlement_receipt.settled_amount.units {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement escrow released amount mismatch".to_string(),
        ));
    }
    Ok(())
}

fn validate_bond_snapshot(
    bundle: &PublicSettlementProofBundle,
    bond: &PublicSettlementBondSnapshot,
) -> Result<(), Web3ContractError> {
    ensure_non_empty(
        &bond.bond_vault_contract,
        "public_settlement.chain_snapshot.bond.bond_vault_contract",
    )?;
    ensure_money(
        &bond.posted_amount,
        "public_settlement.chain_snapshot.bond.posted_amount",
    )?;
    ensure_money(
        &bond.minimum_required_amount,
        "public_settlement.chain_snapshot.bond.minimum_required_amount",
    )?;

    let dispatch = &bundle.settlement_receipt.dispatch;
    if bond.bond_vault_contract != dispatch.bond_vault_contract {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement bond vault mismatch".to_string(),
        ));
    }
    if bond.posted_amount.currency != dispatch.settlement_amount.currency
        || bond.minimum_required_amount.currency != dispatch.settlement_amount.currency
    {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement bond currency mismatch".to_string(),
        ));
    }
    if bond.minimum_required_amount.units < dispatch.settlement_amount.units {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement bond minimum below settlement amount".to_string(),
        ));
    }
    if bond.posted_amount.units < bond.minimum_required_amount.units {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement bond below policy".to_string(),
        ));
    }
    Ok(())
}

fn validate_block_snapshot(
    bundle: &PublicSettlementProofBundle,
    block: &PublicSettlementBlockSnapshot,
    chain_anchor: &crate::anchors::Web3ChainAnchorRecord,
) -> Result<(), Web3ContractError> {
    ensure_non_empty(
        &block.block_hash,
        "public_settlement.chain_snapshot.block.block_hash",
    )?;
    if block.transaction_hashes.is_empty() {
        return Err(Web3ContractError::InvalidProof(
            "public settlement block snapshot transaction list is empty".to_string(),
        ));
    }
    Hash::from_hex(&block.block_hash)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    for transaction_hash in &block.transaction_hashes {
        ensure_non_empty(
            transaction_hash,
            "public_settlement.chain_snapshot.block.transaction_hashes",
        )?;
        Hash::from_hex(transaction_hash)
            .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    }
    if block.block_number != chain_anchor.block_number {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement block number mismatch".to_string(),
        ));
    }
    if block.block_hash != chain_anchor.block_hash {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement block hash mismatch".to_string(),
        ));
    }
    if !block
        .transaction_hashes
        .iter()
        .any(|tx_hash| tx_hash == &chain_anchor.tx_hash)
    {
        return Err(Web3ContractError::InvalidProof(
            "public settlement anchor tx hash missing from block".to_string(),
        ));
    }
    let settlement_tx_hash = &bundle
        .settlement_receipt
        .observed_execution
        .external_reference_id;
    if !block
        .transaction_hashes
        .iter()
        .any(|tx_hash| tx_hash == settlement_tx_hash)
    {
        return Err(Web3ContractError::InvalidProof(
            "public settlement tx hash not included in block".to_string(),
        ));
    }
    Ok(())
}

fn validate_order_binding(bundle: &PublicSettlementProofBundle) -> Result<(), Web3ContractError> {
    validate_order_binding_tuple(bundle)?;

    let mut has_order_ref = false;
    for evidence_ref in &bundle
        .settlement_receipt
        .dispatch
        .capital_instruction
        .body
        .evidence_refs
    {
        if evidence_ref.kind != CapitalBookEvidenceKind::CommerceOrder {
            continue;
        }
        has_order_ref = true;
        if evidence_ref.reference_id != bundle.commerce_order_id {
            return Err(Web3ContractError::InvalidSettlement(
                "public settlement commerce order evidence mismatch".to_string(),
            ));
        }
    }

    if !has_order_ref {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement commerce order evidence missing".to_string(),
        ));
    }
    Ok(())
}

fn validate_order_binding_tuple(
    bundle: &PublicSettlementProofBundle,
) -> Result<(), Web3ContractError> {
    let binding = &bundle.order_binding;
    for (field, value) in [
        (
            "public_settlement.order_binding.transaction_passport_id",
            &binding.transaction_passport_id,
        ),
        (
            "public_settlement.order_binding.commerce_order_id",
            &binding.commerce_order_id,
        ),
        (
            "public_settlement.order_binding.chain_id",
            &binding.chain_id,
        ),
        (
            "public_settlement.order_binding.settlement_reference",
            &binding.settlement_reference,
        ),
        (
            "public_settlement.order_binding.settlement_tx_hash",
            &binding.settlement_tx_hash,
        ),
        (
            "public_settlement.order_binding.beneficiary_address",
            &binding.beneficiary_address,
        ),
        (
            "public_settlement.order_binding.escrow_id",
            &binding.escrow_id,
        ),
    ] {
        ensure_non_empty(value, field)?;
    }
    ensure_money(
        &binding.settlement_amount,
        "public_settlement.order_binding.settlement_amount",
    )?;

    let dispatch = &bundle.settlement_receipt.dispatch;
    let observed = &bundle.settlement_receipt.observed_execution;
    if binding.transaction_passport_id != bundle.transaction_passport_id {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement order binding passport mismatch".to_string(),
        ));
    }
    if binding.commerce_order_id != bundle.commerce_order_id {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement order binding commerce order mismatch".to_string(),
        ));
    }
    if binding.chain_id != bundle.chain_id {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement order binding chain mismatch".to_string(),
        ));
    }
    if binding.settlement_reference != bundle.settlement_receipt.settlement_reference {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement order binding settlement reference mismatch".to_string(),
        ));
    }
    if binding.settlement_tx_hash != observed.external_reference_id {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement order binding settlement tx mismatch".to_string(),
        ));
    }
    if binding.beneficiary_address != dispatch.beneficiary_address {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement order binding beneficiary mismatch".to_string(),
        ));
    }
    if binding.escrow_id != dispatch.escrow_id {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement order binding escrow mismatch".to_string(),
        ));
    }
    if binding.settlement_amount != dispatch.settlement_amount {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement order binding amount mismatch".to_string(),
        ));
    }
    Ok(())
}

fn validate_finality(bundle: &PublicSettlementProofBundle) -> Result<(), Web3ContractError> {
    if bundle.observed_confirmations < bundle.required_confirmations {
        return Err(Web3ContractError::InvalidProof(
            "settlement finality below threshold".to_string(),
        ));
    }
    let snapshot_confirmations = bundle
        .chain_snapshot
        .latest_block_number
        .saturating_sub(bundle.chain_snapshot.observed_block_number)
        .saturating_add(1);
    if u64::from(bundle.observed_confirmations) > snapshot_confirmations {
        return Err(Web3ContractError::InvalidProof(
            "public settlement observed confirmations exceed chain snapshot".to_string(),
        ));
    }
    Ok(())
}

fn validate_dispute_posture(bundle: &PublicSettlementProofBundle) -> Result<(), Web3ContractError> {
    let dispute = required_dispute_snapshot(bundle)?;
    validate_dispute_snapshot(bundle, dispute)?;
    if dispute.open_dispute_count > 0 {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement active dispute blocks finality".to_string(),
        ));
    }
    match bundle.dispute_posture {
        PublicSettlementDisputePosture::Refunded
            if !matches!(
                bundle.settlement_receipt.lifecycle_state,
                Web3SettlementLifecycleState::Reversed | Web3SettlementLifecycleState::TimedOut
            ) =>
        {
            Err(Web3ContractError::InvalidSettlement(
                "refunded dispute posture requires reversed or timed out settlement".to_string(),
            ))
        }
        PublicSettlementDisputePosture::Slashed
            if !matches!(
                bundle.settlement_receipt.lifecycle_state,
                Web3SettlementLifecycleState::ChargedBack | Web3SettlementLifecycleState::Reversed
            ) =>
        {
            Err(Web3ContractError::InvalidSettlement(
                "slashed dispute posture requires charged back or reversed settlement".to_string(),
            ))
        }
        _ => Ok(()),
    }
}

fn validate_finality_settlement_state(
    bundle: &PublicSettlementProofBundle,
) -> Result<(), Web3ContractError> {
    if matches!(
        bundle.settlement_receipt.lifecycle_state,
        Web3SettlementLifecycleState::Failed | Web3SettlementLifecycleState::Reorged
    ) {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement finality requires successful settlement state".to_string(),
        ));
    }
    Ok(())
}

fn active_dispute_posture(posture: PublicSettlementDisputePosture) -> bool {
    matches!(
        posture,
        PublicSettlementDisputePosture::Challenged
            | PublicSettlementDisputePosture::Bonded
            | PublicSettlementDisputePosture::Appealed
    )
}

fn finality_report_status(bundle: &PublicSettlementProofBundle) -> &'static str {
    match bundle.settlement_receipt.lifecycle_state {
        Web3SettlementLifecycleState::Settled => match bundle.dispute_posture {
            PublicSettlementDisputePosture::Closed => "closed",
            _ => "final",
        },
        Web3SettlementLifecycleState::PartiallySettled => "partially_settled",
        Web3SettlementLifecycleState::Reversed => match bundle.dispute_posture {
            PublicSettlementDisputePosture::Refunded => "refunded",
            PublicSettlementDisputePosture::Slashed => "slashed",
            _ => "reversed",
        },
        Web3SettlementLifecycleState::ChargedBack => match bundle.dispute_posture {
            PublicSettlementDisputePosture::Slashed => "slashed",
            _ => "charged_back",
        },
        Web3SettlementLifecycleState::TimedOut => match bundle.dispute_posture {
            PublicSettlementDisputePosture::Refunded => "refunded",
            _ => "timed_out",
        },
        Web3SettlementLifecycleState::Failed => "failed",
        Web3SettlementLifecycleState::Reorged => "reorged",
        Web3SettlementLifecycleState::PendingDispatch
        | Web3SettlementLifecycleState::EscrowLocked => "not_final",
    }
}

/// The status the verifier report emits when a finality status that WOULD assert
/// grounded finality is not independently grounded (no `independent_chain_head`).
pub(crate) const FINALITY_STATUS_UNGROUNDED: &str = "ungrounded";

/// The finality statuses that affirmatively assert the settlement is final and
/// confirmed on chain. These derive from the `Settled` lifecycle state and may be
/// reported ONLY when an INDEPENDENT chain head grounds the confirmation depth
/// (RPI-1). The remaining statuses (`partially_settled`, the reversal/dispute
/// outcomes, and `not_final`) are NOT affirmative-finality assertions, so they are
/// never downgraded.
const GROUNDED_FINALITY_STATUSES: &[&str] = &["final", "closed"];

/// The report's finality status, downgraded fail-closed when finality is not
/// independently grounded.
///
/// When `independent_head_present` is false the verifier cannot vouch for the
/// confirmation depth (it is producer-supplied and unsigned), so any status that
/// would AFFIRM grounded finality is replaced with [`FINALITY_STATUS_UNGROUNDED`].
/// This keeps the STATUS field from asserting grounded finality on its own, so a
/// consumer that keys off the status (rather than the withheld `finality_verified`
/// claim) can never accept ungrounded finality. Non-final outcomes pass through.
fn grounded_finality_report_status(
    bundle: &PublicSettlementProofBundle,
    independent_head_present: bool,
) -> &'static str {
    let status = finality_report_status(bundle);
    if !independent_head_present && GROUNDED_FINALITY_STATUSES.contains(&status) {
        return FINALITY_STATUS_UNGROUNDED;
    }
    status
}

fn validate_dispute_snapshot(
    bundle: &PublicSettlementProofBundle,
    dispute: &PublicSettlementDisputeSnapshot,
) -> Result<(), Web3ContractError> {
    if dispute.schema != CHIO_WEB3_SETTLEMENT_DISPUTE_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(dispute.schema.clone()));
    }
    ensure_non_empty(&dispute.dispute_id, "public_settlement.dispute.dispute_id")?;
    if dispute.posture != bundle.dispute_posture {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement dispute posture mismatch".to_string(),
        ));
    }
    if dispute.challenge_window_secs == 0 {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute challenge window missing".to_string(),
        ));
    }
    let Some(expected_window_close) = bundle
        .settlement_receipt
        .observed_execution
        .observed_at
        .checked_add(dispute.challenge_window_secs)
    else {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute window overflow".to_string(),
        ));
    };
    if dispute.window_closed_at < expected_window_close {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute window closes before challenge period".to_string(),
        ));
    }
    if dispute.observed_at < dispute.window_closed_at {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute snapshot before challenge window close".to_string(),
        ));
    }
    for receipt_id in &dispute.linked_receipt_ids {
        ensure_non_empty(receipt_id, "public_settlement.dispute.linked_receipt_ids")?;
    }
    if dispute.posture != PublicSettlementDisputePosture::Undisputed
        && !dispute
            .linked_receipt_ids
            .iter()
            .any(|receipt_id| receipt_id == &bundle.settlement_receipt.execution_receipt_id)
    {
        return Err(Web3ContractError::InvalidProof(
            "public settlement dispute not linked to settlement receipt".to_string(),
        ));
    }
    let block = required_block_snapshot(bundle)?;
    for tx_hash in &dispute.chain_event_tx_hashes {
        ensure_non_empty(tx_hash, "public_settlement.dispute.chain_event_tx_hashes")?;
        Hash::from_hex(tx_hash)
            .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
        if !block
            .transaction_hashes
            .iter()
            .any(|block_tx_hash| block_tx_hash == tx_hash)
        {
            return Err(Web3ContractError::InvalidProof(
                "public settlement dispute event tx hash not included in block".to_string(),
            ));
        }
    }
    if dispute.posture == PublicSettlementDisputePosture::Undisputed
        && dispute.open_dispute_count != 0
    {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement open dispute count mismatch".to_string(),
        ));
    }
    if active_dispute_posture(dispute.posture) && dispute.open_dispute_count == 0 {
        return Err(Web3ContractError::InvalidSettlement(
            "public settlement active dispute missing".to_string(),
        ));
    }
    Ok(())
}

fn settlement_state_id(state: Web3SettlementLifecycleState) -> &'static str {
    match state {
        Web3SettlementLifecycleState::PendingDispatch => "pending_dispatch",
        Web3SettlementLifecycleState::EscrowLocked => "escrow_locked",
        Web3SettlementLifecycleState::PartiallySettled => "partially_settled",
        Web3SettlementLifecycleState::Settled => "settled",
        Web3SettlementLifecycleState::Reversed => "reversed",
        Web3SettlementLifecycleState::ChargedBack => "charged_back",
        Web3SettlementLifecycleState::TimedOut => "timed_out",
        Web3SettlementLifecycleState::Failed => "failed",
        Web3SettlementLifecycleState::Reorged => "reorged",
    }
}

fn push_claim_once(target: &mut Vec<String>, claim: &str) {
    if !target.iter().any(|existing| existing == claim) {
        target.push(claim.to_string());
    }
}
