//! Custody-neutral, prepare-only x402 settlement attestation signing (M2-14,
//! WS-CL-X402-VERIFY).
//!
//! This is the signing leg of the x402 verify workstream. Chio SIGNS a
//! settlement/anchor attestation with its kernel key: the kernel key attests
//! that the public settlement proof recomputes (recompute is the SOLE proof
//! lane, see [`crate::settlement_proof::verify_public_settlement_proof`]). The
//! path is CUSTODY-NEUTRAL: Chio never holds or moves user value, and the
//! signed attestation carries NO authority to move value or to authorize a
//! tool call. It only records that the proof verified.
//!
//! The path is PREPARE-ONLY and TESTNET-GATED:
//!
//! - The attestation explicitly carries `value_moved_on_chain = false`: signing
//!   the proof never moves value on chain.
//! - The live money-movement leg (the CDP leg, M2-16) is OUT of scope and
//!   entry-gated; it is never carried here. The prepare-only broadcast intent
//!   records only that this leg is blocked.
//! - Signing is rejected fail-closed for any mainnet or non-allow-listed chain
//!   (`mainnet_blocked` and `allowed_chain_ids` are enforced).
//!
//! Value-movement authority and tool-call authority are fail-closed BY
//! CONSTRUCTION, composing with M2-12's [`ToolCallAuthorization`]: there is no
//! constructor in this module that yields an authorized decision, so a
//! custody-neutral attestation can only ever produce DENY.

use serde::{Deserialize, Serialize};

use crate::canonical::canonical_json_bytes;
use crate::crypto::{sha256_hex, Keypair, PublicKey, Signature};
use crate::error::Web3ContractError;
use crate::settlement_proof::{
    public_settlement_chain_is_mainnet, public_settlement_chain_is_testnet,
    verify_public_settlement_proof, PublicSettlementProofBundle, PublicSettlementVerifierTrust,
    ToolCallAuthorization,
};
use crate::validation::ensure_non_empty;

pub const CHIO_X402_SETTLEMENT_ATTESTATION_SCHEMA: &str = "chio.x402-settlement-attestation.v1";
pub const CHIO_X402_PREPARE_ONLY_BROADCAST_INTENT_SCHEMA: &str =
    "chio.x402-prepare-only-broadcast-intent.v1";

/// The custody model an x402 settlement attestation can carry.
///
/// There is exactly one representable variant: the path is custody-neutral by
/// construction. Chio's kernel key only attests that the settlement proof
/// recomputes; it never holds or moves user value. The money movement is the
/// external partner/CDP leg (M2-16), which is out of scope here and blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum X402CustodyModel {
    #[default]
    CustodyNeutral,
}

/// Where the live money-movement leg sits relative to this path.
///
/// The only representable state is "out of scope, blocked, pending partner":
/// the live CDP money-movement leg is M2-16 and is entry-gated. This path never
/// carries an executable money-movement instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum X402LiveMoneyMovementLeg {
    #[default]
    OutOfScopeBlockedPendingPartner,
}

/// A value-movement authorization decision for the x402 path.
///
/// Fail-closed BY CONSTRUCTION, mirroring M2-12's [`ToolCallAuthorization`].
/// It carries a single private flag and there is deliberately NO constructor in
/// this module that yields an authorized decision: there is no `From`/`Into`,
/// no `Deserialize`, and no path from a signed attestation to an authorized
/// value-movement decision. Signing a proof attests it; it never authorizes
/// value to move. The live money-movement leg (M2-16) is the only thing that
/// could authorize value movement, and it is out of scope and blocked here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ValueMovementAuthorization {
    /// Private by design: `false` (DENY). No reachable code path sets it true.
    authorized: bool,
}

impl ValueMovementAuthorization {
    /// The fail-closed default: value movement is NOT authorized.
    #[must_use]
    pub const fn denied() -> Self {
        Self { authorized: false }
    }

    /// Whether this decision authorizes value movement. Always `false`.
    #[must_use]
    pub const fn is_authorized(&self) -> bool {
        self.authorized
    }
}

/// The canonical, kernel-signed body of an x402 settlement attestation.
///
/// Every field is recompute-bound: the settlement fields are taken from the
/// [`crate::settlement_proof::PublicSettlementVerifierReport`] produced by the
/// recompute lane, and the
/// `verifier_report_digest` binds the attestation to that exact report. The
/// custody-neutral, prepare-only, testnet-gated posture is signed into the
/// body: `value_moved_on_chain` is always `false`, `prepare_only` and
/// `testnet_gated` are always `true`, and `custody_model` is always
/// `CustodyNeutral`. There is no authority field of any kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402SettlementAttestationBody {
    pub schema: String,
    pub attestation_id: String,
    pub bundle_id: String,
    pub transaction_passport_id: String,
    pub commerce_order_id: String,
    pub chain_id: String,
    pub settlement_reference: String,
    pub settlement_tx_hash: String,
    pub anchor_tx_hash: String,
    pub registry_root: String,
    pub recomputed_settlement_state: String,
    pub verifier_report_digest: String,
    pub custody_model: X402CustodyModel,
    pub value_moved_on_chain: bool,
    pub prepare_only: bool,
    pub testnet_gated: bool,
    pub issued_at: u64,
    pub attesting_kernel_key: PublicKey,
}

/// A Chio-signed x402 settlement attestation: the kernel-signed body plus the
/// kernel signature over its canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402SignedSettlementAttestation {
    pub body: X402SettlementAttestationBody,
    pub signature: Signature,
}

impl X402SignedSettlementAttestation {
    /// Whether this attestation moved value on chain. Always `false`: the path
    /// is prepare-only and custody-neutral.
    #[must_use]
    pub const fn value_moved_on_chain(&self) -> bool {
        self.body.value_moved_on_chain
    }

    /// The value-movement authorization carried by this attestation: always
    /// [`ValueMovementAuthorization::denied`].
    ///
    /// This is STRUCTURAL, not a runtime check. The body returns the fail-closed
    /// DENY decision without reading any field, so no value of any field can
    /// flip it. Attesting a settlement proof proves the payment settled and the
    /// evidence recomputes; it grants no authority to move value. The live
    /// money-movement leg (M2-16) is the only authority for value movement and
    /// is out of scope and blocked here.
    #[must_use]
    pub const fn value_movement_authorization(&self) -> ValueMovementAuthorization {
        ValueMovementAuthorization::denied()
    }

    /// Convenience guard: `false` for every attestation, by construction.
    #[must_use]
    pub const fn authorizes_value_movement(&self) -> bool {
        self.value_movement_authorization().is_authorized()
    }

    /// The tool-call authorization carried by this attestation: always
    /// [`ToolCallAuthorization::denied`] (composes with M2-12).
    #[must_use]
    pub const fn tool_call_authorization(&self) -> ToolCallAuthorization {
        ToolCallAuthorization::denied()
    }

    /// Convenience guard: `false` for every attestation, by construction.
    #[must_use]
    pub const fn authorizes_tool_call(&self) -> bool {
        self.tool_call_authorization().is_authorized()
    }
}

/// The prepare-only broadcast intent for a custody-neutral x402 attestation.
///
/// This is NOT a broadcastable transaction: it explicitly records that no value
/// moves on chain (`value_moved_on_chain = false`), that the path is
/// prepare-only and testnet-gated, and that the live money-movement leg (M2-16)
/// is out of scope and blocked. It binds to the attestation by id and digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402PrepareOnlyBroadcastIntent {
    pub schema: String,
    pub intent_id: String,
    pub chain_id: String,
    pub attestation_id: String,
    pub attestation_digest: String,
    pub settlement_reference: String,
    pub value_moved_on_chain: bool,
    pub prepare_only: bool,
    pub testnet_gated: bool,
    pub live_money_movement_leg: X402LiveMoneyMovementLeg,
    pub issued_at: u64,
}

impl X402PrepareOnlyBroadcastIntent {
    /// Whether acting on this intent would move value on chain. Always `false`.
    #[must_use]
    pub const fn would_move_value(&self) -> bool {
        self.value_moved_on_chain
    }
}

/// Enforce the prepare-only x402 testnet gate, fail-closed.
///
/// The path may only sign for an explicitly allow-listed chain that is a KNOWN
/// public testnet on a verifier policy that blocks mainnet. Rejects when the
/// policy does not block mainnet, when the allow-list is empty, when the chain
/// is not allow-listed, when the chain is a known mainnet, OR when the chain is
/// not a positively-known testnet.
///
/// The positive known-testnet requirement is the load-bearing fail-closed
/// control: it does NOT rely on the (partial) mainnet deny-list, so an
/// allow-listed chain that the mainnet detector does not enumerate (an unknown
/// or unverified chain, including an unenumerated mainnet such as `eip155:100`)
/// is rejected here rather than being signed for.
fn enforce_x402_prepare_only_testnet_gate(
    chain_id: &str,
    trust: &PublicSettlementVerifierTrust,
) -> Result<(), Web3ContractError> {
    if !trust.mainnet_blocked {
        return Err(Web3ContractError::InvalidProof(
            "x402 prepare-only signing requires a mainnet-blocked verifier policy".to_string(),
        ));
    }
    if trust.allowed_chain_ids.is_empty() {
        return Err(Web3ContractError::InvalidProof(
            "x402 prepare-only signing requires a chain allow-list".to_string(),
        ));
    }
    if !trust
        .allowed_chain_ids
        .iter()
        .any(|allowed| allowed == chain_id)
    {
        return Err(Web3ContractError::InvalidSettlement(
            "x402 prepare-only chain id is not allowed".to_string(),
        ));
    }
    if public_settlement_chain_is_mainnet(chain_id) {
        return Err(Web3ContractError::InvalidSettlement(
            "x402 prepare-only signing is testnet-gated; mainnet chain rejected".to_string(),
        ));
    }
    // Fail closed on anything the protocol cannot positively confirm is a
    // testnet. Relying only on the mainnet deny-list would let an allow-listed
    // chain the detector misses (an unknown/unverified chain) be signed for.
    if !public_settlement_chain_is_testnet(chain_id) {
        return Err(Web3ContractError::InvalidSettlement(
            "x402 prepare-only signing is testnet-gated; only known testnets are allowed"
                .to_string(),
        ));
    }
    Ok(())
}

fn require_trusted_attesting_kernel_key(
    key: &PublicKey,
    trusted_keys: &[PublicKey],
) -> Result<(), Web3ContractError> {
    if trusted_keys.is_empty() {
        return Err(Web3ContractError::InvalidProof(
            "x402 settlement attestation trusted kernel keys missing".to_string(),
        ));
    }
    if trusted_keys.iter().any(|trusted_key| trusted_key == key) {
        Ok(())
    } else {
        Err(Web3ContractError::InvalidProof(
            "x402 settlement attestation kernel key is not trusted".to_string(),
        ))
    }
}

fn x402_canonical_digest<T: Serialize>(
    value: &T,
    label: &str,
) -> Result<String, Web3ContractError> {
    let canonical = canonical_json_bytes(value).map_err(|error| {
        Web3ContractError::InvalidProof(format!("{label} canonicalization failed: {error}"))
    })?;
    Ok(sha256_hex(&canonical))
}

/// Produce a Chio-signed, custody-neutral, prepare-only x402 settlement
/// attestation.
///
/// Recompute is the SOLE proof lane: the bundle is re-verified through
/// [`verify_public_settlement_proof`] and the attestation binds only the
/// recomputed [`crate::settlement_proof::PublicSettlementVerifierReport`]. The
/// path is testnet-gated
/// fail-closed (mainnet and non-allow-listed chains are rejected before and
/// after recompute) and value-neutral: the signed body carries
/// `value_moved_on_chain = false` and no authority to move value or authorize a
/// tool call. NO value moves on chain.
///
/// # Errors
///
/// Returns [`Web3ContractError`] when `attestation_id` is empty, when the chain
/// fails the prepare-only testnet gate, when the settlement proof fails the
/// recompute lane, or when canonical signing fails.
pub fn sign_x402_settlement_attestation(
    bundle: &PublicSettlementProofBundle,
    trust: &PublicSettlementVerifierTrust,
    kernel_keypair: &Keypair,
    attestation_id: &str,
    issued_at: u64,
) -> Result<X402SignedSettlementAttestation, Web3ContractError> {
    ensure_non_empty(attestation_id, "x402_settlement_attestation.attestation_id")?;
    // Testnet gate FIRST, fail-closed: this path never signs for mainnet or for
    // a chain outside the allow-list, regardless of the proof contents.
    enforce_x402_prepare_only_testnet_gate(&bundle.chain_id, trust)?;
    // Recompute is the SOLE proof lane: re-verify before attesting anything.
    let report = verify_public_settlement_proof(bundle, trust)?;
    // Defense in depth: the recomputed chain id must remain testnet-gated.
    enforce_x402_prepare_only_testnet_gate(&report.chain_context.chain_id, trust)?;

    let verifier_report_digest = x402_canonical_digest(&report, "x402 settlement verifier report")?;
    let body = X402SettlementAttestationBody {
        schema: CHIO_X402_SETTLEMENT_ATTESTATION_SCHEMA.to_string(),
        attestation_id: attestation_id.to_string(),
        bundle_id: report.bundle_id.clone(),
        transaction_passport_id: report.transaction_passport_id.clone(),
        commerce_order_id: report.commerce_order_id.clone(),
        chain_id: report.chain_context.chain_id.clone(),
        settlement_reference: report.chain_context.settlement_reference.clone(),
        settlement_tx_hash: report.chain_context.settlement_tx_hash.clone(),
        anchor_tx_hash: report.chain_context.anchor_tx_hash.clone(),
        registry_root: report.chain_context.registry_root.clone(),
        recomputed_settlement_state: report.recomputed_settlement_state.clone(),
        verifier_report_digest,
        // Custody-neutral, prepare-only, testnet-gated posture, signed in.
        custody_model: X402CustodyModel::CustodyNeutral,
        value_moved_on_chain: false,
        prepare_only: true,
        testnet_gated: true,
        issued_at,
        attesting_kernel_key: kernel_keypair.public_key(),
    };
    let (signature, _) = kernel_keypair.sign_canonical(&body).map_err(|error| {
        Web3ContractError::InvalidProof(format!(
            "x402 settlement attestation signing failed: {error}"
        ))
    })?;
    Ok(X402SignedSettlementAttestation { body, signature })
}

/// Verify a Chio-signed x402 settlement attestation.
///
/// Fail-closed on every axis: the custody-neutral, prepare-only, testnet-gated
/// invariants must hold (`value_moved_on_chain == false`, `prepare_only`,
/// `testnet_gated`, `custody_model == CustodyNeutral`), the chain must pass the
/// prepare-only testnet gate, the attesting key must be a trusted kernel key,
/// and the kernel signature must recompute over the canonical body.
///
/// # Errors
///
/// Returns [`Web3ContractError`] when the schema is unknown, when any
/// custody-neutral / prepare-only invariant is violated, when the chain fails
/// the testnet gate, when the attesting key is not trusted, or when the
/// signature fails to verify.
pub fn verify_x402_settlement_attestation(
    attestation: &X402SignedSettlementAttestation,
    trust: &PublicSettlementVerifierTrust,
) -> Result<(), Web3ContractError> {
    let body = &attestation.body;
    if body.schema != CHIO_X402_SETTLEMENT_ATTESTATION_SCHEMA {
        return Err(Web3ContractError::UnsupportedSchema(body.schema.clone()));
    }
    if body.custody_model != X402CustodyModel::CustodyNeutral {
        return Err(Web3ContractError::InvalidProof(
            "x402 settlement attestation must be custody-neutral".to_string(),
        ));
    }
    if body.value_moved_on_chain {
        return Err(Web3ContractError::InvalidProof(
            "x402 settlement attestation must not move value on chain".to_string(),
        ));
    }
    if !body.prepare_only {
        return Err(Web3ContractError::InvalidProof(
            "x402 settlement attestation must be prepare-only".to_string(),
        ));
    }
    if !body.testnet_gated {
        return Err(Web3ContractError::InvalidProof(
            "x402 settlement attestation must be testnet-gated".to_string(),
        ));
    }
    // Testnet gate, fail-closed: reject mainnet and non-allow-listed chains.
    enforce_x402_prepare_only_testnet_gate(&body.chain_id, trust)?;
    // The attesting key must be a trusted kernel key (custody-neutral: the
    // kernel key attests; it is the same key class that signs checkpoints).
    require_trusted_attesting_kernel_key(
        &body.attesting_kernel_key,
        &trust.trusted_anchor_kernel_keys,
    )?;
    // Recompute-and-check the signature over the canonical body.
    let verified = body
        .attesting_kernel_key
        .verify_canonical(body, &attestation.signature)
        .map_err(|error| Web3ContractError::InvalidProof(error.to_string()))?;
    if !verified {
        return Err(Web3ContractError::InvalidProof(
            "x402 settlement attestation signature verification failed".to_string(),
        ));
    }
    Ok(())
}

/// Produce the prepare-only broadcast intent for a verified x402 attestation.
///
/// The intent moves NO value: it records `value_moved_on_chain = false`, marks
/// the path prepare-only and testnet-gated, and records the live money-movement
/// leg as out of scope and blocked (M2-16). The attestation is re-verified
/// fail-closed before the intent is produced.
///
/// # Errors
///
/// Returns [`Web3ContractError`] when `intent_id` is empty, when the
/// attestation fails verification, or when digesting the attestation fails.
pub fn prepare_x402_broadcast_intent(
    attestation: &X402SignedSettlementAttestation,
    trust: &PublicSettlementVerifierTrust,
    intent_id: &str,
    issued_at: u64,
) -> Result<X402PrepareOnlyBroadcastIntent, Web3ContractError> {
    ensure_non_empty(intent_id, "x402_prepare_only_broadcast_intent.intent_id")?;
    // Re-verify: custody-neutral, prepare-only, and testnet-gated, fail-closed.
    verify_x402_settlement_attestation(attestation, trust)?;
    let body = &attestation.body;
    let attestation_digest = x402_canonical_digest(attestation, "x402 settlement attestation")?;
    Ok(X402PrepareOnlyBroadcastIntent {
        schema: CHIO_X402_PREPARE_ONLY_BROADCAST_INTENT_SCHEMA.to_string(),
        intent_id: intent_id.to_string(),
        chain_id: body.chain_id.clone(),
        attestation_id: body.attestation_id.clone(),
        attestation_digest,
        settlement_reference: body.settlement_reference.clone(),
        value_moved_on_chain: false,
        prepare_only: true,
        testnet_gated: true,
        live_money_movement_leg: X402LiveMoneyMovementLeg::OutOfScopeBlockedPendingPartner,
        issued_at,
    })
}
