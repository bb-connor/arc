use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Mutex;

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::SolValue;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedTransactionIntent,
};
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::PublicKey;
use chio_core::hashing::sha256;
use chio_core::web3::settlement::Web3SettlementDispatchArtifact;
use serde::{Deserialize, Serialize};

use crate::approval_witness::{
    parse_eip155_chain_id, parse_intent_settlement_binding, ApprovalReplayOutcome,
    ApprovalReplayStore, IntentSettlementBinding,
};
use crate::SettlementError;

/// Maximum lifetime (in seconds) permitted on a single governed approval
/// token at the settlement layer.
///
/// Mirrors `chio_kernel::MAX_APPROVAL_TTL_SECS`
/// (`crates/kernel/chio-kernel/src/approval.rs`): a token whose
/// `(expires_at - issued_at)` exceeds this cap is rejected so no token can
/// outlive the single-use replay registry's eviction window. The constant is
/// duplicated rather than imported because `chio-kernel` depends on
/// `chio-settle`, so a runtime dependency the other way would be a cycle; the
/// value is pinned to the kernel's documented HITL-protocol cap.
pub const MAX_APPROVAL_TTL_SECS: u64 = 3600;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum X402SettlementMode {
    PrepaidAuthorization,
    EscrowBacked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct X402PaymentRequirements {
    pub version: String,
    pub chain_id: String,
    pub facilitator_url: String,
    pub resource: String,
    pub pay_to: String,
    pub accepted_tokens: Vec<String>,
    pub dispatch_id: String,
    pub capability_id: String,
    pub amount_minor_units: u64,
    pub currency: String,
    pub settlement_mode: X402SettlementMode,
    pub governed_authorization_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Eip3009Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TransferWithAuthorizationInput {
    pub from_address: String,
    pub to_address: String,
    pub value_minor_units: u128,
    pub valid_after: u64,
    pub valid_before: u64,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedTransferWithAuthorization {
    pub domain: Eip3009Domain,
    pub authorization: TransferWithAuthorizationInput,
    pub domain_separator: String,
    pub struct_hash: String,
    pub authorization_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CircleNanopaymentPolicy {
    pub enabled: bool,
    pub managed_balance_id: String,
    pub supported_chain_ids: Vec<String>,
    pub supported_token_symbols: Vec<String>,
    pub max_amount_minor_units: u64,
    pub operator_managed_custody_explicit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedCircleNanopayment {
    pub payment_id: String,
    pub managed_balance_id: String,
    pub chain_id: String,
    pub amount_minor_units: u64,
    pub currency: String,
    pub beneficiary_address: String,
    pub dispatch_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Erc4337PaymasterPolicy {
    pub entry_point: String,
    pub paymaster_address: String,
    pub supported_chain_ids: Vec<String>,
    pub max_sponsor_gas_limit: u64,
    pub max_reimbursement_minor_units: u64,
    pub settlement_deduction_explicit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedPaymasterCompatibility {
    pub dispatch_id: String,
    pub chain_id: String,
    pub entry_point: String,
    pub paymaster_address: String,
    pub user_operation_hash: String,
    pub sponsor_gas_limit: u64,
    pub estimated_reimbursement_minor_units: u64,
    pub allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
}

/// Build the raw x402 payment requirements straight off a dispatch with NO
/// approval binding.
///
/// This is the legacy x402 preparation path. It is `pub(crate)` so downstream
/// cannot bypass the C2 (BAC-541) witness: the only exported x402 entry point
/// is [`build_x402_payment_requirements_with_verified_approval`], which
/// requires a [`VerifiedApproval`] and delegates here only after asserting the
/// live dispatch against the verified binding.
pub(crate) fn build_x402_payment_requirements(
    dispatch: &Web3SettlementDispatchArtifact,
    facilitator_url: &str,
    resource: &str,
    accepted_tokens: Vec<String>,
    settlement_mode: X402SettlementMode,
) -> Result<X402PaymentRequirements, SettlementError> {
    validate_x402_field("facilitator URL", facilitator_url)?;
    validate_x402_field("resource", resource)?;
    if accepted_tokens.is_empty() {
        return Err(SettlementError::InvalidInput(
            "x402 compatibility requires at least one accepted token".to_string(),
        ));
    }
    for (index, token) in accepted_tokens.iter().enumerate() {
        validate_x402_field(&format!("accepted token {index}"), token)?;
    }
    Ok(X402PaymentRequirements {
        version: "x402".to_string(),
        chain_id: dispatch.chain_id.clone(),
        facilitator_url: facilitator_url.to_string(),
        resource: resource.to_string(),
        pay_to: dispatch.beneficiary_address.clone(),
        accepted_tokens,
        dispatch_id: dispatch.dispatch_id.clone(),
        capability_id: resolve_x402_capability_id(dispatch),
        amount_minor_units: dispatch.settlement_amount.units,
        currency: dispatch.settlement_amount.currency.clone(),
        settlement_mode,
        governed_authorization_required: true,
    })
}

/// Resolve the `capability_id` the x402 requirements echo for `dispatch`.
///
/// The dispatch's capital instruction may carry an explicit `capability_id`;
/// when absent the `dispatch_id` stands in. Extracted so the witness wrapper
/// asserts the SAME resolved value against the approval-bound capability id
/// that the inner builder writes into the requirements, leaving no gap between
/// what is pinned and what is advertised.
fn resolve_x402_capability_id(dispatch: &Web3SettlementDispatchArtifact) -> String {
    dispatch
        .capital_instruction
        .body
        .query
        .capability_id
        .clone()
        .unwrap_or_else(|| dispatch.dispatch_id.clone())
}

/// Build x402 payment requirements bound to a verified governing approval
/// (C2 / BAC-541).
///
/// The x402 lane advertises `governed_authorization_required` as a bare
/// bool; on its own that flag is unenforced. This entry point closes the
/// loop: it asserts the live dispatch's chain / payee / amount against the
/// `approval.binding()` produced by [`verify_governed_approval`], so the
/// requirements can only be built when a real, verified
/// [`GovernedApprovalToken`] authorized exactly this spend. For the token, the
/// approval binds the on-chain RAIL token (the symbol the facilitator pulls,
/// for example `"USDC"`), which x402 keeps SEPARATE from the fiat
/// `settlement_amount.currency` (for example `"USD"`); the check therefore
/// requires the approval-bound token to appear in `accepted_tokens` and filters
/// that list down to it, rather than comparing it to the fiat settlement
/// currency. So x402 cannot offer to settle a governed spend in a rail token the
/// approval never authorized, while a normal Base/USDC spend whose fiat currency
/// is USD is still accepted. Any mismatch fails closed.
///
/// The numeric EIP-155 chain id the approval binds is derived from the
/// dispatch's namespaced `chain_id` string (e.g. `8453` for `"eip155:8453"`)
/// INSIDE the verifier via [`parse_eip155_chain_id`], so a caller cannot
/// supply a chain that disagrees with the dispatch. A dispatch whose chain
/// does not match the approval-bound chain fails closed.
///
/// The `VerifiedApproval` witness is CONSUMED by value: a single witness
/// authorizes a single lane use, so it cannot be reused to advertise multiple
/// sets of requirements. `now_unix_seconds` is the lane-use clock: the
/// approval's `approval_expires_at` is re-checked here, so a witness verified
/// just before expiry and held cannot authorize settlement artifacts built
/// after it lapses. The returned `accepted_tokens` are filtered down to the
/// approval-bound token, so the requirements never advertise a token the
/// approval did not authorize even if the caller passed extras.
///
/// The approval's single-use replay slot is consumed HERE, immediately
/// before the requirements are returned: `(request_id, intent_hash)` is
/// recorded into `replay_store`, so the first issued settlement artifact
/// wins across every lane sharing the store and a lane-level rejection never
/// burns the slot. A replayed approval fails closed.
// Every parameter is an independent fail-closed input to the lane (dispatch
// identity, facilitator/resource surface, token filter, mode, witness, lane
// clock, shared replay store); merging any pair would weaken a check.
#[allow(clippy::too_many_arguments)]
pub fn build_x402_payment_requirements_with_verified_approval(
    dispatch: &Web3SettlementDispatchArtifact,
    facilitator_url: &str,
    resource: &str,
    accepted_tokens: Vec<String>,
    settlement_mode: X402SettlementMode,
    approval: VerifiedApproval,
    now_unix_seconds: u64,
    replay_store: &dyn ApprovalReplayStore,
) -> Result<X402PaymentRequirements, SettlementError> {
    let binding = approval.binding();

    // Lane-use expiry: re-check the approval window against the lane-use clock.
    // The witness may have been verified just before expiry and held; an
    // approval that has lapsed by lane use must not authorize settlement.
    binding.assert_not_expired_at("x402", now_unix_seconds)?;

    // Chain: derive the numeric chain id from the dispatch itself and require
    // it to be the chain the approval authorized. The dispatch carries the
    // namespaced CAIP-2 string; the binding carries the bare numeric id.
    let dispatch_chain_id = parse_eip155_chain_id(&dispatch.chain_id)?;
    if dispatch_chain_id != binding.chain_id {
        return Err(SettlementError::InvalidBinding(format!(
            "x402 chain mismatch: dispatch chain {dispatch_chain_id} != approval-bound chain {}",
            binding.chain_id
        )));
    }

    // Payee: the dispatch beneficiary must be the approval-bound payee
    // (case-insensitive hex / checksum).
    let dispatch_payee =
        Address::from_str(dispatch.beneficiary_address.trim()).map_err(|error| {
            SettlementError::InvalidBinding(format!(
                "x402 dispatch beneficiary address invalid: {error}"
            ))
        })?;
    let bound_payee = Address::from_str(binding.payee_address.trim()).map_err(|error| {
        SettlementError::InvalidBinding(format!("approval-bound payee address invalid: {error}"))
    })?;
    if dispatch_payee != bound_payee {
        return Err(SettlementError::InvalidBinding(
            "x402 payee mismatch: dispatch beneficiary is not the approval-bound payee".to_string(),
        ));
    }

    // Amount: the dispatch settlement amount must equal the approval-bound
    // amount. The dispatch carries u64 minor units; widen to compare.
    if u128::from(dispatch.settlement_amount.units) != binding.amount_minor_units {
        return Err(SettlementError::InvalidBinding(format!(
            "x402 amount mismatch: dispatch amount {} != approval-bound amount {}",
            dispatch.settlement_amount.units, binding.amount_minor_units
        )));
    }

    // Dispatch identity: the requirements echo `dispatch.dispatch_id` and a
    // `capability_id` resolved from this dispatch. The approval economics alone
    // (chain / payee / amount / token) do NOT pin WHICH dispatch the witness may
    // settle, so without this a verified approval could be paired with a
    // DIFFERENT dispatch carrying the same economics and produce x402 artifacts
    // for that other dispatch. The witness gate signature-pins `dispatch_id` and
    // `capability_id`, so asserting the live dispatch's identity against them
    // ties the witness to the approved dispatch. Both must match; a dispatch
    // with the same economics but a different `dispatch_id` / `capability_id`
    // fails closed.
    binding.assert_dispatch_id("x402", &dispatch.dispatch_id)?;
    binding.assert_capability_id("x402", &resolve_x402_capability_id(dispatch))?;

    // Contract-pinned approvals cannot be honored by the symbol-only lane.
    // When the approver signed a concrete `token_contract`, the verifier proved
    // that exact contract was approved. The x402 lane identifies its token by
    // SYMBOL only (`accepted_tokens` carries no contract identity), so a
    // facilitator resolving that symbol to a DIFFERENT contract would settle an
    // unapproved token contract. Fail closed: a contract-pinned approval must be
    // honored by a contract-aware lane (EIP-3009), not by this symbol-only one.
    if binding.token_contract.is_some() {
        return Err(SettlementError::InvalidBinding(
            "x402 cannot honor a contract-pinned approval: the approval pins a token contract but \
             the x402 lane identifies its token by symbol only, so the resolved contract is \
             unverified"
                .to_string(),
        ));
    }

    // Token: x402 keeps the ACCEPTED (rail) token it settles in SEPARATE from
    // the fiat settlement currency. `dispatch.settlement_amount.currency` is the
    // fiat amount's currency (for example `"USD"`), while `accepted_tokens` is
    // the on-chain rail token the facilitator pulls (for example `"USDC"` /
    // `"EURC"`); see docs/standards/CHIO_X402_REQUIREMENTS_EXAMPLE.json. The
    // approval binds the RAIL token, so it must be compared to the accepted-token
    // list, NOT to the fiat settlement currency: asserting the bound token equals
    // the fiat currency would wrongly reject a normal Base/USDC spend whose fiat
    // settlement currency is USD. The fiat currency stays a separate amount field
    // on the requirements (carried through unchanged by the inner builder).
    //
    // The approval-bound token must be one the x402 requirements will actually
    // accept, otherwise the requirements could offer to settle this governed
    // spend in a token the approval never authorized. Compared case-insensitively
    // after trimming. A membership check alone is not enough: it proves the bound
    // token is somewhere in `accepted_tokens` but still returns the WHOLE list,
    // so `[approved, other]` would keep advertising `other` to the facilitator.
    // Filter the list down to the approval-bound token(s) so the requirements
    // only ever advertise the approved token, and fail closed when the bound
    // token is absent.
    let filtered_tokens: Vec<String> = accepted_tokens
        .into_iter()
        .filter(|token| {
            token
                .trim()
                .eq_ignore_ascii_case(binding.token_symbol.trim())
        })
        .collect();
    if filtered_tokens.is_empty() {
        return Err(SettlementError::InvalidBinding(format!(
            "x402 token mismatch: approval-bound token {:?} is not in the accepted tokens",
            binding.token_symbol
        )));
    }

    let requirements = build_x402_payment_requirements(
        dispatch,
        facilitator_url,
        resource,
        filtered_tokens,
        settlement_mode,
    )?;

    // Consume the single-use slot LAST: the artifact exists and every
    // fail-closed check has passed, so a rejection anywhere above leaves the
    // approval spendable by a corrected attempt.
    consume_replay_slot_at_issuance(&approval, replay_store)?;
    Ok(requirements)
}

fn validate_x402_field(label: &str, value: &str) -> Result<(), SettlementError> {
    if value.trim().is_empty() {
        return Err(SettlementError::InvalidInput(format!(
            "x402 compatibility requires {label}"
        )));
    }
    if value.trim() != value || value.chars().any(char::is_whitespace) {
        return Err(SettlementError::InvalidInput(format!(
            "x402 compatibility {label} must not contain whitespace"
        )));
    }
    Ok(())
}

/// Approval-bound settlement parameters the caller MUST supply.
///
/// EIP-3009 authorizations are independently replay-able and are not, by
/// themselves, tied to the approval that governs the spend. This binding
/// requires the prepared authorization to be bound to its governing
/// approval so a captured signature cannot be redirected to a different
/// payee, inflated to a different amount, or replayed on a different chain.
///
/// This type is the seam to the governed-approval layer: once a verified
/// [`chio_core_types::capability::governance::GovernedApprovalToken`] is
/// available at the settlement layer, the caller derives these bound
/// values from that token's governed intent and passes them here. Until
/// then, the caller is the trust boundary that MUST extract the values
/// from the verified approval before calling
/// [`prepare_transfer_with_authorization`]. Either way the bound values
/// are asserted against the authorization and any mismatch fails closed.
///
/// The `GovernedApprovalToken` itself does not carry chain/amount/payee/token
/// as discrete fields (they are folded into its `governed_intent_hash`), so
/// this layer cannot re-derive them from the token alone; it asserts the
/// explicitly-bound values the caller resolved from the verified intent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalBinding {
    /// Chain id the governing approval authorized the spend on. Must equal
    /// the EIP-3009 domain `chain_id`.
    pub chain_id: u64,
    /// Payee the governing approval authorized. Must equal the EIP-3009
    /// authorization `to` address (case-insensitive hex / checksum).
    pub payee_address: String,
    /// Amount in token minor units the governing approval authorized. Must
    /// equal the EIP-3009 authorization `value`.
    pub amount_minor_units: u128,
    /// Token/currency symbol the governing approval authorized (for example
    /// `"USDC"`). The chain id alone does not pin the token: a captured
    /// authorization for one token contract can otherwise be redirected to a
    /// different token on the same chain with the same payee and numeric
    /// amount. Each lane asserts its lane-specific token identity against
    /// this symbol (x402 accepted tokens, Circle token symbol). Compared
    /// case-insensitively after trimming.
    pub token_symbol: String,
    /// Token contract address the governing approval authorized (for example
    /// the USDC contract on the target chain). It is asserted against the
    /// EIP-3009 domain `verifying_contract`, which is the contract the signed
    /// transfer actually targets, so a captured authorization cannot be
    /// redirected to a different token contract on the same chain. Compared as
    /// parsed `Address` bytes so checksum vs lowercase hex compare equal.
    ///
    /// REQUIRED for the EIP-3009 lane: [`prepare_transfer_with_authorization`]
    /// fails closed when this is `None`, because a symbol alone cannot pin the
    /// on-chain token. The field stays `Option` only because lanes that
    /// identify their token by symbol and have no contract to compare against
    /// (the x402 accepted-token list and the Circle token symbol) still bind
    /// via `token_symbol` and legitimately leave this `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_contract: Option<String>,
    /// Fiat settlement currency the governing approval authorized (for example
    /// `"USD"`), distinct from the rail [`Self::token_symbol`] on the x402 lane.
    ///
    /// x402 settles a fiat-denominated amount (`"USD"`) in an on-chain rail
    /// token (`"USDC"`); the two are different strings. When the intent ALSO
    /// pins a `max_amount`, the gate clamps `max_amount.currency` against THIS
    /// fiat currency (via [`Self::settlement_currency`]), NOT the rail token, so
    /// a valid USDC/USD x402 approval carrying a fiat `max_amount` is no longer
    /// wrongly rejected. `None` means the rail token doubles as the settlement
    /// currency (Circle / EIP-3009, where they coincide). When the intent
    /// commits a `settlement_currency` this must equal it (signature-pinned).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_currency: Option<String>,
    /// Settlement-dispatch id the governing approval authorized.
    ///
    /// The dispatch-bearing lanes (x402 / Circle) assert the live
    /// `dispatch.dispatch_id` against this value, so a verified witness cannot
    /// be paired with a DIFFERENT dispatch that carries the same economics. It
    /// is signature-pinned: the gate requires the intent to commit the same
    /// `dispatch_id` and rejects a binding that carries one the intent never
    /// committed. The EIP-3009 lane settles off a `domain` + `authorization`
    /// (no dispatch) and leaves this `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dispatch_id: Option<String>,
    /// Capability id the governing approval authorized.
    ///
    /// The x402 requirements echo a `capability_id` resolved from the live
    /// dispatch; this lane asserts that resolved value against the
    /// signature-pinned id here, so a verified witness cannot be paired with a
    /// dispatch whose capability id differs. Signature-pinned the same way as
    /// [`Self::dispatch_id`]. `None` for lanes with no capability identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,
    /// Approval expiry as a Unix timestamp in seconds. The prepared
    /// authorization MUST NOT outlive the governing approval: when an
    /// EIP-3009 `valid_before` would let a signed transfer stay broadcastable
    /// past this instant, preparation fails closed. Binds the off-chain
    /// authorization window to the approval window so a captured signature
    /// cannot be broadcast after the approval that governs it has expired.
    pub approval_expires_at: u64,
}

impl ApprovalBinding {
    /// Assert that a lane's token symbol matches the approval-bound token.
    ///
    /// Comparison is case-insensitive after trimming so `"usdc"`, `" USDC "`,
    /// and `"USDC"` are treated as the same token. Used by lanes that
    /// identify their token by symbol rather than by contract address (the
    /// x402 accepted-token list and the Circle token symbol). Fails closed
    /// on any mismatch so a captured authorization for one token cannot be
    /// redirected to a different token the approval never authorized.
    pub fn assert_token_symbol(
        &self,
        lane: &str,
        lane_token_symbol: &str,
    ) -> Result<(), SettlementError> {
        if !lane_token_symbol
            .trim()
            .eq_ignore_ascii_case(self.token_symbol.trim())
        {
            return Err(SettlementError::InvalidBinding(format!(
                "{lane} token mismatch: lane token {lane_token_symbol:?} is not the \
                 approval-bound token {:?}",
                self.token_symbol
            )));
        }
        Ok(())
    }

    /// Assert the governing approval has not expired as of the lane-use clock.
    ///
    /// The witness verification gate checks the approval window once, at verify
    /// time. A caller can verify just before `approval_expires_at`, hold the
    /// witness, and try to build settlement artifacts later. Each lane entry
    /// point re-checks this at lane use so an approval that has lapsed by the
    /// time the lane runs cannot authorize a later spend. The boundary instant
    /// `now == approval_expires_at` is treated as expired (the approval covers
    /// `[_, approval_expires_at)`), matching the EIP-3009 `valid_before`
    /// half-open window. Fails closed.
    pub fn assert_not_expired_at(
        &self,
        lane: &str,
        now_unix_seconds: u64,
    ) -> Result<(), SettlementError> {
        if now_unix_seconds >= self.approval_expires_at {
            return Err(SettlementError::InvalidBinding(format!(
                "{lane} approval expired: now {now_unix_seconds} >= approval expiry {}",
                self.approval_expires_at
            )));
        }
        Ok(())
    }

    /// The fiat settlement currency the approval authorized.
    ///
    /// Returns the explicit [`Self::settlement_currency`] when present (the
    /// x402 fiat currency, distinct from the rail [`Self::token_symbol`]), else
    /// falls back to the rail token symbol (Circle / EIP-3009, where the rail
    /// token and the settlement currency coincide). This is the field the
    /// `max_amount` currency clamp compares against, so a USDC-rail / USD-fiat
    /// x402 approval clamps correctly.
    #[must_use]
    pub fn settlement_currency(&self) -> &str {
        self.settlement_currency
            .as_deref()
            .unwrap_or(&self.token_symbol)
    }

    /// Assert the live dispatch id is the one the approval signature pinned.
    ///
    /// The dispatch-bearing lanes (x402 / Circle) copy `dispatch.dispatch_id`
    /// into the settlement artifacts they produce. Without this a verified
    /// witness for one dispatch could be paired with a DIFFERENT dispatch that
    /// carries the same chain / payee / amount / token and produce artifacts
    /// for that other dispatch. The witness gate signature-pins
    /// [`Self::dispatch_id`] (it must equal the intent-committed value), so
    /// asserting the live dispatch id against it here ties the witness to the
    /// approved dispatch. Fails closed when the binding pins no dispatch id (a
    /// dispatch-bearing lane requires a signed one) or when it disagrees with
    /// the live dispatch.
    pub fn assert_dispatch_id(&self, lane: &str, dispatch_id: &str) -> Result<(), SettlementError> {
        let Some(bound) = self.dispatch_id.as_deref() else {
            return Err(SettlementError::InvalidBinding(format!(
                "{lane} dispatch identity unbound: the approval pins no dispatch id, so the \
                 witness cannot be tied to this dispatch"
            )));
        };
        if bound != dispatch_id {
            return Err(SettlementError::InvalidBinding(format!(
                "{lane} dispatch mismatch: dispatch id {dispatch_id:?} is not the approval-bound \
                 dispatch {bound:?}"
            )));
        }
        Ok(())
    }

    /// Assert the live capability id is the one the approval signature pinned.
    ///
    /// The x402 requirements echo a `capability_id` resolved from the live
    /// dispatch. As with [`Self::assert_dispatch_id`], a witness for one
    /// dispatch could otherwise be paired with a dispatch whose capability id
    /// differs. The gate signature-pins [`Self::capability_id`], so asserting
    /// the resolved capability id against it ties the witness to the approved
    /// capability. Fails closed when unbound or on any mismatch.
    pub fn assert_capability_id(
        &self,
        lane: &str,
        capability_id: &str,
    ) -> Result<(), SettlementError> {
        let Some(bound) = self.capability_id.as_deref() else {
            return Err(SettlementError::InvalidBinding(format!(
                "{lane} capability identity unbound: the approval pins no capability id, so the \
                 witness cannot be tied to this dispatch's capability"
            )));
        };
        if bound != capability_id {
            return Err(SettlementError::InvalidBinding(format!(
                "{lane} capability mismatch: capability id {capability_id:?} is not the \
                 approval-bound capability {bound:?}"
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// C2 (BAC-541): verify a real GovernedApprovalToken and DERIVE the binding
// from the verified token before any lane settles.
// ---------------------------------------------------------------------------
//
// THE TRUST PATH (read this before changing it)
// =============================================
//
// A `GovernedApprovalToken` does NOT carry discrete amount/payee/chain
// fields. It commits to the *whole* governed intent via a single
// `governed_intent_hash` (the canonical-JSON sha256 of the
// `GovernedTransactionIntent`). So the settlement layer cannot read the
// authorized amount/payee/chain off the token directly. Instead the gate
// below establishes trust in three independent steps and only then trusts
// the caller-resolved [`ApprovalBinding`]:
//
//   1. Ed25519 signature over the canonical token body
//      (`token.verify_signature()`), the approval decision is `Approved`,
//      and the validity window (`token.validate_time(now)`). Any failure
//      aborts settlement (fail-closed): a forged, denied, expired, or
//      not-yet-valid token never reaches a lane.
//   2. The token's `approver` public key equals the *expected principal*
//      the operator configured for this settlement. A validly-signed token
//      from the wrong approver is rejected: signature validity alone does
//      not establish authority.
//   3. The token actually covers THIS settlement. The caller supplies the
//      `GovernedTransactionIntent`; we recompute `intent.binding_hash()`
//      and assert it equals `token.governed_intent_hash`. This is the link
//      that ties the abstract approval to the concrete spend; without it a
//      validly-signed approval for intent A could be replayed to authorize
//      settlement B.
//
// Only after (1)-(3) pass do we treat the [`ApprovalBinding`] the caller
// resolved from that same intent as authoritative. The lanes then assert
// their lane-specific facts (chain id / payee / amount / currency) against
// the binding inside this [`VerifiedApproval`]; any lane-level mismatch
// still fails closed. The caller MUST resolve the `ApprovalBinding` from
// the SAME intent it passes here: `verify_governed_approval` cannot police
// that the binding numerically reflects the intent (the intent binds
// chain/amount/payee only indirectly through the hash), so each lane's
// assertion against the dispatch is the second, independent check that the
// approved economics match what is actually being broadcast.

/// A governing approval whose signature, decision, validity window, approver
/// identity, and intent-coverage have all been verified by
/// [`verify_governed_approval`].
///
/// This type can only be constructed by the verification gate, so a value of
/// this type is a capability witness: holding one means a real
/// [`GovernedApprovalToken`] authorized the carried [`ApprovalBinding`] for
/// the settlement identified by `governed_intent_hash`. The per-lane
/// `*_with_verified_approval` entry points take this BY VALUE and assert the
/// dispatch/authorization against `binding`, consuming the witness so it cannot
/// authorize a second settlement.
///
/// It deliberately does NOT derive `Clone`: a single-use capability witness
/// that could be duplicated would not be single-use, so a caller cannot keep a
/// copy to reuse with a fresh EIP-3009 nonce after a lane has consumed it.
///
/// Holding a witness is NOT yet a consumed approval: the approval's
/// `(request_id, governed_intent_hash)` replay slot is recorded only when a
/// lane wrapper issues a settlement artifact, so a witness that is dropped,
/// or rejected by a lane assertion, leaves the approval spendable by a
/// corrected attempt. See [`verify_governed_approval`].
#[derive(Debug)]
pub struct VerifiedApproval {
    /// The intent hash the verified token committed to (== the recomputed
    /// `binding_hash()` of the intent the caller passed in).
    governed_intent_hash: String,
    /// The approval token id, retained for receipts / audit.
    approval_id: String,
    /// The request id the verified token bound (== the expected request id
    /// the caller passed in). Retained for receipts / audit.
    request_id: String,
    /// The binding the caller resolved from the verified intent. Trusted
    /// only because every check in [`verify_governed_approval`] passed.
    binding: ApprovalBinding,
}

impl VerifiedApproval {
    /// The intent hash the verified approval token committed to.
    #[must_use]
    pub fn governed_intent_hash(&self) -> &str {
        &self.governed_intent_hash
    }

    /// The verified approval token id (for receipts / audit trails).
    #[must_use]
    pub fn approval_id(&self) -> &str {
        &self.approval_id
    }

    /// The request id the verified approval token bound (for receipts /
    /// audit trails).
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    /// The approval-authorized settlement binding. Only trustworthy because
    /// this value could only be produced by the verification gate.
    #[must_use]
    pub fn binding(&self) -> &ApprovalBinding {
        &self.binding
    }
}

/// Verify a [`GovernedApprovalToken`] and derive the trusted settlement
/// [`ApprovalBinding`] from it. This is the single C2 (BAC-541) gate every
/// settlement lane funnels through before it will bind a spend.
///
/// Fail-closed checks, in order:
///
/// 1. **Signature.** `token.verify_signature()` must succeed AND return
///    `true`. A malformed or forged signature aborts settlement.
/// 2. **Decision.** `token.decision` must be
///    [`GovernedApprovalDecision::Approved`]; a `Denied` (or any
///    non-approval) token aborts settlement.
/// 3. **Validity window.** `token.validate_time(now)` must pass; expired or
///    not-yet-valid tokens abort settlement.
/// 4. **Approver identity.** `token.approver` must equal `expected_approver`,
///    the principal the operator expects to have signed this approval. A
///    valid signature from an unexpected approver is rejected.
/// 5. **Subject / request binding.** `token.subject` must equal
///    `expected_subject` and `token.request_id` must equal
///    `expected_request_id`, mirroring the kernel validator. A validly-signed
///    token for a DIFFERENT subject or request (even with the same intent
///    hash and approver) is rejected: signature validity alone does not bind
///    the approval to this caller and this request.
/// 6. **Intent coverage.** `intent.binding_hash()` must equal
///    `token.governed_intent_hash`, proving the approval covers THIS
///    settlement and not some other intent.
/// 7. **Intent settlement binding.** When the intent commits a concrete
///    settlement binding (chain / payee / token / amount) via its
///    [`crate::approval_witness::CHIO_SETTLEMENT_BINDING_CONTEXT_KEY`] context
///    commitment, the caller-resolved `binding` must match it exactly. Because
///    `intent.binding_hash()` covers `context`, this DERIVES the chain / payee
///    / token / amount from what the approver actually signed, so the witness
///    cannot carry a caller-chosen chain, payee, or token contract the
///    approval never authorized.
/// 8. **Committed settlement binding required.** The intent MUST commit a
///    concrete `chioSettlementBinding` (step 7). The `max_amount`-only mode
///    pins amount/currency but NO chain / payee / token / contract, so a
///    settlement witness built from it would leave chain / payee / token
///    caller-chosen; the value lanes require those to be signature-pinned, so a
///    witness is issued only when a committed binding is present (fail-closed).
///    When `max_amount` is ALSO set the resolved `binding` must not exceed it
///    (amount `<=` maximum, matching currency).
/// 9. **Expiry clamp.** `binding.approval_expires_at` must not be later than
///    `token.expires_at`. The binding is derived from the token, so an
///    EIP-3009 `valid_before` clamped to the binding expiry cannot outlive
///    the token; rejecting a longer binding expiry keeps the off-chain spend
///    window bounded by the token.
/// 10. **Lifetime cap.** `(token.expires_at - token.issued_at)` must not exceed
///     [`MAX_APPROVAL_TTL_SECS`] (mirroring the kernel cap), so a token cannot
///     mint a witness that outlives the replay registry's eviction window.
///
/// # Single use is consumed at artifact issuance, not here
///
/// Verification is a read-only proof over the token: this gate never touches
/// the [`ApprovalReplayStore`], so neither a gate-level rejection nor a
/// verified-but-never-settled witness consumes the approval's single-use
/// slot, and re-verifying the same token (for example after a crash between
/// verification and settlement) still succeeds. The single-use unit is the
/// ISSUED SETTLEMENT ARTIFACT: each exported lane wrapper records
/// `(request_id, governed_intent_hash)` into its shared replay store
/// immediately before returning a successful artifact, so the first issuance
/// wins across every lane sharing the store.
///
/// `binding` is the chain/payee/amount the caller resolved from `intent`.
/// It is returned inside the [`VerifiedApproval`] for the lanes to assert
/// against. The lanes' own assertions against the live dispatch are the
/// second, independent economic check (see module trust-path docs).
pub fn verify_governed_approval(
    token: &GovernedApprovalToken,
    intent: &GovernedTransactionIntent,
    expected_approver: &PublicKey,
    expected_subject: &PublicKey,
    expected_request_id: &str,
    binding: ApprovalBinding,
    now_unix_seconds: u64,
) -> Result<VerifiedApproval, SettlementError> {
    // (1) Signature over the canonical token body. `verify_signature`
    // returns Ok(false) for a well-formed-but-wrong signature and Err for a
    // malformed one; both fail closed.
    let signature_ok = token.verify_signature().map_err(|error| {
        SettlementError::Verification(format!(
            "governed approval token signature could not be verified: {error}"
        ))
    })?;
    if !signature_ok {
        return Err(SettlementError::Verification(
            "governed approval token signature is invalid".to_string(),
        ));
    }

    // (2) Decision must be an explicit approval. A denied token that is
    // otherwise valid must never authorize a spend.
    if token.decision != GovernedApprovalDecision::Approved {
        return Err(SettlementError::Verification(
            "governed approval token does not encode an approval decision".to_string(),
        ));
    }

    // (3) Validity window vs. now. `validate_time` returns
    // CapabilityNotYetValid / CapabilityExpired which we surface as
    // verification failures.
    token.validate_time(now_unix_seconds).map_err(|error| {
        SettlementError::Verification(format!(
            "governed approval token is outside its validity window: {error}"
        ))
    })?;

    // (4) Approver identity. A valid signature only proves the holder of
    // `token.approver`'s key signed it; we still require that key to be the
    // principal the operator expects for this settlement.
    if &token.approver != expected_approver {
        return Err(SettlementError::Verification(
            "governed approval token approver is not the expected principal".to_string(),
        ));
    }

    // (5) Subject / request binding. The kernel validator binds the approval
    // token to the capability subject and the originating request; mirror it
    // here so a captured approval for one subject/request cannot be presented
    // for a different one with the same intent hash and approver.
    if &token.subject != expected_subject {
        return Err(SettlementError::Verification(
            "governed approval token subject does not match the expected subject".to_string(),
        ));
    }
    if token.request_id != expected_request_id {
        return Err(SettlementError::Verification(
            "governed approval token request binding does not match the expected request"
                .to_string(),
        ));
    }

    // (6) Intent coverage. Recompute the canonical intent hash and compare
    // to what the token committed to. This binds the abstract approval to
    // THIS concrete settlement intent, defeating cross-intent replay of an
    // otherwise-valid approval.
    let recomputed_intent_hash = intent.binding_hash().map_err(|error| {
        SettlementError::Verification(format!(
            "failed to recompute governed intent binding hash: {error}"
        ))
    })?;
    if recomputed_intent_hash != token.governed_intent_hash {
        return Err(SettlementError::Verification(
            "governed approval token does not cover this settlement intent (intent hash mismatch)"
                .to_string(),
        ));
    }

    // (7) Intent settlement binding. When the approver signed a concrete
    // chain / payee / token / amount commitment into the intent context, the
    // caller-resolved binding must match it exactly. This DERIVES the witness
    // chain / payee / token from what `intent.binding_hash()` (and therefore
    // the approval signature) commits, so a caller cannot substitute a payee,
    // chain, or token contract the approval never authorized.
    let committed_binding = parse_intent_settlement_binding(intent)?;
    if let Some(committed) = committed_binding.as_ref() {
        assert_binding_matches_intent_commitment(committed, &binding)?;
    }

    // (8) Committed settlement binding REQUIRED. A `max_amount`-only intent
    // pins an amount/currency ceiling but commits NO chain / payee / token /
    // contract, so a witness built from it would let the caller choose any
    // chain, payee, or EIP-3009 token contract while only the amount and
    // currency are constrained. The settlement lanes (x402 / EIP-3009 / Circle)
    // are value lanes: chain / payee / token must ALWAYS be signature-pinned, so
    // the witness this gate issues is settlement-capable only when the intent
    // commits a concrete `chioSettlementBinding`. Fail closed when no committed
    // binding is present; a non-settlement use that needs `max_amount`-only must
    // not route through this gate (it would not produce a settlement-capable
    // witness anyway). When `max_amount` is ALSO set, the resolved binding is
    // additionally clamped to it (amount <= maximum, matching currency) below.
    if committed_binding.is_none() {
        return Err(SettlementError::Verification(
            "governed intent commits no chioSettlementBinding: a settlement witness requires a \
             signed chain/payee/token binding, so the max_amount-only mode cannot produce one"
                .to_string(),
        ));
    }
    assert_binding_within_intent_max_amount(intent.max_amount.as_ref(), &binding)?;

    // (9) Expiry clamp. The binding is derived from the token, so its expiry
    // must not outlast the token; otherwise an EIP-3009 `valid_before` clamped
    // to the binding could keep a signed transfer broadcastable past the token
    // that governs it.
    if binding.approval_expires_at > token.expires_at {
        return Err(SettlementError::Verification(format!(
            "approval binding expiry {} outlives the governed approval token expiry {}",
            binding.approval_expires_at, token.expires_at
        )));
    }

    // (10) Lifetime cap. The verifier only checks now-in-window, so a token
    // with `expires_at` far past `issued_at` would mint a long-lived witness
    // that could outlive the single-use replay entry's eviction window. Mirror
    // the kernel cap (`MAX_APPROVAL_TTL_SECS`): reject any token whose
    // `(expires_at - issued_at)` exceeds it. Fail closed.
    let token_lifetime = token.expires_at.saturating_sub(token.issued_at);
    if token_lifetime > MAX_APPROVAL_TTL_SECS {
        return Err(SettlementError::Verification(format!(
            "governed approval token lifetime ({token_lifetime}s) exceeds the maximum \
             ({MAX_APPROVAL_TTL_SECS}s)"
        )));
    }

    Ok(VerifiedApproval {
        governed_intent_hash: token.governed_intent_hash.clone(),
        approval_id: token.id.clone(),
        request_id: token.request_id.clone(),
        binding,
    })
}

/// Consume the approval's single-use replay slot at settlement-artifact
/// issuance.
///
/// Every exported lane wrapper calls this as its FINAL step: all lane
/// assertions have passed and the settlement artifact already exists, so the
/// only remaining outcome is returning it. Recording here (and nowhere
/// earlier) makes the ISSUED ARTIFACT the single-use unit: the first
/// issuance wins across every lane sharing `replay_store`, and neither a
/// gate-level nor a lane-level rejection consumes the slot. Keyed on
/// `(request_id, governed_intent_hash)`, mirroring the kernel
/// `approval_replay_store`; retained until the approval expiry, which the
/// gate clamps to the token expiry.
fn consume_replay_slot_at_issuance(
    approval: &VerifiedApproval,
    replay_store: &dyn ApprovalReplayStore,
) -> Result<(), SettlementError> {
    match replay_store.record_if_fresh(
        approval.request_id(),
        approval.governed_intent_hash(),
        approval.binding().approval_expires_at,
    )? {
        ApprovalReplayOutcome::Fresh => Ok(()),
        ApprovalReplayOutcome::Replayed => Err(SettlementError::Verification(
            "governed approval has already been consumed by an issued settlement artifact \
             (replay rejected)"
                .to_string(),
        )),
    }
}

/// Assert a caller-resolved [`ApprovalBinding`] matches the settlement
/// commitment the approver signed into the intent.
///
/// Every field of `committed` is covered by `intent.binding_hash()` (the
/// canonical-JSON sha256 the approval token signs), so matching against it
/// DERIVES the chain / payee / token / amount from the SIGNED intent. A
/// caller-substituted chain, payee, token contract, or amount that disagrees
/// with what the approver authorized is rejected before any witness is issued.
/// Addresses are compared as parsed [`Address`] bytes so checksum vs lowercase
/// hex compare equal; the token symbol is compared case-insensitively after
/// trimming.
///
/// The token contract is treated as a SIGNED field: a binding that carries a
/// `token_contract` the intent never committed is rejected (not just one that
/// disagrees with a committed contract), so the EIP-3009 lane can never target
/// a contract the approver did not sign.
fn assert_binding_matches_intent_commitment(
    committed: &IntentSettlementBinding,
    binding: &ApprovalBinding,
) -> Result<(), SettlementError> {
    if binding.chain_id != committed.chain_id {
        return Err(SettlementError::Verification(format!(
            "approval binding chain {} does not match the intent-committed chain {}",
            binding.chain_id, committed.chain_id
        )));
    }

    let bound_payee = Address::from_str(binding.payee_address.trim()).map_err(|error| {
        SettlementError::Verification(format!("approval binding payee address invalid: {error}"))
    })?;
    let committed_payee = Address::from_str(committed.payee_address.trim()).map_err(|error| {
        SettlementError::Verification(format!("intent-committed payee address invalid: {error}"))
    })?;
    if bound_payee != committed_payee {
        return Err(SettlementError::Verification(
            "approval binding payee does not match the intent-committed payee".to_string(),
        ));
    }

    if binding.amount_minor_units != committed.amount_minor_units {
        return Err(SettlementError::Verification(format!(
            "approval binding amount {} does not match the intent-committed amount {}",
            binding.amount_minor_units, committed.amount_minor_units
        )));
    }

    if !binding
        .token_symbol
        .trim()
        .eq_ignore_ascii_case(committed.token_symbol.trim())
    {
        return Err(SettlementError::Verification(format!(
            "approval binding token {:?} does not match the intent-committed token {:?}",
            binding.token_symbol, committed.token_symbol
        )));
    }

    // Token contract: the contract the EIP-3009 lane targets MUST have been
    // signed. Compare as parsed Address bytes so casing differences do not
    // matter. Three fail-closed cases:
    //
    //   - intent commits a contract, binding matches it: accept.
    //   - intent commits a contract, binding omits or substitutes it: reject
    //     (the captured approval cannot be redirected to a different contract).
    //   - intent commits NO contract, binding carries one: reject. A symbol
    //     alone does not pin the on-chain token, so a caller that introduces a
    //     `token_contract` the approver never signed could redirect the
    //     EIP-3009 lane to an attacker-chosen contract (the lane only checks
    //     `domain.verifyingContract == binding.token_contract`, and BOTH are
    //     caller-supplied). Refusing an uncommitted contract here guarantees
    //     that whenever the EIP-3009 lane uses a contract, that contract was
    //     committed by the signed intent.
    match committed.token_contract.as_deref() {
        Some(committed_contract) => {
            let committed_contract =
                Address::from_str(committed_contract.trim()).map_err(|error| {
                    SettlementError::Verification(format!(
                        "intent-committed token contract address invalid: {error}"
                    ))
                })?;
            let bound_contract = binding
                .token_contract
                .as_deref()
                .ok_or_else(|| {
                    SettlementError::Verification(
                        "approval binding omits the token contract the intent committed"
                            .to_string(),
                    )
                })
                .and_then(|raw| {
                    Address::from_str(raw.trim()).map_err(|error| {
                        SettlementError::Verification(format!(
                            "approval binding token contract address invalid: {error}"
                        ))
                    })
                })?;
            if bound_contract != committed_contract {
                return Err(SettlementError::Verification(
                    "approval binding token contract does not match the intent-committed contract"
                        .to_string(),
                ));
            }
        }
        None => {
            if binding.token_contract.is_some() {
                return Err(SettlementError::Verification(
                    "approval binding carries a token contract the intent never committed: the \
                     EIP-3009 token contract must be signed, not caller-substituted"
                        .to_string(),
                ));
            }
        }
    }

    // Fiat settlement currency, dispatch id, and capability id are signed the
    // same fail-closed way as the token contract: when the intent commits one,
    // the resolved binding must match it; when the intent commits none, the
    // resolved binding must NOT carry one. This guarantees that whenever a lane
    // clamps against the fiat currency or pins a dispatch / capability identity,
    // that value was committed by the signed intent rather than caller-chosen.
    assert_signed_optional_identity(
        "settlement currency",
        committed.settlement_currency.as_deref(),
        binding.settlement_currency.as_deref(),
        IdentityMatch::CaseInsensitive,
    )?;
    assert_signed_optional_identity(
        "dispatch id",
        committed.dispatch_id.as_deref(),
        binding.dispatch_id.as_deref(),
        IdentityMatch::Exact,
    )?;
    assert_signed_optional_identity(
        "capability id",
        committed.capability_id.as_deref(),
        binding.capability_id.as_deref(),
        IdentityMatch::Exact,
    )?;

    Ok(())
}

/// How [`assert_signed_optional_identity`] compares a committed value against a
/// resolved one.
#[derive(Debug, Clone, Copy)]
enum IdentityMatch {
    /// Compared case-insensitively after trimming (currency symbols).
    CaseInsensitive,
    /// Compared verbatim after trimming (opaque identifiers).
    Exact,
}

/// Assert an optional signed identity field on the resolved binding agrees with
/// the intent commitment, fail-closed in both directions.
///
/// Mirrors the `token_contract` pinning: when the intent commits a value the
/// resolved binding must match it; when the intent commits none the resolved
/// binding must omit it (so a caller cannot introduce a field the approver
/// never signed). `CaseInsensitive` is for currency symbols; `Exact` is for
/// opaque identifiers (dispatch / capability ids).
fn assert_signed_optional_identity(
    label: &str,
    committed: Option<&str>,
    bound: Option<&str>,
    mode: IdentityMatch,
) -> Result<(), SettlementError> {
    match (committed, bound) {
        (Some(committed_value), Some(bound_value)) => {
            let matches = match mode {
                IdentityMatch::CaseInsensitive => bound_value
                    .trim()
                    .eq_ignore_ascii_case(committed_value.trim()),
                IdentityMatch::Exact => bound_value.trim() == committed_value.trim(),
            };
            if !matches {
                return Err(SettlementError::Verification(format!(
                    "approval binding {label} {bound_value:?} does not match the intent-committed \
                     {label} {committed_value:?}"
                )));
            }
            Ok(())
        }
        (Some(_), None) => Err(SettlementError::Verification(format!(
            "approval binding omits the {label} the intent committed"
        ))),
        (None, Some(_)) => Err(SettlementError::Verification(format!(
            "approval binding carries a {label} the intent never committed: it must be signed, \
             not caller-substituted"
        ))),
        (None, None) => Ok(()),
    }
}

/// Assert a resolved [`ApprovalBinding`] does not exceed an intent's approved
/// maximum amount.
///
/// When `max_amount` is `None` the intent pins no monetary ceiling and the
/// binding is unconstrained here (the lanes still assert chain/payee/amount
/// against the live dispatch). When it is `Some`, the bound amount must be
/// `<=` the maximum and the bound FIAT settlement currency must match the
/// approved currency (case-insensitive after trimming), so a witness can never
/// authorize a spend larger than, or in a different currency than, what the
/// intent approved. Fails closed on any breach.
///
/// The clamp compares `max_amount.currency` against
/// [`ApprovalBinding::settlement_currency`] (the FIAT currency), NOT the rail
/// [`ApprovalBinding::token_symbol`]. On the x402 lane the rail token (`USDC`)
/// and the fiat settlement currency (`USD`) differ; comparing the rail token to
/// the fiat `max_amount.currency` would wrongly reject a valid USDC/USD x402
/// approval that also carries a fiat `max_amount`. `settlement_currency()`
/// falls back to the rail token symbol on the Circle / EIP-3009 lanes, where
/// the two coincide, so their existing currency clamp is unchanged.
fn assert_binding_within_intent_max_amount(
    max_amount: Option<&MonetaryAmount>,
    binding: &ApprovalBinding,
) -> Result<(), SettlementError> {
    let Some(max_amount) = max_amount else {
        return Ok(());
    };
    if binding.amount_minor_units > u128::from(max_amount.units) {
        return Err(SettlementError::Verification(format!(
            "approval binding amount {} exceeds the intent-approved maximum {}",
            binding.amount_minor_units, max_amount.units
        )));
    }
    let settlement_currency = binding.settlement_currency();
    if !settlement_currency
        .trim()
        .eq_ignore_ascii_case(max_amount.currency.trim())
    {
        return Err(SettlementError::Verification(format!(
            "approval binding currency {settlement_currency:?} does not match the intent-approved \
             currency {:?}",
            max_amount.currency
        )));
    }
    Ok(())
}

/// Outcome of a [`Eip3009NonceStore::record_if_fresh`] call.
///
/// Mirrors the `RecordOutcome` contract in
/// `chio-custody-hw::nonce_store` for consistency across the trust
/// boundaries: recording a fresh nonce returns [`NonceOutcome::Fresh`];
/// a previously-seen nonce returns [`NonceOutcome::Replayed`] and the
/// caller MUST abort settlement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceOutcome {
    /// The `(authorizer, nonce)` pair was not present and has now been
    /// recorded.
    Fresh,
    /// The pair was already present. Settlement MUST fail closed.
    Replayed,
}

/// Default hard capacity for retained EIP-3009 authorization nonces.
///
/// A malicious or buggy client can present an unbounded stream of distinct
/// nonces. The store fails closed once this many entries are retained and
/// relies on the explicit [`Eip3009NonceStore::gc_expired`] path to reopen
/// capacity. Mirrors `DEFAULT_MAX_NONCE_ENTRIES` in `chio-custody-hw`.
pub const DEFAULT_MAX_EIP3009_NONCE_ENTRIES: usize = 65_536;

/// Single-use nonce store for EIP-3009 authorization replay resistance.
///
/// This is the trust-boundary surface settlement consults BEFORE
/// preparing a transfer. The store is keyed on the EIP-3009 authorizer
/// (`from` address) and a nonce key that scopes the 32-byte authorization
/// `nonce` to its EIP-712 domain (chain id + verifying contract): per
/// EIP-3009 the `(from, nonce)` pair is consumed on-chain by a SPECIFIC
/// token contract, so the same nonce value is an independent spend on a
/// different token or chain. Recording the domain-scoped pair here makes
/// the off-chain preparation path single-use per token contract as well,
/// closing the replay window before a signature is ever broadcast without
/// rejecting a legitimate reuse of the same nonce on a different contract.
///
/// [`prepare_transfer_with_authorization`] keys the store on the canonical
/// `0x` lowercase hex of the PARSED `from`/`nonce` bytes (with the chain id
/// and verifying contract folded into the nonce key), so a re-prefixed or
/// re-cased submission of the same authorization on the same domain maps to
/// the same entry. Implementations additionally lowercase the supplied key
/// defensively, so direct callers cannot evade detection through casing
/// either.
///
/// Implementations are `Send + Sync` so callers can hold them in an
/// `Arc<dyn Eip3009NonceStore>`. The contract intentionally mirrors
/// `chio_custody_hw::nonce_store::PasskeyNonceStore`:
///
/// - `record_if_fresh` is the only mutating entry point and MUST be
///   atomic with respect to concurrent calls, so two parallel replays of
///   the same `(from, nonce)` cannot both observe `Fresh`.
/// - Any present entry is treated as a replay; the record path never
///   prunes. `gc_expired` is the only entry point that drops entries, so
///   replay decisions stay decoupled from the wall clock.
pub trait Eip3009NonceStore: Send + Sync {
    /// Record `(from_address, nonce)` for replay detection.
    ///
    /// `retain_until_unix_seconds` is the time the entry stays GC-able
    /// until (typically the authorization `valid_before`). Atomicity:
    /// two concurrent calls with the same key cannot both observe
    /// [`NonceOutcome::Fresh`].
    fn record_if_fresh(
        &self,
        from_address: &str,
        nonce: &str,
        retain_until_unix_seconds: u64,
    ) -> Result<NonceOutcome, SettlementError>;

    /// Sweep entries whose retention bound is below `now_unix_seconds`.
    ///
    /// Returns the number of records pruned. Advisory: failing to run it
    /// never causes a false [`NonceOutcome::Fresh`].
    fn gc_expired(&self, now_unix_seconds: u64) -> Result<usize, SettlementError>;

    /// Number of currently retained entries. Used by tests and metrics.
    fn len(&self) -> Result<usize, SettlementError>;

    /// True if no entries are retained.
    fn is_empty(&self) -> Result<bool, SettlementError> {
        Ok(self.len()? == 0)
    }
}

/// Internal map keyed on `(from_address, nonce)` whose value is the
/// Unix-seconds retention bound past which the entry is GC-able. Keys are
/// canonicalized (optional `0x` prefix stripped, then lowercased) so that
/// checksum-cased, lowercase, and `0x`-prefixed-vs-bare hex all map to the
/// same entry and cannot evade replay detection.
type Eip3009NonceMap = HashMap<(String, String), u64>;

/// Canonicalize a hex key component for the nonce store: strip an optional
/// `0x`/`0X` prefix and lowercase. This makes `"0xABC"`, `"0xabc"`, and
/// `"abc"` collapse to the same key so prefix/casing formatting cannot be
/// used to replay a previously-seen `(from, nonce)` pair as `Fresh`.
fn canonicalize_nonce_key_component(value: &str) -> String {
    let trimmed = value.trim();
    let without_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    without_prefix.to_ascii_lowercase()
}

/// Process-local single-use EIP-3009 nonce store.
///
/// Backed by `Mutex<Eip3009NonceMap>`. Suitable for tests and
/// single-process deployments. Durable deployments back the
/// [`Eip3009NonceStore`] trait with the SQLite store wired by default in
/// the revocation/nonce-store durability lane (see issue dependencies).
pub struct InMemoryEip3009NonceStore {
    inner: Mutex<Eip3009NonceMap>,
    max_entries: usize,
}

impl Default for InMemoryEip3009NonceStore {
    fn default() -> Self {
        Self::with_max_entries(DEFAULT_MAX_EIP3009_NONCE_ENTRIES)
    }
}

impl InMemoryEip3009NonceStore {
    /// Build a fresh store with the default hard capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a fresh store with a custom hard capacity.
    #[must_use]
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            max_entries,
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Eip3009NonceMap>, SettlementError> {
        self.inner.lock().map_err(|err| {
            SettlementError::InvalidBinding(format!("EIP-3009 nonce store mutex poisoned: {err}"))
        })
    }
}

impl Eip3009NonceStore for InMemoryEip3009NonceStore {
    fn record_if_fresh(
        &self,
        from_address: &str,
        nonce: &str,
        retain_until_unix_seconds: u64,
    ) -> Result<NonceOutcome, SettlementError> {
        let key = (
            canonicalize_nonce_key_component(from_address),
            canonicalize_nonce_key_component(nonce),
        );
        let mut guard = self.lock()?;

        // Fail-closed: any present entry, even past its retention bound,
        // is treated as a replay. `gc_expired` is the ONLY entry point
        // that drops entries; the record path never prunes so replay
        // decisions stay decoupled from the wall clock.
        if guard.contains_key(&key) {
            return Ok(NonceOutcome::Replayed);
        }
        if guard.len() >= self.max_entries {
            return Err(SettlementError::InvalidBinding(format!(
                "EIP-3009 nonce store capacity exceeded: {} retained entries (max {})",
                guard.len(),
                self.max_entries
            )));
        }
        guard.insert(key, retain_until_unix_seconds);
        Ok(NonceOutcome::Fresh)
    }

    fn gc_expired(&self, now_unix_seconds: u64) -> Result<usize, SettlementError> {
        let mut guard = self.lock()?;
        let before = guard.len();
        guard.retain(|_, retain_until| *retain_until >= now_unix_seconds);
        Ok(before - guard.len())
    }

    fn len(&self) -> Result<usize, SettlementError> {
        Ok(self.lock()?.len())
    }
}

/// Prepare an EIP-3009 `transferWithAuthorization` digest, enforcing the
/// money-safety invariants before any signature is broadcast:
///
/// 1. **Single-use nonce.** `nonce_store.record_if_fresh(from, nonce)` is
///    consulted first; a previously-seen `(from, nonce)` pair fails closed
///    with [`SettlementError::InvalidBinding`], rejecting replays.
/// 2. **Time window vs. now.** The authorization is accepted only when
///    `valid_before > now_unix_seconds > valid_after`; an expired or
///    not-yet-valid window fails closed.
/// 3. **Authorization must not outlive the approval.** The EIP-3009
///    `valid_before` must not exceed `binding.approval_expires_at`. A signed
///    transfer stays broadcastable on-chain until `valid_before`, so an
///    authorization whose window outlasts the governing approval is rejected
///    to keep the off-chain spend bounded by the approval window.
/// 4. **Approval binding.** The domain `chain_id`, authorization `to`
///    (payee), `value` (amount), and token identity (the domain
///    `verifying_contract` against the REQUIRED `binding.token_contract`) are
///    asserted against `binding`; any mismatch (or an absent token contract)
///    fails closed. The caller resolves `binding` from the verified governing
///    approval from governed approval validation.
///
/// All checks fail closed. The nonce is recorded only after the time-window,
/// expiry, and binding checks pass, so a rejected authorization does not burn
/// its nonce.
///
/// This is the legacy EIP-3009 preparation path. It is `pub(crate)` so
/// downstream cannot bypass the C2 (BAC-541) witness: the only exported
/// EIP-3009 entry point is [`prepare_transfer_with_verified_approval`], which
/// requires a [`VerifiedApproval`] and derives the binding from it.
pub(crate) fn prepare_transfer_with_authorization(
    domain: Eip3009Domain,
    authorization: TransferWithAuthorizationInput,
    binding: &ApprovalBinding,
    now_unix_seconds: u64,
    nonce_store: &dyn Eip3009NonceStore,
) -> Result<PreparedTransferWithAuthorization, SettlementError> {
    if domain.name.trim().is_empty()
        || domain.version.trim().is_empty()
        || domain.verifying_contract.trim().is_empty()
    {
        return Err(SettlementError::InvalidInput(
            "EIP-3009 domain fields are required".to_string(),
        ));
    }
    if authorization.from_address.trim().is_empty()
        || authorization.to_address.trim().is_empty()
        || authorization.nonce.trim().is_empty()
    {
        return Err(SettlementError::InvalidInput(
            "EIP-3009 authorization requires from, to, and nonce".to_string(),
        ));
    }
    if authorization.value_minor_units == 0
        || authorization.valid_before <= authorization.valid_after
    {
        return Err(SettlementError::InvalidInput(
            "EIP-3009 authorization requires non-zero value and a valid time window".to_string(),
        ));
    }

    let verifying_contract = Address::from_str(&domain.verifying_contract)
        .map_err(|error| SettlementError::InvalidInput(error.to_string()))?;
    let from = Address::from_str(&authorization.from_address)
        .map_err(|error| SettlementError::InvalidInput(error.to_string()))?;
    let to = Address::from_str(&authorization.to_address)
        .map_err(|error| SettlementError::InvalidInput(error.to_string()))?;
    let nonce = B256::from_str(&authorization.nonce)
        .map_err(|error| SettlementError::InvalidInput(error.to_string()))?;

    // (2) Time window vs. current time: accept only when
    // valid_before > now > valid_after. Fail closed outside the window.
    if now_unix_seconds <= authorization.valid_after {
        return Err(SettlementError::InvalidBinding(format!(
            "EIP-3009 authorization is not yet valid: now {now_unix_seconds} <= validAfter {}",
            authorization.valid_after
        )));
    }
    if now_unix_seconds >= authorization.valid_before {
        return Err(SettlementError::InvalidBinding(format!(
            "EIP-3009 authorization is expired: now {now_unix_seconds} >= validBefore {}",
            authorization.valid_before
        )));
    }

    // (3) Authorization must not outlive the governing approval. A signed
    // transfer remains broadcastable on-chain until valid_before, so reject
    // any authorization whose window outlasts approval_expires_at. Fail
    // closed so a captured signature cannot be broadcast after the approval
    // that governs it has expired.
    if authorization.valid_before > binding.approval_expires_at {
        return Err(SettlementError::InvalidBinding(format!(
            "EIP-3009 authorization outlives approval: validBefore {} > approval expiry {}",
            authorization.valid_before, binding.approval_expires_at
        )));
    }

    // (4) Approval binding: chain / payee / amount / token must match the
    // governing approval. Parse the bound payee through the same address
    // codec so checksum vs. lowercase hex compare equal. Fail closed on
    // any mismatch.
    if domain.chain_id != binding.chain_id {
        return Err(SettlementError::InvalidBinding(format!(
            "EIP-3009 chain mismatch: domain chain_id {} != approval-bound chain_id {}",
            domain.chain_id, binding.chain_id
        )));
    }
    let bound_payee = Address::from_str(&binding.payee_address).map_err(|error| {
        SettlementError::InvalidBinding(format!("approval-bound payee address invalid: {error}"))
    })?;
    if to != bound_payee {
        return Err(SettlementError::InvalidBinding(
            "EIP-3009 payee mismatch: authorization `to` is not the approval-bound payee"
                .to_string(),
        ));
    }
    if authorization.value_minor_units != binding.amount_minor_units {
        return Err(SettlementError::InvalidBinding(format!(
            "EIP-3009 amount mismatch: authorization value {} != approval-bound amount {}",
            authorization.value_minor_units, binding.amount_minor_units
        )));
    }
    // Token contract: the domain `verifying_contract` selects the token the
    // signed transfer actually moves. The EIP-3009 lane REQUIRES the approval
    // to pin a token contract: a symbol alone does not identify the on-chain
    // token, so a captured authorization could otherwise be redirected to a
    // different token contract on the same chain with the same payee and
    // numeric amount. Fail closed when the binding carries no contract, then
    // assert the domain contract equals it. Compare parsed Address bytes so
    // checksum vs lowercase hex compare equal. (`verifying_contract` was
    // already parsed above.)
    let bound_token_contract = binding.token_contract.as_deref().ok_or_else(|| {
        SettlementError::InvalidBinding(
            "EIP-3009 requires an approval-bound token contract: a symbol alone cannot pin \
             the on-chain token the signed transfer targets"
                .to_string(),
        )
    })?;
    let bound_contract = Address::from_str(bound_token_contract.trim()).map_err(|error| {
        SettlementError::InvalidBinding(format!(
            "approval-bound token contract address invalid: {error}"
        ))
    })?;
    if verifying_contract != bound_contract {
        return Err(SettlementError::InvalidBinding(
            "EIP-3009 token contract mismatch: domain verifyingContract is not the \
             approval-bound token contract"
                .to_string(),
        ));
    }

    // (1) Single-use nonce: record AFTER the cheap fail-closed checks so a
    // rejected authorization does not consume its nonce, but BEFORE
    // returning a broadcastable digest so the first successful preparation
    // is the only one. Retain until the authorization's own expiry.
    //
    // Key the store on the PARSED canonical bytes (`from` Address, `nonce`
    // B256) rendered as their canonical lowercase `0x` hex, not on the
    // caller's raw text. `Address::from_str`/`B256::from_str` accept both
    // `0x`-prefixed and bare hex and either casing, so two submissions that
    // differ only in prefix/casing would otherwise lowercase to DIFFERENT
    // raw keys and the second would be treated as Fresh, evading replay
    // detection. Canonicalizing here closes that gap.
    //
    // Scope the nonce by the EIP-712 domain (chain id + verifying contract)
    // as well. Per EIP-3009 the same random `(from, nonce)` is an independent
    // authorization on each token contract (and chain): the on-chain nonce
    // state lives in the token contract, and the domain separator already
    // distinguishes the signatures. Keying only on `(from, nonce)` would
    // reject a legitimate second authorization that reuses the same nonce
    // value for a different token (for example USDC vs EURC) or chain. Folding
    // the chain id and canonical verifying-contract bytes into the nonce key
    // keeps each (chain, contract, from, nonce) tuple distinct while still
    // canonicalizing the parsed bytes.
    let canonical_from = format!("0x{}", hex::encode(from.as_slice()));
    let canonical_contract = format!("0x{}", hex::encode(verifying_contract.as_slice()));
    let canonical_nonce = format!(
        "{}:{}:0x{}",
        domain.chain_id,
        canonical_contract,
        hex::encode(nonce.as_slice())
    );
    match nonce_store.record_if_fresh(
        &canonical_from,
        &canonical_nonce,
        authorization.valid_before,
    )? {
        NonceOutcome::Fresh => {}
        NonceOutcome::Replayed => {
            return Err(SettlementError::InvalidBinding(
                "EIP-3009 authorization nonce has already been used (replay rejected)".to_string(),
            ));
        }
    }

    let domain_typehash = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let domain_separator = keccak256(
        (
            domain_typehash,
            keccak256(domain.name.as_bytes()),
            keccak256(domain.version.as_bytes()),
            U256::from(domain.chain_id),
            verifying_contract,
        )
            .abi_encode(),
    );
    let auth_typehash = keccak256(
        b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)",
    );
    let struct_hash = keccak256(
        (
            auth_typehash,
            from,
            to,
            U256::from(authorization.value_minor_units),
            U256::from(authorization.valid_after),
            U256::from(authorization.valid_before),
            nonce,
        )
            .abi_encode(),
    );
    let mut digest_bytes = Vec::with_capacity(66);
    digest_bytes.extend_from_slice(&[0x19, 0x01]);
    digest_bytes.extend_from_slice(domain_separator.as_slice());
    digest_bytes.extend_from_slice(struct_hash.as_slice());
    let authorization_digest = keccak256(digest_bytes);

    Ok(PreparedTransferWithAuthorization {
        domain,
        authorization,
        domain_separator: format!("0x{}", hex::encode(domain_separator)),
        struct_hash: format!("0x{}", hex::encode(struct_hash)),
        authorization_digest: format!("0x{}", hex::encode(authorization_digest)),
    })
}

/// Prepare an EIP-3009 authorization digest bound to a *verified* governing
/// approval (C2 / BAC-541).
///
/// This is the C2-strengthened entry point: rather than trusting a
/// caller-supplied [`ApprovalBinding`] (the C3 / BAC-542 seam), it derives
/// the binding from a [`VerifiedApproval`] that
/// [`verify_governed_approval`] could only have produced after checking the
/// token's signature, decision, validity window, approver identity, and
/// intent coverage. The lane-level chain / payee / amount / nonce / window
/// assertions in [`prepare_transfer_with_authorization`] then run exactly as
/// before against that trusted binding, so a captured authorization still
/// cannot be redirected, inflated, replayed, or re-chained.
///
/// The `VerifiedApproval` witness is CONSUMED by value, so a single witness
/// prepares a single transfer and cannot be reused with a fresh EIP-3009 nonce
/// to prepare another. `now_unix_seconds` is the lane-use clock: the approval's
/// `approval_expires_at` is re-checked here before any digest is built, so an
/// approval verified just before expiry and held cannot authorize a transfer
/// prepared after it lapses.
///
/// The approval's single-use replay slot is consumed HERE, immediately
/// before the prepared digest is returned: `(request_id, intent_hash)` is
/// recorded into `replay_store`, so the first issued settlement artifact
/// wins across every lane sharing the store and a lane-level rejection never
/// burns the slot. Ordering note: the EIP-3009 nonce is recorded inside the
/// inner preparation, so an authorization presented with an
/// already-consumed approval leaves its own nonce consumed. That is
/// fail-closed and only pins the replayed presentation's authorization; a
/// legitimate new spend carries its own approval and its own nonce.
pub fn prepare_transfer_with_verified_approval(
    domain: Eip3009Domain,
    authorization: TransferWithAuthorizationInput,
    approval: VerifiedApproval,
    now_unix_seconds: u64,
    nonce_store: &dyn Eip3009NonceStore,
    replay_store: &dyn ApprovalReplayStore,
) -> Result<PreparedTransferWithAuthorization, SettlementError> {
    let binding = approval.binding();
    // Lane-use expiry: re-check the approval window against the lane-use clock
    // before binding. `prepare_transfer_with_authorization` already rejects an
    // authorization whose `valid_before` outlives `approval_expires_at`, but it
    // is the EIP-3009 window (not the approval window) it checks against `now`;
    // re-check the approval window itself here so a held witness cannot prepare
    // a transfer after the approval has lapsed.
    binding.assert_not_expired_at("EIP-3009", now_unix_seconds)?;
    let prepared = prepare_transfer_with_authorization(
        domain,
        authorization,
        binding,
        now_unix_seconds,
        nonce_store,
    )?;

    // Consume the single-use slot LAST: the digest exists and every lane
    // assertion has passed, so a rejection anywhere above leaves the
    // approval spendable by a corrected attempt.
    consume_replay_slot_at_issuance(&approval, replay_store)?;
    Ok(prepared)
}

/// Evaluate a Circle nanopayment candidate straight off a dispatch with NO
/// approval binding.
///
/// This is the legacy Circle preparation path. It is `pub(crate)` so
/// downstream cannot bypass the C2 (BAC-541) witness: the only exported Circle
/// entry point is [`evaluate_circle_nanopayment_with_verified_approval`],
/// which requires a [`VerifiedApproval`] and asserts the dispatch against the
/// verified binding before delegating here.
pub(crate) fn evaluate_circle_nanopayment(
    dispatch: &Web3SettlementDispatchArtifact,
    policy: &CircleNanopaymentPolicy,
) -> Result<Option<PreparedCircleNanopayment>, SettlementError> {
    if !policy.enabled {
        return Ok(None);
    }
    if !policy.operator_managed_custody_explicit {
        return Err(SettlementError::InvalidInput(
            "Circle nanopayment policy must keep operator-managed custody explicit".to_string(),
        ));
    }
    if !policy
        .supported_chain_ids
        .iter()
        .any(|chain_id| chain_id == &dispatch.chain_id)
    {
        return Ok(None);
    }
    if !policy
        .supported_token_symbols
        .iter()
        .any(|symbol| symbol == &dispatch.settlement_amount.currency)
    {
        return Ok(None);
    }
    if dispatch.settlement_amount.units > policy.max_amount_minor_units {
        return Ok(None);
    }
    Ok(Some(PreparedCircleNanopayment {
        payment_id: format!(
            "chio-circle-{}",
            &sha256(
                format!(
                    "{}:{}:{}",
                    dispatch.dispatch_id, dispatch.chain_id, dispatch.settlement_amount.units
                )
                .as_bytes()
            )
            .to_hex()[..16]
        ),
        managed_balance_id: policy.managed_balance_id.clone(),
        chain_id: dispatch.chain_id.clone(),
        amount_minor_units: dispatch.settlement_amount.units,
        currency: dispatch.settlement_amount.currency.clone(),
        beneficiary_address: dispatch.beneficiary_address.clone(),
        dispatch_id: dispatch.dispatch_id.clone(),
    }))
}

/// Evaluate a Circle nanopayment candidate bound to a *verified* governing
/// approval (C2 / BAC-541).
///
/// The Circle lane otherwise prepares an operator-custodied payout straight
/// off the dispatch with no approval check. This entry point asserts the
/// dispatch's chain / payee / amount / token against the `approval.binding()`
/// derived by [`verify_governed_approval`] BEFORE delegating to
/// [`evaluate_circle_nanopayment`]. The token check compares the dispatch's
/// `settlement_amount.currency` (the symbol Circle settles in) against the
/// approval-bound token, so a captured approval cannot be redirected to a
/// different token. A mismatch fails closed (it is a hard error, distinct
/// from the policy-driven `Ok(None)` "not a candidate" outcome, since an
/// approval-bound spend that disagrees with the dispatch must never be
/// silently dropped).
///
/// The numeric EIP-155 chain id is derived from the dispatch's namespaced
/// `chain_id` string INSIDE the wrapper via [`parse_eip155_chain_id`], so a
/// caller cannot supply a chain that disagrees with the dispatch; a dispatch
/// whose chain does not match the approval-bound chain fails closed.
///
/// The `VerifiedApproval` witness is CONSUMED by value so a single witness
/// evaluates a single Circle candidate and cannot be reused. `now_unix_seconds`
/// is the lane-use clock: the approval's `approval_expires_at` is re-checked
/// here, so a witness verified just before expiry and held cannot authorize a
/// Circle payout prepared after it lapses.
///
/// The approval's single-use replay slot is consumed HERE, and only when a
/// payout is actually prepared: `(request_id, intent_hash)` is recorded into
/// `replay_store` immediately before returning `Ok(Some(_))`. The
/// policy-driven `Ok(None)` "not a candidate" outcome issues no artifact and
/// leaves the slot unconsumed, so the same approval can still settle on
/// another lane; the first issued artifact wins across every lane sharing
/// the store.
pub fn evaluate_circle_nanopayment_with_verified_approval(
    dispatch: &Web3SettlementDispatchArtifact,
    policy: &CircleNanopaymentPolicy,
    approval: VerifiedApproval,
    now_unix_seconds: u64,
    replay_store: &dyn ApprovalReplayStore,
) -> Result<Option<PreparedCircleNanopayment>, SettlementError> {
    let binding = approval.binding();

    // Lane-use expiry: re-check the approval window against the lane-use clock
    // so a held witness cannot authorize a payout after the approval lapses.
    binding.assert_not_expired_at("Circle", now_unix_seconds)?;

    let dispatch_chain_id = parse_eip155_chain_id(&dispatch.chain_id)?;
    if dispatch_chain_id != binding.chain_id {
        return Err(SettlementError::InvalidBinding(format!(
            "Circle chain mismatch: dispatch chain {dispatch_chain_id} != approval-bound chain {}",
            binding.chain_id
        )));
    }

    let dispatch_payee =
        Address::from_str(dispatch.beneficiary_address.trim()).map_err(|error| {
            SettlementError::InvalidBinding(format!(
                "Circle dispatch beneficiary address invalid: {error}"
            ))
        })?;
    let bound_payee = Address::from_str(binding.payee_address.trim()).map_err(|error| {
        SettlementError::InvalidBinding(format!("approval-bound payee address invalid: {error}"))
    })?;
    if dispatch_payee != bound_payee {
        return Err(SettlementError::InvalidBinding(
            "Circle payee mismatch: dispatch beneficiary is not the approval-bound payee"
                .to_string(),
        ));
    }

    if u128::from(dispatch.settlement_amount.units) != binding.amount_minor_units {
        return Err(SettlementError::InvalidBinding(format!(
            "Circle amount mismatch: dispatch amount {} != approval-bound amount {}",
            dispatch.settlement_amount.units, binding.amount_minor_units
        )));
    }

    // Token: the dispatch currency Circle would settle in must be the
    // approval-bound token, so a captured approval cannot be redirected to a
    // different token symbol.
    binding.assert_token_symbol("Circle", &dispatch.settlement_amount.currency)?;

    // Dispatch identity: the prepared payout copies `dispatch.dispatch_id`. As
    // on the x402 lane, the approval economics do not pin WHICH dispatch the
    // witness may settle, so without this a verified approval could be paired
    // with a DIFFERENT dispatch carrying the same economics and produce a payout
    // for that other dispatch. The witness gate signature-pins `dispatch_id`, so
    // asserting the live dispatch id against it ties the witness to the approved
    // dispatch. A dispatch with the same economics but a different `dispatch_id`
    // fails closed.
    binding.assert_dispatch_id("Circle", &dispatch.dispatch_id)?;

    let prepared = evaluate_circle_nanopayment(dispatch, policy)?;
    if prepared.is_some() {
        // Consume the single-use slot only when a payout artifact is issued:
        // the policy-driven None outcome settles nothing, so the approval
        // stays spendable (on this lane or another).
        consume_replay_slot_at_issuance(&approval, replay_store)?;
    }
    Ok(prepared)
}

pub fn prepare_paymaster_compatibility(
    dispatch: &Web3SettlementDispatchArtifact,
    policy: &Erc4337PaymasterPolicy,
    user_operation_hash: &str,
    sponsor_gas_limit: u64,
    estimated_reimbursement_minor_units: u64,
) -> Result<PreparedPaymasterCompatibility, SettlementError> {
    if user_operation_hash.trim().is_empty() {
        return Err(SettlementError::InvalidInput(
            "ERC-4337 compatibility requires a user operation hash".to_string(),
        ));
    }
    let supported_chain = policy
        .supported_chain_ids
        .iter()
        .any(|chain_id| chain_id == &dispatch.chain_id);
    let within_budget = sponsor_gas_limit <= policy.max_sponsor_gas_limit
        && estimated_reimbursement_minor_units <= policy.max_reimbursement_minor_units;
    let allowed = supported_chain && within_budget && policy.settlement_deduction_explicit;
    let rejection_reason = if allowed {
        None
    } else if !supported_chain {
        Some("requested chain is outside the bounded paymaster surface".to_string())
    } else if !policy.settlement_deduction_explicit {
        Some(
            "paymaster reimbursement must remain an explicit settlement-side deduction".to_string(),
        )
    } else {
        Some("requested sponsorship exceeds the bounded gas or reimbursement policy".to_string())
    };

    Ok(PreparedPaymasterCompatibility {
        dispatch_id: dispatch.dispatch_id.clone(),
        chain_id: dispatch.chain_id.clone(),
        entry_point: policy.entry_point.clone(),
        paymaster_address: policy.paymaster_address.clone(),
        user_operation_hash: user_operation_hash.to_string(),
        sponsor_gas_limit,
        estimated_reimbursement_minor_units,
        allowed,
        rejection_reason,
    })
}

#[cfg(test)]
#[path = "payments_tests.rs"]
mod tests;
