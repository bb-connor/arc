use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Mutex;

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::SolValue;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedTransactionIntent,
};
use chio_core::crypto::PublicKey;
use chio_core::hashing::sha256;
use chio_core::web3::settlement::Web3SettlementDispatchArtifact;
use serde::{Deserialize, Serialize};

use crate::SettlementError;

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

pub fn build_x402_payment_requirements(
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
        capability_id: dispatch
            .capital_instruction
            .body
            .query
            .capability_id
            .clone()
            .unwrap_or_else(|| dispatch.dispatch_id.clone()),
        amount_minor_units: dispatch.settlement_amount.units,
        currency: dispatch.settlement_amount.currency.clone(),
        settlement_mode,
        governed_authorization_required: true,
    })
}

/// Build x402 payment requirements bound to a verified governing approval
/// (C2 / BAC-541).
///
/// The x402 lane advertises `governed_authorization_required` as a bare
/// bool; on its own that flag is unenforced. This entry point closes the
/// loop: it asserts the live dispatch's chain / payee / amount / token
/// against the `approval.binding()` produced by [`verify_governed_approval`],
/// so the requirements can only be built when a real, verified
/// [`GovernedApprovalToken`] authorized exactly this spend. The token check
/// requires the approval-bound token symbol to appear in `accepted_tokens`,
/// so x402 cannot offer to settle a governed spend in a token the approval
/// never authorized. Any mismatch fails closed.
///
/// `chain_eip155_id` is the numeric EIP-155 chain id the caller resolved
/// for the dispatch's `chain_id` string (e.g. `8453` for `"eip155:8453"`);
/// it is what the approval binds, since the binding carries a numeric chain
/// id while the dispatch carries the namespaced string.
pub fn build_x402_payment_requirements_with_verified_approval(
    dispatch: &Web3SettlementDispatchArtifact,
    facilitator_url: &str,
    resource: &str,
    accepted_tokens: Vec<String>,
    settlement_mode: X402SettlementMode,
    chain_eip155_id: u64,
    approval: &VerifiedApproval,
) -> Result<X402PaymentRequirements, SettlementError> {
    let binding = approval.binding();

    // Chain: the caller-resolved numeric chain id for this dispatch must be
    // the chain the approval authorized.
    if chain_eip155_id != binding.chain_id {
        return Err(SettlementError::InvalidBinding(format!(
            "x402 chain mismatch: dispatch chain {chain_eip155_id} != approval-bound chain {}",
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

    // Token: the approval-bound token must be one the x402 requirements will
    // actually accept. Otherwise the requirements could offer to settle this
    // governed spend in a token the approval never authorized. Compared
    // case-insensitively after trimming.
    if !accepted_tokens.iter().any(|token| {
        token
            .trim()
            .eq_ignore_ascii_case(binding.token_symbol.trim())
    }) {
        return Err(SettlementError::InvalidBinding(format!(
            "x402 token mismatch: approval-bound token {:?} is not in the accepted tokens {:?}",
            binding.token_symbol, accepted_tokens
        )));
    }

    build_x402_payment_requirements(
        dispatch,
        facilitator_url,
        resource,
        accepted_tokens,
        settlement_mode,
    )
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
/// themselves, tied to the approval that governs the spend. C3 (BAC-542)
/// requires the prepared authorization to be bound to its governing
/// approval so a captured signature cannot be redirected to a different
/// payee, inflated to a different amount, or replayed on a different chain.
///
/// This type is the seam to C2 (BAC-541): once a verified
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
/// `*_with_verified_approval` entry points take this by reference and assert
/// the dispatch/authorization against `binding`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedApproval {
    /// The intent hash the verified token committed to (== the recomputed
    /// `binding_hash()` of the intent the caller passed in).
    governed_intent_hash: String,
    /// The approval token id, retained for receipts / audit.
    approval_id: String,
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
/// 5. **Intent coverage.** `intent.binding_hash()` must equal
///    `token.governed_intent_hash`, proving the approval covers THIS
///    settlement and not some other intent.
///
/// `binding` is the chain/payee/amount the caller resolved from `intent`.
/// It is returned inside the [`VerifiedApproval`] for the lanes to assert
/// against, but note (see module trust-path docs) that the binding's
/// numeric agreement with the intent cannot be enforced here; the lanes'
/// own assertions against the live dispatch are the second, independent
/// economic check.
pub fn verify_governed_approval(
    token: &GovernedApprovalToken,
    intent: &GovernedTransactionIntent,
    expected_approver: &PublicKey,
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

    // (5) Intent coverage. Recompute the canonical intent hash and compare
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

    Ok(VerifiedApproval {
        governed_intent_hash: token.governed_intent_hash.clone(),
        approval_id: token.id.clone(),
        binding,
    })
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
/// C3 (BAC-542) money-safety invariants before any signature is broadcast:
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
///    approval (seam to C2/BAC-541).
///
/// All checks fail closed. The nonce is recorded only after the time-window,
/// expiry, and binding checks pass, so a rejected authorization does not burn
/// its nonce.
pub fn prepare_transfer_with_authorization(
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
pub fn prepare_transfer_with_verified_approval(
    domain: Eip3009Domain,
    authorization: TransferWithAuthorizationInput,
    approval: &VerifiedApproval,
    now_unix_seconds: u64,
    nonce_store: &dyn Eip3009NonceStore,
) -> Result<PreparedTransferWithAuthorization, SettlementError> {
    prepare_transfer_with_authorization(
        domain,
        authorization,
        approval.binding(),
        now_unix_seconds,
        nonce_store,
    )
}

pub fn evaluate_circle_nanopayment(
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
/// `chain_eip155_id` is the numeric EIP-155 chain id the caller resolved for
/// the dispatch's namespaced `chain_id` string, matching what the approval
/// binds.
pub fn evaluate_circle_nanopayment_with_verified_approval(
    dispatch: &Web3SettlementDispatchArtifact,
    policy: &CircleNanopaymentPolicy,
    chain_eip155_id: u64,
    approval: &VerifiedApproval,
) -> Result<Option<PreparedCircleNanopayment>, SettlementError> {
    let binding = approval.binding();

    if chain_eip155_id != binding.chain_id {
        return Err(SettlementError::InvalidBinding(format!(
            "Circle chain mismatch: dispatch chain {chain_eip155_id} != approval-bound chain {}",
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

    evaluate_circle_nanopayment(dispatch, policy)
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
mod tests {
    use super::{
        build_x402_payment_requirements, build_x402_payment_requirements_with_verified_approval,
        evaluate_circle_nanopayment, evaluate_circle_nanopayment_with_verified_approval,
        prepare_paymaster_compatibility, prepare_transfer_with_authorization,
        prepare_transfer_with_verified_approval, verify_governed_approval, ApprovalBinding,
        CircleNanopaymentPolicy, Eip3009Domain, Eip3009NonceStore, Erc4337PaymasterPolicy,
        InMemoryEip3009NonceStore, NonceOutcome, TransferWithAuthorizationInput, VerifiedApproval,
        X402SettlementMode,
    };
    use chio_core::capability::governance::{
        GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
        GovernedTransactionIntent,
    };
    use chio_core::crypto::Keypair;
    use chio_core::web3::settlement::Web3SettlementDispatchArtifact;

    use chio_test_support::prelude::*;

    /// EIP-155 chain id of the sample dispatch (`"eip155:8453"`).
    const DISPATCH_CHAIN_ID: u64 = 8453;
    /// Beneficiary in `CHIO_WEB3_SETTLEMENT_DISPATCH_EXAMPLE.json`.
    const DISPATCH_PAYEE: &str = "0x2222222222222222222222222222222222222222";
    /// Settlement amount (minor units) in the example dispatch.
    const DISPATCH_AMOUNT: u128 = 150;
    /// Token/currency symbol of the example dispatch (`settlement_amount.currency`).
    const DISPATCH_TOKEN_SYMBOL: &str = "USD";
    /// A `now` inside any token window built by `approval_window`.
    const APPROVAL_NOW: u64 = 1_744_000_300;

    /// Build a minimal governed intent. Its canonical hash is what the
    /// approval token commits to; the discrete chain/amount/payee live in
    /// the separately-resolved `ApprovalBinding`.
    fn sample_intent(id: &str) -> GovernedTransactionIntent {
        GovernedTransactionIntent {
            id: id.to_string(),
            server_id: "settlement-server".to_string(),
            tool_name: "transfer_funds".to_string(),
            purpose: "C2 settlement binding test".to_string(),
            max_amount: None,
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: None,
        }
    }

    /// Mint a signed, approved token over `intent`'s binding hash using
    /// `approver`, valid across `APPROVAL_NOW`.
    fn signed_approval(
        approver: &Keypair,
        subject: &Keypair,
        intent: &GovernedTransactionIntent,
    ) -> GovernedApprovalToken {
        let body = GovernedApprovalTokenBody {
            id: "approval-1".to_string(),
            approver: approver.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: intent.binding_hash().test_unwrap(),
            request_id: "req-1".to_string(),
            issued_at: APPROVAL_NOW - 100,
            expires_at: APPROVAL_NOW + 100,
            decision: GovernedApprovalDecision::Approved,
        };
        GovernedApprovalToken::sign(body, approver).test_unwrap()
    }

    /// A binding that matches the sample dispatch's chain/payee/amount/token.
    fn dispatch_binding() -> ApprovalBinding {
        ApprovalBinding {
            chain_id: DISPATCH_CHAIN_ID,
            payee_address: DISPATCH_PAYEE.to_string(),
            amount_minor_units: DISPATCH_AMOUNT,
            token_symbol: DISPATCH_TOKEN_SYMBOL.to_string(),
            // The dispatch lanes identify their token by symbol, not by a
            // contract address, so no contract is pinned here.
            token_contract: None,
            // Matches the `signed_approval` window so the EIP-3009 expiry
            // bound never trips for dispatch-derived bindings.
            approval_expires_at: APPROVAL_NOW + 100,
        }
    }

    /// Verify a fresh approval for `binding`, returning the witness.
    fn verified_for(binding: ApprovalBinding) -> VerifiedApproval {
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let intent = sample_intent("intent-dispatch");
        let token = signed_approval(&approver, &subject, &intent);
        verify_governed_approval(
            &token,
            &intent,
            &approver.public_key(),
            binding,
            APPROVAL_NOW,
        )
        .test_unwrap()
    }

    fn sample_dispatch() -> Web3SettlementDispatchArtifact {
        serde_json::from_str(include_str!(
            "../../../../docs/standards/CHIO_WEB3_SETTLEMENT_DISPATCH_EXAMPLE.json"
        ))
        .test_unwrap()
    }

    const SAMPLE_CHAIN_ID: u64 = 8453;
    const SAMPLE_PAYEE: &str = "0x1000000000000000000000000000000000000002";
    const SAMPLE_VALUE: u128 = 42_000;
    const SAMPLE_VALID_AFTER: u64 = 1_744_000_000;
    const SAMPLE_VALID_BEFORE: u64 = 1_744_000_600;
    /// A `now` strictly inside `(validAfter, validBefore)`.
    const SAMPLE_NOW: u64 = 1_744_000_300;
    const SAMPLE_NONCE: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    /// The token symbol the sample approval authorizes.
    const SAMPLE_TOKEN_SYMBOL: &str = "USDC";
    /// The token contract the sample EIP-3009 domain targets; the sample
    /// binding pins this so the contract-level check passes by default.
    const SAMPLE_TOKEN_CONTRACT: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

    fn sample_domain() -> Eip3009Domain {
        Eip3009Domain {
            name: "USD Coin".to_string(),
            version: "2".to_string(),
            chain_id: SAMPLE_CHAIN_ID,
            verifying_contract: SAMPLE_TOKEN_CONTRACT.to_string(),
        }
    }

    fn sample_authorization() -> TransferWithAuthorizationInput {
        TransferWithAuthorizationInput {
            from_address: "0x1000000000000000000000000000000000000001".to_string(),
            to_address: SAMPLE_PAYEE.to_string(),
            value_minor_units: SAMPLE_VALUE,
            valid_after: SAMPLE_VALID_AFTER,
            valid_before: SAMPLE_VALID_BEFORE,
            nonce: SAMPLE_NONCE.to_string(),
        }
    }

    fn sample_binding() -> ApprovalBinding {
        ApprovalBinding {
            chain_id: SAMPLE_CHAIN_ID,
            payee_address: SAMPLE_PAYEE.to_string(),
            amount_minor_units: SAMPLE_VALUE,
            token_symbol: SAMPLE_TOKEN_SYMBOL.to_string(),
            token_contract: Some(SAMPLE_TOKEN_CONTRACT.to_string()),
            // Approval expiry at least as late as the authorization window so
            // the default sample does not trip the outlives-approval check.
            approval_expires_at: SAMPLE_VALID_BEFORE,
        }
    }

    #[test]
    fn builds_x402_requirements() {
        let dispatch = sample_dispatch();
        let requirements = build_x402_payment_requirements(
            &dispatch,
            "https://facilitator.example/x402",
            "https://tool.example/v1/run",
            vec!["USDC".to_string(), "EURC".to_string()],
            X402SettlementMode::PrepaidAuthorization,
        )
        .test_unwrap();

        assert!(requirements.governed_authorization_required);
        assert_eq!(requirements.dispatch_id, dispatch.dispatch_id);
    }

    #[test]
    fn x402_requirements_reject_blank_accepted_tokens() {
        let dispatch = sample_dispatch();

        let error = build_x402_payment_requirements(
            &dispatch,
            "https://facilitator.example/x402",
            "https://tool.example/v1/run",
            vec!["USDC".to_string(), " ".to_string()],
            X402SettlementMode::PrepaidAuthorization,
        )
        .test_unwrap_err();

        assert!(error.to_string().contains("accepted token"));
    }

    #[test]
    fn prepares_transfer_with_authorization_digest() {
        let store = InMemoryEip3009NonceStore::new();
        let prepared = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &sample_binding(),
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap();

        assert!(prepared.authorization_digest.starts_with("0x"));
        assert_eq!(prepared.authorization_digest.len(), 66);
    }

    #[test]
    fn replayed_nonce_is_rejected_on_second_use() {
        let store = InMemoryEip3009NonceStore::new();

        // First preparation with a fresh nonce succeeds.
        let first = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &sample_binding(),
            SAMPLE_NOW,
            &store,
        );
        assert!(first.is_ok(), "first use of a fresh nonce must succeed");

        // Replaying the same authorization (same from + nonce) against the
        // same store must fail closed.
        let replay = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &sample_binding(),
            SAMPLE_NOW,
            &store,
        );
        let error = replay.test_unwrap_err();
        assert!(
            error.to_string().contains("replay"),
            "second use of the same nonce must be rejected by the nonce store, got: {error}"
        );
    }

    #[test]
    fn replay_is_detected_even_with_checksum_cased_address_and_nonce() {
        // EIP-3009 token contracts consume `(from, nonce)`; a re-cased hex
        // string is the same authorizer/nonce and must not bypass replay
        // detection.
        let store = InMemoryEip3009NonceStore::new();
        let _ = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &sample_binding(),
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap();

        let mut recased = sample_authorization();
        recased.from_address = recased.from_address.to_uppercase().replace("0X", "0x");
        recased.nonce = recased.nonce.to_uppercase().replace("0X", "0x");
        let replay = prepare_transfer_with_authorization(
            sample_domain(),
            recased,
            &sample_binding(),
            SAMPLE_NOW,
            &store,
        );
        assert!(
            replay.test_unwrap_err().to_string().contains("replay"),
            "case-variant of the same (from, nonce) must still be a replay"
        );
    }

    #[test]
    fn expired_authorization_is_rejected() {
        let store = InMemoryEip3009NonceStore::new();
        // now == validBefore is outside the open window (requires now < validBefore).
        let error = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &sample_binding(),
            SAMPLE_VALID_BEFORE,
            &store,
        )
        .test_unwrap_err();
        assert!(
            error.to_string().contains("expired"),
            "an authorization at/after validBefore must be rejected, got: {error}"
        );
        assert!(
            store.is_empty().test_unwrap(),
            "a rejected (expired) authorization must not consume its nonce"
        );
    }

    #[test]
    fn not_yet_valid_authorization_is_rejected() {
        let store = InMemoryEip3009NonceStore::new();
        // now == validAfter is outside the open window (requires now > validAfter).
        let error = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &sample_binding(),
            SAMPLE_VALID_AFTER,
            &store,
        )
        .test_unwrap_err();
        assert!(
            error.to_string().contains("not yet valid"),
            "an authorization at/before validAfter must be rejected, got: {error}"
        );
        assert!(
            store.is_empty().test_unwrap(),
            "a rejected (not-yet-valid) authorization must not consume its nonce"
        );
    }

    #[test]
    fn chain_amount_and_payee_binding_mismatches_are_rejected() {
        let store = InMemoryEip3009NonceStore::new();

        // Chain mismatch.
        let mut wrong_chain = sample_binding();
        wrong_chain.chain_id = 1;
        let error = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &wrong_chain,
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap_err();
        assert!(error.to_string().contains("chain mismatch"), "got: {error}");

        // Amount mismatch.
        let mut wrong_amount = sample_binding();
        wrong_amount.amount_minor_units = SAMPLE_VALUE + 1;
        let error = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &wrong_amount,
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap_err();
        assert!(
            error.to_string().contains("amount mismatch"),
            "got: {error}"
        );

        // Payee mismatch.
        let mut wrong_payee = sample_binding();
        wrong_payee.payee_address = "0x1000000000000000000000000000000000000009".to_string();
        let error = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &wrong_payee,
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap_err();
        assert!(error.to_string().contains("payee mismatch"), "got: {error}");

        // None of the rejected bindings may have consumed the nonce.
        assert!(
            store.is_empty().test_unwrap(),
            "binding-mismatch rejections must not consume the nonce"
        );
    }

    #[test]
    fn payee_binding_accepts_checksum_vs_lowercase_hex() {
        // The bound payee may be checksum-cased while the authorization is
        // lowercase (or vice versa); they must compare equal.
        let store = InMemoryEip3009NonceStore::new();
        let mut binding = sample_binding();
        binding.payee_address = SAMPLE_PAYEE.to_uppercase().replace("0X", "0x");
        let prepared = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &binding,
            SAMPLE_NOW,
            &store,
        );
        assert!(
            prepared.is_ok(),
            "checksum vs lowercase payee hex must be treated as the same address"
        );
    }

    #[test]
    fn nonce_store_records_only_after_checks_pass() {
        // A fresh, in-window, correctly-bound authorization records exactly
        // one nonce entry.
        let store = InMemoryEip3009NonceStore::new();
        assert_eq!(
            store.record_if_fresh("0xabc", "0xdef", 0).test_unwrap(),
            NonceOutcome::Fresh
        );
        assert_eq!(
            store.record_if_fresh("0xabc", "0xdef", 0).test_unwrap(),
            NonceOutcome::Replayed
        );
    }

    #[test]
    fn nonce_store_canonicalizes_prefix_and_casing() {
        // The store must collapse `0x`-prefixed vs bare and checksum vs
        // lowercase keys so none of those formatting differences can present
        // the same (from, nonce) pair as Fresh twice.
        let store = InMemoryEip3009NonceStore::new();
        assert_eq!(
            store.record_if_fresh("0xABC", "0xDEF", 0).test_unwrap(),
            NonceOutcome::Fresh
        );
        // Same bytes, prefix stripped and lowercased: must be a replay.
        assert_eq!(
            store.record_if_fresh("abc", "def", 0).test_unwrap(),
            NonceOutcome::Replayed,
            "bare-hex form of an already-recorded 0x-prefixed key must replay"
        );
        // Same bytes, re-cased with prefix: must also replay.
        assert_eq!(
            store.record_if_fresh("0xAbC", "0xDeF", 0).test_unwrap(),
            NonceOutcome::Replayed,
            "re-cased form of an already-recorded key must replay"
        );
    }

    #[test]
    fn replay_is_detected_across_prefixed_and_bare_authorization_forms() {
        // End-to-end: the SAME authorization submitted once with 0x-prefixed
        // from/nonce and again WITHOUT the prefix parses to identical
        // Address/B256 bytes. Keying the store on the parsed canonical bytes
        // means the second submission is a replay, not Fresh.
        let store = InMemoryEip3009NonceStore::new();
        let _ = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &sample_binding(),
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap();

        // Strip the `0x` prefix from from/nonce; Address/B256 parse both.
        let mut bare = sample_authorization();
        bare.from_address = bare
            .from_address
            .strip_prefix("0x")
            .unwrap_or(&bare.from_address)
            .to_string();
        bare.nonce = bare
            .nonce
            .strip_prefix("0x")
            .unwrap_or(&bare.nonce)
            .to_string();

        let replay = prepare_transfer_with_authorization(
            sample_domain(),
            bare,
            &sample_binding(),
            SAMPLE_NOW,
            &store,
        );
        assert!(
            replay.test_unwrap_err().to_string().contains("replay"),
            "the unprefixed form of an already-prepared authorization must be a replay"
        );
    }

    #[test]
    fn authorization_outliving_approval_is_rejected() {
        // The EIP-3009 window is open and well-bound, but valid_before runs
        // past the approval's expiry: the signed transfer would stay
        // broadcastable after the approval lapses, so it must fail closed and
        // not consume the nonce.
        let store = InMemoryEip3009NonceStore::new();
        let mut short_approval = sample_binding();
        short_approval.approval_expires_at = SAMPLE_VALID_BEFORE - 1;
        let error = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &short_approval,
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap_err();
        assert!(
            error.to_string().contains("outlives approval"),
            "an authorization that outlives its approval must be rejected, got: {error}"
        );
        assert!(
            store.is_empty().test_unwrap(),
            "an authorization rejected for outliving its approval must not consume its nonce"
        );
    }

    #[test]
    fn authorization_ending_exactly_at_approval_expiry_is_accepted() {
        // valid_before == approval_expires_at is the boundary the approval
        // still covers; it must be accepted.
        let store = InMemoryEip3009NonceStore::new();
        let mut binding = sample_binding();
        binding.approval_expires_at = SAMPLE_VALID_BEFORE;
        let prepared = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &binding,
            SAMPLE_NOW,
            &store,
        );
        assert!(
            prepared.is_ok(),
            "valid_before == approval_expires_at must be within the approval window"
        );
    }

    #[test]
    fn token_contract_mismatch_is_rejected() {
        // The approval is bound to a DIFFERENT token contract than the
        // EIP-3009 domain targets. Even with matching chain, payee, and
        // amount, redirecting to another token on the same chain must fail
        // closed and not consume the nonce.
        let store = InMemoryEip3009NonceStore::new();
        let mut wrong_token = sample_binding();
        wrong_token.token_contract = Some("0x4444444444444444444444444444444444444444".to_string());
        let error = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &wrong_token,
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap_err();
        assert!(
            error.to_string().contains("token contract mismatch"),
            "a different token contract on the same chain must be rejected, got: {error}"
        );
        assert!(
            store.is_empty().test_unwrap(),
            "a token-contract-mismatch rejection must not consume the nonce"
        );
    }

    #[test]
    fn token_contract_binding_accepts_checksum_vs_lowercase_hex() {
        // The bound token contract may be cased differently from the domain
        // verifyingContract; they must compare equal as parsed addresses.
        let store = InMemoryEip3009NonceStore::new();
        let mut binding = sample_binding();
        binding.token_contract = Some(SAMPLE_TOKEN_CONTRACT.to_lowercase());
        let prepared = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &binding,
            SAMPLE_NOW,
            &store,
        );
        assert!(
            prepared.is_ok(),
            "checksum vs lowercase token contract hex must be the same address"
        );
    }

    #[test]
    fn absent_token_contract_is_rejected_for_eip3009() {
        // The EIP-3009 lane REQUIRES a bound token contract: a symbol alone
        // cannot pin the on-chain token, so a captured authorization could be
        // redirected to a different token contract on the same chain. With no
        // bound contract the lane must fail closed and not consume the nonce.
        let store = InMemoryEip3009NonceStore::new();
        let mut binding = sample_binding();
        binding.token_contract = None;
        let error = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &binding,
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires an approval-bound token contract"),
            "an EIP-3009 binding with no token contract must be rejected, got: {error}"
        );
        assert!(
            store.is_empty().test_unwrap(),
            "a binding rejected for an absent token contract must not consume the nonce"
        );
    }

    #[test]
    fn same_nonce_on_a_different_token_contract_is_not_a_replay() {
        // Per EIP-3009 the same `(from, nonce)` is an independent spend on a
        // different token contract: the on-chain nonce state lives in the token
        // contract and the EIP-712 domain separates the signatures. The
        // off-chain store keys the nonce by its domain (chain + verifying
        // contract), so reusing the same nonce value against a different token
        // contract must still be Fresh, not a replay.
        let store = InMemoryEip3009NonceStore::new();
        let first = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &sample_binding(),
            SAMPLE_NOW,
            &store,
        );
        assert!(first.is_ok(), "first use of a fresh nonce must succeed");

        // A different token contract on the same chain, with a binding that
        // pins that contract. Same from + nonce value, different domain.
        const OTHER_TOKEN_CONTRACT: &str = "0x4444444444444444444444444444444444444444";
        let mut other_domain = sample_domain();
        other_domain.verifying_contract = OTHER_TOKEN_CONTRACT.to_string();
        let mut other_binding = sample_binding();
        other_binding.token_contract = Some(OTHER_TOKEN_CONTRACT.to_string());

        let second = prepare_transfer_with_authorization(
            other_domain,
            sample_authorization(),
            &other_binding,
            SAMPLE_NOW,
            &store,
        );
        assert!(
            second.is_ok(),
            "the same nonce on a DIFFERENT token contract must not be a replay, got: {second:?}"
        );
        assert_eq!(
            store.len().test_unwrap(),
            2,
            "each (chain, contract, from, nonce) tuple must record a distinct nonce entry"
        );
    }

    #[test]
    fn same_nonce_on_the_same_token_contract_is_a_replay() {
        // Sibling to the cross-contract test: with the SAME domain (chain +
        // verifying contract) the same `(from, nonce)` must still be a replay,
        // so folding the contract into the key does not weaken replay
        // detection on the contract that actually consumes the nonce.
        let store = InMemoryEip3009NonceStore::new();
        let _ = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &sample_binding(),
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap();
        let replay = prepare_transfer_with_authorization(
            sample_domain(),
            sample_authorization(),
            &sample_binding(),
            SAMPLE_NOW,
            &store,
        );
        assert!(
            replay.test_unwrap_err().to_string().contains("replay"),
            "the same nonce on the same token contract must still be a replay"
        );
    }

    #[test]
    fn assert_token_symbol_is_case_insensitive_and_fails_closed() {
        let binding = sample_binding();
        // Case and surrounding whitespace must not matter.
        assert!(binding.assert_token_symbol("x402", " usdc ").is_ok());
        assert!(binding.assert_token_symbol("circle", "USDC").is_ok());
        // A genuinely different token must be rejected.
        let error = binding
            .assert_token_symbol("x402", "EURC")
            .test_unwrap_err();
        assert!(
            error.to_string().contains("token mismatch"),
            "a different token symbol must be rejected, got: {error}"
        );
    }

    #[test]
    fn evaluates_circle_nanopayment_candidate() {
        let dispatch = sample_dispatch();
        let prepared = evaluate_circle_nanopayment(
            &dispatch,
            &CircleNanopaymentPolicy {
                enabled: true,
                managed_balance_id: "bal_123".to_string(),
                supported_chain_ids: vec!["eip155:8453".to_string()],
                supported_token_symbols: vec!["USD".to_string()],
                max_amount_minor_units: 200,
                operator_managed_custody_explicit: true,
            },
        )
        .test_unwrap()
        .test_unwrap();

        assert_eq!(prepared.dispatch_id, dispatch.dispatch_id);
    }

    #[test]
    fn evaluates_paymaster_compatibility() {
        let dispatch = sample_dispatch();
        let prepared = prepare_paymaster_compatibility(
            &dispatch,
            &Erc4337PaymasterPolicy {
                entry_point: "0x1000000000000000000000000000000000000100".to_string(),
                paymaster_address: "0x1000000000000000000000000000000000000101".to_string(),
                supported_chain_ids: vec!["eip155:8453".to_string()],
                max_sponsor_gas_limit: 300_000,
                max_reimbursement_minor_units: 10,
                settlement_deduction_explicit: true,
            },
            "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            250_000,
            5,
        )
        .test_unwrap();

        assert!(prepared.allowed);
        assert!(prepared.rejection_reason.is_none());
    }

    // -----------------------------------------------------------------
    // C2 (BAC-541): GovernedApprovalToken verification gate.
    // -----------------------------------------------------------------

    #[test]
    fn verify_governed_approval_accepts_a_valid_token() {
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let intent = sample_intent("intent-ok");
        let token = signed_approval(&approver, &subject, &intent);

        let verified = verify_governed_approval(
            &token,
            &intent,
            &approver.public_key(),
            dispatch_binding(),
            APPROVAL_NOW,
        )
        .test_unwrap();

        assert_eq!(verified.approval_id(), "approval-1");
        assert_eq!(verified.governed_intent_hash(), token.governed_intent_hash);
        assert_eq!(verified.binding(), &dispatch_binding());
    }

    #[test]
    fn verify_governed_approval_rejects_a_bad_signature() {
        // A token whose signature does not match its body (forged / tampered)
        // must fail closed regardless of every other field being well-formed.
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let intent = sample_intent("intent-badsig");
        let mut token = signed_approval(&approver, &subject, &intent);

        // Tamper with the body AFTER signing so the signature no longer
        // covers it.
        token.request_id = "req-tampered".to_string();

        let error = verify_governed_approval(
            &token,
            &intent,
            &approver.public_key(),
            dispatch_binding(),
            APPROVAL_NOW,
        )
        .test_unwrap_err();
        assert!(
            error.to_string().contains("signature is invalid"),
            "tampered token must be rejected on signature, got: {error}"
        );
    }

    #[test]
    fn verify_governed_approval_rejects_an_expired_token() {
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let intent = sample_intent("intent-expired");
        let token = signed_approval(&approver, &subject, &intent);

        // now == expires_at is outside the window (validate_time requires
        // now < expires_at).
        let error = verify_governed_approval(
            &token,
            &intent,
            &approver.public_key(),
            dispatch_binding(),
            token.expires_at,
        )
        .test_unwrap_err();
        assert!(
            error.to_string().contains("validity window"),
            "an expired approval must be rejected, got: {error}"
        );
    }

    #[test]
    fn verify_governed_approval_rejects_a_denied_decision() {
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let intent = sample_intent("intent-denied");
        // Sign a DENIED token so the signature is valid but the decision is
        // not an approval.
        let body = GovernedApprovalTokenBody {
            id: "approval-denied".to_string(),
            approver: approver.public_key(),
            subject: subject.public_key(),
            governed_intent_hash: intent.binding_hash().test_unwrap(),
            request_id: "req-denied".to_string(),
            issued_at: APPROVAL_NOW - 100,
            expires_at: APPROVAL_NOW + 100,
            decision: GovernedApprovalDecision::Denied,
        };
        let token = GovernedApprovalToken::sign(body, &approver).test_unwrap();

        let error = verify_governed_approval(
            &token,
            &intent,
            &approver.public_key(),
            dispatch_binding(),
            APPROVAL_NOW,
        )
        .test_unwrap_err();
        assert!(
            error.to_string().contains("approval decision"),
            "a denied token must be rejected, got: {error}"
        );
    }

    #[test]
    fn verify_governed_approval_rejects_an_unexpected_approver() {
        // A validly-signed token from the wrong approver key is rejected:
        // signature validity alone does not establish authority.
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let intent = sample_intent("intent-wrong-approver");
        let token = signed_approval(&approver, &subject, &intent);

        let unexpected = Keypair::generate();
        let error = verify_governed_approval(
            &token,
            &intent,
            &unexpected.public_key(),
            dispatch_binding(),
            APPROVAL_NOW,
        )
        .test_unwrap_err();
        assert!(
            error.to_string().contains("expected principal"),
            "an unexpected approver must be rejected, got: {error}"
        );
    }

    #[test]
    fn verify_governed_approval_rejects_intent_not_covered_by_the_token() {
        // The token commits to intent A's hash; presenting a different
        // intent B (whose hash differs) must be rejected. This defeats
        // cross-intent replay of an otherwise-valid approval.
        let approver = Keypair::generate();
        let subject = Keypair::generate();
        let approved_intent = sample_intent("intent-A");
        let token = signed_approval(&approver, &subject, &approved_intent);

        let other_intent = sample_intent("intent-B");
        let error = verify_governed_approval(
            &token,
            &other_intent,
            &approver.public_key(),
            dispatch_binding(),
            APPROVAL_NOW,
        )
        .test_unwrap_err();
        assert!(
            error.to_string().contains("intent hash mismatch"),
            "an approval that does not cover this intent must be rejected, got: {error}"
        );
    }

    // -----------------------------------------------------------------
    // C2: x402 lane binds against the verified approval.
    // -----------------------------------------------------------------

    #[test]
    fn x402_with_verified_approval_authorizes_a_matching_dispatch() {
        let dispatch = sample_dispatch();
        let approval = verified_for(dispatch_binding());

        let requirements = build_x402_payment_requirements_with_verified_approval(
            &dispatch,
            "https://facilitator.example/x402",
            "https://tool.example/v1/run",
            // The approval-bound token (DISPATCH_TOKEN_SYMBOL) must be among
            // the accepted tokens.
            vec![DISPATCH_TOKEN_SYMBOL.to_string(), "USDC".to_string()],
            X402SettlementMode::PrepaidAuthorization,
            DISPATCH_CHAIN_ID,
            &approval,
        )
        .test_unwrap();

        assert!(requirements.governed_authorization_required);
        assert_eq!(requirements.dispatch_id, dispatch.dispatch_id);
    }

    #[test]
    fn x402_with_verified_approval_rejects_a_token_not_accepted() {
        // The approval is bound to DISPATCH_TOKEN_SYMBOL, but the x402
        // requirements would only accept a different token. Offering to
        // settle a governed spend in an unapproved token must fail closed.
        let dispatch = sample_dispatch();
        let error = build_x402_payment_requirements_with_verified_approval(
            &dispatch,
            "https://facilitator.example/x402",
            "https://tool.example/v1/run",
            vec!["USDC".to_string(), "EURC".to_string()],
            X402SettlementMode::PrepaidAuthorization,
            DISPATCH_CHAIN_ID,
            &verified_for(dispatch_binding()),
        )
        .test_unwrap_err();
        assert!(error.to_string().contains("token mismatch"), "got: {error}");
    }

    #[test]
    fn x402_with_verified_approval_rejects_binding_mismatches() {
        let dispatch = sample_dispatch();

        // Chain mismatch: caller-resolved dispatch chain != approval-bound.
        let error = build_x402_payment_requirements_with_verified_approval(
            &dispatch,
            "https://facilitator.example/x402",
            "https://tool.example/v1/run",
            vec!["USDC".to_string()],
            X402SettlementMode::PrepaidAuthorization,
            1,
            &verified_for(dispatch_binding()),
        )
        .test_unwrap_err();
        assert!(error.to_string().contains("chain mismatch"), "got: {error}");

        // Payee mismatch: approval bound to a different payee than the
        // dispatch beneficiary.
        let mut wrong_payee = dispatch_binding();
        wrong_payee.payee_address = "0x3333333333333333333333333333333333333333".to_string();
        let error = build_x402_payment_requirements_with_verified_approval(
            &dispatch,
            "https://facilitator.example/x402",
            "https://tool.example/v1/run",
            vec!["USDC".to_string()],
            X402SettlementMode::PrepaidAuthorization,
            DISPATCH_CHAIN_ID,
            &verified_for(wrong_payee),
        )
        .test_unwrap_err();
        assert!(error.to_string().contains("payee mismatch"), "got: {error}");

        // Amount mismatch: approval bound to a different amount.
        let mut wrong_amount = dispatch_binding();
        wrong_amount.amount_minor_units = DISPATCH_AMOUNT + 1;
        let error = build_x402_payment_requirements_with_verified_approval(
            &dispatch,
            "https://facilitator.example/x402",
            "https://tool.example/v1/run",
            vec!["USDC".to_string()],
            X402SettlementMode::PrepaidAuthorization,
            DISPATCH_CHAIN_ID,
            &verified_for(wrong_amount),
        )
        .test_unwrap_err();
        assert!(
            error.to_string().contains("amount mismatch"),
            "got: {error}"
        );
    }

    // -----------------------------------------------------------------
    // C2: EIP-3009 lane binds against the verified approval.
    // -----------------------------------------------------------------

    /// A verified approval whose binding matches `sample_authorization`.
    fn verified_for_eip3009_authorization() -> VerifiedApproval {
        verified_for(ApprovalBinding {
            chain_id: SAMPLE_CHAIN_ID,
            payee_address: SAMPLE_PAYEE.to_string(),
            amount_minor_units: SAMPLE_VALUE,
            token_symbol: SAMPLE_TOKEN_SYMBOL.to_string(),
            token_contract: Some(SAMPLE_TOKEN_CONTRACT.to_string()),
            approval_expires_at: SAMPLE_VALID_BEFORE,
        })
    }

    #[test]
    fn eip3009_with_verified_approval_authorizes_a_matching_authorization() {
        let store = InMemoryEip3009NonceStore::new();
        let prepared = prepare_transfer_with_verified_approval(
            sample_domain(),
            sample_authorization(),
            &verified_for_eip3009_authorization(),
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap();
        assert!(prepared.authorization_digest.starts_with("0x"));
        assert_eq!(prepared.authorization_digest.len(), 66);
    }

    #[test]
    fn eip3009_with_verified_approval_rejects_a_payee_mismatch() {
        // The verified approval authorizes a DIFFERENT payee than the
        // EIP-3009 authorization's `to`. Binding assertion fails closed and
        // the nonce is not consumed.
        let store = InMemoryEip3009NonceStore::new();
        let approval = verified_for(ApprovalBinding {
            chain_id: SAMPLE_CHAIN_ID,
            payee_address: "0x1000000000000000000000000000000000000009".to_string(),
            amount_minor_units: SAMPLE_VALUE,
            token_symbol: SAMPLE_TOKEN_SYMBOL.to_string(),
            token_contract: Some(SAMPLE_TOKEN_CONTRACT.to_string()),
            approval_expires_at: SAMPLE_VALID_BEFORE,
        });
        let error = prepare_transfer_with_verified_approval(
            sample_domain(),
            sample_authorization(),
            &approval,
            SAMPLE_NOW,
            &store,
        )
        .test_unwrap_err();
        assert!(error.to_string().contains("payee mismatch"), "got: {error}");
        assert!(
            store.is_empty().test_unwrap(),
            "a binding-mismatch rejection must not consume the nonce"
        );
    }

    #[test]
    fn eip3009_with_verified_approval_rejects_an_expired_authorization() {
        // The verified approval is fine, but the EIP-3009 authorization
        // window is closed: the lane still fails closed.
        let store = InMemoryEip3009NonceStore::new();
        let error = prepare_transfer_with_verified_approval(
            sample_domain(),
            sample_authorization(),
            &verified_for_eip3009_authorization(),
            SAMPLE_VALID_BEFORE,
            &store,
        )
        .test_unwrap_err();
        assert!(error.to_string().contains("expired"), "got: {error}");
    }

    // -----------------------------------------------------------------
    // C2: Circle lane binds against the verified approval.
    // -----------------------------------------------------------------

    fn sample_circle_policy() -> CircleNanopaymentPolicy {
        CircleNanopaymentPolicy {
            enabled: true,
            managed_balance_id: "bal_123".to_string(),
            supported_chain_ids: vec!["eip155:8453".to_string()],
            supported_token_symbols: vec!["USD".to_string()],
            max_amount_minor_units: 200,
            operator_managed_custody_explicit: true,
        }
    }

    #[test]
    fn circle_with_verified_approval_authorizes_a_matching_dispatch() {
        let dispatch = sample_dispatch();
        let prepared = evaluate_circle_nanopayment_with_verified_approval(
            &dispatch,
            &sample_circle_policy(),
            DISPATCH_CHAIN_ID,
            &verified_for(dispatch_binding()),
        )
        .test_unwrap()
        .test_unwrap();
        assert_eq!(prepared.dispatch_id, dispatch.dispatch_id);
    }

    #[test]
    fn circle_with_verified_approval_rejects_binding_mismatches() {
        let dispatch = sample_dispatch();

        // Chain mismatch.
        let error = evaluate_circle_nanopayment_with_verified_approval(
            &dispatch,
            &sample_circle_policy(),
            1,
            &verified_for(dispatch_binding()),
        )
        .test_unwrap_err();
        assert!(error.to_string().contains("chain mismatch"), "got: {error}");

        // Payee mismatch.
        let mut wrong_payee = dispatch_binding();
        wrong_payee.payee_address = "0x3333333333333333333333333333333333333333".to_string();
        let error = evaluate_circle_nanopayment_with_verified_approval(
            &dispatch,
            &sample_circle_policy(),
            DISPATCH_CHAIN_ID,
            &verified_for(wrong_payee),
        )
        .test_unwrap_err();
        assert!(error.to_string().contains("payee mismatch"), "got: {error}");

        // Amount mismatch.
        let mut wrong_amount = dispatch_binding();
        wrong_amount.amount_minor_units = DISPATCH_AMOUNT + 1;
        let error = evaluate_circle_nanopayment_with_verified_approval(
            &dispatch,
            &sample_circle_policy(),
            DISPATCH_CHAIN_ID,
            &verified_for(wrong_amount),
        )
        .test_unwrap_err();
        assert!(
            error.to_string().contains("amount mismatch"),
            "got: {error}"
        );

        // Token mismatch: approval bound to a different token than the
        // dispatch settles in. Redirecting a governed spend to another token
        // must fail closed.
        let mut wrong_token = dispatch_binding();
        wrong_token.token_symbol = "EURC".to_string();
        let error = evaluate_circle_nanopayment_with_verified_approval(
            &dispatch,
            &sample_circle_policy(),
            DISPATCH_CHAIN_ID,
            &verified_for(wrong_token),
        )
        .test_unwrap_err();
        assert!(error.to_string().contains("token mismatch"), "got: {error}");
    }
}
