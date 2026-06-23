use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Mutex;

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::SolValue;
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
/// The `GovernedApprovalToken` itself does not carry chain/amount/payee as
/// discrete fields — they are folded into its `governed_intent_hash` — so
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
/// (`from` address) and the 32-byte authorization `nonce`: per EIP-3009
/// the `(from, nonce)` pair is unique per spend and is what the token
/// contract itself consumes on-chain. Recording the pair here makes the
/// off-chain preparation path single-use as well, closing the replay
/// window before a signature is ever broadcast.
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
/// normalized to lowercase so checksum-cased and lowercase hex map to the
/// same entry.
type Eip3009NonceMap = HashMap<(String, String), u64>;

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
            from_address.to_ascii_lowercase(),
            nonce.to_ascii_lowercase(),
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
/// 3. **Approval binding.** The domain `chain_id`, authorization `to`
///    (payee) and `value` (amount) are asserted against `binding`; any
///    mismatch fails closed. The caller resolves `binding` from the
///    verified governing approval (seam to C2/BAC-541).
///
/// All three checks fail closed. The nonce is recorded only after the
/// time-window and binding checks pass, so a rejected authorization does
/// not burn its nonce.
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

    // (3) Approval binding: chain / payee / amount must match the
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

    // (1) Single-use nonce: record AFTER the cheap fail-closed checks so a
    // rejected authorization does not consume its nonce, but BEFORE
    // returning a broadcastable digest so the first successful preparation
    // is the only one. Retain until the authorization's own expiry.
    match nonce_store.record_if_fresh(
        &authorization.from_address,
        &authorization.nonce,
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
        build_x402_payment_requirements, evaluate_circle_nanopayment,
        prepare_paymaster_compatibility, prepare_transfer_with_authorization, ApprovalBinding,
        CircleNanopaymentPolicy, Eip3009Domain, Eip3009NonceStore, Erc4337PaymasterPolicy,
        InMemoryEip3009NonceStore, NonceOutcome, TransferWithAuthorizationInput,
        X402SettlementMode,
    };
    use chio_core::web3::settlement::Web3SettlementDispatchArtifact;

    use chio_test_support::prelude::*;

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

    fn sample_domain() -> Eip3009Domain {
        Eip3009Domain {
            name: "USD Coin".to_string(),
            version: "2".to_string(),
            chain_id: SAMPLE_CHAIN_ID,
            verifying_contract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".to_string(),
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
}
