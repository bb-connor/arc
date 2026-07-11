//! libFuzzer entry-point module for the C2 (BAC-541) approval-witness
//! trust boundary.
//!
//! Gated behind the `fuzz` Cargo feature so it only compiles into the
//! standalone `chio-fuzz` workspace at `../../fuzz`. The production build of
//! `chio-settle` never exposes these symbols and never gets recompiled with
//! libFuzzer instrumentation.
//!
//! # Why this target exists
//!
//! The witness path is the settlement layer's money trust boundary: it
//! parses attacker-controllable JSON (the `chioSettlementBinding` intent
//! commitment), parses attacker-controllable CAIP-2 chain-id strings, and
//! funnels every value lane through the fail-closed
//! [`crate::verify_governed_approval`] gate. All of these surfaces must
//! reject malformed input with `Err(SettlementError::*)`; a panic, abort, or
//! hang on any deny path is a fuzz finding.
//!
//! # What each iteration drives
//!
//! 1. [`crate::parse_eip155_chain_id`] over the raw input as UTF-8 text.
//! 2. [`crate::parse_intent_settlement_binding`] over arbitrary JSON value
//!    shapes, both as the value under the reserved
//!    [`crate::CHIO_SETTLEMENT_BINDING_CONTEXT_KEY`] and as a whole intent
//!    `context`, plus a full [`GovernedTransactionIntent`] decode.
//! 3. When the input decodes into a structured [`FuzzWitnessCase`], a signed
//!    [`GovernedApprovalToken`] is minted with a fixed in-fuzzer keypair,
//!    tamper bits from the input mutate the token / binding / expectations,
//!    and the result is driven through [`crate::verify_governed_approval`]
//!    twice; each issued witness then drives the EIP-3009 lane wrapper
//!    [`crate::prepare_transfer_with_verified_approval`] against ONE shared
//!    replay store, so the issuance-level single-use deny path runs whenever
//!    the fixture verifies.
//!
//! The keypairs are fixed via [`Keypair::from_seed`] with constant seeds,
//! wrapped in [`OnceLock`] so they are materialised once per fuzzer process.
//! The goal is panic / UB / hang coverage on the deny paths, not signature
//! forging: arbitrary bytes cannot forge Ed25519 signatures, so the signed
//! fixture plus tamper bits is what reaches the post-signature checks.

use std::sync::OnceLock;

use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedTransactionIntent,
};
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::Keypair;
use serde::Deserialize;
use serde_json::json;

use crate::{
    parse_eip155_chain_id, parse_intent_settlement_binding,
    prepare_transfer_with_verified_approval, verify_governed_approval, ApprovalBinding,
    Eip3009Domain, InMemoryApprovalReplayStore, InMemoryEip3009NonceStore,
    TransferWithAuthorizationInput, CHIO_SETTLEMENT_BINDING_CONTEXT_KEY,
};

/// Deterministic seed for the fixed approver keypair. Constant so the corpus
/// surface is stable across libFuzzer runs.
const FUZZ_APPROVER_SEED: [u8; 32] = [0x41; 32];

/// Deterministic seed for the fixed subject keypair.
const FUZZ_SUBJECT_SEED: [u8; 32] = [0x42; 32];

/// Deterministic seed for the "wrong principal" keypair used by the
/// approver-mismatch tamper bit.
const FUZZ_OTHER_SEED: [u8; 32] = [0x43; 32];

/// Fixed base clock. Token windows and lane windows are derived relative to
/// this instant so a happy-path case verifies and settles by default.
const FUZZ_NOW: u64 = 1_744_000_300;

/// Request id minted into every fixture token.
const FUZZ_REQUEST_ID: &str = "fuzz-req-1";

/// EIP-3009 `from` address for the lane drive.
const FUZZ_FROM_ADDRESS: &str = "0x1000000000000000000000000000000000000001";

/// Fallback verifying contract when the case pins no token contract.
const FUZZ_TOKEN_CONTRACT: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

fn approver_keypair() -> &'static Keypair {
    static APPROVER: OnceLock<Keypair> = OnceLock::new();
    APPROVER.get_or_init(|| Keypair::from_seed(&FUZZ_APPROVER_SEED))
}

fn subject_keypair() -> &'static Keypair {
    static SUBJECT: OnceLock<Keypair> = OnceLock::new();
    SUBJECT.get_or_init(|| Keypair::from_seed(&FUZZ_SUBJECT_SEED))
}

fn other_keypair() -> &'static Keypair {
    static OTHER: OnceLock<Keypair> = OnceLock::new();
    OTHER.get_or_init(|| Keypair::from_seed(&FUZZ_OTHER_SEED))
}

/// Tamper bit: sign a `Denied` decision instead of `Approved`.
const TAMPER_DENIED: u8 = 1 << 0;
/// Tamper bit: mutate the token body after signing (invalid signature).
const TAMPER_SIGNATURE: u8 = 1 << 1;
/// Tamper bit: verify against a different expected approver.
const TAMPER_WRONG_APPROVER: u8 = 1 << 2;
/// Tamper bit: verify against a different expected request id.
const TAMPER_WRONG_REQUEST: u8 = 1 << 3;
/// Tamper bit: shift the resolved binding's chain AFTER the intent committed
/// it, so the commitment check sees a disagreement.
const TAMPER_BINDING_CHAIN: u8 = 1 << 4;
/// Tamper bit: drop the intent's settlement commitment entirely.
const TAMPER_UNCOMMITTED: u8 = 1 << 5;
/// Tamper bit: let the binding expiry outlive the token expiry.
const TAMPER_OUTLIVING_EXPIRY: u8 = 1 << 6;
/// Tamper bit: shift the lane authorization value off the bound amount.
const TAMPER_LANE_AMOUNT: u8 = 1 << 7;

/// Structured drive form decoded from fuzzer bytes.
///
/// The required fields are exactly the required
/// [`crate::IntentSettlementBinding`] fields, so a serialized settlement
/// binding JSON is directly a valid case; every knob defaults to the
/// happy-path value.
#[derive(Debug, Deserialize)]
struct FuzzWitnessCase {
    chain_id: u64,
    payee_address: String,
    amount_minor_units: u128,
    token_symbol: String,
    #[serde(default)]
    token_contract: Option<String>,
    #[serde(default)]
    settlement_currency: Option<String>,
    #[serde(default)]
    dispatch_id: Option<String>,
    #[serde(default)]
    capability_id: Option<String>,
    /// Tamper bit set (see the `TAMPER_*` constants).
    #[serde(default)]
    tamper: u8,
    /// Token lifetime in seconds. Values above the settlement TTL cap drive
    /// the lifetime-cap deny path.
    #[serde(default = "default_token_ttl")]
    token_ttl: u64,
    /// Signed offset applied to the verification / lane-use clock.
    #[serde(default)]
    now_offset: i64,
    /// Optional intent `max_amount` ceiling, driving the clamp path.
    #[serde(default)]
    max_amount_units: Option<u64>,
    #[serde(default)]
    max_amount_currency: Option<String>,
    /// Seed for the EIP-3009 authorization nonce.
    #[serde(default)]
    nonce_seed: u64,
}

fn default_token_ttl() -> u64 {
    200
}

/// Minimal intent wrapper for the parse-only paths.
fn intent_with_context(context: Option<serde_json::Value>) -> GovernedTransactionIntent {
    GovernedTransactionIntent {
        id: "fuzz-intent".to_string(),
        server_id: "fuzz-settlement-server".to_string(),
        tool_name: "transfer_funds".to_string(),
        purpose: "settlement approval witness fuzz".to_string(),
        max_amount: None,
        commerce: None,
        metered_billing: None,
        runtime_attestation: None,
        call_chain: None,
        autonomy: None,
        context,
    }
}

/// Commit `binding` into an intent context under the reserved key, mirroring
/// how production approvers sign the concrete settlement economics.
fn intent_committing_binding(binding: &ApprovalBinding) -> GovernedTransactionIntent {
    let mut commitment = json!({
        "chain_id": binding.chain_id,
        "payee_address": binding.payee_address,
        "amount_minor_units": binding.amount_minor_units,
        "token_symbol": binding.token_symbol,
    });
    if let Some(contract) = binding.token_contract.as_ref() {
        commitment["token_contract"] = json!(contract);
    }
    if let Some(currency) = binding.settlement_currency.as_ref() {
        commitment["settlement_currency"] = json!(currency);
    }
    if let Some(dispatch_id) = binding.dispatch_id.as_ref() {
        commitment["dispatch_id"] = json!(dispatch_id);
    }
    if let Some(capability_id) = binding.capability_id.as_ref() {
        commitment["capability_id"] = json!(capability_id);
    }
    intent_with_context(Some(
        json!({ CHIO_SETTLEMENT_BINDING_CONTEXT_KEY: commitment }),
    ))
}

fn offset_clock(base: u64, offset: i64) -> u64 {
    if offset >= 0 {
        base.saturating_add(offset as u64)
    } else {
        base.saturating_sub(offset.unsigned_abs())
    }
}

/// Mint a signed fixture token, apply the case's tamper bits, and drive the
/// witness gate plus the EIP-3009 lane wrapper. Every `Result` is discarded:
/// deny outcomes are the expected result and panics are the only finding.
fn drive_witness_and_lane(case: &FuzzWitnessCase) {
    let approver = approver_keypair();
    let subject = subject_keypair();

    // Clamp the amount into u64 range: `serde_json::json!` cannot represent
    // wider integers and the dispatch/authorization amounts are u64-derived
    // anyway, so wider values add no reachable coverage.
    let amount = case.amount_minor_units.min(u128::from(u64::MAX));

    let issued_at = FUZZ_NOW.saturating_sub(100);
    let token_expires_at = issued_at.saturating_add(case.token_ttl);
    let mut binding = ApprovalBinding {
        chain_id: case.chain_id,
        payee_address: case.payee_address.clone(),
        amount_minor_units: amount,
        token_symbol: case.token_symbol.clone(),
        token_contract: case.token_contract.clone(),
        settlement_currency: case.settlement_currency.clone(),
        dispatch_id: case.dispatch_id.clone(),
        capability_id: case.capability_id.clone(),
        approval_expires_at: token_expires_at,
    };

    let mut intent = if case.tamper & TAMPER_UNCOMMITTED != 0 {
        intent_with_context(None)
    } else {
        intent_committing_binding(&binding)
    };
    if let (Some(units), Some(currency)) =
        (case.max_amount_units, case.max_amount_currency.as_ref())
    {
        intent.max_amount = Some(MonetaryAmount {
            units,
            currency: currency.clone(),
        });
    }

    let Ok(intent_hash) = intent.binding_hash() else {
        return;
    };

    let decision = if case.tamper & TAMPER_DENIED != 0 {
        GovernedApprovalDecision::Denied
    } else {
        GovernedApprovalDecision::Approved
    };
    let body = GovernedApprovalTokenBody {
        id: "fuzz-approval-1".to_string(),
        approver: approver.public_key(),
        subject: subject.public_key(),
        governed_intent_hash: intent_hash,
        request_id: FUZZ_REQUEST_ID.to_string(),
        issued_at,
        expires_at: token_expires_at,
        decision,
    };
    let Ok(mut token) = GovernedApprovalToken::sign(body, approver) else {
        return;
    };
    if case.tamper & TAMPER_SIGNATURE != 0 {
        token.issued_at = token.issued_at.wrapping_sub(1);
    }

    // Post-signing binding mutations: the intent committed the original
    // values, so these drive the commitment-mismatch deny paths.
    if case.tamper & TAMPER_BINDING_CHAIN != 0 {
        binding.chain_id = binding.chain_id.wrapping_add(1);
    }
    if case.tamper & TAMPER_OUTLIVING_EXPIRY != 0 {
        binding.approval_expires_at = token.expires_at.saturating_add(1);
    }

    let expected_approver = if case.tamper & TAMPER_WRONG_APPROVER != 0 {
        other_keypair().public_key()
    } else {
        approver.public_key()
    };
    let expected_request_id = if case.tamper & TAMPER_WRONG_REQUEST != 0 {
        "fuzz-req-other"
    } else {
        FUZZ_REQUEST_ID
    };

    let now = offset_clock(FUZZ_NOW, case.now_offset);
    // Verification is read-only over the replay store, so the same token can
    // be verified twice; each issued witness is driven through the lane
    // below against ONE shared replay store, which exercises the
    // issuance-level single-use deny path on the second issuance attempt.
    let first = verify_governed_approval(
        &token,
        &intent,
        &expected_approver,
        &subject.public_key(),
        expected_request_id,
        binding.clone(),
        now,
    );
    let second = verify_governed_approval(
        &token,
        &intent,
        &expected_approver,
        &subject.public_key(),
        expected_request_id,
        binding.clone(),
        now,
    );

    let Ok(witness) = first else {
        drop(second);
        return;
    };

    // Lane drive: EIP-3009 preparation off the issued witness. The domain
    // and authorization are derived from the case so the bound values agree
    // by default and each tamper bit flips exactly one lane assertion.
    let lane_value = if case.tamper & TAMPER_LANE_AMOUNT != 0 {
        amount.wrapping_add(1)
    } else {
        amount
    };
    let domain = Eip3009Domain {
        name: "USD Coin".to_string(),
        version: "2".to_string(),
        chain_id: binding.chain_id,
        verifying_contract: binding
            .token_contract
            .clone()
            .unwrap_or_else(|| FUZZ_TOKEN_CONTRACT.to_string()),
    };
    let authorization = TransferWithAuthorizationInput {
        from_address: FUZZ_FROM_ADDRESS.to_string(),
        to_address: binding.payee_address.clone(),
        value_minor_units: lane_value,
        valid_after: FUZZ_NOW.saturating_sub(200),
        valid_before: binding.approval_expires_at,
        nonce: format!("0x{:064x}", case.nonce_seed),
    };
    let nonce_store = InMemoryEip3009NonceStore::new();
    let replay_store = InMemoryApprovalReplayStore::new();
    let _ = prepare_transfer_with_verified_approval(
        domain.clone(),
        authorization.clone(),
        witness,
        now,
        &nonce_store,
        &replay_store,
    );
    if let Ok(second_witness) = second {
        // Same approval, fresh nonce, shared replay store: covers the
        // issuance-level replay denial (or a second issuance denial via the
        // nonce path when the first attempt failed before consuming).
        let mut second_authorization = authorization;
        second_authorization.nonce = format!("0x{:064x}", case.nonce_seed.wrapping_add(1));
        let _ = prepare_transfer_with_verified_approval(
            domain,
            second_authorization,
            second_witness,
            now,
            &nonce_store,
            &replay_store,
        );
    }
}

/// Drive arbitrary bytes through the settlement approval-witness trust
/// boundary.
///
/// Errors at every step are consumed on purpose: the trust-boundary contract
/// guarantees the only outcomes are `Err(SettlementError::*)` (the expected
/// fail-closed result), an issued artifact for a self-consistent fixture, or
/// a panic / abort that libFuzzer surfaces as a crash.
pub fn fuzz_settlement_approval_witness(data: &[u8]) {
    // Strict CAIP-2 chain-id parse over the raw input as text.
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_eip155_chain_id(text);
    }

    // Settlement-binding parse over arbitrary JSON value shapes: as the
    // value under the reserved context key, and as the whole context.
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let keyed = intent_with_context(Some(
            json!({ CHIO_SETTLEMENT_BINDING_CONTEXT_KEY: value.clone() }),
        ));
        let _ = parse_intent_settlement_binding(&keyed);
        let bare = intent_with_context(Some(value));
        let _ = parse_intent_settlement_binding(&bare);
    }

    // Full governed-intent decode plus commitment parse.
    if let Ok(intent) = serde_json::from_slice::<GovernedTransactionIntent>(data) {
        let _ = parse_intent_settlement_binding(&intent);
    }

    // Structured witness-gate and lane drive.
    if let Ok(case) = serde_json::from_slice::<FuzzWitnessCase>(data) {
        drive_witness_and_lane(&case);
    }
}
