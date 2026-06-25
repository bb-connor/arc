//! Unit tests for the C2 (BAC-541) verified-approval settlement lanes in
//! [`crate::payments`]. Split into a sibling file to keep `payments.rs`
//! under its hygiene line cap while every per-property regression stays
//! next to the witness it guards. `super::` refers to the `payments`
//! module because this file is included via `#[path]` inside it.

use super::{
    build_x402_payment_requirements, build_x402_payment_requirements_with_verified_approval,
    evaluate_circle_nanopayment, evaluate_circle_nanopayment_with_verified_approval,
    prepare_paymaster_compatibility, prepare_transfer_with_authorization,
    prepare_transfer_with_verified_approval, verify_governed_approval, ApprovalBinding,
    CircleNanopaymentPolicy, Eip3009Domain, Eip3009NonceStore, Erc4337PaymasterPolicy,
    InMemoryEip3009NonceStore, NonceOutcome, PreparedCircleNanopayment,
    PreparedTransferWithAuthorization, TransferWithAuthorizationInput, VerifiedApproval,
    X402PaymentRequirements, X402SettlementMode,
};
use crate::approval_witness::{
    ApprovalReplayStore, InMemoryApprovalReplayStore, CHIO_SETTLEMENT_BINDING_CONTEXT_KEY,
};
use crate::SettlementError;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedTransactionIntent,
};
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::Keypair;
use chio_core::web3::settlement::Web3SettlementDispatchArtifact;
use serde_json::json;

use chio_test_support::prelude::*;

/// The request id `signed_approval` mints into every token and that
/// `verified_for` passes as the expected request, so the request-binding
/// check passes by default in the per-lane tests.
const APPROVAL_REQUEST_ID: &str = "req-1";

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

/// Build a minimal governed intent with NO monetary bound (no `max_amount`
/// and no committed settlement binding). The witness gate now refuses such an
/// intent (fail-closed: an unbounded intent pins no ceiling on the spend), so
/// this is used by the property-3 unbounded-rejection regression and as the
/// base for [`intent_with_max_amount`].
fn unbounded_intent(id: &str) -> GovernedTransactionIntent {
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

/// Commit `binding`'s chain/payee/amount/token into an intent `context` under
/// the reserved settlement-binding key, so `intent.binding_hash()` (and thus
/// the approval signature) covers the concrete settlement economics. This
/// mirrors production: the approver signs the intent that commits the spend and
/// the caller resolves the matching `ApprovalBinding` from that same intent.
fn intent_committing_binding(id: &str, binding: &ApprovalBinding) -> GovernedTransactionIntent {
    let mut commitment = json!({
        "chain_id": binding.chain_id,
        "payee_address": binding.payee_address,
        "amount_minor_units": binding.amount_minor_units,
        "token_symbol": binding.token_symbol,
    });
    if let Some(contract) = binding.token_contract.as_ref() {
        commitment["token_contract"] = json!(contract);
    }
    let mut intent = unbounded_intent(id);
    intent.context = Some(json!({ CHIO_SETTLEMENT_BINDING_CONTEXT_KEY: commitment }));
    intent
}

/// Build a governed intent that commits the sample dispatch's
/// chain/payee/amount/token (matching [`dispatch_binding`]). This is the
/// default monetary-bound intent for the gate happy-path and expiry tests.
fn sample_intent(id: &str) -> GovernedTransactionIntent {
    intent_committing_binding(id, &dispatch_binding())
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
        request_id: APPROVAL_REQUEST_ID.to_string(),
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

/// Verify a fresh approval for `binding`, returning the witness. The intent
/// COMMITS `binding`, mirroring production (the approver signs the intent that
/// commits the concrete spend and the caller resolves the matching binding
/// from it), so the per-lane mismatch tests still produce a witness whose
/// binding disagrees only with the live DISPATCH, not with the intent. A fresh
/// `InMemoryApprovalReplayStore` is allocated per call so each helper-produced
/// witness is independent.
fn verified_for(binding: ApprovalBinding) -> VerifiedApproval {
    verified_for_with_token_expiry(binding, APPROVAL_NOW + 100)
}

/// Like [`verified_for`] but mints the approval token with an explicit
/// `expires_at`, so a binding whose `approval_expires_at` is later than
/// `APPROVAL_NOW + 100` (for example the EIP-3009 sample window) can still
/// be witnessed without tripping the expiry clamp. `token_expires_at` must
/// be `>= binding.approval_expires_at`.
fn verified_for_with_token_expiry(
    binding: ApprovalBinding,
    token_expires_at: u64,
) -> VerifiedApproval {
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    // Commit the very binding being verified so the intent-commitment check
    // passes; the lanes still assert the binding against the live dispatch.
    let intent = intent_committing_binding("intent-dispatch", &binding);
    let body = GovernedApprovalTokenBody {
        id: "approval-1".to_string(),
        approver: approver.public_key(),
        subject: subject.public_key(),
        governed_intent_hash: intent.binding_hash().test_unwrap(),
        request_id: APPROVAL_REQUEST_ID.to_string(),
        issued_at: APPROVAL_NOW - 100,
        expires_at: token_expires_at,
        decision: GovernedApprovalDecision::Approved,
    };
    let token = GovernedApprovalToken::sign(body, &approver).test_unwrap();
    let store = InMemoryApprovalReplayStore::new();
    verify_governed_approval(
        &token,
        &intent,
        &approver.public_key(),
        &subject.public_key(),
        APPROVAL_REQUEST_ID,
        binding,
        APPROVAL_NOW,
        &store,
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

/// Verify `token`/`intent` against the gate with the expected
/// approver/subject/request defaulted from the same keypairs, a fresh
/// replay store, and `APPROVAL_NOW`. Returns the gate result so callers
/// can assert on success or the specific rejection.
fn verify_gate(
    token: &GovernedApprovalToken,
    intent: &GovernedTransactionIntent,
    approver: &Keypair,
    subject: &Keypair,
    binding: ApprovalBinding,
    now: u64,
) -> Result<VerifiedApproval, SettlementError> {
    let store = InMemoryApprovalReplayStore::new();
    verify_governed_approval(
        token,
        intent,
        &approver.public_key(),
        &subject.public_key(),
        APPROVAL_REQUEST_ID,
        binding,
        now,
        &store,
    )
}

#[test]
fn verify_governed_approval_accepts_a_valid_token() {
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let intent = sample_intent("intent-ok");
    let token = signed_approval(&approver, &subject, &intent);

    let verified = verify_gate(
        &token,
        &intent,
        &approver,
        &subject,
        dispatch_binding(),
        APPROVAL_NOW,
    )
    .test_unwrap();

    assert_eq!(verified.approval_id(), "approval-1");
    assert_eq!(verified.request_id(), APPROVAL_REQUEST_ID);
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
    token.issued_at = token.issued_at.wrapping_sub(1);

    let error = verify_gate(
        &token,
        &intent,
        &approver,
        &subject,
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
    let error = verify_gate(
        &token,
        &intent,
        &approver,
        &subject,
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
        request_id: APPROVAL_REQUEST_ID.to_string(),
        issued_at: APPROVAL_NOW - 100,
        expires_at: APPROVAL_NOW + 100,
        decision: GovernedApprovalDecision::Denied,
    };
    let token = GovernedApprovalToken::sign(body, &approver).test_unwrap();

    let error = verify_gate(
        &token,
        &intent,
        &approver,
        &subject,
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
    let store = InMemoryApprovalReplayStore::new();
    let error = verify_governed_approval(
        &token,
        &intent,
        &unexpected.public_key(),
        &subject.public_key(),
        APPROVAL_REQUEST_ID,
        dispatch_binding(),
        APPROVAL_NOW,
        &store,
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
    let error = verify_gate(
        &token,
        &other_intent,
        &approver,
        &subject,
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
// C2 round-5: per-property regressions on the witness gate.
// -----------------------------------------------------------------

#[test]
fn verify_governed_approval_rejects_a_wrong_subject() {
    // (1) Subject binding. A validly-signed, approved token whose subject
    // is NOT the expected subject must be rejected even though intent
    // hash and approver match. Without the subject check a captured
    // approval for one principal could settle a different principal's
    // spend.
    let approver = Keypair::generate();
    let token_subject = Keypair::generate();
    let intent = sample_intent("intent-wrong-subject");
    let token = signed_approval(&approver, &token_subject, &intent);

    // Verify with a DIFFERENT expected subject.
    let expected_subject = Keypair::generate();
    let store = InMemoryApprovalReplayStore::new();
    let error = verify_governed_approval(
        &token,
        &intent,
        &approver.public_key(),
        &expected_subject.public_key(),
        APPROVAL_REQUEST_ID,
        dispatch_binding(),
        APPROVAL_NOW,
        &store,
    )
    .test_unwrap_err();
    assert!(
        error.to_string().contains("subject does not match"),
        "a token for a different subject must be rejected, got: {error}"
    );
    assert!(
        store.is_empty().test_unwrap(),
        "a subject-mismatch rejection must not burn the replay slot"
    );
}

#[test]
fn verify_governed_approval_rejects_a_wrong_request_id() {
    // (1) Request binding. A token whose request_id differs from the
    // expected request must be rejected: an approval minted for request A
    // cannot authorize settlement for request B even with the same
    // intent/approver/subject.
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let intent = sample_intent("intent-wrong-request");
    let token = signed_approval(&approver, &subject, &intent);

    let store = InMemoryApprovalReplayStore::new();
    let error = verify_governed_approval(
        &token,
        &intent,
        &approver.public_key(),
        &subject.public_key(),
        "req-OTHER",
        dispatch_binding(),
        APPROVAL_NOW,
        &store,
    )
    .test_unwrap_err();
    assert!(
        error.to_string().contains("request binding does not match"),
        "a token for a different request must be rejected, got: {error}"
    );
}

#[test]
fn verify_governed_approval_is_single_use_with_a_shared_store() {
    // (2) Replay / single-use. The SAME approval verified twice against a
    // SHARED replay store must be rejected on the second presentation,
    // mirroring the kernel approval_replay_store. The first presentation
    // succeeds; the second fails closed.
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let intent = sample_intent("intent-replay");
    let token = signed_approval(&approver, &subject, &intent);

    let store = InMemoryApprovalReplayStore::new();
    let first = verify_governed_approval(
        &token,
        &intent,
        &approver.public_key(),
        &subject.public_key(),
        APPROVAL_REQUEST_ID,
        dispatch_binding(),
        APPROVAL_NOW,
        &store,
    );
    assert!(
        first.is_ok(),
        "first presentation of a fresh approval must succeed"
    );

    let replay = verify_governed_approval(
        &token,
        &intent,
        &approver.public_key(),
        &subject.public_key(),
        APPROVAL_REQUEST_ID,
        dispatch_binding(),
        APPROVAL_NOW,
        &store,
    )
    .test_unwrap_err();
    assert!(
        replay.to_string().contains("already been consumed"),
        "a second presentation of the same approval must be rejected, got: {replay}"
    );
}

#[test]
fn verify_governed_approval_does_not_burn_replay_slot_on_other_rejection() {
    // The replay record happens LAST: a rejection on an earlier check
    // (here a wrong approver) must not record the token, so a corrected
    // presentation can still succeed against the same store.
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let intent = sample_intent("intent-noslot");
    let token = signed_approval(&approver, &subject, &intent);
    let store = InMemoryApprovalReplayStore::new();

    let unexpected = Keypair::generate();
    let _ = verify_governed_approval(
        &token,
        &intent,
        &unexpected.public_key(),
        &subject.public_key(),
        APPROVAL_REQUEST_ID,
        dispatch_binding(),
        APPROVAL_NOW,
        &store,
    )
    .test_unwrap_err();
    assert!(
        store.is_empty().test_unwrap(),
        "an approver-mismatch rejection must not record a replay entry"
    );

    // The corrected presentation (right approver) now succeeds.
    let ok = verify_governed_approval(
        &token,
        &intent,
        &approver.public_key(),
        &subject.public_key(),
        APPROVAL_REQUEST_ID,
        dispatch_binding(),
        APPROVAL_NOW,
        &store,
    );
    assert!(
        ok.is_ok(),
        "a corrected presentation must still verify: {ok:?}"
    );
}

#[test]
fn verify_governed_approval_rejects_a_binding_outliving_the_token() {
    // (3) Expiry clamp. A binding whose approval_expires_at is LATER than
    // the token's own expires_at must be rejected, so an EIP-3009
    // valid_before clamped to the binding cannot outlive the
    // GovernedApprovalToken.
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let intent = sample_intent("intent-overexpiry");
    let token = signed_approval(&approver, &subject, &intent);

    let mut binding = dispatch_binding();
    binding.approval_expires_at = token.expires_at + 1;
    let error =
        verify_gate(&token, &intent, &approver, &subject, binding, APPROVAL_NOW).test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("outlives the governed approval token expiry"),
        "a binding expiry past the token expiry must be rejected, got: {error}"
    );
}

#[test]
fn verify_governed_approval_accepts_binding_expiry_equal_to_token_expiry() {
    // Boundary: binding expiry == token expiry is still bounded by the
    // token, so it must be accepted.
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let intent = sample_intent("intent-expiry-boundary");
    let token = signed_approval(&approver, &subject, &intent);

    let mut binding = dispatch_binding();
    binding.approval_expires_at = token.expires_at;
    let verified =
        verify_gate(&token, &intent, &approver, &subject, binding, APPROVAL_NOW).test_unwrap();
    assert_eq!(verified.binding().approval_expires_at, token.expires_at);
}

/// Build an intent with an explicit `max_amount` of `units`/`currency` and NO
/// committed settlement binding, so the max_amount clamp is the only monetary
/// bound being exercised (the committed-binding check stays out of the way of
/// the amount/currency-clamp regressions).
fn intent_with_max_amount(id: &str, units: u64, currency: &str) -> GovernedTransactionIntent {
    let mut intent = unbounded_intent(id);
    intent.max_amount = Some(MonetaryAmount {
        units,
        currency: currency.to_string(),
    });
    intent
}

#[test]
fn verify_governed_approval_rejects_a_binding_over_intent_max_amount() {
    // (4) Intent amount clamp. When the intent pins max_amount, a binding
    // whose amount exceeds it must be rejected before any witness exists.
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let intent = intent_with_max_amount(
        "intent-overamount",
        DISPATCH_AMOUNT as u64,
        DISPATCH_TOKEN_SYMBOL,
    );
    let token = signed_approval(&approver, &subject, &intent);

    let mut binding = dispatch_binding();
    binding.amount_minor_units = DISPATCH_AMOUNT + 1; // one over the approved max
    let error =
        verify_gate(&token, &intent, &approver, &subject, binding, APPROVAL_NOW).test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("exceeds the intent-approved maximum"),
        "an over-amount binding must be rejected, got: {error}"
    );
}

#[test]
fn verify_governed_approval_rejects_a_binding_with_wrong_intent_currency() {
    // (4) Intent currency clamp. With max_amount set, a binding whose
    // token symbol differs from the approved currency must be rejected.
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let intent = intent_with_max_amount(
        "intent-wrongccy",
        DISPATCH_AMOUNT as u64,
        DISPATCH_TOKEN_SYMBOL,
    );
    let token = signed_approval(&approver, &subject, &intent);

    let mut binding = dispatch_binding();
    binding.token_symbol = "EUR".to_string();
    let error =
        verify_gate(&token, &intent, &approver, &subject, binding, APPROVAL_NOW).test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not match the intent-approved currency"),
        "a wrong-currency binding must be rejected, got: {error}"
    );
}

#[test]
fn verify_governed_approval_accepts_a_binding_at_intent_max_amount() {
    // Boundary: amount == max and matching currency is within the
    // approved ceiling and must verify.
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let intent = intent_with_max_amount(
        "intent-atmax",
        DISPATCH_AMOUNT as u64,
        DISPATCH_TOKEN_SYMBOL,
    );
    let token = signed_approval(&approver, &subject, &intent);

    let verified = verify_gate(
        &token,
        &intent,
        &approver,
        &subject,
        dispatch_binding(),
        APPROVAL_NOW,
    )
    .test_unwrap();
    assert_eq!(verified.binding().amount_minor_units, DISPATCH_AMOUNT);
}

// -----------------------------------------------------------------
// C2 round-6: per-property fail-closed regressions.
// -----------------------------------------------------------------

#[test]
fn verify_governed_approval_rejects_an_unbounded_intent() {
    // (3) Monetary bound required. An intent with neither an explicit
    // `max_amount` nor a committed settlement binding pins no ceiling on the
    // spend, so the gate must refuse to issue a witness for it. Without this
    // fail-closed check an arbitrary caller-supplied ApprovalBinding (any
    // amount) would be accepted for an unbounded intent.
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let intent = unbounded_intent("intent-unbounded");
    let token = signed_approval(&approver, &subject, &intent);

    let error = verify_gate(
        &token,
        &intent,
        &approver,
        &subject,
        dispatch_binding(),
        APPROVAL_NOW,
    )
    .test_unwrap_err();
    assert!(
        error.to_string().contains("carries no monetary bound"),
        "an intent with no monetary bound must not yield a witness, got: {error}"
    );
}

#[test]
fn verify_governed_approval_rejects_a_caller_substituted_chain_payee_token() {
    // (4) Bind payee/chain/token to the SIGNED intent. The intent commits a
    // concrete chain/payee/amount/token via its binding hash; a caller that
    // resolves a binding with a SUBSTITUTED chain, payee, or token (one the
    // approval never signed) must be rejected, so the witness carries the
    // signed chain/payee/token, not caller-chosen ones.
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    // The approver signs a binding committing the dispatch chain/payee/token.
    let intent = intent_committing_binding("intent-committed", &dispatch_binding());
    let token = signed_approval(&approver, &subject, &intent);

    // Substituted chain.
    let mut wrong_chain = dispatch_binding();
    wrong_chain.chain_id = 1;
    let error = verify_gate(
        &token,
        &intent,
        &approver,
        &subject,
        wrong_chain,
        APPROVAL_NOW,
    )
    .test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not match the intent-committed chain"),
        "a substituted chain must be rejected, got: {error}"
    );

    // Substituted payee.
    let mut wrong_payee = dispatch_binding();
    wrong_payee.payee_address = "0x3333333333333333333333333333333333333333".to_string();
    let error = verify_gate(
        &token,
        &intent,
        &approver,
        &subject,
        wrong_payee,
        APPROVAL_NOW,
    )
    .test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not match the intent-committed payee"),
        "a substituted payee must be rejected, got: {error}"
    );

    // Substituted token symbol.
    let mut wrong_token = dispatch_binding();
    wrong_token.token_symbol = "EURC".to_string();
    let error = verify_gate(
        &token,
        &intent,
        &approver,
        &subject,
        wrong_token,
        APPROVAL_NOW,
    )
    .test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not match the intent-committed token"),
        "a substituted token must be rejected, got: {error}"
    );
}

#[test]
fn verify_governed_approval_rejects_a_caller_substituted_token_contract() {
    // (4) Token contract binding. When the intent commits a token contract,
    // a binding that omits or substitutes the contract must be rejected, so a
    // captured approval cannot be redirected to a different token contract on
    // the same chain.
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let committed = ApprovalBinding {
        chain_id: SAMPLE_CHAIN_ID,
        payee_address: SAMPLE_PAYEE.to_string(),
        amount_minor_units: SAMPLE_VALUE,
        token_symbol: SAMPLE_TOKEN_SYMBOL.to_string(),
        token_contract: Some(SAMPLE_TOKEN_CONTRACT.to_string()),
        approval_expires_at: APPROVAL_NOW + 100,
    };
    let intent = intent_committing_binding("intent-committed-contract", &committed);
    let token = signed_approval(&approver, &subject, &intent);

    // Substituted token contract on the same chain.
    let mut wrong_contract = committed.clone();
    wrong_contract.token_contract = Some("0x4444444444444444444444444444444444444444".to_string());
    let error = verify_gate(
        &token,
        &intent,
        &approver,
        &subject,
        wrong_contract,
        APPROVAL_NOW,
    )
    .test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("token contract does not match the intent-committed contract"),
        "a substituted token contract must be rejected, got: {error}"
    );

    // Omitted token contract while the intent committed one.
    let mut omitted = committed.clone();
    omitted.token_contract = None;
    let error =
        verify_gate(&token, &intent, &approver, &subject, omitted, APPROVAL_NOW).test_unwrap_err();
    assert!(
        error
            .to_string()
            .contains("omits the token contract the intent committed"),
        "omitting the committed token contract must be rejected, got: {error}"
    );
}

#[test]
fn verify_governed_approval_accepts_a_binding_matching_the_committed_intent() {
    // Happy path for (3)/(4): an intent that commits the settlement binding
    // and a caller binding that matches it verifies, with no separate
    // max_amount required (the committed binding IS the monetary bound).
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let intent = intent_committing_binding("intent-committed-ok", &dispatch_binding());
    let token = signed_approval(&approver, &subject, &intent);

    let verified = verify_gate(
        &token,
        &intent,
        &approver,
        &subject,
        dispatch_binding(),
        APPROVAL_NOW,
    )
    .test_unwrap();
    assert_eq!(verified.binding(), &dispatch_binding());
}

#[test]
fn shared_store_path_verifies_a_matching_token() {
    // The only exported witness path now REQUIRES an explicit shared replay
    // store (the per-call default store was removed because it could not
    // enforce single-use across settlement requests). A matching token still
    // verifies, and every binding check still runs.
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let intent = sample_intent("intent-shared-store");
    let token = signed_approval(&approver, &subject, &intent);
    let store = InMemoryApprovalReplayStore::new();
    let verified = verify_governed_approval(
        &token,
        &intent,
        &approver.public_key(),
        &subject.public_key(),
        APPROVAL_REQUEST_ID,
        dispatch_binding(),
        APPROVAL_NOW,
        &store,
    )
    .test_unwrap();
    assert_eq!(verified.approval_id(), "approval-1");
}

#[test]
fn cross_call_replay_is_rejected_via_the_shared_store() {
    // (1) Cross-call replay. The witness path no longer offers a per-call
    // default store: callers MUST supply a shared store, so the SAME approval
    // presented across two SEPARATE verification calls against that store is
    // rejected on the second. Without a shared store (the removed default
    // allocated a fresh per-call store) this second call would succeed and the
    // approval would authorize a second settlement.
    let approver = Keypair::generate();
    let subject = Keypair::generate();
    let intent = sample_intent("intent-cross-call");
    let token = signed_approval(&approver, &subject, &intent);

    // A single durable store shared across both settlement requests.
    let shared_store = InMemoryApprovalReplayStore::new();

    let first = verify_governed_approval(
        &token,
        &intent,
        &approver.public_key(),
        &subject.public_key(),
        APPROVAL_REQUEST_ID,
        dispatch_binding(),
        APPROVAL_NOW,
        &shared_store,
    );
    assert!(
        first.is_ok(),
        "the first settlement request must verify the approval"
    );

    let second = verify_governed_approval(
        &token,
        &intent,
        &approver.public_key(),
        &subject.public_key(),
        APPROVAL_REQUEST_ID,
        dispatch_binding(),
        APPROVAL_NOW,
        &shared_store,
    )
    .test_unwrap_err();
    assert!(
        second.to_string().contains("already been consumed"),
        "the same approval presented to a second settlement request must be rejected, got: {second}"
    );
}

/// The public bypass exports are gone: the legacy x402/Circle/EIP-3009
/// preparation functions are `pub(crate)` and not re-exported from the
/// crate root, so downstream cannot construct a settlement that skips the
/// `VerifiedApproval` witness. This compile-time test pins the only
/// exported lane entry points to the `*_with_verified_approval` variants;
/// it would fail to compile if a bypass export were reintroduced because
/// the function-pointer type carries the `VerifiedApproval` argument.
// The explicit fn-pointer types are the assertion: they pin each exported
// lane entry point to its witness-bound signature, so the type complexity is
// intentional here.
#[allow(clippy::type_complexity)]
#[test]
fn exported_lane_entry_points_require_a_verified_approval_witness() {
    // The witness is taken BY VALUE on every lane (single-use), and every lane
    // threads a lane-use clock (re-checks approval expiry at lane use). These
    // fn-pointer types would fail to compile if a lane reverted to borrowing
    // the witness or dropped its clock.
    let _x402: fn(
        &Web3SettlementDispatchArtifact,
        &str,
        &str,
        Vec<String>,
        X402SettlementMode,
        VerifiedApproval,
        u64,
    ) -> Result<X402PaymentRequirements, SettlementError> =
        build_x402_payment_requirements_with_verified_approval;
    let _eip3009: fn(
        Eip3009Domain,
        TransferWithAuthorizationInput,
        VerifiedApproval,
        u64,
        &dyn Eip3009NonceStore,
    ) -> Result<PreparedTransferWithAuthorization, SettlementError> =
        prepare_transfer_with_verified_approval;
    let _circle: fn(
        &Web3SettlementDispatchArtifact,
        &CircleNanopaymentPolicy,
        VerifiedApproval,
        u64,
    ) -> Result<Option<PreparedCircleNanopayment>, SettlementError> =
        evaluate_circle_nanopayment_with_verified_approval;
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
        approval,
        APPROVAL_NOW,
    )
    .test_unwrap();

    assert!(requirements.governed_authorization_required);
    assert_eq!(requirements.dispatch_id, dispatch.dispatch_id);
    // The accepted-token list is filtered down to the approval-bound token:
    // the "USDC" extra must NOT be advertised.
    assert_eq!(
        requirements.accepted_tokens,
        vec![DISPATCH_TOKEN_SYMBOL.to_string()],
        "x402 requirements must advertise only the approval-bound token"
    );
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
        verified_for(dispatch_binding()),
        APPROVAL_NOW,
    )
    .test_unwrap_err();
    assert!(error.to_string().contains("token mismatch"), "got: {error}");
}

#[test]
fn x402_with_verified_approval_rejects_binding_mismatches() {
    let dispatch = sample_dispatch();

    // Chain mismatch: the chain id is derived from the dispatch
    // (eip155:8453 -> 8453), so an approval BOUND to a different chain
    // must fail closed against the dispatch chain.
    let mut wrong_chain = dispatch_binding();
    wrong_chain.chain_id = 1;
    let error = build_x402_payment_requirements_with_verified_approval(
        &dispatch,
        "https://facilitator.example/x402",
        "https://tool.example/v1/run",
        vec![DISPATCH_TOKEN_SYMBOL.to_string()],
        X402SettlementMode::PrepaidAuthorization,
        verified_for(wrong_chain),
        APPROVAL_NOW,
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
        vec![DISPATCH_TOKEN_SYMBOL.to_string()],
        X402SettlementMode::PrepaidAuthorization,
        verified_for(wrong_payee),
        APPROVAL_NOW,
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
        vec![DISPATCH_TOKEN_SYMBOL.to_string()],
        X402SettlementMode::PrepaidAuthorization,
        verified_for(wrong_amount),
        APPROVAL_NOW,
    )
    .test_unwrap_err();
    assert!(
        error.to_string().contains("amount mismatch"),
        "got: {error}"
    );
}

#[test]
fn x402_with_verified_approval_rejects_a_dispatch_currency_mismatch() {
    // (5) x402 dispatch currency. The dispatch's own settlement currency
    // must be the approval-bound token, not merely a member of
    // accepted_tokens. Bind the approval to a token that is NOT the
    // dispatch currency (the dispatch settles in DISPATCH_TOKEN_SYMBOL),
    // but DO list that bound token in accepted_tokens so the membership
    // check would pass: the currency assertion must still fail closed.
    let dispatch = sample_dispatch();
    let mut wrong_currency = dispatch_binding();
    wrong_currency.token_symbol = "EURC".to_string();
    let error = build_x402_payment_requirements_with_verified_approval(
        &dispatch,
        "https://facilitator.example/x402",
        "https://tool.example/v1/run",
        // The bound token IS accepted, so only the dispatch-currency check
        // can reject this.
        vec!["EURC".to_string(), DISPATCH_TOKEN_SYMBOL.to_string()],
        X402SettlementMode::PrepaidAuthorization,
        verified_for(wrong_currency),
        APPROVAL_NOW,
    )
    .test_unwrap_err();
    assert!(
        error.to_string().contains("token mismatch"),
        "a dispatch currency that is not the approval-bound token must be rejected, got: {error}"
    );
}

#[test]
fn x402_with_verified_approval_rejects_a_non_eip155_dispatch_chain() {
    // (6) Chain from dispatch. A dispatch whose chain_id is not a valid
    // eip155 namespace cannot be coerced into a numeric chain id, so the
    // verifier fails closed before binding.
    let mut dispatch = sample_dispatch();
    dispatch.chain_id = "solana:mainnet".to_string();
    let error = build_x402_payment_requirements_with_verified_approval(
        &dispatch,
        "https://facilitator.example/x402",
        "https://tool.example/v1/run",
        vec![DISPATCH_TOKEN_SYMBOL.to_string()],
        X402SettlementMode::PrepaidAuthorization,
        verified_for(dispatch_binding()),
        APPROVAL_NOW,
    )
    .test_unwrap_err();
    assert!(
        error.to_string().contains("not an eip155 namespace"),
        "a non-eip155 dispatch chain must be rejected, got: {error}"
    );
}

// -----------------------------------------------------------------
// C2: EIP-3009 lane binds against the verified approval.
// -----------------------------------------------------------------

/// A verified approval whose binding matches `sample_authorization`. The
/// approval token expiry is set to the EIP-3009 sample window so the
/// binding's `approval_expires_at == SAMPLE_VALID_BEFORE` stays within the
/// token (the expiry clamp requires binding expiry <= token expiry).
fn verified_for_eip3009_authorization() -> VerifiedApproval {
    verified_for_with_token_expiry(
        ApprovalBinding {
            chain_id: SAMPLE_CHAIN_ID,
            payee_address: SAMPLE_PAYEE.to_string(),
            amount_minor_units: SAMPLE_VALUE,
            token_symbol: SAMPLE_TOKEN_SYMBOL.to_string(),
            token_contract: Some(SAMPLE_TOKEN_CONTRACT.to_string()),
            approval_expires_at: SAMPLE_VALID_BEFORE,
        },
        SAMPLE_VALID_BEFORE,
    )
}

#[test]
fn eip3009_with_verified_approval_authorizes_a_matching_authorization() {
    let store = InMemoryEip3009NonceStore::new();
    let prepared = prepare_transfer_with_verified_approval(
        sample_domain(),
        sample_authorization(),
        verified_for_eip3009_authorization(),
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
    let approval = verified_for_with_token_expiry(
        ApprovalBinding {
            chain_id: SAMPLE_CHAIN_ID,
            payee_address: "0x1000000000000000000000000000000000000009".to_string(),
            amount_minor_units: SAMPLE_VALUE,
            token_symbol: SAMPLE_TOKEN_SYMBOL.to_string(),
            token_contract: Some(SAMPLE_TOKEN_CONTRACT.to_string()),
            approval_expires_at: SAMPLE_VALID_BEFORE,
        },
        SAMPLE_VALID_BEFORE,
    );
    let error = prepare_transfer_with_verified_approval(
        sample_domain(),
        sample_authorization(),
        approval,
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
        verified_for_eip3009_authorization(),
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
        verified_for(dispatch_binding()),
        APPROVAL_NOW,
    )
    .test_unwrap()
    .test_unwrap();
    assert_eq!(prepared.dispatch_id, dispatch.dispatch_id);
}

#[test]
fn circle_with_verified_approval_rejects_binding_mismatches() {
    let dispatch = sample_dispatch();

    // Chain mismatch: the chain id is derived from the dispatch, so an
    // approval bound to a different chain fails closed.
    let mut wrong_chain = dispatch_binding();
    wrong_chain.chain_id = 1;
    let error = evaluate_circle_nanopayment_with_verified_approval(
        &dispatch,
        &sample_circle_policy(),
        verified_for(wrong_chain),
        APPROVAL_NOW,
    )
    .test_unwrap_err();
    assert!(error.to_string().contains("chain mismatch"), "got: {error}");

    // Payee mismatch.
    let mut wrong_payee = dispatch_binding();
    wrong_payee.payee_address = "0x3333333333333333333333333333333333333333".to_string();
    let error = evaluate_circle_nanopayment_with_verified_approval(
        &dispatch,
        &sample_circle_policy(),
        verified_for(wrong_payee),
        APPROVAL_NOW,
    )
    .test_unwrap_err();
    assert!(error.to_string().contains("payee mismatch"), "got: {error}");

    // Amount mismatch.
    let mut wrong_amount = dispatch_binding();
    wrong_amount.amount_minor_units = DISPATCH_AMOUNT + 1;
    let error = evaluate_circle_nanopayment_with_verified_approval(
        &dispatch,
        &sample_circle_policy(),
        verified_for(wrong_amount),
        APPROVAL_NOW,
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
        verified_for(wrong_token),
        APPROVAL_NOW,
    )
    .test_unwrap_err();
    assert!(error.to_string().contains("token mismatch"), "got: {error}");
}

// -----------------------------------------------------------------
// C2 round-6: single-use, lane-use expiry, and accepted-token filtering.
// -----------------------------------------------------------------

#[test]
fn x402_filters_extra_accepted_tokens_down_to_the_bound_token() {
    // (6) Filter x402 accepted_tokens. The approval is bound to
    // DISPATCH_TOKEN_SYMBOL but the caller offers `[bound, EURC, USDC]`. A
    // membership check alone would return the whole list and still advertise
    // EURC/USDC to the facilitator; the lane must filter the list down to the
    // approval-bound token so only it is advertised.
    let dispatch = sample_dispatch();
    let requirements = build_x402_payment_requirements_with_verified_approval(
        &dispatch,
        "https://facilitator.example/x402",
        "https://tool.example/v1/run",
        vec![
            DISPATCH_TOKEN_SYMBOL.to_string(),
            "EURC".to_string(),
            "USDC".to_string(),
        ],
        X402SettlementMode::PrepaidAuthorization,
        verified_for(dispatch_binding()),
        APPROVAL_NOW,
    )
    .test_unwrap();
    assert_eq!(
        requirements.accepted_tokens,
        vec![DISPATCH_TOKEN_SYMBOL.to_string()],
        "x402 must advertise only the approval-bound token, not the extras"
    );
}

#[test]
fn x402_rejects_settlement_after_approval_expiry_at_lane_use() {
    // (5) Re-check expiry at x402 lane use. The witness is verified inside its
    // window (`approval_expires_at == APPROVAL_NOW + 100`) but the lane is
    // exercised at `approval_expires_at` (held past expiry). The lane-use clock
    // must reject it, so a witness verified just before expiry cannot build
    // requirements after it lapses.
    let dispatch = sample_dispatch();
    let approval = verified_for(dispatch_binding());
    let expiry = approval.binding().approval_expires_at;
    let error = build_x402_payment_requirements_with_verified_approval(
        &dispatch,
        "https://facilitator.example/x402",
        "https://tool.example/v1/run",
        vec![DISPATCH_TOKEN_SYMBOL.to_string()],
        X402SettlementMode::PrepaidAuthorization,
        approval,
        expiry,
    )
    .test_unwrap_err();
    assert!(
        error.to_string().contains("approval expired"),
        "x402 must reject a held witness used at/after approval expiry, got: {error}"
    );
}

#[test]
fn circle_rejects_settlement_after_approval_expiry_at_lane_use() {
    // (5) Re-check expiry at Circle lane use. Same scenario as the x402 lane:
    // a witness held until `approval_expires_at` must be rejected before any
    // payout is prepared.
    let dispatch = sample_dispatch();
    let approval = verified_for(dispatch_binding());
    let expiry = approval.binding().approval_expires_at;
    let error = evaluate_circle_nanopayment_with_verified_approval(
        &dispatch,
        &sample_circle_policy(),
        approval,
        expiry,
    )
    .test_unwrap_err();
    assert!(
        error.to_string().contains("approval expired"),
        "Circle must reject a held witness used at/after approval expiry, got: {error}"
    );
}

#[test]
fn eip3009_rejects_settlement_after_approval_expiry_at_lane_use() {
    // (5) Re-check expiry at EIP-3009 lane use. The approval window closes at
    // its `approval_expires_at`; exercising the lane at that instant (now ==
    // approval_expires_at) must be rejected by the lane-use expiry re-check
    // before any digest is built, even though the rest of the binding matches.
    let store = InMemoryEip3009NonceStore::new();
    let error = prepare_transfer_with_verified_approval(
        sample_domain(),
        sample_authorization(),
        verified_for_eip3009_authorization(),
        SAMPLE_VALID_BEFORE,
        &store,
    )
    .test_unwrap_err();
    assert!(
        error.to_string().contains("expired"),
        "EIP-3009 must reject a held witness used at/after approval expiry, got: {error}"
    );
    assert!(
        store.is_empty().test_unwrap(),
        "an expiry-rejected lane use must not consume a nonce"
    );
}

#[test]
fn a_consumed_witness_cannot_authorize_a_second_transfer() {
    // (2) Single-use witness. The EIP-3009 lane CONSUMES the witness by value,
    // so a single witness prepares exactly one transfer. The witness is moved
    // into the first call and `VerifiedApproval` is NOT `Clone`, so it cannot
    // be retained and reused with a fresh EIP-3009 nonce to forge a second
    // transfer: a second spend must mint its OWN separately-verified witness.
    // The compile-time fn-pointer test pins the by-value signature; here we
    // show the first use succeeds and a second spend requires a fresh witness.
    let store = InMemoryEip3009NonceStore::new();

    let approval = verified_for_eip3009_authorization();
    let first = prepare_transfer_with_verified_approval(
        sample_domain(),
        sample_authorization(),
        approval,
        SAMPLE_NOW,
        &store,
    );
    assert!(
        first.is_ok(),
        "the first lane use of a witness must succeed"
    );

    // `approval` was moved into the first call and cannot be referenced again
    // (it is not `Clone`), so a second transfer with a FRESH nonce must be
    // authorized by a NEW witness rather than a reused one.
    let mut second_authorization = sample_authorization();
    second_authorization.nonce =
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
    let second = prepare_transfer_with_verified_approval(
        sample_domain(),
        second_authorization,
        verified_for_eip3009_authorization(),
        SAMPLE_NOW,
        &store,
    );
    assert!(
        second.is_ok(),
        "a second spend must be authorized by its OWN witness, not a reused one: {second:?}"
    );
}
