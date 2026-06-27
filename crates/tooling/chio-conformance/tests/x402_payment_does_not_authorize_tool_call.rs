//! x402 Test B (M2-13, WS-CL-X402-VERIFY): a verified x402 payment receipt
//! does NOT authorize a tool call, and this holds STRUCTURALLY.
//!
//! Threat: an integrator settles an x402 payment, watches the public
//! settlement verifier return a `"verified"` verdict, and then treats that
//! verified payment as permission to invoke a tool ("I paid, therefore I may
//! call"). A naive system that read the settlement verdict (or its
//! `verified_claims`) as an authorization signal would let payment success
//! escalate into tool-call authority.
//!
//! Invariant (payment is not authorization, by construction): a fully verified
//! `PublicSettlementVerifierReport` binds settlement and payment claims ONLY
//! (`claim.public_settlement.*`). Tool-call authority lives in a disjoint lane
//! (the capability/governance lane) and is carried by the sealed
//! `ToolCallAuthorization` type, whose authorized state is unrepresentable
//! outside `chio-web3`: its only authorizing constructor is
//! `ToolCallAuthorization::from_capability_grant`, which requires an explicit
//! positive capability `ToolGrant` carrying `Operation::Invoke`. The settlement
//! lane exposes no `From`/`Into`, no constructor, and no field read that maps a
//! settlement verdict into that type, so payment success cannot mint a grant.
//!
//! This test proves three fail-closed facts against a REAL fully-verified x402
//! settlement bundle driven through `verify_public_settlement_proof`:
//!
//! 1. The payment settles (verdict `"verified"`, recomputed state `"settled"`),
//!    yet the report authorizes no tool call: `authorizes_tool_call()` is
//!    `false` and `tool_call_authorization()` is the fail-closed DENY decision.
//!    No emitted claim carries tool-call/capability/invoke authority.
//! 2. The non-authorization is STRUCTURAL, not a runtime verdict-string check:
//!    forging the verdict to `"authorized"` and injecting capability-shaped
//!    `verified_claims` does NOT flip the decision, because
//!    `authorizes_tool_call()` reads no field of the report.
//! 3. The ONLY path to an authorized decision is an explicit capability
//!    `ToolGrant` carrying `Operation::Invoke`. A matching `Invoke` grant
//!    authorizes; a wrong-tool or non-`Invoke` grant fails closed; and the
//!    settlement-derived decision is never equal to the authorization a real
//!    capability grant mints. The settlement lane cannot produce one.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_web3::capability::scope::{Operation, ToolGrant};
use chio_web3::crypto::PublicKey;
use chio_web3::settlement_proof::{
    verify_public_settlement_proof, PublicSettlementProofBundle, PublicSettlementVerifierReport,
    PublicSettlementVerifierTrust, ToolCallAuthorization,
};

/// A real, fully-verified public x402 settlement proof bundle: payment settled
/// on Base and every settlement claim recomputes from the kernel-signed anchor.
/// This is the proof-room `valid-offline-finality` fixture whose canonical
/// verifier report records `verdict: "verified"`, `state: "settled"`.
const VALID_SETTLEMENT_BUNDLE: &str = include_str!(
    "../../../../fixtures/proof-room/public-settlement/valid-offline-finality/settlement-proof-bundle.json"
);

fn valid_settlement_bundle() -> PublicSettlementProofBundle {
    serde_json::from_str(VALID_SETTLEMENT_BUNDLE).expect("valid x402 settlement bundle parses")
}

/// Pin the verifier trust to exactly the keys that signed THIS bundle, mirroring
/// the production `public_settlement_verifier_trust_from_env` shape: the trusted
/// capital signer, anchor kernel, beneficiary identity, and oracle keys are
/// taken from the bundle's own signed artifacts so the recompute lane accepts
/// it. The chain (`eip155:8453`) is allow-listed; mainnet is not blocked for
/// this fixture.
fn trust_for(bundle: &PublicSettlementProofBundle) -> PublicSettlementVerifierTrust {
    let capital_signer: PublicKey = bundle
        .settlement_receipt
        .dispatch
        .capital_instruction
        .signer_key
        .clone();
    let anchor_kernel: PublicKey = bundle
        .settlement_receipt
        .reconciled_anchor_proof
        .as_ref()
        .expect("verified bundle carries a reconciled anchor proof")
        .checkpoint_statement
        .kernel_key
        .clone();
    let beneficiary_identity: PublicKey = bundle
        .chain_snapshot
        .beneficiary_identity_binding
        .as_ref()
        .expect("verified bundle carries a beneficiary identity binding")
        .certificate
        .chio_public_key
        .clone();
    let oracle: PublicKey = bundle
        .settlement_receipt
        .oracle_evidence
        .as_ref()
        .expect("verified bundle carries oracle conversion evidence")
        .oracle_public_key
        .clone()
        .expect("oracle conversion evidence carries a signing key");

    PublicSettlementVerifierTrust {
        trusted_capital_signer_keys: vec![capital_signer],
        trusted_anchor_kernel_keys: vec![anchor_kernel],
        trusted_beneficiary_identity_keys: vec![beneficiary_identity],
        trusted_oracle_keys: vec![oracle],
        allowed_chain_ids: vec![bundle.chain_id.clone()],
        mainnet_blocked: false,
        minimum_confirmations: None,
        expected_trust_market_context: None,
        independent_chain_head: None,
    }
}

/// Drive the bundle through the real recompute lane and assert it verifies.
fn verified_report() -> PublicSettlementVerifierReport {
    let bundle = valid_settlement_bundle();
    let trust = trust_for(&bundle);
    let report = verify_public_settlement_proof(&bundle, &trust)
        .expect("a genuine recomputing x402 settlement proof must verify");
    assert_eq!(report.verdict, "verified");
    assert_eq!(report.recomputed_settlement_state, "settled");
    report
}

/// A capability `ToolGrant` carrying `Operation::Invoke`: the ONLY kind of
/// input that can mint an authorized `ToolCallAuthorization`. This is the
/// capability/governance lane, disjoint from the settlement lane.
fn invoke_grant(server_id: &str, tool_name: &str) -> ToolGrant {
    ToolGrant {
        server_id: server_id.to_string(),
        tool_name: tool_name.to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

/// Fact 1: a fully verified x402 payment receipt settles, yet authorizes no
/// tool call. The verified report carries only settlement/payment claims and
/// its tool-call authorization is the fail-closed DENY decision.
#[test]
fn verified_x402_payment_settles_but_does_not_authorize_tool_call() {
    let report = verified_report();

    // The payment settled, but the report occupies the settlement axis only.
    // There is no `"authorized"` verdict to be mistaken for tool-call authority.
    assert_ne!(report.verdict, "authorized");
    assert!(!report.verified_claims.is_empty());
    for claim in &report.verified_claims {
        assert!(
            claim.starts_with("claim.public_settlement."),
            "settlement proof emitted a non-settlement claim: {claim}"
        );
        for forbidden in ["tool_call", "capability", "authoriz", "invoke"] {
            assert!(
                !claim.contains(forbidden),
                "settlement claim must not carry tool-call authority: {claim}"
            );
        }
    }

    // The core x402 Test B assertion: a verified payment does NOT authorize a
    // tool call. The decision is the fail-closed DENY.
    assert!(!report.authorizes_tool_call());
    assert_eq!(
        report.tool_call_authorization(),
        ToolCallAuthorization::denied()
    );
}

/// Fact 2: the payment-is-not-authorization guarantee is STRUCTURAL, not a
/// runtime check over the verdict string or the claim list. Forging the verdict
/// to `"authorized"` and injecting capability-shaped claims does not flip the
/// decision, because `authorizes_tool_call()` reads no field of the report.
#[test]
fn payment_not_authorization_is_structural_not_a_verdict_string_check() {
    let mut report = verified_report();

    // Baseline: the verified report denies tool-call authority.
    assert!(!report.authorizes_tool_call());
    assert_eq!(
        report.tool_call_authorization(),
        ToolCallAuthorization::denied()
    );

    // Forge the verdict and inject capability-shaped, authorization-shaped
    // claims. If non-authorization were a runtime check over `verdict` or
    // `verified_claims`, this adversarial mutation would flip it. It does not:
    // the guard is structural (no field of the report is consulted), so the
    // decision stays the fail-closed DENY.
    report.verdict = "authorized".to_string();
    report.verified_claims = vec![
        "claim.capability.tool_call_authorized".to_string(),
        "claim.public_settlement.invoke_authorized".to_string(),
        "authorized".to_string(),
    ];
    assert!(!report.authorizes_tool_call());
    assert_eq!(
        report.tool_call_authorization(),
        ToolCallAuthorization::denied()
    );
}

/// Fact 3: the ONLY path to an authorized decision is an explicit capability
/// `ToolGrant` carrying `Operation::Invoke`, and the settlement lane cannot mint
/// one. A matching `Invoke` grant authorizes; a wrong-tool or non-`Invoke` grant
/// fails closed; and the settlement report's decision never equals the grant a
/// real capability lane mints.
#[test]
fn only_an_explicit_capability_invoke_grant_authorizes_and_settlement_cannot_mint_one() {
    let report = verified_report();

    // A matching capability grant carrying `Invoke` is the sole authorizing
    // input: this is the capability/governance lane, not the settlement lane.
    let granted = ToolCallAuthorization::from_capability_grant(
        &invoke_grant("srv", "tool_a"),
        "srv",
        "tool_a",
    );
    assert!(granted.is_authorized());

    // Wrong tool fails closed.
    assert!(!ToolCallAuthorization::from_capability_grant(
        &invoke_grant("srv", "tool_a"),
        "srv",
        "tool_b"
    )
    .is_authorized());

    // A grant without the `Invoke` operation fails closed: paying for a result,
    // or being allowed to read one, is not permission to invoke.
    let read_only = ToolGrant {
        operations: vec![Operation::ReadResult],
        ..invoke_grant("srv", "tool_a")
    };
    assert!(
        !ToolCallAuthorization::from_capability_grant(&read_only, "srv", "tool_a").is_authorized()
    );

    // The settlement-derived decision is DENY and is NOT the authorization the
    // capability lane mints. The two lanes are disjoint; payment success can
    // never stand in for an `Invoke` grant.
    assert!(!report.authorizes_tool_call());
    assert_eq!(
        report.tool_call_authorization(),
        ToolCallAuthorization::denied()
    );
    assert_ne!(report.tool_call_authorization(), granted);
}
