#![cfg(feature = "web3")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chio_core::canonical::CanonicalBytes;
use chio_core::capability::governance::{
    GovernedApprovalDecision, GovernedApprovalToken, GovernedApprovalTokenBody,
    GovernedTransactionIntent, GovernedTransactionIntentBody,
};
use chio_core::capability::scope::MonetaryAmount;
use chio_core::crypto::{ExemptFormat, Keypair};
use chio_core::web3::settlement::Web3SettlementDispatchArtifact;
use chio_security_types::clock::{Clock, ClockError, ClockReading, FixedClock};
use chio_settle::{
    build_x402_payment_requirements, evaluate_circle_nanopayment, verify_governed_approval,
    ApprovalBinding, CircleNanopaymentPolicy, InMemoryApprovalReplayStore, VerifiedApproval,
    X402PaymentRequirements, X402SettlementMode,
};
use chio_settle_types::SettlementError;
use chio_test_support::prelude::*;

#[path = "support/dispatch.rs"]
mod dispatch_support;

struct TestClock(AtomicU64);

impl Clock for TestClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        FixedClock::new(self.0.load(Ordering::SeqCst)).read()
    }
}

struct Fixture {
    approver: Keypair,
    subject: Keypair,
    dispatch: Web3SettlementDispatchArtifact,
    binding: ApprovalBinding,
    clock: Arc<TestClock>,
    replay: Arc<InMemoryApprovalReplayStore>,
}

impl Fixture {
    fn new() -> Self {
        let dispatch = dispatch_support::fixture();
        let capability_id = dispatch
            .capital_instruction
            .body
            .query
            .capability_id
            .clone()
            .test_unwrap();
        Self {
            approver: Keypair::from_seed(&[71; 32]),
            subject: Keypair::from_seed(&[72; 32]),
            binding: ApprovalBinding {
                schema: "chio.settlement-binding.v1".to_string(),
                chain_id: 8453,
                payee_address: dispatch.beneficiary_address.clone(),
                amount_minor_units: u128::from(dispatch.settlement_amount.units),
                token_symbol: "USD".to_string(),
                settlement_currency: "USD".to_string(),
                token_contract: None,
                dispatch_id: dispatch.dispatch_id.clone(),
                capability_id,
            },
            dispatch,
            clock: Arc::new(TestClock(AtomicU64::new(100))),
            replay: Arc::new(InMemoryApprovalReplayStore::default()),
        }
    }

    fn intent(&self) -> GovernedTransactionIntent {
        GovernedTransactionIntent {
            id: "settlement-intent".to_string(),
            server_id: "settlement-server".to_string(),
            tool_name: "settle".to_string(),
            purpose: "approved settlement".to_string(),
            max_amount: Some(MonetaryAmount {
                units: self.dispatch.settlement_amount.units,
                currency: self.binding.settlement_currency.clone(),
            }),
            commerce: None,
            metered_billing: None,
            runtime_attestation: None,
            call_chain: None,
            autonomy: None,
            context: Some(serde_json::json!({"chioSettlementBinding": self.binding})),
            body: GovernedTransactionIntentBody::ToolInvocation,
        }
    }

    fn token(&self, intent: &GovernedTransactionIntent) -> GovernedApprovalToken {
        GovernedApprovalToken::sign(
            GovernedApprovalTokenBody {
                id: "settlement-approval".to_string(),
                approver: self.approver.public_key(),
                subject: self.subject.public_key(),
                governed_intent_hash: intent.binding_hash().test_unwrap(),
                request_id: "settlement-request".to_string(),
                threshold_proposal_hash: None,
                issued_at: 90,
                expires_at: 200,
                decision: GovernedApprovalDecision::Approved,
            },
            &self.approver,
        )
        .test_unwrap()
    }

    fn verify(
        &self,
        token: &GovernedApprovalToken,
        intent: &GovernedTransactionIntent,
    ) -> Result<VerifiedApproval, SettlementError> {
        verify_governed_approval(
            token,
            intent,
            &self.approver.public_key(),
            &self.subject.public_key(),
            "settlement-request",
            self.clock.clone(),
            self.replay.clone(),
        )
    }

    fn witness(&self) -> VerifiedApproval {
        let intent = self.intent();
        self.verify(&self.token(&intent), &intent).test_unwrap()
    }

    fn x402(&self, approval: VerifiedApproval) -> Result<X402PaymentRequirements, SettlementError> {
        build_x402_payment_requirements(
            &self.dispatch,
            approval,
            "https://facilitator.example/x402",
            "https://tool.example/v1/run",
            vec![self.binding.token_symbol.clone()],
            X402SettlementMode::PrepaidAuthorization,
        )
    }

    fn circle(&self, approval: VerifiedApproval) -> Result<(), SettlementError> {
        let prepared = evaluate_circle_nanopayment(
            &self.dispatch,
            approval,
            &CircleNanopaymentPolicy {
                enabled: true,
                managed_balance_id: "balance".to_string(),
                supported_chain_ids: vec!["eip155:8453".to_string()],
                supported_token_symbols: vec!["USD".to_string()],
                max_amount_minor_units: u64::MAX,
                operator_managed_custody_explicit: true,
            },
        )?;
        assert!(prepared.is_some());
        Ok(())
    }
}

fn verification_refused<T: std::fmt::Debug>(result: Result<T, SettlementError>, reason: &str) {
    assert!(matches!(result, Err(SettlementError::Verification(ref actual)) if actual == reason));
}

#[test]
fn valid_signed_approval_issues_one_x402_artifact() {
    let f = Fixture::new();
    let artifact = f.x402(f.witness()).test_unwrap();
    assert_eq!(artifact.dispatch_id, f.binding.dispatch_id);
    assert_eq!(artifact.capability_id, f.binding.capability_id);
    verification_refused(f.x402(f.witness()), "settlement approval already consumed");
}

#[test]
fn a_modified_signature_body_cannot_issue_a_witness() {
    let f = Fixture::new();
    let intent = f.intent();
    let mut token = f.token(&intent);
    token.id.push('x');
    verification_refused(
        f.verify(&token, &intent),
        "settlement approval signature invalid",
    );
    f.x402(f.witness()).test_unwrap();
}

#[test]
fn an_unwrapped_approval_signature_is_refused() {
    let f = Fixture::new();
    let intent = f.intent();
    let mut token = f.token(&intent);
    let canonical = CanonicalBytes::from_serializable(&token.body()).test_unwrap();
    token.signature = f
        .approver
        .sign_exempt(ExemptFormat::JwsSigningInput, canonical.as_bytes());
    verification_refused(
        f.verify(&token, &intent),
        "settlement approval signature invalid",
    );
    f.x402(f.witness()).test_unwrap();
}

#[test]
fn a_valid_signature_from_an_untrusted_approver_is_refused() {
    let f = Fixture::new();
    let intent = f.intent();
    let other = Keypair::from_seed(&[73; 32]);
    let mut body = f.token(&intent).body();
    body.approver = other.public_key();
    let token = GovernedApprovalToken::sign(body, &other).test_unwrap();
    assert!(token.verify_integrity_embedded_key().test_unwrap());
    verification_refused(
        f.verify(&token, &intent),
        "settlement approval approver mismatch",
    );
    f.x402(f.witness()).test_unwrap();
}

#[test]
fn signed_subject_and_request_bindings_are_enforced() {
    for field in ["subject", "request"] {
        let f = Fixture::new();
        let intent = f.intent();
        let mut body = f.token(&intent).body();
        let reason = if field == "subject" {
            body.subject = Keypair::from_seed(&[74; 32]).public_key();
            "settlement approval subject mismatch"
        } else {
            body.request_id.push('x');
            "settlement approval request mismatch"
        };
        let token = GovernedApprovalToken::sign(body, &f.approver).test_unwrap();
        assert!(token.verify_integrity_embedded_key().test_unwrap());
        verification_refused(f.verify(&token, &intent), reason);
        f.x402(f.witness()).test_unwrap();
    }
}

#[test]
fn expired_witness_is_refused_at_artifact_issuance() {
    let f = Fixture::new();
    let witness = f.witness();
    f.clock.0.store(200, Ordering::SeqCst);
    verification_refused(f.x402(witness), "urn:chio:error:kernel:clock-expired");
}

#[test]
fn a_shared_store_prevents_cross_lane_replay_in_both_orders() {
    for circle_first in [false, true] {
        let f = Fixture::new();
        let first = f.witness();
        let second = f.witness();
        if circle_first {
            f.circle(first).test_unwrap();
            verification_refused(f.x402(second), "settlement approval already consumed");
        } else {
            f.x402(first).test_unwrap();
            verification_refused(f.circle(second), "settlement approval already consumed");
        }
    }
}

#[test]
fn x402_uses_the_signed_fiat_currency_independently_of_the_rail_token() {
    let mut f = Fixture::new();
    f.binding.token_symbol = "USDC".to_string();
    let result = f.x402(f.witness()).test_unwrap();
    assert_eq!(result.accepted_tokens, vec!["USDC".to_string()]);
    assert_eq!(result.currency, "USD");
}

#[test]
fn x402_refuses_a_dispatch_with_a_different_signed_fiat_currency_without_consuming() {
    let mut f = Fixture::new();
    f.binding.token_symbol = "USDC".to_string();
    f.binding.settlement_currency = "EUR".to_string();
    let result = f.x402(f.witness());
    assert!(
        matches!(result, Err(SettlementError::InvalidBinding(reason))
        if reason == "x402 settlement currency mismatch")
    );
    f.dispatch.settlement_amount.currency = "EUR".to_string();
    let result = f.x402(f.witness()).test_unwrap();
    assert_eq!(result.currency, "EUR");
}

#[test]
fn symbol_only_lanes_refuse_a_contract_pinned_approval() {
    for circle in [false, true] {
        let mut f = Fixture::new();
        f.binding.token_contract = Some("0x3333333333333333333333333333333333333333".to_string());
        let result = if circle {
            f.circle(f.witness())
        } else {
            f.x402(f.witness()).map(|_| ())
        };
        assert!(
            matches!(result, Err(SettlementError::InvalidBinding(reason))
            if reason == "symbol-only settlement cannot enforce a token contract")
        );
    }
}

#[test]
fn dispatch_identity_comparison_does_not_trim_the_live_identity() {
    let mut f = Fixture::new();
    let witness = f.witness();
    f.dispatch.dispatch_id.push(' ');
    assert!(
        matches!(f.x402(witness), Err(SettlementError::InvalidBinding(reason))
        if reason == "x402 dispatch mismatch")
    );
    f.dispatch.dispatch_id.pop();
    f.x402(f.witness()).test_unwrap();
}

#[test]
fn x402_refuses_missing_capability_identity_without_consuming() {
    let mut f = Fixture::new();
    f.binding.capability_id = f.dispatch.dispatch_id.clone();
    dispatch_support::set_capability(&mut f.dispatch, None);
    assert!(
        matches!(f.x402(f.witness()), Err(SettlementError::InvalidBinding(reason))
        if reason == "x402 capability identity is missing")
    );
    dispatch_support::set_capability(&mut f.dispatch, Some(f.binding.capability_id.clone()));
    f.x402(f.witness()).test_unwrap();
}

#[test]
fn circle_refuses_missing_capability_identity_without_consuming() {
    let mut f = Fixture::new();
    f.binding.capability_id = f.dispatch.dispatch_id.clone();
    dispatch_support::set_capability(&mut f.dispatch, None);
    assert!(
        matches!(f.circle(f.witness()), Err(SettlementError::InvalidBinding(reason))
        if reason == "circle capability identity is missing")
    );
    dispatch_support::set_capability(&mut f.dispatch, Some(f.binding.capability_id.clone()));
    f.circle(f.witness()).test_unwrap();
}

#[test]
fn circle_requires_the_exact_signed_capability_identity() {
    let mut f = Fixture::new();
    let witness = f.witness();
    let original = f
        .dispatch
        .capital_instruction
        .body
        .query
        .capability_id
        .clone();
    f.dispatch.capital_instruction.body.query.capability_id =
        Some(format!("{} ", f.binding.capability_id));
    assert!(
        matches!(f.circle(witness), Err(SettlementError::InvalidBinding(reason))
        if reason == "circle capability mismatch")
    );
    f.dispatch.capital_instruction.body.query.capability_id = original;
    f.circle(f.witness()).test_unwrap();
}

#[test]
fn circle_refuses_a_separate_fiat_currency_for_a_token_native_payout() {
    let mut f = Fixture::new();
    f.binding.token_symbol = "USDC".to_string();
    assert!(
        matches!(f.circle(f.witness()), Err(SettlementError::InvalidBinding(reason))
        if reason == "circle requires token-native settlement currency")
    );
}

#[test]
fn a_signature_over_another_intent_is_refused() {
    let f = Fixture::new();
    let mut intent = f.intent();
    let token = f.token(&intent);
    intent.purpose.push('x');
    verification_refused(
        f.verify(&token, &intent),
        "settlement approval intent mismatch",
    );
    f.x402(f.witness()).test_unwrap();
}

#[test]
fn a_signed_denial_cannot_issue_a_witness() {
    let f = Fixture::new();
    let intent = f.intent();
    let mut body = f.token(&intent).body();
    body.decision = GovernedApprovalDecision::Denied;
    let token = GovernedApprovalToken::sign(body, &f.approver).test_unwrap();
    verification_refused(
        f.verify(&token, &intent),
        "settlement approval decision denied",
    );
    f.x402(f.witness()).test_unwrap();
}

#[test]
fn approval_lifetime_above_one_hour_is_refused() {
    let f = Fixture::new();
    let intent = f.intent();
    let mut body = f.token(&intent).body();
    body.expires_at = body.issued_at + 3601;
    let token = GovernedApprovalToken::sign(body, &f.approver).test_unwrap();
    verification_refused(
        f.verify(&token, &intent),
        "settlement approval lifetime exceeds 3600 seconds",
    );
    f.x402(f.witness()).test_unwrap();
}

#[test]
fn a_maximum_amount_without_a_signed_settlement_commitment_is_refused() {
    let f = Fixture::new();
    let mut intent = f.intent();
    intent.context = None;
    verification_refused(
        f.verify(&f.token(&intent), &intent),
        "settlement approval requires a signed settlement binding",
    );
    f.x402(f.witness()).test_unwrap();
}

#[test]
fn the_signed_maximum_clamps_the_committed_amount() {
    let f = Fixture::new();
    let mut intent = f.intent();
    intent.max_amount.as_mut().test_unwrap().units = 0;
    verification_refused(
        f.verify(&f.token(&intent), &intent),
        "settlement binding exceeds the signed maximum amount",
    );
    f.x402(f.witness()).test_unwrap();
}

#[test]
fn a_regressing_clock_cannot_extend_a_witness() {
    let f = Fixture::new();
    let witness = f.witness();
    f.clock.0.store(99, Ordering::SeqCst);
    verification_refused(
        f.x402(witness),
        "urn:chio:error:kernel:clock-wall-clock-regression",
    );
}
