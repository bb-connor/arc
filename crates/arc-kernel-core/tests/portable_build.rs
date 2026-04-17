#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Integration test exercising the portable kernel core against a
//! realistic capability + guard + request tuple.
//!
//! This test doubles as the "portable build proof": it drives the
//! public API without touching any `std::*` type, and compiles as a
//! regular `cargo test` target. When `arc-core-types` is made
//! `no_std`, this same file will cross-compile to
//! `wasm32-unknown-unknown` unchanged.

use arc_core_types::capability::{
    ArcScope, CapabilityToken, CapabilityTokenBody, Operation, ToolGrant,
};
use arc_core_types::crypto::Keypair;
use arc_core_types::receipt::{ArcReceiptBody, Decision, ToolCallAction, TrustLevel};
use arc_kernel_core::{
    evaluate, sign_receipt, verify_capability, CapabilityError, EvaluateInput, FixedClock, Guard,
    GuardContext, KernelCoreError, PortableToolCallRequest, Verdict,
};

const ISSUED_AT: u64 = 1_700_000_000;
const EXPIRES_AT: u64 = 1_700_100_000;

fn make_capability(subject: &Keypair, issuer: &Keypair) -> CapabilityToken {
    let scope = ArcScope {
        grants: vec![ToolGrant {
            server_id: "srv-a".to_string(),
            tool_name: "echo".to_string(),
            operations: vec![Operation::Invoke],
            constraints: vec![],
            max_invocations: None,
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: None,
        }],
        resource_grants: vec![],
        prompt_grants: vec![],
    };
    let body = CapabilityTokenBody {
        id: "cap-1".to_string(),
        issuer: issuer.public_key(),
        subject: subject.public_key(),
        scope,
        issued_at: ISSUED_AT,
        expires_at: EXPIRES_AT,
        delegation_chain: vec![],
    };
    CapabilityToken::sign(body, issuer).unwrap()
}

fn make_request(subject: &Keypair) -> PortableToolCallRequest {
    PortableToolCallRequest {
        request_id: "req-1".to_string(),
        tool_name: "echo".to_string(),
        server_id: "srv-a".to_string(),
        agent_id: subject.public_key().to_hex(),
        arguments: serde_json::json!({"msg": "hello"}),
    }
}

struct AllowGuard;

impl Guard for AllowGuard {
    fn name(&self) -> &str {
        "allow-all"
    }
    fn evaluate(&self, _ctx: &GuardContext<'_>) -> Result<Verdict, KernelCoreError> {
        Ok(Verdict::Allow)
    }
}

struct DenyGuard;

impl Guard for DenyGuard {
    fn name(&self) -> &str {
        "deny-all"
    }
    fn evaluate(&self, _ctx: &GuardContext<'_>) -> Result<Verdict, KernelCoreError> {
        Ok(Verdict::Deny)
    }
}

#[test]
fn evaluate_allow_path() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability(&subject, &issuer);
    let request = make_request(&subject);
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];
    let allow_guard = AllowGuard;
    let guards: Vec<&dyn Guard> = vec![&allow_guard];

    let verdict = evaluate(EvaluateInput {
        request: &request,
        capability: &capability,
        trusted_issuers: &trusted,
        clock: &clock,
        guards: &guards,
        session_filesystem_roots: None,
    });

    assert!(verdict.is_allow());
    assert_eq!(verdict.matched_grant_index, Some(0));
    assert!(verdict.verified.is_some());
}

#[test]
fn evaluate_deny_on_guard() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability(&subject, &issuer);
    let request = make_request(&subject);
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];
    let deny_guard = DenyGuard;
    let guards: Vec<&dyn Guard> = vec![&deny_guard];

    let verdict = evaluate(EvaluateInput {
        request: &request,
        capability: &capability,
        trusted_issuers: &trusted,
        clock: &clock,
        guards: &guards,
        session_filesystem_roots: None,
    });

    assert!(verdict.is_deny());
    let reason = verdict.reason.unwrap();
    assert!(reason.contains("deny-all"), "reason was: {reason}");
}

#[test]
fn evaluate_out_of_scope() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability(&subject, &issuer);
    let mut request = make_request(&subject);
    request.tool_name = "unknown-tool".to_string();
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];
    let guards: Vec<&dyn Guard> = vec![];

    let verdict = evaluate(EvaluateInput {
        request: &request,
        capability: &capability,
        trusted_issuers: &trusted,
        clock: &clock,
        guards: &guards,
        session_filesystem_roots: None,
    });

    assert!(verdict.is_deny());
    let reason = verdict.reason.unwrap();
    assert!(reason.contains("not in capability scope"));
}

#[test]
fn evaluate_expired_capability() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability(&subject, &issuer);
    let request = make_request(&subject);
    let clock = FixedClock::new(EXPIRES_AT + 1);
    let trusted = [issuer.public_key()];
    let guards: Vec<&dyn Guard> = vec![];

    let verdict = evaluate(EvaluateInput {
        request: &request,
        capability: &capability,
        trusted_issuers: &trusted,
        clock: &clock,
        guards: &guards,
        session_filesystem_roots: None,
    });

    assert!(verdict.is_deny());
    let reason = verdict.reason.unwrap();
    assert!(reason.contains("expired"));
}

#[test]
fn evaluate_subject_mismatch() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let capability = make_capability(&subject, &issuer);
    let mut request = make_request(&subject);
    request.agent_id = Keypair::generate().public_key().to_hex();
    let clock = FixedClock::new(ISSUED_AT + 1);
    let trusted = [issuer.public_key()];
    let guards: Vec<&dyn Guard> = vec![];

    let verdict = evaluate(EvaluateInput {
        request: &request,
        capability: &capability,
        trusted_issuers: &trusted,
        clock: &clock,
        guards: &guards,
        session_filesystem_roots: None,
    });

    assert!(verdict.is_deny());
    let reason = verdict.reason.unwrap();
    assert!(reason.contains("does not match capability subject"));
}

#[test]
fn verify_capability_untrusted_issuer() {
    let subject = Keypair::generate();
    let issuer = Keypair::generate();
    let other = Keypair::generate();
    let capability = make_capability(&subject, &issuer);
    let clock = FixedClock::new(ISSUED_AT + 1);

    let err = verify_capability(&capability, &[other.public_key()], &clock).unwrap_err();
    assert_eq!(err, CapabilityError::UntrustedIssuer);
}

#[test]
fn sign_receipt_with_backend() {
    let keypair = Keypair::generate();
    let backend = arc_core_types::crypto::Ed25519Backend::new(keypair.clone());

    let body = ArcReceiptBody {
        id: "rcpt-1".to_string(),
        timestamp: ISSUED_AT,
        capability_id: "cap-1".to_string(),
        tool_server: "srv-a".to_string(),
        tool_name: "echo".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"msg": "hi"})).unwrap(),
        decision: Decision::Allow,
        content_hash: "0".repeat(64),
        policy_hash: "0".repeat(64),
        evidence: vec![],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: keypair.public_key(),
    };

    let receipt = sign_receipt(body, &backend).unwrap();
    assert!(receipt.verify_signature().unwrap());
}
