use std::collections::HashMap;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use chio_core_types::{
    capability::{
        scope::ChioScope,
        token::{CapabilityToken, CapabilityTokenBody},
    },
    Keypair,
};
use chio_http_core::{
    AuthMethod, CallerIdentity, HttpAuthority, HttpAuthorityError, HttpAuthorityInput,
    HttpAuthorityPolicy, HttpMethod,
};
use chio_security_types::clock::{Clock, ClockError, ClockReading, MonotonicInstant, UnixMillis};
use chio_test_support::prelude::*;

struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn read(&self) -> Result<ClockReading, ClockError> {
        Ok(ClockReading::new(
            UnixMillis::from_secs(self.0.load(Ordering::SeqCst))?,
            MonotonicInstant::from_nanos(1),
        ))
    }
}

fn input<'a>(query: &'a HashMap<String, String>, token: &'a str) -> HttpAuthorityInput<'a> {
    HttpAuthorityInput {
        request_id: "original-input".into(),
        method: HttpMethod::Post,
        route_pattern: "/test".into(),
        path: "/test",
        query,
        caller: CallerIdentity {
            subject: "agent".into(),
            auth_method: AuthMethod::Anonymous,
            verified: false,
            tenant: None,
            agent_id: None,
        },
        body_hash: None,
        body_length: 0,
        session_id: None,
        capability_id_hint: None,
        presented_capability: Some(token),
        requested_tool_server: None,
        requested_tool_name: None,
        requested_arguments: None,
        model_metadata: None,
        unsupported_authorization_extension: None,
        execution_nonce: None,
        policy: HttpAuthorityPolicy::DenyByDefault,
    }
}

#[test]
fn original_capability_and_receipts_share_the_kernel_clock() {
    let clock = Arc::new(TestClock(AtomicU64::new(100)));
    let issuer = Keypair::from_seed(&[27; 32]);
    let authority = HttpAuthority::builder()
        .clock(clock.clone())
        .allow_ephemeral_receipt_log(true)
        .allow_ephemeral_revocation_store(true)
        .build(issuer.clone(), "policy".into())
        .test_expect("authority builds");
    let token = CapabilityToken::sign(
        CapabilityTokenBody {
            id: "capability".into(),
            issuer: issuer.public_key(),
            subject: issuer.public_key(),
            scope: ChioScope {
                grants: vec![chio_http_core::http_authority_tool_grant()],
                ..ChioScope::default()
            },
            issued_at: 90,
            expires_at: 110,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &issuer,
    )
    .test_expect("capability signs");
    let token = serde_json::to_string(&token).test_expect("capability encodes");
    let query = HashMap::new();
    let prepared = authority
        .prepare(input(&query, &token))
        .test_expect("live capability prepares");
    assert!(prepared.verdict.is_allowed());
    let receipt = authority
        .sign_decision_receipt(&prepared)
        .test_expect("receipt signs");
    assert_eq!(receipt.timestamp, 100);
    clock.0.store(111, Ordering::SeqCst);
    let expired = authority
        .prepare(input(&query, &token))
        .test_expect("expired capability is a signed denial");
    assert!(expired.verdict.is_denied());
    clock.0.store(99, Ordering::SeqCst);
    assert!(matches!(
        authority.prepare(input(&query, &token)),
        Err(HttpAuthorityError::Clock(ClockError::WallClockRegression))
    ));
}

#[test]
fn original_capability_failure_is_retained_behind_a_safe_signed_denial() {
    let authority = HttpAuthority::builder()
        .allow_ephemeral_receipt_log(true)
        .allow_ephemeral_revocation_store(true)
        .build(Keypair::from_seed(&[28; 32]), "policy".into())
        .test_expect("authority builds");
    let query = HashMap::new();
    let original = r#"{"private-marker":1,"private-marker":2}"#;
    let prepared = authority
        .prepare(input(&query, original))
        .test_expect("invalid input is a denial");
    assert!(prepared.verdict.is_denied());
    let cause = prepared
        .capability_input_error
        .as_ref()
        .test_expect("native parser cause retained");
    assert!(std::error::Error::source(cause).is_some());
    let receipt = authority
        .sign_decision_receipt(&prepared)
        .test_expect("denial signs");
    let public = serde_json::to_string(&receipt).test_expect("receipt encodes");
    assert!(!public.contains("private-marker"));
}
