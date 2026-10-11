//! A signed security context must not become an unbound HTTP grant.
use std::collections::HashMap;
use std::sync::Arc;

use chio_core_types::{
    capability::{
        caveat::{CapabilitySecurityBinding, CAPABILITY_SECURITY_BINDING_SCHEMA},
        scope::ChioScope,
        token::{CapabilityToken, CapabilityTokenBody},
    },
    Keypair,
};
use chio_http_core::{
    http_authority_tool_grant, CallerIdentity, HttpAuthority, HttpAuthorityInput,
    HttpAuthorityPolicy, HttpMethod, Verdict, HTTP_AUTHORITY_SERVER_ID,
};
use chio_security_types::clock::FixedClock;
use chio_test_support::prelude::*;

fn body(issuer: &Keypair) -> CapabilityTokenBody {
    CapabilityTokenBody {
        id: "security-binding-projection".into(),
        issuer: issuer.public_key(),
        subject: issuer.public_key(),
        scope: ChioScope {
            grants: vec![http_authority_tool_grant()],
            ..ChioScope::default()
        },
        issued_at: 90,
        expires_at: 110,
        delegation_chain: Vec::new(),
        aggregate_invocation_budget: None,
    }
}

fn binding(issuer: &Keypair) -> CapabilitySecurityBinding {
    CapabilitySecurityBinding {
        schema: CAPABILITY_SECURITY_BINDING_SCHEMA.into(),
        tenant_id: "tenant-a".into(),
        lineage_id: "lineage-a".into(),
        session_id: "session-a".into(),
        principal_id: issuer.public_key().to_hex(),
        isolation_epoch_id: "epoch-a".into(),
        context_generation: 1,
        workload_id: "workload-a".into(),
        server_id: HTTP_AUTHORITY_SERVER_ID.into(),
        workload_signer_public_key: issuer.public_key().to_hex(),
    }
}

fn authority(issuer: &Keypair) -> HttpAuthority {
    HttpAuthority::builder()
        .clock(Arc::new(FixedClock::new(100)))
        .allow_ephemeral_receipt_log(true)
        .allow_ephemeral_revocation_store(true)
        .build(issuer.clone(), "binding-policy".into())
        .test_expect("authority builds with the token's trusted issuer")
}

fn input<'a>(query: &'a HashMap<String, String>, raw: &'a str) -> HttpAuthorityInput<'a> {
    HttpAuthorityInput {
        request_id: "security-binding-request".into(),
        method: HttpMethod::Post,
        route_pattern: "/pets".into(),
        path: "/pets",
        query,
        caller: CallerIdentity::anonymous(),
        body_hash: None,
        body_length: 0,
        session_id: None,
        capability_id_hint: None,
        presented_capability: Some(raw),
        requested_tool_server: None,
        requested_tool_name: None,
        requested_arguments: None,
        model_metadata: None,
        unsupported_authorization_extension: None,
        execution_nonce: None,
        policy: HttpAuthorityPolicy::DenyByDefault,
    }
}

fn bound_projection_denies(session: Option<&str>, policy: HttpAuthorityPolicy) {
    let issuer = Keypair::from_seed(&[42; 32]);
    let binding = binding(&issuer);
    let token =
        CapabilityToken::sign_with_security_binding(body(&issuer), binding.clone(), &issuer)
            .test_expect("the trusted issuer signs the complete binding");
    assert!(token.verify_signature().test_unwrap());
    assert_eq!(token.security_binding().test_unwrap(), Some(binding));
    token.validate_time(100).test_unwrap();
    let raw = serde_json::to_string(&token).test_unwrap();
    let authority = authority(&issuer);
    let query = HashMap::new();
    let mut request = input(&query, &raw);
    request.session_id = session.map(str::to_owned);
    request.policy = policy;
    if let Some(session) = session {
        // These transport labels cannot authenticate an invocation context,
        // including when a caller copies every available matching label.
        let matching = session == "session-a";
        request.caller.subject = issuer.public_key().to_hex();
        request.caller.agent_id = Some(issuer.public_key().to_hex());
        request.caller.tenant = Some(if matching { "tenant-a" } else { "tenant-b" }.into());
    }
    let prepared = authority.prepare(request).test_unwrap();
    assert!(
        matches!(&prepared.verdict, Verdict::Deny { reason, .. }
            if reason.contains("security-bound capabilities require authenticated context-preserving kernel dispatch")),
        "bound capability projected through {session:?} / {policy:?}: {:?}",
        prepared.verdict
    );
    assert!(prepared.capability_id.is_none());
    let receipt = authority.sign_decision_receipt(&prepared).test_unwrap();
    assert!(receipt.verify_signature().test_unwrap());
    assert!(receipt.capability_id.is_none());
}

#[test]
fn security_binding_projection_denies_absent_context() {
    bound_projection_denies(None, HttpAuthorityPolicy::DenyByDefault);
}

#[test]
fn security_binding_projection_denies_wrong_session_labels() {
    bound_projection_denies(Some("session-b"), HttpAuthorityPolicy::DenyByDefault);
}

#[test]
fn security_binding_projection_denies_copied_matching_labels() {
    bound_projection_denies(Some("session-a"), HttpAuthorityPolicy::DenyByDefault);
}

#[test]
fn security_binding_projection_denies_session_allow_fallback() {
    bound_projection_denies(None, HttpAuthorityPolicy::SessionAllow);
}

#[test]
fn security_binding_projection_preserves_unbound_capability() {
    let issuer = Keypair::from_seed(&[42; 32]);
    let token = CapabilityToken::sign(body(&issuer), &issuer).test_unwrap();
    assert!(token.verify_signature().test_unwrap());
    assert!(token.security_binding().test_unwrap().is_none());
    let raw = serde_json::to_string(&token).test_unwrap();
    let query = HashMap::new();
    let result = authority(&issuer)
        .evaluate(input(&query, &raw))
        .test_unwrap();
    assert!(result.verdict.is_allowed());
    assert_eq!(
        result.receipt.capability_id.as_deref(),
        Some(token.id.as_str())
    );
    assert!(result.receipt.verify_signature().test_unwrap());
}

#[test]
fn security_binding_projection_preserves_dpop_refusal() {
    let issuer = Keypair::from_seed(&[42; 32]);
    let mut token_body = body(&issuer);
    let mut grant = http_authority_tool_grant();
    grant.dpop_required = Some(true);
    token_body.scope.grants = vec![grant];
    let token = CapabilityToken::sign(token_body, &issuer).test_unwrap();
    assert!(token.verify_signature().test_unwrap());
    assert!(token.security_binding().test_unwrap().is_none());
    let raw = serde_json::to_string(&token).test_unwrap();
    let query = HashMap::new();
    let result = authority(&issuer)
        .evaluate(input(&query, &raw))
        .test_unwrap();
    assert!(matches!(&result.verdict, Verdict::Deny { reason, .. }
        if reason.contains("proof-required capabilities require kernel-mediated dispatch")));
    assert!(result.receipt.verify_signature().test_unwrap());
}
