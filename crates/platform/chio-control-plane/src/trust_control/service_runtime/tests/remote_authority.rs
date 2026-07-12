use super::super::super::*;
use super::super::pinned_authority::PinnedControlAuthority;
use super::super::remote_authority::{
    build_remote_capability_authority, build_remote_capability_authority_for_test,
};
use super::support::{
    assert_bearer_request, assert_json_post, ScriptedResponse, ScriptedResponseServer,
};
use chio_core::capability::runtime_attestation::RuntimeAssuranceTier;
use chio_core::capability::scope::{Operation, ToolGrant};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_test_support::prelude::*;

fn pinned_authority(current: &Keypair, historical: Vec<PublicKey>) -> PinnedControlAuthority {
    PinnedControlAuthority::new(current.public_key(), historical).test_unwrap()
}

fn authority_status(current: &Keypair, advertised_trusted_keys: Vec<String>) -> String {
    serde_json::to_string(&TrustAuthorityStatus {
        configured: true,
        backend: Some("sqlite".to_string()),
        public_key: Some(current.public_key().to_hex()),
        generation: Some(7),
        rotated_at: Some(1_000),
        applies_to_future_sessions_only: true,
        trusted_public_keys: advertised_trusted_keys,
    })
    .test_unwrap()
}

fn test_scope(tool_name: &str) -> ChioScope {
    ChioScope {
        grants: vec![ToolGrant {
            server_id: "remote-authority-tests".to_string(),
            tool_name: tool_name.to_string(),
            operations: vec![Operation::Invoke],
            constraints: Vec::new(),
            max_invocations: Some(1),
            max_cost_per_invocation: None,
            max_total_cost: None,
            dpop_required: Some(true),
        }],
        resource_grants: Vec::new(),
        prompt_grants: Vec::new(),
    }
}

fn signed_capability(
    issuer: &Keypair,
    subject: PublicKey,
    scope: ChioScope,
    issued_at: u64,
    expires_at: u64,
) -> CapabilityToken {
    CapabilityToken::sign(
        CapabilityTokenBody {
            id: "remote-issued-capability".to_string(),
            issuer: issuer.public_key(),
            subject,
            scope,
            issued_at,
            expires_at,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        issuer,
    )
    .test_unwrap()
}

fn capability_response(
    request: &IssueCapabilityRequest,
    capability: CapabilityToken,
    signer: &Keypair,
) -> String {
    let signed = SignedIssueCapabilityResponse::sign(
        request,
        capability,
        signer,
        7,
        1_000,
        unix_timestamp_now(),
    )
    .test_unwrap();
    String::from_utf8(canonical_json_bytes(&signed).test_unwrap()).test_unwrap()
}

fn bound_authority_server(
    current: &Keypair,
    capability: CapabilityToken,
) -> ScriptedResponseServer {
    let current = current.clone();
    ScriptedResponseServer::spawn_dynamic(2, move |request| {
        if request.method == "GET" {
            return ScriptedResponse {
                status: 200,
                body: authority_status(&current, Vec::new()),
                content_type: "application/json",
            };
        }
        let issue_request: IssueCapabilityRequest =
            serde_json::from_str(&request.body).test_unwrap();
        ScriptedResponse {
            status: 200,
            body: capability_response(&issue_request, capability.clone(), &current),
            content_type: "application/json",
        }
    })
}

fn runtime_attestation(now: u64) -> RuntimeAttestationEvidence {
    RuntimeAttestationEvidence {
        schema: "test.runtime-attestation.v1".to_string(),
        verifier: "https://verifier.example.test".to_string(),
        tier: RuntimeAssuranceTier::Attested,
        issued_at: now.saturating_sub(1),
        expires_at: now.saturating_add(300),
        evidence_sha256: "ab".repeat(32),
        runtime_identity: Some("runtime://remote-authority-test".to_string()),
        workload_identity: None,
        claims: Some(json!({ "environment": "test" })),
    }
}

#[test]
fn remote_capability_authority_uses_only_the_pinned_trust_bundle() {
    let current = Keypair::generate();
    let historical = Keypair::generate();
    let attacker = Keypair::generate();
    let server = ScriptedResponseServer::spawn(vec![ScriptedResponse {
        status: 200,
        body: authority_status(
            &current,
            vec![
                "not-a-public-key".to_string(),
                attacker.public_key().to_hex(),
            ],
        ),
        content_type: "application/json",
    }]);

    let authority = build_remote_capability_authority_for_test(
        &server.url,
        "secret",
        pinned_authority(&current, vec![historical.public_key()]),
    )
    .test_unwrap();

    assert_eq!(authority.authority_public_key(), current.public_key());
    assert_eq!(authority.trusted_public_keys(), vec![current.public_key()]);
    assert!(!authority
        .trusted_public_keys()
        .contains(&attacker.public_key()));
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_bearer_request(&requests[0], "GET", AUTHORITY_PATH, &[]);
}

#[test]
fn remote_capability_authority_requires_exact_current_pin_and_https() {
    let pinned = Keypair::generate();
    let attacker = Keypair::generate();
    let mismatch_server = ScriptedResponseServer::spawn(vec![ScriptedResponse {
        status: 200,
        body: authority_status(&attacker, vec![pinned.public_key().to_hex()]),
        content_type: "application/json",
    }]);

    let mismatch_error = match build_remote_capability_authority_for_test(
        &mismatch_server.url,
        "secret",
        pinned_authority(&pinned, Vec::new()),
    ) {
        Ok(_) => panic!("endpoint current signer must not replace the independent pin"),
        Err(error) => error,
    };
    assert!(mismatch_error
        .to_string()
        .contains("does not match the pinned"));

    let transport_error = match build_remote_capability_authority(
        "http://127.0.0.1:1",
        "secret",
        pinned_authority(&pinned, Vec::new()),
    ) {
        Ok(_) => panic!("public remote authority construction must require HTTPS"),
        Err(error) => error,
    };
    assert!(transport_error.to_string().contains("requires HTTPS"));
}

#[test]
fn remote_capability_authority_forwards_exact_attestation_and_accepts_bound_token() {
    let current = Keypair::generate();
    let subject = Keypair::generate();
    let scope = test_scope("bound");
    let now = unix_timestamp_now();
    let attestation = runtime_attestation(now);
    let capability = signed_capability(
        &current,
        subject.public_key(),
        scope.clone(),
        now,
        now.saturating_add(60),
    );
    let server = bound_authority_server(&current, capability.clone());
    let authority = build_remote_capability_authority_for_test(
        &server.url,
        "secret",
        pinned_authority(&current, Vec::new()),
    )
    .test_unwrap();

    let issued = authority
        .issue_capability_with_attestation(
            &subject.public_key(),
            scope.clone(),
            60,
            Some(attestation.clone()),
        )
        .test_unwrap();
    assert_eq!(issued.id, capability.id);

    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    let subject_fragment = format!("\"subjectPublicKey\":\"{}\"", subject.public_key().to_hex());
    let attestation_issued_at = format!("\"issued_at\":{}", attestation.issued_at);
    let attestation_expires_at = format!("\"expires_at\":{}", attestation.expires_at);
    assert_json_post(
        &requests[1],
        ISSUE_CAPABILITY_PATH,
        &[
            &subject_fragment,
            "\"scope\":{",
            "\"server_id\":\"remote-authority-tests\"",
            "\"tool_name\":\"bound\"",
            "\"operations\":[\"invoke\"]",
            "\"max_invocations\":1",
            "\"dpop_required\":true",
            "\"ttlSeconds\":60",
            "\"schema\":\"chio.capability-issuance-request.v1\"",
            "\"requestNonce\":",
            "\"requestedAt\":",
            "\"runtimeAttestation\":{",
            "\"schema\":\"test.runtime-attestation.v1\"",
            "\"verifier\":\"https://verifier.example.test\"",
            "\"tier\":\"attested\"",
            &attestation_issued_at,
            &attestation_expires_at,
            "\"evidence_sha256\":\"abababababababababababababababababababababababababababababababab\"",
            "\"runtime_identity\":\"runtime://remote-authority-test\"",
            "\"claims\":{\"environment\":\"test\"}",
        ],
    );
}

#[test]
fn remote_capability_authority_rejects_unbound_or_invalid_responses() {
    let current = Keypair::generate();
    let attacker = Keypair::generate();
    let subject = Keypair::generate();
    let other_subject = Keypair::generate();
    let requested_scope = test_scope("requested");
    let now = unix_timestamp_now();

    let attacker_issued = signed_capability(
        &attacker,
        subject.public_key(),
        requested_scope.clone(),
        now,
        now.saturating_add(60),
    );
    let mut invalid_signature = signed_capability(
        &attacker,
        subject.public_key(),
        requested_scope.clone(),
        now,
        now.saturating_add(60),
    );
    invalid_signature.issuer = current.public_key();
    let wrong_subject = signed_capability(
        &current,
        other_subject.public_key(),
        requested_scope.clone(),
        now,
        now.saturating_add(60),
    );
    let wrong_scope = signed_capability(
        &current,
        subject.public_key(),
        test_scope("broader"),
        now,
        now.saturating_add(60),
    );
    let excessive_lifetime = signed_capability(
        &current,
        subject.public_key(),
        requested_scope.clone(),
        now,
        now.saturating_add(61),
    );

    let cases = [
        ("current pinned signer", attacker_issued),
        ("signature", invalid_signature),
        ("subject", wrong_subject),
        ("scope", wrong_scope),
        ("lifetime", excessive_lifetime),
    ];

    for (expected_error, capability) in cases {
        let envelope_signer = if expected_error == "current pinned signer" {
            &attacker
        } else {
            &current
        };
        let status_current = current.clone();
        let envelope_signer = envelope_signer.clone();
        let server = ScriptedResponseServer::spawn_dynamic(2, move |request| {
            if request.method == "GET" {
                return ScriptedResponse {
                    status: 200,
                    body: authority_status(&status_current, Vec::new()),
                    content_type: "application/json",
                };
            }
            let issue_request: IssueCapabilityRequest =
                serde_json::from_str(&request.body).test_unwrap();
            ScriptedResponse {
                status: 200,
                body: capability_response(&issue_request, capability.clone(), &envelope_signer),
                content_type: "application/json",
            }
        });
        let authority = build_remote_capability_authority_for_test(
            &server.url,
            "secret",
            pinned_authority(&current, vec![attacker.public_key()]),
        )
        .test_unwrap();

        let error = authority
            .issue_capability(&subject.public_key(), requested_scope.clone(), 60)
            .test_unwrap_err();
        let error_text = error.to_string();
        assert!(
            error_text.contains(expected_error)
                || (expected_error == "current pinned signer"
                    && error_text.contains("response signer is not pinned")),
            "expected {expected_error:?} rejection, got {error}"
        );
        assert_eq!(authority.authority_public_key(), current.public_key());
        assert_eq!(authority.trusted_public_keys(), vec![current.public_key()]);
    }
}

#[test]
fn remote_capability_authority_rejects_ttl_overflow_before_remote_issue() {
    let current = Keypair::generate();
    let subject = Keypair::generate();
    let server = ScriptedResponseServer::spawn(vec![ScriptedResponse {
        status: 200,
        body: authority_status(&current, Vec::new()),
        content_type: "application/json",
    }]);
    let authority = build_remote_capability_authority_for_test(
        &server.url,
        "secret",
        pinned_authority(&current, Vec::new()),
    )
    .test_unwrap();

    let error = authority
        .issue_capability(&subject.public_key(), test_scope("overflow"), u64::MAX)
        .test_unwrap_err();
    assert!(error.to_string().contains("overflows"));
    assert_eq!(
        server.requests().len(),
        1,
        "overflow must fail before an issuance POST"
    );
}

#[test]
fn remote_capability_authority_rejects_response_bound_to_different_attestation() {
    let current = Keypair::generate();
    let subject = Keypair::generate();
    let scope = test_scope("attestation-binding");
    let now = unix_timestamp_now();
    let capability = signed_capability(
        &current,
        subject.public_key(),
        scope.clone(),
        now,
        now.saturating_add(60),
    );
    let status_current = current.clone();
    let response_signer = current.clone();
    let server = ScriptedResponseServer::spawn_dynamic(2, move |request| {
        if request.method == "GET" {
            return ScriptedResponse {
                status: 200,
                body: authority_status(&status_current, Vec::new()),
                content_type: "application/json",
            };
        }
        let mut different_request: IssueCapabilityRequest =
            serde_json::from_str(&request.body).test_unwrap();
        different_request.runtime_attestation = None;
        ScriptedResponse {
            status: 200,
            body: capability_response(&different_request, capability.clone(), &response_signer),
            content_type: "application/json",
        }
    });
    let authority = build_remote_capability_authority_for_test(
        &server.url,
        "secret",
        pinned_authority(&current, Vec::new()),
    )
    .test_unwrap();

    let error = authority
        .issue_capability_with_attestation(
            &subject.public_key(),
            scope,
            60,
            Some(runtime_attestation(now)),
        )
        .test_unwrap_err();

    assert!(error.to_string().contains("request binding mismatch"));
}

#[test]
fn remote_capability_authority_validates_status_and_issue_per_failover_endpoint() {
    let current = Keypair::generate();
    let stale = Keypair::generate();
    let subject = Keypair::generate();
    let scope = test_scope("failover");
    let now = unix_timestamp_now();
    let capability = signed_capability(
        &current,
        subject.public_key(),
        scope.clone(),
        now,
        now.saturating_add(60),
    );
    let stale_server = ScriptedResponseServer::spawn(vec![ScriptedResponse {
        status: 200,
        body: authority_status(&stale, Vec::new()),
        content_type: "application/json",
    }]);
    let healthy_server = bound_authority_server(&current, capability.clone());
    let authority = build_remote_capability_authority_for_test(
        &format!("{},{}", stale_server.url, healthy_server.url),
        "secret",
        pinned_authority(&current, vec![stale.public_key()]),
    )
    .test_unwrap();

    let issued = authority
        .issue_capability(&subject.public_key(), scope, 60)
        .test_unwrap();

    assert_eq!(issued.id, capability.id);
    assert_eq!(stale_server.requests().len(), 1);
    assert_eq!(healthy_server.requests().len(), 2);
}

#[test]
fn remote_capability_authority_skips_invalid_issue_response() {
    let current = Keypair::generate();
    let subject = Keypair::generate();
    let scope = test_scope("issue-failover");
    let now = unix_timestamp_now();
    let capability = signed_capability(
        &current,
        subject.public_key(),
        scope.clone(),
        now,
        now.saturating_add(60),
    );
    let first = ScriptedResponseServer::spawn(vec![
        ScriptedResponse {
            status: 200,
            body: authority_status(&current, Vec::new()),
            content_type: "application/json",
        },
        ScriptedResponse {
            status: 200,
            body: "not-json".to_string(),
            content_type: "application/json",
        },
    ]);
    let response_signer = current.clone();
    let second = ScriptedResponseServer::spawn_dynamic(1, move |request| {
        let issue_request: IssueCapabilityRequest =
            serde_json::from_str(&request.body).test_unwrap();
        ScriptedResponse {
            status: 200,
            body: capability_response(&issue_request, capability.clone(), &response_signer),
            content_type: "application/json",
        }
    });
    let authority = build_remote_capability_authority_for_test(
        &format!("{},{}", first.url, second.url),
        "secret",
        pinned_authority(&current, Vec::new()),
    )
    .test_unwrap();

    let issued = authority
        .issue_capability(&subject.public_key(), scope, 60)
        .test_unwrap();

    assert_eq!(issued.id, "remote-issued-capability");
    assert_eq!(first.requests().len(), 2);
    assert_eq!(second.requests().len(), 1);
}
