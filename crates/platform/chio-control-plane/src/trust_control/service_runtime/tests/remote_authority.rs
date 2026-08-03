use super::super::super::*;
use super::super::pinned_authority::PinnedControlAuthority;
use super::super::remote_authority::{
    build_remote_capability_authority_for_test as build_remote_capability_authority_for_test_inner,
    build_remote_capability_authority_for_test_with_runtime,
    require_authenticated_authority_transport, RemoteCapabilityAuthorityTestRuntime,
};
use super::super::remote_capability_request_store::{
    request_recovery_expiry, BoundedMemoryRemoteCapabilityRequestStore,
    RemoteCapabilityIssuanceClock, RemoteCapabilityRequestStore,
    SqliteRemoteCapabilityRequestStore, StoredRemoteCapabilityRequest,
    StoredRemoteCapabilityRequestSelection,
};
use super::support::{
    assert_bearer_request, assert_json_post, ScriptedResponse, ScriptedResponseServer,
};
use chio_core::capability::runtime_attestation::RuntimeAssuranceTier;
use chio_core::capability::scope::{Operation, ToolGrant};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_test_support::prelude::*;

struct FixedRemoteCapabilityClock {
    now: std::sync::atomic::AtomicU64,
}

impl FixedRemoteCapabilityClock {
    fn new(now: u64) -> Self {
        Self {
            now: std::sync::atomic::AtomicU64::new(now),
        }
    }

    fn set(&self, now: u64) {
        self.now.store(now, std::sync::atomic::Ordering::SeqCst);
    }
}

impl RemoteCapabilityIssuanceClock for FixedRemoteCapabilityClock {
    fn now_unix_seconds(&self) -> Result<u64, String> {
        Ok(self.now.load(std::sync::atomic::Ordering::SeqCst))
    }
}

struct FixedStoredRemoteCapabilityRequestStore {
    stored: StoredRemoteCapabilityRequest,
}

impl RemoteCapabilityRequestStore for FixedStoredRemoteCapabilityRequestStore {
    fn load(
        &self,
        _pending_identity: &str,
        _now: u64,
    ) -> Result<Option<StoredRemoteCapabilityRequest>, String> {
        Ok(Some(self.stored.clone()))
    }

    fn load_or_insert(
        &self,
        _pending_identity: &str,
        _candidate: &IssueCapabilityRequest,
        _recovery_expires_at: u64,
        _now: u64,
    ) -> Result<StoredRemoteCapabilityRequestSelection, String> {
        Err("mismatched fixed store must not insert".to_string())
    }

    fn remove_if_exact(
        &self,
        _pending_identity: &str,
        _canonical_request: &[u8],
        _recovery_expires_at: u64,
    ) -> Result<(), String> {
        Err("mismatched fixed store must not remove".to_string())
    }
}

fn pinned_authority(current: &Keypair, historical: Vec<PublicKey>) -> PinnedControlAuthority {
    PinnedControlAuthority::new(current.public_key(), historical).test_unwrap()
}

fn build_remote_capability_authority_for_test(
    control_url: &str,
    workload_token: &str,
    pinned: PinnedControlAuthority,
) -> Result<Box<dyn CapabilityAuthority>, CliError> {
    build_remote_capability_authority_for_test_inner(
        control_url,
        workload_token,
        pinned,
        "tenant-remote-authority",
        "workload-remote-authority",
        "remote-authority-tests",
        Keypair::generate(),
        Keypair::generate(),
    )
}

fn build_remote_capability_authority_with_runtime_for_test(
    control_url: &str,
    workload_token: &str,
    pinned: PinnedControlAuthority,
    workload_signer: Keypair,
    session_admission_signer: Keypair,
    pending_requests: Arc<dyn RemoteCapabilityRequestStore>,
    clock: Arc<dyn RemoteCapabilityIssuanceClock>,
) -> Result<Box<dyn CapabilityAuthority>, CliError> {
    build_remote_capability_authority_for_test_with_runtime(
        control_url,
        workload_token,
        pinned,
        "tenant-remote-authority",
        "workload-remote-authority",
        "remote-authority-tests",
        RemoteCapabilityAuthorityTestRuntime {
            workload_signer,
            session_admission_signer,
            pending_requests,
            issuance_clock: clock,
        },
    )
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

fn issue_with_context(
    authority: &dyn CapabilityAuthority,
    subject: &PublicKey,
    scope: ChioScope,
    ttl_seconds: u64,
    runtime_attestation: Option<RuntimeAttestationEvidence>,
) -> Result<CapabilityToken, chio_kernel::KernelError> {
    authority.issue_capability_with_security_context(
        subject,
        scope,
        ttl_seconds,
        runtime_attestation,
        &chio_kernel::CapabilityIssuanceContext {
            tenant_id: chio_security_types::ports::TenantId::new("tenant-remote-authority")
                .test_unwrap(),
            lineage_id: chio_security_types::ports::LineageId::new("lineage-remote-authority")
                .test_unwrap(),
            session_id: Some(
                chio_security_types::ports::SessionId::new("session-remote-authority")
                    .test_unwrap(),
            ),
            principal_id: Some(
                chio_security_types::PrincipalId::new("principal-remote-authority").test_unwrap(),
            ),
            isolation_epoch_id: Some(
                chio_security_types::ports::IsolationEpochId::new("isolation-remote-authority")
                    .test_unwrap(),
            ),
            context_generation: Some(1),
        },
    )
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

fn security_bound_capability_for_request(
    issuer: &Keypair,
    request: &IssueCapabilityRequest,
    issued_at: u64,
    expires_at: u64,
) -> CapabilityToken {
    let template = signed_capability(
        issuer,
        PublicKey::from_hex(&request.subject_public_key).test_unwrap(),
        request.scope.clone(),
        issued_at,
        expires_at,
    );
    bind_capability_template_to_request(&template, request, issuer)
}

fn bind_capability_template_to_request(
    template: &CapabilityToken,
    request: &IssueCapabilityRequest,
    issuer: &Keypair,
) -> CapabilityToken {
    CapabilityToken::sign_with_security_binding(
        CapabilityTokenBody {
            id: template.id.clone(),
            issuer: template.issuer.clone(),
            subject: template.subject.clone(),
            scope: template.scope.clone(),
            issued_at: template.issued_at,
            expires_at: template.expires_at,
            delegation_chain: template.delegation_chain.clone(),
            aggregate_invocation_budget: template.aggregate_invocation_budget.clone(),
        },
        CapabilitySecurityBinding {
            schema: CAPABILITY_SECURITY_BINDING_SCHEMA.to_string(),
            tenant_id: request.tenant_id.to_string(),
            lineage_id: request.lineage_id.to_string(),
            session_id: request.security_session_id.clone(),
            principal_id: request.principal_id.clone(),
            isolation_epoch_id: request.isolation_epoch_id.clone(),
            context_generation: request.context_generation,
            workload_id: request.workload_id.clone(),
            server_id: request.server_id.clone(),
            workload_signer_public_key: request.workload_signer_public_key.to_hex(),
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
    capability_response_at(request, capability, signer, unix_timestamp_now())
}

fn capability_response_at(
    request: &IssueCapabilityRequest,
    capability: CapabilityToken,
    signer: &Keypair,
    issued_at: u64,
) -> String {
    let signed =
        SignedIssueCapabilityResponse::sign(request, capability, signer, 7, 1_000, issued_at)
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
        let capability = bind_capability_template_to_request(&capability, &issue_request, &current);
        ScriptedResponse {
            status: 200,
            body: capability_response(&issue_request, capability, &current),
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
    assert!(authority
        .trusted_public_keys()
        .contains(&historical.public_key()));
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
        .contains("neither the current pin nor a configured successor"));

    let transport_error =
        require_authenticated_authority_transport("http://127.0.0.1:1", false).test_unwrap_err();
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

    let issued = issue_with_context(
        authority.as_ref(),
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
            "\"schema\":\"chio.capability-issuance-request.v2\"",
            "\"requestNonce\":",
            "\"requestedAt\":",
            "\"tenantId\":\"tenant-remote-authority\"",
            "\"lineageId\":\"lineage-remote-authority\"",
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
        let capability_signer = if expected_error == "signature" {
            attacker.clone()
        } else {
            envelope_signer.clone()
        };
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
            let capability = if expected_error == "signature" {
                let attacker_template = signed_capability(
                    &capability_signer,
                    capability.subject.clone(),
                    capability.scope.clone(),
                    capability.issued_at,
                    capability.expires_at,
                );
                let mut bound = bind_capability_template_to_request(
                    &attacker_template,
                    &issue_request,
                    &capability_signer,
                );
                bound.issuer = envelope_signer.public_key();
                bound
            } else {
                bind_capability_template_to_request(&capability, &issue_request, &capability_signer)
            };
            ScriptedResponse {
                status: 200,
                body: capability_response(&issue_request, capability, &envelope_signer),
                content_type: "application/json",
            }
        });
        let authority = build_remote_capability_authority_for_test(
            &server.url,
            "secret",
            pinned_authority(&current, vec![attacker.public_key()]),
        )
        .test_unwrap();

        let error = issue_with_context(
            authority.as_ref(),
            &subject.public_key(),
            requested_scope.clone(),
            60,
            None,
        )
        .test_unwrap_err();
        let error_text = error.to_string();
        assert!(
            error_text.contains(expected_error)
                || (expected_error == "current pinned signer"
                    && error_text.contains("response signer is not pinned")),
            "expected {expected_error:?} rejection, got {error}"
        );
        assert_eq!(authority.authority_public_key(), current.public_key());
        let trusted = authority.trusted_public_keys();
        assert_eq!(trusted.len(), 2);
        assert!(trusted.contains(&current.public_key()));
        assert!(trusted.contains(&attacker.public_key()));
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

    let error = issue_with_context(
        authority.as_ref(),
        &subject.public_key(),
        test_scope("overflow"),
        u64::MAX,
        None,
    )
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
    let workload_signer = Keypair::generate();
    let session_admission_signer = Keypair::generate();
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
    let response_workload_signer = workload_signer.clone();
    let response_session_admission_signer = session_admission_signer.clone();
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
        let subject = PublicKey::from_hex(&issue_request.subject_public_key).test_unwrap();
        let different_request = IssueCapabilityRequest::new(
            issue_request.request_nonce.clone(),
            issue_request.requested_at,
            issue_request.tenant_id.clone(),
            issue_request.lineage_id.clone(),
            issue_request.security_session_id.clone(),
            issue_request.principal_id.clone(),
            issue_request.isolation_epoch_id.clone(),
            issue_request.context_generation,
            issue_request.workload_id.clone(),
            issue_request.server_id.clone(),
            issue_request.expected_authority_public_key.clone(),
            issue_request.expected_authority_generation,
            &subject,
            issue_request.scope.clone(),
            issue_request.ttl_seconds,
            None,
            &response_workload_signer,
            &response_session_admission_signer,
        )
        .test_unwrap();
        let capability =
            bind_capability_template_to_request(&capability, &different_request, &response_signer);
        ScriptedResponse {
            status: 200,
            body: capability_response_at(&different_request, capability, &response_signer, now),
            content_type: "application/json",
        }
    });
    let authority = build_remote_capability_authority_with_runtime_for_test(
        &server.url,
        "secret",
        pinned_authority(&current, Vec::new()),
        workload_signer,
        session_admission_signer,
        Arc::new(BoundedMemoryRemoteCapabilityRequestStore::for_test()),
        Arc::new(FixedRemoteCapabilityClock::new(now)),
    )
    .test_unwrap();

    let error = issue_with_context(
        authority.as_ref(),
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

    let issued = issue_with_context(authority.as_ref(), &subject.public_key(), scope, 60, None)
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
        let capability =
            bind_capability_template_to_request(&capability, &issue_request, &response_signer);
        ScriptedResponse {
            status: 200,
            body: capability_response(&issue_request, capability, &response_signer),
            content_type: "application/json",
        }
    });
    let authority = build_remote_capability_authority_for_test(
        &format!("{},{}", first.url, second.url),
        "secret",
        pinned_authority(&current, Vec::new()),
    )
    .test_unwrap();

    let issued = issue_with_context(authority.as_ref(), &subject.public_key(), scope, 60, None)
        .test_unwrap();

    assert_eq!(issued.id, "remote-issued-capability");
    assert_eq!(first.requests().len(), 2);
    assert_eq!(second.requests().len(), 1);
}

#[test]
fn remote_capability_authority_reuses_exact_request_after_ambiguous_failure() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let current = Keypair::generate();
    let subject = Keypair::generate();
    let scope = test_scope("ambiguous-retry");
    let status_current = current.clone();
    let response_signer = current.clone();
    let post_count = Arc::new(AtomicUsize::new(0));
    let handler_post_count = Arc::clone(&post_count);
    let server = ScriptedResponseServer::spawn_dynamic(3, move |request| {
        if request.method == "GET" {
            return ScriptedResponse {
                status: 200,
                body: authority_status(&status_current, Vec::new()),
                content_type: "application/json",
            };
        }
        let attempt = handler_post_count.fetch_add(1, Ordering::SeqCst);
        if attempt == 0 {
            return ScriptedResponse {
                status: 503,
                body: "ambiguous transport failure".to_string(),
                content_type: "text/plain",
            };
        }
        let issue_request: IssueCapabilityRequest =
            serde_json::from_str(&request.body).test_unwrap();
        let now = unix_timestamp_now();
        let capability = security_bound_capability_for_request(
            &response_signer,
            &issue_request,
            now,
            now.saturating_add(60),
        );
        ScriptedResponse {
            status: 200,
            body: capability_response(&issue_request, capability, &response_signer),
            content_type: "application/json",
        }
    });
    let authority = build_remote_capability_authority_for_test(
        &server.url,
        "secret",
        pinned_authority(&current, Vec::new()),
    )
    .test_unwrap();

    issue_with_context(
        authority.as_ref(),
        &subject.public_key(),
        scope.clone(),
        60,
        None,
    )
    .test_unwrap_err();
    let issued = issue_with_context(authority.as_ref(), &subject.public_key(), scope, 60, None)
        .test_unwrap();
    assert_eq!(issued.id, "remote-issued-capability");
    assert_eq!(post_count.load(Ordering::SeqCst), 2);

    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[1].body, requests[2].body);
    let first: IssueCapabilityRequest = serde_json::from_str(&requests[1].body).test_unwrap();
    let second: IssueCapabilityRequest = serde_json::from_str(&requests[2].body).test_unwrap();
    assert_eq!(first.request_nonce, second.request_nonce);
}

#[test]
fn remote_capability_authority_reuses_stale_exact_request_after_freshness_window() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let base_time = unix_timestamp_now();
    let current = Keypair::generate();
    let subject = Keypair::generate();
    let scope = test_scope("delayed-ambiguous-retry");
    let status_current = current.clone();
    let response_signer = current.clone();
    let post_count = Arc::new(AtomicUsize::new(0));
    let handler_post_count = Arc::clone(&post_count);
    let finalized_response = Arc::new(std::sync::Mutex::new(None::<String>));
    let handler_finalized_response = Arc::clone(&finalized_response);
    let server = ScriptedResponseServer::spawn_dynamic(3, move |request| {
        if request.method == "GET" {
            return ScriptedResponse {
                status: 200,
                body: authority_status(&status_current, Vec::new()),
                content_type: "application/json",
            };
        }
        let attempt = handler_post_count.fetch_add(1, Ordering::SeqCst);
        if attempt == 0 {
            let issue_request: IssueCapabilityRequest =
                serde_json::from_str(&request.body).test_unwrap();
            let capability = security_bound_capability_for_request(
                &response_signer,
                &issue_request,
                base_time,
                base_time.saturating_add(300),
            );
            let response =
                capability_response_at(&issue_request, capability, &response_signer, base_time);
            *handler_finalized_response.lock().test_unwrap() = Some(response);
            return ScriptedResponse {
                status: 503,
                body: "response lost after durable finalization".to_string(),
                content_type: "text/plain",
            };
        }
        ScriptedResponse {
            status: 200,
            body: handler_finalized_response
                .lock()
                .test_unwrap()
                .clone()
                .test_expect("finalized response"),
            content_type: "application/json",
        }
    });
    let workload_signer = Keypair::generate();
    let session_signer = Keypair::generate();
    let pending_requests: Arc<dyn RemoteCapabilityRequestStore> =
        Arc::new(BoundedMemoryRemoteCapabilityRequestStore::for_test());
    let clock = Arc::new(FixedRemoteCapabilityClock::new(base_time));
    let authority = build_remote_capability_authority_with_runtime_for_test(
        &server.url,
        "secret",
        pinned_authority(&current, Vec::new()),
        workload_signer,
        session_signer,
        pending_requests,
        Arc::clone(&clock) as Arc<dyn RemoteCapabilityIssuanceClock>,
    )
    .test_unwrap();

    issue_with_context(
        authority.as_ref(),
        &subject.public_key(),
        scope.clone(),
        300,
        None,
    )
    .test_unwrap_err();
    clock.set(base_time.saturating_add(61));
    let issued = issue_with_context(authority.as_ref(), &subject.public_key(), scope, 300, None)
        .test_unwrap();
    assert_eq!(issued.id, "remote-issued-capability");
    assert_eq!(post_count.load(Ordering::SeqCst), 2);

    let requests = server.requests();
    assert_eq!(requests[1].body, requests[2].body);
    let recovered: IssueCapabilityRequest = serde_json::from_str(&requests[2].body).test_unwrap();
    assert_eq!(recovered.requested_at, base_time);
}

#[test]
fn remote_capability_authority_recovers_exact_request_after_process_reconstruction() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    let base_time = unix_timestamp_now();
    let current = Keypair::generate();
    let subject = Keypair::generate();
    let scope = test_scope("restart-ambiguous-retry");
    let status_current = current.clone();
    let response_signer = current.clone();
    let post_count = Arc::new(AtomicUsize::new(0));
    let handler_post_count = Arc::clone(&post_count);
    let finalized_response = Arc::new(std::sync::Mutex::new(None::<String>));
    let handler_finalized_response = Arc::clone(&finalized_response);
    let server = ScriptedResponseServer::spawn_dynamic(4, move |request| {
        if request.method == "GET" {
            return ScriptedResponse {
                status: 200,
                body: authority_status(&status_current, Vec::new()),
                content_type: "application/json",
            };
        }
        let attempt = handler_post_count.fetch_add(1, Ordering::SeqCst);
        if attempt == 0 {
            let issue_request: IssueCapabilityRequest =
                serde_json::from_str(&request.body).test_unwrap();
            let capability = security_bound_capability_for_request(
                &response_signer,
                &issue_request,
                base_time,
                base_time.saturating_add(300),
            );
            let response =
                capability_response_at(&issue_request, capability, &response_signer, base_time);
            *handler_finalized_response.lock().test_unwrap() = Some(response);
            return ScriptedResponse {
                status: 503,
                body: "response lost before process restart".to_string(),
                content_type: "text/plain",
            };
        }
        ScriptedResponse {
            status: 200,
            body: handler_finalized_response
                .lock()
                .test_unwrap()
                .clone()
                .test_expect("finalized response"),
            content_type: "application/json",
        }
    });
    let directory = tempfile::tempdir().test_unwrap();
    let database_path = directory.path().join("verifier.sqlite3");
    drop(rusqlite::Connection::open(&database_path).test_unwrap());
    let workload_signer = Keypair::generate();
    let session_signer = Keypair::generate();
    let clock = Arc::new(FixedRemoteCapabilityClock::new(base_time));
    let first_store: Arc<dyn RemoteCapabilityRequestStore> =
        Arc::new(SqliteRemoteCapabilityRequestStore::open(&database_path).test_unwrap());
    let first = build_remote_capability_authority_with_runtime_for_test(
        &server.url,
        "secret",
        pinned_authority(&current, Vec::new()),
        workload_signer.clone(),
        session_signer.clone(),
        first_store,
        Arc::clone(&clock) as Arc<dyn RemoteCapabilityIssuanceClock>,
    )
    .test_unwrap();
    issue_with_context(
        first.as_ref(),
        &subject.public_key(),
        scope.clone(),
        300,
        None,
    )
    .test_unwrap_err();
    drop(first);

    clock.set(base_time.saturating_add(61));
    let reopened_store: Arc<dyn RemoteCapabilityRequestStore> =
        Arc::new(SqliteRemoteCapabilityRequestStore::open(&database_path).test_unwrap());
    let restarted = build_remote_capability_authority_with_runtime_for_test(
        &server.url,
        "secret",
        pinned_authority(&current, Vec::new()),
        workload_signer,
        session_signer,
        reopened_store,
        Arc::clone(&clock) as Arc<dyn RemoteCapabilityIssuanceClock>,
    )
    .test_unwrap();
    let issued = issue_with_context(restarted.as_ref(), &subject.public_key(), scope, 300, None)
        .test_unwrap();
    assert_eq!(issued.id, "remote-issued-capability");
    assert_eq!(post_count.load(Ordering::SeqCst), 2);

    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(requests[1].body, requests[3].body);
    let before: IssueCapabilityRequest = serde_json::from_str(&requests[1].body).test_unwrap();
    let after: IssueCapabilityRequest = serde_json::from_str(&requests[3].body).test_unwrap();
    assert_eq!(before.request_nonce, after.request_nonce);
}

#[test]
fn remote_capability_authority_rejects_stored_request_for_different_pending_identity() {
    let base_time = unix_timestamp_now();
    let current = Keypair::generate();
    let subject = Keypair::generate();
    let workload_signer = Keypair::generate();
    let session_signer = Keypair::generate();
    let server = ScriptedResponseServer::spawn(vec![ScriptedResponse {
        status: 200,
        body: authority_status(&current, Vec::new()),
        content_type: "application/json",
    }]);
    let mismatched_request = IssueCapabilityRequest::new(
        "ab".repeat(32),
        base_time,
        chio_security_types::ports::TenantId::new("tenant-remote-authority").test_unwrap(),
        chio_security_types::ports::LineageId::new("lineage-remote-authority").test_unwrap(),
        "session-remote-authority".to_string(),
        "principal-remote-authority".to_string(),
        "isolation-remote-authority".to_string(),
        1,
        "workload-remote-authority".to_string(),
        "remote-authority-tests".to_string(),
        current.public_key(),
        7,
        &subject.public_key(),
        test_scope("stored-different-scope"),
        300,
        None,
        &workload_signer,
        &session_signer,
    )
    .test_unwrap();
    let stored = StoredRemoteCapabilityRequest {
        canonical_request: chio_core::canonical::canonical_json_bytes(&mismatched_request)
            .test_unwrap(),
        recovery_expires_at: request_recovery_expiry(&mismatched_request).test_unwrap(),
        request: mismatched_request,
    };
    let pending_requests: Arc<dyn RemoteCapabilityRequestStore> =
        Arc::new(FixedStoredRemoteCapabilityRequestStore { stored });
    let clock = Arc::new(FixedRemoteCapabilityClock::new(base_time));
    let authority = build_remote_capability_authority_with_runtime_for_test(
        &server.url,
        "secret",
        pinned_authority(&current, Vec::new()),
        workload_signer,
        session_signer,
        pending_requests,
        Arc::clone(&clock) as Arc<dyn RemoteCapabilityIssuanceClock>,
    )
    .test_unwrap();

    let error = issue_with_context(
        authority.as_ref(),
        &subject.public_key(),
        test_scope("requested-scope"),
        300,
        None,
    )
    .test_unwrap_err();
    assert!(error.to_string().contains("wrong canonical identity"));
    assert_eq!(
        server.requests().len(),
        1,
        "stored identity mismatch must fail before an issuance POST"
    );
}
