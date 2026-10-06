use super::*;
use crate::policy::{RuntimeAssuranceIssuancePolicy, RuntimeAssuranceTierPolicy, TierScopeCeiling};
use chio_core::capability::{
    runtime_attestation::{RuntimeAssuranceTier, RuntimeAttestationEvidence},
    scope::{ChioScope, Operation, ToolGrant},
    trust_policy::{AttestationTrustPolicy, AttestationTrustRule},
};
use chio_core::crypto::Keypair;
use tower::ServiceExt;

#[tokio::test]
async fn authenticated_issuance_route_rejects_unsigned_matching_attestation(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = chio_test_support::private_tempdir()?;
    let mut state = metrics_state("service-secret");
    state.config.authority_seed_path = Some(directory.path().join("authority.seed"));
    state.config.authority_workload_token = Some("workload-secret".to_owned());
    let now = chio_test_support::clock::unix_seconds();
    let evidence = RuntimeAttestationEvidence {
        schema: chio_appraisal::AZURE_MAA_ATTESTATION_SCHEMA.to_owned(),
        verifier: "https://maa.contoso.test".to_owned(),
        tier: RuntimeAssuranceTier::Verified,
        issued_at: now.saturating_sub(5),
        expires_at: now + 300,
        evidence_sha256: "a".repeat(64),
        runtime_identity: Some("spiffe://chio/runtime/caller".to_owned()),
        workload_identity: None,
        claims: Some(serde_json::json!({"azureMaa": {"attestationType": "sgx"}})),
    };
    let mut payload = IssueCapabilityRequest {
        subject_public_key: Keypair::generate().public_key().to_hex(),
        scope: ChioScope {
            grants: vec![ToolGrant {
                server_id: "payments".to_owned(),
                tool_name: "charge".to_owned(),
                operations: vec![Operation::Invoke],
                constraints: Vec::new(),
                max_invocations: Some(10),
                max_cost_per_invocation: None,
                max_total_cost: None,
                dpop_required: None,
            }],
            resource_grants: Vec::new(),
            prompt_grants: Vec::new(),
        },
        ttl_seconds: 120,
        runtime_attestation: None,
    };
    let request = |payload: &IssueCapabilityRequest| {
        axum::http::Request::builder()
            .method("POST")
            .uri(ISSUE_CAPABILITY_PATH)
            .header(AUTHORIZATION, "Bearer workload-secret")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_vec(payload).test_unwrap(),
            ))
            .test_unwrap()
    };
    // Prove that authentication, key custody and ordinary issuance work on this route.
    let response = super::super::build_router(state.clone())
        .oneshot(request(&payload))
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
    let issued: IssueCapabilityResponse = serde_json::from_slice(&body)?;
    assert_eq!(
        issued.capability.subject.to_hex(),
        payload.subject_public_key
    );

    state.config.runtime_assurance_policy = Some(RuntimeAssuranceIssuancePolicy {
        tiers: vec![RuntimeAssuranceTierPolicy {
            name: "verified".to_owned(),
            minimum_attestation_tier: RuntimeAssuranceTier::Verified,
            max_scope: TierScopeCeiling {
                operations: vec![Operation::Invoke],
                max_invocations: Some(20),
                max_cost_per_invocation: None,
                max_total_cost: None,
                max_delegation_depth: Some(0),
                ttl_seconds: 300,
                constraints_required: false,
            },
        }],
        attestation_trust_policy: Some(AttestationTrustPolicy {
            rules: vec![AttestationTrustRule {
                name: "azure-contoso".to_owned(),
                schema: evidence.schema.clone(),
                verifier: evidence.verifier.clone(),
                effective_tier: RuntimeAssuranceTier::Verified,
                verifier_family: Some(chio_appraisal::AttestationVerifierFamily::AzureMaa),
                max_evidence_age_seconds: Some(120),
                allowed_attestation_types: vec!["sgx".to_owned()],
                required_assertions: BTreeMap::new(),
            }],
        }),
    });
    payload.runtime_attestation = Some(evidence);
    let response = super::super::build_router(state)
        .oneshot(request(&payload))
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
    let message = std::str::from_utf8(&body)?;
    assert!(message.contains("authenticated"), "{message}");
    assert!(!message.contains("\"capability\""));
    Ok(())
}
