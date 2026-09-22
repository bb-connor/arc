use super::*;
use crate::capability::issue_capability;
use crate::proof::{body_digest, issue_request_proof};
use crate::protocol::*;
use chio_core_types::{Ed25519Backend, Keypair};
use chio_kernel::supplemental_quota::BROKER_CAPABILITY_EXECUTION_PROFILE;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[cfg(unix)]
mod kernel;

struct Clock(u64);
impl DaemonClock for Clock {
    fn now_unix_seconds(&self) -> Result<u64> {
        Ok(self.0)
    }
}

fn fixture() -> TestResult<(
    BrokerQuotaVerifier,
    BrokerExecuteRequest,
    SupplementalQuotaVerificationContext,
)> {
    let issuer = Keypair::from_seed(&[31; 32]);
    let caller = Keypair::from_seed(&[32; 32]);
    let config = BrokerQuotaVerifierConfig {
        issuer: issuer.public_key(),
        audience: "broker".into(),
        server_id: "broker-tools".into(),
        tool_name: "execute".into(),
        provider_adapter_id: "bearer".into(),
        provider_adapter_version: 1,
        credential_placement: ProviderPlacementConfig::BearerAuthorization,
    };
    let verifier = BrokerQuotaVerifier::new(config, Arc::new(Clock(100)))?;
    let request = BrokerRequest {
        destination: BrokerDestination::parse("https://example.com/v1", "POST", false)?,
        headers: vec![HeaderField::normalized(
            "content-type",
            b"application/json",
        )?],
        body: b"{}".to_vec(),
        approved_preview_sha256: None,
        options: CallerOptions {
            timeout_ms: 1000,
            streaming: false,
            response_limit_bytes: 256,
        },
    };
    let capability = issue_capability(
        BrokerCapabilityBody {
            schema: BROKER_CAPABILITY_SCHEMA.into(),
            issuer: issuer.public_key(),
            capability_id: "broker-cap".into(),
            parent_capability_id: "parent-cap".into(),
            subject: caller.public_key(),
            audience: "broker".into(),
            issued_at_unix_seconds: 90,
            not_before_unix_seconds: 90,
            expires_at_unix_seconds: 200,
            credential: CredentialRef {
                provider: "generic-https".into(),
                credential_id: "credential".into(),
                version: 1,
            },
            provider_adapter_id: "bearer".into(),
            provider_adapter_version: 1,
            destination: request.destination.clone(),
            constraints: RequestConstraints {
                allowed_caller_headers: vec!["content-type".into()],
                provider_owned_headers: vec!["authorization".into()],
                maximum_body_bytes: 128,
                required_body_sha256: body_digest(&request.body),
                required_preview_sha256: None,
                redirect_policy: RedirectPolicy::Disabled,
                maximum_response_bytes: 256,
                streaming_allowed: false,
                maximum_timeout_ms: 1000,
            },
            broker_quota_key_id: "broker-quota".into(),
            maximum_executions: 1,
            consumption: AttemptConsumption::CaptureBeforeDispatch,
            revocation_id: "broker-revocation".into(),
            proof: ProofBinding {
                mode: ProofMode::PublicKey,
                caller_public_key: caller.public_key(),
                nonce_ttl_seconds: 30,
            },
        },
        &Ed25519Backend::new(issuer),
        true,
    )?;
    let proof = issue_request_proof(&capability, &request, "1".repeat(32), 100, &caller)?;
    let execute = BrokerExecuteRequest {
        schema: BROKER_EXECUTE_SCHEMA.into(),
        invocation_id: "request-1".into(),
        capability,
        proof,
        request,
    };
    let mut features = chio_core_types::capability::features::CapabilityNegotiation::default();
    features
        .features
        .insert(BROKER_CAPABILITY_EXECUTION_PROFILE.into(), true);
    let context = SupplementalQuotaVerificationContext {
        capability_id: "parent-cap".into(),
        capability_digest: "a".repeat(64),
        request_namespace_digest: "b".repeat(64),
        operation_id: "c".repeat(64),
        subject: caller.public_key(),
        request_id: "request-1".into(),
        normalized_destination: r#"{"server_id":"broker-tools","tool_name":"execute"}"#.into(),
        arguments_hash: hex::encode(Sha256::digest(canonical_json_bytes(&execute)?)),
        negotiated_profile: BROKER_CAPABILITY_EXECUTION_PROFILE.into(),
        negotiated_features: features,
        verifier_binding: verifier.binding().clone(),
    };
    Ok((verifier, execute, context))
}

#[test]
fn signed_broker_request_produces_original_operation_bound_quota() -> TestResult {
    let (verifier, execute, context) = fixture()?;
    let claim = verifier.verify(&canonical_json_bytes(&execute)?, &context)?;
    assert_eq!(claim.operation_id, context.operation_id);
    assert_eq!(claim.capability_digest, context.capability_digest);
    assert_eq!(
        claim.request_namespace_digest,
        context.request_namespace_digest
    );
    assert_eq!(
        claim.broker_capability_id,
        execute.capability.body.capability_id
    );
    assert_eq!(claim.max_invocations, 1);
    assert_eq!(claim.expires_at, 130);
    assert_eq!(
        claim.supplemental_revocation_ids,
        ["broker-cap", "broker-revocation"]
    );
    Ok(())
}

#[test]
fn signed_broker_request_cannot_move_between_kernel_requests() -> TestResult {
    let (verifier, execute, context) = fixture()?;
    let bytes = canonical_json_bytes(&execute)?;
    let mut mutations = Vec::new();
    let mut changed = context.clone();
    changed.capability_id = "other-parent".into();
    mutations.push(changed);
    let mut changed = context.clone();
    changed.subject = Keypair::generate().public_key();
    mutations.push(changed);
    let mut changed = context.clone();
    changed.request_id = "other-request".into();
    mutations.push(changed);
    let mut changed = context.clone();
    changed.arguments_hash = "e".repeat(64);
    mutations.push(changed);
    let mut changed = context.clone();
    changed.normalized_destination = r#"{"server_id":"other","tool_name":"execute"}"#.into();
    mutations.push(changed);
    let mut changed = context.clone();
    changed.verifier_binding.configuration_digest = "e".repeat(64);
    mutations.push(changed);
    let mut changed = context.clone();
    changed.negotiated_profile = "other".into();
    mutations.push(changed);
    for changed in mutations {
        assert!(verifier.verify(&bytes, &changed).is_err());
    }
    Ok(())
}

#[test]
fn broker_admission_rejects_substitution_even_when_kernel_hash_is_updated() -> TestResult {
    let (verifier, execute, context) = fixture()?;
    let mut mutations = Vec::new();
    let mut changed = execute.clone();
    changed.capability.body.maximum_executions = 100;
    mutations.push(changed);
    let mut changed = execute.clone();
    changed.request.destination.exact_path_and_query = "/other".into();
    mutations.push(changed);
    let mut changed = execute.clone();
    changed.request.headers[0].value = b"text/plain".to_vec();
    mutations.push(changed);
    let mut changed = execute.clone();
    changed.request.body = b"changed".to_vec();
    mutations.push(changed);
    let mut changed = execute.clone();
    changed.request.options.timeout_ms = 999;
    mutations.push(changed);
    let mut changed = execute.clone();
    changed.proof.body.nonce = "4".repeat(32);
    mutations.push(changed);
    for changed in mutations {
        let bytes = canonical_json_bytes(&changed)?;
        let mut moved = context.clone();
        moved.arguments_hash = hex::encode(Sha256::digest(&bytes));
        assert!(verifier.verify(&bytes, &moved).is_err());
    }
    // A valid caller signature cannot broaden the issuer's constraints.
    let mut changed = execute;
    changed.request.options.timeout_ms = 1001;
    changed.proof = issue_request_proof(
        &changed.capability,
        &changed.request,
        "2".repeat(32),
        100,
        &Keypair::from_seed(&[32; 32]),
    )?;
    let bytes = canonical_json_bytes(&changed)?;
    let mut moved = context;
    moved.arguments_hash = hex::encode(Sha256::digest(&bytes));
    assert!(verifier.verify(&bytes, &moved).is_err());
    Ok(())
}

#[test]
fn broker_admission_uses_installed_trust_and_live_clock() -> TestResult {
    let (verifier, execute, context) = fixture()?;
    let bytes = canonical_json_bytes(&execute)?;
    for time in [89, 99, 130, 200] {
        let changed = BrokerQuotaVerifier::new(verifier.config.clone(), Arc::new(Clock(time)))?;
        assert!(
            changed.verify(&bytes, &context).is_err(),
            "accepted at {time}"
        );
    }
    let mut configs = Vec::new();
    let mut changed = verifier.config.clone();
    changed.issuer = Keypair::generate().public_key();
    configs.push(changed);
    let mut changed = verifier.config.clone();
    changed.audience = "other".into();
    configs.push(changed);
    let mut changed = verifier.config.clone();
    changed.provider_adapter_id = "other".into();
    configs.push(changed);
    let mut changed = verifier.config.clone();
    changed.provider_adapter_version = 2;
    configs.push(changed);
    let mut changed = verifier.config.clone();
    changed.credential_placement = ProviderPlacementConfig::ApiKeyHeader;
    configs.push(changed);
    for config in configs {
        let changed = BrokerQuotaVerifier::new(config, Arc::new(Clock(100)))?;
        let mut moved = context.clone();
        moved.verifier_binding = changed.binding().clone();
        assert!(changed.verify(&bytes, &moved).is_err());
    }
    struct FailedClock;
    impl DaemonClock for FailedClock {
        fn now_unix_seconds(&self) -> Result<u64> {
            Err(crate::BrokerError::AuthorityUnavailable(
                "test clock unavailable".into(),
            ))
        }
    }
    let failed = BrokerQuotaVerifier::new(verifier.config, Arc::new(FailedClock))?;
    assert!(failed.verify(&bytes, &context).is_err());
    Ok(())
}

#[test]
fn broker_admission_requires_bounded_exact_typed_canonical_json() -> TestResult {
    let (verifier, execute, mut context) = fixture()?;
    let mut unknown = serde_json::to_value(&execute)?;
    unknown["unreviewed_option"] = serde_json::json!(true);
    let bytes = canonical_json_bytes(&unknown)?;
    context.arguments_hash = hex::encode(Sha256::digest(&bytes));
    assert!(verifier.verify(&bytes, &context).is_err());
    let canonical = canonical_json_bytes(&execute)?;
    context.arguments_hash = hex::encode(Sha256::digest(&canonical));
    let repeated = format!(
        "{{\"schema\":\"{}\",{}",
        BROKER_EXECUTE_SCHEMA,
        std::str::from_utf8(&canonical)?.trim_start_matches('{')
    );
    assert!(verifier.verify(repeated.as_bytes(), &context).is_err());
    assert!(verifier
        .verify(&serde_json::to_vec_pretty(&execute)?, &context)
        .is_err());
    assert!(verifier.verify(&vec![b' '; 65_537], &context).is_err());
    Ok(())
}

#[test]
fn broker_quota_identity_stays_constant_across_separate_invocations() -> TestResult {
    let (verifier, mut execute, mut context) = fixture()?;
    let first = verifier.verify(&canonical_json_bytes(&execute)?, &context)?;
    execute.invocation_id = "request-2".into();
    execute.proof = issue_request_proof(
        &execute.capability,
        &execute.request,
        "3".repeat(32),
        100,
        &Keypair::from_seed(&[32; 32]),
    )?;
    context.request_id = execute.invocation_id.clone();
    context.operation_id = "d".repeat(64);
    let bytes = canonical_json_bytes(&execute)?;
    context.arguments_hash = hex::encode(Sha256::digest(&bytes));
    let second = verifier.verify(&bytes, &context)?;
    assert_eq!(
        first.request_constraint_digest,
        second.request_constraint_digest
    );
    assert_eq!(first.broker_capability_id, second.broker_capability_id);
    assert_ne!(first.request_binding_hash, second.request_binding_hash);
    Ok(())
}
