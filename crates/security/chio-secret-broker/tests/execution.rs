#![allow(clippy::unwrap_used, clippy::expect_used)]

use chio_core_types::Keypair;
use chio_secret_broker::capability::{issue_capability, verify_capability};
use chio_secret_broker::proof::{body_digest, issue_request_proof, verify_request_proof};
use chio_secret_broker::protocol::{
    decode_execute_request, AttemptConsumption, BrokerCapabilityBody, BrokerDestination,
    BrokerExecuteRequest, BrokerRequest, CallerOptions, CredentialRef, HeaderField, ProofBinding,
    ProofMode, RedirectPolicy, RequestConstraints, BROKER_CAPABILITY_SCHEMA, BROKER_EXECUTE_SCHEMA,
    MAX_WIRE_BYTES,
};

fn fixture() -> (Keypair, Keypair, BrokerExecuteRequest) {
    let issuer = Keypair::from_seed(&[1; 32]);
    let caller = Keypair::from_seed(&[2; 32]);
    let destination =
        BrokerDestination::parse("https://example.com/v1?x=1", "post", false).expect("destination");
    let request = BrokerRequest {
        destination: destination.clone(),
        headers: vec![HeaderField::normalized("content-type", b"application/json").expect("header")],
        body: b"payload".to_vec(),
        approved_preview_sha256: None,
        options: CallerOptions {
            timeout_ms: 500,
            streaming: false,
            response_limit_bytes: 1024,
        },
    };
    let capability = issue_capability(
        BrokerCapabilityBody {
            schema: BROKER_CAPABILITY_SCHEMA.to_string(),
            issuer: issuer.public_key(),
            capability_id: "broker-capability".to_string(),
            parent_capability_id: "parent-capability".to_string(),
            subject: caller.public_key(),
            audience: "broker-service".to_string(),
            issued_at_unix_seconds: 10,
            not_before_unix_seconds: 10,
            expires_at_unix_seconds: 100,
            credential: CredentialRef {
                provider: "generic-https".to_string(),
                credential_id: "credential-a".to_string(),
                version: 1,
            },
            provider_adapter_id: "generic-bearer".to_string(),
            provider_adapter_version: 1,
            destination,
            constraints: RequestConstraints {
                allowed_caller_headers: vec!["content-type".to_string()],
                provider_owned_headers: vec!["authorization".to_string()],
                maximum_body_bytes: 1024,
                required_body_sha256: body_digest(&request.body),
                required_preview_sha256: None,
                redirect_policy: RedirectPolicy::Disabled,
                maximum_response_bytes: 1024,
                streaming_allowed: false,
                maximum_timeout_ms: 500,
            },
            broker_quota_key_id: "broker-quota".to_string(),
            maximum_executions: 2,
            consumption: AttemptConsumption::CaptureBeforeDispatch,
            revocation_id: "broker-revocation".to_string(),
            proof: ProofBinding {
                mode: ProofMode::PublicKey,
                caller_public_key: caller.public_key(),
                nonce_ttl_seconds: 30,
            },
        },
        &issuer,
        true,
    )
    .expect("capability");
    let proof = issue_request_proof(
        &capability,
        &request,
        "nonce-abcdefghijkl".to_string(),
        20,
        &caller,
    )
    .expect("proof");
    (
        issuer,
        caller,
        BrokerExecuteRequest {
            schema: BROKER_EXECUTE_SCHEMA.to_string(),
            invocation_id: "invocation-a".to_string(),
            capability,
            proof,
            request,
        },
    )
}

#[test]
fn canonical_wire_round_trip_and_unknown_field_rejection() {
    let (_, _, request) = fixture();
    let bytes = serde_json::to_vec(&request).expect("encode");
    assert_eq!(decode_execute_request(&bytes).expect("decode"), request);
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("value");
    value["unknown"] = serde_json::json!(true);
    assert!(decode_execute_request(&serde_json::to_vec(&value).expect("encode")).is_err());
}

#[test]
fn capability_and_proof_reject_single_field_tampering() {
    let (issuer, _, request) = fixture();
    verify_capability(
        &request.capability,
        &issuer.public_key(),
        "broker-service",
        20,
        true,
    )
    .expect("capability");
    verify_request_proof(&request.proof, &request.capability, &request.request, 20, 1)
        .expect("proof");

    let mut changed = request.clone();
    changed.request.options.timeout_ms = 499;
    assert!(
        verify_request_proof(&changed.proof, &changed.capability, &changed.request, 20, 1).is_err()
    );

    let mut changed = request;
    changed.capability.body.credential.version = 2;
    assert!(verify_capability(
        &changed.capability,
        &issuer.public_key(),
        "broker-service",
        20,
        true
    )
    .is_err());
}

#[test]
fn destination_normalization_pins_default_port_case_and_exact_query() {
    let normalized =
        BrokerDestination::parse("https://EXAMPLE.COM:443/v1/items?b=2&a=1", "post", false)
            .expect("destination");
    assert_eq!(normalized.normalized_host, "example.com");
    assert_eq!(normalized.explicit_port, 443);
    assert_eq!(normalized.method, "POST");
    assert_eq!(normalized.exact_path_and_query, "/v1/items?b=2&a=1");
}

#[test]
fn capability_signature_rejects_each_bound_field_tamper() {
    let (issuer, _, request) = fixture();
    let original = serde_json::to_value(&request.capability).expect("value");
    let mutations = [
        (
            "/body/schema",
            serde_json::json!("chio.broker-capability.v2"),
        ),
        (
            "/body/issuer",
            serde_json::json!(Keypair::from_seed(&[9; 32]).public_key()),
        ),
        (
            "/body/capabilityId",
            serde_json::json!("broker-capability-mutated"),
        ),
        (
            "/body/parentCapabilityId",
            serde_json::json!("parent-mutated"),
        ),
        (
            "/body/subject",
            serde_json::json!(Keypair::from_seed(&[8; 32]).public_key()),
        ),
        ("/body/audience", serde_json::json!("other-audience")),
        ("/body/issuedAtUnixSeconds", serde_json::json!(9)),
        ("/body/notBeforeUnixSeconds", serde_json::json!(11)),
        ("/body/expiresAtUnixSeconds", serde_json::json!(101)),
        (
            "/body/credential/provider",
            serde_json::json!("other-provider"),
        ),
        (
            "/body/credential/credentialId",
            serde_json::json!("credential-b"),
        ),
        ("/body/credential/version", serde_json::json!(2)),
        (
            "/body/providerAdapterId",
            serde_json::json!("other-adapter"),
        ),
        ("/body/providerAdapterVersion", serde_json::json!(2)),
        (
            "/body/destination/normalizedHost",
            serde_json::json!("other.example"),
        ),
        ("/body/destination/explicitPort", serde_json::json!(8443)),
        (
            "/body/destination/exactPathAndQuery",
            serde_json::json!("/other"),
        ),
        ("/body/destination/method", serde_json::json!("PUT")),
        (
            "/body/constraints/maximumBodyBytes",
            serde_json::json!(1000),
        ),
        (
            "/body/constraints/requiredBodySha256",
            serde_json::json!("f".repeat(64)),
        ),
        (
            "/body/constraints/requiredPreviewSha256",
            serde_json::json!("e".repeat(64)),
        ),
        (
            "/body/constraints/maximumResponseBytes",
            serde_json::json!(1000),
        ),
        (
            "/body/constraints/streamingAllowed",
            serde_json::json!(true),
        ),
        ("/body/constraints/maximumTimeoutMs", serde_json::json!(499)),
        ("/body/brokerQuotaKeyId", serde_json::json!("other-quota")),
        ("/body/maximumExecutions", serde_json::json!(3)),
        ("/body/revocationId", serde_json::json!("other-revocation")),
        (
            "/body/proof/callerPublicKey",
            serde_json::json!(Keypair::from_seed(&[7; 32]).public_key()),
        ),
        ("/body/proof/nonceTtlSeconds", serde_json::json!(29)),
    ];
    for (pointer, replacement) in mutations {
        let mut value = original.clone();
        *value.pointer_mut(pointer).expect("pointer") = replacement;
        let mutated = serde_json::from_value(value).expect("mutated capability");
        assert!(
            verify_capability(&mutated, &issuer.public_key(), "broker-service", 20, true).is_err(),
            "tamper survived at {pointer}"
        );
    }
}

#[test]
fn proof_rejects_body_path_header_option_key_stale_and_future_changes() {
    let (_, _, request) = fixture();
    let proof = &request.proof;

    let mut changed = request.request.clone();
    changed.body.push(0);
    assert!(verify_request_proof(proof, &request.capability, &changed, 20, 1).is_err());

    let mut changed = request.request.clone();
    changed.destination.exact_path_and_query = "/v1?x=2".to_string();
    assert!(verify_request_proof(proof, &request.capability, &changed, 20, 1).is_err());

    let mut changed = request.request.clone();
    changed.headers[0].value = b"text/plain".to_vec();
    assert!(verify_request_proof(proof, &request.capability, &changed, 20, 1).is_err());

    let mut changed = request.request.clone();
    changed.headers.clear();
    assert!(verify_request_proof(proof, &request.capability, &changed, 20, 1).is_err());

    let mut changed = request.request.clone();
    changed
        .headers
        .push(HeaderField::normalized("x-caller", b"added").expect("additional normalized header"));
    changed
        .headers
        .sort_by(|left, right| left.name.cmp(&right.name));
    assert!(verify_request_proof(proof, &request.capability, &changed, 20, 1).is_err());

    let mut changed = request.request.clone();
    changed.options.streaming = true;
    assert!(verify_request_proof(proof, &request.capability, &changed, 20, 1).is_err());

    let mut changed = request.request.clone();
    changed.options.timeout_ms = 499;
    assert!(verify_request_proof(proof, &request.capability, &changed, 20, 1).is_err());

    let mut wrong_key = request.proof.clone();
    wrong_key.body.authority_key = Keypair::from_seed(&[9; 32]).public_key();
    assert!(
        verify_request_proof(&wrong_key, &request.capability, &request.request, 20, 1).is_err()
    );

    assert!(verify_request_proof(proof, &request.capability, &request.request, 51, 1).is_err());
    assert!(verify_request_proof(proof, &request.capability, &request.request, 10, 1).is_err());
}

#[test]
fn duplicate_reordered_and_unknown_option_inputs_fail_closed() {
    let (_, _, request) = fixture();
    let mut duplicate = request.request.clone();
    duplicate.headers.push(duplicate.headers[0].clone());
    assert!(duplicate.validate_bounds().is_err());

    let mut reordered = request.request.clone();
    reordered
        .headers
        .push(HeaderField::normalized("accept", b"application/json").expect("additional header"));
    assert!(reordered.validate_bounds().is_err());

    let mut value = serde_json::to_value(&request).expect("value");
    value["request"]["options"]["unknownTransportBehavior"] = serde_json::json!(true);
    assert!(decode_execute_request(&serde_json::to_vec(&value).expect("wire")).is_err());
    assert!(decode_execute_request(&vec![b' '; MAX_WIRE_BYTES + 1]).is_err());
}
