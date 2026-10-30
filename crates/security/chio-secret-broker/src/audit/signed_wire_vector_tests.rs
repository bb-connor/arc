use chio_test_support::prelude::*;

use std::path::{Path, PathBuf};

use chio_core_types::{canonical_json_bytes, Ed25519Backend, Keypair, SigningBackend};

use super::*;
use crate::authority_ipc::{
    sign_authority_request_body, sign_authority_response, signed_request_digest,
    verify_authority_exchange, AuthorityRequestBody, AUTHORITY_REQUEST_SCHEMA,
};

const BROKER_SEED: u8 = 85;
const AUTHORITY_SEED: u8 = 102;
const RUNNER_SEED: u8 = 161;
const COMPARISON_SEED: u8 = 162;
const REQUEST_ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const REQUEST_ISSUED_AT: u64 = 1_700_000_000;
const RESPONSE_ISSUED_AT: u64 = 1_700_000_001;
const CLOCK_SKEW_SECONDS: u64 = 30;

fn backend(seed: u8) -> Ed25519Backend {
    Ed25519Backend::new(Keypair::from_seed(&[seed; 32]))
}

fn vector_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/bindings/vectors/security/signed-wire")
}

fn line(value: &impl Serialize) -> Vec<u8> {
    let mut bytes = canonical_json_bytes(value).test_unwrap();
    bytes.push(b'\n');
    bytes
}

fn runner_body() -> BrokerAuditRunnerAuthorizationBody {
    BrokerAuditRunnerAuthorizationBody {
        schema: BROKER_AUDIT_RUNNER_AUTHORIZATION_SCHEMA.to_string(),
        audit_id: "audit-production-2026-07-16-001".to_string(),
        deployment_id: "production-us-east-1".to_string(),
        broker_instance_id: "broker-prod-01".to_string(),
        tenant_scope: "tenant-production".to_string(),
        runner_id: "security-migration-runner".to_string(),
        reference_source: "legacy-egress-capture-2026-07-16".to_string(),
        reference_commitment_sha256: "1".repeat(64),
        capability_sha256: "2".repeat(64),
        proof_sha256: "3".repeat(64),
        canonical_request_sha256: "4".repeat(64),
        provider_adapter_id: "generic-bearer".to_string(),
        provider_adapter_version: 1,
        credential_provider: "production-vault".to_string(),
        revocation_authority_domain: "revocation.production".to_string(),
        issued_at_unix_seconds: 1_784_160_000,
        expires_at_unix_seconds: 1_784_160_300,
    }
}

fn runner() -> SignedBrokerAuditRunnerAuthorization {
    SignedBrokerAuditRunnerAuthorization::sign(runner_body(), &backend(RUNNER_SEED)).test_unwrap()
}

fn comparison_body(runner: &SignedBrokerAuditRunnerAuthorization) -> BrokerAuditComparisonBody {
    let runner_sha256 = runner_authorization_digest(runner).test_unwrap();
    BrokerAuditComparisonBody {
        schema: BROKER_AUDIT_COMPARISON_SCHEMA.to_string(),
        issued_at_unix_seconds: 1_784_160_010,
        capability_sha256: runner.body.capability_sha256.clone(),
        proof_sha256: runner.body.proof_sha256.clone(),
        canonical_request_sha256: runner.body.canonical_request_sha256.clone(),
        authority_context_sha256: "5".repeat(64),
        audit_id_sha256: broker_audit_id_digest(&runner.body.audit_id).test_unwrap(),
        governed_audit_intent_sha256: broker_audit_governed_intent_digest(
            &runner.body,
            &runner_sha256,
        )
        .test_unwrap(),
        audit_authorization_sha256: "8".repeat(64),
        runner_authorization_sha256: runner_sha256,
        reference_source_sha256: broker_audit_reference_source_digest(
            &runner.body.reference_source,
        )
        .test_unwrap(),
        broker_outbound_projection_commitment_sha256: "b".repeat(64),
        reference_outbound_projection_commitment_sha256: "b".repeat(64),
        projections_equal: true,
        network_dispatch_count: 0,
        accounting_mutation_count: 0,
        raw_credential_returned: false,
    }
}

fn comparison(runner: &SignedBrokerAuditRunnerAuthorization) -> SignedBrokerAuditComparison {
    sign_broker_audit_comparison(comparison_body(runner), &backend(COMPARISON_SEED)).test_unwrap()
}

fn authority_request() -> crate::authority_ipc::SignedAuthorityRequest {
    let broker = backend(BROKER_SEED);
    sign_authority_request_body(
        AuthorityRequestBody {
            schema: AUTHORITY_REQUEST_SCHEMA.to_string(),
            request_id: REQUEST_ID.to_string(),
            issued_at_unix_seconds: REQUEST_ISSUED_AT,
            broker: broker.public_key().test_unwrap(),
            operation: AuthorityOperation::Capabilities,
        },
        &broker,
    )
    .test_unwrap()
}

fn authority_response(
    request: &crate::authority_ipc::SignedAuthorityRequest,
) -> crate::authority_ipc::SignedAuthorityResponse {
    sign_authority_response(
        REQUEST_ID,
        &signed_request_digest(request).test_unwrap(),
        AuthorityResult::Rejected {
            code: "vector_denied".to_string(),
        },
        RESPONSE_ISSUED_AT,
        &backend(AUTHORITY_SEED),
    )
    .test_unwrap()
}

fn generated_positives() -> Vec<(&'static str, Vec<u8>)> {
    let runner = runner();
    let comparison = comparison(&runner);
    let request = authority_request();
    let response = authority_response(&request);
    vec![
        (
            "positive/broker-audit-comparison-body-v1.json",
            line(&comparison.body),
        ),
        (
            "positive/broker-audit-comparison-envelope-v1.json",
            line(&comparison),
        ),
        (
            "positive/broker-audit-runner-authorization-body-v1.json",
            line(&runner.body),
        ),
        (
            "positive/broker-audit-runner-authorization-envelope-v1.json",
            line(&runner),
        ),
        (
            "positive/broker-authority-request-body-v1.json",
            line(&request.body),
        ),
        (
            "positive/broker-authority-request-envelope-v1.json",
            line(&request),
        ),
        (
            "positive/broker-authority-response-body-v1.json",
            line(&response.body),
        ),
        (
            "positive/broker-authority-response-envelope-v1.json",
            line(&response),
        ),
    ]
}

fn committed(relative: &str) -> Vec<u8> {
    std::fs::read(vector_root().join(relative)).test_unwrap()
}

fn canonical_of(relative: &str) -> Vec<u8> {
    committed(relative)
        .strip_suffix(b"\n")
        .test_expect("committed fixture ends with a newline")
        .to_vec()
}

#[test]
fn committed_broker_signed_wire_positives_match_the_signing_paths() {
    for (relative, expected) in generated_positives() {
        assert!(
            committed(relative) == expected,
            "fixture tests/bindings/vectors/security/signed-wire/{relative} is out of date"
        );
    }
}

#[test]
fn committed_broker_signed_wire_positives_verify_against_the_pinned_keys() {
    let runner = SignedBrokerAuditRunnerAuthorization::from_canonical_bytes(&canonical_of(
        "positive/broker-audit-runner-authorization-envelope-v1.json",
    ))
    .test_unwrap();
    assert_eq!(
        runner.signer,
        backend(RUNNER_SEED).public_key().test_unwrap()
    );
    let comparison = SignedBrokerAuditComparison::from_canonical_bytes(&canonical_of(
        "positive/broker-audit-comparison-envelope-v1.json",
    ))
    .test_unwrap();
    verify_broker_audit_comparison(
        &comparison,
        &backend(COMPARISON_SEED).public_key().test_unwrap(),
    )
    .test_unwrap();
    assert_eq!(
        comparison.body,
        comparison_body(&runner),
        "comparison body is not bound to the committed runner authorization"
    );

    let request: crate::authority_ipc::SignedAuthorityRequest = serde_json::from_slice(
        &canonical_of("positive/broker-authority-request-envelope-v1.json"),
    )
    .test_unwrap();
    let response: crate::authority_ipc::SignedAuthorityResponse = serde_json::from_slice(
        &canonical_of("positive/broker-authority-response-envelope-v1.json"),
    )
    .test_unwrap();
    verify_authority_exchange(
        request,
        response,
        &backend(AUTHORITY_SEED).public_key().test_unwrap(),
        RESPONSE_ISSUED_AT,
        CLOCK_SKEW_SECONDS,
    )
    .test_unwrap();
}

#[test]
#[ignore = "regenerator: rewrites the broker rows of tests/bindings/vectors/security/signed-wire/positive"]
fn regenerate_broker_signed_wire_positives() {
    for (relative, bytes) in generated_positives() {
        std::fs::write(vector_root().join(relative), bytes).test_unwrap();
    }
}
