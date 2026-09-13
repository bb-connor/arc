use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use chio_core_types::{canonical_json_bytes, PublicKey};
use chio_test_support::prelude::*;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;

use super::{decode_canonical_response, validate_execute_failure, validate_execute_response};
use crate::capability::verify_capability;
use crate::proof::verify_request_proof;
use crate::protocol::{
    decode_execute_request, BrokerExecuteFailure, BrokerExecuteRequest, BrokerExecuteResponse,
    SignedBrokerCapability,
};
use crate::receipt::{
    verify_execution_receipt, verify_failure_receipt, BrokerFailureReceiptBody,
    SignedBrokerFailureReceipt, SignedBrokerReceipt,
};
use crate::registration::{
    attempt_registration_digest, verify_register_attempt_authorization, RegisterAttemptAction,
    SignedRegisterAttemptAuthorization,
};
use crate::store::AttemptRegistration;
use crate::{BrokerError, Result};

const CAPABILITY_ISSUER_HEX: &str =
    "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce";
const RECEIPT_AND_REGISTRATION_AUTHORITY_HEX: &str =
    "fa4834147f6e690c3693eff61336046403cd8ae2a14f31b3c407358569239565";
const BROKER_AUDIENCE: &str = "broker-service-production";
const VERIFICATION_TIME: u64 = 100;
const MAXIMUM_CLOCK_SKEW_SECONDS: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ErrorKind {
    InvalidRequest,
    AuthorizationDenied,
}

const SEMANTIC_CASES: [(&str, &str, ErrorKind, &str); 18] = [
    (
        "capability_noncanonical_trailing_newline",
        "noncanonical_capability_bytes",
        ErrorKind::AuthorizationDenied,
        "is not canonical JSON",
    ),
    (
        "capability_parent_self_binding",
        "invalid_capability_identity",
        ErrorKind::InvalidRequest,
        "capability identity, time, adapter, or execution bound is invalid",
    ),
    (
        "capability_subject_proof_mismatch",
        "subject_proof_key_mismatch",
        ErrorKind::InvalidRequest,
        "capability identity, time, adapter, or execution bound is invalid",
    ),
    (
        "capability_signature_tampered",
        "invalid_capability_signature",
        ErrorKind::AuthorizationDenied,
        "capability signature is invalid",
    ),
    (
        "proof_body_digest_tampered",
        "body_digest_mismatch",
        ErrorKind::AuthorizationDenied,
        "proof does not bind the complete request",
    ),
    (
        "proof_header_digest_tampered",
        "header_digest_mismatch",
        ErrorKind::AuthorizationDenied,
        "proof does not bind the complete request",
    ),
    (
        "proof_option_digest_tampered",
        "option_digest_mismatch",
        ErrorKind::AuthorizationDenied,
        "proof does not bind the complete request",
    ),
    (
        "execute_request_destination_rebound",
        "destination_binding_mismatch",
        ErrorKind::AuthorizationDenied,
        "proof does not bind the complete request",
    ),
    (
        "receipt_capture_revocation_digest_tampered",
        "receipt_signature_or_capture_binding",
        ErrorKind::AuthorizationDenied,
        "receipt signature is invalid",
    ),
    (
        "receipt_quota_not_canonical",
        "noncanonical_quota_order",
        ErrorKind::AuthorizationDenied,
        "quota set is not canonical",
    ),
    (
        "receipt_signature_tampered",
        "invalid_receipt_signature",
        ErrorKind::AuthorizationDenied,
        "receipt signature is invalid",
    ),
    (
        "execute_response_receipt_signature_tampered",
        "invalid_response_receipt_signature",
        ErrorKind::AuthorizationDenied,
        "receipt signature is invalid",
    ),
    (
        "attempt_registration_id_rebound",
        "noncanonical_attempt_identifier",
        ErrorKind::InvalidRequest,
        "attempt identifiers do not match the canonical derivation",
    ),
    (
        "register_attempt_authorization_action_tampered",
        "invalid_registration_authorization_signature",
        ErrorKind::AuthorizationDenied,
        "authorization binding is invalid",
    ),
    (
        "failure_receipt_partial_attempt_binding",
        "incomplete_failure_attempt_binding",
        ErrorKind::InvalidRequest,
        "failure receipt attempt binding is incomplete",
    ),
    (
        "failure_receipt_untruthful_dispatch_state",
        "untruthful_failure_dispatch_state",
        ErrorKind::InvalidRequest,
        "stage, outcome, or dispatch state is inconsistent",
    ),
    (
        "failure_receipt_signature_tampered",
        "invalid_failure_receipt_signature",
        ErrorKind::AuthorizationDenied,
        "failure receipt signature is invalid",
    ),
    (
        "execute_failure_diagnostic_rebound",
        "failure_diagnostic_binding_mismatch",
        ErrorKind::AuthorizationDenied,
        "failure receipt envelope or request binding is invalid",
    ),
];

const SCHEMA_REJECTED_CASES: [&str; 2] = [
    "execute_response_receipt_missing",
    "receipt_forbidden_credential_value",
];

#[derive(Deserialize)]
struct VectorIndex {
    schema: String,
    positive: Vec<PositiveVector>,
    negative: Vec<NegativeVector>,
}

#[derive(Deserialize)]
struct PositiveVector {
    id: String,
    file: String,
}

#[derive(Deserialize)]
struct NegativeVector {
    id: String,
    file: String,
}

#[derive(Deserialize)]
struct MutationCorpus {
    schema: String,
    operation_format: String,
    cases: Vec<MutationCase>,
}

#[derive(Deserialize)]
struct MutationCase {
    id: String,
    base: String,
    mutation: Mutation,
    expected: ExpectedOutcome,
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Mutation {
    AppendBytes { hex: String },
    Replace { path: String, value: Value },
    Add { path: String, value: Value },
    Remove { path: String },
}

#[derive(Deserialize)]
struct ExpectedOutcome {
    json_parse_valid: bool,
    json_schema_valid: bool,
    semantic_valid: bool,
    failure: String,
}

#[test]
fn every_schema_valid_broker_mutation_is_rejected_by_its_native_semantic_boundary() {
    let root = vector_root();
    let index: VectorIndex = decode_json(&read(&root.join("index.json")), "broker vector index")
        .test_expect("broker vector index must decode");
    assert_eq!(index.schema, "chio.test-vector.broker.index.v1");
    assert!(!index.positive.is_empty(), "positive vector index is empty");
    let positive_ids = index
        .positive
        .iter()
        .map(|entry| entry.id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(positive_ids.len(), index.positive.len());
    assert!(positive_ids.iter().all(|id| !id.is_empty()));
    assert_eq!(
        index
            .negative
            .iter()
            .map(|entry| (entry.id.as_str(), entry.file.as_str()))
            .collect::<Vec<_>>(),
        vec![("broker_mutations_v1", "mutations-v1.json")]
    );

    let corpus: MutationCorpus = decode_json(
        &read(&root.join("mutations-v1.json")),
        "broker mutation corpus",
    )
    .test_expect("broker mutation corpus must decode");
    assert_eq!(corpus.schema, "chio.test-vector.broker.mutations.v1");
    assert_eq!(
        corpus.operation_format,
        "RFC 6902 single-operation subset plus append_bytes"
    );

    let mut cases = BTreeMap::new();
    let positive_files = index
        .positive
        .iter()
        .map(|entry| entry.file.as_str())
        .collect::<BTreeSet<_>>();
    for case in &corpus.cases {
        assert!(!case.id.is_empty(), "mutation case ID is empty");
        assert!(
            positive_files.contains(case.base.as_str()),
            "{} references an unindexed positive vector {}",
            case.id,
            case.base
        );
        assert!(case.expected.json_parse_valid, "{} must parse", case.id);
        assert!(!case.expected.semantic_valid, "{} must be invalid", case.id);
        assert!(
            cases.insert(case.id.as_str(), case).is_none(),
            "duplicate broker mutation case {}",
            case.id
        );
    }

    let expected_semantic_ids = SEMANTIC_CASES
        .iter()
        .map(|(id, _, _, _)| *id)
        .collect::<BTreeSet<_>>();
    assert_eq!(expected_semantic_ids.len(), SEMANTIC_CASES.len());
    assert_eq!(
        cases
            .values()
            .filter(|case| case.expected.json_schema_valid)
            .map(|case| case.id.as_str())
            .collect::<BTreeSet<_>>(),
        expected_semantic_ids
    );
    assert_eq!(
        cases
            .values()
            .filter(|case| !case.expected.json_schema_valid)
            .map(|case| case.id.as_str())
            .collect::<BTreeSet<_>>(),
        SCHEMA_REJECTED_CASES.into_iter().collect::<BTreeSet<_>>()
    );
    assert_registration_authorization_digest_binding(&root);

    for case in cases.values() {
        let base = read(&root.join(&case.base));
        let mutated = apply_mutation(&base, &case.mutation);
        assert_eq!(
            serde_json::from_slice::<Value>(&mutated).is_ok(),
            case.expected.json_parse_valid,
            "{} parse expectation drifted",
            case.id
        );
    }

    for (id, failure, kind, message) in SEMANTIC_CASES {
        let case = cases
            .get(id)
            .test_expect("declared semantic case must exist");
        assert_eq!(case.expected.failure, failure, "{id} failure label drifted");
        let base = read(&root.join(&case.base));
        verify_semantics(id, &base)
            .unwrap_or_else(|error| panic!("{id} positive vector was rejected: {error}"));
        let mutated = apply_mutation(&base, &case.mutation);
        let error = verify_semantics(id, &mutated)
            .test_expect_err("schema-valid mutation must fail native semantics");
        assert_error(id, &error, kind, message);
    }
}

fn assert_registration_authorization_digest_binding(root: &Path) {
    let registration: AttemptRegistration = decode_json(
        &read(&root.join("positive/broker-attempt-registration-v1.json")),
        "broker attempt registration",
    )
    .test_expect("positive attempt registration must decode");
    let authorization: SignedRegisterAttemptAuthorization = decode_json(
        &read(&root.join("positive/broker-register-attempt-authorization-envelope-v1.json")),
        "register-attempt authorization",
    )
    .test_expect("positive register-attempt authorization must decode");
    let typed_digest = attempt_registration_digest(&registration)
        .test_expect("positive attempt registration must have a canonical digest");
    assert_eq!(
        authorization.body.registration_digest, typed_digest,
        "register-attempt authorization must bind typed canonical registration bytes"
    );
}

fn verify_semantics(id: &str, bytes: &[u8]) -> Result<()> {
    match id {
        "capability_noncanonical_trailing_newline" => {
            decode_canonical_response::<SignedBrokerCapability>(bytes, "broker capability")?;
            Ok(())
        }
        "capability_parent_self_binding"
        | "capability_subject_proof_mismatch"
        | "capability_signature_tampered" => {
            let capability: SignedBrokerCapability = decode_json(bytes, "broker capability")?;
            verify_capability(
                &capability,
                &capability_issuer(),
                BROKER_AUDIENCE,
                VERIFICATION_TIME,
                true,
            )
        }
        "proof_body_digest_tampered"
        | "proof_header_digest_tampered"
        | "proof_option_digest_tampered"
        | "execute_request_destination_rebound" => {
            let request = decode_execute_request(bytes)?;
            verify_execute_request(&request)
        }
        "receipt_capture_revocation_digest_tampered"
        | "receipt_quota_not_canonical"
        | "receipt_signature_tampered" => {
            let receipt: SignedBrokerReceipt = decode_json(bytes, "broker receipt")?;
            verify_execution_receipt(&receipt, &receipt_and_registration_authority())
        }
        "execute_response_receipt_signature_tampered" => {
            let response: BrokerExecuteResponse = decode_json(bytes, "broker execute response")?;
            validate_execute_response(
                &related_execute_request(),
                &response,
                &receipt_and_registration_authority(),
            )
        }
        "attempt_registration_id_rebound" => {
            let registration: AttemptRegistration =
                decode_json(bytes, "broker attempt registration")?;
            registration.validate()
        }
        "register_attempt_authorization_action_tampered" => {
            let authorization: SignedRegisterAttemptAuthorization =
                decode_json(bytes, "register-attempt authorization")?;
            verify_register_attempt_authorization(
                &authorization,
                &related_attempt_registration(),
                RegisterAttemptAction::Register,
                "tenant-production",
                &receipt_and_registration_authority(),
                VERIFICATION_TIME,
                MAXIMUM_CLOCK_SKEW_SECONDS,
            )
        }
        "failure_receipt_partial_attempt_binding" | "failure_receipt_untruthful_dispatch_state" => {
            let body: BrokerFailureReceiptBody = decode_json(bytes, "failure receipt body")?;
            body.validate()
        }
        "failure_receipt_signature_tampered" => {
            let receipt: SignedBrokerFailureReceipt = decode_json(bytes, "broker failure receipt")?;
            verify_failure_receipt(&receipt, &receipt_and_registration_authority())
        }
        "execute_failure_diagnostic_rebound" => {
            let failure: BrokerExecuteFailure = decode_json(bytes, "broker execute failure")?;
            validate_execute_failure(
                &related_execute_request(),
                &failure,
                Some(failure.diagnostic_code.as_str()),
                &receipt_and_registration_authority(),
            )
        }
        _ => Err(BrokerError::Invariant(format!(
            "unmapped broker semantic vector {id}"
        ))),
    }
}

fn verify_execute_request(request: &BrokerExecuteRequest) -> Result<()> {
    verify_capability(
        &request.capability,
        &capability_issuer(),
        BROKER_AUDIENCE,
        VERIFICATION_TIME,
        true,
    )?;
    verify_request_proof(
        &request.proof,
        &request.capability,
        &request.request,
        VERIFICATION_TIME,
        MAXIMUM_CLOCK_SKEW_SECONDS,
    )
}

fn related_execute_request() -> BrokerExecuteRequest {
    let bytes = read(&vector_root().join("positive/broker-execute-request-v1.json"));
    let request = decode_execute_request(&bytes).test_expect("related execute request must decode");
    verify_execute_request(&request).test_expect("related execute request must verify");
    request
}

fn related_attempt_registration() -> AttemptRegistration {
    let bytes = read(&vector_root().join("positive/broker-attempt-registration-v1.json"));
    let registration: AttemptRegistration =
        decode_json(&bytes, "related attempt registration").test_expect("registration must decode");
    registration
        .validate()
        .test_expect("related attempt registration must verify");
    registration
}

fn capability_issuer() -> PublicKey {
    PublicKey::from_hex(CAPABILITY_ISSUER_HEX).test_expect("fixed capability issuer must parse")
}

fn receipt_and_registration_authority() -> PublicKey {
    PublicKey::from_hex(RECEIPT_AND_REGISTRATION_AUTHORITY_HEX)
        .test_expect("fixed receipt and registration authority must parse")
}

fn assert_error(id: &str, error: &BrokerError, kind: ErrorKind, message: &str) {
    let actual_kind = match error {
        BrokerError::InvalidRequest(_) => ErrorKind::InvalidRequest,
        BrokerError::AuthorizationDenied(_) => ErrorKind::AuthorizationDenied,
        _ => panic!("{id} failed at the wrong boundary: {error}"),
    };
    assert_eq!(actual_kind, kind, "{id} returned the wrong error kind");
    assert!(
        error.to_string().contains(message),
        "{id} failed for the wrong reason: {error}"
    );
}

fn apply_mutation(base: &[u8], mutation: &Mutation) -> Vec<u8> {
    match mutation {
        Mutation::AppendBytes { hex } => {
            let mut mutated = base.to_vec();
            mutated.extend(hex::decode(hex).test_expect("append_bytes hex must decode"));
            mutated
        }
        Mutation::Replace { path, value } => {
            let mut document: Value =
                serde_json::from_slice(base).test_expect("replacement base must parse");
            *document
                .pointer_mut(path)
                .unwrap_or_else(|| panic!("replacement pointer {path} must exist")) = value.clone();
            canonical_json_bytes(&document).test_expect("mutated document must canonicalize")
        }
        Mutation::Add { path, value } => {
            let mut document: Value =
                serde_json::from_slice(base).test_expect("add base must parse");
            let (parent, key) = pointer_parent_mut(&mut document, path);
            let object = parent
                .as_object_mut()
                .unwrap_or_else(|| panic!("add pointer {path} parent must be an object"));
            assert!(
                object.insert(key, value.clone()).is_none(),
                "add pointer {path} unexpectedly replaced a value"
            );
            canonical_json_bytes(&document).test_expect("mutated document must canonicalize")
        }
        Mutation::Remove { path } => {
            let mut document: Value =
                serde_json::from_slice(base).test_expect("remove base must parse");
            let (parent, key) = pointer_parent_mut(&mut document, path);
            let object = parent
                .as_object_mut()
                .unwrap_or_else(|| panic!("remove pointer {path} parent must be an object"));
            assert!(
                object.remove(&key).is_some(),
                "remove pointer {path} must exist"
            );
            canonical_json_bytes(&document).test_expect("mutated document must canonicalize")
        }
    }
}

fn pointer_parent_mut<'a>(document: &'a mut Value, path: &str) -> (&'a mut Value, String) {
    let (parent_path, token) = path
        .rsplit_once('/')
        .unwrap_or_else(|| panic!("JSON pointer {path} must contain a slash"));
    let token = token.replace("~1", "/").replace("~0", "~");
    let parent = if parent_path.is_empty() {
        document
    } else {
        document
            .pointer_mut(parent_path)
            .unwrap_or_else(|| panic!("JSON pointer parent {parent_path} must exist"))
    };
    (parent, token)
}

fn decode_json<T: DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T> {
    serde_json::from_slice(bytes)
        .map_err(|error| BrokerError::InvalidRequest(format!("{label} decoding failed: {error}")))
}

fn read(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn vector_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/bindings/vectors/security/broker")
}
