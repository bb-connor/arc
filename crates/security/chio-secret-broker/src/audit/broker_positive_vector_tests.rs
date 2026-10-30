use chio_test_support::prelude::*;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use chio_core_types::crypto::verify_wrapped;
use chio_core_types::{
    canonical_json_bytes, sha256_hex, CanonicalBytes, Keypair, PublicKey, Signature,
};
use serde_json::{json, Value};

use super::*;
use crate::authority_ipc::{signed_request_digest, SignedAuthorityRequest};
use crate::capability::capability_digest;
use crate::proof::proof_digest;
use crate::protocol::BrokerExecuteRequest;
use crate::registration::{
    attempt_registration_digest, broker_execute_request_registration_digest, prepared_dispatch_id,
};
use crate::store::AttemptRegistration;

const BROKER_DIRECTORY: &str = "tests/bindings/vectors/security/broker/positive";
const SIGNED_WIRE_DIRECTORY: &str = "tests/bindings/vectors/security/signed-wire/positive";

const CAPABILITY_ISSUER_SEED: u8 = 51;
const PROOF_SUBJECT_SEED: u8 = 52;
const RECEIPT_AND_REGISTRATION_SEED: u8 = 41;
const COMPLETION_RECEIPT_SEED: u8 = 43;
const AUDIT_BROKER_SEED: u8 = 201;
const AUDIT_RUNNER_SEED: u8 = 202;
const AUDIT_AUTHORITY_SEED: u8 = 203;
const WIRE_BROKER_SEED: u8 = 85;
const WIRE_AUTHORITY_SEED: u8 = 102;
const WIRE_RUNNER_SEED: u8 = 161;
const WIRE_COMPARISON_SEED: u8 = 162;

const PINNED_SIGNERS: [(&str, &str, u8); 14] = [
    (
        BROKER_DIRECTORY,
        "chio.broker-capability.v1",
        CAPABILITY_ISSUER_SEED,
    ),
    (
        BROKER_DIRECTORY,
        "chio.broker-request-proof.v1",
        PROOF_SUBJECT_SEED,
    ),
    (
        BROKER_DIRECTORY,
        "chio.broker-register-attempt-authorization.v1",
        RECEIPT_AND_REGISTRATION_SEED,
    ),
    (
        BROKER_DIRECTORY,
        "chio.broker-execution-failure-receipt.v1",
        RECEIPT_AND_REGISTRATION_SEED,
    ),
    (
        BROKER_DIRECTORY,
        "chio.broker-execution-receipt.v1",
        COMPLETION_RECEIPT_SEED,
    ),
    (
        BROKER_DIRECTORY,
        "chio.broker-privileged-audit-challenge.v1",
        AUDIT_BROKER_SEED,
    ),
    (
        BROKER_DIRECTORY,
        "chio.broker-audit-runner-authorization.v1",
        AUDIT_RUNNER_SEED,
    ),
    (
        BROKER_DIRECTORY,
        "chio.broker-audit-comparison.v1",
        AUDIT_BROKER_SEED,
    ),
    (
        BROKER_DIRECTORY,
        "chio.broker-authority-request.v1",
        AUDIT_BROKER_SEED,
    ),
    (
        BROKER_DIRECTORY,
        "chio.broker-authority-response.v1",
        AUDIT_AUTHORITY_SEED,
    ),
    (
        SIGNED_WIRE_DIRECTORY,
        "chio.broker-audit-runner-authorization.v1",
        WIRE_RUNNER_SEED,
    ),
    (
        SIGNED_WIRE_DIRECTORY,
        "chio.broker-audit-comparison.v1",
        WIRE_COMPARISON_SEED,
    ),
    (
        SIGNED_WIRE_DIRECTORY,
        "chio.broker-authority-request.v1",
        WIRE_BROKER_SEED,
    ),
    (
        SIGNED_WIRE_DIRECTORY,
        "chio.broker-authority-response.v1",
        WIRE_AUTHORITY_SEED,
    ),
];

const EXPECTED_BROKER_ENVELOPES: usize = 20;
const EXPECTED_SIGNED_WIRE_ENVELOPES: usize = 4;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn keypair(seed: u8) -> Keypair {
    Keypair::from_seed(&[seed; 32])
}

fn read(directory: &str, name: &str) -> Value {
    let bytes = fs::read(repository_root().join(directory).join(name)).test_unwrap();
    serde_json::from_slice(&bytes).test_unwrap()
}

fn write(name: &str, value: &Value) {
    let path = repository_root().join(BROKER_DIRECTORY).join(name);
    let trailing_newline = fs::read(&path).test_unwrap().ends_with(b"\n");
    let mut bytes = canonical_json_bytes(value).test_unwrap();
    if trailing_newline {
        bytes.push(b'\n');
    }
    fs::write(&path, bytes).test_unwrap();
}

fn digest_of(value: &Value) -> String {
    sha256_hex(&canonical_json_bytes(value).test_unwrap())
}

fn sign_body(seed: u8, body: &Value) -> Value {
    let schema = body["schema"].as_str().test_unwrap();
    let signature = CanonicalBytes::from_value(body)
        .and_then(|canonical| keypair(seed).sign_wrapped(schema, &canonical))
        .test_unwrap();
    serde_json::to_value(signature).test_unwrap()
}

fn resign(seed: u8, envelope: &mut Value, with_signer: bool) {
    let body = envelope["body"].clone();
    envelope["signature"] = sign_body(seed, &body);
    if with_signer {
        envelope["signer"] = serde_json::to_value(keypair(seed).public_key()).test_unwrap();
    }
}

fn envelope_from(name: &str, seed: u8, with_signer: bool) -> Value {
    let mut envelope = read(BROKER_DIRECTORY, name);
    resign(seed, &mut envelope, with_signer);
    envelope
}

fn resign_exchange(exchange: &mut Value) {
    let mut request = exchange["request"].clone();
    resign(AUDIT_BROKER_SEED, &mut request, false);
    let request_digest = signed_request_digest(
        &serde_json::from_value::<SignedAuthorityRequest>(request.clone()).test_unwrap(),
    )
    .test_unwrap();
    let mut response = exchange["response"].clone();
    response["body"]["requestDigest"] = Value::String(request_digest.clone());
    resign(AUDIT_AUTHORITY_SEED, &mut response, false);
    exchange["requestSha256"] = Value::String(request_digest);
    exchange["responseSha256"] = Value::String(digest_of(&response));
    exchange["request"] = request;
    exchange["response"] = response;
}

#[test]
#[ignore = "regenerates the committed broker positive vectors"]
fn regenerate_broker_positive_vectors() {
    let capability = envelope_from(
        "broker-capability-envelope-v1.json",
        CAPABILITY_ISSUER_SEED,
        false,
    );
    let proof = envelope_from(
        "broker-request-proof-envelope-v1.json",
        PROOF_SUBJECT_SEED,
        false,
    );

    let mut execute_request = read(BROKER_DIRECTORY, "broker-execute-request-v1.json");
    execute_request["capability"] = capability.clone();
    execute_request["proof"] = proof.clone();
    let request: BrokerExecuteRequest =
        serde_json::from_value(execute_request.clone()).test_unwrap();
    let capability_sha256 = capability_digest(&request.capability).test_unwrap();

    let mut registration = read(BROKER_DIRECTORY, "broker-attempt-registration-v1.json");
    registration["requestCanonicalDigest"] =
        Value::String(broker_execute_request_registration_digest(&request).test_unwrap());
    registration["proofDigest"] = Value::String(proof_digest(&request.proof).test_unwrap());
    let registration_typed: AttemptRegistration =
        serde_json::from_value(registration.clone()).test_unwrap();
    let mut authorization = read(
        BROKER_DIRECTORY,
        "broker-register-attempt-authorization-envelope-v1.json",
    );
    authorization["body"]["registrationDigest"] =
        Value::String(attempt_registration_digest(&registration_typed).test_unwrap());
    resign(RECEIPT_AND_REGISTRATION_SEED, &mut authorization, false);
    let mut authorization_body = read(
        BROKER_DIRECTORY,
        "broker-register-attempt-authorization-body-v1.json",
    );
    authorization_body["registrationDigest"] = authorization["body"]["registrationDigest"].clone();
    let mut dispatch_acknowledgement = read(
        BROKER_DIRECTORY,
        "broker-prepare-dispatch-acknowledgement-v1.json",
    );
    dispatch_acknowledgement["preparedDispatchId"] =
        Value::String(prepared_dispatch_id(&registration_typed, &request).test_unwrap());

    let mut evidence_source = read(BROKER_DIRECTORY, "broker-execution-evidence-v1.json");
    evidence_source["capabilityDigest"] = Value::String(capability_sha256.clone());
    let mut receipt_body = read(BROKER_DIRECTORY, "broker-execution-receipt-body-v1.json");
    receipt_body["evidence"] = evidence_source.clone();

    let mut failure_body = read(
        BROKER_DIRECTORY,
        "broker-execution-failure-receipt-body-v1.json",
    );
    failure_body["capabilityDigest"] = Value::String(capability_sha256);
    let mut failure_receipt = read(
        BROKER_DIRECTORY,
        "broker-execution-failure-receipt-envelope-v1.json",
    );
    failure_receipt["body"] = failure_body.clone();
    resign(RECEIPT_AND_REGISTRATION_SEED, &mut failure_receipt, true);
    let challenge = envelope_from(
        "broker-privileged-audit-challenge-v1.json",
        AUDIT_BROKER_SEED,
        true,
    );

    let mut runner = read(BROKER_DIRECTORY, "broker-privileged-audit-evidence-v1.json")
        ["runnerAuthorization"]
        .clone();
    resign(AUDIT_RUNNER_SEED, &mut runner, true);
    let runner_typed: SignedBrokerAuditRunnerAuthorization =
        serde_json::from_value(runner.clone()).test_unwrap();
    let runner_sha256 = runner_authorization_digest(&runner_typed).test_unwrap();
    let governed_intent =
        broker_audit_governed_intent_digest(&runner_typed.body, &runner_sha256).test_unwrap();

    let mut evidence = read(BROKER_DIRECTORY, "broker-privileged-audit-evidence-v1.json");
    evidence["challenge"] = challenge.clone();
    evidence["runnerAuthorization"] = runner.clone();
    for exchange in ["livenessAuthorityExchange", "revocationAuthorityExchange"] {
        resign_exchange(&mut evidence[exchange]);
    }
    evidence["comparison"]["body"]["runnerAuthorizationSha256"] = Value::String(runner_sha256);
    evidence["comparison"]["body"]["governedAuditIntentSha256"] = Value::String(governed_intent);
    let mut comparison = evidence["comparison"].clone();
    resign(AUDIT_BROKER_SEED, &mut comparison, true);
    evidence["comparison"] = comparison;

    let mut commit = read(BROKER_DIRECTORY, "broker-privileged-audit-commit-v1.json");
    commit["runnerAuthorization"] = runner;

    let mut open = read(BROKER_DIRECTORY, "broker-privileged-audit-open-v1.json");
    open["request"]["capability"] = capability.clone();
    open["request"]["proof"] = proof.clone();

    let mut execute_failure = read(BROKER_DIRECTORY, "broker-execute-failure-v1.json");
    execute_failure["receipt"] = failure_receipt.clone();
    execute_failure["receiptReference"] = Value::String(format!(
        "broker-failure-receipt-sha256-{}",
        digest_of(&failure_receipt)
    ));

    write("broker-capability-envelope-v1.json", &capability);
    write("broker-request-proof-envelope-v1.json", &proof);
    write(
        "broker-register-attempt-authorization-envelope-v1.json",
        &authorization,
    );
    write(
        "broker-register-attempt-authorization-body-v1.json",
        &authorization_body,
    );
    write("broker-attempt-registration-v1.json", &registration);
    write(
        "broker-prepare-dispatch-acknowledgement-v1.json",
        &dispatch_acknowledgement,
    );
    write("broker-execution-evidence-v1.json", &evidence_source);
    write("broker-execution-receipt-body-v1.json", &receipt_body);
    write(
        "broker-execution-failure-receipt-body-v1.json",
        &failure_body,
    );
    write(
        "broker-execution-failure-receipt-envelope-v1.json",
        &failure_receipt,
    );
    write("broker-privileged-audit-challenge-v1.json", &challenge);
    write("broker-privileged-audit-evidence-v1.json", &evidence);
    write("broker-privileged-audit-commit-v1.json", &commit);
    write("broker-privileged-audit-open-v1.json", &open);
    write("broker-execute-request-v1.json", &execute_request);
    write("broker-execute-failure-v1.json", &execute_failure);
}

fn collect_envelopes(value: &Value, path: &str, out: &mut Vec<(String, Value)>) {
    match value {
        Value::Object(fields) => {
            let is_envelope = fields.get("signature").is_some_and(Value::is_string)
                && fields
                    .get("body")
                    .and_then(|body| body.get("schema"))
                    .is_some_and(Value::is_string);
            if is_envelope {
                out.push((path.to_string(), value.clone()));
            }
            for (key, child) in fields {
                collect_envelopes(child, &format!("{path}/{key}"), out);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                collect_envelopes(child, &format!("{path}/{index}"), out);
            }
        }
        _ => {}
    }
}

fn verify_directory(directory: &str, failures: &mut Vec<String>) -> usize {
    let pinned: BTreeMap<&str, PublicKey> = PINNED_SIGNERS
        .iter()
        .filter(|(pinned_directory, _, _)| *pinned_directory == directory)
        .map(|(_, schema, seed)| (*schema, keypair(*seed).public_key()))
        .collect();
    let mut names: Vec<String> = fs::read_dir(repository_root().join(directory))
        .test_unwrap()
        .map(|entry| entry.test_unwrap().file_name().into_string().test_unwrap())
        .filter(|name| name.starts_with("broker-") && name.ends_with(".json"))
        .collect();
    names.sort();
    let mut checked = 0;
    for name in names {
        let value = read(directory, &name);
        let mut envelopes = Vec::new();
        collect_envelopes(&value, "", &mut envelopes);
        for (path, envelope) in envelopes {
            checked += 1;
            let label = format!("{directory}/{name}{path}");
            let schema = envelope["body"]["schema"].as_str().test_unwrap();
            let Some(key) = pinned.get(schema) else {
                failures.push(format!("{label}: no pinned signer for {schema}"));
                continue;
            };
            if let Some(signer) = envelope.get("signer") {
                let carried: std::result::Result<PublicKey, _> =
                    serde_json::from_value(signer.clone());
                if carried.as_ref().ok() != Some(key) {
                    failures.push(format!("{label}: carried signer is not the pinned signer"));
                    continue;
                }
            }
            let signature: std::result::Result<Signature, _> =
                serde_json::from_value(envelope["signature"].clone());
            match signature {
                Ok(signature) => {
                    if verify_wrapped(key, schema, &envelope["body"], &signature).is_err() {
                        failures.push(format!("{label}: signature does not verify"));
                    }
                }
                Err(error) => failures.push(format!("{label}: signature is malformed: {error}")),
            }
        }
    }
    checked
}

#[test]
fn every_broker_vector_signature_verifies_under_its_pinned_signer() {
    let mut failures = Vec::new();
    let broker = verify_directory(BROKER_DIRECTORY, &mut failures);
    let signed_wire = verify_directory(SIGNED_WIRE_DIRECTORY, &mut failures);
    if broker != EXPECTED_BROKER_ENVELOPES {
        failures.push(format!(
            "{BROKER_DIRECTORY}: expected {EXPECTED_BROKER_ENVELOPES} signed envelopes, found {broker}"
        ));
    }
    if signed_wire != EXPECTED_SIGNED_WIRE_ENVELOPES {
        failures.push(format!(
            "{SIGNED_WIRE_DIRECTORY}: expected {EXPECTED_SIGNED_WIRE_ENVELOPES} signed envelopes, found {signed_wire}"
        ));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn a_tampered_broker_vector_body_is_rejected() {
    let mut envelope = read(BROKER_DIRECTORY, "broker-capability-envelope-v1.json");
    envelope["body"]["maximumExecutions"] = json!(3);
    let key = keypair(CAPABILITY_ISSUER_SEED).public_key();
    let signature: Signature = serde_json::from_value(envelope["signature"].clone()).test_unwrap();
    assert!(verify_wrapped(
        &key,
        "chio.broker-capability.v1",
        &envelope["body"],
        &signature
    )
    .is_err());
}
