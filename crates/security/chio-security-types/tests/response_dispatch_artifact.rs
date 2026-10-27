#![cfg(feature = "std")]

use chio_security_types::ports::{
    PreparedActiveResponseDispatchBinding, ResponseDispatchAuthorizationBody,
};
use chio_security_types::ResponseExecutionDispatchBinding;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

fn dispatch_binding() -> Value {
    json!({
        "schema_version": 1,
        "tenant_id": "tenant-dispatch",
        "dispatch_id": "dispatch-response",
        "action_id": "action-response",
        "plan_hash": ([1u8; 32]),
        "executor_authority_id": "executor-authority",
        "executor_authority_generation": 7,
        "authorization_capability_hash": ([3u8; 32]),
        "governed_intent_hash": ([4u8; 32]),
        "policy_decision_hash": ([5u8; 32]),
        "approval": { "approval_mode": "automatic" },
        "authorized_at_unix_ms": 40_000
    })
}

fn dispatch_authorization() -> Value {
    let mut value = dispatch_binding();
    let fields = value
        .as_object_mut()
        .unwrap_or_else(|| panic!("dispatch fixture must be an object"));
    fields.remove("tenant_id");
    fields.remove("dispatch_id");
    fields.insert(
        "key".to_owned(),
        json!({ "tenant_id": "tenant-dispatch", "dispatch_id": "dispatch-response" }),
    );
    fields.insert("response_body_hash".to_owned(), json!(([2u8; 32])));
    value
}

fn assert_decode_refusal<T: DeserializeOwned>(value: Value, expected: &str) {
    let error = match serde_json::from_value::<T>(value) {
        Ok(_) => panic!("dispatch without an artifact fingerprint was accepted"),
        Err(error) => error,
    };
    assert_eq!(error.classify(), serde_json::error::Category::Data);
    assert_eq!(error.to_string(), expected);
}

#[test]
fn prepared_binding_refuses_missing_artifact_fingerprint() {
    assert_decode_refusal::<PreparedActiveResponseDispatchBinding>(
        dispatch_binding(),
        "missing field `admission_artifact_fingerprint`",
    );
}

#[test]
fn authorization_refuses_missing_artifact_fingerprint() {
    assert_decode_refusal::<ResponseDispatchAuthorizationBody>(
        dispatch_authorization(),
        "missing field `admission_artifact_fingerprint`",
    );
}

#[test]
fn execution_binding_refuses_missing_artifact_fingerprint() {
    assert_decode_refusal::<ResponseExecutionDispatchBinding>(
        dispatch_binding(),
        "missing field `admission_artifact_fingerprint`",
    );
}

#[test]
fn prepared_binding_refuses_null_artifact_fingerprint() {
    let mut value = dispatch_binding();
    value["admission_artifact_fingerprint"] = Value::Null;
    assert_decode_refusal::<PreparedActiveResponseDispatchBinding>(
        value,
        "invalid type: null, expected an array of length 32",
    );
}

#[test]
fn authorization_refuses_null_artifact_fingerprint() {
    let mut value = dispatch_authorization();
    value["admission_artifact_fingerprint"] = Value::Null;
    assert_decode_refusal::<ResponseDispatchAuthorizationBody>(
        value,
        "invalid type: null, expected an array of length 32",
    );
}

#[test]
fn execution_binding_refuses_null_artifact_fingerprint() {
    let mut value = dispatch_binding();
    value["admission_artifact_fingerprint"] = Value::Null;
    assert_decode_refusal::<ResponseExecutionDispatchBinding>(
        value,
        "invalid type: null, expected an array of length 32",
    );
}

#[test]
fn execution_binding_accepts_required_v1_artifact() {
    let mut value = dispatch_binding();
    value["admission_artifact_fingerprint"] = json!(([7u8; 32]));
    let binding: ResponseExecutionDispatchBinding = serde_json::from_value(value)
        .unwrap_or_else(|error| panic!("bound v1 fixture failed to decode: {error}"));
    assert_eq!(
        binding.validate_for_response(
            &binding.tenant_id,
            &binding.action_id,
            &binding.plan_hash,
            50_000,
        ),
        Ok(())
    );
}

#[test]
fn execution_binding_refuses_unsupported_artifact_schemas() {
    for schema in [0, 2, u8::MAX] {
        let mut value = dispatch_binding();
        value["schema_version"] = json!(schema);
        value["admission_artifact_fingerprint"] = json!(([7u8; 32]));
        let binding: ResponseExecutionDispatchBinding = serde_json::from_value(value)
            .unwrap_or_else(|error| panic!("schema fixture failed to decode: {error}"));
        assert_eq!(
            binding.validate_for_response(
                &binding.tenant_id,
                &binding.action_id,
                &binding.plan_hash,
                50_000,
            ),
            Err(
                chio_security_types::ResponseExecutionDispatchBindingError::Invalid(
                    "unsupported or unbound artifact schema"
                )
            ),
            "schema {schema}"
        );
    }
}
