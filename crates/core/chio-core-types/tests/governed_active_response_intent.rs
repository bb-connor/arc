#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core_types::capability::governance::{
    GovernedResponseEffect, GovernedResponsePlanIntentBody, GovernedTransactionIntent,
    GOVERNED_RESPONSE_PLAN_SCHEMA,
};
use chio_core_types::{canonical_json_bytes, Keypair};
use serde_json::{json, Value};

const MAX_RESPONSE_PLAN_BODY_BYTES: usize = 64 * 1024;

fn valid_response_plan_body() -> GovernedResponsePlanIntentBody {
    let canonical_plan_body = json!({
        "actionId": "action-1",
        "affectedSetHash": "a".repeat(64),
        "createdAt": 1_000,
        "expiresAt": 1_200,
        "policyVersion": "policy-7",
        "tenant": "tenant-1"
    });
    let plan_body_hash =
        GovernedResponsePlanIntentBody::compute_plan_body_hash(&canonical_plan_body).unwrap();
    GovernedResponsePlanIntentBody::new(
        GOVERNED_RESPONSE_PLAN_SCHEMA,
        "action-1",
        "operator-capability-1",
        "b".repeat(64),
        1_300,
        Keypair::generate().public_key(),
        canonical_plan_body,
        plan_body_hash,
        json!({
            "affectedSetHash": "a".repeat(64),
            "tenant": "tenant-1"
        }),
        vec![
            GovernedResponseEffect::FreezeIssuance,
            GovernedResponseEffect::SuspendCapabilitySet,
        ],
        1_200,
        json!({
            "contributionId": "action-1",
            "mode": "remove_contribution"
        }),
    )
    .unwrap()
}

fn decode_plan_error(value: Value) -> String {
    serde_json::from_value::<GovernedResponsePlanIntentBody>(value)
        .unwrap_err()
        .to_string()
}

fn decode_intent_error(value: Value) -> String {
    serde_json::from_value::<GovernedTransactionIntent>(value)
        .unwrap_err()
        .to_string()
}

fn assert_refused(message: &str, expected: &str) {
    assert_eq!(message, expected);
}

fn hash_error(body: &Value) -> String {
    GovernedResponsePlanIntentBody::compute_plan_body_hash(body)
        .unwrap_err()
        .to_string()
}

fn response_plan_json() -> Value {
    serde_json::to_value(valid_response_plan_body()).unwrap()
}

#[test]
fn active_response_plan_uses_an_explicit_typed_variant_and_binds_the_complete_body() {
    let intent = GovernedTransactionIntent::active_response_plan(valid_response_plan_body());
    let encoded = serde_json::to_value(&intent).unwrap();

    assert_eq!(encoded["body"]["kind"], "active_response_plan");
    assert!(encoded["body"].get("value").is_some());
    assert_ne!(
        intent.binding_hash().unwrap(),
        intent
            .as_active_response_plan()
            .unwrap()
            .plan_body_hash_value()
    );
    assert_eq!(
        serde_json::from_value::<GovernedTransactionIntent>(encoded.clone()).unwrap(),
        intent
    );

    let mut reordered = encoded;
    reordered["body"]["value"]["ordered_effects"] =
        json!(["suspend_capability_set", "freeze_issuance"]);
    let reordered: GovernedTransactionIntent = serde_json::from_value(reordered).unwrap();
    assert_ne!(
        intent.binding_hash().unwrap(),
        reordered.binding_hash().unwrap()
    );
}

#[test]
fn response_plan_rejects_unknown_fields_and_partial_variant_markers() {
    let mut body = response_plan_json();
    body["unknown_field"] = json!(true);
    assert_refused(
        &decode_plan_error(body),
        "unknown field `unknown_field`, expected one of `plan_schema`, `plan_id`, `operator_capability_id`, `operator_capability_hash`, `operator_capability_expires_at`, `executor_subject`, `canonical_plan_body`, `plan_body_hash`, `target_binding`, `ordered_effects`, `expires_at`, `rollback_binding`",
    );

    let mut partial = serde_json::to_value(GovernedTransactionIntent::active_response_plan(
        valid_response_plan_body(),
    ))
    .unwrap();
    partial["body"] = json!({"kind": "active_response_plan"});
    assert_refused(&decode_intent_error(partial), "missing field `value`");

    let mut wrong_kind = serde_json::to_value(GovernedTransactionIntent::active_response_plan(
        valid_response_plan_body(),
    ))
    .unwrap();
    wrong_kind["body"]["kind"] = json!("delete_account");
    assert_refused(
        &decode_intent_error(wrong_kind),
        "unknown variant `delete_account`, expected one of `tool_invocation`, `bound_tool_invocation`, `active_response_plan`",
    );
}

#[test]
fn response_plan_rejects_raw_hash_substitution_and_body_hash_mismatch() {
    let mut raw_hash = response_plan_json();
    raw_hash["canonical_plan_body"] = json!("a".repeat(64));
    raw_hash["plan_body_hash"] = json!("a".repeat(64));
    assert_refused(
        &decode_plan_error(raw_hash),
        "canonical JSON error: governed response plan body must be an object",
    );

    let mut mismatched = response_plan_json();
    mismatched["canonical_plan_body"]["tenant"] = json!("tenant-2");
    assert_refused(
        &decode_plan_error(mismatched),
        "canonical JSON error: governed response plan body hash does not match its canonical body",
    );

    let mut embedded_raw_hash = response_plan_json();
    embedded_raw_hash["canonical_plan_body"] = json!({"planHash": "a".repeat(64)});
    embedded_raw_hash["plan_body_hash"] = json!("a".repeat(64));
    assert_refused(
        &decode_plan_error(embedded_raw_hash),
        "canonical JSON error: governed response plan body is empty or recursively hashed",
    );
}

#[test]
fn response_plan_rejects_empty_duplicate_and_unsupported_effects() {
    let mut empty = response_plan_json();
    empty["ordered_effects"] = json!([]);
    assert_refused(
        &decode_plan_error(empty),
        "canonical JSON error: governed response plan must contain between 1 and 5 effects",
    );

    let mut duplicate = response_plan_json();
    duplicate["ordered_effects"] = json!(["suspend_session", "suspend_session"]);
    assert_refused(
        &decode_plan_error(duplicate),
        "canonical JSON error: governed response plan effects must be unique",
    );

    let mut unsupported = response_plan_json();
    unsupported["ordered_effects"] = json!(["delete_account"]);
    assert_refused(
        &decode_plan_error(unsupported),
        "unknown variant `delete_account`, expected one of `throttle_session`, `restrict_egress`, `suspend_session`, `suspend_capability_set`, `freeze_issuance`",
    );
}

#[test]
fn response_plan_rejects_invalid_digests_and_expiry_bounds() {
    for invalid_digest in ["abc".to_string(), "A".repeat(64), "g".repeat(64)] {
        let mut body = response_plan_json();
        body["operator_capability_hash"] = json!(invalid_digest);
        assert_refused(
            &decode_plan_error(body),
            "canonical JSON error: governed response plan operator capability hash must be lowercase SHA-256 hex",
        );
    }

    let mut expires_after_capability = response_plan_json();
    expires_after_capability["expires_at"] = json!(1_301);
    assert_refused(
        &decode_plan_error(expires_after_capability),
        "canonical JSON error: governed response plan expiry exceeds operator capability expiry",
    );

    let mut zero_expiry = response_plan_json();
    zero_expiry["expires_at"] = json!(0);
    assert_refused(
        &decode_plan_error(zero_expiry),
        "canonical JSON error: governed response plan expiry exceeds operator capability expiry",
    );
}

#[test]
fn response_plan_rejects_unbounded_identifiers_and_canonical_bodies() {
    let mut identifier = response_plan_json();
    identifier["plan_id"] = json!("x".repeat(257));
    assert_refused(
        &decode_plan_error(identifier),
        "canonical JSON error: governed response plan plan id is not canonical bounded text",
    );

    let mut huge_body = response_plan_json();
    huge_body["canonical_plan_body"] = json!({"payload": "x".repeat(65_536)});
    assert_refused(
        &hash_error(&huge_body["canonical_plan_body"]),
        "canonical JSON error: governed response plan canonical plan body exceeds the byte ceiling",
    );
    huge_body["plan_body_hash"] = json!("a".repeat(64));
    assert_refused(
        &decode_plan_error(huge_body),
        "canonical JSON error: governed response plan canonical plan body exceeds the byte ceiling",
    );
}

#[test]
fn response_plan_hashing_rejects_bodies_above_the_governance_node_ceiling() {
    let oversized = json!({"nodes": vec![false; 4_097]});

    assert_refused(
        &hash_error(&oversized),
        "canonical JSON error: governed response plan canonical plan body exceeds the JSON shape ceiling",
    );
}

#[test]
fn response_plan_hashing_enforces_the_exact_canonical_byte_ceiling() {
    let at_limit = json!({"payload": "x".repeat(MAX_RESPONSE_PLAN_BODY_BYTES - 14)});
    let above_limit = json!({"payload": "x".repeat(MAX_RESPONSE_PLAN_BODY_BYTES - 13)});

    assert_eq!(
        canonical_json_bytes(&at_limit).unwrap().len(),
        MAX_RESPONSE_PLAN_BODY_BYTES
    );
    assert!(GovernedResponsePlanIntentBody::compute_plan_body_hash(&at_limit).is_ok());
    assert_refused(
        &hash_error(&above_limit),
        "canonical JSON error: governed response plan canonical plan body exceeds the byte ceiling",
    );
}
