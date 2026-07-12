#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core_types::capability::governance::{
    GovernedResponseEffect, GovernedResponsePlanIntentBody, GovernedToolInvocationIntentBody,
    GovernedTransactionIntent, CHIO_GOVERNED_TRANSACTION_INTENT_SCHEMA_V2,
    CHIO_RESPONSE_PLAN_SCHEMA,
};
use chio_core_types::{canonical_json_bytes, sha256_hex, Keypair};
use serde_json::{json, Value};

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
        CHIO_RESPONSE_PLAN_SCHEMA,
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

fn response_plan_json() -> Value {
    serde_json::to_value(valid_response_plan_body()).unwrap()
}

#[test]
fn tool_invocation_fields_are_preserved_inside_the_explicit_versioned_variant() {
    let tool_body = json!({
        "id": "intent-1",
        "server_id": "srv-pay",
        "tool_name": "charge",
        "purpose": "pay supplier",
        "max_amount": {"units": 500, "currency": "USD"},
        "commerce": {
            "seller": "merchant.example",
            "shared_payment_token_id": "spt-1"
        }
    });

    let intent = GovernedTransactionIntent::tool_invocation(
        serde_json::from_value::<GovernedToolInvocationIntentBody>(tool_body.clone()).unwrap(),
    );
    let encoded = serde_json::to_value(&intent).unwrap();

    assert!(intent.as_tool_invocation().is_some());
    assert_eq!(
        encoded["schema"],
        CHIO_GOVERNED_TRANSACTION_INTENT_SCHEMA_V2
    );
    assert_eq!(encoded["kind"], "tool_invocation");
    assert_eq!(encoded["body"], tool_body);
    assert_eq!(
        intent.binding_hash().unwrap(),
        sha256_hex(&canonical_json_bytes(&encoded).unwrap())
    );
}

#[test]
fn active_response_plan_uses_an_explicit_versioned_variant_and_binds_the_complete_body() {
    let intent = GovernedTransactionIntent::active_response_plan(valid_response_plan_body());
    let encoded = serde_json::to_value(&intent).unwrap();

    assert_eq!(
        encoded["schema"],
        CHIO_GOVERNED_TRANSACTION_INTENT_SCHEMA_V2
    );
    assert_eq!(encoded["kind"], "active_response_plan");
    assert!(encoded.get("body").is_some());
    assert_ne!(
        intent.binding_hash().unwrap(),
        intent.as_active_response_plan().unwrap().plan_body_hash()
    );
    assert_eq!(
        serde_json::from_value::<GovernedTransactionIntent>(encoded.clone()).unwrap(),
        intent
    );

    let mut reordered = encoded;
    reordered["body"]["orderedEffects"] = json!(["suspend_capability_set", "freeze_issuance"]);
    let reordered: GovernedTransactionIntent = serde_json::from_value(reordered).unwrap();
    assert_ne!(
        intent.binding_hash().unwrap(),
        reordered.binding_hash().unwrap()
    );
}

#[test]
fn response_plan_rejects_unknown_fields_and_partial_variant_markers() {
    let mut body = response_plan_json();
    body["unknownField"] = json!(true);
    assert!(serde_json::from_value::<GovernedResponsePlanIntentBody>(body).is_err());

    let partial = json!({
        "schema": CHIO_GOVERNED_TRANSACTION_INTENT_SCHEMA_V2,
        "body": response_plan_json()
    });
    assert!(serde_json::from_value::<GovernedTransactionIntent>(partial).is_err());

    let mut unknown_envelope = serde_json::to_value(
        GovernedTransactionIntent::active_response_plan(valid_response_plan_body()),
    )
    .unwrap();
    unknown_envelope["unknownField"] = json!(true);
    assert!(serde_json::from_value::<GovernedTransactionIntent>(unknown_envelope).is_err());

    let mut wrong_schema = serde_json::to_value(GovernedTransactionIntent::active_response_plan(
        valid_response_plan_body(),
    ))
    .unwrap();
    wrong_schema["schema"] = json!("chio.governed-transaction-intent.v3");
    assert!(serde_json::from_value::<GovernedTransactionIntent>(wrong_schema).is_err());
}

#[test]
fn response_plan_rejects_raw_hash_substitution_and_body_hash_mismatch() {
    let mut raw_hash = response_plan_json();
    raw_hash["canonicalPlanBody"] = json!("a".repeat(64));
    raw_hash["planBodyHash"] = json!("a".repeat(64));
    assert!(serde_json::from_value::<GovernedResponsePlanIntentBody>(raw_hash).is_err());

    let mut mismatched = response_plan_json();
    mismatched["canonicalPlanBody"]["tenant"] = json!("tenant-2");
    assert!(serde_json::from_value::<GovernedResponsePlanIntentBody>(mismatched).is_err());

    let mut embedded_raw_hash = response_plan_json();
    embedded_raw_hash["canonicalPlanBody"] = json!({"planHash": "a".repeat(64)});
    embedded_raw_hash["planBodyHash"] = json!("a".repeat(64));
    assert!(serde_json::from_value::<GovernedResponsePlanIntentBody>(embedded_raw_hash).is_err());
}

#[test]
fn response_plan_rejects_empty_duplicate_and_unsupported_effects() {
    let mut empty = response_plan_json();
    empty["orderedEffects"] = json!([]);
    assert!(serde_json::from_value::<GovernedResponsePlanIntentBody>(empty).is_err());

    let mut duplicate = response_plan_json();
    duplicate["orderedEffects"] = json!(["suspend_session", "suspend_session"]);
    assert!(serde_json::from_value::<GovernedResponsePlanIntentBody>(duplicate).is_err());

    let mut unsupported = response_plan_json();
    unsupported["orderedEffects"] = json!(["delete_account"]);
    assert!(serde_json::from_value::<GovernedResponsePlanIntentBody>(unsupported).is_err());
}

#[test]
fn response_plan_rejects_invalid_digests_and_expiry_bounds() {
    for invalid_digest in ["abc".to_string(), "A".repeat(64), "g".repeat(64)] {
        let mut body = response_plan_json();
        body["operatorCapabilityHash"] = json!(invalid_digest);
        assert!(serde_json::from_value::<GovernedResponsePlanIntentBody>(body).is_err());
    }

    let mut expires_after_capability = response_plan_json();
    expires_after_capability["expiresAt"] = json!(1_301);
    assert!(
        serde_json::from_value::<GovernedResponsePlanIntentBody>(expires_after_capability).is_err()
    );

    let mut zero_expiry = response_plan_json();
    zero_expiry["expiresAt"] = json!(0);
    assert!(serde_json::from_value::<GovernedResponsePlanIntentBody>(zero_expiry).is_err());
}

#[test]
fn response_plan_rejects_unbounded_identifiers_and_canonical_bodies() {
    let mut identifier = response_plan_json();
    identifier["planId"] = json!("x".repeat(257));
    assert!(serde_json::from_value::<GovernedResponsePlanIntentBody>(identifier).is_err());

    let mut huge_body = response_plan_json();
    huge_body["canonicalPlanBody"] = json!({"payload": "x".repeat(65_536)});
    huge_body["planBodyHash"] = json!(GovernedResponsePlanIntentBody::compute_plan_body_hash(
        &huge_body["canonicalPlanBody"]
    )
    .unwrap());
    assert!(serde_json::from_value::<GovernedResponsePlanIntentBody>(huge_body).is_err());
}
