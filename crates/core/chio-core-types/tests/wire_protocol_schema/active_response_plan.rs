use chio_core_types::capability::governance::GovernedResponsePlanIntentBody;
use serde_json::{json, Value};

use super::{load_schema, repo_root, schema_root, validator_for_schema};

const SCHEMA: &str = "agent/active-response-governed-intent.schema.json";

fn fixture(name: &str) -> Value {
    let corpus: Value = serde_json::from_str(
        &std::fs::read_to_string(
            repo_root().join("tests/bindings/fixtures/protocol-primitives-v1.json"),
        )
        .expect("protocol-primitives fixture corpus exists"),
    )
    .expect("protocol-primitives fixture corpus parses");
    corpus["cases"]
        .as_array()
        .expect("fixture cases are an array")
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("fixture `{name}` exists"))["instance"]
        .clone()
}

fn schema_accepts(instance: &Value) -> bool {
    let schema = load_schema(SCHEMA);
    validator_for_schema(&schema_root().join(SCHEMA), &schema).is_valid(instance)
}

fn native_accepts(instance: &Value) -> bool {
    serde_json::from_value::<GovernedResponsePlanIntentBody>(instance.clone()).is_ok()
}

fn with(base: &Value, field: &str, value: Value) -> Value {
    let mut instance = base.clone();
    instance[field] = value;
    instance
}

#[test]
fn active_response_schema_matches_native_plan_bounds() {
    let base = fixture("active-response-intent");
    assert!(
        native_accepts(&base),
        "native validator rejected the base plan"
    );
    assert!(schema_accepts(&base), "schema rejected the base plan");

    let all_effects = json!([
        "throttle_session",
        "restrict_egress",
        "suspend_session",
        "suspend_capability_set",
        "freeze_issuance"
    ]);
    let mut at_bound = with(&base, "ordered_effects", all_effects);
    at_bound["plan_id"] = json!("p".repeat(256));
    at_bound["operator_capability_id"] = json!("o".repeat(256));
    assert!(
        native_accepts(&at_bound),
        "native validator rejected an at-bound plan"
    );
    assert!(
        schema_accepts(&at_bound),
        "schema rejected an at-bound plan"
    );

    let rejected = [
        (
            "duplicate effects",
            with(
                &base,
                "ordered_effects",
                json!(["throttle_session", "throttle_session"]),
            ),
        ),
        (
            "six effects",
            with(
                &base,
                "ordered_effects",
                json!([
                    "throttle_session",
                    "restrict_egress",
                    "suspend_session",
                    "suspend_capability_set",
                    "freeze_issuance",
                    "throttle_session"
                ]),
            ),
        ),
        ("empty effects", with(&base, "ordered_effects", json!([]))),
        (
            "overlong plan id",
            with(&base, "plan_id", json!("p".repeat(257))),
        ),
        (
            "control character plan id",
            with(&base, "plan_id", json!("plan\u{7}1")),
        ),
        ("padded plan id", with(&base, "plan_id", json!("plan-1 "))),
        (
            "overlong operator capability id",
            with(&base, "operator_capability_id", json!("o".repeat(257))),
        ),
        (
            "control character operator capability id",
            with(&base, "operator_capability_id", json!("operator\u{0}cap")),
        ),
        (
            "padded operator capability id",
            with(&base, "operator_capability_id", json!(" operator-cap-1")),
        ),
        (
            "empty target binding",
            with(&base, "target_binding", json!({})),
        ),
        (
            "empty rollback binding",
            with(&base, "rollback_binding", json!({})),
        ),
        (
            "empty plan body",
            with(&base, "canonical_plan_body", json!({})),
        ),
        (
            "camel-case recursively hashed plan body",
            with(
                &base,
                "canonical_plan_body",
                json!({ "action": "throttle", "planHash": "a" }),
            ),
        ),
        (
            "snake-case recursively hashed plan body",
            with(
                &base,
                "canonical_plan_body",
                json!({ "action": "throttle", "plan_hash": "a" }),
            ),
        ),
    ];
    for (label, instance) in rejected {
        assert!(
            !native_accepts(&instance),
            "native validator accepted {label}"
        );
        assert!(!schema_accepts(&instance), "schema accepted {label}");
    }
}

fn without(base: &Value, field: &str) -> Value {
    let mut instance = base.clone();
    instance
        .as_object_mut()
        .expect("plan is an object")
        .remove(field);
    instance
}

const REQUIRED_FIELDS: [&str; 12] = [
    "plan_schema",
    "plan_id",
    "operator_capability_id",
    "operator_capability_hash",
    "operator_capability_expires_at",
    "executor_subject",
    "canonical_plan_body",
    "plan_body_hash",
    "target_binding",
    "ordered_effects",
    "expires_at",
    "rollback_binding",
];

#[test]
fn active_response_schema_and_native_agree_on_structure_and_scalars() {
    let base = fixture("active-response-intent");
    let p256 = format!("p256:{}", "a".repeat(130));
    let p384 = format!("p384:{}", "b".repeat(194));
    let accepted = [
        (
            "p256 executor",
            with(&base, "executor_subject", json!(p256)),
        ),
        (
            "p384 executor",
            with(&base, "executor_subject", json!(p384)),
        ),
        (
            "unicode identifier",
            with(&base, "plan_id", json!("plan\u{e9}-1")),
        ),
        (
            "interior space identifier",
            with(&base, "plan_id", json!("plan 1")),
        ),
        ("equal expiries", with(&base, "expires_at", json!(300))),
        (
            "nested hash key in plan body",
            with(
                &base,
                "canonical_plan_body",
                json!({ "action": { "planHash": "x" } }),
            ),
        ),
    ];
    for (label, instance) in accepted {
        // A changed plan body no longer matches its recorded digest, and a
        // p256 or p384 subject must be a point on its curve; only the native
        // validator checks either, so the schema is asserted alone for those.
        if label == "nested hash key in plan body"
            || label.ends_with("executor") && label != "ed25519 executor"
        {
            assert!(schema_accepts(&instance), "schema rejected {label}");
            continue;
        }
        assert!(native_accepts(&instance), "native rejected {label}");
        assert!(schema_accepts(&instance), "schema rejected {label}");
    }

    let mut rejected = vec![
        ("unknown field".to_owned(), with(&base, "extra", json!(1))),
        (
            "unsupported plan schema".to_owned(),
            with(&base, "plan_schema", json!("chio.response-plan.v2")),
        ),
        (
            "non-string plan id".to_owned(),
            with(&base, "plan_id", json!(7)),
        ),
        (
            "empty plan id".to_owned(),
            with(&base, "plan_id", json!("")),
        ),
        (
            "leading tab plan id".to_owned(),
            with(&base, "plan_id", json!("\tplan-1")),
        ),
        (
            "short capability hash".to_owned(),
            with(&base, "operator_capability_hash", json!("ab")),
        ),
        (
            "uppercase capability hash".to_owned(),
            with(&base, "operator_capability_hash", json!("B".repeat(64))),
        ),
        (
            "non-hex plan body hash".to_owned(),
            with(&base, "plan_body_hash", json!("g".repeat(64))),
        ),
        (
            "uppercase executor".to_owned(),
            with(&base, "executor_subject", json!("C".repeat(64))),
        ),
        (
            "short executor".to_owned(),
            with(&base, "executor_subject", json!("cc")),
        ),
        (
            "prefixed executor with wrong length".to_owned(),
            with(&base, "executor_subject", json!("p256:aa")),
        ),
        (
            "unknown effect".to_owned(),
            with(&base, "ordered_effects", json!(["wipe_disk"])),
        ),
        (
            "effects not an array".to_owned(),
            with(&base, "ordered_effects", json!("throttle_session")),
        ),
        (
            "zero expiry".to_owned(),
            with(&base, "expires_at", json!(0)),
        ),
        (
            "zero operator expiry".to_owned(),
            with(&base, "operator_capability_expires_at", json!(0)),
        ),
        (
            "negative expiry".to_owned(),
            with(&base, "expires_at", json!(-1)),
        ),
        (
            "fractional expiry".to_owned(),
            with(&base, "expires_at", json!(1.5)),
        ),
        (
            "array plan body".to_owned(),
            with(&base, "canonical_plan_body", json!([1])),
        ),
        (
            "array target binding".to_owned(),
            with(&base, "target_binding", json!([1])),
        ),
        (
            "string rollback binding".to_owned(),
            with(&base, "rollback_binding", json!("automatic")),
        ),
        (
            "null target binding".to_owned(),
            with(&base, "target_binding", Value::Null),
        ),
    ];
    for field in REQUIRED_FIELDS {
        rejected.push((format!("missing {field}"), without(&base, field)));
    }
    for (label, instance) in rejected {
        assert!(
            !native_accepts(&instance),
            "native validator accepted {label}"
        );
        assert!(!schema_accepts(&instance), "schema accepted {label}");
    }
}

#[test]
fn active_response_native_rules_the_schema_cannot_express_fail_closed() {
    let base = fixture("active-response-intent");
    let deep = (0..40).fold(json!({ "leaf": 1 }), |inner, _| json!({ "n": inner }));
    let wide: Vec<Value> = (0..4_200).map(|n| json!(n)).collect();
    let rejected = [
        (
            "identifier over 256 bytes with fewer than 257 characters",
            with(&base, "plan_id", json!("\u{e9}".repeat(129))),
        ),
        (
            "expiry past the operator capability expiry",
            with(&base, "expires_at", json!(301)),
        ),
        (
            "plan body that does not match its digest",
            with(&base, "canonical_plan_body", json!({ "action": "other" })),
        ),
        (
            "target binding over the byte ceiling",
            with(&base, "target_binding", json!({ "k": "x".repeat(16_385) })),
        ),
        (
            "rollback binding nested past the depth ceiling",
            with(&base, "rollback_binding", deep),
        ),
        (
            "target binding past the node ceiling",
            with(&base, "target_binding", json!({ "values": wide })),
        ),
    ];
    for (label, instance) in rejected {
        assert!(
            !native_accepts(&instance),
            "native validator accepted {label}"
        );
    }
}
