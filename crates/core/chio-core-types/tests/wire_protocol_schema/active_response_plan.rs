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
