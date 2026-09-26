use super::*;

#[test]
fn response_plan_authorization_body_excludes_its_own_hash() {
    let plan = build_response_plan(plan_input(2))
        .unwrap_or_else(|failure| panic!("valid response plan rejected: {failure}"));
    let body = plan.authorization_body();
    let mut encoded = serde_json::to_value(&body)
        .unwrap_or_else(|failure| panic!("authorization body encoding failed: {failure}"));

    assert_eq!(body.action_id, plan.action_id);
    assert!(encoded.get("plan_hash").is_none());
    let keys = encoded
        .as_object()
        .unwrap_or_else(|| panic!("authorization body is not an object"))
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    let expected = [
        "action_id",
        "affected_ids",
        "affected_set_hash",
        "approval_requirement",
        "created_at_unix_ms",
        "effects",
        "execution",
        "expires_at_unix_ms",
        "operator_capability",
        "policy_hash",
        "policy_version",
        "reason_hash",
        "submitter",
        "tenant_id",
        "trigger_finding_hash",
        "trigger_finding_id",
        "trigger_finding_receipt_id",
        "ttl_ms",
    ]
    .into_iter()
    .collect();
    assert_eq!(keys, expected);
    let canonical = serde_json::to_string(&body)
        .unwrap_or_else(|failure| panic!("authorization body encoding failed: {failure}"));
    assert!(!canonical.contains("canonical_contribution"));
    assert!(!canonical.contains("posture_rank"));

    encoded["plan_hash"] = serde_json::json!(plan.plan_hash);
    let rejected = serde_json::from_value::<ResponsePlanAuthorizationBody>(encoded)
        .err()
        .unwrap_or_else(|| panic!("authorization body accepted its own plan hash"));
    assert!(rejected.to_string().contains("unknown field `plan_hash`"));
}

#[test]
fn response_plan_rejects_authorization_body_above_governance_ceiling() {
    let mut input = plan_input(1);
    input.affected_ids = (0..300)
        .map(|index| record(&format!("affected-{index:04}-{}", "a".repeat(220))))
        .collect();

    assert!(matches!(
        build_response_plan(input),
        Err(StateMachineError::InvalidPlan(PlanDefect::PlanBodyHash(_)))
    ));
}
