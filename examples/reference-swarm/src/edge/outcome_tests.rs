use super::*;

#[test]
fn only_exact_capability_budget_errors_are_candidates_for_receipt_verification() {
    let denied = CallOutcome {
        is_error: true,
        text: "invocation budget exhausted for capability cap-1".to_owned(),
        structured: Value::Null,
        event: Some("tool_denied".to_owned()),
    };
    assert!(denied.budget_exhausted("cap-1"));
    for text in [
        "trusted admission operation time regressed",
        "authority unavailable",
        "has been revoked",
        "provider error: invocation budget exhausted for capability cap-1",
        "invocation budget exhausted for capability cap-2",
    ] {
        assert!(!CallOutcome {
            text: text.to_owned(),
            ..denied.clone()
        }
        .budget_exhausted("cap-1"));
    }
    assert!(!CallOutcome {
        is_error: false,
        ..denied.clone()
    }
    .budget_exhausted("cap-1"));
    assert!(CallOutcome {
        event: None,
        ..denied.clone()
    }
    .budget_exhausted("cap-1"));
    assert!(!CallOutcome {
        event: Some("authority_unavailable".to_owned()),
        ..denied
    }
    .budget_exhausted("cap-1"));
}
