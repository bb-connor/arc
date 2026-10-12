use crate::capability::scope::{Constraint, MonetaryAmount, Operation, ToolGrant};
use crate::settlement_proof::ToolCallAuthorization;

fn invoke_grant() -> ToolGrant {
    ToolGrant {
        server_id: "srv".to_string(),
        tool_name: "tool_a".to_string(),
        operations: vec![Operation::Invoke],
        constraints: vec![],
        max_invocations: None,
        max_cost_per_invocation: None,
        max_total_cost: None,
        dpop_required: None,
    }
}

fn authorizes(grant: &ToolGrant) -> bool {
    ToolCallAuthorization::from_capability_grant(grant, "srv", "tool_a").is_authorized()
}

fn usd(units: u64) -> Option<MonetaryAmount> {
    Some(MonetaryAmount {
        units,
        currency: "USD".to_string(),
    })
}

#[test]
fn tool_call_authorization_defaults_to_denied() {
    assert!(!ToolCallAuthorization::default().is_authorized());
    assert_eq!(
        ToolCallAuthorization::default(),
        ToolCallAuthorization::denied()
    );
}

#[test]
fn matching_unbounded_invoke_grant_authorizes() {
    assert!(authorizes(&invoke_grant()));
    let wildcard = ToolGrant {
        server_id: "*".to_string(),
        tool_name: "*".to_string(),
        ..invoke_grant()
    };
    assert!(authorizes(&wildcard));
}

#[test]
fn wrong_target_or_missing_invoke_denies() {
    assert!(
        !ToolCallAuthorization::from_capability_grant(&invoke_grant(), "srv", "tool_b")
            .is_authorized()
    );
    assert!(
        !ToolCallAuthorization::from_capability_grant(&invoke_grant(), "other", "tool_a")
            .is_authorized()
    );
    let read_only = ToolGrant {
        operations: vec![Operation::ReadResult],
        ..invoke_grant()
    };
    assert!(!authorizes(&read_only));
}

#[test]
fn constrained_grant_denies() {
    let constrained = ToolGrant {
        constraints: vec![Constraint::PathPrefix("/safe".to_string())],
        ..invoke_grant()
    };
    assert!(!authorizes(&constrained));
}

#[test]
fn invocation_capped_grant_denies() {
    for cap in [0, 1] {
        let capped = ToolGrant {
            max_invocations: Some(cap),
            ..invoke_grant()
        };
        assert!(!authorizes(&capped), "max_invocations = Some({cap})");
    }
}

#[test]
fn monetary_capped_grant_denies() {
    for units in [0, 500] {
        let per_call = ToolGrant {
            max_cost_per_invocation: usd(units),
            ..invoke_grant()
        };
        assert!(!authorizes(&per_call), "max_cost_per_invocation = {units}");
        let total = ToolGrant {
            max_total_cost: usd(units),
            ..invoke_grant()
        };
        assert!(!authorizes(&total), "max_total_cost = {units}");
    }
}

#[test]
fn dpop_required_grant_denies() {
    let required = ToolGrant {
        dpop_required: Some(true),
        ..invoke_grant()
    };
    assert!(!authorizes(&required));
    let optional = ToolGrant {
        dpop_required: Some(false),
        ..invoke_grant()
    };
    assert!(authorizes(&optional));
}
