//! Unit tests for bilateral policy evaluation summary validation.
//!
//! `validate_policy_evaluation_summary` gates strict treaty-bound DSSE
//! admission. These tests pin the fail-closed rejection paths so verifier
//! wiring cannot silently accept mismatched or malformed verdict payloads.

use chio_federation::{
    validate_policy_evaluation_summary, BilateralCoSigningError, PolicyEvaluationSummary,
    PolicyVerdict,
};

fn allow_verdict(policy_id: &str) -> PolicyVerdict {
    PolicyVerdict {
        verdict: "allow".to_string(),
        policy_id: policy_id.to_string(),
        policy_version: "v1".to_string(),
        rationale_code: None,
    }
}

fn summary(
    server_a: PolicyVerdict,
    server_b: PolicyVerdict,
    joint: Option<&str>,
) -> PolicyEvaluationSummary {
    PolicyEvaluationSummary {
        server_a_verdict: server_a,
        server_b_verdict: server_b,
        joint_disposition: joint.map(str::to_string),
    }
}

#[test]
fn validate_policy_evaluation_summary_accepts_matching_allow_verdicts() {
    let input = summary(
        allow_verdict("policy-a"),
        allow_verdict("policy-b"),
        Some("allow"),
    );

    validate_policy_evaluation_summary(&input).expect("matching allow verdicts should validate");
}

#[test]
fn validate_policy_evaluation_summary_rejects_mismatched_server_verdicts() {
    let input = summary(
        allow_verdict("policy-a"),
        PolicyVerdict {
            verdict: "deny".to_string(),
            ..allow_verdict("policy-b")
        },
        Some("deny"),
    );

    let err = validate_policy_evaluation_summary(&input)
        .expect_err("server_a and server_b verdict mismatch must fail closed");

    match err {
        BilateralCoSigningError::CanonicalJson(message) => {
            assert!(message.contains("server_a=allow server_b=deny"));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn validate_policy_evaluation_summary_rejects_joint_disposition_mismatch() {
    let input = summary(
        allow_verdict("policy-a"),
        allow_verdict("policy-b"),
        Some("deny"),
    );

    let err = validate_policy_evaluation_summary(&input)
        .expect_err("joint_disposition must agree with server verdicts");

    match err {
        BilateralCoSigningError::CanonicalJson(message) => {
            assert!(message.contains("joint_disposition=deny"));
            assert!(message.contains("verdict=allow"));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn validate_policy_evaluation_summary_rejects_unsupported_verdict_tokens() {
    let input = summary(
        PolicyVerdict {
            verdict: "observe".to_string(),
            ..allow_verdict("policy-a")
        },
        PolicyVerdict {
            verdict: "observe".to_string(),
            ..allow_verdict("policy-b")
        },
        Some("observe"),
    );

    let err = validate_policy_evaluation_summary(&input)
        .expect_err("unsupported verdict strings must fail closed");

    match err {
        BilateralCoSigningError::CanonicalJson(message) => {
            assert!(message.contains("unsupported verdict"));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn validate_policy_evaluation_summary_rejects_empty_policy_id() {
    let mut verdict = allow_verdict("policy-a");
    verdict.policy_id.clear();
    let input = summary(verdict.clone(), allow_verdict("policy-b"), Some("allow"));

    let err = validate_policy_evaluation_summary(&input)
        .expect_err("empty policy_id must fail closed");

    match err {
        BilateralCoSigningError::CanonicalJson(message) => {
            assert!(message.contains("policy_id must be non-empty"));
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}
