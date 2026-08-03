#![allow(clippy::expect_used, clippy::unwrap_used)]

use chio_core::capability::threshold_approval::{
    ThresholdApprovalRequest, ThresholdApprovalRequirementResolver,
    ThresholdApprovalResolutionError, DEFAULT_THRESHOLD_APPROVAL_TIMEOUT_SECONDS,
    MAX_THRESHOLD_APPROVAL_TIMEOUT_SECONDS, MAX_THRESHOLD_APPROVAL_TOKENS,
};
use chio_core::crypto::Keypair;
use chio_policy::compiler::{
    compile_policy_with_approver_directory, AuthenticatedApproverDirectorySnapshot,
    ThresholdApprovalResolver,
};
use chio_policy::models::{
    ChioApproverSet, ChioExtension, ChioHumanInLoopAdvanced, Extensions, HushSpec,
};
use chio_policy::{compile_policy, validate};

fn policy(name: &str, required: u32, of: Vec<String>, timeout_seconds: Option<u64>) -> HushSpec {
    HushSpec {
        hushspec: "0.1.0".to_string(),
        name: Some(name.to_string()),
        description: None,
        extends: None,
        merge_strategy: None,
        rules: None,
        extensions: Some(Extensions {
            chio: Some(ChioExtension {
                human_in_loop: Some(ChioHumanInLoopAdvanced {
                    approve_when: vec!["tool requires governed approval".to_string()],
                    approvers: Some(ChioApproverSet {
                        n: required,
                        of,
                        timeout_seconds,
                    }),
                }),
                ..ChioExtension::default()
            }),
            ..Extensions::default()
        }),
        metadata: None,
    }
}

fn key_hex() -> String {
    Keypair::generate().public_key().to_hex()
}

fn request() -> ThresholdApprovalRequest {
    ThresholdApprovalRequest::new("request-1", "payments", "refund")
        .expect("request key should be valid")
}

#[test]
fn malformed_approver_sets_fail_policy_validation() {
    let first = key_hex();
    let second = key_hex();
    let oversized = (0..=MAX_THRESHOLD_APPROVAL_TOKENS)
        .map(|_| key_hex())
        .collect::<Vec<_>>();
    let cases = [
        policy("zero", 0, vec![first.clone()], None),
        policy("above-set", 3, vec![first.clone(), second.clone()], None),
        policy("empty-id", 1, vec![String::new()], None),
        policy("whitespace-id", 1, vec![format!(" {first}")], None),
        policy("duplicate-id", 2, vec![first.clone(), first.clone()], None),
        policy(
            "duplicate-key",
            2,
            vec![first.clone(), format!("0x{first}")],
            None,
        ),
        policy("unresolved-alias", 1, vec!["alice".to_string()], None),
        policy("zero-timeout", 1, vec![first.clone()], Some(0)),
        policy(
            "excessive-timeout",
            1,
            vec![first],
            Some(MAX_THRESHOLD_APPROVAL_TIMEOUT_SECONDS + 1),
        ),
        policy("oversized-one-of", 1, oversized.clone(), None),
        policy(
            "oversized-all-of",
            u32::try_from(oversized.len()).expect("bounded oversized test set"),
            oversized,
            None,
        ),
    ];

    for spec in cases {
        let result = validate(&spec);
        assert!(
            !result.is_valid(),
            "malformed threshold policy unexpectedly validated: {:?}",
            spec.name
        );
    }
}

#[test]
fn compilation_requires_an_authenticated_directory_snapshot() {
    let spec = policy("directory-required", 1, vec![key_hex()], None);
    let error = match compile_policy(&spec) {
        Ok(_) => panic!("implicit approver authority must be rejected"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("approver directory"));
}

#[test]
fn default_timeout_and_eligible_digest_are_deterministic() {
    let first = key_hex();
    let second = key_hex();
    let directory = AuthenticatedApproverDirectorySnapshot::from_self_authenticating_hex_keys(
        7,
        vec![first.clone(), second.clone()],
    )
    .expect("directory should validate");
    let left = compile_policy_with_approver_directory(
        &policy("ordered-left", 2, vec![first.clone(), second.clone()], None),
        &directory,
    )
    .expect("left policy should compile");
    let right = compile_policy_with_approver_directory(
        &policy("ordered-right", 2, vec![second, first], None),
        &directory,
    )
    .expect("right policy should compile");
    let left_requirement = left
        .threshold_approval
        .expect("left requirement")
        .requirement()
        .expect("left requirement should be present");
    let right_requirement = right
        .threshold_approval
        .expect("right requirement")
        .requirement()
        .expect("right requirement should be present");

    assert_eq!(
        left_requirement.proposal_timeout_seconds(),
        DEFAULT_THRESHOLD_APPROVAL_TIMEOUT_SECONDS
    );
    assert_eq!(
        left_requirement.eligible_set_digest(),
        right_requirement.eligible_set_digest()
    );
    assert_eq!(left_requirement.approver_directory_version(), 7);
    assert_eq!(right_requirement.approver_directory_version(), 7);
    assert_ne!(
        left_requirement.policy_hash(),
        right_requirement.policy_hash()
    );
}

#[test]
fn unresolved_directory_member_fails_compilation() {
    let selected = key_hex();
    let other = key_hex();
    let directory =
        AuthenticatedApproverDirectorySnapshot::from_self_authenticating_hex_keys(1, vec![other])
            .expect("directory should validate");
    let error = match compile_policy_with_approver_directory(
        &policy("unresolved", 1, vec![selected], None),
        &directory,
    ) {
        Ok(_) => panic!("an absent directory member must fail closed"),
        Err(error) => error,
    };
    assert!(error
        .to_string()
        .contains("not present in approver directory"));
}

#[test]
fn stale_policy_hash_is_rejected() {
    let key = key_hex();
    let directory = AuthenticatedApproverDirectorySnapshot::from_self_authenticating_hex_keys(
        1,
        vec![key.clone()],
    )
    .expect("directory should validate");
    let compiled = compile_policy_with_approver_directory(
        &policy("current", 1, vec![key], Some(1200)),
        &directory,
    )
    .expect("policy should compile");
    let snapshot = compiled.threshold_approval.expect("resolver snapshot");
    let resolver = ThresholdApprovalResolver::new(snapshot);

    let error = resolver
        .resolve_threshold_approval_requirement(&request(), &"00".repeat(32))
        .expect_err("stale policy hash must deny");
    assert!(matches!(
        error,
        ThresholdApprovalResolutionError::StalePolicy { .. }
    ));
}

#[test]
fn reload_atomically_replaces_policy_and_directory_version() {
    let first = key_hex();
    let second = key_hex();
    let directory_v1 = AuthenticatedApproverDirectorySnapshot::from_self_authenticating_hex_keys(
        1,
        vec![first.clone()],
    )
    .expect("v1 directory should validate");
    let directory_v2 = AuthenticatedApproverDirectorySnapshot::from_self_authenticating_hex_keys(
        2,
        vec![second.clone()],
    )
    .expect("v2 directory should validate");
    let compiled_v1 =
        compile_policy_with_approver_directory(&policy("v1", 1, vec![first], None), &directory_v1)
            .expect("v1 policy should compile");
    let compiled_v2 = compile_policy_with_approver_directory(
        &policy("v2", 1, vec![second], Some(1200)),
        &directory_v2,
    )
    .expect("v2 policy should compile");
    let snapshot_v1 = compiled_v1.threshold_approval.expect("v1 snapshot");
    let snapshot_v2 = compiled_v2.threshold_approval.expect("v2 snapshot");
    let policy_hash_v1 = snapshot_v1.policy_hash().to_string();
    let policy_hash_v2 = snapshot_v2.policy_hash().to_string();
    let resolver = ThresholdApprovalResolver::new(snapshot_v1);

    let before = resolver
        .resolve_threshold_approval_requirement(&request(), &policy_hash_v1)
        .expect("v1 should resolve before reload");
    assert_eq!(before.approver_directory_version(), 1);

    resolver
        .replace_snapshot(snapshot_v2)
        .expect("snapshot replacement should succeed");

    let stale = resolver
        .resolve_threshold_approval_requirement(&request(), &policy_hash_v1)
        .expect_err("v1 must be stale after replacement");
    assert!(matches!(
        stale,
        ThresholdApprovalResolutionError::StalePolicy { .. }
    ));
    let after = resolver
        .resolve_threshold_approval_requirement(&request(), &policy_hash_v2)
        .expect("v2 should resolve after reload");
    assert_eq!(after.approver_directory_version(), 2);
    assert_eq!(after.proposal_timeout_seconds(), 1200);
}

#[test]
fn directory_rejects_zero_version_and_duplicate_public_keys() {
    let key = key_hex();
    assert!(
        AuthenticatedApproverDirectorySnapshot::from_self_authenticating_hex_keys(
            0,
            vec![key.clone()]
        )
        .is_err()
    );
    assert!(
        AuthenticatedApproverDirectorySnapshot::from_self_authenticating_hex_keys(
            1,
            vec![key.clone(), format!("0x{key}")]
        )
        .is_err()
    );
}
