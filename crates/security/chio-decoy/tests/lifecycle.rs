use chio_decoy::{fail_transition, retry_transition, transition, ArmedReplacement, LifecycleError};
use chio_security_types::ports::{ArtifactId, Digest32, RecordId, TenantId};
use chio_security_types::{
    DecoyErrorClass, DecoyLifecycle, DecoyLifecycleState, DecoyOperationAttempt,
    DecoyOperationKind, DecoyRecord, DecoySurface, DecoyVersion,
};
use chio_test_support::prelude::*;

fn id(value: &str) -> RecordId {
    RecordId::new(value).test_expect("valid record id")
}

fn artifact(value: &str) -> ArtifactId {
    ArtifactId::new(value).test_expect("valid artifact id")
}

fn record(state: DecoyLifecycleState) -> DecoyRecord {
    DecoyRecord {
        tenant_id: TenantId::new("tenant-a").test_expect("valid tenant"),
        artifact_id: artifact("artifact-a-v1"),
        public_marker_ref: None,
        surface: DecoySurface::CredentialFile,
        scope_id: id("scope-a"),
        marker_digest: Digest32::new([1; 32]),
        creation_policy_id: id("policy-a"),
        version: DecoyVersion::new(1).test_expect("valid version"),
        version_hash: Digest32::new([2; 32]),
        lifecycle: state.into(),
        generation: 7,
        expires_at_unix_ms: 9_000_000,
        predecessor_artifact_id: None,
        successor_artifact_id: None,
    }
}

fn attempt(
    record: &DecoyRecord,
    kind: DecoyOperationKind,
    successor_artifact_id: Option<ArtifactId>,
) -> DecoyOperationAttempt {
    DecoyOperationAttempt {
        operation_id: id(&format!("operation-{kind:?}")),
        kind,
        expected_generation: record.generation,
        expected_version: record.version,
        successor_artifact_id,
    }
}

fn replacement(old: &DecoyRecord) -> DecoyRecord {
    DecoyRecord {
        tenant_id: old.tenant_id.clone(),
        artifact_id: artifact("artifact-a-v2"),
        public_marker_ref: None,
        surface: old.surface,
        scope_id: old.scope_id.clone(),
        marker_digest: Digest32::new([3; 32]),
        creation_policy_id: old.creation_policy_id.clone(),
        version: old.version.checked_next().test_expect("next version"),
        version_hash: Digest32::new([4; 32]),
        lifecycle: DecoyLifecycle::Armed,
        generation: 2,
        expires_at_unix_ms: old.expires_at_unix_ms + 1,
        predecessor_artifact_id: Some(old.artifact_id.clone()),
        successor_artifact_id: None,
    }
}

#[test]
fn lifecycle_accepts_every_linear_edge() {
    let cases = [
        (
            DecoyLifecycleState::Planned,
            DecoyOperationKind::BeginMaterialization,
            DecoyLifecycleState::Materializing,
        ),
        (
            DecoyLifecycleState::Materializing,
            DecoyOperationKind::Arm,
            DecoyLifecycleState::Armed,
        ),
        (
            DecoyLifecycleState::Armed,
            DecoyOperationKind::Trigger,
            DecoyLifecycleState::Triggered,
        ),
        (
            DecoyLifecycleState::Triggered,
            DecoyOperationKind::BeginRotation,
            DecoyLifecycleState::Rotating,
        ),
    ];

    for (from, operation, to) in cases {
        let current = record(from);
        let successor =
            (operation == DecoyOperationKind::BeginRotation).then(|| artifact("artifact-a-v2"));
        let next = transition(&current, &attempt(&current, operation, successor), None)
            .test_expect("legal edge");
        assert_eq!(next.lifecycle.state(), Some(to));
        assert_eq!(next.generation, current.generation + 1);
    }

    let mut rotating = record(DecoyLifecycleState::Rotating);
    rotating.successor_artifact_id = Some(artifact("artifact-a-v2"));
    let successor = replacement(&rotating);
    let retire = attempt(
        &rotating,
        DecoyOperationKind::Retire,
        Some(successor.artifact_id.clone()),
    );
    let next = transition(
        &rotating,
        &retire,
        Some(&ArmedReplacement::new(&rotating, &successor).test_expect("armed replacement")),
    )
    .test_expect("rotation may retire after replacement is armed");
    assert_eq!(next.lifecycle, DecoyLifecycle::Retired);
}

#[test]
fn lifecycle_rejects_every_non_linear_edge() {
    let states = [
        DecoyLifecycleState::Planned,
        DecoyLifecycleState::Materializing,
        DecoyLifecycleState::Armed,
        DecoyLifecycleState::Triggered,
        DecoyLifecycleState::Rotating,
        DecoyLifecycleState::Retired,
    ];
    let operations = [
        DecoyOperationKind::BeginMaterialization,
        DecoyOperationKind::Arm,
        DecoyOperationKind::Trigger,
        DecoyOperationKind::BeginRotation,
        DecoyOperationKind::Retire,
    ];

    for state in states {
        for operation in operations {
            let is_legal = matches!(
                (state, operation),
                (
                    DecoyLifecycleState::Planned,
                    DecoyOperationKind::BeginMaterialization
                ) | (DecoyLifecycleState::Materializing, DecoyOperationKind::Arm)
                    | (DecoyLifecycleState::Armed, DecoyOperationKind::Trigger)
                    | (
                        DecoyLifecycleState::Triggered,
                        DecoyOperationKind::BeginRotation
                    )
            );
            if is_legal {
                continue;
            }
            let current = record(state);
            let successor = matches!(
                operation,
                DecoyOperationKind::BeginRotation | DecoyOperationKind::Retire
            )
            .then(|| artifact("artifact-a-v2"));
            assert!(matches!(
                transition(&current, &attempt(&current, operation, successor), None),
                Err(LifecycleError::IllegalEdge | LifecycleError::ReplacementRequired)
            ));
        }
    }
}

#[test]
fn error_preserves_prior_and_only_exact_retry_or_retire_is_legal() {
    let current = record(DecoyLifecycleState::Materializing);
    let arm = attempt(&current, DecoyOperationKind::Arm, None);
    let failed = fail_transition(&current, &arm, DecoyErrorClass::IoFailure)
        .test_expect("record materialization error");
    assert_eq!(
        failed.lifecycle,
        DecoyLifecycle::Error {
            prior: DecoyLifecycleState::Materializing,
            attempted: arm.clone(),
            error_class: DecoyErrorClass::IoFailure,
        }
    );

    let mut different = arm.clone();
    different.operation_id = id("different-operation");
    assert_eq!(
        retry_transition(&failed, &different, None),
        Err(LifecycleError::RetryMismatch)
    );
    assert_eq!(
        transition(&failed, &different, None),
        Err(LifecycleError::RecoveryRestricted)
    );

    let retried = retry_transition(&failed, &arm, None).test_expect("exact retry");
    assert_eq!(retried.lifecycle, DecoyLifecycle::Armed);
    assert_eq!(retried.generation, failed.generation + 1);

    let retire = DecoyOperationAttempt {
        operation_id: id("retire-error"),
        kind: DecoyOperationKind::Retire,
        expected_generation: failed.generation,
        expected_version: failed.version,
        successor_artifact_id: None,
    };
    assert_eq!(
        transition(&failed, &retire, None)
            .test_expect("operator may retire error state")
            .lifecycle,
        DecoyLifecycle::Retired
    );
}

#[test]
fn retire_requires_a_distinct_armed_successor_for_the_next_version() {
    let mut old = record(DecoyLifecycleState::Rotating);
    old.successor_artifact_id = Some(artifact("artifact-a-v2"));
    let retire = attempt(
        &old,
        DecoyOperationKind::Retire,
        Some(artifact("artifact-a-v2")),
    );
    assert_eq!(
        transition(&old, &retire, None),
        Err(LifecycleError::ReplacementRequired)
    );

    let mut not_armed = replacement(&old);
    not_armed.lifecycle = DecoyLifecycle::Materializing;
    assert_eq!(
        ArmedReplacement::new(&old, &not_armed),
        Err(LifecycleError::ReplacementNotArmed)
    );

    let mut wrong_tenant = replacement(&old);
    wrong_tenant.tenant_id = TenantId::new("tenant-b").test_expect("valid tenant");
    assert_eq!(
        ArmedReplacement::new(&old, &wrong_tenant),
        Err(LifecycleError::ReplacementMismatch)
    );
}

#[test]
fn stale_generation_and_wrong_version_fail_closed() {
    let current = record(DecoyLifecycleState::Armed);
    let mut stale = attempt(&current, DecoyOperationKind::Trigger, None);
    stale.expected_generation -= 1;
    assert_eq!(
        transition(&current, &stale, None),
        Err(LifecycleError::GenerationConflict)
    );

    let mut wrong_version = attempt(&current, DecoyOperationKind::Trigger, None);
    wrong_version.expected_version = DecoyVersion::new(2).test_expect("valid version");
    assert_eq!(
        transition(&current, &wrong_version, None),
        Err(LifecycleError::VersionConflict)
    );
}
