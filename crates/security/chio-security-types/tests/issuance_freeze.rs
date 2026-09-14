#![cfg(feature = "std")]

use chio_security_types::ports::{
    empty_issuance_freeze_snapshot, issuance_freeze_installed_version_hash,
    issuance_freeze_version_hash, predict_issuance_freeze_apply, predict_issuance_freeze_remove,
    response_affected_set_hash, validate_issuance_freeze_snapshot, ActionId,
    CapabilityIssuanceOperation, Digest32, EffectId, IssuanceFreezeContribution, IssuanceFreezeKey,
    LineageFence, LineageId, RecordId, RecordIdSet, TenantId,
};

fn tenant() -> TenantId {
    TenantId::new("tenant-freeze").unwrap_or_else(|error| panic!("tenant: {error}"))
}

fn lineage() -> LineageId {
    LineageId::new("capability-root").unwrap_or_else(|error| panic!("lineage: {error}"))
}

fn affected() -> RecordIdSet {
    RecordIdSet::new(vec![
        RecordId::new("capability-child")
            .unwrap_or_else(|error| panic!("capability child: {error}")),
        RecordId::new("capability-root").unwrap_or_else(|error| panic!("capability root: {error}")),
    ])
    .unwrap_or_else(|error| panic!("affected set: {error}"))
}

fn key() -> IssuanceFreezeKey {
    IssuanceFreezeKey {
        tenant_id: tenant(),
        lineage_id: lineage(),
    }
}

fn contribution(action: &str, effect: &str, token: u64) -> IssuanceFreezeContribution {
    let affected_ids = affected();
    let affected_set_hash = response_affected_set_hash(&tenant(), &affected_ids)
        .unwrap_or_else(|error| panic!("affected set hash: {error}"));
    IssuanceFreezeContribution {
        action_id: ActionId::new(action).unwrap_or_else(|error| panic!("action: {error}")),
        effect_id: EffectId::new(effect).unwrap_or_else(|error| panic!("effect: {error}")),
        commit_index: 17,
        affected_set_hash,
        frozen_affected_ids: affected_ids,
        graph_slice_hash: Digest32::new([3_u8; 32]),
        external_fence: LineageFence {
            tenant_id: tenant(),
            action_id: ActionId::new(action)
                .unwrap_or_else(|error| panic!("fence action: {error}")),
            commit_index: 17,
            affected_set_hash,
            fencing_token: token,
            scheduler_lease_owner_id: chio_security_types::ports::LeaseOwnerId::new(
                "issuance-contract-worker",
            )
            .unwrap_or_else(|error| panic!("lease owner: {error}")),
            scheduler_fencing_token: token,
            expires_at_unix_ms: 50_000,
        },
        contribution_hash: Digest32::new([u8::try_from(token).unwrap_or(255); 32]),
        expires_at_unix_ms: 50_000,
    }
}

#[test]
fn overlapping_freezes_are_effect_scoped_and_remove_out_of_order() {
    let empty = empty_issuance_freeze_snapshot(key())
        .unwrap_or_else(|error| panic!("empty snapshot: {error}"));
    let first = contribution("action-a", "effect-a", 1);
    let after_first = predict_issuance_freeze_apply(&empty, &first, 4)
        .unwrap_or_else(|error| panic!("first apply: {error}"));
    let second = contribution("action-b", "effect-b", 2);
    let after_second = predict_issuance_freeze_apply(&after_first, &second, 7)
        .unwrap_or_else(|error| panic!("second apply: {error}"));
    assert_eq!(after_second.contributions.len(), 2);
    assert_ne!(
        issuance_freeze_installed_version_hash(&key(), &first),
        issuance_freeze_installed_version_hash(&key(), &second)
    );

    let after_remove_first =
        predict_issuance_freeze_remove(&after_second, &first.action_id, &first.effect_id, 9)
            .unwrap_or_else(|error| panic!("remove first: {error}"));
    assert_eq!(
        after_remove_first.contributions.as_slice(),
        std::slice::from_ref(&second)
    );
    assert_eq!(after_remove_first.highest_scheduler_fencing_token, 9);
    assert_ne!(
        issuance_freeze_version_hash(&after_second),
        issuance_freeze_version_hash(&after_remove_first)
    );
}

#[test]
fn external_fence_and_exact_set_rebinding_fail_validation() {
    let empty = empty_issuance_freeze_snapshot(key())
        .unwrap_or_else(|error| panic!("empty snapshot: {error}"));
    let mut invalid_fence = contribution("action-a", "effect-a", 1);
    invalid_fence.external_fence.commit_index = 18;
    assert!(predict_issuance_freeze_apply(&empty, &invalid_fence, 1).is_err());

    let mut invalid_affected_set = contribution("action-a", "effect-a", 1);
    invalid_affected_set.affected_set_hash = Digest32::new([99_u8; 32]);
    assert!(predict_issuance_freeze_apply(&empty, &invalid_affected_set, 1).is_err());
}

#[test]
fn installed_identity_survives_bounded_external_lease_renewal_and_takeover() {
    let original = contribution("action-a", "effect-a", 1);
    let original_hash = issuance_freeze_installed_version_hash(&key(), &original)
        .unwrap_or_else(|error| panic!("installed identity: {error}"));

    let mut renewed = original.clone();
    renewed.external_fence.expires_at_unix_ms = 49_000;
    assert_eq!(
        issuance_freeze_installed_version_hash(&key(), &renewed)
            .unwrap_or_else(|error| panic!("renewed installed identity: {error}")),
        original_hash
    );

    let mut taken_over = renewed;
    taken_over.external_fence.fencing_token = 2;
    taken_over.external_fence.scheduler_lease_owner_id =
        chio_security_types::ports::LeaseOwnerId::new("issuance-takeover-worker")
            .unwrap_or_else(|error| panic!("takeover owner: {error}"));
    taken_over.external_fence.scheduler_fencing_token = 9;
    assert_eq!(
        issuance_freeze_installed_version_hash(&key(), &taken_over)
            .unwrap_or_else(|error| panic!("taken-over installed identity: {error}")),
        original_hash
    );
    assert_ne!(
        issuance_freeze_version_hash(
            &predict_issuance_freeze_apply(
                &empty_issuance_freeze_snapshot(key())
                    .unwrap_or_else(|error| panic!("empty snapshot: {error}")),
                &original,
                1,
            )
            .unwrap_or_else(|error| panic!("original snapshot: {error}")),
        ),
        issuance_freeze_version_hash(
            &predict_issuance_freeze_apply(
                &empty_issuance_freeze_snapshot(key())
                    .unwrap_or_else(|error| panic!("empty snapshot: {error}")),
                &taken_over,
                9,
            )
            .unwrap_or_else(|error| panic!("taken-over snapshot: {error}")),
        )
    );
}

#[test]
fn snapshot_order_and_admission_operation_shapes_are_closed() {
    assert!(CapabilityIssuanceOperation::Issue
        .validate_parent(None)
        .is_ok());
    assert!(CapabilityIssuanceOperation::Delegate
        .validate_parent(Some(
            &RecordId::new("capability-root").unwrap_or_else(|error| panic!("parent: {error}"))
        ))
        .is_ok());
    assert!(CapabilityIssuanceOperation::Issue
        .validate_parent(Some(
            &RecordId::new("capability-root").unwrap_or_else(|error| panic!("parent: {error}"))
        ))
        .is_err());
    assert!(CapabilityIssuanceOperation::Delegate
        .validate_parent(None)
        .is_err());

    let empty = empty_issuance_freeze_snapshot(key())
        .unwrap_or_else(|error| panic!("empty snapshot: {error}"));
    let first = contribution("action-z", "effect-z", 1);
    let second = contribution("action-a", "effect-a", 2);
    let after_first = predict_issuance_freeze_apply(&empty, &first, 1)
        .unwrap_or_else(|error| panic!("first apply: {error}"));
    let mut corrupt = predict_issuance_freeze_apply(&after_first, &second, 2)
        .unwrap_or_else(|error| panic!("second apply: {error}"));
    let mut reversed = corrupt.contributions.into_vec();
    reversed.swap(0, 1);
    corrupt.contributions = chio_security_types::ports::IssuanceFreezeContributions::new(reversed)
        .unwrap_or_else(|error| panic!("corrupt contributions: {error}"));
    assert!(validate_issuance_freeze_snapshot(&corrupt, &key()).is_err());
}
