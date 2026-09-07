#![cfg(feature = "std")]

use chio_security_types::ports::{
    capability_set_suspension_installed_version_hash, capability_set_suspension_version_hash,
    empty_capability_set_suspension_snapshot, predict_capability_set_suspension_apply,
    predict_capability_set_suspension_remove, response_affected_set_hash,
    validate_capability_set_suspension_snapshot, ActionId, CapabilitySetSuspensionContribution,
    CapabilitySetSuspensionContributions, CapabilitySetSuspensionKey, Digest32, EffectId, RecordId,
    RecordIdSet, TenantId,
};

fn tenant(value: &str) -> TenantId {
    TenantId::new(value).unwrap_or_else(|error| panic!("tenant: {error}"))
}

fn affected(values: &[&str]) -> RecordIdSet {
    RecordIdSet::new(
        values
            .iter()
            .map(|value| RecordId::new(*value).unwrap_or_else(|error| panic!("record id: {error}")))
            .collect(),
    )
    .unwrap_or_else(|error| panic!("affected set: {error}"))
}

fn key(tenant_id: &TenantId, affected_ids: &RecordIdSet) -> CapabilitySetSuspensionKey {
    CapabilitySetSuspensionKey {
        tenant_id: tenant_id.clone(),
        affected_set_hash: response_affected_set_hash(tenant_id, affected_ids)
            .unwrap_or_else(|error| panic!("affected set hash: {error}")),
    }
}

fn contribution(
    action_id: &str,
    effect_id: &str,
    affected_ids: RecordIdSet,
    marker: u8,
) -> CapabilitySetSuspensionContribution {
    CapabilitySetSuspensionContribution {
        action_id: ActionId::new(action_id).unwrap_or_else(|error| panic!("action id: {error}")),
        effect_id: EffectId::new(effect_id).unwrap_or_else(|error| panic!("effect id: {error}")),
        affected_ids,
        contribution_hash: Digest32::new([marker; 32]),
        expires_at_unix_ms: 10_000,
    }
}

#[test]
fn affected_set_commitment_binds_tenant_order_and_membership() {
    let first_tenant = tenant("tenant-a");
    let second_tenant = tenant("tenant-b");
    let first = affected(&["capability-a", "capability-b"]);
    let second = affected(&["capability-a", "capability-c"]);
    assert_ne!(
        response_affected_set_hash(&first_tenant, &first),
        response_affected_set_hash(&second_tenant, &first)
    );
    assert_ne!(
        response_affected_set_hash(&first_tenant, &first),
        response_affected_set_hash(&first_tenant, &second)
    );
    assert!(RecordIdSet::new(vec![
        RecordId::new("capability-b").unwrap_or_else(|error| panic!("record id: {error}")),
        RecordId::new("capability-a").unwrap_or_else(|error| panic!("record id: {error}")),
    ])
    .is_err());
}

#[test]
fn affected_set_commitment_uses_canonical_object_key_order() {
    let hash = response_affected_set_hash(
        &tenant("tenant-a"),
        &affected(&["capability-a", "capability-b"]),
    )
    .unwrap_or_else(|error| panic!("affected set hash: {error}"));
    assert_eq!(
        hash,
        Digest32::new([
            57, 34, 61, 149, 88, 127, 156, 26, 68, 189, 165, 180, 176, 155, 64, 164, 100, 81, 176,
            158, 93, 220, 246, 166, 109, 151, 120, 133, 54, 217, 33, 100,
        ])
    );
}

#[test]
fn effect_scoped_contributions_compose_and_remove_out_of_order() {
    let tenant_id = tenant("tenant-compose");
    let affected_ids = affected(&["capability-a", "capability-b"]);
    let key = key(&tenant_id, &affected_ids);
    let empty = empty_capability_set_suspension_snapshot(key.clone())
        .unwrap_or_else(|error| panic!("empty snapshot: {error}"));
    let first = contribution("action-a", "effect-a", affected_ids.clone(), 1);
    let after_first = predict_capability_set_suspension_apply(&empty, &first, 3)
        .unwrap_or_else(|error| panic!("first apply: {error}"));
    let second = contribution("action-b", "effect-b", affected_ids, 2);
    let after_second = predict_capability_set_suspension_apply(&after_first, &second, 5)
        .unwrap_or_else(|error| panic!("second apply: {error}"));
    assert_eq!(after_second.generation, 2);
    assert_eq!(after_second.contributions.len(), 2);
    assert_eq!(after_second.highest_fencing_token, 5);
    assert_ne!(
        capability_set_suspension_installed_version_hash(&key, &first),
        capability_set_suspension_installed_version_hash(&key, &second)
    );

    let after_remove_first = predict_capability_set_suspension_remove(
        &after_second,
        &first.action_id,
        &first.effect_id,
        7,
    )
    .unwrap_or_else(|error| panic!("remove first: {error}"));
    assert_eq!(
        after_remove_first.contributions.as_slice(),
        std::slice::from_ref(&second)
    );
    assert_eq!(after_remove_first.highest_fencing_token, 7);
    let empty_again = predict_capability_set_suspension_remove(
        &after_remove_first,
        &second.action_id,
        &second.effect_id,
        9,
    )
    .unwrap_or_else(|error| panic!("remove second: {error}"));
    assert!(empty_again.contributions.is_empty());
    assert_ne!(
        capability_set_suspension_version_hash(&empty),
        capability_set_suspension_version_hash(&empty_again)
    );
}

#[test]
fn wrong_set_contribution_and_noncanonical_snapshot_fail_closed() {
    let tenant_id = tenant("tenant-integrity");
    let expected = affected(&["capability-a", "capability-b"]);
    let wrong = affected(&["capability-a", "capability-c"]);
    let key = key(&tenant_id, &expected);
    let empty = empty_capability_set_suspension_snapshot(key.clone())
        .unwrap_or_else(|error| panic!("empty snapshot: {error}"));
    let wrong_contribution = contribution("action-wrong", "effect-wrong", wrong, 3);
    assert!(predict_capability_set_suspension_apply(&empty, &wrong_contribution, 1).is_err());

    let first = contribution("action-z", "effect-z", expected.clone(), 4);
    let second = contribution("action-a", "effect-a", expected, 5);
    let after_first = predict_capability_set_suspension_apply(&empty, &first, 1)
        .unwrap_or_else(|error| panic!("first apply: {error}"));
    let mut corrupt = predict_capability_set_suspension_apply(&after_first, &second, 2)
        .unwrap_or_else(|error| panic!("second apply: {error}"));
    let mut reversed = corrupt.contributions.into_vec();
    reversed.swap(0, 1);
    corrupt.contributions = CapabilitySetSuspensionContributions::new(reversed)
        .unwrap_or_else(|error| panic!("corrupt contributions: {error}"));
    assert!(validate_capability_set_suspension_snapshot(&corrupt, &key).is_err());
}
