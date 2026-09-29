use super::*;

#[test]
fn overlapping_session_suspensions_remove_only_their_own_contribution() {
    let store = Arc::new(RecordingOverlayStore::default());
    let port = port(Arc::clone(&store));
    let target = session_containment_target(&tenant(), &session())
        .unwrap_or_else(|error| panic!("target: {error}"));
    let first_base = session_overlay_version_hash(store.as_ref(), &target)
        .unwrap_or_else(|error| panic!("first base: {error}"));
    let first = request(EffectOperation::Apply, first_base, 3);
    let first_applied = port
        .execute(&first)
        .unwrap_or_else(|error| panic!("first apply: {error}"));

    let second_base = session_overlay_version_hash(store.as_ref(), &target)
        .unwrap_or_else(|error| panic!("second base: {error}"));
    let mut second = request(EffectOperation::Apply, second_base, 8);
    second.action_id =
        ActionId::new("action-b").unwrap_or_else(|error| panic!("second action: {error}"));
    second.effect_id =
        EffectId::new("effect-b").unwrap_or_else(|error| panic!("second effect: {error}"));
    second.idempotency_key = RecordId::new("response_effect_command:command-b")
        .unwrap_or_else(|error| panic!("second command: {error}"));
    let second_applied = port
        .execute(&second)
        .unwrap_or_else(|error| panic!("second apply: {error}"));

    let mut remove_first = first.clone();
    remove_first.operation = EffectOperation::Remove;
    remove_first.expected_version_hash = first_applied.resulting_version_hash;
    remove_first.idempotency_key = RecordId::new("response_effect_command:remove-first")
        .unwrap_or_else(|error| panic!("remove first key: {error}"));
    let restored = port
        .execute(&remove_first)
        .unwrap_or_else(|error| panic!("remove first: {error}"));
    assert!(!restored.applied);
    let after_first = store
        .snapshot(&target)
        .unwrap_or_else(|| panic!("overlay after first removal missing"));
    assert_eq!(after_first.active_contributions.len(), 1);
    assert_eq!(
        after_first.active_contributions.as_slice()[0].effect_id,
        second.effect_id
    );
    assert_eq!(after_first.effective_posture_rank, 8);

    let mut remove_second = second.clone();
    remove_second.operation = EffectOperation::Remove;
    remove_second.expected_version_hash = second_applied.resulting_version_hash;
    remove_second.idempotency_key = RecordId::new("response_effect_command:remove-second")
        .unwrap_or_else(|error| panic!("remove second key: {error}"));
    port.execute(&remove_second)
        .unwrap_or_else(|error| panic!("remove second: {error}"));
    let after_second = store
        .snapshot(&target)
        .unwrap_or_else(|| panic!("overlay after second removal missing"));
    assert!(after_second.active_contributions.is_empty());
    assert_eq!(after_second.effective_posture_rank, 0);
}
