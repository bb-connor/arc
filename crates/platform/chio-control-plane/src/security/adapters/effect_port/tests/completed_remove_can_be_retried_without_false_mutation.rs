use super::*;


#[test]
fn completed_remove_can_be_retried_without_false_mutation() {
    let store = Arc::new(RecordingOverlayStore::default());
    let port = port(Arc::clone(&store));
    let target = session_containment_target(&tenant(), &session())
        .unwrap_or_else(|error| panic!("target: {error}"));
    let base = session_overlay_version_hash(store.as_ref(), &target)
        .unwrap_or_else(|error| panic!("base: {error}"));
    let apply = request(EffectOperation::Apply, base, 5);
    let applied = port
        .execute(&apply)
        .unwrap_or_else(|error| panic!("apply: {error}"));
    let mut remove = apply;
    remove.operation = EffectOperation::Remove;
    remove.expected_version_hash = applied.resulting_version_hash;
    remove.idempotency_key = RecordId::new("response_effect_command:remove")
        .unwrap_or_else(|error| panic!("remove key: {error}"));
    let first = port
        .execute(&remove)
        .unwrap_or_else(|error| panic!("first remove: {error}"));
    assert!(!first.applied);
    let removed_snapshot = store
        .snapshot(&target)
        .unwrap_or_else(|| panic!("removed overlay missing"));
    assert_eq!(
        first.resulting_version_hash,
        containment_overlay_version_hash(&removed_snapshot)
            .unwrap_or_else(|error| panic!("removed result hash: {error}"))
    );
    assert_eq!(
        port.load_result(&query(&remove)),
        Ok(EffectExecutionStatus::Completed {
            result: first.clone()
        })
    );
    let retry = port
        .execute(&remove)
        .unwrap_or_else(|error| panic!("retry remove: {error}"));
    assert_eq!(retry, first);
    assert_eq!(store.counts().1, 1);
    assert!(store
        .snapshot(&target)
        .unwrap_or_else(|| panic!("overlay after retry missing"))
        .active_contributions
        .is_empty());
}
