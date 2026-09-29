use super::*;

#[test]
fn suspend_session_apply_and_ack_loss_query_bind_the_exact_contribution() {
    let store = Arc::new(RecordingOverlayStore::default());
    let target = session_containment_target(&tenant(), &session())
        .unwrap_or_else(|error| panic!("target: {error}"));
    let base_hash = session_overlay_version_hash(store.as_ref(), &target)
        .unwrap_or_else(|error| panic!("base version: {error}"));
    let port = port(Arc::clone(&store));
    let apply = request(EffectOperation::Apply, base_hash, 4);
    assert_eq!(
        port.load_result(&query(&apply)),
        Ok(EffectExecutionStatus::NotExecuted)
    );
    let result = port
        .execute(&apply)
        .unwrap_or_else(|error| panic!("apply: {error}"));
    assert!(result.applied);
    let snapshot = store
        .snapshot(&target)
        .unwrap_or_else(|| panic!("session overlay missing"));
    assert_eq!(snapshot.active_contributions.len(), 1);
    assert_eq!(
        snapshot.active_contributions.as_slice()[0].effect_id,
        apply.effect_id
    );
    assert_eq!(snapshot.active_contributions.as_slice()[0].posture_rank, 4);
    assert_eq!(
        snapshot.active_contributions.as_slice()[0].expires_at_unix_ms,
        Some(apply.plan_expires_at_unix_ms)
    );
    assert_eq!(
        result.resulting_version_hash,
        containment_installed_version_hash(&target, &snapshot.active_contributions.as_slice()[0])
            .unwrap_or_else(|error| panic!("installed result hash: {error}"))
    );
    assert_eq!(
        port.load_result(&query(&apply)),
        Ok(EffectExecutionStatus::Completed {
            result: result.clone()
        })
    );
    assert_eq!(port.execute(&apply), Ok(result));
    assert_eq!(store.counts().0, 1, "ack recovery must not apply twice");
}
