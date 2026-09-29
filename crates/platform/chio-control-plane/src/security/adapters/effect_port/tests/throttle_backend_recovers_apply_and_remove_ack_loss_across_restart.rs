use super::*;


#[test]
fn throttle_backend_recovers_apply_and_remove_ack_loss_across_restart() {
    let store = Arc::new(RecordingThrottleStore::default());
    store.lose_next_apply_ack();
    let empty = empty_session_throttle_snapshot(super::super::SessionThrottleKey {
        tenant_id: tenant(),
        session_id: session(),
    })
    .unwrap_or_else(|error| panic!("empty throttle snapshot: {error}"));
    let apply = throttle_request(
        EffectOperation::Apply,
        session_throttle_version_hash(&empty)
            .unwrap_or_else(|error| panic!("empty throttle version: {error}")),
    );
    let port = throttle_port(store.clone());
    assert_eq!(
        port.load_result(&query(&apply)),
        Ok(EffectExecutionStatus::NotExecuted)
    );
    let applied = port
        .execute(&apply)
        .unwrap_or_else(|error| panic!("recover throttle apply ack: {error}"));
    assert!(applied.applied);
    assert_eq!(applied.effect_id, apply.effect_id);
    assert_eq!(store.counts().0, 1);
    assert_eq!(port.execute(&apply), Ok(applied.clone()));
    assert_eq!(store.counts().0, 1);

    let restarted = throttle_port(store.clone());
    assert_eq!(
        restarted.load_result(&query(&apply)),
        Ok(EffectExecutionStatus::Completed {
            result: applied.clone()
        })
    );
    assert_eq!(restarted.execute(&apply), Ok(applied.clone()));
    assert_eq!(store.counts().0, 1);

    store.lose_next_remove_ack();
    let mut remove = apply;
    remove.operation = EffectOperation::Remove;
    remove.expected_version_hash = applied.resulting_version_hash;
    remove.idempotency_key = RecordId::new("response_effect_command:throttle-remove")
        .unwrap_or_else(|error| panic!("throttle remove command: {error}"));
    let removed = restarted
        .execute(&remove)
        .unwrap_or_else(|error| panic!("recover throttle remove ack: {error}"));
    assert!(!removed.applied);
    assert_eq!(store.counts().1, 1);
    let restarted_again = throttle_port(store.clone());
    assert_eq!(restarted_again.execute(&remove), Ok(removed.clone()));
    assert_eq!(
        restarted_again.load_result(&query(&remove)),
        Ok(EffectExecutionStatus::Completed { result: removed })
    );
    assert_eq!(store.counts().1, 1);
}
