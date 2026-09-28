use super::*;

#[test]
fn exact_tenant_identifiers_remain_isolated_after_restart() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("session-throttle-overlap.db");
    let first_action = action("throttle-action-first");
    let (store, work) = open_claimed_store(&path, &[first_action.as_str()]);
    let empty = empty_session_throttle_snapshot(key())
        .unwrap_or_else(|error| panic!("empty throttle snapshot: {error}"));
    let first = apply_request(
        first_action.clone(),
        effect("throttle-effect-first"),
        &empty,
        work_for(&work, &first_action).fencing_token,
        SessionThrottleLimits {
            window_ms: 1_000,
            max_invocations: 2,
        },
        "throttle-apply-first",
    );

    let expected = store
        .apply_session_throttle(&first)
        .unwrap_or_else(|error| panic!("apply: {error}"));
    let check = |store: &SqliteSecurityStateStore| {
        assert_eq!(
            store
                .load_session_throttles(&first.key)
                .unwrap_or_else(|error| panic!("owned snapshot: {error}")),
            Some(expected.clone())
        );
        let owned = query(&first.command.request);
        let owned_status = store
            .load_session_throttle_result(&owned)
            .unwrap_or_else(|error| panic!("owned result: {error}"));
        assert_ne!(owned_status, EffectExecutionStatus::NotExecuted);
        let foreign =
            TenantId::new("exact-foreign-tenant").unwrap_or_else(|error| panic!("tenant: {error}"));
        let mut key = first.key.clone();
        key.tenant_id = foreign.clone();
        assert_eq!(
            store
                .load_session_throttles(&key)
                .unwrap_or_else(|error| panic!("foreign snapshot: {error}")),
            None
        );
        let consumed = consume(store, "exact-invocation", 10_100);
        assert!(consumed.allowed);
        assert_eq!(consumed.windows.len(), 1);
        let foreign_consumption = store
            .consume_session_invocation(&SessionThrottleConsumeRequest {
                key: key.clone(),
                invocation_id: record("exact-invocation"),
                observed_at_unix_ms: 10_100,
            })
            .unwrap_or_else(|error| panic!("foreign invocation: {error}"));
        assert!(foreign_consumption.allowed);
        assert!(foreign_consumption.windows.is_empty());
        let mut probe = owned;
        probe.tenant_id = foreign;
        assert_eq!(
            store
                .load_session_throttle_result(&probe)
                .unwrap_or_else(|error| panic!("foreign result: {error}")),
            EffectExecutionStatus::NotExecuted
        );
    };
    check(&store);
    drop(store);
    let reopened =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("reopen: {error}"));
    check(&reopened);
}
