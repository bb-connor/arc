use super::*;

#[test]
fn exact_tenant_identifiers_remain_isolated_after_restart() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("egress.db");
    let now = now_unix_ms();
    let store =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("open store: {error}"));
    let first_work = scheduled_action(&store, "action-first", "claim-first", now);
    let first = contribution("effect-first", &["server-a", "server-b"], now + 60_000);
    let first_request = EgressRestrictionApplyRequest {
        key: key(),
        action_id: first_work.action_id.clone(),
        contribution: first.clone(),
        expected_generation: 0,
        scheduler_fencing_token: first_work.fencing_token,
        command: command(
            &first_work.action_id,
            &first,
            EffectOperation::Apply,
            first_work.fencing_token,
            "response_effect_command:first-apply",
        ),
    };

    let expected = store
        .apply_egress_restriction(&first_request)
        .unwrap_or_else(|error| panic!("apply: {error}"));
    let check = |store: &SqliteSecurityStateStore| {
        assert_eq!(
            store
                .load_egress_restrictions(&first_request.key)
                .unwrap_or_else(|error| panic!("owned snapshot: {error}")),
            Some(expected.clone())
        );
        let owned = query(&first_request.command.request);
        let owned_status = store
            .load_egress_restriction_result(&owned)
            .unwrap_or_else(|error| panic!("owned result: {error}"));
        assert_ne!(owned_status, EffectExecutionStatus::NotExecuted);
        let foreign =
            TenantId::new("exact-foreign-tenant").unwrap_or_else(|error| panic!("tenant: {error}"));
        let mut key = first_request.key.clone();
        key.tenant_id = foreign.clone();
        assert_eq!(
            store
                .load_egress_restrictions(&key)
                .unwrap_or_else(|error| panic!("foreign snapshot: {error}")),
            None
        );
        let mut probe = owned;
        probe.tenant_id = foreign;
        assert_eq!(
            store
                .load_egress_restriction_result(&probe)
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
