use super::*;

#[test]
fn exact_tenant_identifiers_remain_isolated_after_restart() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("capability-suspension-overlap.db");
    let first_action = action("capability-suspension-action-first");
    let (store, work) = open_claimed_store(&path, &[first_action.as_str()]);
    let first_set = affected(&["capability-a", "capability-shared"]);
    let first_empty = empty_capability_set_suspension_snapshot(key(&first_set))
        .unwrap_or_else(|error| panic!("first empty snapshot: {error}"));
    let first = apply_request(
        first_action.clone(),
        effect("capability-suspension-effect-first"),
        first_set,
        &first_empty,
        work_for(&work, &first_action).fencing_token,
        "capability-suspension-apply-first",
    );

    let expected = store
        .apply_capability_set_suspension(&first)
        .unwrap_or_else(|error| panic!("apply: {error}"));
    let check = |store: &SqliteSecurityStateStore| {
        assert_eq!(
            store
                .load_capability_set_suspensions(&first.key)
                .unwrap_or_else(|error| panic!("owned snapshot: {error}")),
            Some(expected.clone())
        );
        let owned = query(&first.command.request);
        let owned_status = store
            .load_capability_set_suspension_result(&owned)
            .unwrap_or_else(|error| panic!("owned result: {error}"));
        assert_ne!(owned_status, EffectExecutionStatus::NotExecuted);
        let foreign =
            TenantId::new("exact-foreign-tenant").unwrap_or_else(|error| panic!("tenant: {error}"));
        let mut key = first.key.clone();
        key.tenant_id = foreign.clone();
        assert_eq!(
            store
                .load_capability_set_suspensions(&key)
                .unwrap_or_else(|error| panic!("foreign snapshot: {error}")),
            None
        );
        let mut probe = owned;
        probe.tenant_id = foreign;
        assert_eq!(
            store
                .load_capability_set_suspension_result(&probe)
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
