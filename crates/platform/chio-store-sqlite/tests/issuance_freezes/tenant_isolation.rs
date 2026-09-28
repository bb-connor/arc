use super::*;

#[test]
fn exact_tenant_identifiers_remain_isolated_after_restart() {
    let directory = tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
    let path = directory.path().join("issuance-freeze-overlap.db");
    let first_action = action("issuance-freeze-action-first");
    let (store, work) = open_claimed_store(&path, &[first_action.as_str()]);
    let empty = empty_issuance_freeze_snapshot(key())
        .unwrap_or_else(|error| panic!("empty freeze snapshot: {error}"));
    let first = apply_request(
        first_action.clone(),
        effect("issuance-freeze-effect-first"),
        &empty,
        work_for(&work, &first_action).fencing_token,
        101,
        "issuance-freeze-apply-first",
    );

    let expected = store
        .apply_issuance_freeze(&first)
        .unwrap_or_else(|error| panic!("apply: {error}"));
    let check = |store: &SqliteSecurityStateStore| {
        assert_eq!(
            store
                .load_issuance_freezes(&first.key)
                .unwrap_or_else(|error| panic!("owned snapshot: {error}")),
            Some(expected.clone())
        );
        let owned = query(&first.command.request);
        let owned_status = store
            .load_issuance_freeze_operation(&owned)
            .unwrap_or_else(|error| panic!("owned result: {error}"));
        assert_ne!(
            owned_status,
            chio_security_types::ports::IssuanceFreezeOperationStatus::NotExecuted
        );
        let foreign =
            TenantId::new("exact-foreign-tenant").unwrap_or_else(|error| panic!("tenant: {error}"));
        let mut key = first.key.clone();
        key.tenant_id = foreign.clone();
        assert_eq!(
            store
                .load_issuance_freezes(&key)
                .unwrap_or_else(|error| panic!("foreign snapshot: {error}")),
            None
        );
        let mut probe = owned;
        probe.tenant_id = foreign;
        assert_eq!(
            store
                .load_issuance_freeze_operation(&probe)
                .unwrap_or_else(|error| panic!("foreign result: {error}")),
            chio_security_types::ports::IssuanceFreezeOperationStatus::NotExecuted
        );
    };
    check(&store);
    drop(store);
    let reopened =
        SqliteSecurityStateStore::open(&path).unwrap_or_else(|error| panic!("reopen: {error}"));
    check(&reopened);
}
